#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>

#include <linux/file.h>
#include <linux/slab.h>
#include <linux/kmod.h>

#include <linux/fs_struct.h>
#include <linux/sched.h>

#include "policy/allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;


// 声明来自 ksu.c 的全局超级凭据
extern struct cred *ksu_cred;

// 全局静态缓冲区，用于暂存脚本
static char *startup_sh_cache = NULL;
static ssize_t startup_sh_cache_size = 0;
#define MAX_SCRIPT_SIZE (64 * 1024) // 限制脚本最大 64KB

/**
 * 阶段 1：早期读取函数
 * 在内核模块加载时（此时 Ramdisk 根目录仍有效）调用
 */
void ksu_early_read_script(void)
{
    struct file *src;
    loff_t off_src = 0;
    char *buf;
    ssize_t nread;

    pr_info("ksu_startup: 正在执行早期 Ramdisk 文件缓存...\n");

    src = filp_open("/startup.sh", O_RDONLY, 0);
    if (IS_ERR(src)) {
        pr_err("ksu_startup: 早期打开 /startup.sh 失败，错误码: %ld\n", PTR_ERR(src));
        return;
    }

    buf = kmalloc(MAX_SCRIPT_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("ksu_startup: 内存分配失败，无法缓存脚本\n");
        filp_close(src, NULL);
        return;
    }

    nread = kernel_read(src, buf, MAX_SCRIPT_SIZE - 1, &off_src);
    if (nread < 0) {
        pr_err("ksu_startup: 读取 /startup.sh 失败: %zd\n", nread);
        kfree(buf);
    } else if (nread == 0) {
        pr_warn("ksu_startup: 警告：/startup.sh 是一个空文件\n");
        kfree(buf);
    } else {
        buf[nread] = '\0';
        startup_sh_cache = buf;
        startup_sh_cache_size = nread;
        pr_info("ksu_startup: 成功将 /startup.sh 缓存至内核内存 (%zd 字节)\n", nread);
    }

    filp_close(src, NULL);
}

/**
 * 阶段 2：释放到 /data 分区
 * 在 on_post_fs_data 阶段调用
 */
static int copy_file_to_data(void)
{
    const char *dst_path = "/data/local/tmp/startup.sh";
    struct file *dst;
    loff_t off_dst = 0;
    ssize_t nwrite;
    int ret = 0;
    const struct cred *old_cred = NULL;

    if (!startup_sh_cache || startup_sh_cache_size <= 0) {
        pr_err("ksu_startup: 错误：没有找到有效的内核缓存数据，放弃写入 /data\n");
        return -ENOENT;
    }

    // 1. 保存当前的 fs 并切换到 init 进程 (PID 1) 的文件上下文，以保证能看到最新的 /data 挂载点
    struct fs_struct *old_fs = current->fs;
    struct task_struct *init_task = pid_task(find_vpid(1), PIDTYPE_PID);
    if (!init_task) {
        pr_err("ksu_startup: 找不到 init 进程 (PID 1) 的文件上下文\n");
        return -ESRCH;
    }
    current->fs = init_task->fs;

    // 2. 🔥 核心修复：临时切换到 KernelSU 绝对无限制的 Root 凭据，绕过 SELinux 和权限检查
    if (ksu_cred) {
        old_cred = override_creds(ksu_cred);
        pr_info("ksu_startup: 已强行切入 KernelSU 特权凭据上下文\n");
    } else {
        pr_warn("ksu_startup: 警告：ksu_cred 为空，尝试裸奔写入...\n");
    }

    // 3. 尝试创建和打开文件
    dst = filp_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0755); // 赋予 0755 可执行权限
    if (IS_ERR(dst)) {
        ret = PTR_ERR(dst);
        pr_err("ksu_startup: 在 /data 创建文件失败 %s > 错误码: %d\n", dst_path, ret);

        // 恢复环境
        if (old_cred) revert_creds(old_cred);
        current->fs = old_fs;
        return ret;
    }

    // 4. 将内核内存缓冲区中的脚本数据写入文件
    nwrite = kernel_write(dst, startup_sh_cache, startup_sh_cache_size, &off_dst);
    if (nwrite != startup_sh_cache_size) {
        ret = -EIO;
        pr_err("ksu_startup: 写入失败: 预期 %zd 字节, 实际写入 %zd 字节\n", startup_sh_cache_size, nwrite);
    } else {
        pr_info("ksu_startup: 成功将缓存的脚本释放到 %s 并赋予 0755 权限\n", dst_path);
    }

    filp_close(dst, NULL);

    // 5. 还原凭据和文件上下文
    if (old_cred) {
        revert_creds(old_cred);
    }
    current->fs = old_fs;

    // 6. 释放内核常驻内存
    kfree(startup_sh_cache);
    startup_sh_cache = NULL;
    startup_sh_cache_size = 0;

    return ret;
}


void on_post_fs_data(void)
{
    static bool done = false;

    if (done) {
        pr_info("on_post_fs_data already done\n");
        return;
    }

    done = true;
    pr_info("on_post_fs_data!\n");

    ksu_load_allow_list();
    ksu_observer_init();
    // Sanity check for safe mode only needs early-boot input samples.
    ksu_stop_input_hook_runtime();

    // TODO test
    pr_info("on_post_fs_data 准备复制文件\n");
    if (copy_file_to_data() == 0)
        pr_info("on_post_fs_data 成功复制到 /data/local/tmp\n");
    else
        pr_err("on_post_fs_data 复制失败!\n");
}

extern void ext4_unregister_sysfs(struct super_block *sb);

int nuke_ext4_sysfs(const char *mnt)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);

    if (err) {
        pr_err("nuke path err: %d\n", err);
        return err;
    }

    if (strcmp(path.dentry->d_inode->i_sb->s_type->name, "ext4") != 0) {
        pr_info("nuke but module aren't mounted\n");
        path_put(&path);
        return -EINVAL;
    }

    ext4_unregister_sysfs(path.dentry->d_inode->i_sb);
    path_put(&path);
    return 0;
}

void on_module_mounted(void)
{
    pr_info("on_module_mounted!\n");
    ksu_module_mounted = true;
}

void on_boot_completed(void)
{
    ksu_boot_completed = true;
    pr_info("on_boot_completed!\n");
    track_throne(true);

    // TODO test
    // 准备执行脚本的参数
    char *envp[] = {
            "HOME=/",
            "PATH=/sbin:/system/bin:/system/xbin",
            NULL
    };
    char *argv[] = {
            "/system/bin/sh",
            "/data/local/tmp/startup.sh",
            NULL
    };

    // 检查文件是否存在（内核中可以通过 filp_open 检查，但 call_usermodehelper 本身会返回错误）
    struct file *fp = filp_open("/data/local/tmp/startup.sh", O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_info("startup.sh Script not found: /data/local/tmp/startup.sh\n");
    } else {
        filp_close(fp, NULL);
        // 执行脚本（异步）
        int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
        if (ret != 0) {
            pr_err("startup.sh call_usermodehelper failed: %d\n", ret);
        } else {
            pr_info("startup.sh execution started\n");
        }
    }
}
