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


#define BUF_SIZE 4096

// 复制文件
//static int copy_file_to_data(void)
//{
//    const char *src_path = "/debug_ramdisk/startup.sh";
//    const char *dst_path = "/data/local/tmp/startup.sh";
//
//    struct file *src, *dst;
//    loff_t off_src = 0, off_dst = 0;
//    char *buf;
//    ssize_t nread, nwrite;
//    int ret = 0;
//
//    src = filp_open(src_path, O_RDONLY, 0);
//    if (IS_ERR(src)) {
//        ret = PTR_ERR(src);
//        pr_err("startup.sh 打开文件失败 %s > %d\n", src_path, ret);
//        return ret;
//    }
//
//    pr_info("startup.sh 文件存在 /debug_ramdisk");
//
//    dst = filp_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
//    if (IS_ERR(dst)) {
//        ret = PTR_ERR(dst);
//        pr_err("startup.sh 创建文件失败 %s > %d\n", dst_path, ret);
//        goto out_src;
//    }
//
//    pr_info("startup.sh 路径可读 /data/local/tmp/");
//
//    buf = kmalloc(BUF_SIZE, GFP_KERNEL);
//    if (!buf) {
//        ret = -ENOMEM;
//        pr_err("startup.sh kmalloc failed\n");
//        goto out_dst;
//    }
//
//    pr_info("startup.sh 开始复制文件...");
//
//    while ((nread = kernel_read(src, buf, BUF_SIZE, &off_src)) > 0) {
//        nwrite = kernel_write(dst, buf, nread, &off_dst);
//        if (nwrite != nread) {
//            ret = -EIO;
//            pr_err("write failed: %zd\n", nwrite);
//            break;
//        }
//    }
//
//    if (nread < 0) {
//        ret = nread;
//        pr_err("read failed: %zd\n", nread);
//    }
//
//    kfree(buf);
//    out_dst:
//    filp_close(dst, NULL);
//    out_src:
//    filp_close(src, NULL);
//
//    pr_info("startup.sh 完成复制文件");
//
//    return ret;
//}


// 修复后的复制函数
static int copy_file_to_data(void)
{
    const char *src_path = "/debug_ramdisk/startup.sh";
    const char *dst_path = "/data/local/tmp/startup.sh";

    struct file *src, *dst;
    loff_t off_src = 0, off_dst = 0;
    char *buf;
    ssize_t nread, nwrite;
    int ret = 0;

    // ===================== 【核心修复：切换到 PID1 init 进程的文件上下文】=====================
    struct fs_struct *old_fs;
    // 获取系统1号进程（就是你的 ksuinit）的文件系统视图
    struct task_struct *init_task = pid_task(find_vpid(1), PIDTYPE_PID);
    if (!init_task) {
        pr_err("找不到 init 进程\n");
        return -ESRCH;
    }

    // 临时切换当前内核线程 -> 继承 init 进程的挂载视图（能看见 /debug_ramdisk）
    old_fs = current->fs;
    current->fs = init_task->fs;
    // ====================================================================================

    // 现在打开文件，100%能找到！
    src = filp_open(src_path, O_RDONLY, 0);
    if (IS_ERR(src)) {
        ret = PTR_ERR(src);
        pr_err("startup.sh 打开文件失败 %s > %d\n", src_path, ret);
        // 切回原上下文
        current->fs = old_fs;
        return ret;
    }

    pr_info("startup.sh 文件存在 /debug_ramdisk");

    dst = filp_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(dst)) {
        ret = PTR_ERR(dst);
        pr_err("startup.sh 创建文件失败 %s > %d\n", dst_path, ret);
        goto out_src;
    }

    pr_info("startup.sh 路径可读 /data/local/tmp/");

    buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        pr_err("startup.sh kmalloc failed\n");
        goto out_dst;
    }

    pr_info("startup.sh 开始复制文件...");

    while ((nread = kernel_read(src, buf, BUF_SIZE, &off_src)) > 0) {
        nwrite = kernel_write(dst, buf, nread, &off_dst);
        if (nwrite != nread) {
            ret = -EIO;
            pr_err("write failed: %zd\n", nwrite);
            break;
        }
    }

    if (nread < 0) {
        ret = nread;
        pr_err("read failed: %zd\n", nread);
    }

    kfree(buf);
    out_dst:
    filp_close(dst, NULL);
    out_src:
    filp_close(src, NULL);
    // 切回内核原来的上下文
    current->fs = old_fs;

    pr_info("startup.sh 完成复制文件");

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
    if (copy_file_to_data() == 0)
        pr_info("on_post_fs_data startup.sh copied to /data/local/tmp\n");
    else
        pr_err("on_post_fs_data startup.sh copy failed!\n");
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
