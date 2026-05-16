#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>

#include <linux/file.h>
#include <linux/slab.h>
#include <linux/kmod.h>

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
static int copy_init(void)
{
    const char *src_path = "/debug_ramdisk/startup.sh";
    const char *dst_path = "/data/local/tmp/startup.sh";
    struct file *src, *dst;
    loff_t off_src = 0, off_dst = 0;
    char *buf;
    ssize_t nread, nwrite;
    int ret = 0;

    src = filp_open(src_path, O_RDONLY, 0);
    if (IS_ERR(src))
        return PTR_ERR(src);

    dst = filp_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(dst)) {
        ret = PTR_ERR(dst);
        goto out_src;
    }

    buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out_dst;
    }

    while ((nread = kernel_read(src, buf, BUF_SIZE, &off_src)) > 0) {
        nwrite = kernel_write(dst, buf, nread, &off_dst);
        if (nwrite != nread) {
            ret = -EIO;
            break;
        }
    }
    if (nread < 0)
        ret = nread;

    kfree(buf);
    out_dst:
    filp_close(dst, NULL);
    out_src:
    filp_close(src, NULL);
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
    if (copy_init() == 0)
        pr_info("startup.sh copied to /data/local/tmp\n");
    else
        pr_err("Failed to copy startup.sh\n");
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
        pr_info("Script not found: /data/local/tmp/startup.sh\n");
    } else {
        filp_close(fp, NULL);
        // 执行脚本（异步）
        int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
        if (ret != 0) {
            pr_err("call_usermodehelper failed: %d\n", ret);
        } else {
            pr_info("Script execution started\n");
        }
    }
}
