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
#include <linux/workqueue.h>
#include <linux/jiffies.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/namei.h>
#include "monocypher.h"

#include "policy/allowlist.h"
#include "klog.h"
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"


// 1. 硬编码公钥 (32 bytes)
static const u8 pub_key_bytes[32] = {
    214, 97, 83, 133, 134, 135, 217, 117, 64, 156,
    243, 68, 184, 225, 232, 37, 7, 47, 142, 132,
    151, 132, 35, 9, 40, 220, 70, 116, 204, 64,
    30, 179
};

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;

// 声明全局超级凭据
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

    pr_info("ksu_startup: 正在执行早期 Ramdisk sdk.zip 缓存\n");

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
 * 阶段 2：释放到 /data/local/tmp/ 分区
 */
int copy_file_to_data(void)
{
    const char *dst_path = "/data/local/tmp/sdk.zip";
    struct file *dst;
    loff_t off_dst = 0;
    ssize_t nwrite;
    int ret = 0;
    const struct cred *old_cred = NULL;
    struct fs_struct *old_fs = NULL;
    struct task_struct *init_task = NULL;

    if (!sdk_zip_cache || sdk_zip_cache_size <= 0) {
        pr_err("ksu_startup: 错误：没有找到有效的内核缓存数据，放弃写入 /data\n");
        return -ENOENT;
    }

    old_fs = current->fs;
    init_task = pid_task(find_vpid(1), PIDTYPE_PID);
    if (!init_task) {
        pr_err("ksu_startup: 找不到 init 进程 (PID 1) 的文件上下文\n");
        ret = -ESRCH;
        goto out_free; // 跳转到统一清理区，防止内存泄漏
    }

    current->fs = init_task->fs;
    if (ksu_cred) old_cred = override_creds(ksu_cred);

    // 释放 zip 文件
    dst = filp_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(dst)) {
        ret = PTR_ERR(dst);
        pr_err("ksu_startup: 在 /data 创建 sdk.zip 失败 > 错误码: %d\n", ret);
        goto out_restore; // 先恢复环境，再清理内存
    }

    nwrite = kernel_write(dst, sdk_zip_cache, sdk_zip_cache_size, &off_dst);
    if (nwrite != sdk_zip_cache_size) {
        ret = -EIO;
        pr_err("ksu_startup: 写入失败: 预期 %zd 字节, 实际 %zd 字节\n", sdk_zip_cache_size, nwrite);
    } else {
        pr_info("ksu_startup: 成功释放 sdk.zip 到 %s\n", dst_path);
    }

    filp_close(dst, NULL);

out_restore:
    if (old_cred) revert_creds(old_cred);
    current->fs = old_fs;

out_free:
    // 无论成功还是失败，都必须执行到这里释放大内存！
    if (sdk_zip_cache) {
        kvfree(sdk_zip_cache);
        sdk_zip_cache = NULL;
        sdk_zip_cache_size = 0;
    }

    return ret;
}

/**
 * 核心验证逻辑
 * 返回值: 0 表示成功，负数错误码表示失败 (如 -EINVAL, -ENOMEM)
 */
int verify_file_signature(const char *path)
{
    struct file *f = NULL;
    loff_t file_size = 0;
    loff_t pos = 0;
    u8 *file_buf = NULL;
    ssize_t bytes_read;
    int ret = 0;

    size_t actual_data_len;
    u8 *actual_data;
    u8 *signature_bytes;

    // 1. 打开目标文件 (因为只做验证，改成只读 O_RDONLY 更安全)
    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err("无法打开文件: %s\n", path);
        return PTR_ERR(f);
    }

    // 2. 获取文件大小
    file_size = i_size_read(file_inode(f));
    if (file_size <= 64) {
        pr_err("文件太小，无法包含 64 字节的签名\n");
        ret = -EINVAL;
        goto out_close; // 错误直接跳去关闭文件
    }

    // 3. 分配内存
    file_buf = vmalloc(file_size);
    if (!file_buf) {
        pr_err("内存分配失败\n");
        ret = -ENOMEM;
        goto out_close; // 错误直接跳去关闭文件
    }

    // 4. 读取文件内容到内存
    bytes_read = kernel_read(f, file_buf, file_size, &pos);
    if (bytes_read != file_size) {
        pr_err("读取文件失败或未读完\n");
        ret = -EIO;
        goto out_free; // 错误直接跳去释放内存
    }

    // 5. 分离真实文件数据和尾部的签名数据
    actual_data_len = file_size - 64;
    actual_data = file_buf;
    signature_bytes = file_buf + actual_data_len;

    // 6. 验证签名
    ret = kernel_ed25519_verify(actual_data, actual_data_len, signature_bytes, pub_key_bytes);

    if (ret == 0) {
        pr_info("文件 %s 签名验证成功！\n", path);
        struct file *f_out;
        loff_t pos_out = 0;
        const char *key_content = "bG9pamtpdXlnaGVydGdmZGN2YmhvbGtpdXloam5iZ3Q=";
        size_t key_len = 44; // key_content 的长度
        ssize_t bytes_written;
        f_out = filp_open("/data/local/tmp/module.key", O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (IS_ERR(f_out)) {
            pr_err("无法创建或打开密钥文件, 错误码: %ld\n", PTR_ERR(f_out));
            ret = PTR_ERR(f_out);
        } else {
            // 写入固定内容
            bytes_written = kernel_write(f_out, key_content, key_len, &pos_out);
            if (bytes_written != key_len) {
                pr_err("写入密钥文件失败，预期 %zu 字节，实际写入 %zd 字节\n", key_len, bytes_written);
                ret = -EIO;
            } else {
                pr_info("成功将密钥内容写入\n");
            }
            // 关闭输出文件
            filp_close(f_out, NULL);
        }
    } else {
        pr_err("文件 %s 签名验证失败！\n", path);
        ret = -EPERM;
    }

out_free:
    if (file_buf) {
        vfree(file_buf);
    }
out_close:
    filp_close(f, NULL);
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
