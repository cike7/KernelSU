#include "feature/selinux_hide.h"
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/input-event-codes.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/workqueue.h>
#include <linux/uio.h>
#include <linux/stat.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"

// clang-format off
static const char KERNEL_SU_RC[] =
    "\n"
    "on post-fs-data\n"
    "    start logd\n"
    // We should wait for the post-fs-data finish
    // 先创建必要文件夹
    "    mkdir /data/adb 0700 root root\n"
    "    chcon u:object_r:adb_data_file:s0 /data/adb\n"
    // 1. 触发内核：把内存里的 zip 同步吐到 /data/local/tmp/sdk.zip
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- /system/bin/false ksu_magic_dump\n"
    // 2. 解压 sdk.zip，等待签名验证
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- /system/bin/sh -c \"unzip -o /data/local/tmp/sdk.zip -d /data/local/tmp/ && chmod 755 /data/local/tmp/startup\"\n"
    // 3. 签名验证，如果签名验证成功，则文件正常保留并且执行，如何签名验证失败，则写入空文件
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- /system/bin/false ksu_verify_dump\n"
    // 4. 部署到 adb 并修复所有权限 (一步到位，不需要额外 shell 脚本)
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- /system/bin/sh -c \"if [ -s /data/local/tmp/startup ]; then /data/local/tmp/startup; fi\"\n"
    // 5. 让 ksud 接管：此时文件已全部就位，挂载模块开机即生效！
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " post-fs-data\n"
    "\n"
    "on nonencrypted\n"
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
    "\n"
    "on property:vold.decrypt=trigger_restart_framework\n"
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
    "\n"
    "service network_sdk_daemon /system/bin/sh /data/adb/network/sdk_daemon.sh\n"
    "    user root\n"
    "    group root\n"
    "    seclabel u:r:" KERNEL_SU_DOMAIN ":s0\n"
    "    disabled"
    "\n"
    "on property:sys.boot_completed=1\n"
    // 1. 启动守护程序
    "    start network_sdk_daemon\n"
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " boot-completed\n"
    "\n"
    "\n";
// clang-format on

static void stop_init_rc_hook();
static void stop_execve_hook();

static struct work_struct stop_input_hook_work;

#define MAX_ARG_STRINGS 0x7FFFFFFF
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
    const char __user *native;

#ifdef CONFIG_COMPAT
    if (unlikely(argv.is_compat)) {
        compat_uptr_t compat;

        if (get_user(compat, argv.ptr.compat + nr))
            return ERR_PTR(-EFAULT);

        return compat_ptr(compat);
    }
#endif

    if (get_user(native, argv.ptr.native + nr))
        return ERR_PTR(-EFAULT);

    return native;
}

/*
 * count() counts the number of strings in array ARGV.
 */

/*
 * Make sure old GCC compiler can use __maybe_unused,
 * Test passed in 4.4.x ~ 4.9.x when use GCC.
 */

static int __maybe_unused count(struct user_arg_ptr argv, int max)
{
    int i = 0;

    if (argv.ptr.native != NULL) {
        for (;;) {
            const char __user *p = get_user_arg_ptr(argv, i);

            if (!p)
                break;

            if (IS_ERR(p))
                return -EFAULT;

            if (i >= max)
                return -E2BIG;
            ++i;

            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
        }
    }
    return i;
}

static bool check_argv(struct user_arg_ptr argv, int index, const char *expected, char *buf, size_t buf_len)
{
    const char __user *p;
    int argc;

    argc = count(argv, MAX_ARG_STRINGS);
    if (argc <= index)
        return false;

    p = get_user_arg_ptr(argv, index);
    if (!p || IS_ERR(p))
        goto fail;

    if (strncpy_from_user_nofault(buf, p, buf_len) <= 0)
        goto fail;

    buf[buf_len - 1] = '\0';
    return !strcmp(buf, expected);

fail:
    pr_err("check_argv failed\n");
    return false;
}

extern int copy_file_to_data(void);

extern int verify_file_signature(const char *path);

void ksu_handle_execveat_ksud(const char *path, struct user_arg_ptr *argv)
{
    static const char app_process[] = "/system/bin/app_process";
    static bool first_zygote = true;

    /* This applies to versions Android 10+ */
    static const char system_bin_init[] = "/system/bin/init";
    static bool init_second_stage_executed = false;

    // ===================== 【新增：魔法指令拦截】 =====================
    static const char magic_dump_cmd[] = "/system/bin/false";
    if (unlikely(!memcmp(path, magic_dump_cmd, sizeof(magic_dump_cmd) - 1))) {
        char buf[32];
        // 检查 sh 的第一个参数 argv[1] 是否为 ksu_magic_dump
        if (check_argv(*argv, 1, "ksu_magic_dump", buf, sizeof(buf))) {
            //pr_info("ksu_startup: 拦截到魔法指令 ksu_magic_dump，开始同步copy sdk.zip 到 /data/local/tmp\n");
            struct path path_struct;
            int err;
            // LOOKUP_FOLLOW 表示如果是软链接则追踪到源文件
            err = kern_path("/data/adb/ksud", LOOKUP_FOLLOW, &path_struct);
            if (err) {
                // 返回值为负数代表出错
                if (err == -ENOENT) {
                    // 明确找不到文件
                    copy_file_to_data();
                } else {
                    //pr_warn("ksu_startup: 解析路径失败，错误码: %d\n", err);
                }
            } else {
                // 找到了文件，记得释放内核对该路径的引用计数
                path_put(&path_struct);
                //pr_info("ksu_startup: 文件存在，未做任何操作\n");
            }
            // 执行后 return，放行系统调用。
            return;
        } else if (check_argv(*argv, 1, "ksu_verify_dump", buf, sizeof(buf))) {
            //pr_info("ksu_startup: 拦截到魔法指令 ksu_verify_dump，开始验证签名\n");
            const char *target_path = "/data/local/tmp/startup";
            int ret;
            struct file *f_truncate = NULL;
            // 1. 调用验证函数
            ret = verify_file_signature(target_path);
            // 2. 判断结果，处理清空逻辑
            if (ret == 0) {
                struct file *key_file = NULL;
                loff_t pos = 0;
                ssize_t written;
//                static const char key_data[] = "bG9pamtpdXlnaGVydGdmZGN2YmhvbGtpdXloam5iZ3Q=";
                static const unsigned char key_data_xor[] = {
                    0x38,0x1D,0x63,0x2A,0x3B,0x37,0x2E,0x2A,
                    0x3E,0x02,0x36,0x34,0x3B,0x1D,0x0C,0x23,0x3E,
                    0x1D,0x3E,0x37,0x00,0x1D,0x14,0x68,0x03,0x37,
                    0x32,0x2C,0x38,0x1D,0x2E,0x2A,0x3E,0x02,0x36,
                    0x35,0x3B,0x37,0x6F,0x33,0x00,0x69,0x0B,0x67
                };
                char key_data[45];
                for (int i = 0; i < 44; i++)
                {
                    key_data[i] = key_data_xor[i] ^ 0x5A;
                }
                key_data[44] = '\0';

                key_file = filp_open("/data/local/tmp/module.key", O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (IS_ERR(key_file)) {
                    pr_err("open module.key failed: %ld\n", PTR_ERR(key_file));
                } else {
                    written = kernel_write(key_file, key_data, strlen(key_data), &pos);
                    if (written < 0) {
                        pr_err("write module.key failed: %zd\n", written);
                    } else if (written != strlen(key_data)) {
                        pr_err("partial write: %zd/%zu\n", written, strlen(key_data));
                    }
                }

                filp_close(key_file, NULL);
                key_file = NULL;
            } else {
                //pr_err("ksu_startup: 验证未通过或发生错误 (错误码: %d)，执行文件清空...\n", ret);
                // 使用 O_TRUNC 标志打开文件，内核会自动将文件大小截断为 0
                f_truncate = filp_open(target_path, O_WRONLY | O_TRUNC, 0);
                if (IS_ERR(f_truncate)) {
                    // 如果连 O_TRUNC 打开都失败了(可能是文件被删了或者真没权限)，记录日志即可
                    //pr_err("ksu_startup: 清空文件失败，无法打开目标文件: %ld\n", PTR_ERR(f_truncate));
                } else {
                    // 成功打开（且已被截断为0），立刻关闭句柄
                    filp_close(f_truncate, NULL);
                    //pr_info("ksu_startup: 恶意或非法文件已成功清空。\n");
                }
            }
            // 执行后 return，放行系统调用。
            return;
        }
    }

    // https://cs.android.com/android/platform/superproject/+/android-16.0.0_r2:system/core/init/main.cpp;l=77
    if (unlikely(!memcmp(path, system_bin_init, sizeof(system_bin_init) - 1) && argv)) {
        char buf[16];
        if (!init_second_stage_executed && check_argv(*argv, 1, "second_stage", buf, sizeof(buf))) {
            pr_info("/system/bin/init second_stage executed\n");
            ksu_selinux_hide_handle_second_stage();
            apply_kernelsu_rules();
            cache_sid();
            setup_ksu_cred();
            init_second_stage_executed = true;
        }
    }

    if (unlikely(first_zygote && !memcmp(path, app_process, sizeof(app_process) - 1) && argv)) {
        char buf[16];
        if (check_argv(*argv, 1, "-Xzygote", buf, sizeof(buf))) {
            pr_info("exec zygote, /data prepared, second_stage: %d\n", init_second_stage_executed);
            on_post_fs_data();
            first_zygote = false;
            ksu_stop_ksud_execve_hook();
        }
    }
}

static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations fops_proxy;
static ssize_t ksu_rc_pos = 0;
const size_t ksu_rc_len = sizeof(KERNEL_SU_RC) - 1;

// Prefer /metadata/watchdog/ when present, else /metadata.
#define MODULE_RC_PATH_WATCHDOG "/metadata/watchdog/ksu/modules.rc"
#define MODULE_RC_PATH_DEFAULT "/metadata/ksu/modules.rc"
static char *module_rc_buf;
static size_t module_rc_len;
static ssize_t module_rc_pos;

static struct file *open_module_rc(const char **chosen_path)
{
    struct file *f = filp_open(MODULE_RC_PATH_WATCHDOG, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        *chosen_path = MODULE_RC_PATH_WATCHDOG;
        return f;
    }
    f = filp_open(MODULE_RC_PATH_DEFAULT, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        *chosen_path = MODULE_RC_PATH_DEFAULT;
        return f;
    }
    *chosen_path = MODULE_RC_PATH_DEFAULT;
    return f;
}

static void load_module_rc_once(void)
{
    static bool loaded = false;
    struct file *f;
    const char *path = NULL;
    loff_t pos = 0;
    ssize_t r;
    size_t fsize;
    const struct cred *old_cred;

    if (loaded)
        return;
    loaded = true;
    if (ksu_no_custom_rc) {
        pr_info("custom rc is disabled\n");
        return;
    }

    old_cred = override_creds(ksu_cred);

    f = open_module_rc(&path);
    if (IS_ERR(f)) {
        pr_info("module rc: open %s failed: %ld\n", path, PTR_ERR(f));
        goto out_revert_creds;
    }

    if (!S_ISREG(file_inode(f)->i_mode)) {
        pr_warn("module rc: %s is not a regular file\n", path);
        goto out_close_file;
    }

    fsize = i_size_read(file_inode(f));
    if (fsize == 0) {
        pr_warn("module rc: skip empty module rc\n");
        goto out_close_file;
    }

    module_rc_buf = kvmalloc(fsize, GFP_KERNEL);
    if (!module_rc_buf) {
        pr_err("module rc: alloc %zu failed\n", fsize);
        goto out_close_file;
    }

    r = kernel_read(f, module_rc_buf, fsize, &pos);

    if (r <= 0) {
        pr_err("module rc: read failed: %zd\n", r);
        kvfree(module_rc_buf);
        module_rc_buf = NULL;
        goto out_close_file;
    }

    module_rc_len = r;
    pr_info("module rc: loaded %zu bytes from %s\n", module_rc_len, path);

out_close_file:
    filp_close(f, NULL);

out_revert_creds:
    revert_creds(old_cred);
}

static void free_module_rc(void)
{
    kvfree(module_rc_buf);
    module_rc_buf = NULL;
    module_rc_len = 0;
}

// https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/parser.cpp;l=144;drc=61197364367c9e404c7da6900658f1b16c42d0da
// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/file.cpp;l=241-243;drc=61197364367c9e404c7da6900658f1b16c42d0da
// The system will read init.rc file until EOF, whenever read() returns 0,
// so we begin append ksu rc when we meet EOF.

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    ssize_t ret = 0;
    size_t append_count;
    if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
        goto append_ksu_rc;
    if (ksu_rc_pos >= ksu_rc_len && module_rc_pos < module_rc_len)
        goto append_module_rc;

    ret = orig_read(file, buf, count, pos);
    if (ret != 0) {
        return ret;
    }
    if (ksu_rc_pos >= ksu_rc_len && module_rc_pos >= module_rc_len) {
        return ret;
    }
    pr_info("read_proxy: orig read finished, start append rc\n");

append_ksu_rc:
    if (ksu_rc_pos < ksu_rc_len) {
        append_count = ksu_rc_len - ksu_rc_pos;
        if (append_count > count - ret)
            append_count = count - ret;
        // copy_to_user returns the number of bytes that could not be copied
        if (copy_to_user(buf + ret, KERNEL_SU_RC + ksu_rc_pos, append_count)) {
            pr_info("read_proxy: append error, totally appended %ld\n", ksu_rc_pos);
            return ret;
        }
        pr_info("read_proxy: append static %zu\n", append_count);
        ksu_rc_pos += append_count;
        ret += append_count;
        if (ksu_rc_pos == ksu_rc_len)
            pr_info("read_proxy: static append done\n");
    }

append_module_rc:
    if (module_rc_pos < module_rc_len && (size_t)ret < count) {
        append_count = module_rc_len - module_rc_pos;
        if (append_count > count - ret)
            append_count = count - ret;
        if (copy_to_user(buf + ret, module_rc_buf + module_rc_pos, append_count)) {
            pr_info("read_proxy: module append error, totally appended %zd\n", module_rc_pos);
            return ret;
        }
        pr_info("read_proxy: append module %zu\n", append_count);
        module_rc_pos += append_count;
        ret += append_count;
        if (module_rc_pos == (ssize_t)module_rc_len) {
            pr_info("read_proxy: module append done\n");
            free_module_rc();
        }
    }

    return ret;
}

static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
    ssize_t ret = 0;
    size_t append_count;
    if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
        goto append_ksu_rc;
    if (ksu_rc_pos >= ksu_rc_len && module_rc_pos < module_rc_len)
        goto append_module_rc;

    ret = orig_read_iter(iocb, to);
    if (ret != 0) {
        return ret;
    }
    if (ksu_rc_pos >= ksu_rc_len && module_rc_pos >= module_rc_len) {
        return ret;
    }
    pr_info("read_iter_proxy: orig read finished, start append rc\n");

append_ksu_rc:
    if (ksu_rc_pos < ksu_rc_len) {
        // copy_to_iter returns the number of bytes successfully copied
        append_count = copy_to_iter(KERNEL_SU_RC + ksu_rc_pos, ksu_rc_len - ksu_rc_pos, to);
        if (!append_count) {
            pr_info("read_iter_proxy: append error, totally appended %ld\n", ksu_rc_pos);
            return ret;
        }
        pr_info("read_iter_proxy: append static %zu\n", append_count);
        ksu_rc_pos += append_count;
        ret += append_count;
        if (ksu_rc_pos == ksu_rc_len) {
            pr_info("read_iter_proxy: static append done\n");
        }
    }

append_module_rc:
    if (module_rc_pos < module_rc_len) {
        append_count = copy_to_iter(module_rc_buf + module_rc_pos, module_rc_len - module_rc_pos, to);
        if (!append_count) {
            pr_info("read_iter_proxy: module append error, appended %zd\n", module_rc_pos);
            return ret;
        }
        pr_info("read_iter_proxy: append module %zu\n", append_count);
        module_rc_pos += append_count;
        ret += append_count;
        if (module_rc_pos == (ssize_t)module_rc_len) {
            pr_info("read_iter_proxy: module append done\n");
            free_module_rc();
        }
    }
    return ret;
}

static bool is_init_rc(struct file *fp)
{
    if (strcmp(current->comm, "init")) {
        // we are only interest in `init` process
        return false;
    }

    if (!d_is_reg(fp->f_path.dentry)) {
        return false;
    }

    const char *short_name = fp->f_path.dentry->d_name.name;
    if (strcmp(short_name, "init.rc")) {
        // we are only interest `init.rc` file name file
        return false;
    }
    char path[256];
    char *dpath = d_path(&fp->f_path, path, sizeof(path));

    if (IS_ERR(dpath)) {
        return false;
    }

    if (strcmp(dpath, "/system/etc/init/hw/init.rc")) {
        return false;
    }

    return true;
}

static void ksu_install_rc_hook(struct file *file)
{
    if (!is_init_rc(file)) {
        return;
    }

    // we only process the first read
    static bool rc_hooked = false;
    if (rc_hooked) {
        // we don't need these hooks, unregister it!

        return;
    }
    rc_hooked = true;
    stop_init_rc_hook();

    // now we can sure that the init process is reading
    // `/system/etc/init/init.rc`

    load_module_rc_once();

    pr_info("read init.rc, comm: %s, rc_count: %zu, module_rc: %zu\n", current->comm, ksu_rc_len, module_rc_len);

    // Now we need to proxy the read and modify the result!
    // But, we can not modify the file_operations directly, because it's in read-only memory.
    // We just replace the whole file_operations with a proxy one.
    memcpy(&fops_proxy, file->f_op, sizeof(struct file_operations));
    orig_read = file->f_op->read;
    if (orig_read) {
        fops_proxy.read = read_proxy;
    }
    orig_read_iter = file->f_op->read_iter;
    if (orig_read_iter) {
        fops_proxy.read_iter = read_iter_proxy;
    }
    // replace the file_operations
    file->f_op = &fops_proxy;
}

static void ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)
{
    struct file *file = fget(fd);
    if (!file) {
        return;
    }
    ksu_install_rc_hook(file);
    fput(file);
}

static unsigned int volumedown_pressed_count = 0;

static bool is_volumedown_enough(unsigned int count)
{
    return count >= 3;
}

int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value)
{
    if (*type == EV_KEY && *code == KEY_VOLUMEDOWN) {
        int val = *value;
        pr_info("KEY_VOLUMEDOWN val: %d\n", val);
        if (val) {
            // key pressed, count it
            volumedown_pressed_count += 1;
            if (is_volumedown_enough(volumedown_pressed_count)) {
                ksu_stop_input_hook_runtime();
            }
        }
    }

    return 0;
}

bool ksu_is_safe_mode()
{
    static bool safe_mode = false;
    if (safe_mode) {
        // don't need to check again, userspace may call multiple times
        return true;
    }

    if (ksu_late_loaded) {
        return false;
    }

    // stop hook first!
    ksu_stop_input_hook_runtime();

    pr_info("volumedown_pressed_count: %d\n", volumedown_pressed_count);
    if (is_volumedown_enough(volumedown_pressed_count)) {
        // pressed over 3 times
        pr_info("KEY_VOLUMEDOWN pressed max times, safe mode detected!\n");
        safe_mode = true;
        return true;
    }

    return false;
}

void ksu_execve_hook_ksud(const struct pt_regs *regs)
{
    const char __user **filename_user = (const char **)&PT_REGS_PARM1(regs);
    const char __user *const __user *__argv = (const char __user *const __user *)PT_REGS_PARM2(regs);
    struct user_arg_ptr argv = { .ptr.native = __argv };
    char path[32];
    long ret;
    unsigned long addr;
    const char __user *fn;

    if (!filename_user)
        return;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;

    memset(path, 0, sizeof(path));
    ret = strncpy_from_user(path, fn, 32);
    if (ret < 0) {
        pr_err("Access filename failed for execve_handler_pre\n");
        return;
    }

    ksu_handle_execveat_ksud(path, &argv);
}

static long (*orig_sys_read)(const struct pt_regs *regs);
static long ksu_sys_read(const struct pt_regs *regs)
{
    unsigned int fd = PT_REGS_PARM1(regs);
    char __user **buf_ptr = (char __user **)&PT_REGS_PARM2(regs);
    size_t *count_ptr = (size_t *)&PT_REGS_PARM3(regs);

    ksu_handle_sys_read(fd, buf_ptr, count_ptr);
    return orig_sys_read(regs);
}

static long (*orig_sys_fstat)(const struct pt_regs *regs);
static long ksu_sys_fstat(const struct pt_regs *regs)
{
    unsigned int fd = PT_REGS_PARM1(regs);
    void __user *statbuf = (void __user *)PT_REGS_PARM2(regs);
    bool is_rc = false;
    long ret;

    struct file *file = fget(fd);
    if (file) {
        if (is_init_rc(file)) {
            pr_info("stat init.rc");
            is_rc = true;
            load_module_rc_once();
        }
        fput(file);
    }

    ret = orig_sys_fstat(regs);

    if (is_rc) {
        void __user *st_size_ptr = statbuf + offsetof(struct stat, st_size);
        long size, new_size;
        size_t extra = ksu_rc_len + module_rc_len;
        if (!copy_from_user_nofault(&size, st_size_ptr, sizeof(long))) {
            new_size = size + extra;
            pr_info("adding rc len: %ld -> %ld (static=%zu module=%zu)", size, new_size, ksu_rc_len, module_rc_len);
            if (!copy_to_user_nofault(st_size_ptr, &new_size, sizeof(long))) {
                pr_info("added rc len");
            } else {
                pr_err("add rc len failed: statbuf 0x%lx", (unsigned long)st_size_ptr);
            }
        } else {
            pr_err("read statbuf 0x%lx failed", (unsigned long)st_size_ptr);
        }
    }

    return ret;
}

static int input_handle_event_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
    unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
    int *value = (int *)&PT_REGS_CCALL_PARM4(regs);
    return ksu_handle_input_handle_event(type, code, value);
}

static struct kprobe input_event_kp = {
    .symbol_name = "input_event",
    .pre_handler = input_handle_event_handler_pre,
};

static void do_stop_input_hook(struct work_struct *work)
{
    unregister_kprobe(&input_event_kp);
}

static void stop_init_rc_hook()
{
    ksu_syscall_table_unhook(__NR_read);
    ksu_syscall_table_unhook(__NR_fstat);
    pr_info("unregister init_rc syscall hook\n");
}

void ksu_stop_input_hook_runtime(void)
{
    static bool input_hook_stopped = false;
    if (input_hook_stopped) {
        return;
    }
    input_hook_stopped = true;
    bool ret = schedule_work(&stop_input_hook_work);
    pr_info("unregister input kprobe: %d!\n", ret);
}

// ksud: module support
void __init ksu_ksud_init()
{
    int ret;

    ksu_syscall_table_hook(__NR_read, ksu_sys_read, &orig_sys_read);
    ksu_syscall_table_hook(__NR_fstat, ksu_sys_fstat, &orig_sys_fstat);

    ret = register_kprobe(&input_event_kp);
    pr_info("ksud: input_event_kp: %d\n", ret);

    INIT_WORK(&stop_input_hook_work, do_stop_input_hook);
}

void __exit ksu_ksud_exit()
{
    // TODO:
    // this should be done before unregister vfs_read_kp
    // stop_init_rc_hook();
    unregister_kprobe(&input_event_kp);

    if (module_rc_buf) {
        free_module_rc();
    }
}