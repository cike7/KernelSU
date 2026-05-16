use std::path::Path;
use std::fs::{copy, metadata, File};
use std::io::{ErrorKind, Write};
use anyhow::{Context, Result};
use rustix::fs::{Mode, symlink, unlink};
use rustix::{
    fd::AsFd,
    fs::{Access, CWD, FileType, access, makedev, mkdir, mknodat},
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, UnmountFlags, fsconfig_create,
        fsmount, fsopen, move_mount, unmount,
    },
};

struct AutoUmount {
    mountpoints: Vec<String>,
}

impl Drop for AutoUmount {
    fn drop(&mut self) {
        for mountpoint in self.mountpoints.iter().rev() {
            if let Err(e) = unmount(mountpoint.as_str(), UnmountFlags::DETACH) {
                log::error!("Cannot umount {}: {}", mountpoint, e)
            }
        }
    }
}

fn mount_filesystem(name: &str, mountpoint: &str) -> Result<()> {
    mkdir(mountpoint, Mode::from_raw_mode(0o755)).or_else(|err| match err.kind() {
        ErrorKind::AlreadyExists => Ok(()),
        _ => Err(err),
    })?;
    let fs_fd = fsopen(name, FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_create(fs_fd.as_fd())?;
    let mount_fd = fsmount(
        fs_fd.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?;
    move_mount(
        mount_fd.as_fd(),
        "",
        CWD,
        mountpoint,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}

fn prepare_mount() -> AutoUmount {
    let mut mountpoints = vec![];

    // mount procfs
    match mount_filesystem("proc", "/proc") {
        Ok(_) => mountpoints.push("/proc".to_string()),
        Err(e) => log::error!("Cannot mount procfs: {:?}", e),
    }

    // mount sysfs
    match mount_filesystem("sysfs", "/sys") {
        Ok(_) => mountpoints.push("/sys".to_string()),
        Err(e) => log::error!("Cannot mount sysfs: {:?}", e),
    }

    AutoUmount { mountpoints }
}

fn setup_kmsg() {
    const KMSG: &str = "/dev/kmsg";
    let device = match access(KMSG, Access::EXISTS) {
        Ok(_) => KMSG,
        Err(_) => {
            // try to create it
            mknodat(
                CWD,
                "/kmsg",
                FileType::CharacterDevice,
                0o666.into(),
                makedev(1, 11),
            )
            .ok();
            "/kmsg"
        }
    };

    let _ = kernlog::init_with_device(device);
}

fn unlimit_kmsg() {
    // Disable kmsg rate limiting
    if let Ok(mut rate) = std::fs::File::options()
        .write(true)
        .open("/proc/sys/kernel/printk_devkmsg")
    {
        writeln!(rate, "on").ok();
    }
}

/// 修复版：完善错误日志+检查源文件+确保目标目录可写+处理权限
fn copy_files_to_debug_ramdisk() {
    const SRC_PATH: &str = "/startup.sh";
    const DST_DIR: &str = "/debug_ramdisk";
    const DST_PATH: &str = "/debug_ramdisk/startup.sh";

    // 1. 检查源文件是否存在且可读
    match metadata(SRC_PATH) {
        Err(e) => {
            log::error!("Source file check failed ({}): {}", SRC_PATH, e);
            return;
        }
        Ok(meta) => {
            if !meta.is_file() {
                log::error!("{} is not a regular file", SRC_PATH);
                return;
            }
            // 检查源文件是否可读
            if let Err(e) = File::open(SRC_PATH) {
                log::error!("Cannot read source file {}: {}", SRC_PATH, e);
                return;
            }
        }
    }

    // 2. 确保目标目录存在，且权限正确
    if let Err(e) = mkdir(DST_DIR, Mode::from_raw_mode(0o777)) { // 放宽目录权限便于写入
        match e.kind() {
            ErrorKind::AlreadyExists => {
                // 验证目标目录是否可写
                let test_file = format!("{}/.ksu_test", DST_DIR);
                let writeable = File::create(&test_file).and_then(|mut f| f.write_all(b"test")).is_ok();
                if !writeable {
                    log::error!("Target dir {} exists but is not writable", DST_DIR);
                    // 尝试重新挂载 debug_ramdisk 为可写（关键修复）
                    if let Err(me) = mount_filesystem("tmpfs", DST_DIR) {
                        log::error!("Failed to remount {} as writable: {}", DST_DIR, me);
                    } else {
                        log::info!("Remounted {} as writable tmpfs", DST_DIR);
                    }
                } else {
                    // 清理测试文件
                    let _ = std::fs::remove_file(&test_file);
                }
            }
            _ => {
                log::error!("Cannot create {}: {}", DST_DIR, e);
                return;
            }
        }
    }

    // 3. 执行复制（带详细错误上下文）
    match copy(SRC_PATH, DST_PATH) {
        Ok(bytes) => log::info!("Successfully copied {} to {} ({} bytes)", SRC_PATH, DST_PATH, bytes),
        Err(e) => {
            log::error!("Copy failed ({} -> {}): {}", SRC_PATH, DST_PATH, e);
            // 补充错误类型分析
            match e.kind() {
                ErrorKind::PermissionDenied => log::error!("Reason: Permission denied (check src/dst permissions or fs read-only)"),
                ErrorKind::NotFound => log::error!("Reason: Source or target path not found"),
                ErrorKind::ReadOnlyFilesystem => log::error!("Reason: Target filesystem is read-only (need remount rw)"),
                _ => log::error!("Reason: Other IO error"),
            }
        }
    }
}

pub fn init() -> Result<()> {
    // Setup kernel log first
    setup_kmsg();

    log::info!("Hello, KernelSU!");

    // mount /proc and /sys to access kernel interface
    let _dontdrop = prepare_mount();

    // This relies on the fact that we have /proc mounted
    unlimit_kmsg();

    // TODO test
    // 优先确保 /debug_ramdisk 挂载为可写（新增：解决只读问题）
    if let Err(e) = mount_filesystem("tmpfs", "/debug_ramdisk") {
        log::warn!("Failed to mount /debug_ramdisk as tmpfs: {}", e);
    }

    // 自定义文件复制到 /debug_ramdisk（借鉴 Magisk 方案）
    copy_files_to_debug_ramdisk();

    if ksuinit::has_kernelsu() {
        log::info!("KernelSU may be already loaded in kernel, skip!");
    } else {
        log::info!("Loading kernelsu.ko..");
        if let Err(e) = load_module_from_path("/kernelsu.ko") {
            log::error!("Cannot load kernelsu.ko: {:?}", e);
        }
    }

    // And now we should prepare the real init to transfer control to it
    unlink("/init")?;

    let real_init = match access("/init.real", Access::EXISTS) {
        Ok(_) => "init.real",
        Err(_) => "/system/bin/init",
    };

    log::info!("init is {}", real_init);
    symlink(real_init, "/init")?;

    Ok(())
}

fn load_module_from_path(path: &str) -> Result<()> {
    anyhow::ensure!(rustix::process::getpid().is_init(), "Invalid process");
    let buffer = std::fs::read(path).with_context(|| format!("Cannot read file {}", path))?;
    ksuinit::load_module(&buffer)
}
