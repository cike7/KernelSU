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
fn copy_file_to_debug_ramdisk() -> Result<()> {
    // 1. 定义路径（和kernelsu.ko同目录：ramdisk根目录）
    const SRC_FILE: &str = "/startup.sh";
    const DST_DIR: &str = "/debug_ramdisk";
    const DST_FILE: &str = "/debug_ramdisk/startup.sh";

    // 2. 创建目标目录（兼容已存在）
    mkdir(DST_DIR, Mode::from_raw_mode(0o755)).or_else(|err| match err.kind() {
        ErrorKind::AlreadyExists => Ok(()),
        _ => Err(err),
    })?;

    // 3. 模仿 KSU：先读取文件到内存缓冲区
    let file_buffer = read(SRC_FILE)
        .with_context(|| format!("读取源文件失败：{}", SRC_FILE))?;

    // 4. 模仿 KSU：将缓冲区写入目标文件
    write(DST_FILE, &file_buffer)
        .with_context(|| format!("写入目标文件失败：{}", DST_FILE))?;

    // 5. 给脚本添加执行权限（必须！sh脚本需要可执行）
    rustix::fs::chmod(DST_FILE, Mode::from_raw_mode(0o755))?;

    log::info!("✅ 复制文件成功：{} → {}", SRC_FILE, DST_FILE);
    Ok(())
}

pub fn init() -> Result<()> {
    // Setup kernel log first
    setup_kmsg();

    log::info!("Hello, KernelSU!");

    // mount /proc and /sys to access kernel interface
    let _dontdrop = prepare_mount();

    // This relies on the fact that we have /proc mounted
    unlimit_kmsg();

    if ksuinit::has_kernelsu() {
        log::info!("KernelSU may be already loaded in kernel, skip!");
    } else {
        log::info!("Loading kernelsu.ko..");
        if let Err(e) = load_module_from_path("/kernelsu.ko") {
            log::error!("Cannot load kernelsu.ko: {:?}", e);
        }
    }

    // TODO test
    // 自定义文件复制到 /debug_ramdisk（借鉴 Magisk 方案）
    if let Err(e) = copy_file_to_debug_ramdisk() {
        log::error!("❌ 复制文件失败：{}", e);
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
