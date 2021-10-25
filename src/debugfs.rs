use nix::{
    mount::{mount, MsFlags},
    unistd,
};
use proc_mounts::MountIter;
use slog::info;
use std::{fs::create_dir_all, path::Path};

use crate::error::OxidebpfError;
use crate::LOGGER;

/// Returns the path where `debugfs` is mounted or None if unable to locate.
pub(crate) fn get_debugfs_mount_point() -> Option<String> {
    let mount_iter = match MountIter::new() {
        Ok(mount_iter) => mount_iter,
        Err(e) => {
            info!(LOGGER.0, "failed to create MountIter: {}", e.to_string());
            return None;
        }
    };

    mount_iter
        .flatten()
        .find(|m| m.fstype == "debugfs")
        .map(|m| m.dest.into_os_string().into_string().unwrap_or_default())
}

/// Mounts debugfs to the specified location if it hasn't been mounted already.
pub(crate) fn mount_debugfs_if_missing(mount_location: &str) -> Result<(), OxidebpfError> {
    if get_debugfs_mount_point().is_some() {
        return Ok(());
    }

    let path = Path::new(mount_location);
    if !path.exists() {
        // creation is best effort - chown may fail on some paths, such as `/sys/kernel/debug`
        if let Err(e) = create_dir_all(path)
            .map_err(|_e| OxidebpfError::FileIOError)
            .and_then(|_| {
                unistd::chown(path, Some(unistd::getuid()), Some(unistd::getgid())).map_err(|_| {
                    OxidebpfError::LinuxError(
                        "chown".to_string(),
                        nix::errno::from_i32(nix::errno::errno()),
                    )
                })
            })
        {
            info!(
                LOGGER.0,
                "failure to create mount point directory: {}",
                e.to_string()
            );
        }
    }

    // mount with the default debugfs mount options
    mount(
        Some("debugfs"),
        mount_location,
        Some("debugfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RELATIME,
        None::<&str>,
    )
    .map_err(|_e| {
        OxidebpfError::LinuxError(
            "mount(debugfs)".to_string(),
            nix::errno::from_i32(nix::errno::errno()),
        )
    })?;

    Ok(())
}
