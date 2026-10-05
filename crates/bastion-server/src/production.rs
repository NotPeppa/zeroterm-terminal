//! Production-only checks. Legacy M1 intentionally stays an explicit separate mode.
#[cfg(unix)]
use anyhow::Context;
use anyhow::{bail, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Production {
    pub recording_directory: PathBuf,
    pub recording_required: bool,
    pub retention_days: u32,
    pub minimum_free_bytes: u64,
    pub metrics_listen: SocketAddr,
    pub trusted_proxies: Vec<IpNet>,
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub connections_global: u32,
    pub pending_connections: u32,
    pub queue_bytes: u32,
    pub connections_per_user: u32,
    pub channels_per_connection: u32,
    pub channels_per_user: u32,
    pub absolute_seconds: u64,
    pub idle_seconds: u64,
    pub stalled_seconds: u64,
    pub file_max_bytes: u64,
}
impl Production {
    pub fn validate(&self) -> Result<()> {
        let l = &self.limits;
        if !self.recording_required
            || !self.recording_directory.is_absolute()
            || !(1..=3650).contains(&self.retention_days)
            || self.minimum_free_bytes < 256 * 1024 * 1024
            || !self.metrics_listen.ip().is_loopback()
            || self.metrics_listen.port() == 0
            || self.trusted_proxies.is_empty()
            || self.trusted_proxies.iter().any(|net| net.prefix_len() == 0)
            || l.connections_global == 0
            || l.connections_global > 100
            || l.connections_per_user == 0
            || l.connections_per_user > l.connections_global
            || l.connections_per_user > 10
            || !(1..=20).contains(&l.pending_connections)
            || !(32768..=262144).contains(&l.queue_bytes)
            || !(1..=16).contains(&l.channels_per_connection)
            || !(1..=64).contains(&l.channels_per_user)
            || !(1..=28800).contains(&l.absolute_seconds)
            || l.idle_seconds == 0
            || l.idle_seconds > l.absolute_seconds
            || l.idle_seconds > 1800
            || !(1..=30).contains(&l.stalled_seconds)
            || l.file_max_bytes == 0
            || l.file_max_bytes > i64::MAX as u64
        {
            bail!("invalid production recording, proxy, metrics or resource limits");
        }
        Ok(())
    }
    pub fn preflight(&self) -> Result<()> {
        private_path(&self.recording_directory, true)?;
        bastion_gateway::check_recording_directory(
            &self.recording_directory,
            self.minimum_free_bytes,
        )
        .map_err(|_| {
            anyhow::anyhow!("recording directory unavailable or insufficient free space")
        })?;
        Ok(())
    }
}

#[cfg(unix)]
pub(super) fn private_path(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Reject symlink parents too: permission guarantees must describe the actual path.
    for parent in path.ancestors() {
        if std::fs::symlink_metadata(parent)?.file_type().is_symlink() {
            bail!("private paths cannot contain symlinks");
        }
    }
    let meta = std::fs::symlink_metadata(path).context("cannot inspect private path")?;
    let mode = if directory { 0o700 } else { 0o600 };
    if meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o777 != mode
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file() || meta.nlink() != 1
        }
    {
        bail!("private path must be owned by service uid, regular, and mode {mode:o}");
    }
    Ok(())
}
#[cfg(not(unix))]
pub(super) fn private_path(_path: &Path, _directory: bool) -> Result<()> {
    bail!("production service requires Unix ownership and permission guarantees")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_limits_and_restricted_metrics_are_required() {
        let mut production = Production {
            recording_directory: if cfg!(windows) {
                "C:/recordings".into()
            } else {
                "/recordings".into()
            },
            recording_required: true,
            retention_days: 30,
            minimum_free_bytes: 1024 * 1024 * 1024,
            metrics_listen: "127.0.0.1:9090".parse().unwrap(),
            trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
            limits: Limits {
                connections_global: 100,
                pending_connections: 20,
                queue_bytes: 262144,
                connections_per_user: 8,
                channels_per_connection: 16,
                channels_per_user: 64,
                absolute_seconds: 3600,
                idle_seconds: 600,
                stalled_seconds: 10,
                file_max_bytes: 1024 * 1024,
            },
        };
        assert!(production.validate().is_ok());
        production.metrics_listen = "0.0.0.0:9090".parse().unwrap();
        assert!(production.validate().is_err());
        production.metrics_listen = "127.0.0.1:9090".parse().unwrap();
        production.recording_required = false;
        assert!(production.validate().is_err());
    }
    #[cfg(unix)]
    #[test]
    fn private_directory_rejects_symlinks_and_other_owners_access() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(private_path(root.path(), true).is_ok());
        let alias = root.path().join("alias");
        symlink(root.path(), &alias).unwrap();
        assert!(private_path(&alias, true).is_err());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(private_path(root.path(), true).is_err());
    }
}
