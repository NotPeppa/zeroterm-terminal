//! RFC-006 §7.1 native SSH gateway configuration. Absent `BASTION_NATIVE_SSH_LISTEN` keeps native off.
use anyhow::{bail, Context, Result};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub(crate) struct NativeSettings {
    pub listen: SocketAddr,
    pub public_host: String,
    pub public_port: u16,
    pub host_key: ssh_key::PrivateKey,
    /// Connections accepted but not yet authenticated (RFC-006 §4.2).
    pub max_unauthenticated: usize,
}
impl NativeSettings {
    /// Gateway host key as the single `ssh-ed25519 AAAA…` line clients pin (no comment).
    pub fn public_key(&self) -> Result<String> {
        let mut public = self.host_key.public_key().clone();
        public.set_comment("");
        Ok(public.to_openssh()?)
    }
}
/// Default host key location: `secrets/ssh_host_ed25519_key` beside the configuration file
/// (`/etc/zeroterm-bastion/secrets/…` in Docker). Never generated here; a missing key refuses startup.
pub(crate) fn host_key_path(config: &Path, env: &impl Fn(&str) -> Option<String>) -> PathBuf {
    env("BASTION_NATIVE_SSH_HOST_KEY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            config
                .parent()
                .unwrap_or(Path::new("."))
                .join("secrets/ssh_host_ed25519_key")
        })
}
pub(crate) fn load(
    config: &Path,
    origin_host: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<NativeSettings>> {
    let value = |name: &str| env(name).filter(|v| !v.is_empty());
    let Some(listen) = value("BASTION_NATIVE_SSH_LISTEN") else {
        for name in [
            "BASTION_NATIVE_SSH_PUBLIC_HOST",
            "BASTION_NATIVE_SSH_PUBLIC_PORT",
            "BASTION_NATIVE_SSH_MAX_UNAUTHENTICATED",
        ] {
            if value(name).is_some() {
                bail!("{name} requires BASTION_NATIVE_SSH_LISTEN");
            }
        }
        return Ok(None);
    };
    let listen: SocketAddr = listen
        .parse()
        .context("BASTION_NATIVE_SSH_LISTEN must be ip:port")?;
    if listen.port() == 0 {
        bail!("BASTION_NATIVE_SSH_LISTEN needs an explicit port");
    }
    let public_host = value("BASTION_NATIVE_SSH_PUBLIC_HOST").unwrap_or_else(|| origin_host.into());
    if !bastion_api::valid_host(&public_host) {
        bail!("BASTION_NATIVE_SSH_PUBLIC_HOST must be a host name or IP address");
    }
    let public_port = match value("BASTION_NATIVE_SSH_PUBLIC_PORT") {
        Some(port) => port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .context("BASTION_NATIVE_SSH_PUBLIC_PORT must be 1..65535")?,
        None => listen.port(),
    };
    let max_unauthenticated = match value("BASTION_NATIVE_SSH_MAX_UNAUTHENTICATED") {
        Some(count) => count
            .parse::<usize>()
            .ok()
            .filter(|count| (1..=1024).contains(count))
            .context("BASTION_NATIVE_SSH_MAX_UNAUTHENTICATED must be 1..1024")?,
        None => 64,
    };
    let path = host_key_path(config, &env);
    let host_key = read_host_key(&path)?;
    Ok(Some(NativeSettings {
        listen,
        public_host,
        public_port,
        host_key,
        max_unauthenticated,
    }))
}
/// One unencrypted Ed25519 key, owned by the service uid, mode 0600, no symlinks.
pub(crate) fn read_host_key(path: &Path) -> Result<ssh_key::PrivateKey> {
    crate::production::private_path(path, false)
        .context("native SSH host key must be a private 0600 file")?;
    let pem = bastion_secrets::read_secret_file(path)?;
    let key = ssh_key::PrivateKey::from_openssh(pem.expose())
        .map_err(|_| anyhow::anyhow!("native SSH host key is not an OpenSSH private key"))?;
    if key.is_encrypted() || key.algorithm() != ssh_key::Algorithm::Ed25519 {
        bail!("native SSH host key must be one unencrypted Ed25519 key");
    }
    Ok(key)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{collections::HashMap, os::unix::fs::PermissionsExt};
    fn key_file(dir: &Path, mode: u32) -> PathBuf {
        let secrets = dir.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]));
        let path = secrets.join("ssh_host_ed25519_key");
        std::fs::write(
            &path,
            key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }
    fn env(values: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }
    #[test]
    fn native_gateway_is_off_by_default_and_needs_a_private_ed25519_key() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("production.toml");
        assert!(load(&config, "bastion.example.com", env(&[]))
            .unwrap()
            .is_none());
        assert!(load(
            &config,
            "h",
            env(&[("BASTION_NATIVE_SSH_PUBLIC_PORT", "22")])
        )
        .is_err());
        let listen = [("BASTION_NATIVE_SSH_LISTEN", "0.0.0.0:2222")];
        assert!(
            load(&config, "h", env(&listen)).is_err(),
            "missing key refuses"
        );
        let path = key_file(root.path(), 0o644);
        assert!(
            load(&config, "h", env(&listen)).is_err(),
            "readable key refuses"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let settings = load(&config, "bastion.example.com", env(&listen))
            .unwrap()
            .unwrap();
        assert_eq!(
            (settings.public_host.as_str(), settings.public_port),
            ("bastion.example.com", 2222)
        );
        assert_eq!(settings.max_unauthenticated, 64);
        let line = settings.public_key().unwrap();
        assert!(
            line.starts_with("ssh-ed25519 AAAA") && line.split(' ').count() == 2,
            "{line}"
        );
        let mapped = load(
            &config,
            "h",
            env(&[
                ("BASTION_NATIVE_SSH_LISTEN", "0.0.0.0:2222"),
                ("BASTION_NATIVE_SSH_PUBLIC_HOST", "ssh.example.com"),
                ("BASTION_NATIVE_SSH_PUBLIC_PORT", "22"),
            ]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            (mapped.public_host.as_str(), mapped.public_port),
            ("ssh.example.com", 22)
        );
        for (name, bad) in [
            ("BASTION_NATIVE_SSH_LISTEN", "2222"),
            ("BASTION_NATIVE_SSH_LISTEN", "0.0.0.0:0"),
            ("BASTION_NATIVE_SSH_PUBLIC_PORT", "0"),
            ("BASTION_NATIVE_SSH_PUBLIC_HOST", "bad host"),
            ("BASTION_NATIVE_SSH_MAX_UNAUTHENTICATED", "0"),
            ("BASTION_NATIVE_SSH_MAX_UNAUTHENTICATED", "many"),
        ] {
            let mut values = vec![("BASTION_NATIVE_SSH_LISTEN", "0.0.0.0:2222")];
            values.retain(|(k, _)| *k != name);
            values.push((name, bad));
            assert!(load(&config, "h", env(&values)).is_err(), "{name}={bad}");
        }
        std::fs::write(&path, "not a key").unwrap();
        assert!(read_host_key(&path).is_err());
    }
}
