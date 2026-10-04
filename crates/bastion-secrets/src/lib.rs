use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{fmt, path::Path};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
mod credentials;
mod passwords;
pub use credentials::{CipherContext, Credential, Envelope, KeyRing};
pub use passwords::{hash_password, verify_password};

pub struct Secret(Zeroizing<String>);
impl Secret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn random() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(bytes.as_mut());
        Self::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn hash(&self) -> [u8; 32] {
        hash(self.expose())
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
pub fn hash(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
pub fn matches_hash(expected: &[u8; 32], candidate: &str) -> bool {
    bool::from(expected.ct_eq(&hash(candidate)))
}

/// Refuse symlinks and group/world accessible secrets. M0 is Unix only.
pub fn read_secret_file(path: &Path) -> Result<Secret> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let meta = std::fs::symlink_metadata(path).context("cannot inspect secret file")?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.len() > 128 * 1024 {
        bail!("secret file must be a regular file, <=128 KiB, mode 0600 or stricter");
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.mode() & 0o077 != 0 || opened.uid() != unsafe { libc::geteuid() }
    {
        bail!("secret file must be owned by the current user and mode 0600 or stricter");
    }
    use std::io::Read;
    let mut value = Zeroizing::new(String::new());
    (&mut file)
        .take(128 * 1024 + 1)
        .read_to_string(&mut value)?;
    if value.len() > 128 * 1024 || value.is_empty() {
        bail!("invalid secret file length");
    }
    Ok(Secret(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_are_random_and_redacted() {
        let a = Secret::random();
        let b = Secret::random();
        assert_eq!(a.expose().len(), 43);
        assert_ne!(a.hash(), b.hash());
        assert!(matches_hash(&a.hash(), a.expose()));
        assert!(!matches_hash(&a.hash(), b.expose()));
        assert!(!format!("{a:?}").contains(a.expose()));
    }
}
