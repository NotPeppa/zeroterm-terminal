use crate::read_secret_file;
use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    Password {
        password: String,
    },
    PrivateKey {
        key_pem: String,
        passphrase: Option<String>,
    },
}
impl Credential {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Password { .. } => "password",
            Self::PrivateKey { .. } => "private_key",
        }
    }
    pub fn validate_lengths(&self) -> bool {
        match self {
            Self::Password { password } => !password.is_empty() && password.len() <= 16384,
            Self::PrivateKey {
                key_pem,
                passphrase,
            } => {
                !key_pem.is_empty()
                    && key_pem.len() <= 128 * 1024
                    && passphrase.as_ref().is_none_or(|s| s.len() <= 16384)
            }
        }
    }
}
#[derive(Clone)]
pub struct CipherContext {
    pub server_id: String,
    pub credential_id: Uuid,
    pub kind: String,
    pub revision: i64,
}
impl CipherContext {
    fn aad(&self, purpose: &str) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            purpose,
            &self.server_id,
            self.credential_id,
            &self.kind,
            self.revision,
        ))?)
    }
}
#[derive(Clone)]
pub struct Envelope {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
    pub key_version: i64,
}
pub struct KeyRing {
    active: i64,
    keys: BTreeMap<i64, Zeroizing<[u8; 32]>>,
}
impl KeyRing {
    pub fn from_files(active: i64, files: &BTreeMap<i64, PathBuf>) -> Result<Self> {
        let mut keys = BTreeMap::new();
        for (version, path) in files {
            if *version < 1 {
                bail!("invalid KEK version");
            }
            let input = read_secret_file(path)?;
            let bytes = Zeroizing::new(
                URL_SAFE_NO_PAD.decode(input.expose().trim_end_matches(['\r', '\n']))?,
            );
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("KEK must contain 32 bytes"))?;
            keys.insert(*version, Zeroizing::new(key));
        }
        if !keys.contains_key(&active) {
            bail!("active KEK is missing");
        }
        Ok(Self { active, keys })
    }
    pub fn seal(&self, context: &CipherContext, value: &Credential) -> Result<Envelope> {
        if context.kind != value.kind() || context.revision < 1 || !value.validate_lengths() {
            bail!("invalid credential context");
        }
        let plaintext = Zeroizing::new(serde_json::to_vec(value)?);
        let mut dek = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 24];
        let mut wrap_nonce = [0u8; 24];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(dek.as_mut());
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut wrap_nonce);
        let ciphertext = XChaCha20Poly1305::new_from_slice(dek.as_ref())
            .unwrap()
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plaintext,
                    aad: &context.aad("zt-credential-v1")?,
                },
            )
            .map_err(|_| anyhow::anyhow!("credential encryption failed"))?;
        let wrapped_dek = XChaCha20Poly1305::new_from_slice(self.keys[&self.active].as_ref())
            .unwrap()
            .encrypt(
                (&wrap_nonce).into(),
                Payload {
                    msg: dek.as_ref(),
                    aad: &context.aad("zt-credential-wrap-v1")?,
                },
            )
            .map_err(|_| anyhow::anyhow!("DEK wrapping failed"))?;
        Ok(Envelope {
            ciphertext,
            nonce: nonce.to_vec(),
            wrapped_dek,
            wrap_nonce: wrap_nonce.to_vec(),
            key_version: self.active,
        })
    }
    pub fn open(&self, context: &CipherContext, envelope: &Envelope) -> Result<Credential> {
        let key = self
            .keys
            .get(&envelope.key_version)
            .ok_or_else(|| anyhow::anyhow!("credential KEK version is unavailable"))?;
        if envelope.nonce.len() != 24
            || envelope.wrap_nonce.len() != 24
            || envelope.wrapped_dek.len() != 48
            || envelope.ciphertext.len() > 256 * 1024
        {
            bail!("invalid credential envelope");
        }
        let dek = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(key.as_ref())
                .unwrap()
                .decrypt(
                    envelope.wrap_nonce.as_slice().into(),
                    Payload {
                        msg: &envelope.wrapped_dek,
                        aad: &context.aad("zt-credential-wrap-v1")?,
                    },
                )
                .map_err(|_| anyhow::anyhow!("credential integrity failure"))?,
        );
        let cipher =
            XChaCha20Poly1305::new_from_slice(&dek).map_err(|_| anyhow::anyhow!("invalid DEK"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    envelope.nonce.as_slice().into(),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &context.aad("zt-credential-v1")?,
                    },
                )
                .map_err(|_| anyhow::anyhow!("credential integrity failure"))?,
        );
        let value: Credential = serde_json::from_slice(&plaintext)?;
        if value.kind() != context.kind || !value.validate_lengths() {
            bail!("invalid decrypted credential");
        }
        Ok(value)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelopes_bind_identity_revision_kind_and_detect_tampering() {
        let ring = KeyRing {
            active: 1,
            keys: BTreeMap::from([(1, Zeroizing::new([7; 32]))]),
        };
        let context = CipherContext {
            server_id: "server".into(),
            credential_id: Uuid::new_v4(),
            kind: "password".into(),
            revision: 1,
        };
        let value = Credential::Password {
            password: "SECRET marker with spaces ".into(),
        };
        let envelope = ring.seal(&context, &value).unwrap();
        assert!(!envelope.ciphertext.windows(6).any(|w| w == b"SECRET"));
        match ring.open(&context, &envelope).unwrap() {
            Credential::Password { ref password } => {
                assert_eq!(password, "SECRET marker with spaces ")
            }
            _ => panic!(),
        }
        let mut other = context.clone();
        other.credential_id = Uuid::new_v4();
        assert!(ring.open(&other, &envelope).is_err());
        other = context.clone();
        other.revision += 1;
        assert!(ring.open(&other, &envelope).is_err());
        other = context.clone();
        other.kind = "private_key".into();
        assert!(ring.open(&other, &envelope).is_err());
        other = context.clone();
        other.server_id = "other".into();
        assert!(ring.open(&other, &envelope).is_err());
        let mut broken = envelope;
        broken.ciphertext[0] ^= 1;
        assert!(ring.open(&context, &broken).is_err());
    }
}
