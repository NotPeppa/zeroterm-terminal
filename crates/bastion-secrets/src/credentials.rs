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
impl KeyRing {
    /// Authenticate the existing credential, then rotate only its KEK envelope.
    /// Identity, revision, ciphertext and data nonce are preserved exactly.
    pub fn rewrap_credential_dek(
        &self,
        context: &CipherContext,
        envelope: &Envelope,
    ) -> Result<Envelope> {
        if context.revision < 1 {
            bail!("invalid credential context");
        }
        // Validation uses the existing wire/AAD contract. Credential zeroizes on drop.
        drop(self.open(context, envelope)?);
        let old_key = self
            .keys
            .get(&envelope.key_version)
            .ok_or_else(|| anyhow::anyhow!("credential KEK version is unavailable"))?;
        let aad = context.aad("zt-credential-wrap-v1")?;
        let dek = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(old_key.as_ref())
                .expect("32-byte KEK")
                .decrypt(
                    envelope.wrap_nonce.as_slice().into(),
                    Payload {
                        msg: &envelope.wrapped_dek,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("credential integrity failure"))?,
        );
        let mut wrap_nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut wrap_nonce);
        let wrapped_dek = XChaCha20Poly1305::new_from_slice(self.keys[&self.active].as_ref())
            .expect("32-byte KEK")
            .encrypt(
                (&wrap_nonce).into(),
                Payload {
                    msg: &dek,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("DEK wrapping failed"))?;
        Ok(Envelope {
            ciphertext: envelope.ciphertext.clone(),
            nonce: envelope.nonce.clone(),
            wrapped_dek,
            wrap_nonce: wrap_nonce.to_vec(),
            key_version: self.active,
        })
    }

    pub fn new_recording_dek(
        &self,
        context: &crate::recording::RecordingContext,
    ) -> Result<(
        crate::recording::RecordingKey,
        crate::recording::RecordingEnvelope,
    )> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(bytes.as_mut());
        let key = crate::recording::RecordingKey(bytes);
        let envelope = self.wrap_recording_dek(context, &key)?;
        Ok((key, envelope))
    }

    pub fn wrap_recording_dek(
        &self,
        context: &crate::recording::RecordingContext,
        key: &crate::recording::RecordingKey,
    ) -> Result<crate::recording::RecordingEnvelope> {
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let wrapped_dek = XChaCha20Poly1305::new_from_slice(self.keys[&self.active].as_ref())
            .expect("32-byte KEK")
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: key.0.as_ref(),
                    aad: &context.aad()?,
                },
            )
            .map_err(|_| anyhow::Error::new(crate::recording::RecordingError::Integrity))?;
        Ok(crate::recording::RecordingEnvelope {
            wrapped_dek,
            wrap_nonce: nonce.to_vec(),
            key_version: self.active,
        })
    }

    pub fn open_recording_dek(
        &self,
        context: &crate::recording::RecordingContext,
        envelope: &crate::recording::RecordingEnvelope,
    ) -> Result<crate::recording::RecordingKey> {
        use crate::recording::{RecordingError, RecordingKey};
        let kek = self
            .keys
            .get(&envelope.key_version)
            .ok_or_else(|| anyhow::Error::new(RecordingError::UnknownKey(envelope.key_version)))?;
        if envelope.wrap_nonce.len() != 24 || envelope.wrapped_dek.len() != 48 {
            bail!(RecordingError::Invalid("malformed wrapped recording DEK"));
        }
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(kek.as_ref())
                .expect("32-byte KEK")
                .decrypt(
                    envelope.wrap_nonce.as_slice().into(),
                    Payload {
                        msg: &envelope.wrapped_dek,
                        aad: &context.aad()?,
                    },
                )
                .map_err(|_| anyhow::Error::new(RecordingError::Integrity))?,
        );
        let mut bytes = Zeroizing::new([0u8; 32]);
        if plaintext.len() != bytes.len() {
            bail!(RecordingError::Invalid("recording DEK must be 32 bytes"));
        }
        bytes.copy_from_slice(&plaintext);
        Ok(RecordingKey(bytes))
    }

    /// Rotate only the KEK envelope; the recording DEK, prefix and file do not change.
    pub fn rewrap_recording_dek(
        &self,
        context: &crate::recording::RecordingContext,
        envelope: &crate::recording::RecordingEnvelope,
    ) -> Result<crate::recording::RecordingEnvelope> {
        let key = self.open_recording_dek(context, envelope)?;
        self.wrap_recording_dek(context, &key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::{
        RecordingContext, RecordingEnvelope, RecordingError, RecordingHeader, RecordingReader,
        RecordingWriter,
    };

    #[test]
    fn credential_dek_rewrap_preserves_payload_and_authenticates_before_rotation() {
        let old = KeyRing {
            active: 1,
            keys: BTreeMap::from([(1, Zeroizing::new([7; 32]))]),
        };
        let rotating = KeyRing {
            active: 2,
            keys: BTreeMap::from([(1, Zeroizing::new([7; 32])), (2, Zeroizing::new([9; 32]))]),
        };
        let new = KeyRing {
            active: 2,
            keys: BTreeMap::from([(2, Zeroizing::new([9; 32]))]),
        };
        for value in [
            Credential::Password {
                password: " SECRET unchanged ".into(),
            },
            Credential::PrivateKey {
                key_pem: "PRIVATE KEY unchanged".into(),
                passphrase: Some(" unchanged ".into()),
            },
        ] {
            let context = CipherContext {
                server_id: "server".into(),
                credential_id: Uuid::new_v4(),
                kind: value.kind().into(),
                revision: 17,
            };
            let envelope = old.seal(&context, &value).unwrap();
            let original = envelope.clone();
            let rotated = rotating.rewrap_credential_dek(&context, &envelope).unwrap();
            assert_eq!(rotated.ciphertext, envelope.ciphertext);
            assert_eq!(rotated.nonce, envelope.nonce);
            assert_eq!(rotated.key_version, 2);
            assert_ne!(rotated.wrap_nonce, envelope.wrap_nonce);
            assert_ne!(rotated.wrapped_dek, envelope.wrapped_dek);
            let opened = new.open(&context, &rotated).unwrap();
            let expected = Zeroizing::new(serde_json::to_vec(&value).unwrap());
            let actual = Zeroizing::new(serde_json::to_vec(&opened).unwrap());
            assert_eq!(*actual, *expected);
            assert_eq!(context.revision, 17);
            assert_eq!(original.ciphertext, envelope.ciphertext);
            assert_eq!(original.nonce, envelope.nonce);
            assert_eq!(original.wrapped_dek, envelope.wrapped_dek);
            assert_eq!(original.wrap_nonce, envelope.wrap_nonce);
            assert_eq!(original.key_version, envelope.key_version);
            assert!(new.open(&context, &envelope).is_err());
            assert!(old.open(&context, &rotated).is_err());
            assert!(new.rewrap_credential_dek(&context, &envelope).is_err());
            for field in 0..4 {
                let mut changed = context.clone();
                match field {
                    0 => changed.server_id = "other".into(),
                    1 => changed.credential_id = Uuid::new_v4(),
                    2 => changed.kind = "other".into(),
                    _ => changed.revision += 1,
                }
                assert!(rotating.rewrap_credential_dek(&changed, &envelope).is_err());
            }
            for field in 0..4 {
                let mut corrupted = envelope.clone();
                match field {
                    0 => corrupted.ciphertext[0] ^= 1,
                    1 => corrupted.nonce[0] ^= 1,
                    2 => corrupted.wrapped_dek[0] ^= 1,
                    _ => corrupted.wrap_nonce[0] ^= 1,
                }
                assert!(rotating
                    .rewrap_credential_dek(&context, &corrupted)
                    .is_err());
            }
            let mut changed = context.clone();
            changed.revision = 0;
            assert!(rotating.rewrap_credential_dek(&changed, &envelope).is_err());
            let again = new.rewrap_credential_dek(&context, &rotated).unwrap();
            assert_eq!(again.ciphertext, rotated.ciphertext);
            assert_eq!(again.nonce, rotated.nonce);
            assert_ne!(again.wrap_nonce, rotated.wrap_nonce);
            assert!(new.open(&context, &again).is_ok());
        }
    }

    #[test]
    fn recording_keys_bind_server_identity_and_purpose_and_rewrap_without_file_changes() {
        let old = KeyRing {
            active: 1,
            keys: BTreeMap::from([(1, Zeroizing::new([7; 32]))]),
        };
        let rotating = KeyRing {
            active: 2,
            keys: BTreeMap::from([(1, Zeroizing::new([7; 32])), (2, Zeroizing::new([9; 32]))]),
        };
        let new = KeyRing {
            active: 2,
            keys: BTreeMap::from([(2, Zeroizing::new([9; 32]))]),
        };
        let context = RecordingContext::new("server", Uuid::new_v4());
        let (key, envelope) = old.new_recording_dek(&context).unwrap();
        assert_eq!(envelope.wrapped_dek.len(), 48);
        assert_eq!(envelope.wrap_nonce.len(), 24);
        assert_eq!(envelope.key_version, 1);
        assert_eq!(
            *old.open_recording_dek(&context, &envelope).unwrap().0,
            *key.0
        );
        let mut changed = context.clone();
        changed.server_id = "other".into();
        assert!(old.open_recording_dek(&changed, &envelope).is_err());
        changed = context.clone();
        changed.recording_id = Uuid::new_v4();
        assert!(old.open_recording_dek(&changed, &envelope).is_err());
        assert!(matches!(
            new.open_recording_dek(&context, &envelope)
                .unwrap_err()
                .downcast_ref::<RecordingError>(),
            Some(RecordingError::UnknownKey(1))
        ));
        for field in [0, 1] {
            let mut corrupt = envelope.clone();
            if field == 0 {
                corrupt.wrapped_dek[0] ^= 1;
            } else {
                corrupt.wrap_nonce[0] ^= 1;
            }
            assert!(matches!(
                old.open_recording_dek(&context, &corrupt)
                    .unwrap_err()
                    .downcast_ref::<RecordingError>(),
                Some(RecordingError::Integrity)
            ));
        }
        let mut malformed = envelope.clone();
        malformed.wrapped_dek.pop();
        assert!(old.open_recording_dek(&context, &malformed).is_err());
        malformed = envelope.clone();
        malformed.wrap_nonce.pop();
        assert!(old.open_recording_dek(&context, &malformed).is_err());
        let credential_context = CipherContext {
            server_id: "server".into(),
            credential_id: context.recording_id,
            kind: "password".into(),
            revision: 1,
        };
        let credential = old
            .seal(
                &credential_context,
                &Credential::Password {
                    password: "secret".into(),
                },
            )
            .unwrap();
        let swapped = RecordingEnvelope {
            wrapped_dek: credential.wrapped_dek.clone(),
            wrap_nonce: credential.wrap_nonce.clone(),
            key_version: 1,
        };
        assert!(old.open_recording_dek(&context, &swapped).is_err());
        let header = RecordingHeader::new(context.recording_id);
        let mut writer = RecordingWriter::new(Vec::new(), header.clone(), key).unwrap();
        writer.append_ndjson(b"{\"seq\":0,\"elapsed_us\":0,\"type\":\"meta\",\"format_version\":1,\"term\":\"xterm\",\"cols\":80,\"rows\":24}\n{\"seq\":1,\"elapsed_us\":1,\"type\":\"end\",\"reason\":\"closed\"}\n").unwrap();
        let file = writer.finish().unwrap();
        let before = file.clone();
        let rewrapped = rotating.rewrap_recording_dek(&context, &envelope).unwrap();
        assert_eq!(rewrapped.key_version, 2);
        assert_ne!(rewrapped.wrap_nonce, envelope.wrap_nonce);
        let key = new.open_recording_dek(&context, &rewrapped).unwrap();
        let mut reader = RecordingReader::new(std::io::Cursor::new(&file), &header, key).unwrap();
        assert!(reader.next_chunk().unwrap().is_some());
        assert!(reader.next_chunk().unwrap().is_none());
        assert_eq!(before, file);
        assert!(new.rewrap_recording_dek(&context, &envelope).is_err());
    }

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
