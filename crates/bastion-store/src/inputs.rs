use crate::StoreResult;
use bastion_domain::{ErrorCode, RdpSecurity, TargetProtocol};
use bastion_secrets::Credential;
use serde::{Deserialize, Deserializer};
pub type CredentialInput = Credential;
// Missing => None; explicit null => Some(None). Plain double Option loses this distinction.
pub fn nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetCreate {
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub tags: Vec<String>,
    pub group_id: Option<uuid::Uuid>,
    pub protocol: TargetProtocol,
    pub security: Option<RdpSecurity>,
    pub ssh_host_key: Option<String>,
    pub rdp_certificate_sha256: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetUpdate {
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tags: Option<Vec<String>>,
    #[serde(default, deserialize_with = "nullable")]
    pub group_id: Option<Option<uuid::Uuid>>,
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "nullable")]
    pub security: Option<Option<RdpSecurity>>,
    #[serde(default, deserialize_with = "nullable")]
    pub ssh_host_key: Option<Option<String>>,
    #[serde(default, deserialize_with = "nullable")]
    pub rdp_certificate_sha256: Option<Option<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCreate {
    pub label: String,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub credential: CredentialInput,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUpdate {
    pub label: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    pub username: Option<Option<String>>,
    #[serde(default, deserialize_with = "nullable")]
    pub domain: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub credential: Option<CredentialInput>,
}
fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
pub fn valid_ssh_host_key(value: &str) -> bool {
    if value.len() > 16384 || value.chars().any(char::is_control) {
        return false;
    }
    let Ok(key) = ssh_key::PublicKey::from_openssh(value) else {
        return false;
    };
    matches!(
        key.algorithm(),
        ssh_key::Algorithm::Ed25519
            | ssh_key::Algorithm::Rsa { .. }
            | ssh_key::Algorithm::Ecdsa { .. }
    )
}
pub fn valid_certificate_pin(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl AssetCreate {
    pub fn validate(&mut self) -> StoreResult<()> {
        if !text(&self.name, 128)
            || !text(&self.host, 253)
            || self.host.contains(['/', '@', ' ', '[', ']'])
            || self.port == 0
            || self.tags.len() > 32
            || self.tags.iter().any(|s| !text(s, 64))
        {
            return Err(ErrorCode::InvalidArgument);
        }
        match self.protocol {
            TargetProtocol::Ssh
                if self.security.is_none()
                    && self.rdp_certificate_sha256.is_none()
                    && self.ssh_host_key.as_deref().is_none_or(valid_ssh_host_key) => {}
            TargetProtocol::Rdp
                if self.ssh_host_key.is_none()
                    && self
                        .rdp_certificate_sha256
                        .as_deref()
                        .is_none_or(valid_certificate_pin) =>
            {
                self.security.get_or_insert(RdpSecurity::Nla);
            }
            TargetProtocol::Vnc
                if self.security.is_none()
                    && self.ssh_host_key.is_none()
                    && self.rdp_certificate_sha256.is_none() => {}
            _ => return Err(ErrorCode::InvalidArgument),
        }
        Ok(())
    }
}
pub(crate) fn validate_account(
    protocol: TargetProtocol,
    label: &str,
    username: Option<&str>,
    domain: Option<&str>,
    credential: &CredentialInput,
) -> StoreResult<()> {
    if !text(label, 128)
        || username.is_some_and(|s| !text(s, 128))
        || domain.is_some_and(|s| !text(s, 253))
        || (protocol != TargetProtocol::Rdp && domain.is_some())
        || (protocol == TargetProtocol::Vnc) != username.is_none()
    {
        return Err(ErrorCode::InvalidArgument);
    }
    match credential {
        Credential::None if protocol == TargetProtocol::Vnc => Ok(()),
        Credential::Password { password }
            if credential.validate_lengths()
                && !password.contains('\0')
                && (protocol != TargetProtocol::Vnc || password.len() <= 8) =>
        {
            Ok(())
        }
        Credential::PrivateKey {
            key_pem,
            passphrase,
        } if protocol == TargetProtocol::Ssh && credential.validate_lengths() => {
            if key_pem.contains('\0') || passphrase.as_ref().is_some_and(|p| p.contains('\0')) {
                Err(ErrorCode::InvalidArgument)
            } else {
                Ok(())
            }
        }
        _ => Err(ErrorCode::InvalidArgument),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nullable_and_protocol_shapes() {
        let missing: AccountUpdate = serde_json::from_str("{}").unwrap();
        assert_eq!(missing.domain, None);
        let clear: AccountUpdate = serde_json::from_str("{\"domain\":null}").unwrap();
        assert_eq!(clear.domain, Some(None));
        assert!(
            validate_account(TargetProtocol::Vnc, "vnc", None, None, &Credential::None).is_ok()
        );
        assert!(validate_account(
            TargetProtocol::Ssh,
            "ssh",
            Some("u"),
            None,
            &Credential::None
        )
        .is_err());
        assert!(validate_account(
            TargetProtocol::Vnc,
            "vnc",
            None,
            None,
            &Credential::Password {
                password: "123456789".into()
            }
        )
        .is_err());
        assert!(valid_certificate_pin(&"a".repeat(64)));
        assert!(!valid_certificate_pin(&"A".repeat(64)));
    }
}

fn kdf_cost_bounded(kdf: &ssh_key::Kdf) -> bool {
    matches!(kdf,ssh_key::Kdf::Bcrypt{salt,rounds} if (1..=64).contains(rounds) && (1..=64).contains(&salt.len()))
}
pub(crate) async fn validate_credential_input(value: &CredentialInput) -> StoreResult<()> {
    if !matches!(value, Credential::PrivateKey { .. }) {
        return Ok(());
    }
    if !value.validate_lengths() {
        return Err(ErrorCode::InvalidArgument);
    }
    static WORKERS: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    let permit = WORKERS
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(4)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| ErrorCode::RateLimited)?;
    let value = value.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let Credential::PrivateKey {
            key_pem,
            passphrase,
        } = &value
        else {
            return Err(ErrorCode::InvalidArgument);
        };
        if key_pem.contains('\0') || passphrase.as_ref().is_some_and(|p| p.contains('\0')) {
            return Err(ErrorCode::InvalidArgument);
        }
        let key =
            ssh_key::PrivateKey::from_openssh(key_pem).map_err(|_| ErrorCode::InvalidArgument)?;
        // Restrict encrypted OpenSSH to the format exercised by libssh2's memory API.
        if !matches!(
            key.cipher(),
            ssh_key::Cipher::None | ssh_key::Cipher::Aes256Ctr
        ) {
            return Err(ErrorCode::InvalidArgument);
        }
        if key.is_encrypted() && !kdf_cost_bounded(key.kdf()) {
            return Err(ErrorCode::InvalidArgument);
        }
        let key = if key.is_encrypted() {
            key.decrypt(passphrase.as_deref().ok_or(ErrorCode::InvalidArgument)?)
                .map_err(|_| ErrorCode::InvalidArgument)?
        } else {
            key
        };
        // The pinned libssh2 engine failed RSA authentication against modern OpenSSH.
        if key.algorithm() == ssh_key::Algorithm::Ed25519 {
            Ok(())
        } else {
            Err(ErrorCode::InvalidArgument)
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .map_err(|_| ErrorCode::RateLimited)?
        .map_err(|_| ErrorCode::InternalError)?
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    #[test]
    fn ssh_assets_can_wait_for_confirmation_but_supplied_keys_are_validated() {
        let base =
            serde_json::json!({"name":"test","host":"target.test","port":22,"protocol":"ssh"});
        let mut asset: AssetCreate = serde_json::from_value(base.clone()).unwrap();
        asset.validate().unwrap();
        for key in [
            "",
            "SHA256:abcd",
            "host ssh-ed25519 AAAA",
            "ssh-ed25519 AAAA",
        ] {
            asset.ssh_host_key = Some(key.into());
            assert!(asset.validate().is_err());
        }
        asset.ssh_host_key = None;
        asset.rdp_certificate_sha256 = Some("a".repeat(64));
        assert!(asset.validate().is_err());
        let update: AssetUpdate = serde_json::from_str(r#"{"ssh_host_key":null}"#).unwrap();
        assert_eq!(update.ssh_host_key, Some(None));
    }
    #[test]
    fn rdp_assets_can_wait_for_confirmation_but_supplied_pins_are_validated() {
        let mut asset: AssetCreate = serde_json::from_value(
            serde_json::json!({"name":"desk","host":"target.test","port":3389,"protocol":"rdp"}),
        )
        .unwrap();
        asset.validate().unwrap();
        assert_eq!(asset.security, Some(RdpSecurity::Nla));
        for pin in ["", "A".repeat(64).as_str(), "a".repeat(63).as_str()] {
            asset.rdp_certificate_sha256 = Some(pin.into());
            assert!(asset.validate().is_err());
        }
        asset.rdp_certificate_sha256 = Some("a".repeat(64));
        asset.validate().unwrap();
        asset.ssh_host_key = Some("ssh-ed25519 AAAA".into());
        assert!(asset.validate().is_err());
    }
    #[test]
    fn nullable_updates_distinguish_absent_and_null() {
        let missing: AccountUpdate = serde_json::from_str("{}").unwrap();
        let clear: AccountUpdate =
            serde_json::from_str(r#"{"username":null,"domain":null}"#).unwrap();
        assert!(missing.username.is_none());
        assert_eq!(clear.username, Some(None));
        assert_eq!(clear.domain, Some(None));
        assert!(serde_json::from_str::<AssetUpdate>(r#"{"protocol":"rdp"}"#).is_err());
    }
    #[test]
    fn protocol_specific_account_boundaries() {
        assert!(
            validate_account(TargetProtocol::Vnc, "label", None, None, &Credential::None).is_ok()
        );
        assert!(validate_account(
            TargetProtocol::Ssh,
            "label",
            Some("root"),
            None,
            &Credential::None
        )
        .is_err());
        assert!(validate_account(
            TargetProtocol::Vnc,
            "label",
            Some("root"),
            None,
            &Credential::None
        )
        .is_err());
        for password in ["123456789", "密码密"] {
            assert!(validate_account(
                TargetProtocol::Vnc,
                "label",
                None,
                None,
                &Credential::Password {
                    password: password.into()
                }
            )
            .is_err());
        }
        assert!(validate_account(
            TargetProtocol::Vnc,
            "label",
            None,
            None,
            &Credential::Password {
                password: "密码".into()
            }
        )
        .is_ok());
        assert!(validate_account(TargetProtocol::Vnc, " ", None, None, &Credential::None).is_err());
        assert!(!valid_certificate_pin(&"A".repeat(64)));
        assert!(valid_certificate_pin(&"a".repeat(64)));
    }
    #[test]
    fn hostile_kdf_work_is_rejected_before_decrypt() {
        for (salt, rounds) in [
            (vec![1; 16], 0),
            (vec![1; 16], 65),
            (vec![1; 65], 16),
            (vec![], 16),
        ] {
            assert!(!kdf_cost_bounded(&ssh_key::Kdf::Bcrypt { salt, rounds }));
        }
        assert!(kdf_cost_bounded(&ssh_key::Kdf::Bcrypt {
            salt: vec![1; 16],
            rounds: 64
        }));
    }
    #[tokio::test]
    async fn private_keys_are_parsed_off_runtime_and_unsupported_formats_rejected() {
        let key = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
            "test-only",
        )
        .unwrap();
        let credential = Credential::PrivateKey {
            key_pem: key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
            passphrase: None,
        };
        validate_credential_input(&credential).await.unwrap();
        assert!(validate_credential_input(&Credential::PrivateKey {
            key_pem: "-----BEGIN RSA PRIVATE KEY-----\nmalformed".into(),
            passphrase: None
        })
        .await
        .is_err());
        assert!(!valid_ssh_host_key(&format!(
            "{}\tbad",
            key.public_key().to_openssh().unwrap()
        )));
    }
}
