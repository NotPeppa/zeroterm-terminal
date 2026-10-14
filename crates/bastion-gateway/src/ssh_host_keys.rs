use crate::NetworkPolicy;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use bastion_domain::ErrorCode;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

#[derive(Debug, Serialize)]
pub struct SshHostKey {
    pub public_key: String,
    pub fingerprint: String,
    pub algorithm: String,
}

pub fn ssh_host_key_fingerprint(key: &str) -> Result<String, ErrorCode> {
    if !bastion_store::valid_ssh_host_key(key) {
        return Err(ErrorCode::InvalidArgument);
    }
    let encoded = key
        .split_whitespace()
        .nth(1)
        .ok_or(ErrorCode::InvalidArgument)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ErrorCode::InvalidArgument)?;
    Ok(format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(bytes))
    ))
}

fn parse_scan(output: &[u8]) -> Result<Vec<SshHostKey>, ErrorCode> {
    if output.len() > 65536 {
        return Err(ErrorCode::TargetRequestRejected);
    }
    let output = std::str::from_utf8(output).map_err(|_| ErrorCode::TargetRequestRejected)?;
    let mut keys = Vec::new();
    for line in output
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 || keys.len() >= 5 {
            return Err(ErrorCode::TargetRequestRejected);
        }
        let public_key = format!("{} {}", fields[1], fields[2]);
        let fingerprint = ssh_host_key_fingerprint(&public_key)?;
        if !keys
            .iter()
            .any(|key: &SshHostKey| key.public_key == public_key)
        {
            keys.push(SshHostKey {
                public_key,
                fingerprint,
                algorithm: fields[1].into(),
            });
        }
    }
    if keys.is_empty() {
        return Err(ErrorCode::TargetUnreachable);
    }
    keys.sort_by_key(|key| match key.algorithm.as_str() {
        "ssh-ed25519" => 0,
        "ssh-rsa" => 2,
        _ => 1,
    });
    Ok(keys)
}

/// Discovery only: never authenticates, stores a pin, or bypasses session verification.
pub async fn scan_ssh_host_keys(
    policy: &NetworkPolicy,
    host: &str,
    port: u16,
) -> Result<Vec<SshHostKey>, ErrorCode> {
    let address = policy.resolve(host, port).await?;
    let mut command = Command::new("ssh-keyscan");
    command
        .args([
            "-T",
            "4",
            "-p",
            &port.to_string(),
            "-t",
            "ed25519,ecdsa,rsa",
            "--",
            &address.ip().to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    let mut child = command
        .spawn()
        .map_err(|_| ErrorCode::TargetProtocolUnavailable)?;
    timeout(Duration::from_secs(6), async {
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .ok_or(ErrorCode::InternalError)?
            .take(65537)
            .read_to_end(&mut output)
            .await
            .map_err(|_| ErrorCode::TargetUnreachable)?;
        if output.len() > 65536 {
            return Err(ErrorCode::TargetRequestRejected);
        }
        let status = child
            .wait()
            .await
            .map_err(|_| ErrorCode::TargetUnreachable)?;
        if !status.success() {
            return Err(ErrorCode::TargetUnreachable);
        }
        parse_scan(&output)
    })
    .await
    .map_err(|_| ErrorCode::TargetTimeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZbpRJIMtxDOgmfuMBMjqc0KTjiTRG/H/N/jegwxgxg";

    #[test]
    fn scan_strips_endpoint_and_validates_fingerprint_without_accepting_malformed_keys() {
        let output = format!("# banner\n[127.0.0.1]:2222 {KEY}\n[127.0.0.1]:2222 {KEY}\n");
        let keys = parse_scan(output.as_bytes()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].public_key, KEY);
        assert_eq!(
            keys[0].fingerprint,
            "SHA256:Rps9HebWfLbpgWp+TI4T/TIB88Ugr+HVQM53G9LrShU"
        );
        for output in [
            "",
            "target ssh-ed25519 AAAA",
            "target ssh-ed25519 AAAA extra",
        ] {
            assert!(parse_scan(output.as_bytes()).is_err());
        }
        assert!(parse_scan(&vec![b'a'; 65537]).is_err());
    }

    #[tokio::test]
    async fn discovery_enforces_network_policy_before_starting_scanner() {
        let policy = NetworkPolicy {
            allow: vec!["127.0.0.0/8".parse().unwrap()],
            deny: vec!["127.0.0.1/32".parse().unwrap()],
        };
        assert!(matches!(
            scan_ssh_host_keys(&policy, "127.0.0.1", 22).await,
            Err(ErrorCode::TargetAddressDenied)
        ));
    }
}
