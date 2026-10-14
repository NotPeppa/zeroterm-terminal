use crate::NetworkPolicy;
use bastion_domain::ErrorCode;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

#[derive(Debug, Serialize)]
pub struct RdpCertificate {
    /// Lowercase hex SHA-256 of the leaf certificate's DER bytes: the value an asset pins.
    pub sha256: String,
    /// Security protocol the server selected during X.224 negotiation.
    pub selected_protocol: &'static str,
}

/// TPKT + X.224 Connection Request + RDP_NEG_REQ asking for TLS or CredSSP (both start with TLS).
const CONNECTION_REQUEST: [u8; 19] = [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];

/// Parses the X.224 Connection Confirm; only TLS-based selections are accepted.
fn selected_protocol(confirm: &[u8]) -> Result<&'static str, ErrorCode> {
    // TPKT(4) + LI + CC code + dst/src ref + class = 11, then RDP_NEG_RSP/FAILURE (8).
    if confirm.len() != 19 || confirm[0] != 3 || confirm[5] & 0xf0 != 0xd0 {
        return Err(ErrorCode::TargetProtocolUnavailable);
    }
    let negotiation = &confirm[11..];
    if negotiation[0] != 2 || u16::from_le_bytes([negotiation[2], negotiation[3]]) != 8 {
        return Err(ErrorCode::TargetProtocolUnavailable);
    }
    match u32::from_le_bytes(negotiation[4..8].try_into().unwrap()) {
        1 => Ok("tls"),
        2 => Ok("nla"),
        8 => Ok("nla-ex"),
        _ => Err(ErrorCode::TargetProtocolUnavailable),
    }
}

/// Accepts any certificate so it can be shown for approval, but still requires the handshake
/// signature, so the result belongs to a server holding that certificate's private key.
#[derive(Debug)]
struct Discover(Arc<CryptoProvider>);
impl ServerCertVerifier for Discover {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn scan(address: SocketAddr) -> Result<RdpCertificate, ErrorCode> {
    let unreachable = |_| ErrorCode::TargetUnreachable;
    let mut socket =
        TcpStream::connect_timeout(&address, Duration::from_secs(4)).map_err(unreachable)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .map_err(unreachable)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(4)))
        .map_err(unreachable)?;
    socket.write_all(&CONNECTION_REQUEST).map_err(unreachable)?;
    let mut confirm = [0u8; 19];
    socket.read_exact(&mut confirm[..4]).map_err(unreachable)?;
    if usize::from(u16::from_be_bytes([confirm[2], confirm[3]])) != confirm.len() {
        return Err(ErrorCode::TargetProtocolUnavailable);
    }
    socket.read_exact(&mut confirm[4..]).map_err(unreachable)?;
    let selected_protocol = selected_protocol(&confirm)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| ErrorCode::InternalError)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Discover(provider)))
        .with_no_client_auth();
    let mut tls = rustls::ClientConnection::new(Arc::new(config), address.ip().into())
        .map_err(|_| ErrorCode::InternalError)?;
    while tls.is_handshaking() {
        tls.complete_io(&mut socket)
            .map_err(|_| ErrorCode::TargetProtocolUnavailable)?;
    }
    let leaf = tls
        .peer_certificates()
        .and_then(<[_]>::first)
        .ok_or(ErrorCode::TargetProtocolUnavailable)?;
    let sha256 = Sha256::digest(leaf.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    // No CredSSP or RDP data follows: nothing about any account is ever sent.
    tls.send_close_notify();
    let _ = tls.complete_io(&mut socket);
    Ok(RdpCertificate {
        sha256,
        selected_protocol,
    })
}

/// Discovery only: never authenticates or stores a pin; sessions still verify the approved pin.
pub async fn scan_rdp_certificate(
    policy: &NetworkPolicy,
    host: &str,
    port: u16,
) -> Result<RdpCertificate, ErrorCode> {
    let address = policy.resolve(host, port).await?;
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || scan(address)),
    )
    .await
    .map_err(|_| ErrorCode::TargetTimeout)?
    .map_err(|_| ErrorCode::InternalError)?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirm(kind: u8, protocol: u32) -> Vec<u8> {
        let mut bytes = vec![3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, kind, 0, 8, 0];
        bytes.extend(protocol.to_le_bytes());
        bytes
    }

    #[test]
    fn negotiation_accepts_only_tls_based_selections() {
        assert_eq!(selected_protocol(&confirm(2, 1)), Ok("tls"));
        assert_eq!(selected_protocol(&confirm(2, 2)), Ok("nla"));
        assert_eq!(selected_protocol(&confirm(2, 8)), Ok("nla-ex"));
        for bad in [confirm(2, 0), confirm(3, 5), confirm(2, 4)] {
            assert!(selected_protocol(&bad).is_err());
        }
        assert!(selected_protocol(&confirm(2, 1)[..18]).is_err());
        let mut wrong_tpdu = confirm(2, 1);
        wrong_tpdu[5] = 0xe0;
        assert!(selected_protocol(&wrong_tpdu).is_err());
    }

    #[tokio::test]
    async fn discovery_enforces_network_policy_before_connecting() {
        let policy = NetworkPolicy {
            allow: vec!["127.0.0.0/8".parse().unwrap()],
            deny: vec!["127.0.0.1/32".parse().unwrap()],
        };
        assert!(matches!(
            scan_rdp_certificate(&policy, "127.0.0.1", 3389).await,
            Err(ErrorCode::TargetAddressDenied)
        ));
    }
}
