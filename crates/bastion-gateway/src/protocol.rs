use async_trait::async_trait;
use bastion_domain::*;
use bastion_secrets::{CipherContext, Credential, Envelope, KeyRing};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
mod guacd;
mod native;
mod policy;
mod recording;
mod runtime;
mod sftp;
mod ssh;
mod web;
pub use guacd::protocol_available;
pub use native::{serve_native, NativeListenerConfig, NativeTicket, NativeTickets};
pub use recording::{check_recording_directory, RecordingConfig, SessionRecording};
pub use runtime::{RuntimeLimits, RuntimeRegistry};
pub use web::run_web_session;
#[async_trait]
pub trait GatewayBackend: Send + Sync {
    fn registry(&self) -> Arc<RuntimeRegistry> {
        RuntimeRegistry::global()
    }
    fn recording_config(&self) -> Option<RecordingConfig> {
        None
    }
    async fn authorize(&self, connection: &Connection) -> Result<(), ErrorCode>;
    async fn transition(
        &self,
        id: Uuid,
        state: ConnectionState,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode>;
    async fn begin_recording(
        &self,
        connection: &Connection,
        recording: RecordingCreate,
    ) -> Result<(), ErrorCode>;
    async fn activate_recording(
        &self,
        connection: &Connection,
        recording_id: Uuid,
    ) -> Result<(), ErrorCode>;
    async fn checkpoint_recording(
        &self,
        id: Uuid,
        written: i64,
        synced: i64,
        bytes: i64,
    ) -> Result<(), ErrorCode>;
    async fn finish_recording(
        &self,
        id: Uuid,
        state: RecordingState,
        bytes: i64,
        checksum: Option<String>,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode>;
    /// `connecting → active` for a native connection with no recording (exec/sftp only, RFC-006
    /// §14.2), after the same authorization as `activate_recording`. Idempotent once active;
    /// refuses websocket connections.
    async fn activate_native_connection(&self, _connection: &Connection) -> Result<(), ErrorCode> {
        Err(ErrorCode::TargetProtocolUnavailable)
    }
    /// Audits one finished native exec channel (`exec.completed`, RFC-006 §14.3). `command` is the
    /// full request bytes; the store keeps a 4 KiB preview and the SHA-256.
    async fn exec_completed(
        &self,
        _connection: &Connection,
        _command: &[u8],
        _outcome: &ExecOutcome,
    ) -> Result<(), ErrorCode> {
        Err(ErrorCode::TargetProtocolUnavailable)
    }
    /// SFTP operation/file/session metadata audit; never includes file contents.
    async fn sftp_audit(
        &self,
        _connection: &Connection,
        _entry: &SftpAudit,
    ) -> Result<(), ErrorCode> {
        Err(ErrorCode::TargetProtocolUnavailable)
    }
    async fn sftp_rejected(
        &self,
        _connection: &Connection,
        _reason: ErrorCode,
    ) -> Result<(), ErrorCode> {
        Err(ErrorCode::TargetProtocolUnavailable)
    }
    /// Audits a native exec request refused before the target ran it (`exec.rejected`).
    async fn exec_rejected(
        &self,
        _connection: &Connection,
        _command: &[u8],
        _reason: ErrorCode,
    ) -> Result<(), ErrorCode> {
        Err(ErrorCode::TargetProtocolUnavailable)
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuacdConfig {
    pub address: SocketAddr,
    pub bridge_bind: SocketAddr,
    pub bridge_advertise_host: String,
    pub allowed_source_ips: Vec<IpAddr>,
    #[serde(default)]
    pub rdp_strict_pin_verified: bool,
    pub version: String,
    #[serde(default)]
    pub vnc_trusted_cidrs: Vec<IpNet>,
}
impl GuacdConfig {
    pub fn validate(&self) -> Result<(), ErrorCode> {
        let advertised: IpAddr = self
            .bridge_advertise_host
            .parse()
            .map_err(|_| ErrorCode::InvalidArgument)?;
        if self.version != "1.6.0"
            || self.address.port() == 0
            || self.address.ip().is_unspecified()
            || self.bridge_bind.port() != 0
            || self.bridge_bind.ip().is_unspecified()
            || advertised.is_unspecified()
            || advertised.is_multicast()
            || !match advertised {
                IpAddr::V4(ip) => ip.is_private(),
                IpAddr::V6(ip) => ip.is_unique_local(),
            }
            || self.bridge_bind.ip() != advertised
            || self.allowed_source_ips.is_empty()
            || self.allowed_source_ips.len() > 8
            || self
                .allowed_source_ips
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct NetworkPolicy {
    pub allow: Vec<IpNet>,
    pub deny: Vec<IpNet>,
}
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
impl NetworkPolicy {
    pub fn permits(&self, address: IpAddr) -> bool {
        let address = normalize_ip(address);
        self.allow.iter().any(|net| net.contains(&address))
            && !self.deny.iter().any(|net| net.contains(&address))
    }
    pub async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ErrorCode> {
        let addresses = timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| ErrorCode::TargetTimeout)?
        .map_err(|_| ErrorCode::TargetUnreachable)?;
        addresses
            .into_iter()
            .find(|a| self.permits(a.ip()))
            .ok_or(ErrorCode::TargetAddressDenied)
    }
}
#[derive(Clone)]
pub enum TargetEndpoint {
    Restricted {
        host: String,
        port: u16,
        policy: Arc<NetworkPolicy>,
    },
}
impl TargetEndpoint {
    pub(crate) async fn resolve(&self) -> Result<SocketAddr, ErrorCode> {
        match self {
            Self::Restricted { host, port, policy } => policy.resolve(host, *port).await,
        }
    }
}
#[derive(Clone)]
pub enum TargetAuth {
    None,
    Encrypted {
        context: CipherContext,
        envelope: Envelope,
        keys: Arc<KeyRing>,
    },
}
#[derive(Clone)]
pub struct Target {
    pub address: TargetEndpoint,
    pub protocol: TargetProtocol,
    pub security: Option<RdpSecurity>,
    pub ssh_host_key: Option<String>,
    pub rdp_certificate_sha256: Option<String>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub auth: TargetAuth,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deny_first_and_mapped_ip() {
        let p = NetworkPolicy {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: vec!["127.0.0.0/8".parse().unwrap()],
        };
        assert!(p.permits("10.20.1.2".parse().unwrap()));
        assert!(!p.permits("::ffff:127.0.0.1".parse().unwrap()));
    }
    #[test]
    fn guacd_config_rejects_public_or_hostname_bridge() {
        let mut c = GuacdConfig {
            address: "10.1.0.2:4822".parse().unwrap(),
            bridge_bind: "10.1.0.1:0".parse().unwrap(),
            bridge_advertise_host: "10.1.0.1".into(),
            allowed_source_ips: vec!["10.1.0.2".parse().unwrap()],
            version: "1.6.0".into(),
            rdp_strict_pin_verified: false,
            vnc_trusted_cidrs: Vec::new(),
        };
        assert!(c.validate().is_ok());
        c.bridge_advertise_host = "example.org".into();
        assert!(c.validate().is_err());
    }
}
