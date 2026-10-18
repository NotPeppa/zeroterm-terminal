mod guacamole;
mod terminal;
use chrono::{DateTime, Utc};
pub use guacamole::*;
use serde::{Deserialize, Serialize};
pub use terminal::*;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 2;
pub const STREAM_PROTOCOL: &str = "bastion.guac.v1";
pub const SSH_STREAM_PROTOCOL: &str = "bastion.ssh.v1";
pub const MAX_DATA_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetProtocol {
    Ssh,
    Rdp,
    Vnc,
}
impl TargetProtocol {
    pub fn stream_protocol(self) -> &'static str {
        match self {
            Self::Ssh => SSH_STREAM_PROTOCOL,
            Self::Rdp | Self::Vnc => STREAM_PROTOCOL,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpSecurity {
    #[default]
    Nla,
    Tls,
}
impl RdpSecurity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nla => "nla",
            Self::Tls => "tls",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Display {
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
}
impl Default for Display {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            dpi: 96,
        }
    }
}
impl Display {
    pub fn validate(self) -> Result<(), ErrorCode> {
        if (1..=3840).contains(&self.width)
            && (1..=2160).contains(&self.height)
            && (48..=192).contains(&self.dpi)
        {
            Ok(())
        } else {
            Err(ErrorCode::InvalidArgument)
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub asset_id: Uuid,
    pub account_id: Uuid,
    #[serde(default)]
    pub display: Display,
}
#[derive(Serialize)]
pub struct WebSessionResponse {
    pub session_id: Uuid,
    pub connection_id: Uuid,
    pub ws_token: String,
    pub expires_at: DateTime<Utc>,
    pub target_protocol: TargetProtocol,
    pub stream_protocol: &'static str,
}

/// Which login family a token belongs to. Browser cookies and native Bearer tokens never cross over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Web,
    Native,
}
impl ClientType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
        }
    }
}
/// Client-to-bastion leg of a connection (RFC-006). The target side is identical for both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Websocket,
    NativeSsh,
}
impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Websocket => "websocket",
            Self::NativeSsh => "native_ssh",
        }
    }
    /// The only login family allowed to issue, consume or keep a connection of this transport.
    pub fn client_type(self) -> ClientType {
        match self {
            Self::Websocket => ClientType::Web,
            Self::NativeSsh => ClientType::Native,
        }
    }
}
/// RFC-006 native protocol family advertised in `/info.native` and ticket responses.
pub const NATIVE_PROTOCOL_VERSION: u32 = 1;
/// Native capabilities currently open (RFC-006 §14.1), in canonical order.
pub const NATIVE_CAPABILITIES: &[&str] = &["shell", "exec", "sftp"];
/// A ticket asks for a non-empty subset of the open capabilities, in any order; unknown,
/// duplicate or not-yet-open capabilities are invalid input.
pub fn validate_native_capabilities(capabilities: &[String]) -> Result<(), ErrorCode> {
    let valid = !capabilities.is_empty()
        && capabilities.iter().enumerate().all(|(index, capability)| {
            NATIVE_CAPABILITIES.contains(&capability.as_str())
                && !capabilities[..index].contains(capability)
        });
    if valid {
        Ok(())
    } else {
        Err(ErrorCode::InvalidArgument)
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTicketRequest {
    pub asset_id: Uuid,
    pub account_id: Uuid,
    pub capabilities: Vec<String>,
}
/// Store result of native issuance; the API adds the public gateway address.
pub struct NativeTicketIssued {
    pub ticket_id: Uuid,
    pub ticket_secret: String,
    pub connection_id: Uuid,
    pub capabilities: Vec<String>,
    pub expires_at: DateTime<Utc>,
}
/// What the SSH gateway gets from a consumed `zt1:` ticket: the connecting row and the capabilities
/// the ticket was issued for (in request order), which bound the channel requests it may accept.
#[derive(Clone, Debug)]
pub struct NativeSession {
    pub connection: Connection,
    pub capabilities: Vec<String>,
}
/// How one native `exec` channel ended (RFC-006 §14.3); audited as `exec.completed`. Output is
/// never recorded, only these counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecOutcome {
    /// Target `exit-status`; None when the command ended by signal or without reporting one.
    pub exit_status: Option<u32>,
    /// Target `exit-signal` name as sent (e.g. `TERM`).
    pub exit_signal: Option<String>,
    pub stdin_bytes: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub duration_ms: u64,
}

/// One SFTP audit row (RFC-006 §14.4); never carries file contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SftpAudit {
    /// Target result for a mutation; fsync is counted only in Session.
    Operation {
        op: SftpOp,
        path: Vec<u8>,
        target_path: Option<Vec<u8>>,
        status: u32,
    },
    /// Successful CLOSE, an unfinished handle, or a refused write-intent OPEN. Paths remain raw
    /// until the store sanitizes them; no variant can supply its own connection/actor identity.
    File {
        path: Vec<u8>,
        flags: u32,
        status: Option<u32>,
        read_bytes: u64,
        write_bytes: u64,
        sha256: Option<String>,
        read_sha256: Option<String>,
        write_sha256: Option<String>,
    },
    /// Final per-request counters and SFTP frame bytes, including local unsupported responses.
    Session {
        requests: std::collections::BTreeMap<String, u64>,
        input_bytes: u64,
        output_bytes: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SftpOp {
    Setstat,
    Fsetstat,
    Remove,
    Mkdir,
    Rmdir,
    Rename,
    Symlink,
    PosixRename,
    Hardlink,
}
impl SftpOp {
    pub fn as_action(self) -> &'static str {
        match self {
            Self::Setstat => "sftp.setstat",
            Self::Fsetstat => "sftp.fsetstat",
            Self::Remove => "sftp.remove",
            Self::Mkdir => "sftp.mkdir",
            Self::Rmdir => "sftp.rmdir",
            Self::Rename => "sftp.rename",
            Self::Symlink => "sftp.symlink",
            Self::PosixRename => "sftp.posix-rename",
            Self::Hardlink => "sftp.hardlink",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Pending,
    Connecting,
    Active,
    Closing,
    Closed,
    Failed,
    Expired,
    Revoked,
    Interrupted,
}
impl ConnectionState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Failed | Self::Expired | Self::Revoked | Self::Interrupted
        )
    }
    pub fn permits(self, next: Self) -> bool {
        use ConnectionState::*;
        matches!(
            (self, next),
            (Pending, Connecting | Expired | Revoked)
                | (Connecting, Active | Failed | Closing | Interrupted)
                | (Active, Closing | Failed | Interrupted)
                | (Closing, Closed | Failed | Interrupted)
        )
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Connection {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub asset_id: Uuid,
    pub account_id: Uuid,
    pub target_protocol: TargetProtocol,
    pub transport: Transport,
    /// Native connections have no pixel display and carry the nominal default (recording header only).
    pub display: Display,
    pub protocol_version: u32,
    pub state: ConnectionState,
    pub created_at: DateTime<Utc>,
    pub failure: Option<Failure>,
    pub user_id: Option<Uuid>,
    pub login_session_id: Option<Uuid>,
    #[serde(skip)]
    pub auth_revision: i64,
    #[serde(skip)]
    pub routing_revision: i64,
    #[serde(skip)]
    pub account_revision: i64,
    #[serde(skip)]
    pub credential_revision: Option<i64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Failure {
    pub code: ErrorCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    #[error("输入不符合协议要求")]
    InvalidArgument,
    #[error("需要登录")]
    Unauthenticated,
    #[error("没有该资产账号的权限")]
    PermissionDenied,
    #[error("资源不存在")]
    ResourceNotFound,
    #[serde(rename = "SESSION_TICKET_INVALID")]
    #[error("连接票据无效")]
    TicketInvalid,
    #[serde(rename = "SESSION_TICKET_USED")]
    #[error("连接票据已使用")]
    TicketUsed,
    #[serde(rename = "SESSION_TICKET_EXPIRED")]
    #[error("连接票据已过期")]
    TicketExpired,
    #[error("连接数量达到上限")]
    ConnectionLimit,
    #[error("目标主机密钥不匹配")]
    TargetHostKeyChanged,
    #[error("无法连接目标")]
    TargetUnreachable,
    #[error("目标连接超时")]
    TargetTimeout,
    #[error("目标账号认证失败")]
    TargetAuthFailed,
    #[error("内部错误")]
    InternalError,
    #[serde(rename = "SESSION_EXPIRED")]
    #[error("访问令牌已过期")]
    AccessTokenExpired,
    #[error("客户端协议版本不支持")]
    ClientProtocolUnsupported,
    #[error("目标请求被拒绝")]
    TargetRequestRejected,
    #[error("录制不可用")]
    RecordingUnavailable,
    #[error("认证或网关失败")]
    AuthOrGatewayFailed,
    #[error("设备登录已撤销")]
    LoginSessionRevoked,
    #[error("用户已停用")]
    UserDisabled,
    #[serde(rename = "SESSION_TICKET_STALE")]
    #[error("连接票据策略或配置已变化")]
    TicketStale,
    #[error("目标地址不在允许范围")]
    TargetAddressDenied,
    #[error("目标主机密钥未核验")]
    TargetHostKeyUnknown,
    #[error("目标证书不匹配")]
    TargetCertificateChanged,
    #[error("目标协议安全引擎未验证")]
    TargetProtocolUnavailable,
    #[error("权限存储暂不可用")]
    PolicyStoreUnavailable,
    #[error("操作过于频繁")]
    RateLimited,
    #[error("更新需要 If-Match 修订号")]
    PreconditionRequired,
    #[error("资源已修改，请重新读取")]
    RevisionConflict,
    #[error("资源已存在")]
    ResourceConflict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Operator,
    Auditor,
}
impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserView {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    pub enabled: bool,
    pub revision: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub user: UserView,
    pub login_session_id: Uuid,
    /// When the access token that produced this identity expires. The browser console schedules a
    /// silent refresh from it, so it travels with every authenticated request.
    pub access_expires_at: Option<DateTime<Utc>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
    pub device_label: String,
}
// Internal cookie material; API must never serialize this structure directly.
pub struct LoginResponse {
    pub user: UserView,
    pub access_token: String,
    pub refresh_token: String,
    pub login_session_id: Uuid,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingState {
    Preparing,
    Active,
    Complete,
    Partial,
    Failed,
    Corrupt,
    Missing,
    Expired,
}
impl RecordingState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Active => "active",
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Corrupt => "corrupt",
            Self::Missing => "missing",
            Self::Expired => "expired",
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct RecordingView {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub target_protocol: TargetProtocol,
    pub format_version: u32,
    pub bytes: i64,
    pub checksum: Option<String>,
    pub state: RecordingState,
    pub retention_until: DateTime<Utc>,
    pub last_written_seq: i64,
    pub last_synced_seq: i64,
}
#[derive(Clone)]
pub struct RecordingCreate {
    pub id: Uuid,
    pub relative_path: String,
    pub format_version: u32,
    pub retention_until: DateTime<Utc>,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
    pub key_version: i64,
    pub nonce_prefix: Vec<u8>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DeviceSessionView {
    pub id: Uuid,
    pub device_label: String,
    pub current: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_contract_rejects_legacy_and_bounds_display() {
        let ids = serde_json::json!({"asset_id":Uuid::new_v4(),"account_id":Uuid::new_v4()});
        let request: SessionRequest = serde_json::from_value(ids.clone()).unwrap();
        assert_eq!(request.display, Display::default());
        let mut legacy = ids;
        legacy["purpose"] = "terminal".into();
        assert!(serde_json::from_value::<SessionRequest>(legacy).is_err());
        assert!(Display {
            width: 3841,
            ..Default::default()
        }
        .validate()
        .is_err());
        let native = |caps: &[&str]| {
            validate_native_capabilities(&caps.iter().map(|c| c.to_string()).collect::<Vec<_>>())
        };
        for accepted in [
            &["shell"][..],
            &["exec"],
            &["sftp"],
            &["shell", "exec"],
            &["exec", "shell", "sftp"],
        ] {
            assert!(native(accepted).is_ok(), "{accepted:?}");
        }
        for rejected in [
            &[][..],
            &["unknown"],
            &["shell", "sftp", "sftp"],
            &["shell", "shell"],
            &["exec", "shell", "exec"],
            &["Shell"],
            &["pty"],
            &[""],
        ] {
            assert!(native(rejected).is_err(), "{rejected:?}");
        }
        let ticket = serde_json::json!({"asset_id":Uuid::new_v4(),"account_id":Uuid::new_v4(),"capabilities":["shell"]});
        assert!(serde_json::from_value::<NativeTicketRequest>(ticket.clone()).is_ok());
        for (field, value) in [
            ("purpose", serde_json::json!("terminal")),
            ("display", serde_json::json!({})),
        ] {
            let mut extra = ticket.clone();
            extra[field] = value;
            assert!(serde_json::from_value::<NativeTicketRequest>(extra).is_err());
        }
        let mut missing = ticket;
        missing.as_object_mut().unwrap().remove("capabilities");
        assert!(serde_json::from_value::<NativeTicketRequest>(missing).is_err());
        assert_eq!(Transport::NativeSsh.client_type(), ClientType::Native);
        assert_eq!(
            serde_json::to_value(Transport::NativeSsh).unwrap(),
            "native_ssh"
        );
        for state in [
            ConnectionState::Closed,
            ConnectionState::Failed,
            ConnectionState::Interrupted,
        ] {
            assert!(!state.permits(ConnectionState::Active));
        }
    }
}
