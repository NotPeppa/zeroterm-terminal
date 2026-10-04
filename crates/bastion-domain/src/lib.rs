mod websocket;
pub use websocket::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Shell,
    Exec,
    Sftp,
}
impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Exec => "exec",
            Self::Sftp => "sftp",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Terminal,
    Sftp,
    Metrics,
    ServerTool,
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Sftp => "sftp",
            Self::Metrics => "metrics",
            Self::ServerTool => "server_tool",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketTransport {
    Ssh,
    Websocket,
}
impl TicketTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Websocket => "websocket",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TicketRequest {
    pub asset_id: Uuid,
    pub account_id: Uuid,
    pub capabilities: Vec<Capability>,
    pub purpose: Purpose,
}

impl TicketRequest {
    pub fn validate(&mut self, allowed: &[Capability]) -> Result<(), ErrorCode> {
        if self.capabilities.is_empty() || self.capabilities.len() > 3 {
            return Err(ErrorCode::InvalidArgument);
        }
        self.capabilities.sort();
        self.capabilities.dedup();
        if self.capabilities.iter().any(|c| !allowed.contains(c)) {
            return Err(ErrorCode::PermissionDenied);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GatewayAddress {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
}

// Deliberately no Debug: this is the only response containing the secret.
#[derive(Serialize)]
pub struct TicketResponse {
    pub protocol_version: u32,
    pub ticket_id: Uuid,
    pub ticket_secret: String,
    pub connection_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub gateway: GatewayAddress,
    pub capabilities: Vec<Capability>,
}

#[derive(Serialize)]
pub struct WebSessionResponse {
    pub protocol_version: u32,
    pub session_id: Uuid,
    pub ws_token: String,
    pub connection_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub capabilities: Vec<Capability>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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
                | (Closing, Closed | Interrupted)
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Connection {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub asset_id: Uuid,
    pub account_id: Uuid,
    pub capabilities: Vec<Capability>,
    pub purpose: Purpose,
    pub transport: TicketTransport,
    pub protocol_version: u32,
    pub state: ConnectionState,
    pub created_at: DateTime<Utc>,
    pub failure: Option<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_session_id: Option<Uuid>,
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
    #[error("没有该资产账号或能力的权限")]
    PermissionDenied,
    #[error("资源不存在")]
    ResourceNotFound,
    #[serde(rename = "SESSION_TICKET_INVALID", alias = "TICKET_INVALID")]
    #[error("连接票据无效")]
    TicketInvalid,
    #[serde(rename = "SESSION_TICKET_USED", alias = "TICKET_USED")]
    #[error("连接票据已使用")]
    TicketUsed,
    #[serde(rename = "SESSION_TICKET_EXPIRED", alias = "TICKET_EXPIRED")]
    #[error("连接票据已过期")]
    TicketExpired,
    #[serde(rename = "UNKNOWN_CAPABILITY")]
    #[error("未知能力")]
    UnknownCapability,
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
    #[serde(rename = "SESSION_EXPIRED", alias = "ACCESS_TOKEN_EXPIRED")]
    #[error("访问令牌已过期")]
    AccessTokenExpired,
    #[error("客户端协议版本不支持")]
    ClientProtocolUnsupported,
    #[error("通道权限不足")]
    ChannelPermissionDenied,
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
    #[serde(rename = "SESSION_TICKET_STALE", alias = "TICKET_STALE")]
    #[error("连接票据的策略或配置已变化")]
    TicketStale,
    #[error("目标地址不在允许范围")]
    TargetAddressDenied,
    #[error("目标主机密钥未核验")]
    TargetHostKeyUnknown,
    #[error("权限存储暂不可用")]
    PolicyStoreUnavailable,
    #[error("操作过于频繁")]
    RateLimited,
    #[error("更新需要 If-Match 修订号")]
    PreconditionRequired,
    #[error("资源已经修改，请重新读取")]
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
}

// Authentication bodies and responses intentionally do not implement Debug.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
    pub device_label: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshInput {
    pub refresh_token: String,
}
#[derive(Serialize)]
pub struct LoginResponse {
    pub user: UserView,
    pub access_token: String,
    pub refresh_token: String,
    pub login_session_id: Uuid,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_states_cannot_be_reopened() {
        for state in [
            ConnectionState::Closed,
            ConnectionState::Failed,
            ConnectionState::Expired,
            ConnectionState::Revoked,
            ConnectionState::Interrupted,
        ] {
            assert!(!state.permits(ConnectionState::Active));
            assert!(!state.permits(ConnectionState::Connecting));
        }
    }
    #[test]
    fn error_wire_names_accept_legacy_values() {
        for (code, current, legacy) in [
            (
                ErrorCode::TicketInvalid,
                "SESSION_TICKET_INVALID",
                "TICKET_INVALID",
            ),
            (ErrorCode::TicketUsed, "SESSION_TICKET_USED", "TICKET_USED"),
            (
                ErrorCode::TicketExpired,
                "SESSION_TICKET_EXPIRED",
                "TICKET_EXPIRED",
            ),
            (
                ErrorCode::TicketStale,
                "SESSION_TICKET_STALE",
                "TICKET_STALE",
            ),
            (
                ErrorCode::AccessTokenExpired,
                "SESSION_EXPIRED",
                "ACCESS_TOKEN_EXPIRED",
            ),
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), current);
            for name in [current, legacy] {
                assert_eq!(
                    serde_json::from_value::<ErrorCode>(serde_json::json!(name)).unwrap(),
                    code
                );
            }
        }
    }
    #[test]
    fn unknown_capabilities_are_rejected() {
        assert!(serde_json::from_str::<Capability>("\"forward\"").is_err());
    }
}
