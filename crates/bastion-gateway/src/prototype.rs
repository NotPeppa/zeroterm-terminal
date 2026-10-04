use crate::{GatewayBackend, Target};
use async_trait::async_trait;
use bastion_domain::{Connection, ConnectionState, ErrorCode};
use bastion_store::PrototypeStore;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct PrototypeBackend {
    store: Arc<PrototypeStore>,
    target: Target,
}
#[async_trait]
impl GatewayBackend for PrototypeBackend {
    async fn consume(&self, id: Uuid, secret: &str) -> Result<(Connection, Target), ErrorCode> {
        Ok((self.store.consume(id, secret)?, self.target.clone()))
    }
    async fn authorize(&self, _: &Connection) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn transition(
        &self,
        id: Uuid,
        state: ConnectionState,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        self.store.transition(id, state, failure);
        Ok(())
    }
    async fn channel_audit(
        &self,
        _: &Connection,
        _: &str,
        _: Option<String>,
        _: Option<usize>,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }
}
pub async fn run(
    listener: TcpListener,
    key: russh::keys::PrivateKey,
    target: Target,
    store: Arc<PrototypeStore>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    crate::run_backend(
        listener,
        key,
        Arc::new(PrototypeBackend { store, target }),
        shutdown,
    )
    .await
}
