use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

/// Persisted non-shell channel lifetime. Drop is a failed close, never success.
pub(crate) struct ChannelLifecycle {
    pub(crate) id: Uuid,
    backend: Arc<dyn GatewayBackend>,
    exit: Mutex<(Option<u32>, Option<String>)>,
    finished: AtomicBool,
}
impl ChannelLifecycle {
    pub(crate) async fn begin(
        session: &ConnectionSession,
        upstream: u32,
        kind: bastion_domain::ChannelKind,
    ) -> Result<Arc<Self>, ErrorCode> {
        let id = timeout(
            Duration::from_secs(2),
            session
                .backend
                .begin_channel(&session.connection, upstream, kind),
        )
        .await
        .unwrap_or(Err(ErrorCode::PolicyStoreUnavailable))?;
        Ok(Arc::new(Self {
            id,
            backend: session.backend.clone(),
            exit: Mutex::new((None, None)),
            finished: AtomicBool::new(false),
        }))
    }
    pub(crate) async fn streaming(&self) -> Result<(), ErrorCode> {
        timeout(Duration::from_secs(2), self.backend.mark_streaming(self.id))
            .await
            .unwrap_or(Err(ErrorCode::PolicyStoreUnavailable))
    }
    pub(crate) fn exit(&self, code: Option<u32>, signal: Option<String>) {
        *self.exit.lock().unwrap() = (code, signal);
    }
    pub(crate) async fn finish(&self, failure: Option<ErrorCode>) -> Result<(), ErrorCode> {
        if self.finished.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let (code, signal) = self.exit.lock().unwrap().clone();
        let result = timeout(
            Duration::from_secs(2),
            self.backend.finish_channel(self.id, code, signal, failure),
        )
        .await
        .unwrap_or(Err(ErrorCode::PolicyStoreUnavailable));
        if result.is_err() {
            self.finished.store(false, Ordering::Release);
        }
        result
    }
}
impl Drop for ChannelLifecycle {
    fn drop(&mut self) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            let backend = self.backend.clone();
            let id = self.id;
            let (code, signal) = self.exit.lock().unwrap().clone();
            let registry = backend.registry();
            registry.track(tokio::spawn(async move {
                let _ = timeout(
                    Duration::from_secs(2),
                    backend.finish_channel(id, code, signal, Some(ErrorCode::TargetUnreachable)),
                )
                .await;
            }));
        }
    }
}
