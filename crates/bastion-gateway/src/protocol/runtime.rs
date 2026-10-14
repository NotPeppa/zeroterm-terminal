use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, OnceLock,
};
use std::{
    future::Future,
    task::{Context, Poll, Wake, Waker},
};
#[derive(Clone)]
pub struct RuntimeLimits {
    pub global_connections: usize,
    pub user_connections: usize,
    pub pending_connections: usize,
    pub queue_bytes: usize,
    pub startup_timeout: Duration,
    pub max_duration: Duration,
    pub idle_timeout: Duration,
    pub stall_timeout: Duration,
}
impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            global_connections: 10,
            user_connections: 3,
            pending_connections: 20,
            queue_bytes: 256 * 1024,
            startup_timeout: Duration::from_secs(45),
            max_duration: Duration::from_secs(8 * 3600),
            idle_timeout: Duration::from_secs(1800),
            stall_timeout: Duration::from_secs(30),
        }
    }
}
#[derive(Default)]
pub struct RuntimeRegistry {
    entries: Mutex<HashMap<Uuid, Entry>>,
    limits: RuntimeLimits,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    task_failed: AtomicBool,
    recorder_slots: OnceLock<Arc<tokio::sync::Semaphore>>,
}
struct Entry {
    user: Option<Uuid>,
    login: Option<Uuid>,
    stop: CancellationToken,
}
impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn limits(&self) -> &RuntimeLimits {
        &self.limits
    }
    pub fn with_limits(limits: RuntimeLimits) -> Result<Self, ErrorCode> {
        let cap = RuntimeLimits::default();
        if limits.global_connections == 0
            || limits.global_connections > cap.global_connections
            || limits.user_connections == 0
            || limits.user_connections > cap.user_connections
            || limits.user_connections > limits.global_connections
            || limits.pending_connections == 0
            || limits.pending_connections > cap.pending_connections
            || !(MAX_DATA_BYTES..=cap.queue_bytes).contains(&limits.queue_bytes)
            || !limits.queue_bytes.is_multiple_of(MAX_DATA_BYTES)
            || limits.startup_timeout.is_zero()
            || limits.startup_timeout > cap.startup_timeout
            || limits.max_duration.is_zero()
            || limits.max_duration > cap.max_duration
            || limits.idle_timeout.is_zero()
            || limits.idle_timeout > cap.idle_timeout
            || limits.stall_timeout.is_zero()
            || limits.stall_timeout > cap.stall_timeout
        {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(Self {
            limits,
            ..Default::default()
        })
    }
    pub fn global() -> Arc<Self> {
        static REGISTRY: OnceLock<Arc<RuntimeRegistry>> = OnceLock::new();
        REGISTRY.get_or_init(|| Arc::new(Self::new())).clone()
    }
    pub fn revoke_connection(&self, id: Uuid) {
        if let Some(e) = self.entries.lock().unwrap().get(&id) {
            e.stop.cancel();
        }
    }
    pub fn revoke_user(&self, id: Uuid) {
        for e in self.entries.lock().unwrap().values() {
            if e.user == Some(id) {
                e.stop.cancel();
            }
        }
    }
    pub fn revoke_login(&self, id: Uuid) {
        for e in self.entries.lock().unwrap().values() {
            if e.login == Some(id) {
                e.stop.cancel();
            }
        }
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        c: &Connection,
        stop: CancellationToken,
    ) -> Result<ConnectionLease, ErrorCode> {
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(&c.id)
            || entries.len() >= self.limits.global_connections
            || entries.values().filter(|e| e.user == c.user_id).count()
                >= self.limits.user_connections
        {
            return Err(ErrorCode::ConnectionLimit);
        }
        entries.insert(
            c.id,
            Entry {
                user: c.user_id,
                login: c.login_session_id,
                stop,
            },
        );
        Ok(ConnectionLease {
            registry: self.clone(),
            id: c.id,
        })
    }
    pub(crate) fn recording_slot(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ErrorCode> {
        self.recorder_slots
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(self.limits.global_connections)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::ConnectionLimit)
    }
    pub(crate) fn track(&self, task: JoinHandle<()>) {
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain_mut(|t| {
            if !t.is_finished() {
                return true;
            }
            match std::pin::Pin::new(t).poll(&mut context) {
                Poll::Ready(Ok(())) => false,
                Poll::Ready(Err(_)) => {
                    self.task_failed.store(true, Ordering::Release);
                    false
                }
                Poll::Pending => true,
            }
        });
        tasks.push(task);
    }
    pub async fn drain(&self, budget: Duration) -> Result<(), ErrorCode> {
        let mut tasks = std::mem::take(&mut *self.tasks.lock().unwrap()).into_iter();
        let deadline = tokio::time::Instant::now() + budget;
        while let Some(mut task) = tasks.next() {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    self.tasks.lock().unwrap().extend(tasks);
                    self.task_failed.store(true, Ordering::Release);
                    return Err(ErrorCode::RecordingUnavailable);
                }
                Err(_) => {
                    let mut pending = self.tasks.lock().unwrap();
                    pending.push(task);
                    pending.extend(tasks);
                    return Err(ErrorCode::RecordingUnavailable);
                }
            }
        }
        if self.task_failed.load(Ordering::Acquire) {
            Err(ErrorCode::RecordingUnavailable)
        } else {
            Ok(())
        }
    }
}
pub(crate) struct ConnectionLease {
    registry: Arc<RuntimeRegistry>,
    id: Uuid,
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if let Some(e) = self.registry.entries.lock().unwrap().remove(&self.id) {
            e.stop.cancel();
        }
    }
}
pub(crate) async fn authorize(
    backend: &dyn GatewayBackend,
    connection: &Connection,
) -> Result<(), ErrorCode> {
    timeout(Duration::from_secs(2), backend.authorize(connection))
        .await
        .unwrap_or(Err(ErrorCode::PolicyStoreUnavailable))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn connection(user: Uuid) -> Connection {
        Connection {
            id: Uuid::new_v4(),
            ticket_id: Uuid::new_v4(),
            asset_id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            target_protocol: TargetProtocol::Ssh,
            display: Display::default(),
            protocol_version: 2,
            state: ConnectionState::Connecting,
            created_at: chrono::Utc::now(),
            failure: None,
            user_id: Some(user),
            login_session_id: Some(Uuid::new_v4()),
            auth_revision: 1,
            routing_revision: 1,
            account_revision: 1,
            credential_revision: Some(1),
        }
    }
    #[test]
    fn limits_raii_and_revocation() {
        let registry = Arc::new(RuntimeRegistry::new());
        let user = Uuid::new_v4();
        let mut leases = Vec::new();
        let mut tokens = Vec::new();
        for _ in 0..3 {
            let stop = CancellationToken::new();
            leases.push(registry.reserve(&connection(user), stop.clone()).unwrap());
            tokens.push(stop);
        }
        assert!(registry
            .reserve(&connection(user), CancellationToken::new())
            .is_err());
        registry.revoke_user(user);
        assert!(tokens.iter().all(CancellationToken::is_cancelled));
        drop(leases);
        assert!(registry.entries.lock().unwrap().is_empty());
        assert!(RuntimeRegistry::with_limits(RuntimeLimits {
            startup_timeout: Duration::from_secs(46),
            ..Default::default()
        })
        .is_err());
    }
    #[tokio::test]
    async fn cleanup_panic_fails_drain() {
        let r = RuntimeRegistry::new();
        r.track(tokio::spawn(async { panic!("injected cleanup failure") }));
        assert!(r.drain(Duration::from_secs(1)).await.is_err());
    }
    #[test]
    fn writer_slots_survive_connection_cancellation_until_io_actually_finishes() {
        let registry = RuntimeRegistry::new();
        let mut slots: Vec<_> = (0..10)
            .map(|_| registry.recording_slot().unwrap())
            .collect();
        assert!(registry.recording_slot().is_err());
        registry.revoke_user(Uuid::new_v4());
        assert!(registry.recording_slot().is_err());
        slots.pop();
        assert!(registry.recording_slot().is_ok());
        drop(slots);
        assert!(registry.recording_slot().is_ok());
    }
}
