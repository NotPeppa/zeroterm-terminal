use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, OnceLock, Weak,
};
use std::{
    future::Future,
    task::{Context, Poll, Wake, Waker},
};
use tokio::time::Instant;

const POLICY_INTERVAL: Duration = Duration::from_secs(1);
const POLICY_TIMEOUT: Duration = Duration::from_secs(2);
const POLICY_GRACE: Duration = Duration::from_secs(5);
pub(crate) const STALL_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(1800);
const MAX_DURATION: Duration = Duration::from_secs(8 * 3600);

#[derive(Clone)]
pub struct RuntimeLimits {
    pub global_connections: usize,
    pub user_connections: usize,
    pub pending_connections: usize,
    pub connection_channels: usize,
    pub user_channels: usize,
    pub queue_bytes: usize,
    pub max_duration: Duration,
    pub idle_timeout: Duration,
    pub stall_timeout: Duration,
}
impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            global_connections: 100,
            user_connections: 10,
            pending_connections: 20,
            connection_channels: 16,
            user_channels: 64,
            queue_bytes: 256 * 1024,
            max_duration: MAX_DURATION,
            idle_timeout: IDLE_TIMEOUT,
            stall_timeout: STALL_TIMEOUT,
        }
    }
}
#[derive(Default)]
pub struct RuntimeRegistry {
    entries: Mutex<HashMap<Uuid, RegistryEntry>>,
    limits: RuntimeLimits,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    task_failed: AtomicBool,
}
struct RegistryEntry {
    user: Option<Uuid>,
    login: Option<Uuid>,
    stop: CancellationToken,
    channels: usize,
    session: Weak<ConnectionSession>,
}
impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn limits(&self) -> &RuntimeLimits {
        &self.limits
    }
    pub fn with_limits(limits: RuntimeLimits) -> Result<Self, ErrorCode> {
        let cap = RuntimeLimits::default();
        if limits.global_connections == 0
            || limits.global_connections > cap.global_connections
            || limits.user_connections == 0
            || limits.user_connections > cap.user_connections
            || limits.pending_connections == 0
            || limits.pending_connections > cap.pending_connections
            || limits.connection_channels == 0
            || limits.connection_channels > cap.connection_channels
            || limits.user_channels == 0
            || limits.user_channels > cap.user_channels
            || limits.queue_bytes == 0
            || limits.queue_bytes > cap.queue_bytes
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
            entries: Mutex::new(HashMap::new()),
            limits,
            tasks: Mutex::new(Vec::new()),
            task_failed: AtomicBool::new(false),
        })
    }
    pub fn global() -> Arc<Self> {
        static REGISTRY: OnceLock<Arc<RuntimeRegistry>> = OnceLock::new();
        REGISTRY.get_or_init(|| Arc::new(Self::new())).clone()
    }
    pub(crate) fn track(&self, task: JoinHandle<()>) {
        let mut tasks = self.tasks.lock().unwrap();
        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        tasks.retain_mut(|task| {
            if !task.is_finished() {
                return true;
            }
            match std::pin::Pin::new(task).poll(&mut context) {
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
        let deadline = Instant::now() + budget;
        while let Some(mut task) = tasks.next() {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    self.tasks.lock().unwrap().extend(tasks);
                    return Err(ErrorCode::RecordingUnavailable);
                }
                Err(_) => {
                    let mut tracked = self.tasks.lock().unwrap();
                    tracked.push(task);
                    tracked.extend(tasks);
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
    pub fn revoke_connection(&self, id: Uuid) {
        if let Some(entry) = self.entries.lock().unwrap().get(&id) {
            entry.stop.cancel();
        }
    }
    pub fn revoke_login(&self, id: Uuid) {
        for entry in self.entries.lock().unwrap().values() {
            if entry.login == Some(id) {
                entry.stop.cancel();
            }
        }
    }
    pub fn revoke_user(&self, id: Uuid) {
        for entry in self.entries.lock().unwrap().values() {
            if entry.user == Some(id) {
                entry.stop.cancel();
            }
        }
    }
    pub fn get(
        &self,
        id: Uuid,
        user: Uuid,
        login: Uuid,
    ) -> Result<Arc<ConnectionSession>, ErrorCode> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(&id).ok_or(ErrorCode::ResourceNotFound)?;
        if entry.user != Some(user) || entry.login != Some(login) {
            return Err(ErrorCode::PermissionDenied);
        }
        if entry.stop.is_cancelled() {
            return Err(ErrorCode::LoginSessionRevoked);
        }
        entry.session.upgrade().ok_or(ErrorCode::ResourceNotFound)
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        connection: &Connection,
        stop: CancellationToken,
    ) -> Result<ConnectionLease, ErrorCode> {
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(&connection.id)
            || entries.len() >= self.limits.global_connections
            || entries
                .values()
                .filter(|entry| entry.user == connection.user_id)
                .count()
                >= self.limits.user_connections
        {
            return Err(ErrorCode::ConnectionLimit);
        }
        entries.insert(
            connection.id,
            RegistryEntry {
                user: connection.user_id,
                login: connection.login_session_id,
                stop,
                channels: 0,
                session: Weak::new(),
            },
        );
        Ok(ConnectionLease {
            registry: self.clone(),
            id: connection.id,
        })
    }
    pub(crate) fn channel(self: &Arc<Self>, id: Uuid) -> Result<ChannelLease, ErrorCode> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get(&id).ok_or(ErrorCode::ResourceNotFound)?;
        if entry.stop.is_cancelled() {
            return Err(ErrorCode::LoginSessionRevoked);
        }
        let user = entry.user;
        let user_channels: usize = entries
            .values()
            .filter(|e| e.user == user)
            .map(|e| e.channels)
            .sum();
        if entry.channels >= self.limits.connection_channels
            || user_channels >= self.limits.user_channels
        {
            return Err(ErrorCode::ConnectionLimit);
        }
        entries.get_mut(&id).unwrap().channels += 1;
        Ok(ChannelLease {
            registry: self.clone(),
            id,
        })
    }
}
pub(crate) struct ConnectionLease {
    registry: Arc<RuntimeRegistry>,
    id: Uuid,
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if let Some(entry) = self.registry.entries.lock().unwrap().remove(&self.id) {
            entry.stop.cancel();
        }
    }
}
pub(crate) struct ChannelLease {
    registry: Arc<RuntimeRegistry>,
    id: Uuid,
}
impl Drop for ChannelLease {
    fn drop(&mut self) {
        if let Some(entry) = self.registry.entries.lock().unwrap().get_mut(&self.id) {
            entry.channels = entry.channels.saturating_sub(1);
        }
    }
}

/// One authenticated target transport, shared by terminal and HTTP file channels.
pub struct ConnectionSession {
    pub(crate) connection: Connection,
    pub(crate) target: TargetHandle,
    pub(crate) backend: Arc<dyn GatewayBackend>,
    pub(crate) registry: Arc<RuntimeRegistry>,
    pub(crate) stop: CancellationToken,
    pub(crate) activity: watch::Sender<Instant>,
    _lease: ConnectionLease,
}
impl ConnectionSession {
    pub async fn connect(
        connection: Connection,
        target: Target,
        backend: Arc<dyn GatewayBackend>,
        stop: CancellationToken,
    ) -> Result<Arc<Self>, ErrorCode> {
        let registry = backend.registry();
        let lease = registry.reserve(&connection, stop.clone())?;
        let target = tokio::select! {
            _ = stop.cancelled() => return Err(ErrorCode::LoginSessionRevoked),
            result = timeout(TARGET_TIMEOUT, async {
                authorize(backend.as_ref(), &connection).await?;
                let target = connect_target(&target).await?;
                if let Err(error) = authorize(backend.as_ref(), &connection).await {
                    let _ = target.disconnect(Disconnect::ByApplication, "authorization failed", "en").await;
                    return Err(error);
                }
                backend.transition(connection.id, ConnectionState::Active, None).await?;
                Ok(target)
            }) => result.map_err(|_| ErrorCode::TargetTimeout)??,
        };
        let (activity, activity_rx) = watch::channel(Instant::now());
        let session = Arc::new(Self {
            connection,
            target,
            backend,
            registry: registry.clone(),
            stop: stop.clone(),
            activity,
            _lease: lease,
        });
        registry
            .entries
            .lock()
            .unwrap()
            .get_mut(&session.connection.id)
            .unwrap()
            .session = Arc::downgrade(&session);
        let weak = Arc::downgrade(&session);
        let backend = session.backend.clone();
        let connection = session.connection.clone();
        let target = session.target.clone();
        let idle_timeout = registry.limits.idle_timeout;
        let max_duration = registry.limits.max_duration;
        registry.track(tokio::spawn(async move {
            let reason = tokio::select! {
                _ = stop.cancelled() => None,
                code = policy_checks(backend.as_ref(), &connection) => Some(code),
                _ = idle_checks(activity_rx, idle_timeout) => Some(ErrorCode::TargetTimeout),
                _ = tokio::time::sleep(max_duration) => Some(ErrorCode::TargetTimeout),
                _ = async { while !target.is_closed() { tokio::time::sleep(Duration::from_millis(200)).await; } } => Some(ErrorCode::TargetUnreachable),
            };
            stop.cancel();
            let _ = timeout(
                Duration::from_secs(2),
                target.disconnect(Disconnect::ByApplication, "gateway connection closed", "en"),
            )
            .await;
            let _ = timeout(Duration::from_secs(2), async {
                backend
                    .transition(connection.id, ConnectionState::Closing, reason)
                    .await?;
                backend
                    .transition(connection.id, ConnectionState::Closed, reason)
                    .await
            })
            .await;
            drop(weak);
        }));
        Ok(session)
    }
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    pub fn cancel(&self) {
        self.stop.cancel();
    }
    pub async fn open_sftp(
        self: &Arc<Self>,
        user: Uuid,
        login: Uuid,
    ) -> Result<SftpSession, ErrorCode> {
        if self.connection.user_id != Some(user) || self.connection.login_session_id != Some(login)
        {
            return Err(ErrorCode::PermissionDenied);
        }
        self.check(Capability::Sftp).await?;
        SftpSession::open(self.clone()).await
    }
    pub(crate) async fn check(&self, capability: Capability) -> Result<(), ErrorCode> {
        if self.stop.is_cancelled() {
            return Err(ErrorCode::LoginSessionRevoked);
        }
        if !self.connection.capabilities.contains(&capability) {
            return Err(ErrorCode::ChannelPermissionDenied);
        }
        authorize(self.backend.as_ref(), &self.connection).await
    }
    pub(crate) fn touch(&self) {
        self.activity.send_replace(Instant::now());
    }
}
impl Drop for ConnectionSession {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

pub(crate) async fn authorize(
    backend: &dyn GatewayBackend,
    connection: &Connection,
) -> Result<(), ErrorCode> {
    timeout(POLICY_TIMEOUT, backend.authorize(connection))
        .await
        .unwrap_or(Err(ErrorCode::PolicyStoreUnavailable))
}
pub(crate) async fn policy_checks(
    backend: &dyn GatewayBackend,
    connection: &Connection,
) -> ErrorCode {
    let mut failure: Option<Instant> = None;
    let mut next = Instant::now() + POLICY_INTERVAL;
    loop {
        let end = failure.map(|first| first + POLICY_GRACE);
        tokio::time::sleep_until(end.map(|end| end.min(next)).unwrap_or(next)).await;
        if end.is_some_and(|end| Instant::now() >= end) {
            return ErrorCode::PolicyStoreUnavailable;
        }
        let started = Instant::now();
        let budget = end
            .map(|end| end.saturating_duration_since(started).min(POLICY_TIMEOUT))
            .unwrap_or(POLICY_TIMEOUT);
        match timeout(budget, backend.authorize(connection))
            .await
            .unwrap_or(Err(ErrorCode::PolicyStoreUnavailable))
        {
            Ok(()) => failure = None,
            Err(ErrorCode::PolicyStoreUnavailable) => {
                failure.get_or_insert(started);
            }
            Err(code) => return code,
        }
        next = started + POLICY_INTERVAL;
    }
}
pub(crate) async fn idle_checks(mut activity: watch::Receiver<Instant>, budget: Duration) {
    loop {
        let deadline = *activity.borrow_and_update() + budget;
        tokio::select! {
            changed = activity.changed() => if changed.is_err() { return; },
            _ = tokio::time::sleep_until(deadline) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn connection(id: Uuid, user: Uuid) -> Connection {
        Connection {
            id,
            ticket_id: Uuid::new_v4(),
            asset_id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            capabilities: vec![Capability::Sftp],
            purpose: bastion_domain::Purpose::Terminal,
            transport: bastion_domain::TicketTransport::Websocket,
            protocol_version: 1,
            state: ConnectionState::Connecting,
            created_at: chrono::Utc::now(),
            failure: None,
            user_id: Some(user),
            login_session_id: Some(Uuid::new_v4()),
        }
    }
    #[tokio::test]
    async fn reaped_cleanup_panic_still_fails_drain() {
        let registry = RuntimeRegistry::new();
        let task = tokio::spawn(async {
            panic!("cleanup failed");
        });
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
        registry.track(task);
        registry.track(tokio::spawn(async {}));
        assert_eq!(
            registry.drain(Duration::from_secs(1)).await,
            Err(ErrorCode::RecordingUnavailable)
        );
    }
    #[test]
    fn limits_and_revoke_are_shared_and_raii() {
        let registry = Arc::new(RuntimeRegistry::new());
        let user = Uuid::new_v4();
        let mut connections = Vec::new();
        let mut channels = Vec::new();
        for _ in 0..4 {
            let connection = connection(Uuid::new_v4(), user);
            connections.push(
                registry
                    .reserve(&connection, CancellationToken::new())
                    .unwrap(),
            );
            for _ in 0..16 {
                channels.push(registry.channel(connection.id).unwrap());
            }
            assert!(registry.channel(connection.id).is_err());
        }
        let extra = connection(Uuid::new_v4(), user);
        connections.push(registry.reserve(&extra, CancellationToken::new()).unwrap());
        assert!(registry.channel(extra.id).is_err());
        channels.pop();
        assert!(registry.channel(extra.id).is_ok());
        registry.revoke_user(user);
        assert!(registry.channel(extra.id).is_err());
        drop(connections);
        assert!(registry.entries.lock().unwrap().is_empty());
    }
}
