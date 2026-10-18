//! RFC-006 native SSH entry. ZeroTerm (or any standard SSH client) authenticates with
//! `zt1:<ticket_id>` + ticket secret. Up to sixteen session channels share one pinned target
//! socket. Shell uses the browser frame pump and recording; exec and SFTP carry metadata audits.
//! Registry revocation, authorization and time limits apply to the whole connection.
use super::*;
use super::{
    recording::SessionRecording,
    runtime::authorize,
    ssh::{input_charge, NativeLink},
};
use bytes::Bytes;
use russh::{
    keys::PrivateKey,
    server::{self, Auth, Msg, Session},
    Channel, ChannelId, ChannelMsg, MethodKind, MethodSet,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, watch, Notify, OnceCell},
    task::JoinSet,
    time::Instant,
};

/// One redeemed `zt1:` ticket: the connecting connection and its resolved target.
pub struct NativeTicket {
    pub connection: Connection,
    pub capabilities: Vec<String>,
    pub target: Target,
}
/// Ticket redemption, implemented by the control API (store, key ring, network policy, limiter).
#[async_trait]
pub trait NativeTickets: Send + Sync {
    /// Exactly one call per SSH connection. `ticket` is None for a malformed `zt1:` username. Failures
    /// are audited with the peer address and leave a valid ticket untouched on a wrong secret.
    async fn redeem(
        &self,
        ticket: Option<Uuid>,
        secret: &str,
        peer: IpAddr,
    ) -> Result<NativeTicket, ErrorCode>;
}
#[derive(Clone)]
pub struct NativeListenerConfig {
    pub host_key: PrivateKey,
    /// Connections that have not yet authenticated (RFC-006 §4.2, default 64).
    pub max_unauthenticated: usize,
    /// From accept to a successful password, 10 s by RFC-006 §4.2.
    pub handshake_timeout: Duration,
}

/// Accept loop. Stores `true` into `running` while accepting and `false` before it stops; on
/// `shutdown` it stops accepting and waits (bounded) for every connection to finish its recording.
pub async fn serve_native(
    listener: TcpListener,
    config: NativeListenerConfig,
    tickets: Arc<dyn NativeTickets>,
    backend: Arc<dyn GatewayBackend>,
    shutdown: CancellationToken,
    running: Arc<AtomicBool>,
) -> Result<(), ErrorCode> {
    if config.max_unauthenticated == 0 || config.handshake_timeout.is_zero() {
        return Err(ErrorCode::InvalidArgument);
    }
    let limits = backend.registry().limits().clone();
    let ssh = Arc::new(server::Config {
        server_id: russh::SshId::Standard("SSH-2.0-ZeroTermBastion".into()),
        methods: MethodSet::from(&[MethodKind::Password][..]),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![config.host_key.clone()],
        // OpenSSH probes `none` first; the single password attempt is enforced by the handler.
        max_auth_attempts: 6,
        window_size: limits.queue_bytes as u32,
        maximum_packet_size: MAX_DATA_BYTES as u32,
        channel_buffer_size: 16,
        event_buffer_size: 16,
        // Idle/absolute limits live at connection level; keepalives detect a dead peer.
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        nodelay: true,
        ..Default::default()
    });
    let unauthenticated = Arc::new(Semaphore::new(config.max_unauthenticated));
    let mut connections = JoinSet::new();
    running.store(true, Ordering::Release);
    let result = loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break Ok(()),
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(value) => value,
                    // Transient per-connection failures (e.g. reset before accept) must not stop the listener.
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::Interrupted) => continue,
                    Err(_) => break Err(ErrorCode::InternalError),
                };
                // Over the unauthenticated bound the socket is dropped before any SSH byte.
                let Ok(permit) = unauthenticated.clone().try_acquire_owned() else { continue };
                let _ = socket.set_nodelay(true);
                connections.spawn(connection(
                    socket,
                    peer.ip(),
                    ssh.clone(),
                    config.handshake_timeout,
                    permit,
                    tickets.clone(),
                    backend.clone(),
                    shutdown.child_token(),
                ));
            }
        }
    };
    running.store(false, Ordering::Release);
    drop(listener);
    shutdown.cancel();
    // Each connection sees cancellation and finishes its recording; bound the wait.
    let drained = timeout(Duration::from_secs(9), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    connections.abort_all();
    if drained.is_err() {
        return Err(ErrorCode::RecordingUnavailable);
    }
    result
}

struct Authenticated {
    context: Arc<NativeContext>,
}
struct NativeContext {
    ticket: NativeTicket,
    handle: server::Handle,
    backend: Arc<dyn GatewayBackend>,
    target: OnceCell<Result<Arc<ssh::TargetSession>, ErrorCode>>,
    stop: CancellationToken,
    activity: Mutex<Instant>,
    failure: Mutex<Option<ErrorCode>>,
    tasks: Mutex<JoinSet<()>>,
    started: AtomicBool,
}
impl NativeContext {
    fn touch(&self) {
        *self.activity.lock().unwrap() = Instant::now();
    }
    fn fail(&self, code: ErrorCode) {
        self.failure.lock().unwrap().get_or_insert(code);
        self.stop.cancel();
    }
    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().unwrap();
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                self.fail(ErrorCode::InternalError);
            }
        }
        tasks.spawn(task);
    }
    fn permits(&self, capability: &str) -> bool {
        self.ticket.capabilities.iter().any(|c| c == capability)
    }
    async fn target(&self) -> Result<Arc<ssh::TargetSession>, ErrorCode> {
        self.target
            .get_or_init(|| async {
                let registry = self.backend.registry();
                let result = tokio::select! {
                    _ = self.stop.cancelled() => Err(ErrorCode::LoginSessionRevoked),
                    result = timeout(self.backend.registry().limits().startup_timeout,
                        ssh::connect_target(&self.ticket.connection, &self.ticket.target,
                            self.backend.as_ref(), registry.limits())) =>
                        result.unwrap_or(Err(ErrorCode::TargetTimeout)).map(Arc::new),
                };
                if let Err(code) = result {
                    self.fail(code);
                }
                result
            })
            .await
            .clone()
    }
}
struct NativeChannel {
    channel: Option<Channel<Msg>>,
    shared: Arc<Shared>,
    pty: bool,
    used: bool,
    done: Arc<AtomicBool>,
}

#[derive(Default)]
struct Input {
    acks: VecDeque<u32>,
    size: Option<(u32, u32)>,
    data: VecDeque<u8>,
    activity: bool,
    shell: bool,
    /// Buffered client input exceeded `Shared::budget`: the session closes as overloaded.
    overflow: bool,
    /// The client closed its channel: like a browser's normal close, input ends and the session
    /// finishes gracefully.
    closed: bool,
}
/// Handler, channel reader and output writer state. Never awaited while locked.
struct Shared {
    input: Mutex<Input>,
    /// Wakes `forward` (new input, ACK, size, close).
    wake: Notify,
    /// Hard bound of buffered client input, in bytes.
    budget: usize,
    /// None until `ssh::run` reports ready (true) or fails first (false).
    ready: watch::Sender<Option<bool>>,
}
impl Shared {
    fn update(&self, change: impl FnOnce(&mut Input)) {
        change(&mut self.input.lock().unwrap());
        self.wake.notify_one();
    }
}
fn clamp_size(cols: u32, rows: u32) -> (u32, u32) {
    // xterm limits of the browser contract; real clients may report 0 or very wide terminals.
    (cols.clamp(2, 500), rows.clamp(1, 200))
}

struct NativeHandler {
    tickets: Arc<dyn NativeTickets>,
    backend: Arc<dyn GatewayBackend>,
    peer: IpAddr,
    attempted: bool,
    auth: Option<oneshot::Sender<Option<Authenticated>>>,
    ticket: Option<NativeTicket>,
    context: Option<Arc<NativeContext>>,
    channels: HashMap<ChannelId, NativeChannel>,
    shell_used: bool,
    stop: CancellationToken,
}
impl Drop for NativeHandler {
    fn drop(&mut self) {
        // A consumed ticket whose session never started still ends in a terminal state.
        if let Some(ticket) = self.ticket.take() {
            let backend = self.backend.clone();
            tokio::spawn(async move {
                let _ = backend
                    .transition(
                        ticket.connection.id,
                        ConnectionState::Failed,
                        Some(ErrorCode::AuthOrGatewayFailed),
                    )
                    .await;
            });
        }
    }
}
impl NativeHandler {
    /// Any authentication after the single password attempt tears the connection down.
    fn second_attempt(&self) -> Result<(), russh::Error> {
        if self.attempted {
            Err(russh::Error::Disconnect)
        } else {
            Ok(())
        }
    }
}
impl NativeHandler {
    /// Dispatches exec and SFTP onto the shared authenticated target socket.
    async fn start_plain(
        &mut self,
        id: ChannelId,
        command: Option<&[u8]>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let ctx = self.context.as_ref().unwrap().clone();
        let Some(c) = self.channels.get_mut(&id) else {
            return session.channel_failure(id);
        };
        if c.used || c.pty {
            return session.channel_failure(id);
        }
        let Some(client) = c.channel.take() else {
            return session.channel_failure(id);
        };
        c.used = true;
        let done = c.done.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let command = command.map(Vec::from);
        let task_ctx = ctx.clone();
        // Opening exec/SFTP is not interaction: periodic client tools (metrics polling) must not keep an
        // otherwise idle connection alive. exec stdin, SFTP requests and shell input still count.
        ctx.spawn(async move {
            if plain_session(task_ctx, client, command, ready_tx).await {
                done.store(true, Ordering::Release);
            }
        });
        let result = tokio::select! {
            _ = ctx.stop.cancelled() => None,
            result = ready_rx => result.ok(),
        };
        match result {
            Some(Ok(())) => session.channel_success(id),
            Some(Err(client)) => {
                if let Some(c) = self.channels.get_mut(&id) {
                    c.channel = Some(client);
                    c.used = false;
                }
                session.channel_failure(id)
            }
            None => session.channel_failure(id),
        }
    }
}
fn refuse() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(MethodSet::empty()),
        partial_success: false,
    }
}
impl server::Handler for NativeHandler {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        self.second_attempt()?;
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }
    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        _: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.second_attempt()?;
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.second_attempt()?;
        Ok(refuse())
    }
    async fn auth_openssh_certificate(
        &mut self,
        _: &str,
        _: &russh::keys::Certificate,
    ) -> Result<Auth, Self::Error> {
        self.second_attempt()?;
        Ok(refuse())
    }
    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _: &str,
        _: &str,
        _: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        self.second_attempt()?;
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.second_attempt()?;
        self.attempted = true;
        let ticket = user
            .strip_prefix("zt1:")
            .and_then(|id| Uuid::parse_str(id).ok())
            .filter(|id| user.len() == 4 + 36 && id.hyphenated().to_string() == user[4..]);
        let redeemed = tokio::select! {
            _ = self.stop.cancelled() => Err(ErrorCode::PolicyStoreUnavailable),
            result = self.tickets.redeem(ticket, password, self.peer) => result,
        };
        match redeemed {
            Ok(ticket) => {
                self.ticket = Some(ticket);
                Ok(Auth::Accept)
            }
            Err(_) => {
                // The connection task disconnects; one password attempt per connection.
                if let Some(auth) = self.auth.take() {
                    let _ = auth.send(None);
                }
                Ok(refuse())
            }
        }
    }
    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let (Some(ticket), Some(auth)) = (self.ticket.take(), self.auth.take()) else {
            return Err(russh::Error::Inconsistent);
        };
        let context = Arc::new(NativeContext {
            ticket,
            handle: session.handle(),
            backend: self.backend.clone(),
            target: OnceCell::new(),
            stop: self.stop.clone(),
            activity: Mutex::new(Instant::now()),
            failure: Mutex::new(None),
            tasks: Mutex::new(JoinSet::new()),
            started: AtomicBool::new(false),
        });
        if auth
            .send(Some(Authenticated {
                context: context.clone(),
            }))
            .is_err()
        {
            let _ = self
                .backend
                .transition(
                    context.ticket.connection.id,
                    ConnectionState::Failed,
                    Some(ErrorCode::AuthOrGatewayFailed),
                )
                .await;
            return Err(russh::Error::Disconnect);
        }
        self.context = Some(context);
        Ok(())
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.retain(|_, c| !c.done.load(Ordering::Acquire));
        if self.context.is_none() || self.channels.len() >= 16 {
            return Ok(());
        }
        let shared = Arc::new(Shared {
            input: Mutex::new(Input::default()),
            wake: Notify::new(),
            budget: 4 * self.backend.registry().limits().queue_bytes,
            ready: watch::channel(None).0,
        });
        let id = channel.id();
        reply.accept().await;
        self.channels.insert(
            id,
            NativeChannel {
                channel: Some(channel),
                shared,
                pty: false,
                used: false,
                done: Arc::new(AtomicBool::new(false)),
            },
        );
        Ok(())
    }
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(c) = self.channels.get_mut(&channel) else {
            return session.channel_failure(channel);
        };
        if !self.context.as_ref().is_some_and(|c| c.permits("shell"))
            || c.pty
            || c.used
            || self.shell_used
        {
            return session.channel_failure(channel);
        }
        c.pty = true;
        c.shared
            .update(|input| input.size = Some(clamp_size(cols, rows)));
        session.channel_success(channel)
    }
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(c) = self.channels.get(&channel) else {
            return session.channel_failure(channel);
        };
        if !c.pty {
            return session.channel_failure(channel);
        }
        c.shared
            .update(|input| input.size = Some(clamp_size(cols, rows)));
        session.channel_success(channel)
    }
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(ctx) = self.context.clone() else {
            return session.channel_failure(channel);
        };
        let Some(c) = self.channels.get_mut(&channel) else {
            return session.channel_failure(channel);
        };
        if !ctx.permits("shell") || !c.pty || c.used || self.shell_used {
            return session.channel_failure(channel);
        }
        let Some(client) = c.channel.take() else {
            return session.channel_failure(channel);
        };
        self.shell_used = true;
        c.used = true;
        c.shared.update(|input| input.shell = true);
        let (shared, done) = (c.shared.clone(), c.done.clone());
        let mut ready = shared.ready.subscribe();
        ctx.started.store(true, Ordering::Release);
        ctx.touch();
        let task_ctx = ctx.clone();
        ctx.spawn(async move {
            shell_session(task_ctx, client, shared).await;
            done.store(true, Ordering::Release);
        });
        let opened = tokio::select! {
            _ = ctx.stop.cancelled() => false,
            value = ready.wait_for(Option::is_some) => value.ok().and_then(|v| *v).unwrap_or(false),
        };
        if opened {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(ctx) = self.context.clone() else {
            return session.channel_failure(channel);
        };
        let reason = if !ctx.permits("exec") {
            Some(ErrorCode::PermissionDenied)
        } else if command.len() > 64 * 1024 || command.contains(&0) {
            Some(ErrorCode::InvalidArgument)
        } else if !self
            .channels
            .get(&channel)
            .is_some_and(|c| !c.used && !c.pty && c.channel.is_some())
        {
            Some(ErrorCode::TargetRequestRejected)
        } else {
            None
        };
        if let Some(code) = reason {
            let _ = ctx
                .backend
                .exec_rejected(&ctx.ticket.connection, command, code)
                .await;
            return session.channel_failure(channel);
        }
        self.start_plain(channel, Some(command), session).await
    }
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            return session.channel_failure(channel);
        }
        if let Some(ctx) = &self.context {
            let reason = if !ctx.permits("sftp") {
                Some(ErrorCode::PermissionDenied)
            } else if !self
                .channels
                .get(&channel)
                .is_some_and(|c| !c.used && !c.pty && c.channel.is_some())
            {
                Some(ErrorCode::TargetRequestRejected)
            } else {
                None
            };
            if let Some(code) = reason {
                let _ = ctx
                    .backend
                    .sftp_rejected(&ctx.ticket.connection, code)
                    .await;
                return session.channel_failure(channel);
            }
        } else {
            return session.channel_failure(channel);
        }
        self.start_plain(channel, None, session).await
    }
    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
    }
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        _: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Ignored: the target environment is never client-controlled.
        session.channel_failure(channel)
    }
    async fn signal(
        &mut self,
        channel: ChannelId,
        _: russh::Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
    }
    // agent, x11/direct/forwarded tcpip, streamlocal channels and global forwarding requests keep
    // russh's rejecting defaults.
}

#[allow(clippy::too_many_arguments)]
async fn connection(
    socket: tokio::net::TcpStream,
    peer: IpAddr,
    config: Arc<server::Config>,
    handshake: Duration,
    permit: OwnedSemaphorePermit,
    tickets: Arc<dyn NativeTickets>,
    backend: Arc<dyn GatewayBackend>,
    stop: CancellationToken,
) {
    let deadline = Instant::now() + handshake;
    let (auth_tx, mut auth_rx) = oneshot::channel();
    let handler = NativeHandler {
        tickets,
        backend: backend.clone(),
        peer,
        attempted: false,
        auth: Some(auth_tx),
        ticket: None,
        context: None,
        channels: HashMap::new(),
        shell_used: false,
        stop: stop.clone(),
    };
    let Ok(Ok(mut running)) =
        tokio::time::timeout_at(deadline, server::run_stream(config, socket, handler)).await
    else {
        return;
    };
    let handle = running.handle();
    let mut ended = false;
    let authenticated = tokio::select! {
        _ = &mut running => { ended = true; None },
        _ = stop.cancelled() => None,
        value = tokio::time::timeout_at(deadline, &mut auth_rx) => value.ok().and_then(Result::ok).flatten(),
    };
    // Shutdown or the deadline can race a just-redeemed ticket: it still ends as failed.
    auth_rx.close();
    let authenticated = match (authenticated, auth_rx.try_recv()) {
        (None, Ok(Some(Authenticated { context }))) => {
            let _ = backend
                .transition(
                    context.ticket.connection.id,
                    ConnectionState::Failed,
                    Some(ErrorCode::AuthOrGatewayFailed),
                )
                .await;
            None
        }
        (value, _) => value,
    };
    if ended {
        return;
    }
    let Some(Authenticated { context }) = authenticated else {
        let _ = timeout(
            Duration::from_secs(1),
            handle.disconnect(
                russh::Disconnect::NoMoreAuthMethodsAvailable,
                "authentication failed".into(),
                "en".into(),
            ),
        )
        .await;
        let _ = timeout(Duration::from_secs(1), running).await;
        drop(permit);
        return;
    };
    drop(permit);
    let registry = backend.registry();
    let limits = registry.limits().clone();
    let lease = registry.reserve(&context.ticket.connection, stop.clone());
    let started = Instant::now();
    let result = match lease.as_ref() {
        Err(code) => Err(*code),
        Ok(_) => {
            let mut checks = tokio::time::interval(Duration::from_secs(1));
            loop {
                let idle = *context.activity.lock().unwrap() + limits.idle_timeout;
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => break Err(context.failure.lock().unwrap().unwrap_or(ErrorCode::LoginSessionRevoked)),
                    value = &mut running => {
                        ended = true;
                        break if matches!(value, Ok(())) && context.started.load(Ordering::Acquire) { Ok(()) }
                            else { Err(ErrorCode::AuthOrGatewayFailed) };
                    },
                    _ = tokio::time::sleep_until(started + limits.max_duration) => break Err(ErrorCode::TargetTimeout),
                    _ = tokio::time::sleep_until(idle) => {
                        if context.activity.lock().unwrap().elapsed() >= limits.idle_timeout {
                            break Err(ErrorCode::TargetTimeout);
                        }
                    },
                    _ = checks.tick() => if let Err(code) = authorize(backend.as_ref(), &context.ticket.connection).await { break Err(code); },
                }
            }
        }
    };
    if let Err(code) = result {
        context.failure.lock().unwrap().get_or_insert(code);
    }
    stop.cancel();
    let mut tasks = std::mem::take(&mut *context.tasks.lock().unwrap());
    while let Some(task) = tasks.join_next().await {
        if task.is_err() {
            context
                .failure
                .lock()
                .unwrap()
                .get_or_insert(ErrorCode::InternalError);
        }
    }
    if let Some(Ok(target)) = context.target.get() {
        let _ = timeout(
            Duration::from_secs(1),
            target
                .handle
                .disconnect(russh::Disconnect::ByApplication, "", "en"),
        )
        .await;
    }
    let code = *context.failure.lock().unwrap();
    if let Some(code) = code {
        let _ = backend
            .transition(
                context.ticket.connection.id,
                ConnectionState::Failed,
                Some(code),
            )
            .await;
    } else {
        let _ = backend
            .transition(context.ticket.connection.id, ConnectionState::Closing, None)
            .await;
        let _ = backend
            .transition(context.ticket.connection.id, ConnectionState::Closed, None)
            .await;
    }
    drop(lease);
    if ended {
        return;
    }
    let _ = timeout(
        Duration::from_secs(1),
        handle.disconnect(
            russh::Disconnect::ByApplication,
            "connection closed".into(),
            "en".into(),
        ),
    )
    .await;
    let _ = timeout(Duration::from_secs(2), running).await;
}

/// Shell only: reuse the browser's frame pump and recording, on the connection's target handle.
async fn shell_session(ctx: Arc<NativeContext>, channel: Channel<Msg>, shared: Arc<Shared>) {
    let limits = ctx.backend.registry().limits().clone();
    let capacity = (limits.queue_bytes / MAX_DATA_BYTES).max(1);
    let (input, mut incoming) = mpsc::channel(capacity);
    let (outgoing, output) = mpsc::channel(capacity);
    let link = NativeLink::new(limits.queue_bytes);
    let id = channel.id();
    let (reader, writer) = channel.split();
    let io = async {
        tokio::join!(
            read_client(reader, &shared, &ctx.stop, &ctx),
            write_client(output, writer, &shared, &ctx.stop)
        );
    };
    let run = async {
        let target = ctx.target().await?;
        let recording =
            SessionRecording::prepare(ctx.backend.clone(), &ctx.ticket.connection).await?;
        let pump = ssh::run_on_target(
            &target.handle,
            &ctx.ticket.connection,
            ctx.backend.as_ref(),
            &recording,
            &mut incoming,
            &outgoing,
            &ctx.stop,
            &limits,
            &link,
        );
        tokio::pin!(pump);
        let mut ready = shared.ready.subscribe();
        let deadline = Instant::now() + limits.startup_timeout;
        let result = loop {
            let opened = *ready.borrow() == Some(true);
            tokio::select! {
                biased;
                _ = ctx.stop.cancelled() => break Err(ErrorCode::LoginSessionRevoked),
                _ = recording.closed() => break Err(ErrorCode::RecordingUnavailable),
                result = &mut pump => break result,
                _ = tokio::time::sleep_until(deadline), if !opened => break Err(ErrorCode::TargetTimeout),
                _ = ready.changed(), if !opened => {},
            }
        };
        let clean = result.is_ok() && !ctx.stop.is_cancelled();
        recording
            .finish(
                if clean { "closed" } else { "interrupted" },
                if clean {
                    RecordingState::Complete
                } else {
                    RecordingState::Partial
                },
                result.as_ref().err().copied(),
            )
            .await?;
        result
    };
    let result = {
        tokio::pin!(run);
        tokio::pin!(io);
        let forwarding = forward(&shared, &link, input, &ctx.stop);
        tokio::pin!(forwarding);
        let mut io_done = false;
        let mut forward_done = false;
        loop {
            tokio::select! {
                value = &mut run => break value,
                _ = &mut io, if !io_done => io_done = true,
                _ = &mut forwarding, if !forward_done => forward_done = true,
            }
        }
    };
    shared.ready.send_if_modified(|v| {
        if v.is_none() {
            *v = Some(false);
            true
        } else {
            false
        }
    });
    if result.is_ok() {
        let exit = link.exit.lock().unwrap().clone();
        relay_exit(&ctx, id, exit).await;
    } else if let Err(code) = result {
        ctx.fail(code);
    }
    // Handle APIs are used only for control messages; data uses the window-aware channel writer.
    shared.update(|i| i.closed = true);
    let _ = ctx.handle.close(id).await;
}

async fn relay_exit(ctx: &NativeContext, id: ChannelId, exit: ssh::TargetExit) {
    if exit.eof {
        let _ = ctx.handle.eof(id).await;
    }
    if let Some((signal, core, message)) = exit.signal {
        let _ = ctx
            .handle
            .exit_signal_request(id, signal, core, message, "en".into())
            .await;
    } else if let Some(status) = exit.status {
        let _ = ctx.handle.exit_status_request(id, status).await;
    }
}

/// Exec/SFTP startup replies only once the target has accepted the request. A refusal returns
/// ownership of the client channel so it can be reused, as required by the native client contract.
async fn plain_session(
    ctx: Arc<NativeContext>,
    client: Channel<Msg>,
    command: Option<Vec<u8>>,
    ready: oneshot::Sender<Result<(), Channel<Msg>>>,
) -> bool {
    let limits = ctx.backend.registry().limits().clone();
    let open = async {
        let target = ctx.target().await?;
        authorize(ctx.backend.as_ref(), &ctx.ticket.connection).await?;
        let mut upstream = target
            .handle
            .channel_open_session()
            .await
            .map_err(|_| ErrorCode::TargetRequestRejected)?;
        if let Some(command) = &command {
            upstream.exec(true, command.clone()).await
        } else {
            upstream.request_subsystem(true, "sftp").await
        }
        .map_err(|_| ErrorCode::TargetRequestRejected)?;
        if let Err(code) = ssh::accepted(&mut upstream).await {
            let _ = upstream.close().await;
            return Err(code);
        }
        ctx.backend
            .activate_native_connection(&ctx.ticket.connection)
            .await?;
        Ok(upstream)
    };
    let opened = tokio::select! {
        _ = ctx.stop.cancelled() => Err(ErrorCode::LoginSessionRevoked),
        value = timeout(limits.startup_timeout, open) => value.unwrap_or(Err(ErrorCode::TargetTimeout)),
    };
    let upstream = match opened {
        Ok(channel) => channel,
        Err(code) => {
            if let Some(command) = &command {
                let _ = ctx
                    .backend
                    .exec_rejected(&ctx.ticket.connection, command, code)
                    .await;
            } else {
                let _ = ctx
                    .backend
                    .sftp_rejected(&ctx.ticket.connection, code)
                    .await;
            }
            let _ = ready.send(Err(client));
            return false;
        }
    };
    ctx.started.store(true, Ordering::Release);
    let id = client.id();
    if ready.send(Ok(())).is_err() {
        let _ = upstream.close().await;
        return true;
    }
    if let Some(command) = command {
        exec_channel(&ctx, client, upstream, &command).await;
    } else {
        super::sftp::run(
            &ctx.ticket.connection,
            ctx.backend.clone(),
            client,
            upstream,
            &ctx.stop,
            &ctx.activity,
            limits.stall_timeout,
        )
        .await;
    }
    let _ = ctx.handle.close(id).await;
    true
}

async fn exec_channel(
    ctx: &NativeContext,
    client: Channel<Msg>,
    upstream: Channel<russh::client::Msg>,
    command: &[u8],
) {
    let started = Instant::now();
    let mut outcome = ExecOutcome::default();
    let stdin_bytes = std::sync::atomic::AtomicU64::new(0);
    let (mut from_client, to_client) = client.split();
    let (mut from_target, to_target) = upstream.split();
    let stall = ctx.backend.registry().limits().stall_timeout;
    // Independent bounded SSH readers/writers avoid bidirectional echo deadlocks. Every write is
    // bounded by a stall deadline and by the peer's channel window; no application output queue.
    let input = async {
        loop {
            match from_client.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    ctx.touch();
                    timeout(stall, to_target.data_bytes(data.clone()))
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())?;
                    stdin_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Some(ChannelMsg::Eof) => {
                    to_target.eof().await.map_err(|_| ())?;
                }
                Some(ChannelMsg::Close) | None => return Ok::<_, ()>(()),
                _ => {}
            }
        }
    };
    let output = async {
        let mut exit = ssh::TargetExit::default();
        loop {
            match from_target.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    let n = data.len() as u64;
                    timeout(stall, to_client.data_bytes(data))
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())?;
                    outcome.stdout_bytes += n;
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    let n = data.len() as u64;
                    timeout(stall, to_client.extended_data_bytes(ext, data))
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())?;
                    if ext == 1 {
                        outcome.stderr_bytes += n;
                    }
                }
                Some(ChannelMsg::Eof) => exit.eof = true,
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    exit.status = Some(exit_status);
                    outcome.exit_status = Some(exit_status);
                }
                Some(ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    ..
                }) => {
                    outcome.exit_signal = Some(match &signal_name {
                        russh::Sig::Custom(name) => name.clone(),
                        _ => format!("{signal_name:?}"),
                    });
                    exit.signal = Some((signal_name, core_dumped, error_message));
                }
                Some(ChannelMsg::Close) | None => {
                    relay_exit(ctx, to_client.id(), exit).await;
                    return Ok::<_, ()>(());
                }
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                _ => return Err(()),
            }
        }
    };
    {
        tokio::pin!(input);
        tokio::pin!(output);
        tokio::select! {
            _ = ctx.stop.cancelled() => {},
            _ = &mut input => {},
            _ = &mut output => {},
        }
    }
    let _ = timeout(Duration::from_secs(1), to_target.close()).await;
    outcome.stdin_bytes = stdin_bytes.load(Ordering::Relaxed);
    outcome.duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let _ = ctx
        .backend
        .exec_completed(&ctx.ticket.connection, command, &outcome)
        .await;
}

/// Client channel data is queued here and this reader never waits: russh refills the receive window
/// on arrival and its session loop also carries our output, so blocking here could stall output and,
/// through `ssh::pump`, input. Input past `budget` is never truncated; the session closes instead,
/// like browser overload.
async fn read_client(
    mut reader: russh::ChannelReadHalf,
    shared: &Shared,
    stop: &CancellationToken,
    ctx: &NativeContext,
) {
    loop {
        let message = tokio::select! {
            _ = stop.cancelled() => return,
            message = reader.wait() => message,
        };
        match message {
            Some(ChannelMsg::Data { data }) => {
                ctx.touch();
                shared.update(|input| {
                    if input.data.len() + data.len() > shared.budget {
                        input.overflow = true;
                    } else {
                        input.data.extend(data.iter());
                        input.activity = true;
                    }
                });
            }
            // Client EOF has no target-side frame; the target decides when the shell ends.
            Some(ChannelMsg::Eof) => {}
            Some(ChannelMsg::Close) => {
                shared.update(|input| input.closed = true);
                return;
            }
            // The SSH connection itself went away: abnormal, like a browser socket error.
            None => {
                stop.cancel();
                return;
            }
            // Requests are answered by the handler; stderr from a client is meaningless.
            Some(_) => {}
        }
    }
}

/// `run` output: type 1 goes to the channel (bounded by the client's SSH window), then its ACK is
/// queued. Type 2 echoes a size the client already has; type 3 releases the shell reply.
async fn write_client(
    mut output: mpsc::Receiver<Vec<u8>>,
    writer: russh::ChannelWriteHalf<Msg>,
    shared: &Shared,
    stop: &CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            _ = stop.cancelled() => return,
            frame = output.recv() => frame,
        };
        let Some(frame) = frame else { return };
        match frame.first() {
            Some(&TERMINAL_DATA) if frame.len() > 1 => {
                let written = tokio::select! {
                    _ = stop.cancelled() => return,
                    result = writer.data_bytes(Bytes::copy_from_slice(&frame[1..])) => result,
                };
                if written.is_err() {
                    stop.cancel();
                    return;
                }
                shared.update(|input| input.acks.push_back(frame.len() as u32));
            }
            Some(&TERMINAL_SIZE) => {}
            Some(&TERMINAL_READY) if frame.len() == 1 => {
                shared.ready.send_replace(Some(true));
            }
            _ => {
                stop.cancel();
                return;
            }
        }
    }
}

/// The single producer of `run`'s input frames. ACKs never wait for input credit, so output can
/// always drain; type 1 and resize frames take pacer credit that `ssh::pump` returns after the target
/// write. Any client byte counts as interaction (RFC-006 §7.3), sent as type 5 at most once a second.
async fn forward(
    shared: &Shared,
    link: &NativeLink,
    incoming: mpsc::Sender<Vec<u8>>,
    stop: &CancellationToken,
) {
    let mut sent_size: Option<(u32, u32)> = None;
    let mut last_activity: Option<Instant> = None;
    loop {
        enum Next {
            Free(Vec<u8>),
            Size((u32, u32)),
            Data(usize),
            Wait(Option<Instant>),
        }
        let next = {
            let mut input = shared.input.lock().unwrap();
            let activity_due = last_activity.map(|at| at + Duration::from_secs(1));
            if input.closed && input.acks.is_empty() && input.data.is_empty() {
                // Dropping `incoming` ends `ssh::pump` cleanly once its queued input was written.
                return;
            } else if input.overflow {
                // `pump` rejects a client READY frame as invalid input: the browser overload code.
                input.overflow = false;
                Next::Free(vec![TERMINAL_READY])
            } else if let Some(count) = input.acks.pop_front() {
                let mut frame = vec![TERMINAL_ACK];
                frame.extend_from_slice(&count.to_be_bytes());
                Next::Free(frame)
            } else if !input.shell {
                Next::Wait(None)
            } else if sent_size.is_none() {
                match input.size.take() {
                    // The first size starts `ssh::run`, which consumes it without credit.
                    Some(size) => {
                        sent_size = Some(size);
                        Next::Free(terminal_size_frame(size.0, size.1).unwrap_or_default())
                    }
                    None => Next::Wait(None),
                }
            } else if input.size.is_some_and(|size| Some(size) != sent_size) {
                Next::Size(input.size.unwrap())
            } else if !input.data.is_empty() {
                input.size = None;
                Next::Data(input.data.len().min(MAX_DATA_BYTES - 1))
            } else if input.activity && activity_due.is_none_or(|due| due <= Instant::now()) {
                input.size = None;
                input.activity = false;
                last_activity = Some(Instant::now());
                Next::Free(vec![TERMINAL_ACTIVITY])
            } else {
                input.size = None;
                Next::Wait(activity_due.filter(|_| input.activity))
            }
        };
        let frame = match next {
            Next::Free(frame) => frame,
            Next::Wait(until) => {
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = shared.wake.notified() => {},
                    _ = tokio::time::sleep_until(until.unwrap_or_else(Instant::now)), if until.is_some() => {},
                }
                continue;
            }
            Next::Size(_) | Next::Data(_) => {
                let length = match next {
                    Next::Data(n) => n + 1,
                    _ => 5,
                };
                tokio::select! {
                    _ = stop.cancelled() => return,
                    // A newly queued ACK must not wait behind input credit.
                    _ = shared.wake.notified() => continue,
                    permit = link.pacer.acquire_many(input_charge(length) as u32) => match permit {
                        Ok(permit) => permit.forget(),
                        Err(_) => return,
                    },
                }
                let mut input = shared.input.lock().unwrap();
                match next {
                    Next::Data(n) => {
                        // Only this task drains, so at least `n` bytes are still buffered.
                        let mut frame = Vec::with_capacity(n + 1);
                        frame.push(TERMINAL_DATA);
                        frame.extend(input.data.drain(..n));
                        frame
                    }
                    Next::Size(size) => {
                        // The latest size wins; one that equals the target's needs no frame or credit.
                        let size = input.size.take().unwrap_or(size);
                        if Some(size) == sent_size {
                            link.pacer.add_permits(input_charge(5));
                            continue;
                        }
                        sent_size = Some(size);
                        terminal_size_frame(size.0, size.1).unwrap_or_default()
                    }
                    _ => unreachable!(),
                }
            }
        };
        tokio::select! {
            _ = stop.cancelled() => return,
            sent = incoming.send(frame) => if sent.is_err() { return },
        }
    }
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
