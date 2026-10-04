use anyhow::Result;
use async_trait::async_trait;
use bastion_domain::{Capability, Connection, ConnectionState, ErrorCode};
#[cfg(feature = "dev-prototype")]
use bastion_secrets::read_secret_file;
use bastion_secrets::{CipherContext, Credential, Envelope, KeyRing};
use ipnet::IpNet;
use russh::{
    client, server, Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect,
    MethodKind,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const START_TIMEOUT: Duration = Duration::from_secs(10);
const TARGET_TIMEOUT: Duration = Duration::from_secs(30);
const EMPTY_TIMEOUT: Duration = Duration::from_secs(10);

#[async_trait]
pub trait GatewayBackend: Send + Sync {
    async fn consume(&self, id: Uuid, secret: &str) -> Result<(Connection, Target), ErrorCode>;
    async fn authorize(&self, connection: &Connection) -> Result<(), ErrorCode>;
    async fn transition(
        &self,
        id: Uuid,
        state: ConnectionState,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode>;
    async fn channel_audit(
        &self,
        connection: &Connection,
        kind: &str,
        command_hash: Option<String>,
        command_len: Option<usize>,
    ) -> Result<(), ErrorCode>;
}

#[derive(Clone)]
pub struct NetworkPolicy {
    pub allow: Vec<IpNet>,
    pub deny: Vec<IpNet>,
}
impl NetworkPolicy {
    pub fn permits(&self, address: IpAddr) -> bool {
        let address = match address {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
            _ => address,
        };
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
        // Dial the selected resolved IP, never the hostname a second time.
        addresses
            .into_iter()
            .find(|a| self.permits(a.ip()))
            .ok_or(ErrorCode::TargetAddressDenied)
    }
}
#[derive(Clone)]
pub enum TargetEndpoint {
    #[cfg(feature = "dev-prototype")]
    Direct(SocketAddr),
    Restricted {
        host: String,
        port: u16,
        policy: Arc<NetworkPolicy>,
    },
}
impl TargetEndpoint {
    async fn resolve(&self) -> Result<SocketAddr, ErrorCode> {
        match self {
            #[cfg(feature = "dev-prototype")]
            Self::Direct(address) => Ok(*address),
            Self::Restricted { host, port, policy } => policy.resolve(host, *port).await,
        }
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn deny_wins_including_ipv4_mapped_ipv6() {
        let policy = NetworkPolicy {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: vec![
                "127.0.0.0/8".parse().unwrap(),
                "169.254.0.0/16".parse().unwrap(),
            ],
        };
        assert!(policy.permits("10.20.1.2".parse().unwrap()));
        assert!(!policy.permits("127.0.0.1".parse().unwrap()));
        assert!(!policy.permits("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!policy.permits("169.254.169.254".parse().unwrap()));
    }
}

#[derive(Clone)]
pub enum TargetAuth {
    Encrypted {
        context: CipherContext,
        envelope: Envelope,
        keys: Arc<KeyRing>,
    },
    #[cfg(feature = "dev-prototype")]
    PasswordFile(std::path::PathBuf),
    #[cfg(feature = "dev-prototype")]
    PrivateKeyFile {
        path: std::path::PathBuf,
        passphrase_file: Option<std::path::PathBuf>,
    },
}
#[derive(Clone)]
pub struct Target {
    pub address: TargetEndpoint,
    pub username: String,
    pub public_keys: Vec<russh::keys::PublicKey>,
    pub auth: TargetAuth,
}

pub struct TargetClient {
    keys: Vec<russh::keys::PublicKey>,
    mismatch: Arc<std::sync::atomic::AtomicBool>,
}
impl client::Handler for TargetClient {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let matches = self
            .keys
            .iter()
            .any(|expected| key.key_data() == expected.key_data());
        if !matches {
            self.mismatch
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(matches)
    }
}
type TargetHandle = Arc<client::Handle<TargetClient>>;
type TargetResult = Result<TargetHandle, ErrorCode>;

/// Authenticate only, using exactly the gateway's address and host-key checks.
/// No command or subsystem is executed for an administrator's probe.
pub async fn test_target(target: &Target) -> Result<(), ErrorCode> {
    let handle = timeout(Duration::from_secs(12), connect_target(target))
        .await
        .map_err(|_| ErrorCode::TargetTimeout)??;
    let _ = handle
        .disconnect(
            Disconnect::ByApplication,
            "authentication probe completed",
            "en",
        )
        .await;
    Ok(())
}

async fn connect_target(target: &Target) -> TargetResult {
    if target.public_keys.is_empty() {
        return Err(ErrorCode::TargetHostKeyUnknown);
    }
    let address = target.address.resolve().await?;
    let mismatch = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let config = client::Config {
        window_size: 256 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 8,
        inactivity_timeout: Some(Duration::from_secs(1800)),
        keepalive_interval: Some(Duration::from_secs(30)),
        nodelay: true,
        ..Default::default()
    };
    let mut handle = timeout(
        Duration::from_secs(15),
        client::connect(
            Arc::new(config),
            address,
            TargetClient {
                keys: target.public_keys.clone(),
                mismatch: mismatch.clone(),
            },
        ),
    )
    .await
    .map_err(|_| ErrorCode::TargetTimeout)?
    .map_err(|_| {
        if mismatch.load(std::sync::atomic::Ordering::Relaxed) {
            ErrorCode::TargetHostKeyChanged
        } else {
            ErrorCode::TargetUnreachable
        }
    })?;
    // Only after the key callback accepts do we load or submit target credentials.
    let result = match &target.auth {
        TargetAuth::Encrypted {
            context,
            envelope,
            keys,
        } => {
            let credential = keys
                .open(context, envelope)
                .map_err(|_| ErrorCode::TargetAuthFailed)?;
            match &credential {
                Credential::Password { password } => {
                    handle
                        .authenticate_password(&target.username, password)
                        .await
                }
                Credential::PrivateKey {
                    key_pem,
                    passphrase,
                } => {
                    let key = russh::keys::decode_secret_key(key_pem, passphrase.as_deref())
                        .map_err(|_| ErrorCode::TargetAuthFailed)?;
                    let alg = handle
                        .best_supported_rsa_hash()
                        .await
                        .map_err(|_| ErrorCode::TargetAuthFailed)?
                        .flatten();
                    handle
                        .authenticate_publickey(
                            &target.username,
                            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), alg),
                        )
                        .await
                }
            }
        }
        #[cfg(feature = "dev-prototype")]
        TargetAuth::PasswordFile(path) => {
            let secret = read_secret_file(path).map_err(|_| ErrorCode::TargetAuthFailed)?;
            handle
                .authenticate_password(&target.username, secret.expose())
                .await
        }
        #[cfg(feature = "dev-prototype")]
        TargetAuth::PrivateKeyFile {
            path,
            passphrase_file,
        } => {
            let pem = read_secret_file(path).map_err(|_| ErrorCode::TargetAuthFailed)?;
            let passphrase = passphrase_file
                .as_ref()
                .map(|path| read_secret_file(path))
                .transpose()
                .map_err(|_| ErrorCode::TargetAuthFailed)?;
            let key = russh::keys::decode_secret_key(
                pem.expose(),
                passphrase.as_ref().map(|s| s.expose()),
            )
            .map_err(|_| ErrorCode::TargetAuthFailed)?;
            let alg = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|_| ErrorCode::TargetAuthFailed)?
                .flatten();
            handle
                .authenticate_publickey(
                    &target.username,
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), alg),
                )
                .await
        }
    }
    .map_err(|_| ErrorCode::TargetAuthFailed)?;
    if !result.success() {
        let _ = handle
            .disconnect(
                Disconnect::ByApplication,
                "target authentication failed",
                "en",
            )
            .await;
        return Err(ErrorCode::TargetAuthFailed);
    }
    Ok(Arc::new(handle))
}

struct GatewayHandler {
    backend: Arc<dyn GatewayBackend>,
    target: Option<Arc<Target>>,
    stop: CancellationToken,
    authenticated: watch::Sender<bool>,
    connection: Option<Connection>,
    target_ready_sender: Option<watch::Sender<Option<TargetResult>>>,
    ready: Option<watch::Receiver<Option<TargetResult>>>,
    init: Option<JoinHandle<()>>,
    channels: HashMap<ChannelId, JoinHandle<()>>,
}

impl Drop for GatewayHandler {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(init) = self.init.take() {
            init.abort();
        }
        if let Some(ready) = &self.ready {
            if let Some(Ok(target)) = ready.borrow().clone() {
                tokio::spawn(async move {
                    let _ = timeout(
                        Duration::from_secs(2),
                        target.disconnect(Disconnect::ByApplication, "upstream closed", "en"),
                    )
                    .await;
                });
            }
        }
        for (_, task) in self.channels.drain() {
            task.abort();
        }
        if let Some(connection) = &self.connection {
            let backend = self.backend.clone();
            let id = connection.id;
            tokio::spawn(async move {
                let _ = backend.transition(id, ConnectionState::Closing, None).await;
                let _ = backend.transition(id, ConnectionState::Closed, None).await;
            });
        }
    }
}

impl server::Handler for GatewayHandler {
    type Error = russh::Error;
    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        _: &russh::keys::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::reject())
    }
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        let Some(id) = user
            .strip_prefix("zt1:")
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            return Ok(server::Auth::reject());
        };
        let Ok((connection, target)) = self.backend.consume(id, password).await else {
            return Ok(server::Auth::reject());
        };
        let (tx, rx) = watch::channel(None);
        self.ready = Some(rx);
        self.connection = Some(connection);
        self.target = Some(Arc::new(target));
        // Target networking starts in auth_succeeded, with an upstream handle.
        self.init = None;
        self.target_ready_sender = Some(tx);
        Ok(server::Auth::Accept)
    }
    async fn auth_succeeded(&mut self, session: &mut server::Session) -> Result<(), Self::Error> {
        let tx = self
            .target_ready_sender
            .take()
            .expect("accepted auth has sender");
        self.authenticated.send_replace(true);
        let target = self.target.clone().unwrap();
        let backend = self.backend.clone();
        let connection = self.connection.clone().unwrap();
        let stop = self.stop.clone();
        let id = self.connection.as_ref().unwrap().id;
        let upstream = session.handle();
        self.init = Some(tokio::spawn(async move {
            let result = tokio::select! {
                _ = stop.cancelled() => return,
                result = timeout(TARGET_TIMEOUT, async {
                    backend.authorize(&connection).await?;
                    let target_handle=connect_target(&target).await?;
                    backend.authorize(&connection).await?;
                    backend.transition(id,ConnectionState::Active,None).await?;
                    Ok(target_handle)
                }) => result.unwrap_or(Err(ErrorCode::TargetTimeout)),
            };
            if let Err(code) = &result {
                let _ = backend
                    .transition(id, ConnectionState::Failed, Some(*code))
                    .await;
            }
            let failed = result.is_err();
            tx.send_replace(Some(result.clone()));
            if failed {
                let _ = upstream
                    .disconnect(
                        Disconnect::ByApplication,
                        "target initialization failed".into(),
                        "en".into(),
                    )
                    .await;
                return;
            }
            let target_handle = result.unwrap();
            // A target transport closing must also end the upstream connection.
            let mut next_policy = tokio::time::Instant::now();
            let mut db_failure: Option<tokio::time::Instant> = None;
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if target_handle.is_closed() { break; }
                        if tokio::time::Instant::now()>=next_policy {
                            let started=tokio::time::Instant::now();
                            let budget=db_failure.map(|first|Duration::from_secs(5).saturating_sub(first.elapsed())).unwrap_or(Duration::from_secs(2));
                            if budget.is_zero() { break; }
                            match timeout(budget,backend.authorize(&connection)).await.unwrap_or(Err(ErrorCode::PolicyStoreUnavailable)) {
                                Ok(())=>db_failure=None,
                                Err(ErrorCode::PolicyStoreUnavailable)=> {db_failure.get_or_insert(started);if db_failure.unwrap().elapsed()>=Duration::from_secs(5){break;}},
                                Err(_)=>break,
                            }
                            next_policy=tokio::time::Instant::now()+Duration::from_secs(2);
                        }
                    }
                }
            }
            let _ = target_handle
                .disconnect(Disconnect::ByApplication, "gateway connection closed", "en")
                .await;
            let _ = upstream
                .disconnect(
                    Disconnect::ByApplication,
                    "target connection closed".into(),
                    "en".into(),
                )
                .await;
        }));
        Ok(())
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.retain(|_, task| !task.is_finished());
        let (Some(connection), Some(ready)) = (&self.connection, &self.ready) else {
            return Ok(());
        };
        if self.channels.len() >= 16 || self.backend.authorize(connection).await.is_err() {
            return Ok(());
        }
        let id = channel.id();
        let ready = ready.clone();
        let caps = connection.capabilities.clone();
        let connection = connection.clone();
        let backend = self.backend.clone();
        let stop = self.stop.child_token();
        let upstream = session.handle();
        reply.accept().await;
        self.channels.insert(
            id,
            tokio::spawn(async move {
                if let Err(error) = channel_worker(
                    channel,
                    ready,
                    caps,
                    upstream.clone(),
                    stop,
                    backend,
                    connection,
                )
                .await
                {
                    tracing::debug!(channel_id = %id, reason = %error, "channel ended");
                }
                let _ = upstream.close(id).await;
            }),
        );
        Ok(())
    }
    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        // This request has no reply in normal clients. Reject reply-seeking variants.
        session.channel_failure(channel)?;
        Ok(())
    }
    async fn signal(
        &mut self,
        channel: ChannelId,
        _: russh::Sig,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }
}

pub async fn run_backend(
    listener: TcpListener,
    key: russh::keys::PrivateKey,
    backend: Arc<dyn GatewayBackend>,
    shutdown: CancellationToken,
) -> Result<()> {
    let config = Arc::new(server::Config {
        keys: vec![key],
        methods: (&[MethodKind::Password][..]).into(),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: 3,
        window_size: 256 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 8,
        event_buffer_size: 8,
        inactivity_timeout: Some(Duration::from_secs(1800)),
        keepalive_interval: Some(Duration::from_secs(30)),
        nodelay: true,
        ..Default::default()
    });
    let permits = Arc::new(Semaphore::new(100));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let stop = shutdown.child_token(); let (auth_tx, auth_rx) = watch::channel(false);
                let handler = GatewayHandler { backend: backend.clone(), target: None, stop: stop.clone(),
                    authenticated: auth_tx, connection: None, ready: None, target_ready_sender: None, init: None, channels: HashMap::new() };
                let config = config.clone();
                tasks.spawn(connection_task(socket, config, handler, auth_rx, stop, permit));
            }
        }
    }
    // Each session task sees cancellation; bound final shutdown cleanup.
    let _ = timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    Ok(())
}

async fn connection_task(
    socket: tokio::net::TcpStream,
    config: Arc<server::Config>,
    handler: GatewayHandler,
    mut authenticated: watch::Receiver<bool>,
    stop: CancellationToken,
    _permit: OwnedSemaphorePermit,
) {
    let Ok(Ok(mut running)) = timeout(
        Duration::from_secs(15),
        server::run_stream(config, socket, handler),
    )
    .await
    else {
        return;
    };
    let handle = running.handle();
    let auth_deadline = async {
        while !*authenticated.borrow_and_update() {
            authenticated.changed().await.map_err(|_| ())?;
        }
        Ok::<_, ()>(())
    };
    tokio::select! {
        _ = &mut running => return,
        _ = stop.cancelled() => {},
        authenticated = timeout(Duration::from_secs(15), auth_deadline) => {
            if matches!(authenticated, Ok(Ok(()))) {
                tokio::select! { _ = &mut running => return, _ = stop.cancelled() => {} }
            }
        }
    }
    stop.cancel();
    let _ = handle
        .disconnect(
            Disconnect::ByApplication,
            "connection closed".into(),
            "en".into(),
        )
        .await;
    let _ = timeout(Duration::from_secs(2), running).await;
}

async fn wait_target(mut ready: watch::Receiver<Option<TargetResult>>) -> Result<TargetHandle> {
    loop {
        if let Some(result) = ready.borrow_and_update().clone() {
            return result.map_err(Into::into);
        }
        ready.changed().await?;
    }
}

async fn request_result(channel: &mut Channel<client::Msg>) -> Result<bool> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(true),
            Some(ChannelMsg::Failure) => return Ok(false),
            Some(ChannelMsg::WindowAdjusted { .. }) => {}
            _ => anyhow::bail!("target closed or sent data before request result"),
        }
    }
}

async fn channel_worker(
    mut upstream_channel: Channel<server::Msg>,
    ready: watch::Receiver<Option<TargetResult>>,
    caps: Vec<Capability>,
    upstream: server::Handle,
    stop: CancellationToken,
    backend: Arc<dyn GatewayBackend>,
    connection: Connection,
) -> Result<()> {
    let id = upstream_channel.id();
    let mut downstream = PendingChannel(None);
    let mut configured = false;
    let mut pty = false;
    let deadline = tokio::time::sleep(EMPTY_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        let event = tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            _ = &mut deadline => return Ok(()),
            event = upstream_channel.wait() => event,
        };
        let Some(event) = event else {
            return Ok(());
        };
        let (want_reply, allowed, starts) = match &event {
            ChannelMsg::RequestPty {
                want_reply,
                term,
                col_width,
                row_height,
                terminal_modes,
                ..
            } => (
                *want_reply,
                caps.contains(&Capability::Shell)
                    && !pty
                    && term.len() <= 128
                    && *col_width <= 10000
                    && *row_height <= 10000
                    && terminal_modes.len() <= 130,
                false,
            ),
            ChannelMsg::SetEnv {
                want_reply,
                variable_name,
                variable_value,
            } => (
                *want_reply,
                matches!(variable_name.as_str(), "LANG" | "LC_ALL" | "LC_CTYPE")
                    && variable_value.len() <= 1024
                    && !variable_value.contains('\0'),
                false,
            ),
            ChannelMsg::RequestShell { want_reply } => {
                (*want_reply, caps.contains(&Capability::Shell), true)
            }
            ChannelMsg::Exec {
                want_reply,
                command,
            } => (
                *want_reply,
                caps.contains(&Capability::Exec) && command.len() <= 65536 && !command.contains(&0),
                true,
            ),
            ChannelMsg::RequestSubsystem { want_reply, name } => (
                *want_reply,
                name == "sftp" && caps.contains(&Capability::Sftp),
                true,
            ),
            ChannelMsg::Close | ChannelMsg::Eof => return Ok(()),
            ChannelMsg::AgentForward { .. } | ChannelMsg::RequestX11 { .. } => continue, // synchronous handler rejects
            ChannelMsg::WindowAdjusted { .. } => continue,
            _ => anyhow::bail!("data or unsupported event before channel start"),
        };
        if !allowed {
            if want_reply {
                let _ = upstream.channel_request_reply(id, false).await;
            }
            continue;
        }
        backend.authorize(&connection).await?;
        if starts {
            let (kind, command) = match &event {
                ChannelMsg::RequestShell { .. } => ("shell", None),
                ChannelMsg::Exec { command, .. } => ("exec", Some(command.as_slice())),
                _ => ("sftp", None),
            };
            backend
                .channel_audit(
                    &connection,
                    kind,
                    command.map(|bytes| format!("{:x}", Sha256::digest(bytes))),
                    command.map(|bytes| bytes.len()),
                )
                .await?;
        }
        let accepted = tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            result = timeout(Duration::from_secs(45), async {
                if downstream.0.is_none() {
                    let target = wait_target(ready.clone()).await?;
                    downstream.0 = Some(timeout(START_TIMEOUT, target.channel_open_session()).await??);
                }
                let channel = downstream.0.as_mut().unwrap();
                match &event {
                    ChannelMsg::RequestPty { term, col_width, row_height, pix_width, pix_height, terminal_modes, .. } => {
                        channel.request_pty(true, term, *col_width, *row_height, *pix_width, *pix_height, terminal_modes).await?;
                    },
                    ChannelMsg::SetEnv { variable_name, variable_value, .. } => { channel.set_env(true, variable_name, variable_value).await?; },
                    ChannelMsg::RequestShell { .. } => { channel.request_shell(true).await?; },
                    ChannelMsg::Exec { command, .. } => { channel.exec(true, command.clone()).await?; },
                    ChannelMsg::RequestSubsystem { name, .. } => { channel.request_subsystem(true, name.clone()).await?; },
                    _ => unreachable!(),
                }
                timeout(START_TIMEOUT, request_result(channel)).await?
            }) => result??,
        };
        if !configured {
            configured = true;
            deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + START_TIMEOUT);
        }
        if want_reply {
            upstream
                .channel_request_reply(id, accepted)
                .await
                .map_err(|_| anyhow::anyhow!("upstream closed"))?;
        }
        if accepted && matches!(event, ChannelMsg::RequestPty { .. }) {
            pty = true;
        }
        if starts && accepted {
            let downstream = downstream.0.take().unwrap();
            return bridge(upstream_channel, downstream, upstream, pty, stop).await;
        }
        // Configuring channels also have an absolute deadline, never extended by env spam.
    }
}

struct PendingChannel(Option<Channel<client::Msg>>);
impl Drop for PendingChannel {
    fn drop(&mut self) {
        if let Some(channel) = self.0.take() {
            tokio::spawn(async move {
                let _ = timeout(Duration::from_secs(1), channel.close()).await;
            });
        }
    }
}
struct ActiveChannel(Arc<ChannelWriteHalf<client::Msg>>);
impl Drop for ActiveChannel {
    fn drop(&mut self) {
        let writer = self.0.clone();
        tokio::spawn(async move {
            let _ = timeout(Duration::from_secs(1), writer.close()).await;
        });
    }
}

async fn bridge(
    up: Channel<server::Msg>,
    down: Channel<client::Msg>,
    upstream: server::Handle,
    pty: bool,
    stop: CancellationToken,
) -> Result<()> {
    let id = up.id();
    let (up_read, up_write) = up.split();
    let (down_read, down_write) = down.split();
    let down_write = Arc::new(down_write);
    let _cleanup = ActiveChannel(down_write.clone());
    let input = input_loop(up_read, down_write, upstream.clone(), id, pty);
    let output = output_loop(down_read, up_write, upstream.clone(), id);
    tokio::pin!(input, output);
    tokio::select! {
        _ = stop.cancelled() => {},
        result = &mut output => { result?; },
        result = &mut input => {
            result?;
            // EOF half closes stdin; target output must still drain to close.
            tokio::select! { _ = stop.cancelled() => {}, result = &mut output => { result?; } }
        }
    }
    Ok(())
}

async fn input_loop(
    mut reader: ChannelReadHalf,
    writer: Arc<ChannelWriteHalf<client::Msg>>,
    upstream: server::Handle,
    id: ChannelId,
    pty: bool,
) -> Result<()> {
    let mut eof = false;
    while let Some(event) = reader.wait().await {
        match event {
            ChannelMsg::Data { data } if !eof => writer.data_bytes(data).await?,
            ChannelMsg::ExtendedData { data, ext } if !eof => {
                writer.extended_data_bytes(ext, data).await?
            }
            ChannelMsg::Eof if !eof => {
                writer.eof().await?;
                eof = true;
            }
            ChannelMsg::Close => {
                writer.close().await?;
                return Ok(());
            }
            ChannelMsg::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            } if pty
                && col_width > 0
                && col_width <= 10000
                && row_height > 0
                && row_height <= 10000 =>
            {
                writer
                    .window_change(col_width, row_height, pix_width, pix_height)
                    .await?;
            }
            ChannelMsg::Signal { signal }
                if matches!(
                    signal,
                    russh::Sig::ABRT
                        | russh::Sig::ALRM
                        | russh::Sig::FPE
                        | russh::Sig::HUP
                        | russh::Sig::ILL
                        | russh::Sig::INT
                        | russh::Sig::KILL
                        | russh::Sig::PIPE
                        | russh::Sig::QUIT
                        | russh::Sig::SEGV
                        | russh::Sig::TERM
                        | russh::Sig::USR1
                ) =>
            {
                writer.signal(signal).await?;
            }
            ChannelMsg::RequestPty { want_reply, .. }
            | ChannelMsg::SetEnv { want_reply, .. }
            | ChannelMsg::RequestShell { want_reply }
            | ChannelMsg::Exec { want_reply, .. }
            | ChannelMsg::RequestSubsystem { want_reply, .. }
                if want_reply =>
            {
                let _ = upstream.channel_request_reply(id, false).await;
            }
            _ => {}
        }
    }
    writer.close().await?;
    Ok(())
}

async fn output_loop(
    mut reader: ChannelReadHalf,
    writer: ChannelWriteHalf<server::Msg>,
    upstream: server::Handle,
    id: ChannelId,
) -> Result<()> {
    while let Some(event) = reader.wait().await {
        match event {
            ChannelMsg::Data { data } => writer.data_bytes(data).await?,
            ChannelMsg::ExtendedData { data, ext } => writer.extended_data_bytes(ext, data).await?,
            ChannelMsg::Eof => writer.eof().await?,
            ChannelMsg::ExitStatus { exit_status } => writer.exit_status(exit_status).await?,
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                upstream
                    .exit_signal_request(id, signal_name, core_dumped, error_message, lang_tag)
                    .await
                    .map_err(|_| anyhow::anyhow!("upstream closed"))?;
            }
            ChannelMsg::Close => {
                writer.close().await?;
                return Ok(());
            }
            _ => {}
        }
    }
    Ok(())
}
