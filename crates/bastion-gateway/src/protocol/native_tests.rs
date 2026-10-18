//! RFC-006 §9 gateway and lifecycle checks against an in-process russh target. The recording is
//! real (encrypted file in a 0700 temp directory) and verified with the existing Reader.
use super::*;
use bastion_domain::{RecordingCreate, RecordingState};
use bastion_secrets::recording::{RecordingContext, RecordingEnvelope, RecordingHeader};
use russh::{client, keys::Algorithm};
use std::sync::atomic::AtomicUsize;

const SECRET: &str = "ticket-secret-0123456789-abcdefghijklmnopqrs";

fn key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
}

// ---------------------------------------------------------------- target SSH server
/// What a test asks the target shell to do after it received `trigger` input.
#[derive(Clone, Copy, PartialEq)]
enum Ending {
    /// Echo input; on "exit\r" send EOF, exit-status 7 and close.
    Status,
    /// On "kill\r" send exit-signal TERM and close.
    Signal,
}
#[derive(Default)]
struct TargetLog {
    sizes: Vec<(u32, u32)>,
    input: Vec<u8>,
    authentications: usize,
    commands: Vec<Vec<u8>>,
    reject_sftp: bool,
}
use crate::protocol::sftp::tests as wire;
fn memory_version(include_unknown: bool) -> Vec<u8> {
    let mut response = vec![0, 0, 0, 0, 2, 0, 0, 0, 3];
    for name in [
        "limits@openssh.com",
        "fsync@openssh.com",
        "users-groups-by-id@openssh.com",
    ] {
        if include_unknown || name != "users-groups-by-id@openssh.com" {
            response.extend(wire::string(name.as_bytes()));
            response.extend(wire::string(b"1"));
        }
    }
    let n = (response.len() - 4) as u32;
    response[..4].copy_from_slice(&n.to_be_bytes());
    response
}
#[derive(Default, Clone)]
struct MemorySftp {
    buffer: Vec<u8>,
    handles: HashMap<Vec<u8>, Vec<u8>>,
    serial: u32,
}
struct MemoryFields<'a>(&'a [u8]);
impl<'a> MemoryFields<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }
    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }
    fn string(&mut self) -> Vec<u8> {
        let n = self.u32() as usize;
        self.take(n).to_vec()
    }
}
impl MemorySftp {
    fn respond(&mut self, packet: &[u8], files: &mut HashMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
        let mut f = MemoryFields(&packet[4..]);
        let kind = f.take(1)[0];
        if kind == 1 {
            return memory_version(true);
        }
        let id = f.u32();
        match kind {
            3 | 11 => {
                let path = f.string();
                let flags = if kind == 3 { f.u32() } else { 0 };
                if path.starts_with(b"/denied") {
                    return wire::status(id, 3);
                }
                if !files.contains_key(&path) && flags & 8 == 0 && kind == 3 {
                    return wire::status(id, 2);
                }
                if flags & 16 != 0 || !files.contains_key(&path) {
                    files.insert(path.clone(), Vec::new());
                }
                self.serial += 1;
                let handle = self.serial.to_be_bytes().to_vec();
                self.handles.insert(handle.clone(), path);
                wire::frame(102, id, &wire::string(&handle))
            }
            4 => {
                let h = f.string();
                self.handles.remove(&h);
                wire::status(id, 0)
            }
            5 | 6 => {
                let h = f.string();
                let offset = f.u64() as usize;
                let path = &self.handles[&h];
                let file = files.get_mut(path).unwrap();
                if kind == 6 {
                    let data = f.string();
                    if file.len() < offset + data.len() {
                        file.resize(offset + data.len(), 0);
                    }
                    file[offset..offset + data.len()].copy_from_slice(&data);
                    wire::status(id, 0)
                } else {
                    let n = f.u32() as usize;
                    if offset >= file.len() {
                        wire::status(id, 1)
                    } else {
                        wire::frame(
                            103,
                            id,
                            &wire::string(&file[offset..file.len().min(offset + n)]),
                        )
                    }
                }
            }
            7 | 8 | 17 => {
                let name = f.string();
                let path = if kind == 8 {
                    self.handles.get(&name).unwrap_or(&name)
                } else {
                    &name
                };
                if let Some(file) = files.get(path) {
                    let mut b = 1u32.to_be_bytes().to_vec();
                    b.extend((file.len() as u64).to_be_bytes());
                    wire::frame(105, id, &b)
                } else {
                    wire::status(id, 2)
                }
            }
            14 => {
                files.insert(f.string(), Vec::new());
                wire::status(id, 0)
            }
            12 => wire::status(id, 1),
            16 | 19 => {
                let name = f.string();
                let mut body = 1u32.to_be_bytes().to_vec();
                body.extend(wire::string(&name));
                body.extend(wire::string(&name));
                body.extend([0; 4]);
                wire::frame(104, id, &body)
            }
            13 | 15 => {
                files.remove(&f.string());
                wire::status(id, 0)
            }
            18 => {
                let from = f.string();
                let to = f.string();
                if let Some(data) = files.remove(&from) {
                    files.insert(to, data);
                }
                wire::status(id, 0)
            }
            200 => {
                let name = f.string();
                if name == b"limits@openssh.com" {
                    let body: Vec<u8> = [262144u64, 261120, 261120, 1024]
                        .into_iter()
                        .flat_map(u64::to_be_bytes)
                        .collect();
                    wire::frame(201, id, &body)
                } else {
                    wire::status(id, 0)
                }
            }
            _ => wire::status(id, 0),
        }
    }
}
#[derive(Clone)]
struct TargetShell {
    ending: Ending,
    log: Arc<Mutex<TargetLog>>,
    exec_channels: HashMap<ChannelId, Vec<u8>>,
    sftp_channels: HashMap<ChannelId, MemorySftp>,
    files: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}
impl server::Handler for TargetShell {
    type Error = russh::Error;
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.log.lock().unwrap().authentications += 1;
        Ok(if user == "target-user" && password == "target-pass" {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }
    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
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
        self.log.lock().unwrap().sizes.push((cols, rows));
        session.channel_success(channel)
    }
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, Bytes::from_static(b"target$ "))
    }
    async fn window_change_request(
        &mut self,
        _: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.lock().unwrap().sizes.push((cols, rows));
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.lock().unwrap().commands.push(command.to_vec());
        if command == b"reject" {
            return session.channel_failure(channel);
        }
        session.channel_success(channel)?;
        if command == b"stdin" || command == b"wait" {
            self.exec_channels.insert(channel, Vec::new());
            return Ok(());
        }
        session.data(channel, Bytes::copy_from_slice(command))?;
        session.extended_data(channel, 1, Bytes::from_static(b"stderr"))?;
        session.eof(channel)?;
        if command == b"signal" {
            session.exit_signal_request(channel, russh::Sig::TERM, false, "terminated", "en")?;
        } else {
            session.exit_status_request(channel, 5)?;
        }
        session.close(channel)
    }
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(data) = self.exec_channels.remove(&channel) {
            session.data(channel, Bytes::from(data))?;
            session.eof(channel)?;
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
        }
        Ok(())
    }
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" || self.log.lock().unwrap().reject_sftp {
            return session.channel_failure(channel);
        }
        self.sftp_channels.insert(channel, MemorySftp::default());
        session.channel_success(channel)
    }
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(input) = self.exec_channels.get_mut(&channel) {
            input.extend_from_slice(data);
            return Ok(());
        }
        if let Some(sftp) = self.sftp_channels.get_mut(&channel) {
            sftp.buffer.extend_from_slice(data);
            while sftp.buffer.len() >= 4 {
                let n = u32::from_be_bytes(sftp.buffer[..4].try_into().unwrap()) as usize;
                if sftp.buffer.len() < n + 4 {
                    break;
                }
                let packet: Vec<_> = sftp.buffer.drain(..n + 4).collect();
                let response = sftp.respond(&packet, &mut self.files.lock().unwrap());
                session.data(channel, Bytes::from(response))?;
            }
            return Ok(());
        }
        let input = {
            let mut log = self.log.lock().unwrap();
            log.input.extend_from_slice(data);
            log.input.clone()
        };
        session.data(channel, Bytes::copy_from_slice(data))?;
        if input.ends_with(b"big\r") {
            session.data(channel, Bytes::from(vec![b'x'; 200 * 1024]))?;
            session.data(channel, Bytes::from_static(b"BIG-END"))?;
        }
        if self.ending == Ending::Status && input.ends_with(b"exit\r") {
            session.data(channel, Bytes::from_static(b"bye\r\n"))?;
            session.eof(channel)?;
            session.exit_status_request(channel, 7)?;
            session.close(channel)?;
        }
        if self.ending == Ending::Signal && input.ends_with(b"kill\r") {
            session.exit_signal_request(channel, russh::Sig::TERM, false, "terminated", "en")?;
            session.close(channel)?;
        }
        Ok(())
    }
}
async fn target(ending: Ending) -> (SocketAddr, String, Arc<Mutex<TargetLog>>) {
    let host = key();
    let public = host.public_key().to_openssh().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(TargetLog::default()));
    let shell = TargetShell {
        ending,
        log: log.clone(),
        exec_channels: HashMap::new(),
        sftp_channels: HashMap::new(),
        files: Arc::new(Mutex::new(HashMap::new())),
    };
    let config = Arc::new(server::Config {
        keys: vec![host],
        auth_rejection_time: Duration::ZERO,
        ..Default::default()
    });
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (config, shell) = (config.clone(), shell.clone());
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, shell).await {
                    let _ = session.await;
                }
            });
        }
    });
    (address, public, log)
}

// ---------------------------------------------------------------- bastion side fakes
struct TestRecording {
    keys: Arc<KeyRing>,
    directory: PathBuf,
    rows: Mutex<Vec<(Uuid, RecordingCreate, Option<RecordingState>)>>,
}
struct TestBackend {
    registry: Arc<RuntimeRegistry>,
    recording: Arc<TestRecording>,
    states: Mutex<Vec<(ConnectionState, Option<ErrorCode>)>>,
    authorized: AtomicBool,
    recording_fault: AtomicBool,
    exec: Mutex<Vec<(Vec<u8>, ExecOutcome)>>,
    rejected: Mutex<Vec<ErrorCode>>,
    sftp: Mutex<Vec<SftpAudit>>,
    sftp_rejected: Mutex<Vec<ErrorCode>>,
    audit_delay: Mutex<Duration>,
    audit_error: AtomicBool,
    audit_started: AtomicUsize,
    activated: AtomicUsize,
}
use std::path::PathBuf;
#[async_trait]
impl GatewayBackend for TestBackend {
    fn registry(&self) -> Arc<RuntimeRegistry> {
        self.registry.clone()
    }
    fn recording_config(&self) -> Option<RecordingConfig> {
        Some(RecordingConfig {
            server_id: "test".into(),
            directory: self.recording.directory.clone(),
            keys: self.recording.keys.clone(),
            retention: Duration::from_secs(3600),
            min_free_bytes: 1,
        })
    }
    async fn authorize(&self, _: &Connection) -> Result<(), ErrorCode> {
        if self.authorized.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(ErrorCode::PermissionDenied)
        }
    }
    async fn transition(
        &self,
        _: Uuid,
        state: ConnectionState,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        self.states.lock().unwrap().push((state, failure));
        Ok(())
    }
    async fn activate_native_connection(&self, _: &Connection) -> Result<(), ErrorCode> {
        self.activated.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn exec_completed(
        &self,
        _: &Connection,
        command: &[u8],
        outcome: &ExecOutcome,
    ) -> Result<(), ErrorCode> {
        self.exec
            .lock()
            .unwrap()
            .push((command.to_vec(), outcome.clone()));
        Ok(())
    }
    async fn exec_rejected(
        &self,
        _: &Connection,
        _: &[u8],
        code: ErrorCode,
    ) -> Result<(), ErrorCode> {
        self.rejected.lock().unwrap().push(code);
        Ok(())
    }
    async fn sftp_audit(&self, _: &Connection, entry: &SftpAudit) -> Result<(), ErrorCode> {
        self.audit_started.fetch_add(1, Ordering::Release);
        let delay = *self.audit_delay.lock().unwrap();
        tokio::time::sleep(delay).await;
        if self.audit_error.load(Ordering::Acquire) {
            return Err(ErrorCode::PolicyStoreUnavailable);
        }
        self.sftp.lock().unwrap().push(entry.clone());
        Ok(())
    }
    async fn sftp_rejected(&self, _: &Connection, code: ErrorCode) -> Result<(), ErrorCode> {
        self.sftp_rejected.lock().unwrap().push(code);
        Ok(())
    }
    async fn begin_recording(
        &self,
        connection: &Connection,
        recording: RecordingCreate,
    ) -> Result<(), ErrorCode> {
        self.recording
            .rows
            .lock()
            .unwrap()
            .push((connection.id, recording, None));
        Ok(())
    }
    async fn activate_recording(&self, _: &Connection, _: Uuid) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn checkpoint_recording(&self, _: Uuid, _: i64, _: i64, _: i64) -> Result<(), ErrorCode> {
        if self.recording_fault.load(Ordering::Acquire) {
            Err(ErrorCode::RecordingUnavailable)
        } else {
            Ok(())
        }
    }
    async fn finish_recording(
        &self,
        id: Uuid,
        state: RecordingState,
        _: i64,
        _: Option<String>,
        _: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        for row in self.recording.rows.lock().unwrap().iter_mut() {
            if row.1.id == id {
                row.2 = Some(state);
            }
        }
        Ok(())
    }
}
struct Tickets {
    target: Target,
    backend: Arc<TestBackend>,
    calls: AtomicUsize,
    consumed: Mutex<Option<Connection>>,
    capabilities: Vec<String>,
}
#[async_trait]
impl NativeTickets for Tickets {
    async fn redeem(
        &self,
        ticket: Option<Uuid>,
        secret: &str,
        _: IpAddr,
    ) -> Result<NativeTicket, ErrorCode> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if ticket.is_none() || secret != SECRET {
            return Err(ErrorCode::TicketInvalid);
        }
        let connection = Connection {
            id: Uuid::new_v4(),
            ticket_id: ticket.unwrap(),
            asset_id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            target_protocol: TargetProtocol::Ssh,
            transport: Transport::NativeSsh,
            display: Display::default(),
            protocol_version: PROTOCOL_VERSION,
            state: ConnectionState::Connecting,
            created_at: chrono::Utc::now(),
            failure: None,
            user_id: Some(Uuid::new_v4()),
            login_session_id: Some(Uuid::new_v4()),
            auth_revision: 1,
            routing_revision: 1,
            account_revision: 1,
            credential_revision: Some(1),
        };
        let _ = &self.backend;
        *self.consumed.lock().unwrap() = Some(connection.clone());
        Ok(NativeTicket {
            connection,
            capabilities: self.capabilities.clone(),
            target: self.target.clone(),
        })
    }
}
struct Gateway {
    address: SocketAddr,
    public: russh::keys::PublicKey,
    backend: Arc<TestBackend>,
    tickets: Arc<Tickets>,
    shutdown: CancellationToken,
    running: Arc<AtomicBool>,
    task: Mutex<Option<tokio::task::JoinHandle<Result<(), ErrorCode>>>>,
    target_log: Arc<Mutex<TargetLog>>,
    _directory: tempfile_dir::Dir,
}
mod tempfile_dir {
    /// 0700 recording directory under the system temp dir (macOS: realpath, no /var symlink).
    pub struct Dir(pub std::path::PathBuf);
    impl Dir {
        pub fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            let path = base.join(format!("bastion-native-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
fn keyring(directory: &std::path::Path) -> KeyRing {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join("kek-test");
    std::fs::write(&path, bastion_secrets::Secret::random().expose()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let keys =
        KeyRing::from_files(1, &std::collections::BTreeMap::from([(1, path.clone())])).unwrap();
    std::fs::remove_file(path).unwrap();
    keys
}
async fn gateway_with(
    ending: Ending,
    limits: RuntimeLimits,
    handshake: Duration,
    capabilities: &[&str],
) -> Gateway {
    gateway_fixture(ending, limits, handshake, capabilities, None).await
}
#[derive(serde::Deserialize)]
struct OpenSshFixture {
    address: SocketAddr,
    username: String,
    approved_key: String,
    private_key_file: PathBuf,
}
async fn gateway_fixture(
    ending: Ending,
    limits: RuntimeLimits,
    handshake: Duration,
    capabilities: &[&str],
    fixture: Option<OpenSshFixture>,
) -> Gateway {
    let (address, public, target_log) = if let Some(f) = &fixture {
        (
            f.address,
            f.approved_key.clone(),
            Arc::new(Mutex::new(TargetLog::default())),
        )
    } else {
        target(ending).await
    };
    let directory = tempfile_dir::Dir::new();
    let keys = Arc::new(keyring(&directory.0));
    let context = CipherContext {
        server_id: "test".into(),
        credential_id: Uuid::new_v4(),
        kind: if fixture.is_some() {
            "private_key"
        } else {
            "password"
        }
        .into(),
        revision: 1,
    };
    let credential = if let Some(f) = &fixture {
        Credential::PrivateKey {
            key_pem: std::fs::read_to_string(&f.private_key_file).unwrap(),
            passphrase: None,
        }
    } else {
        Credential::Password {
            password: "target-pass".into(),
        }
    };
    let envelope = keys.seal(&context, &credential).unwrap();
    let target = Target {
        address: TargetEndpoint::Restricted {
            host: address.ip().to_string(),
            port: address.port(),
            policy: Arc::new(NetworkPolicy {
                allow: vec!["127.0.0.0/8".parse().unwrap()],
                deny: vec![],
            }),
        },
        protocol: TargetProtocol::Ssh,
        security: None,
        ssh_host_key: Some(public),
        rdp_certificate_sha256: None,
        username: Some(
            fixture
                .as_ref()
                .map(|f| f.username.clone())
                .unwrap_or_else(|| "target-user".into()),
        ),
        domain: None,
        auth: TargetAuth::Encrypted {
            context,
            envelope,
            keys: keys.clone(),
        },
    };
    let backend = Arc::new(TestBackend {
        registry: Arc::new(RuntimeRegistry::with_limits(limits).unwrap()),
        recording: Arc::new(TestRecording {
            keys,
            directory: directory.0.clone(),
            rows: Mutex::new(Vec::new()),
        }),
        states: Mutex::new(Vec::new()),
        authorized: AtomicBool::new(true),
        recording_fault: AtomicBool::new(false),
        exec: Mutex::new(Vec::new()),
        rejected: Mutex::new(Vec::new()),
        sftp: Mutex::new(Vec::new()),
        sftp_rejected: Mutex::new(Vec::new()),
        audit_delay: Mutex::new(Duration::ZERO),
        audit_error: AtomicBool::new(false),
        audit_started: AtomicUsize::new(0),
        activated: AtomicUsize::new(0),
    });
    let tickets = Arc::new(Tickets {
        target,
        backend: backend.clone(),
        calls: AtomicUsize::new(0),
        consumed: Mutex::new(None),
        capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
    });
    let host = key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let running = Arc::new(AtomicBool::new(false));
    let public = host.public_key().clone();
    let task = tokio::spawn(serve_native(
        listener,
        NativeListenerConfig {
            host_key: host,
            max_unauthenticated: 4,
            handshake_timeout: handshake,
        },
        tickets.clone(),
        backend.clone(),
        shutdown.clone(),
        running.clone(),
    ));
    for _ in 0..100 {
        if running.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(running.load(Ordering::Acquire));
    Gateway {
        address: gateway_address,
        public,
        backend,
        tickets,
        shutdown,
        running,
        task: Mutex::new(Some(task)),
        target_log,
        _directory: directory,
    }
}
async fn gateway(ending: Ending) -> Gateway {
    gateway_with(
        ending,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["shell"],
    )
    .await
}

// ---------------------------------------------------------------- client
struct Pinned(russh::keys::PublicKey);
impl client::Handler for Pinned {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        offered: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(
            matches!(offered, russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.0.key_data()),
        )
    }
}
async fn connect(g: &Gateway) -> client::Handle<Pinned> {
    timeout(
        Duration::from_secs(5),
        client::connect(
            Arc::new(client::Config::default()),
            g.address,
            Pinned(g.public.clone()),
        ),
    )
    .await
    .unwrap()
    .unwrap()
}
async fn login(g: &Gateway) -> client::Handle<Pinned> {
    let mut session = connect(g).await;
    let user = format!("zt1:{}", Uuid::new_v4());
    assert!(session
        .authenticate_password(user, SECRET)
        .await
        .unwrap()
        .success());
    session
}
/// Waits for a request reply, skipping flow-control notices.
async fn reply(channel: &mut Channel<client::Msg>) -> bool {
    loop {
        match timeout(Duration::from_secs(10), channel.wait())
            .await
            .unwrap()
        {
            Some(ChannelMsg::Success) => return true,
            Some(ChannelMsg::Failure) => return false,
            Some(ChannelMsg::WindowAdjusted { .. }) => continue,
            other => panic!("unexpected {other:?}"),
        }
    }
}
async fn shell(session: &client::Handle<Pinned>) -> Channel<client::Msg> {
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 100, 30, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut channel).await, "pty-req");
    channel.request_shell(true).await.unwrap();
    assert!(reply(&mut channel).await, "shell after ready");
    channel
}
/// Collects output until `needle` appears; returns everything read.
async fn read_until(channel: &mut Channel<client::Msg>, needle: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    timeout(Duration::from_secs(10), async {
        while !output.windows(needle.len()).any(|w| w == needle) {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
                Some(_) => {}
                None => panic!("closed before {:?}", String::from_utf8_lossy(needle)),
            }
        }
    })
    .await
    .unwrap();
    output
}
#[derive(Debug, Default)]
struct End {
    eof: bool,
    status: Option<u32>,
    signal: Option<String>,
    closed: bool,
}
async fn read_end(channel: &mut Channel<client::Msg>) -> End {
    let mut end = End::default();
    timeout(Duration::from_secs(10), async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Eof => end.eof = true,
                ChannelMsg::ExitStatus { exit_status } => end.status = Some(exit_status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    end.signal = Some(format!("{signal_name:?}"))
                }
                ChannelMsg::Close => {
                    end.closed = true;
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    end
}
async fn wait_states(
    g: &Gateway,
    last: ConnectionState,
) -> Vec<(ConnectionState, Option<ErrorCode>)> {
    timeout(Duration::from_secs(10), async {
        loop {
            let states = g.backend.states.lock().unwrap().clone();
            if states.last().is_some_and(|(state, _)| *state == last) {
                return states;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("states: {:?}", g.backend.states.lock().unwrap()))
}
/// Reads the connection's recording with the production Reader and returns its output bytes.
fn recording_output(g: &Gateway) -> (RecordingState, Vec<u8>) {
    let rows = g.backend.recording.rows.lock().unwrap();
    let (connection_id, create, state) = rows.last().unwrap();
    let context = RecordingContext::new("test", create.id, *connection_id, TargetProtocol::Ssh);
    let key = g
        .backend
        .recording
        .keys
        .open_recording_dek(
            &context,
            &RecordingEnvelope {
                wrapped_dek: create.wrapped_dek.clone(),
                wrap_nonce: create.wrap_nonce.clone(),
                key_version: create.key_version,
            },
        )
        .unwrap();
    let header = RecordingHeader {
        recording_id: create.id,
        connection_id: *connection_id,
        target_protocol: TargetProtocol::Ssh,
        stream_protocol: SSH_STREAM_PROTOCOL.into(),
        nonce_prefix: create.nonce_prefix.clone().try_into().unwrap(),
    };
    let file =
        std::fs::File::open(g.backend.recording.directory.join(&create.relative_path)).unwrap();
    let mut reader = bastion_secrets::recording::RecordingReader::new(file, &header, key).unwrap();
    let mut output = Vec::new();
    let mut sizes = 0;
    while let Some(chunk) = reader.next_chunk().unwrap() {
        for line in chunk
            .plaintext
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
        {
            let event: serde_json::Value = serde_json::from_slice(line).unwrap();
            assert_ne!(event["type"], "input", "input is never recorded");
            if event["type"] == "meta" {
                assert_eq!(
                    (event["stream_protocol"].as_str(), event["width"].as_u64()),
                    (Some(SSH_STREAM_PROTOCOL), Some(1280))
                );
            }
            if event["type"] == "output" {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(event["data_base64"].as_str().unwrap())
                    .unwrap();
                if bytes[0] == TERMINAL_SIZE {
                    sizes += 1;
                }
                output.extend_from_slice(&bytes);
            }
        }
    }
    assert!(sizes >= 1, "type 2 frames give replay its geometry");
    (state.unwrap(), output)
}

// ---------------------------------------------------------------- tests
#[tokio::test]
async fn shell_pty_resize_eof_exit_status_and_recording() {
    let g = gateway(Ending::Status).await;
    let session = login(&g).await;
    let mut channel = shell(&session).await;
    read_until(&mut channel, b"target$ ").await;
    channel.window_change(120, 40, 0, 0).await.unwrap();
    channel.data(&b"echo hi\r"[..]).await.unwrap();
    read_until(&mut channel, b"echo hi\r").await;
    // 200 KiB of output passes the 256 KiB budget only because written data is ACKed.
    channel.data(&b"big\r"[..]).await.unwrap();
    let big = read_until(&mut channel, b"BIG-END").await;
    assert!(big.iter().filter(|b| **b == b'x').count() == 200 * 1024);
    // A paste larger than one 32 KiB frame is split, never truncated.
    let paste = vec![b'p'; 100 * 1024];
    channel.data(&paste[..]).await.unwrap();
    channel.data(&b"exit\r"[..]).await.unwrap();
    read_until(&mut channel, b"bye").await;
    let end = read_end(&mut channel).await;
    assert!(end.eof && end.status == Some(7) && end.closed, "{end:?}");
    session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    let states = wait_states(&g, ConnectionState::Closed).await;
    assert_eq!(
        states,
        vec![
            (ConnectionState::Closing, None),
            (ConnectionState::Closed, None)
        ]
    );
    {
        let log = g.target_log.lock().unwrap();
        assert_eq!(log.sizes, vec![(100, 30), (120, 40)]);
        assert_eq!(log.input.iter().filter(|b| **b == b'p').count(), 100 * 1024);
    }
    let (state, output) = recording_output(&g);
    assert_eq!(state, RecordingState::Complete);
    assert!(output.windows(7).any(|w| w == b"BIG-END"));
    assert!(output.windows(3).any(|w| w == b"bye"));
    drop(session);
    g.shutdown.cancel();
    let task = g.task.lock().unwrap().take().unwrap();
    timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!g.running.load(Ordering::Acquire));
}

#[tokio::test]
async fn exit_signal_is_relayed() {
    let g = gateway(Ending::Signal).await;
    let session = login(&g).await;
    let mut channel = shell(&session).await;
    read_until(&mut channel, b"target$ ").await;
    channel.data(&b"kill\r"[..]).await.unwrap();
    let end = read_end(&mut channel).await;
    assert_eq!(end.signal.as_deref(), Some("TERM"), "{end:?}");
    assert!(end.closed && end.status.is_none());
    session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    wait_states(&g, ConnectionState::Closed).await;
}

#[tokio::test]
async fn one_password_attempt_and_no_other_methods() {
    let g = gateway(Ending::Status).await;
    // Wrong secret: rejected, and the connection is gone (no second try on it).
    let mut session = connect(&g).await;
    let user = format!("zt1:{}", Uuid::new_v4());
    assert!(!session
        .authenticate_password(user.clone(), "wrong")
        .await
        .unwrap()
        .success());
    timeout(Duration::from_secs(3), async {
        while !session.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gateway disconnects after the failed attempt");
    let second = session.authenticate_password(user.clone(), SECRET).await;
    assert!(!matches!(second, Ok(ref r) if r.success()));
    assert_eq!(g.tickets.calls.load(Ordering::SeqCst), 1);
    // Malformed usernames never reach a ticket lookup with an id.
    let mut session = connect(&g).await;
    assert!(!session
        .authenticate_password("root", SECRET)
        .await
        .unwrap()
        .success());
    // none and publickey are refused and do not authenticate.
    let mut session = connect(&g).await;
    assert!(!session
        .authenticate_none(user.clone())
        .await
        .unwrap()
        .success());
    let probe = key();
    let result = session
        .authenticate_publickey(
            user.clone(),
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(probe), None),
        )
        .await
        .unwrap();
    assert!(!result.success());
    // The password attempt still works after the none/publickey probes (OpenSSH order).
    assert!(session
        .authenticate_password(user, SECRET)
        .await
        .unwrap()
        .success());
    assert!(g.backend.states.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unauthorized_requests_and_forwarding_are_rejected() {
    let g = gateway(Ending::Status).await;
    let session = login(&g).await;
    let mut channel = session.channel_open_session().await.unwrap();
    // shell before pty-req is refused.
    channel.request_shell(true).await.unwrap();
    assert!(!reply(&mut channel).await);
    channel.exec(true, "id").await.unwrap();
    assert!(!reply(&mut channel).await, "exec");
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(!reply(&mut channel).await, "sftp");
    channel.agent_forward(true).await.unwrap();
    assert!(!reply(&mut channel).await, "agent");
    channel
        .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00", 0)
        .await
        .unwrap();
    assert!(!reply(&mut channel).await, "x11");
    channel.set_env(true, "LANG", "C").await.unwrap();
    assert!(!reply(&mut channel).await, "env is ignored");
    let extra = session
        .channel_open_session()
        .await
        .expect("multiple sessions allowed");
    extra.close().await.unwrap();
    assert!(session
        .channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 5000)
        .await
        .is_err());
    assert!(session
        .channel_open_direct_streamlocal("/tmp/x")
        .await
        .is_err());
    assert!(session.tcpip_forward("127.0.0.1", 0).await.is_err());
    assert!(session.streamlocal_forward("/tmp/y").await.is_err());
    // The one session channel still works afterwards.
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    channel.request_shell(true).await.unwrap();
    assert!(reply(&mut channel).await);
    read_until(&mut channel, b"target$ ").await;
}

#[tokio::test]
async fn exec_only_ticket_rejects_shell_without_disconnect() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["exec"],
    )
    .await;
    let session = login(&g).await;
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(!reply(&mut channel).await);
    channel.request_shell(true).await.unwrap();
    assert!(!reply(&mut channel).await);
    channel.exec(true, "hello").await.unwrap();
    assert!(reply(&mut channel).await);
    read_until(&mut channel, b"hello").await;
    assert_eq!(read_end(&mut channel).await.status, Some(5));
    assert!(g.backend.recording.rows.lock().unwrap().is_empty());
    assert_eq!(g.backend.activated.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn unauthenticated_connections_time_out() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_millis(300),
        &["shell"],
    )
    .await;
    // Raw TCP that never speaks SSH, and an SSH client that never authenticates.
    let mut raw = tokio::net::TcpStream::connect(g.address).await.unwrap();
    let session = connect(&g).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    use tokio::io::AsyncReadExt;
    let mut buffer = [0u8; 256];
    let closed = timeout(Duration::from_secs(2), async {
        loop {
            match raw.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "raw socket closed after the handshake deadline"
    );
    timeout(Duration::from_secs(2), async {
        while !session.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn revocation_mid_session_disconnects_and_drain_closes() {
    let g = gateway(Ending::Status).await;
    let session = login(&g).await;
    let mut channel = shell(&session).await;
    read_until(&mut channel, b"target$ ").await;
    let user = g
        .tickets
        .consumed
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .user_id
        .unwrap();
    g.backend.registry.revoke_user(user);
    let end = read_end(&mut channel).await;
    assert!(end.closed && end.status.is_none(), "{end:?}");
    let states = wait_states(&g, ConnectionState::Failed).await;
    assert_eq!(
        states,
        vec![(
            ConnectionState::Failed,
            Some(ErrorCode::LoginSessionRevoked)
        )]
    );
    let (state, _) = recording_output(&g);
    assert_eq!(state, RecordingState::Partial);

    // Periodic authorization (grant removal, credential change, user disable) closes the session too.
    g.backend.states.lock().unwrap().clear();
    let session = login(&g).await;
    let mut channel = shell(&session).await;
    read_until(&mut channel, b"target$ ").await;
    g.backend.authorized.store(false, Ordering::Release);
    let end = read_end(&mut channel).await;
    assert!(end.closed, "{end:?}");
    let states = wait_states(&g, ConnectionState::Failed).await;
    assert_eq!(
        states,
        vec![(ConnectionState::Failed, Some(ErrorCode::PermissionDenied))]
    );
    g.backend.authorized.store(true, Ordering::Release);

    // Drain: stop accepting, close the live session, and finish its recording.
    g.backend.states.lock().unwrap().clear();
    let session = login(&g).await;
    let mut channel = shell(&session).await;
    read_until(&mut channel, b"target$ ").await;
    g.shutdown.cancel();
    let end = read_end(&mut channel).await;
    assert!(end.closed);
    let task = g.task.lock().unwrap().take().unwrap();
    timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!g.running.load(Ordering::Acquire));
    assert!(
        tokio::net::TcpStream::connect(g.address).await.is_err(),
        "listener closed"
    );
    assert!(g
        .backend
        .registry
        .drain(Duration::from_secs(5))
        .await
        .is_ok());
    let (state, _) = recording_output(&g);
    assert_eq!(state, RecordingState::Partial);
}

#[tokio::test]
async fn unauthenticated_concurrency_is_bounded() {
    let g = gateway(Ending::Status).await;
    // max_unauthenticated is 4: hold four raw sockets, the fifth is dropped before the SSH banner.
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(tokio::net::TcpStream::connect(g.address).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut extra = tokio::net::TcpStream::connect(g.address).await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut buffer = [0u8; 64];
    let read = timeout(Duration::from_secs(2), extra.read(&mut buffer))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "no banner over the bound");
    drop(held);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let session = login(&g).await;
    let _ = shell(&session).await;
}

async fn exec_result(channel: &mut Channel<client::Msg>) -> (Vec<u8>, Vec<u8>, End) {
    let (mut out, mut err, mut end) = (Vec::new(), Vec::new(), End::default());
    timeout(Duration::from_secs(10), async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => err.extend_from_slice(&data),
                ChannelMsg::Eof => end.eof = true,
                ChannelMsg::ExitStatus { exit_status } => end.status = Some(exit_status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    end.signal = Some(format!("{signal_name:?}"))
                }
                ChannelMsg::Close => {
                    end.closed = true;
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    (out, err, end)
}
#[tokio::test]
async fn concurrent_exec_shell_and_sftp_reuse_one_target_and_record_only_shell() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["shell", "exec", "sftp"],
    )
    .await;
    let session = login(&g).await;
    let mut first = session.channel_open_session().await.unwrap();
    first.exec(true, "stdin").await.unwrap();
    assert!(reply(&mut first).await);
    assert!(g.backend.recording.rows.lock().unwrap().is_empty());
    let mut terminal = shell(&session).await;
    read_until(&mut terminal, b"target$ ").await;
    let mut second = session.channel_open_session().await.unwrap();
    second.exec(true, "exec-only-output").await.unwrap();
    assert!(reply(&mut second).await);
    let (out, err, end) = exec_result(&mut second).await;
    assert_eq!(out, b"exec-only-output");
    assert_eq!(err, b"stderr");
    assert!(end.eof && end.status == Some(5) && end.closed);
    first.data(&b"stdin-content"[..]).await.unwrap();
    first.eof().await.unwrap();
    let (out, _, end) = exec_result(&mut first).await;
    assert_eq!(out, b"stdin-content");
    assert_eq!(end.status, Some(0));
    let mut sftp = session.channel_open_session().await.unwrap();
    sftp.request_subsystem(true, "sftp").await.unwrap();
    assert!(reply(&mut sftp).await);
    sftp.data(&[0, 0, 0, 5, 1, 0, 0, 0, 3][..]).await.unwrap();
    let version = read_until(&mut sftp, &[2, 0, 0, 0, 3]).await;
    assert_eq!(version, memory_version(false));
    // Unsupported extensions are answered locally and leave the channel usable.
    let mut request = vec![0, 0, 0, 0, 200, 0, 0, 0, 42];
    request.extend_from_slice(&4u32.to_be_bytes());
    request.extend_from_slice(b"nope");
    let n = (request.len() - 4) as u32;
    request[..4].copy_from_slice(&n.to_be_bytes());
    sftp.data(&request[..]).await.unwrap();
    let response = read_until(&mut sftp, &[101, 0, 0, 0, 42, 0, 0, 0, 8]).await;
    assert_eq!(response[4], 101);
    sftp.close().await.unwrap();
    terminal.data(&b"exit\r"[..]).await.unwrap();
    read_until(&mut terminal, b"bye").await;
    assert_eq!(read_end(&mut terminal).await.status, Some(7));
    // Completing shell does not end the SSH connection, and never permits another shell.
    let mut later = session.channel_open_session().await.unwrap();
    later
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(!reply(&mut later).await);
    later.exec(true, "signal").await.unwrap();
    assert!(reply(&mut later).await);
    let (_, _, end) = exec_result(&mut later).await;
    assert_eq!(end.signal.as_deref(), Some("TERM"));
    assert_eq!(g.target_log.lock().unwrap().authentications, 1);
    session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    wait_states(&g, ConnectionState::Closed).await;
    let (state, bytes) = recording_output(&g);
    assert_eq!(state, RecordingState::Complete);
    assert!(!bytes
        .windows(b"exec-only-output".len())
        .any(|b| b == b"exec-only-output"));
    assert_eq!(g.backend.exec.lock().unwrap().len(), 3);
    let results = g.backend.exec.lock().unwrap();
    let (_, stdin) = results.iter().find(|(c, _)| c == b"stdin").unwrap();
    assert_eq!(
        (stdin.stdin_bytes, stdin.stdout_bytes, stdin.stderr_bytes),
        (13, 13, 0)
    );
    assert!(g
        .backend
        .sftp
        .lock()
        .unwrap()
        .iter()
        .any(|entry| matches!(entry, SftpAudit::Session { .. })));
}
#[tokio::test]
async fn exec_validation_target_rejection_and_channel_limit() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["exec"],
    )
    .await;
    let session = login(&g).await;
    let mut c = session.channel_open_session().await.unwrap();
    for command in [b"a\0b".to_vec(), vec![b'x'; 65537], b"reject".to_vec()] {
        c.exec(true, command).await.unwrap();
        assert!(!reply(&mut c).await);
    }
    c.exec(true, "valid").await.unwrap();
    assert!(reply(&mut c).await);
    assert_eq!(exec_result(&mut c).await.0, b"valid");
    assert_eq!(
        *g.backend.rejected.lock().unwrap(),
        [
            ErrorCode::InvalidArgument,
            ErrorCode::InvalidArgument,
            ErrorCode::TargetRequestRejected
        ]
    );
    let mut channels = Vec::new();
    for _ in 0..16 {
        channels.push(session.channel_open_session().await.unwrap());
    }
    assert!(session.channel_open_session().await.is_err());
    channels.pop().unwrap().close().await.unwrap();
    let mut new = session.channel_open_session().await.unwrap();
    new.exec(true, "wait").await.unwrap();
    assert!(reply(&mut new).await);
    let connection = g.tickets.consumed.lock().unwrap().clone().unwrap();
    g.backend.registry.revoke_connection(connection.id);
    assert!(read_end(&mut new).await.closed);
    wait_states(&g, ConnectionState::Failed).await;
    let results = g.backend.exec.lock().unwrap();
    let (_, interrupted) = results.iter().find(|(c, _)| c == b"wait").unwrap();
    assert_eq!(interrupted.exit_status, None);
    assert!(g.backend.recording.rows.lock().unwrap().is_empty());
}

/// System OpenSSH clients -> native gateway -> disposable real sshd. No production endpoint or
/// user key is assumed: the explicit fixture points at a loopback disposable target and test key.
#[tokio::test]
#[ignore = "requires BASTION_NATIVE_OPENSSH_FIXTURE pointing at a disposable loopback sshd fixture"]
async fn real_openssh_exec_and_sftp_roundtrip() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var("BASTION_NATIVE_OPENSSH_FIXTURE").unwrap();
    let fixture: OpenSshFixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(fixture.address.ip().is_loopback());
    let g = gateway_fixture(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["shell", "exec", "sftp"],
        Some(fixture),
    )
    .await;
    let directory = &g._directory.0;
    let askpass = directory.join("askpass");
    std::fs::write(&askpass, format!("#!/bin/sh\nprintf '%s\\n' '{SECRET}'\n")).unwrap();
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
    let known = directory.join("known_hosts");
    std::fs::write(
        &known,
        format!(
            "[127.0.0.1]:{} {}\n",
            g.address.port(),
            g.public.to_openssh().unwrap()
        ),
    )
    .unwrap();
    let user = format!("zt1:{}", Uuid::new_v4());
    let mut common = vec![
        "-F".to_string(),
        "/dev/null".to_string(),
        "-q".to_string(),
        "-o".to_string(),
        format!("User={user}"),
        "-o".into(),
        format!("UserKnownHostsFile={}", known.display()),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        "PreferredAuthentications=password".into(),
        "-o".into(),
        "PubkeyAuthentication=no".into(),
        "-o".into(),
        "NumberOfPasswordPrompts=1".into(),
        "-o".into(),
        "ProxyCommand=none".into(),
        "-o".into(),
        "BatchMode=no".into(),
    ];
    let mut ssh = tokio::process::Command::new("ssh");
    ssh.kill_on_drop(true)
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .args(&common)
        .args([
            "-p",
            &g.address.port().to_string(),
            "127.0.0.1",
            "printf stdout; printf stderr >&2; exit 5",
        ]);
    let output = timeout(Duration::from_secs(20), ssh.output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"stdout");
    assert_eq!(output.stderr, b"stderr");
    // A real ControlMaster shell, exec and SFTP must share a single ticket/target socket.
    let control = directory.join("control");
    let mut master = tokio::process::Command::new("ssh");
    master
        .kill_on_drop(true)
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .args(&common)
        .args([
            "-M",
            "-S",
            control.to_str().unwrap(),
            "-tt",
            "-p",
            &g.address.port().to_string(),
            "127.0.0.1",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut master = master.spawn().unwrap();
    timeout(Duration::from_secs(10), async {
        while !control.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    common.extend([
        "-o".into(),
        format!("ControlPath={}", control.display()),
        "-o".into(),
        "ControlMaster=no".into(),
    ]);
    let output = tokio::process::Command::new("ssh")
        .kill_on_drop(true)
        .args(&common)
        .args([
            "-p",
            &g.address.port().to_string(),
            "127.0.0.1",
            "printf multiplex-exec; exit 6",
        ])
        .output()
        .await
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"multiplex-exec");
    // Deterministic binary payload catches fragmentation, offset and SHA-256 accounting errors.
    let content: Vec<_> = (0..8 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
    let upload = directory.join("upload");
    let download = directory.join("download");
    let remote = directory.join("remote");
    let renamed = directory.join("renamed");
    let folder = directory.join("folder");
    std::fs::write(&upload, &content).unwrap();
    let partial_remote = directory.join("partial-remote");
    let short = directory.join("short");
    std::fs::write(&short, &content[..1024]).unwrap();
    let resumed = directory.join("resumed");
    std::fs::write(&resumed, &content[..4096]).unwrap();
    let denied = directory.join("denied");
    std::fs::create_dir(&denied).unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o500)).unwrap();
    let batch = directory.join("batch");
    std::fs::write(&batch,format!("put -f {} {}\nget {} {}\nput {} {}\nreput {} {}\nreget {} {}\nls -l {}\n-put {} {}/file\nrename {} {}\nrm {}\nrm {}\nmkdir {}\nrmdir {}\nbye\n",
        upload.display(),remote.display(),remote.display(),download.display(),short.display(),partial_remote.display(),
        upload.display(),partial_remote.display(),remote.display(),resumed.display(),directory.display(),upload.display(),denied.display(),
        remote.display(),renamed.display(),renamed.display(),partial_remote.display(),folder.display(),folder.display())).unwrap();
    let mut sftp = tokio::process::Command::new("sftp");
    sftp.kill_on_drop(true)
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .args(&common)
        .args([
            "-P",
            &g.address.port().to_string(),
            "-b",
            batch.to_str().unwrap(),
            "127.0.0.1",
        ]);
    let output = timeout(Duration::from_secs(30), sftp.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(download).unwrap(), content);
    timeout(Duration::from_secs(10), async {
        while !g
            .backend
            .sftp
            .lock()
            .unwrap()
            .iter()
            .any(|entry| matches!(entry, SftpAudit::Session { .. }))
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let expected = format!("{:x}", Sha256::digest(&content));
    {
        let audits = g.backend.sftp.lock().unwrap();
        let files: Vec<_> = audits
            .iter()
            .filter(|a| matches!(a, SftpAudit::File { .. }))
            .collect();
        assert_eq!(files.len(), 6, "{audits:?}");
        assert_eq!(
            files
                .iter()
                .filter(|a| matches!(a,SftpAudit::File{sha256:Some(hash),..} if hash==&expected))
                .count(),
            2
        );
        assert_eq!(
            files
                .iter()
                .filter(|a| matches!(
                    a,
                    SftpAudit::File {
                        status: Some(0),
                        sha256: None,
                        ..
                    }
                ))
                .count(),
            2
        );
        assert!(files.iter().any(|a|matches!(a,SftpAudit::File{write_bytes,status:Some(0),sha256:None,..} if *write_bytes==content.len() as u64-1024)));
        assert!(files.iter().any(|a|matches!(a,SftpAudit::File{read_bytes,status:Some(0),sha256:None,..} if *read_bytes==content.len() as u64-4096)));
        assert!(files.iter().any(|a| matches!(
            a,
            SftpAudit::File {
                status: Some(3),
                write_bytes: 0,
                sha256: None,
                ..
            }
        )));
        assert_eq!(std::fs::read(resumed).unwrap(), content);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("Operation unsupported"));
        for op in [
            SftpOp::PosixRename,
            SftpOp::Remove,
            SftpOp::Mkdir,
            SftpOp::Rmdir,
        ] {
            assert!(
                audits.iter().any(
                    |a| matches!(a,SftpAudit::Operation{op:actual,status:0,..} if *actual==op)
                ),
                "{op:?}"
            );
        }
    }
    assert_eq!(
        g.tickets.calls.load(Ordering::Relaxed),
        2,
        "one initial exec plus one multiplexed connection"
    );
    use tokio::io::AsyncWriteExt;
    master
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"exit\n")
        .await
        .unwrap();
    timeout(Duration::from_secs(10), master.wait())
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            if g.backend
                .recording
                .rows
                .lock()
                .unwrap()
                .last()
                .is_some_and(|(_, _, state)| *state == Some(RecordingState::Complete))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (_, recorded) = recording_output(&g);
    assert!(!recorded
        .windows(b"multiplex-exec".len())
        .any(|w| w == b"multiplex-exec"));
    g.shutdown.cancel();
    let task = g.task.lock().unwrap().take().unwrap();
    timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn malformed_sftp_closes_only_its_channel_and_capability_rejection_keeps_channel_usable() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["exec", "sftp"],
    )
    .await;
    let session = login(&g).await;
    let mut bad = session.channel_open_session().await.unwrap();
    bad.request_subsystem(true, "sftp").await.unwrap();
    assert!(reply(&mut bad).await);
    bad.data(&[0, 4, 0, 1][..]).await.unwrap();
    assert!(read_end(&mut bad).await.closed);
    let mut c = session.channel_open_session().await.unwrap();
    c.exec(true, "still-alive").await.unwrap();
    assert!(reply(&mut c).await);
    assert_eq!(exec_result(&mut c).await.0, b"still-alive");
    assert!(!session.is_closed());
    let no_sftp = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["exec"],
    )
    .await;
    let session = login(&no_sftp).await;
    let mut c = session.channel_open_session().await.unwrap();
    c.request_subsystem(true, "sftp").await.unwrap();
    assert!(!reply(&mut c).await);
    c.exec(true, "permitted").await.unwrap();
    assert!(reply(&mut c).await);
    assert_eq!(exec_result(&mut c).await.0, b"permitted");
}

#[tokio::test]
async fn exec_stdin_activity_refreshes_connection_idle_deadline() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits {
            idle_timeout: Duration::from_millis(500),
            ..Default::default()
        },
        Duration::from_secs(10),
        &["exec"],
    )
    .await;
    let session = login(&g).await;
    let mut c = session.channel_open_session().await.unwrap();
    c.exec(true, "wait").await.unwrap();
    assert!(reply(&mut c).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    c.data(&b"activity"[..]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !session.is_closed(),
        "stdin extended the original idle deadline"
    );
    assert!(read_end(&mut c).await.closed);
    let states = wait_states(&g, ConnectionState::Failed).await;
    assert_eq!(
        states.last(),
        Some(&(ConnectionState::Failed, Some(ErrorCode::TargetTimeout)))
    );
    assert_eq!(g.backend.exec.lock().unwrap()[0].1.stdin_bytes, 8);
}
#[tokio::test]
async fn repeated_exec_requests_do_not_refresh_connection_idle_deadline() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits {
            idle_timeout: Duration::from_millis(600),
            ..Default::default()
        },
        Duration::from_secs(10),
        &["exec"],
    )
    .await;
    let session = login(&g).await;
    // Polling every 200 ms would keep the connection alive forever if exec counted as interaction.
    let polled = timeout(Duration::from_secs(3), async {
        loop {
            let Ok(mut c) = session.channel_open_session().await else {
                break;
            };
            if c.exec(true, "permitted").await.is_err() || !reply(&mut c).await {
                break;
            }
            let _ = exec_result(&mut c).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(polled.is_ok(), "idle deadline closed the polled connection");
    let states = wait_states(&g, ConnectionState::Failed).await;
    assert_eq!(
        states.last(),
        Some(&(ConnectionState::Failed, Some(ErrorCode::TargetTimeout)))
    );
}
#[tokio::test]
async fn recording_failure_ends_shell_and_concurrent_exec() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["shell", "exec"],
    )
    .await;
    let session = login(&g).await;
    let mut terminal = shell(&session).await;
    read_until(&mut terminal, b"target$ ").await;
    let mut command = session.channel_open_session().await.unwrap();
    command.exec(true, "wait").await.unwrap();
    assert!(reply(&mut command).await);
    g.backend.recording_fault.store(true, Ordering::Release);
    terminal.data(&b"big\r"[..]).await.unwrap();
    read_end(&mut terminal).await;
    assert!(read_end(&mut command).await.closed);
    let states = wait_states(&g, ConnectionState::Failed).await;
    assert_eq!(
        states.last(),
        Some(&(
            ConnectionState::Failed,
            Some(ErrorCode::RecordingUnavailable)
        ))
    );
    assert_eq!(
        g.backend.recording.rows.lock().unwrap().last().unwrap().2,
        Some(RecordingState::Partial)
    );
    assert_eq!(g.backend.exec.lock().unwrap().len(), 1);
}

struct SftpReader {
    reader: russh::ChannelReadHalf,
    buffer: Vec<u8>,
}
impl SftpReader {
    async fn packet(&mut self) -> Vec<u8> {
        timeout(Duration::from_secs(20), async {
            loop {
                if self.buffer.len() >= 4 {
                    let n = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
                    if self.buffer.len() >= n + 4 {
                        return self.buffer.drain(..n + 4).collect();
                    }
                }
                match self.reader.wait().await {
                    Some(ChannelMsg::Data { data }) => self.buffer.extend_from_slice(&data),
                    Some(ChannelMsg::Close) | None => panic!("SFTP channel closed before response"),
                    _ => {}
                }
            }
        })
        .await
        .unwrap()
    }
}
async fn sftp_channel(
    session: &client::Handle<Pinned>,
) -> (SftpReader, russh::ChannelWriteHalf<client::Msg>) {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(reply(&mut channel).await);
    let (reader, writer) = channel.split();
    let mut reader = SftpReader {
        reader,
        buffer: Vec::new(),
    };
    writer
        .data_bytes(Bytes::from_static(&[0, 0, 0, 5, 1, 0, 0, 0, 3]))
        .await
        .unwrap();
    assert_eq!(reader.packet().await, memory_version(false));
    (reader, writer)
}
async fn sftp_open(
    reader: &mut SftpReader,
    writer: &russh::ChannelWriteHalf<client::Msg>,
    path: &[u8],
    flags: u32,
) -> Vec<u8> {
    let mut b = wire::string(path);
    b.extend(flags.to_be_bytes());
    b.extend([0; 4]);
    writer.data_bytes(wire::frame(3, 1, &b)).await.unwrap();
    let packet = reader.packet().await;
    assert_eq!(packet[4], 102);
    MemoryFields(&packet[9..]).string()
}
async fn sftp_close(
    reader: &mut SftpReader,
    writer: &russh::ChannelWriteHalf<client::Msg>,
    handle: &[u8],
) {
    writer
        .data_bytes(wire::frame(4, 1000, &wire::string(handle)))
        .await
        .unwrap();
    assert_eq!(reader.packet().await, wire::status(1000, 0));
}
#[tokio::test]
async fn sftp_only_eight_mib_pipeline_activates_once_and_audits_hashes() {
    use sha2::{Digest, Sha256};
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["sftp"],
    )
    .await;
    let session = login(&g).await;
    let (mut reader, writer) = sftp_channel(&session).await;
    let handle = sftp_open(&mut reader, &writer, b"/large", 0x1a).await;
    let data: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
    let mut hash = Sha256::new();
    for _ in 0..64 {
        hash.update(&data);
    }
    let expected = format!("{:x}", hash.finalize());
    let writes = async {
        for i in 0..64 {
            let mut b = wire::string(&handle);
            b.extend((i as u64 * data.len() as u64).to_be_bytes());
            b.extend(wire::string(&data));
            writer.data_bytes(wire::frame(6, i + 2, &b)).await.unwrap();
        }
    };
    let acks = async {
        for i in 0..64 {
            assert_eq!(reader.packet().await, wire::status(i + 2, 0));
        }
    };
    tokio::join!(writes, acks);
    sftp_close(&mut reader, &writer, &handle).await;
    let handle = sftp_open(&mut reader, &writer, b"/large", 1).await;
    let reads = async {
        for i in 0..64 {
            let mut b = wire::string(&handle);
            b.extend((i as u64 * data.len() as u64).to_be_bytes());
            b.extend((data.len() as u32).to_be_bytes());
            writer.data_bytes(wire::frame(5, i + 2, &b)).await.unwrap();
        }
    };
    let responses = async {
        for _ in 0..64 {
            let packet = reader.packet().await;
            assert_eq!(packet[4], 103);
            assert_eq!(MemoryFields(&packet[9..]).string(), data);
        }
    };
    tokio::join!(reads, responses);
    sftp_close(&mut reader, &writer, &handle).await;
    // EOF is a valid READ response and contributes no bytes to the hash.
    let handle = sftp_open(&mut reader, &writer, b"/large", 1).await;
    let mut b = wire::string(&handle);
    b.extend((8 * 1024 * 1024u64).to_be_bytes());
    b.extend(1u32.to_be_bytes());
    writer.data_bytes(wire::frame(5, 2, &b)).await.unwrap();
    assert_eq!(reader.packet().await, wire::status(2, 1));
    sftp_close(&mut reader, &writer, &handle).await;
    {
        let audits = g.backend.sftp.lock().unwrap();
        for (index, write) in [(0, true), (1, false)] {
            assert!(
                matches!(&audits[index],SftpAudit::File{status:Some(0),sha256:Some(actual),read_bytes,write_bytes,..}
            if actual==&expected && *read_bytes==if write {0}else{8*1024*1024} && *write_bytes==if write {8*1024*1024}else{0})
            );
        }
    }
    writer.close().await.unwrap();
    assert_eq!(g.backend.activated.load(Ordering::Relaxed), 1);
    assert!(g.backend.recording.rows.lock().unwrap().is_empty());
}
#[tokio::test]
async fn sftp_denied_open_and_subsystem_rejections_preserve_client_status_and_reuse() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["sftp", "exec"],
    )
    .await;
    let session = login(&g).await;
    let (mut reader, writer) = sftp_channel(&session).await;
    let mut b = wire::string(b"/denied/file");
    b.extend(0x1au32.to_be_bytes());
    b.extend([0; 4]);
    writer.data_bytes(wire::frame(3, 1, &b)).await.unwrap();
    assert_eq!(reader.packet().await, wire::status(1, 3));
    assert!(matches!(
        &g.backend.sftp.lock().unwrap()[0],
        SftpAudit::File {
            status: Some(3),
            write_bytes: 0,
            sha256: None,
            ..
        }
    ));
    g.target_log.lock().unwrap().reject_sftp = true;
    let mut channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "foo").await.unwrap();
    assert!(!reply(&mut channel).await);
    assert!(g.backend.sftp_rejected.lock().unwrap().is_empty());
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(!reply(&mut channel).await);
    assert_eq!(
        *g.backend.sftp_rejected.lock().unwrap(),
        [ErrorCode::TargetRequestRejected]
    );
    channel.exec(true, "permitted").await.unwrap();
    assert!(reply(&mut channel).await);
    assert_eq!(exec_result(&mut channel).await.0, b"permitted");
    let no_sftp = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["exec"],
    )
    .await;
    let session = login(&no_sftp).await;
    let mut channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(!reply(&mut channel).await);
    assert_eq!(
        *no_sftp.backend.sftp_rejected.lock().unwrap(),
        [ErrorCode::PermissionDenied]
    );
    channel.exec(true, "valid").await.unwrap();
    assert!(reply(&mut channel).await);
}
#[tokio::test]
async fn sftp_audit_errors_are_best_effort_and_slow_audits_do_not_block_drain() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["sftp"],
    )
    .await;
    let session = login(&g).await;
    let (mut reader, writer) = sftp_channel(&session).await;
    g.backend.audit_error.store(true, Ordering::Release);
    let handle = sftp_open(&mut reader, &writer, b"/new", 0x1a).await;
    sftp_close(&mut reader, &writer, &handle).await;
    g.backend.audit_error.store(false, Ordering::Release);
    *g.backend.audit_delay.lock().unwrap() = Duration::from_secs(5);
    let handle = sftp_open(&mut reader, &writer, b"/new", 1).await;
    let started = Instant::now();
    sftp_close(&mut reader, &writer, &handle).await;
    assert!(started.elapsed() < Duration::from_secs(3));
    let _ = sftp_open(&mut reader, &writer, b"/new", 1).await;
    g.shutdown.cancel();
    let task = g.task.lock().unwrap().take().unwrap();
    timeout(Duration::from_secs(9), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    wait_states(&g, ConnectionState::Failed).await;
}
#[tokio::test]
async fn sftp_revocation_finishes_open_file_and_request_activity_resets_idle() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits {
            idle_timeout: Duration::from_millis(700),
            ..Default::default()
        },
        Duration::from_secs(10),
        &["sftp"],
    )
    .await;
    let session = login(&g).await;
    let (mut reader, writer) = sftp_channel(&session).await;
    let _ = sftp_open(&mut reader, &writer, b"/open", 0x1a).await;
    for id in 2..5 {
        tokio::time::sleep(Duration::from_millis(350)).await;
        writer
            .data_bytes(wire::frame(17, id, &wire::string(b"/open")))
            .await
            .unwrap();
        assert_eq!(reader.packet().await[4], 105);
        assert!(!session.is_closed());
    }
    let connection = g.tickets.consumed.lock().unwrap().clone().unwrap();
    g.backend.registry.revoke_connection(connection.id);
    wait_states(&g, ConnectionState::Failed).await;
    let audits = g.backend.sftp.lock().unwrap();
    assert!(audits
        .iter()
        .any(|a| matches!(a, SftpAudit::File { status: None, .. })));
    assert!(audits
        .iter()
        .any(|a| matches!(a,SftpAudit::Session{requests,..} if requests["stat"]==3)));
}
#[tokio::test]
async fn sftp_channel_counts_toward_limit_and_close_releases_capacity() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["sftp"],
    )
    .await;
    let session = login(&g).await;
    let (_, writer) = sftp_channel(&session).await;
    let mut channels = Vec::new();
    for _ in 0..15 {
        channels.push(session.channel_open_session().await.unwrap());
    }
    assert!(session.channel_open_session().await.is_err());
    writer.close().await.unwrap();
    let new = session.channel_open_session().await.unwrap();
    new.close().await.unwrap();
}

#[tokio::test]
async fn disconnect_during_close_audit_settles_file_before_session_summary() {
    let g = gateway_with(
        Ending::Status,
        RuntimeLimits::default(),
        Duration::from_secs(10),
        &["sftp"],
    )
    .await;
    let session = login(&g).await;
    let (mut reader, writer) = sftp_channel(&session).await;
    let handle = sftp_open(&mut reader, &writer, b"/race", 0x1a).await;
    *g.backend.audit_delay.lock().unwrap() = Duration::from_millis(200);
    writer
        .data_bytes(wire::frame(4, 2, &wire::string(&handle)))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while g.backend.audit_started.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let connection = g.tickets.consumed.lock().unwrap().clone().unwrap();
    g.backend.registry.revoke_connection(connection.id);
    wait_states(&g, ConnectionState::Failed).await;
    let audits = g.backend.sftp.lock().unwrap();
    assert_eq!(audits.len(), 2, "{audits:?}");
    assert!(matches!(
        audits[0],
        SftpAudit::File {
            status: Some(0),
            ..
        }
    ));
    assert!(matches!(audits[1], SftpAudit::Session { .. }));
}
