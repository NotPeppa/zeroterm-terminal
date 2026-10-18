use super::*;
use super::{recording::SessionRecording, runtime::authorize, web::output};
use russh::{
    client,
    keys::{Algorithm, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate},
    Channel, ChannelMsg,
};
use std::{borrow::Cow, collections::VecDeque, net::Shutdown};
use tokio::{sync::mpsc, time::Instant};

pub(super) struct PinnedHost {
    key: PublicKey,
}
impl client::Handler for PinnedHost {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        offered: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(
            matches!(offered, PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.key.key_data()),
        )
    }
}
// The same TCP connection is shut down even if startup/pump is cancelled or aborted.
struct SocketGuard(std::net::TcpStream);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}
type SshChannel = Channel<client::Msg>;
/// What the target reported before closing its shell channel; the native entry relays it.
#[derive(Clone, Debug, Default)]
pub(crate) struct TargetExit {
    pub eof: bool,
    pub status: Option<u32>,
    pub signal: Option<(russh::Sig, bool, String)>,
}
/// State shared between `run` and the native SSH adapter (RFC-006 §7.3). The browser passes none.
pub(crate) struct NativeLink {
    /// Input credit in `input_charge` units. The adapter takes it before queueing a frame and `pump`
    /// returns it once the target write completed, so `pump`'s own credit check can never trip and
    /// input backpressure reaches the adapter instead of closing the session.
    pub pacer: Arc<Semaphore>,
    pub exit: std::sync::Mutex<TargetExit>,
}
impl NativeLink {
    pub fn new(queue_bytes: usize) -> Self {
        Self {
            pacer: Arc::new(Semaphore::new(queue_bytes)),
            exit: Default::default(),
        }
    }
}
/// At least 128 per frame: keeps the queued frame count within `pump`'s input queue capacity.
pub(crate) fn input_charge(frame: usize) -> usize {
    frame.max(128)
}
pub(super) async fn accepted(channel: &mut SshChannel) -> Result<(), ErrorCode> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            // OpenSSH may announce input flow-control credit before shell success.
            Some(ChannelMsg::WindowAdjusted { .. }) => continue,
            _ => return Err(ErrorCode::TargetRequestRejected),
        }
    }
}

/// One authenticated, pinned target socket, shared by all native channels.
pub(super) struct TargetSession {
    pub handle: client::Handle<PinnedHost>,
    _guard: SocketGuard,
}
pub(super) async fn connect_target(
    connection: &Connection,
    target: &Target,
    backend: &dyn GatewayBackend,
    limits: &RuntimeLimits,
) -> Result<TargetSession, ErrorCode> {
    authorize(backend, connection).await?;
    let approved = target
        .ssh_host_key
        .as_deref()
        .filter(|key| bastion_store::valid_ssh_host_key(key))
        .ok_or(ErrorCode::TargetHostKeyUnknown)?;
    let key = PublicKey::from_openssh(approved).map_err(|_| ErrorCode::TargetHostKeyUnknown)?;
    let username = target
        .username
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(ErrorCode::InvalidArgument)?;
    let address = target.address.resolve().await?;
    let socket = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|_| ErrorCode::TargetUnreachable)?;
    socket
        .set_nodelay(true)
        .map_err(|_| ErrorCode::TargetUnreachable)?;
    let raw = socket
        .into_std()
        .map_err(|_| ErrorCode::TargetUnreachable)?;
    let guard = SocketGuard(raw.try_clone().map_err(|_| ErrorCode::TargetUnreachable)?);
    let socket = tokio::net::TcpStream::from_std(raw).map_err(|_| ErrorCode::TargetUnreachable)?;
    let mut config = client::Config {
        window_size: limits.queue_bytes as u32,
        maximum_packet_size: (MAX_DATA_BYTES - 1) as u32,
        channel_buffer_size: limits.queue_bytes / MAX_DATA_BYTES,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 2,
        ..Default::default()
    };
    // Negotiate the approved key's algorithm; don't accidentally choose another server key.
    config.preferred.key = Cow::Owned(match key.algorithm() {
        Algorithm::Rsa { .. } => vec![
            Algorithm::Rsa {
                hash: Some(russh::keys::HashAlg::Sha512),
            },
            Algorithm::Rsa {
                hash: Some(russh::keys::HashAlg::Sha256),
            },
        ],
        algorithm => vec![algorithm],
    });
    let mut session = client::connect_stream(Arc::new(config), socket, PinnedHost { key })
        .await
        .map_err(|error| {
            if matches!(error, russh::Error::UnknownKey) {
                ErrorCode::TargetHostKeyChanged
            } else {
                ErrorCode::TargetUnreachable
            }
        })?;
    // Host key was checked on this socket, before any target credentials are submitted.
    authorize(backend, connection).await?;
    let credential = match &target.auth {
        TargetAuth::Encrypted {
            context,
            envelope,
            keys,
        } => keys
            .open(context, envelope)
            .map_err(|_| ErrorCode::TargetAuthFailed)?,
        TargetAuth::None => return Err(ErrorCode::TargetAuthFailed),
    };
    if !credential.validate_lengths() {
        return Err(ErrorCode::TargetAuthFailed);
    }
    let auth = match &credential {
        Credential::Password { password } => {
            session
                .authenticate_password(username, password.as_str())
                .await
        }
        Credential::PrivateKey {
            key_pem,
            passphrase,
        } => {
            // Key decryption can be expensive; don't block Tokio's runtime or cancellation.
            let pem = zeroize::Zeroizing::new(key_pem.clone());
            let phrase = zeroize::Zeroizing::new(passphrase.clone());
            let private = tokio::task::spawn_blocking(move || {
                russh::keys::decode_secret_key(&pem, phrase.as_deref())
            })
            .await
            .map_err(|_| ErrorCode::TargetAuthFailed)?
            .map_err(|_| ErrorCode::TargetAuthFailed)?;
            authorize(backend, connection).await?;
            session
                .authenticate_publickey(
                    username,
                    PrivateKeyWithHashAlg::new(Arc::new(private), None),
                )
                .await
        }
        Credential::None => return Err(ErrorCode::TargetAuthFailed),
    }
    .map_err(|_| ErrorCode::TargetAuthFailed)?;
    drop(credential);
    if !auth.success() {
        return Err(ErrorCode::TargetAuthFailed);
    }
    Ok(TargetSession {
        handle: session,
        _guard: guard,
    })
}

#[allow(clippy::too_many_arguments)]
async fn open_shell(
    session: &client::Handle<PinnedHost>,
    connection: &Connection,
    backend: &dyn GatewayBackend,
    recording: &SessionRecording,
    outgoing: &mpsc::Sender<Vec<u8>>,
    stop: &CancellationToken,
    limits: &RuntimeLimits,
    initial: &[u8],
    initial_size: (u32, u32),
) -> Result<SshChannel, ErrorCode> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|_| ErrorCode::TargetRequestRejected)?;
    channel
        .request_pty(
            true,
            "xterm-256color",
            initial_size.0,
            initial_size.1,
            0,
            0,
            &[],
        )
        .await
        .map_err(|_| ErrorCode::TargetRequestRejected)?;
    accepted(&mut channel).await?;
    channel
        .request_shell(true)
        .await
        .map_err(|_| ErrorCode::TargetRequestRejected)?;
    accepted(&mut channel).await?;
    authorize(backend, connection).await?;
    recording.activate().await?;
    output(
        recording,
        outgoing,
        initial,
        stop,
        limits.stall_timeout,
        true,
    )
    .await?;
    output(
        recording,
        outgoing,
        &[TERMINAL_READY],
        stop,
        limits.stall_timeout,
        false,
    )
    .await?;
    Ok(channel)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_on_target(
    session: &client::Handle<PinnedHost>,
    connection: &Connection,
    backend: &dyn GatewayBackend,
    recording: &SessionRecording,
    incoming: &mut mpsc::Receiver<Vec<u8>>,
    outgoing: &mpsc::Sender<Vec<u8>>,
    stop: &CancellationToken,
    limits: &RuntimeLimits,
    native: &NativeLink,
) -> Result<(), ErrorCode> {
    let initial = incoming.recv().await.ok_or(ErrorCode::TargetUnreachable)?;
    let initial_size = terminal_size(&initial)?;
    let channel = open_shell(
        session,
        connection,
        backend,
        recording,
        outgoing,
        stop,
        limits,
        &initial,
        initial_size,
    )
    .await?;
    pump(
        connection,
        backend,
        recording,
        incoming,
        outgoing,
        stop,
        limits,
        channel,
        initial_size,
        Some(native),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    connection: &Connection,
    target: &Target,
    backend: &dyn GatewayBackend,
    recording: &SessionRecording,
    incoming: &mut mpsc::Receiver<Vec<u8>>,
    outgoing: &mpsc::Sender<Vec<u8>>,
    stop: &CancellationToken,
    limits: &RuntimeLimits,
    started: Instant,
    deadline: Instant,
    native: Option<&NativeLink>,
) -> Result<(), ErrorCode> {
    // Only a bounded initial size is admitted before ready; no user input.
    let initial = tokio::select! {
        _ = stop.cancelled() => return Err(ErrorCode::LoginSessionRevoked),
        value = tokio::time::timeout_at(deadline,incoming.recv()) => value.map_err(|_|ErrorCode::TargetTimeout)?.ok_or(ErrorCode::TargetUnreachable)?,
    };
    let initial_size = terminal_size(&initial)?;
    let startup = async {
        let target_session = connect_target(connection, target, backend, limits).await?;
        let session = &target_session.handle;
        let channel = open_shell(
            session,
            connection,
            backend,
            recording,
            outgoing,
            stop,
            limits,
            &initial,
            initial_size,
        )
        .await?;
        Ok::<_, ErrorCode>((target_session, channel, initial_size))
    };
    let closed = async {
        while !incoming.is_closed() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    let (target_session, channel, initial_size) = tokio::select! {
        biased;
        _ = stop.cancelled() => return Err(ErrorCode::LoginSessionRevoked),
        _ = closed => return Err(ErrorCode::LoginSessionRevoked),
        value = tokio::time::timeout_at(deadline,startup) => value.unwrap_or(Err(ErrorCode::TargetTimeout))?,
    };
    let result = tokio::time::timeout_at(
        started + limits.max_duration,
        pump(
            connection,
            backend,
            recording,
            incoming,
            outgoing,
            stop,
            limits,
            channel,
            initial_size,
            native,
        ),
    )
    .await
    .unwrap_or(Err(ErrorCode::TargetTimeout));
    // Guard shuts the TCP socket even when these bounded best-effort messages fail.
    let _ = timeout(
        Duration::from_secs(1),
        target_session
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "en"),
    )
    .await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn pump(
    connection: &Connection,
    backend: &dyn GatewayBackend,
    recording: &SessionRecording,
    incoming: &mut mpsc::Receiver<Vec<u8>>,
    outgoing: &mpsc::Sender<Vec<u8>>,
    stop: &CancellationToken,
    limits: &RuntimeLimits,
    channel: SshChannel,
    initial_size: (u32, u32),
    native: Option<&NativeLink>,
) -> Result<(), ErrorCode> {
    let (mut reader, writer) = channel.split();
    let credits = Arc::new(Semaphore::new(limits.queue_bytes));
    let (input_tx, mut input_rx) =
        mpsc::channel::<(Vec<u8>, OwnedSemaphorePermit)>((limits.queue_bytes / 128).max(1));
    let (resized_tx, mut resized_rx) = mpsc::channel::<Vec<u8>>(8);
    let mut input_tx = Some(input_tx);
    // Poll writes independently: awaiting data() in the read loop can deadlock
    // russh when its bounded echo queue fills before the next input is sent.
    let forwarding = async {
        while let Some((bytes, credit)) = input_rx.recv().await {
            let charge = input_charge(bytes.len());
            let write = async {
                if bytes[0] == TERMINAL_DATA {
                    writer
                        .data(&bytes[1..])
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)
                } else {
                    let size = terminal_size(&bytes)?;
                    writer
                        .window_change(size.0, size.1, 0, 0)
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    resized_tx
                        .send(bytes)
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)
                }
            };
            tokio::select! {
                _ = stop.cancelled() => return Err(ErrorCode::LoginSessionRevoked),
                result = timeout(limits.stall_timeout, write) => result.map_err(|_| ErrorCode::TargetTimeout)??,
            }
            drop(credit);
            if let Some(link) = native {
                link.pacer.add_permits(charge);
            }
        }
        Ok::<_, ErrorCode>(())
    };
    tokio::pin!(forwarding);
    let mut last_input = Instant::now();
    let mut checks = tokio::time::interval(Duration::from_secs(1));
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending = VecDeque::new();
    let mut outstanding = 0usize;
    let mut rendered = Instant::now();
    let mut size = initial_size;
    let mut target_closed = false;
    let mut browser_closed = false;
    loop {
        if target_closed && outstanding == 0 {
            return if credits.available_permits() == limits.queue_bytes {
                Ok(())
            } else {
                Err(ErrorCode::TargetUnreachable)
            };
        }
        tokio::select! {
            biased;
            _ = stop.cancelled() => return Err(ErrorCode::LoginSessionRevoked),
            _ = tokio::time::sleep_until(last_input+limits.idle_timeout), if native.is_none() => return Err(ErrorCode::TargetTimeout),
            _ = tokio::time::sleep_until(rendered+limits.stall_timeout), if outstanding>0 => return Err(ErrorCode::TargetTimeout),
            _ = checks.tick(), if native.is_none() => authorize(backend,connection).await?,
            result = &mut forwarding => return result,
            Some(bytes) = resized_rx.recv() => output(recording,outgoing,&bytes,stop,limits.stall_timeout,true).await?,
            message = reader.wait(), if !target_closed && outstanding + MAX_DATA_BYTES <= limits.queue_bytes => {
                match message {
                    Some(ChannelMsg::Data{data} | ChannelMsg::ExtendedData{data,..}) => {
                        if data.len()>=MAX_DATA_BYTES {return Err(ErrorCode::TargetRequestRejected);}
                        for chunk in data.chunks(MAX_DATA_BYTES-1) {
                            let mut frame=Vec::with_capacity(chunk.len()+1);frame.push(TERMINAL_DATA);frame.extend_from_slice(chunk);
                            output(recording,outgoing,&frame,stop,limits.stall_timeout,true).await?;
                            if !browser_closed {
                                if outstanding==0 {rendered=Instant::now();}
                                outstanding+=frame.len();pending.push_back(frame.len());
                            }
                        }
                    },
                    Some(ChannelMsg::Close) => target_closed=true,
                    Some(ChannelMsg::WindowAdjusted{..}) => {},
                    // Recorded for the native entry to relay after the output drained; the browser ignores them.
                    Some(ChannelMsg::Eof) => if let Some(link)=native {link.exit.lock().unwrap().eof=true;},
                    Some(ChannelMsg::ExitStatus{exit_status}) => if let Some(link)=native {link.exit.lock().unwrap().status=Some(exit_status);},
                    Some(ChannelMsg::ExitSignal{signal_name,core_dumped,error_message,..}) => match native {
                        Some(link) => link.exit.lock().unwrap().signal=Some((signal_name,core_dumped,error_message.chars().take(256).collect())),
                        None => return Err(ErrorCode::TargetRequestRejected),
                    },
                    None => return Err(ErrorCode::TargetUnreachable),
                    _ => return Err(ErrorCode::TargetRequestRejected),
                }
            },
            bytes = incoming.recv(), if !browser_closed => {
                let Some(bytes) = bytes else {
                    input_tx.take();browser_closed=true;outstanding=0;pending.clear();continue;
                };
                if bytes.len()>MAX_DATA_BYTES {return Err(ErrorCode::InvalidArgument);}
                match bytes.first() {
                    Some(&TERMINAL_DATA) if bytes.len()>1 => {
                        authorize(backend,connection).await?;
                        let credit=credits.clone().try_acquire_many_owned(bytes.len() as u32).map_err(|_|ErrorCode::InvalidArgument)?;
                        input_tx.as_ref().ok_or(ErrorCode::TargetUnreachable)?.try_send((bytes,credit)).map_err(|_|ErrorCode::InvalidArgument)?;
                    },
                    Some(&TERMINAL_SIZE) => {
                        let next = terminal_size(&bytes)?;
                        if next != size {
                            authorize(backend,connection).await?;
                            let credit=credits.clone().try_acquire_many_owned(bytes.len() as u32).map_err(|_|ErrorCode::InvalidArgument)?;
                            input_tx.as_ref().ok_or(ErrorCode::TargetUnreachable)?.try_send((bytes,credit)).map_err(|_|ErrorCode::InvalidArgument)?;
                            size=next;
                        }
                    },
                    Some(&TERMINAL_ACK) if bytes.len()==5 => {
                        let count = u32::from_be_bytes(bytes[1..].try_into().unwrap()) as usize;
                        if pending.pop_front()!=Some(count) {return Err(ErrorCode::InvalidArgument);}
                        outstanding-=count;rendered=Instant::now();
                    },
                    Some(&TERMINAL_ACTIVITY) if bytes.len()==1 => {
                        authorize(backend,connection).await?;last_input=Instant::now();
                    },
                    _ => return Err(ErrorCode::InvalidArgument),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client::Handler;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    #[ignore = "requires BASTION_SSH_PTY_FIXTURE_FILE: authorized disposable OpenSSH target and local key path"]
    async fn real_openssh_accepts_pty_and_shell_with_output() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            address: String,
            username: String,
            approved_key: String,
            private_key_file: String,
        }
        let path = std::env::var("BASTION_SSH_PTY_FIXTURE_FILE").unwrap();
        let fixture: Fixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let pem =
            zeroize::Zeroizing::new(std::fs::read_to_string(fixture.private_key_file).unwrap());
        let private = russh::keys::decode_secret_key(&pem, None).unwrap();
        drop(pem);
        let config = client::Config {
            window_size: 256 * 1024,
            maximum_packet_size: (MAX_DATA_BYTES - 1) as u32,
            channel_buffer_size: 8,
            ..Default::default()
        };
        let target: std::net::SocketAddr = fixture.address.parse().unwrap();
        let mut session = timeout(
            Duration::from_secs(15),
            client::connect(
                Arc::new(config),
                target,
                PinnedHost {
                    key: PublicKey::from_openssh(&fixture.approved_key).unwrap(),
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(session
            .authenticate_publickey(
                fixture.username,
                PrivateKeyWithHashAlg::new(Arc::new(private), None)
            )
            .await
            .unwrap()
            .success());
        let mut channel = session.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        timeout(Duration::from_secs(10), accepted(&mut channel))
            .await
            .unwrap()
            .expect("PTY confirmation");
        channel.request_shell(true).await.unwrap();
        timeout(Duration::from_secs(10), accepted(&mut channel))
            .await
            .unwrap()
            .expect("shell confirmation");
        channel
            .data(b"printf '\\132\\124\\137\\120\\124\\131\\137\\117\\113\\n'; exit\n".as_slice())
            .await
            .unwrap();
        let mut output = Vec::new();
        timeout(Duration::from_secs(10), async {
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => {
                        output.extend_from_slice(&data);
                        assert!(output.len() < 1024 * 1024);
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        assert!(output
            .windows(b"ZT_PTY_OK".len())
            .any(|bytes| bytes == b"ZT_PTY_OK"));
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
    }
    struct AuthProbe(Arc<AtomicUsize>);
    impl russh::server::Handler for AuthProbe {
        type Error = russh::Error;
        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(russh::server::Auth::Accept)
        }
        async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(russh::server::Auth::reject())
        }
    }
    #[tokio::test]
    async fn wrong_host_key_never_submits_authentication_on_the_target_socket() {
        for matching in [false, true] {
            let host = russh::keys::PrivateKey::random(
                &mut russh::keys::key::safe_rng(),
                Algorithm::Ed25519,
            )
            .unwrap();
            let other = russh::keys::PrivateKey::random(
                &mut russh::keys::key::safe_rng(),
                Algorithm::Ed25519,
            )
            .unwrap();
            let approved = if matching {
                host.public_key().clone()
            } else {
                other.public_key().clone()
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let probe = calls.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let config = russh::server::Config {
                    keys: vec![host],
                    auth_rejection_time: Duration::ZERO,
                    ..Default::default()
                };
                if let Ok(session) =
                    russh::server::run_stream(Arc::new(config), stream, AuthProbe(probe)).await
                {
                    let _ = session.await;
                }
            });
            let result = timeout(
                Duration::from_secs(5),
                client::connect(
                    Arc::new(client::Config::default()),
                    address,
                    PinnedHost { key: approved },
                ),
            )
            .await
            .unwrap();
            if matching {
                let mut session = result.unwrap();
                assert!(session
                    .authenticate_password("probe", "not-a-real-secret")
                    .await
                    .unwrap()
                    .success());
                session
                    .disconnect(russh::Disconnect::ByApplication, "", "en")
                    .await
                    .unwrap();
            } else {
                assert!(result.is_err());
            }
            timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(matching));
        }
    }
    #[tokio::test]
    async fn pinned_key_compares_key_material_and_rejects_different_key() {
        let a =
            russh::keys::PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
                .unwrap();
        let b =
            russh::keys::PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
                .unwrap();
        let mut handler = PinnedHost {
            key: a.public_key().clone(),
        };
        assert!(handler
            .check_server_key(&a.public_key().clone().into())
            .await
            .unwrap());
        assert!(!handler
            .check_server_key(&b.public_key().clone().into())
            .await
            .unwrap());
    }
}
