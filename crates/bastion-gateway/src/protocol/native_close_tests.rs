//! Exercise the real native SSH bridge and recorder with a delayed metadata ACK.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bastion_domain::{RecordingCreate, RecordingState};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex};

struct TempRoot(PathBuf);
impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("bastion-native-close-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Finish {
    state: RecordingState,
    checksum: Option<String>,
    exit_code: Option<u32>,
    failure: Option<ErrorCode>,
}
struct Backend {
    connection: Connection,
    target: Target,
    config: RecordingConfig,
    registry: Arc<RuntimeRegistry>,
    entered: Semaphore,
    release: Semaphore,
    finishes: Mutex<Vec<Finish>>,
}
#[async_trait]
impl GatewayBackend for Backend {
    fn registry(&self) -> Arc<RuntimeRegistry> {
        self.registry.clone()
    }
    fn recording_config(&self) -> Option<RecordingConfig> {
        Some(self.config.clone())
    }
    async fn consume(&self, _: Uuid, _: &str) -> Result<(Connection, Target), ErrorCode> {
        Ok((self.connection.clone(), self.target.clone()))
    }
    async fn authorize(&self, _: &Connection) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn transition(
        &self,
        _: Uuid,
        _: ConnectionState,
        _: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
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
    async fn begin_shell(
        &self,
        _: &Connection,
        _: u32,
        _: RecordingCreate,
    ) -> Result<Uuid, ErrorCode> {
        Ok(Uuid::new_v4())
    }
    async fn activate_shell(&self, _: &Connection, _: Uuid, _: Uuid) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn mark_streaming(&self, _: Uuid) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn checkpoint_recording(&self, _: Uuid, _: i64, _: i64, _: i64) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn finish_shell(
        &self,
        _: Uuid,
        _: Uuid,
        state: RecordingState,
        _: i64,
        checksum: Option<String>,
        exit_code: Option<u32>,
        _: Option<String>,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        if state == RecordingState::Complete {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        self.finishes.lock().unwrap().push(Finish {
            state,
            checksum,
            exit_code,
            failure,
        });
        Ok(())
    }
}

// Only a loopback test peer; production still pins this generated fixture key.
struct Peer(russh::keys::PublicKey);
impl client::Handler for Peer {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(key == &self.0)
    }
}
struct TargetPeer(Arc<Semaphore>);
impl server::Handler for TargetPeer {
    type Error = russh::Error;
    async fn auth_password(&mut self, _: &str, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        _: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(id)?;
        let handle = session.handle();
        let close = self.0.clone();
        tokio::spawn(async move {
            handle
                .data(id, b"native-close-output\0\xff".to_vec())
                .await
                .unwrap();
            handle.exit_status_request(id, 7).await.unwrap();
            close.acquire().await.unwrap().forget();
            let _ = handle.eof(id).await;
            let _ = handle.close(id).await;
        });
        Ok(())
    }
}
fn key(seed: u8) -> russh::keys::PrivateKey {
    russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(
        &[seed; 32],
    ))
}

async fn exercise(cancel_before_target_close: bool) {
    let root = TempRoot::new();
    let kek = root.0.join("kek");
    fs::write(&kek, URL_SAFE_NO_PAD.encode([7; 32])).unwrap();
    fs::set_permissions(&kek, fs::Permissions::from_mode(0o600)).unwrap();
    let recordings = root.0.join("recordings");
    fs::create_dir(&recordings).unwrap();
    fs::set_permissions(&recordings, fs::Permissions::from_mode(0o700)).unwrap();
    let keys = Arc::new(KeyRing::from_files(1, &BTreeMap::from([(1, kek)])).unwrap());
    let context = CipherContext {
        server_id: "native-close-test".into(),
        credential_id: Uuid::new_v4(),
        kind: "password".into(),
        revision: 1,
    };
    let envelope = keys
        .seal(
            &context,
            &Credential::Password {
                password: "fixture".into(),
            },
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target_key = key(3);
    let public = target_key.public_key().clone();
    let close = Arc::new(Semaphore::new(usize::from(!cancel_before_target_close)));
    let target_close = close.clone();
    let target_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server::run_stream(
            Arc::new(server::Config {
                keys: vec![target_key],
                auth_rejection_time: Duration::ZERO,
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            }),
            socket,
            TargetPeer(target_close),
        )
        .await
        .unwrap()
        .await
    });
    let backend = Arc::new(Backend {
        connection: Connection {
            id: Uuid::new_v4(),
            ticket_id: Uuid::new_v4(),
            asset_id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            capabilities: vec![Capability::Shell],
            purpose: bastion_domain::Purpose::Terminal,
            transport: bastion_domain::TicketTransport::Ssh,
            protocol_version: 1,
            state: ConnectionState::Connecting,
            created_at: chrono::Utc::now(),
            failure: None,
            user_id: Some(Uuid::new_v4()),
            login_session_id: Some(Uuid::new_v4()),
        },
        target: Target {
            address: TargetEndpoint::Restricted {
                host: "127.0.0.1".into(),
                port: address.port(),
                policy: Arc::new(NetworkPolicy {
                    allow: vec!["127.0.0.1/32".parse().unwrap()],
                    deny: vec![],
                }),
            },
            username: "fixture".into(),
            public_keys: vec![public],
            auth: TargetAuth::Encrypted {
                context,
                envelope,
                keys: keys.clone(),
            },
        },
        config: RecordingConfig {
            server_id: "native-close-test".into(),
            directory: recordings.clone(),
            keys,
            retention: Duration::from_secs(60),
            min_free_bytes: 0,
        },
        registry: Arc::new(RuntimeRegistry::new()),
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        finishes: Mutex::new(Vec::new()),
    });
    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_address = gateway_listener.local_addr().unwrap();
    let gateway_key = key(4);
    let gateway_public = gateway_key.public_key().clone();
    let shutdown = CancellationToken::new();
    let gateway = tokio::spawn(run_backend(
        gateway_listener,
        gateway_key,
        backend.clone(),
        shutdown.clone(),
    ));
    let mut client = client::connect(
        Arc::new(client::Config::default()),
        gateway_address,
        Peer(gateway_public),
    )
    .await
    .unwrap();
    assert!(client
        .authenticate_password(format!("zt1:{}", backend.connection.ticket_id), "fixture")
        .await
        .unwrap()
        .success());
    let mut channel = client.channel_open_session().await.unwrap();
    channel.request_shell(true).await.unwrap();
    let mut output = Vec::new();
    loop {
        match channel.wait().await.unwrap() {
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => {
                assert_eq!(exit_status, 7);
                break;
            }
            ChannelMsg::Close => panic!("close preceded exit status"),
            _ => {}
        }
    }
    assert_eq!(output, b"native-close-output\0\xff");
    if cancel_before_target_close {
        shutdown.cancel();
        client
            .disconnect(Disconnect::ByApplication, "fixture cancellation", "en")
            .await
            .unwrap();
        close.add_permits(1);
    } else {
        timeout(Duration::from_secs(3), backend.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        let closed = async {
            while let Some(event) = channel.wait().await {
                if matches!(event, ChannelMsg::Close) {
                    return;
                }
            }
            panic!("channel vanished before close");
        };
        tokio::pin!(closed);
        assert!(
            timeout(Duration::from_millis(100), &mut closed)
                .await
                .is_err(),
            "SSH Close exposed before recorder metadata ACK"
        );
        backend.release.add_permits(1);
        timeout(Duration::from_secs(3), closed).await.unwrap();
        // Disconnect immediately on Close: GatewayHandler::drop must not interrupt seal.
        client
            .disconnect(Disconnect::ByApplication, "client closed immediately", "en")
            .await
            .unwrap();
        shutdown.cancel();
    }
    timeout(Duration::from_secs(8), gateway)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    backend
        .registry
        .drain(Duration::from_secs(5))
        .await
        .unwrap();
    let target_result = timeout(Duration::from_secs(3), target_task)
        .await
        .unwrap()
        .unwrap();
    assert!(match target_result {
        Ok(()) | Err(russh::Error::Disconnect | russh::Error::HUP) => true,
        Err(russh::Error::IO(error)) => matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ),
        Err(error) => panic!("unexpected target error: {error}"),
    });
    let finishes = backend.finishes.lock().unwrap();
    assert_eq!(finishes.len(), 1, "recording finalized more than once");
    let finish = &finishes[0];
    if cancel_before_target_close {
        assert_eq!(finish.state, RecordingState::Partial);
    } else {
        assert_eq!(finish.state, RecordingState::Complete);
        assert_eq!(finish.exit_code, Some(7));
        assert_eq!(finish.failure, None);
        let file = fs::read_dir(recordings)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            finish.checksum.as_deref(),
            Some(format!("{:x}", Sha256::digest(fs::read(file).unwrap())).as_str())
        );
    }
}

#[tokio::test]
async fn native_close_waits_for_recording_metadata_before_client_disconnect() {
    timeout(Duration::from_secs(20), exercise(false))
        .await
        .unwrap();
}
#[tokio::test]
async fn native_cancel_before_target_close_never_marks_recording_complete() {
    timeout(Duration::from_secs(20), exercise(true))
        .await
        .unwrap();
}
