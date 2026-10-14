use super::*;
use std::collections::{HashSet, VecDeque};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
pub(crate) struct GuacdStream {
    pub socket: TcpStream,
    pub parser: GuacParser,
    pub pending: VecDeque<GuacInstruction>,
}
impl GuacdStream {
    pub(crate) async fn instruction(&mut self) -> Result<GuacInstruction, ErrorCode> {
        loop {
            if let Some(i) = self.pending.pop_front() {
                return Ok(i);
            }
            let mut bytes = [0; MAX_DATA_BYTES];
            let n = self
                .socket
                .read(&mut bytes)
                .await
                .map_err(|_| ErrorCode::TargetUnreachable)?;
            if n == 0 {
                self.parser.finish()?;
                return Err(ErrorCode::TargetUnreachable);
            }
            self.pending.extend(self.parser.push(&bytes[..n])?);
        }
    }
    pub(crate) async fn send(&mut self, elements: &[&str]) -> Result<(), ErrorCode> {
        self.socket
            .write_all(&guac_encode(elements))
            .await
            .map_err(|_| ErrorCode::TargetUnreachable)
    }
}
async fn select(
    config: &GuacdConfig,
    protocol: TargetProtocol,
) -> Result<(GuacdStream, Vec<String>), ErrorCode> {
    config.validate()?;
    let socket = TcpStream::connect(config.address)
        .await
        .map_err(|_| ErrorCode::TargetUnreachable)?;
    socket
        .set_nodelay(true)
        .map_err(|_| ErrorCode::TargetUnreachable)?;
    let mut stream = GuacdStream {
        socket,
        parser: GuacParser::new(MAX_INSTRUCTION_BYTES),
        pending: VecDeque::new(),
    };
    stream.send(&["select", protocol.as_str()]).await?;
    let args = stream.instruction().await?;
    if args.opcode() != "args"
        || args.bytes.len() > 32 * 1024
        || args.args().first().map(String::as_str) != Some("VERSION_1_5_0")
        || args
            .args()
            .iter()
            .any(|a| a.is_empty() || a.len() > 128 || a.chars().any(char::is_control))
    {
        return Err(ErrorCode::TargetProtocolUnavailable);
    }
    let names = args.args()[1..].to_vec();
    if names.len() != names.iter().collect::<HashSet<_>>().len() {
        return Err(ErrorCode::TargetProtocolUnavailable);
    }
    check_arguments(config, protocol, &names)?;
    Ok((stream, names))
}
fn check_arguments(
    config: &GuacdConfig,
    protocol: TargetProtocol,
    names: &[String],
) -> Result<(), ErrorCode> {
    let required: &[&str] = match protocol {
        TargetProtocol::Ssh => &[
            "hostname",
            "port",
            "username",
            "password",
            "private-key",
            "passphrase",
            "host-key",
            "enable-sftp",
            "disable-copy",
            "disable-paste",
            "recording-path",
            "zt-target-ready",
            "zt-ssh-display-only",
        ],
        TargetProtocol::Rdp => &[
            "hostname",
            "port",
            "username",
            "password",
            "domain",
            "security",
            "ignore-cert",
            "cert-tofu",
            "zt-strict-cert-pin",
            "disable-copy",
            "disable-paste",
            "disable-audio",
            "enable-printing",
            "enable-drive",
            "recording-path",
            "zt-target-ready",
        ],
        TargetProtocol::Vnc => &[
            "hostname",
            "port",
            "password",
            "disable-copy",
            "disable-paste",
            "autoretry",
            "recording-path",
            "zt-target-ready",
        ],
    };
    if required
        .iter()
        .any(|arg| !names.iter().any(|name| name == arg))
        || (protocol == TargetProtocol::Rdp && !config.rdp_strict_pin_verified)
        || (protocol == TargetProtocol::Vnc && config.vnc_trusted_cidrs.is_empty())
    {
        return Err(ErrorCode::TargetProtocolUnavailable);
    }
    Ok(())
}
pub async fn protocol_available(config: &GuacdConfig, protocol: TargetProtocol) -> bool {
    matches!(
        timeout(Duration::from_secs(2), select(config, protocol)).await,
        Ok(Ok(_))
    )
}
fn parameters(
    config: &GuacdConfig,
    target: &Target,
    display: Display,
    port: u16,
    credential: &Credential,
    names: &[String],
) -> Result<Vec<String>, ErrorCode> {
    check_arguments(config, target.protocol, names)?;
    let mut values: HashMap<&str, String> = HashMap::new();
    for name in [
        "disable-audio",
        "disable-download",
        "disable-upload",
        "sftp-disable-download",
        "sftp-disable-upload",
    ] {
        values.insert(name, "true".into());
    }
    values.insert("disable-copy", "false".into());
    values.insert("disable-paste", "false".into());
    for name in [
        "enable-sftp",
        "enable-agent",
        "enable-printing",
        "enable-drive",
        "create-drive-path",
        "enable-audio",
        "enable-audio-input",
        "enable-touch",
        "read-only",
        "ignore-cert",
        "cert-tofu",
        "disable-auth",
        "console-audio",
        "reverse-connect",
        "wol-send-packet",
    ] {
        values.insert(name, "false".into());
    }
    values.insert("zt-target-ready", "true".into());
    values.insert("zt-ssh-display-only", "true".into());
    values.insert("hostname", config.bridge_advertise_host.clone());
    values.insert("port", port.to_string());
    values.insert("timeout", "40".into());
    values.insert("width", display.width.to_string());
    values.insert("height", display.height.to_string());
    values.insert("dpi", display.dpi.to_string());
    values.insert("username", target.username.clone().unwrap_or_default());
    values.insert("domain", target.domain.clone().unwrap_or_default());
    values.insert("autoretry", "0".into());
    values.insert("terminal-type", "xterm-256color".into());
    values.insert("color-depth", "24".into());
    values.insert("resize-method", "display-update".into());
    values.insert(
        "disable-display-resize",
        if target.protocol == TargetProtocol::Vnc {
            "true".into()
        } else {
            "false".into()
        },
    );
    match target.protocol {
        TargetProtocol::Ssh => {
            let key = target
                .ssh_host_key
                .as_deref()
                .filter(|s| bastion_store::valid_ssh_host_key(s))
                .ok_or(ErrorCode::TargetHostKeyUnknown)?;
            if target.username.as_ref().is_none_or(String::is_empty) {
                return Err(ErrorCode::InvalidArgument);
            }
            values.insert(
                "host-key",
                format!("[{}]:{} {}", config.bridge_advertise_host, port, key),
            );
        }
        TargetProtocol::Rdp => {
            let pin = target
                .rdp_certificate_sha256
                .as_deref()
                .filter(|s| bastion_store::valid_certificate_pin(s))
                .ok_or(ErrorCode::TargetCertificateChanged)?;
            let security = target.security.ok_or(ErrorCode::InvalidArgument)?;
            if target.username.as_ref().is_none_or(String::is_empty) {
                return Err(ErrorCode::InvalidArgument);
            }
            values.insert("zt-strict-cert-pin", pin.to_owned());
            values.insert("security", security.as_str().into());
        }
        TargetProtocol::Vnc => {
            if target.username.is_some() || target.domain.is_some() {
                return Err(ErrorCode::InvalidArgument);
            }
        }
    }
    match (target.protocol, credential) {
        (TargetProtocol::Vnc, Credential::None) => {}
        (_, Credential::Password { password })
            if credential.validate_lengths()
                && !password.contains('\0')
                && (target.protocol != TargetProtocol::Vnc || password.len() <= 8) =>
        {
            values.insert("password", password.clone());
        }
        (
            TargetProtocol::Ssh,
            Credential::PrivateKey {
                key_pem,
                passphrase,
            },
        ) if credential.validate_lengths() => {
            values.insert("private-key", key_pem.clone());
            values.insert("passphrase", passphrase.clone().unwrap_or_default());
        }
        _ => return Err(ErrorCode::TargetAuthFailed),
    }
    // connect has one protocol-version element followed by exactly the daemon's args.
    let mut result = vec!["connect".into(), "VERSION_1_5_0".into()];
    result.extend(
        names
            .iter()
            .map(|name| values.remove(name.as_str()).unwrap_or_default()),
    );
    Ok(result)
}
pub(crate) async fn handshake(
    config: &GuacdConfig,
    target: &Target,
    connection: &Connection,
    backend: &dyn GatewayBackend,
    port: u16,
) -> Result<GuacdStream, ErrorCode> {
    let (mut stream, names) = select(config, target.protocol).await?;
    let display = connection.display;
    let width = display.width.to_string();
    let height = display.height.to_string();
    let dpi = display.dpi.to_string();
    stream.send(&["size", &width, &height, &dpi]).await?;
    stream.send(&["audio"]).await?;
    stream.send(&["video"]).await?;
    stream
        .send(&["image", "image/png", "image/jpeg", "image/webp"])
        .await?;
    runtime::authorize(backend, connection).await?; // Last policy check before decrypting/submitting credentials.
    let credential = match &target.auth {
        TargetAuth::None => Credential::None,
        TargetAuth::Encrypted {
            context,
            envelope,
            keys,
        } => keys
            .open(context, envelope)
            .map_err(|_| ErrorCode::TargetAuthFailed)?,
    };
    let args = zeroize::Zeroizing::new(parameters(
        config,
        target,
        display,
        port,
        &credential,
        &names,
    )?);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let bytes = zeroize::Zeroizing::new(guac_encode(&refs));
    stream
        .socket
        .write_all(&bytes)
        .await
        .map_err(|_| ErrorCode::TargetUnreachable)?;
    drop(bytes);
    drop(args);
    drop(credential);
    let ready = stream.instruction().await?;
    if ready.opcode() != "ready"
        || ready.args().len() != 1
        || !ready.args()[0].starts_with('$')
        || ready.args()[0].len() > 128
    {
        return Err(ErrorCode::TargetAuthFailed);
    }
    runtime::authorize(backend, connection).await?;
    Ok(stream)
}
pub(crate) struct TargetBridge {
    pub port: u16,
    pub ended: watch::Receiver<Option<ErrorCode>>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl TargetBridge {
    pub(crate) async fn start(
        config: &GuacdConfig,
        target: &Target,
        deadline: tokio::time::Instant,
        stop: &CancellationToken,
    ) -> Result<Self, ErrorCode> {
        config.validate()?;
        let approved = target.address.resolve().await?;
        if target.protocol == TargetProtocol::Vnc
            && !config
                .vnc_trusted_cidrs
                .iter()
                .any(|cidr| cidr.contains(&normalize_ip(approved.ip())))
        {
            return Err(ErrorCode::TargetAddressDenied);
        }
        let listener = TcpListener::bind(config.bridge_bind)
            .await
            .map_err(|_| ErrorCode::TargetUnreachable)?;
        let port = listener
            .local_addr()
            .map_err(|_| ErrorCode::TargetUnreachable)?
            .port();
        if !(32768..=60999).contains(&port) {
            return Err(ErrorCode::TargetProtocolUnavailable);
        }
        let source = config.allowed_source_ips.clone();
        let cancel = stop.child_token();
        let actor_cancel = cancel.clone();
        let (tx, ended) = watch::channel(None);
        let task = tokio::spawn(async move {
            let result = tokio::select! {_ = actor_cancel.cancelled()=>Ok(()),result=async{
             let (mut guacd,peer)=tokio::time::timeout_at(deadline,listener.accept()).await.map_err(|_|ErrorCode::TargetTimeout)?.map_err(|_|ErrorCode::TargetUnreachable)?;drop(listener);
             if !source.iter().any(|ip|normalize_ip(*ip)==normalize_ip(peer.ip())){return Err(ErrorCode::TargetAddressDenied);}
             let mut target=tokio::time::timeout_at(deadline,TcpStream::connect(approved)).await.map_err(|_|ErrorCode::TargetTimeout)?.map_err(|_|ErrorCode::TargetUnreachable)?;
             tokio::io::copy_bidirectional(&mut guacd,&mut target).await.map_err(|_|ErrorCode::TargetUnreachable)?;Ok(())
            }=>result};
            tx.send_replace(Some(result.err().unwrap_or(ErrorCode::TargetUnreachable)));
        });
        Ok(Self {
            port,
            ended,
            stop: cancel,
            task: Some(task),
        })
    }
    pub(crate) async fn close(&mut self) {
        self.stop.cancel();
        if let Some(mut task) = self.task.take() {
            if timeout(Duration::from_secs(2), &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}
impl Drop for TargetBridge {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> GuacdConfig {
        GuacdConfig {
            address: "10.1.0.2:4822".parse().unwrap(),
            bridge_bind: "10.1.0.1:0".parse().unwrap(),
            bridge_advertise_host: "10.1.0.1".into(),
            allowed_source_ips: vec!["10.1.0.2".parse().unwrap()],
            version: "1.6.0".into(),
            rdp_strict_pin_verified: false,
            vnc_trusted_cidrs: Vec::new(),
        }
    }
    #[test]
    fn stock_rdp_fingerprint_fallback_never_passes_gate() {
        let mut c = config();
        let names = [
            "hostname",
            "port",
            "username",
            "password",
            "domain",
            "security",
            "ignore-cert",
            "cert-tofu",
            "cert-fingerprints",
            "disable-copy",
            "disable-paste",
            "disable-audio",
            "enable-printing",
            "enable-drive",
            "recording-path",
            "zt-target-ready",
        ]
        .map(str::to_owned)
        .to_vec();
        assert!(check_arguments(&c, TargetProtocol::Rdp, &names).is_err());
        c.rdp_strict_pin_verified = true;
        assert!(check_arguments(&c, TargetProtocol::Rdp, &names).is_err());
        let mut patched = names;
        patched.push("zt-strict-cert-pin".into());
        assert!(check_arguments(&c, TargetProtocol::Rdp, &patched).is_ok());
    }
    #[test]
    fn bridge_known_hosts_line_and_no_secret_features() {
        let c = config();
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEaZRcgOCeoIDYMvGUeWswEFkatDd1DjeZvGTLXKtSCR";
        let target = Target {
            address: TargetEndpoint::Restricted {
                host: "example.org".into(),
                port: 22,
                policy: Arc::new(NetworkPolicy {
                    allow: Vec::new(),
                    deny: Vec::new(),
                }),
            },
            protocol: TargetProtocol::Ssh,
            security: None,
            ssh_host_key: Some(key.into()),
            rdp_certificate_sha256: None,
            username: Some("u".into()),
            domain: None,
            auth: TargetAuth::None,
        };
        let names = [
            "hostname",
            "port",
            "username",
            "password",
            "private-key",
            "passphrase",
            "host-key",
            "enable-sftp",
            "disable-copy",
            "disable-paste",
            "recording-path",
            "zt-target-ready",
            "zt-ssh-display-only",
        ]
        .map(str::to_owned);
        let previous_engine: Vec<_> = names
            .iter()
            .filter(|name| name.as_str() != "zt-ssh-display-only")
            .cloned()
            .collect();
        assert!(check_arguments(&c, TargetProtocol::Ssh, &previous_engine).is_err());
        let args = parameters(
            &c,
            &target,
            Display::default(),
            40000,
            &Credential::Password {
                password: "secret".into(),
            },
            &names,
        )
        .unwrap();
        let by_name: HashMap<_, _> = names.iter().zip(args[2..].iter()).collect();
        assert_eq!(
            by_name[&"host-key".to_owned()],
            &format!("[10.1.0.1]:40000 {key}")
        );
        assert_eq!(by_name[&"enable-sftp".to_owned()], "false");
        assert_eq!(by_name[&"disable-copy".to_owned()], "false");
        assert_eq!(by_name[&"disable-paste".to_owned()], "false");
        assert_eq!(by_name[&"recording-path".to_owned()], "");
        assert_eq!(by_name[&"zt-ssh-display-only".to_owned()], "true");
    }
}
