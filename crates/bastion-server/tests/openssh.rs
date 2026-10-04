//! Opt-in tests launched by tests/openssh_smoke.py with a real OpenSSH target.
#![cfg(feature = "dev-prototype")]
use anyhow::{Context, Result};
use bastion_secrets::read_secret_file;
use russh::{client, Channel, ChannelMsg};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

#[derive(Deserialize)]
struct Fixture {
    api: String,
    ssh_port: u16,
    api_token_file: PathBuf,
    gateway_public_key_file: PathBuf,
    asset_id: String,
    account_id: String,
    scratch: PathBuf,
}
impl Fixture {
    fn load() -> Result<Self> {
        let path =
            std::env::var("BASTION_TEST_FIXTURE").context("run python3 tests/openssh_smoke.py")?;
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
    async fn connect(&self, capabilities: &[&str]) -> Result<client::Handle<TrustedGateway>> {
        let bearer = read_secret_file(&self.api_token_file)?;
        let http = reqwest::Client::builder().no_proxy().build()?;
        let response: Value = http.post(format!("{}/api/v1/connection-tickets",self.api))
            .bearer_auth(bearer.expose()).json(&json!({"asset_id":self.asset_id,"account_id":self.account_id,"capabilities":capabilities,"purpose":"terminal"}))
            .send().await?.error_for_status()?.json().await?;
        let expected = russh::keys::PublicKey::from_openssh(&std::fs::read_to_string(
            &self.gateway_public_key_file,
        )?)?;
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(20)),
            ..Default::default()
        };
        let mut handle = client::connect(
            Arc::new(config),
            ("127.0.0.1", self.ssh_port),
            TrustedGateway(expected),
        )
        .await?;
        assert!(handle
            .authenticate_password(
                response["gateway"]["username"].as_str().unwrap(),
                response["ticket_secret"].as_str().unwrap()
            )
            .await?
            .success());
        Ok(handle)
    }
}
struct TrustedGateway(russh::keys::PublicKey);
impl client::Handler for TrustedGateway {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(key.key_data() == self.0.key_data())
    }
}

async fn collect(
    mut channel: Channel<client::Msg>,
) -> Result<(Vec<u8>, Vec<u8>, Option<u32>, usize, usize)> {
    timeout(Duration::from_secs(15), async {
        let (mut stdout, mut stderr, mut code, mut success, mut failure) =
            (Vec::new(), Vec::new(), None, 0, 0);
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend(data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend(data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                ChannelMsg::Success => success += 1,
                ChannelMsg::Failure => failure += 1,
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok((stdout, stderr, code, success, failure))
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the real OpenSSH fixture from tests/openssh_smoke.py"]
async fn real_openssh_multichannel_and_request_semantics() -> Result<()> {
    let fixture = Fixture::load()?;
    let session = fixture.connect(&["shell", "exec", "sftp"]).await?;

    // The fixture sets target MaxSessions=2. Sixteen allocated channels must not
    // consume target sessions, and rejecting #17 must not break the connection.
    let mut empty = Vec::new();
    for _ in 0..16 {
        empty.push(session.channel_open_session().await?);
    }
    assert!(session.channel_open_session().await.is_err());
    for channel in empty {
        channel.close().await?;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A slow command and a fast command are independent channels.
    let slow = session.channel_open_session().await?;
    slow.exec(true, b"sleep 1; printf slow".to_vec()).await?;
    let fast = session.channel_open_session().await?;
    fast.exec(true, b"printf fast; printf err >&2; exit 7".to_vec())
        .await?;
    let (out, err, code, success, failure) =
        timeout(Duration::from_millis(900), collect(fast)).await??;
    assert_eq!(out, b"fast");
    assert_eq!(err, b"err");
    assert_eq!(code, Some(7));
    assert_eq!((success, failure), (1, 0));
    assert_eq!(collect(slow).await?.0, b"slow");

    // Preserve stdin EOF while draining output emitted after EOF.
    let channel = session.channel_open_session().await?;
    channel
        .exec(true, b"cat; printf after-eof; exit 3".to_vec())
        .await?;
    channel.data(&b"raw\0bytes\xff"[..]).await?;
    channel.eof().await?;
    let result = collect(channel).await?;
    assert_eq!(result.0, b"raw\0bytes\xffafter-eof");
    assert_eq!(result.2, Some(3));

    // A no-reply env request must not steal or add a response to the exec.
    let channel = session.channel_open_session().await?;
    channel.set_env(false, "LANG", "C").await?;
    channel.exec(true, b"printf pipeline".to_vec()).await?;
    let result = collect(channel).await?;
    assert_eq!(result.0, b"pipeline");
    assert_eq!((result.3, result.4), (1, 0));
    // Reverse pipeline: a following no-reply exec cannot suppress env's reply.
    let channel = session.channel_open_session().await?;
    channel.set_env(true, "LANG", "C").await?;
    channel.exec(false, b"printf reverse".to_vec()).await?;
    let result = collect(channel).await?;
    assert_eq!(result.0, b"reverse");
    assert_eq!((result.3, result.4), (1, 0));

    let channel = session.channel_open_session().await?;
    channel.exec(false, b"printf no-reply".to_vec()).await?;
    let result = collect(channel).await?;
    assert_eq!(result.0, b"no-reply");
    assert_eq!((result.3, result.4), (0, 0));

    // Only the first successfully started process is allowed on each channel.
    let channel = session.channel_open_session().await?;
    channel
        .exec(true, b"sleep 0.3; printf first".to_vec())
        .await?;
    channel.exec(true, b"printf second".to_vec()).await?;
    let result = collect(channel).await?;
    assert_eq!(result.0, b"first");
    assert_eq!((result.3, result.4), (1, 1));

    // PTY modes, shell startup and resizing are forwarded to OpenSSH.
    let mut shell = session.channel_open_session().await?;
    shell
        .request_pty(
            true,
            "xterm-256color",
            80,
            24,
            0,
            0,
            &[(russh::Pty::ECHO, 0)],
        )
        .await?;
    assert!(matches!(
        timeout(Duration::from_secs(10), shell.wait()).await?,
        Some(ChannelMsg::Success)
    ));
    shell.request_shell(true).await?;
    assert!(matches!(
        timeout(Duration::from_secs(10), shell.wait()).await?,
        Some(ChannelMsg::Success)
    ));
    shell.window_change(100, 40, 0, 0).await?;
    shell
        .data(&b"stty size; printf '\\nSHELL-MARKER\\n'; exit\n"[..])
        .await?;
    let result = collect(shell).await?;
    assert!(String::from_utf8_lossy(&result.0).contains("40 100"));
    assert!(String::from_utf8_lossy(&result.0).contains("SHELL-MARKER"));

    // SFTP data is raw, including zero and non-UTF-8 bytes.
    let mut channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    assert!(matches!(
        timeout(Duration::from_secs(10), channel.wait()).await?,
        Some(ChannelMsg::Success)
    ));
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await?;
    let path = fixture
        .scratch
        .join("rust-sftp.bin")
        .to_string_lossy()
        .into_owned();
    let bytes: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let mut file = sftp.create(&path).await?;
    file.write_all(&bytes).await?;
    file.shutdown().await?;
    let mut file = sftp.open(&path).await?;
    let mut received = Vec::new();
    file.read_to_end(&mut received).await?;
    assert_eq!(received, bytes);
    sftp.remove_file(&path).await?;
    sftp.close().await?;

    let restricted = fixture.connect(&["sftp"]).await?;
    for kind in ["shell", "exec", "subsystem"] {
        let mut channel = restricted.channel_open_session().await?;
        match kind {
            "shell" => channel.request_shell(true).await?,
            "exec" => channel.exec(true, b"printf forbidden".to_vec()).await?,
            _ => channel.request_subsystem(true, "other").await?,
        }
        assert!(matches!(
            timeout(Duration::from_secs(5), channel.wait()).await?,
            Some(ChannelMsg::Failure)
        ));
        channel.close().await?;
    }
    assert!(restricted
        .channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 1000)
        .await
        .is_err());
    assert!(restricted.tcpip_forward("127.0.0.1", 0).await.is_err());
    restricted
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await?;
    session
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await?;
    Ok(())
}
