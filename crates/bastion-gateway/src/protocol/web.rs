use super::*;
use bastion_domain::{
    ChannelKind, ClientControl, ClientFrame, DataStream, ServerControl, ServerFrame,
    TicketTransport, MAX_DATA_BYTES, WEBSOCKET_VERSION,
};
use std::collections::HashSet;
use tokio::{sync::mpsc, time::Instant};

pub async fn run_web_session(
    connection: Connection,
    target: Target,
    backend: Arc<dyn GatewayBackend>,
    mut incoming: mpsc::Receiver<ClientFrame>,
    outgoing: mpsc::Sender<ServerFrame>,
    stop: CancellationToken,
) -> Result<(), ErrorCode> {
    if incoming.max_capacity() > 8
        || outgoing.max_capacity() > 8
        || connection.state != ConnectionState::Connecting
        || connection.transport != TicketTransport::Websocket
        || connection.protocol_version != u32::from(WEBSOCKET_VERSION)
    {
        return Err(ErrorCode::InvalidArgument);
    }
    let session =
        match ConnectionSession::connect(connection.clone(), target, backend.clone(), stop.clone())
            .await
        {
            Ok(session) => session,
            Err(code) => {
                let _ = backend
                    .transition(connection.id, ConnectionState::Failed, Some(code))
                    .await;
                return Err(code);
            }
        };
    send(
        &outgoing,
        ServerControl::SessionReady {
            v: WEBSOCKET_VERSION,
            connection_id: connection.id,
        },
    )
    .await?;
    let mut channels: HashMap<u32, WebChannel> = HashMap::new();
    let mut seen = HashSet::new();
    let mut tasks = JoinSet::new();
    let bytes = Arc::new(Semaphore::new(session.registry.limits().queue_bytes));
    let result=async {
        loop {
            let frame=tokio::select! {
                _=stop.cancelled()=>return Ok(()),
                _=session.stop.cancelled()=>return Ok(()),
                _=outgoing.closed()=>return Ok(()),
                done=tasks.join_next(),if !tasks.is_empty()=>{if let Some(Ok(id))=done{channels.remove(&id);}continue;},
                frame=incoming.recv()=>match frame {Some(frame)=>frame,None=>return Ok(())},
            };
            let id=frame_channel(&frame);
            let valid=match &frame {ClientFrame::Control(control)=>control.validate(),ClientFrame::Data{channel_id,data}=>if *channel_id==0 || data.len()>MAX_DATA_BYTES{Err(ErrorCode::InvalidArgument)}else{Ok(())}};
            if let Err(code)=valid {channel_error(&outgoing,id,code).await?;if let Some(id)=id{if let Some(channel)=channels.remove(&id){channel.stop.cancel();}}continue;}
            if matches!(frame,ClientFrame::Control(ClientControl::Ping{..})) {send(&outgoing,ServerControl::Pong{v:WEBSOCKET_VERSION}).await?;continue;}
            if let ClientFrame::Control(ClientControl::Open{channel_id,kind,..})=frame {
                if seen.contains(&channel_id) || seen.len()>=4096 {channel_error(&outgoing,Some(channel_id),ErrorCode::InvalidArgument).await?;continue;}
                seen.insert(channel_id);
                let capability=kind_capability(kind);
                if let Err(code)=session.check(capability).await {channel_error(&outgoing,Some(channel_id),code).await?;continue;}
                let permit=match session.registry.channel(connection.id) {Ok(permit)=>permit,Err(code)=>{channel_error(&outgoing,Some(channel_id),code).await?;continue;}};
                let (tx,rx)=mpsc::channel(8);let child=session.stop.child_token();
                channels.insert(channel_id,WebChannel{incoming:tx,stop:child.clone()});
                let session=session.clone();let outgoing=outgoing.clone();
                send(&outgoing,ServerControl::Opened{v:WEBSOCKET_VERSION,channel_id}).await?;
                tasks.spawn(async move {
                    let _permit=permit;
                    let result=tokio::select!{_=child.cancelled()=>Ok(()),result=web_channel(session,rx,&outgoing,channel_id,kind)=>result};
                    if let Err(code)=result {let _=channel_error(&outgoing,Some(channel_id),code).await;}
                    let _=send(&outgoing,ServerControl::Closed{v:WEBSOCKET_VERSION,channel_id}).await;
                    channel_id
                });
                continue;
            }
            let id=id.unwrap();
            let Some(channel)=channels.get(&id) else {channel_error(&outgoing,Some(id),ErrorCode::InvalidArgument).await?;continue;};
            if matches!(frame,ClientFrame::Control(ClientControl::Close{..})) {channel.stop.cancel();continue;}
            let size=match &frame {ClientFrame::Data{data,..}=>data.len(),ClientFrame::Control(ClientControl::ExecStart{command_base64,..})=>command_base64.len(),_=>256}.max(1);
            let permit=match bytes.clone().try_acquire_many_owned(size as u32) {Ok(permit)=>permit,Err(_)=>{channel.stop.cancel();channel_error(&outgoing,Some(id),ErrorCode::ConnectionLimit).await?;continue;}};
            // Never head-of-line block every channel on a single target's stalled input.
            if channel.incoming.try_send(QueuedFrame{frame,_bytes:permit}).is_err() {channel.stop.cancel();channel_error(&outgoing,Some(id),ErrorCode::TargetTimeout).await?;}
        }
    }.await;
    session.cancel();
    for channel in channels.values() {
        channel.stop.cancel();
    }
    let _ = timeout(Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    result
}
struct WebChannel {
    incoming: mpsc::Sender<QueuedFrame>,
    stop: CancellationToken,
}
struct QueuedFrame {
    frame: ClientFrame,
    _bytes: OwnedSemaphorePermit,
}
fn frame_channel(frame: &ClientFrame) -> Option<u32> {
    match frame {
        ClientFrame::Data { channel_id, .. } => Some(*channel_id),
        ClientFrame::Control(control) => match control {
            ClientControl::Ping { .. } => None,
            ClientControl::Open { channel_id, .. }
            | ClientControl::ExecStart { channel_id, .. }
            | ClientControl::SftpOpen { channel_id, .. }
            | ClientControl::Pty { channel_id, .. }
            | ClientControl::Shell { channel_id, .. }
            | ClientControl::Resize { channel_id, .. }
            | ClientControl::Eof { channel_id, .. }
            | ClientControl::Close { channel_id, .. } => Some(*channel_id),
        },
    }
}
fn kind_capability(kind: ChannelKind) -> Capability {
    match kind {
        ChannelKind::Shell => Capability::Shell,
        ChannelKind::Exec => Capability::Exec,
        ChannelKind::Sftp => Capability::Sftp,
    }
}
async fn channel_error(
    outgoing: &mpsc::Sender<ServerFrame>,
    channel_id: Option<u32>,
    code: ErrorCode,
) -> Result<(), ErrorCode> {
    send(
        outgoing,
        ServerControl::Error {
            v: WEBSOCKET_VERSION,
            channel_id,
            code,
        },
    )
    .await
}
async fn send(
    outgoing: &mpsc::Sender<ServerFrame>,
    control: ServerControl,
) -> Result<(), ErrorCode> {
    timeout(STALL_TIMEOUT, outgoing.send(ServerFrame::Control(control)))
        .await
        .map_err(|_| ErrorCode::TargetTimeout)?
        .map_err(|_| ErrorCode::TargetUnreachable)
}
#[derive(Clone, Copy)]
struct WebState {
    id: u32,
    kind: ChannelKind,
    pty: bool,
    started: bool,
    eof: bool,
}
impl WebState {
    fn validate(&self, frame: &ClientFrame) -> Result<(), ErrorCode> {
        if frame_channel(frame) != Some(self.id) {
            return Err(ErrorCode::InvalidArgument);
        }
        match frame {
            ClientFrame::Control(control) => {
                control.validate()?;
                match control {
                    ClientControl::Pty { .. }
                        if self.kind == ChannelKind::Shell && !self.pty && !self.started =>
                    {
                        Ok(())
                    }
                    ClientControl::Shell { .. }
                        if self.kind == ChannelKind::Shell && !self.started =>
                    {
                        Ok(())
                    }
                    ClientControl::ExecStart { .. }
                        if self.kind == ChannelKind::Exec && !self.started =>
                    {
                        Ok(())
                    }
                    ClientControl::SftpOpen { .. }
                        if self.kind == ChannelKind::Sftp && !self.started =>
                    {
                        Ok(())
                    }
                    ClientControl::Resize { .. }
                        if self.kind == ChannelKind::Shell && self.pty && self.started =>
                    {
                        Ok(())
                    }
                    ClientControl::Eof { .. } if self.started => Ok(()),
                    ClientControl::Close { .. } => Ok(()),
                    _ => Err(ErrorCode::InvalidArgument),
                }
            }
            ClientFrame::Data { data, .. }
                if self.started && !self.eof && data.len() <= MAX_DATA_BYTES =>
            {
                Ok(())
            }
            _ => Err(ErrorCode::InvalidArgument),
        }
    }
}
async fn web_channel(
    session: Arc<ConnectionSession>,
    mut incoming: mpsc::Receiver<QueuedFrame>,
    outgoing: &mpsc::Sender<ServerFrame>,
    id: u32,
    kind: ChannelKind,
) -> Result<(), ErrorCode> {
    let mut state = WebState {
        id,
        kind,
        pty: false,
        started: false,
        eof: false,
    };
    let mut pending = PendingChannel(None);
    let mut deadline = Instant::now() + EMPTY_TIMEOUT;
    let mut configuring = false;
    let mut recording = None;
    let mut lifecycle: Option<Arc<ChannelLifecycle>> = None;
    let mut term = "xterm".to_owned();
    let mut cols = 80;
    let mut rows = 24;
    loop {
        let Some(queued) = tokio::time::timeout_at(deadline, incoming.recv())
            .await
            .map_err(|_| ErrorCode::TargetTimeout)?
        else {
            return Ok(());
        };
        state.validate(&queued.frame)?;
        if !configuring {
            configuring = true;
            deadline = Instant::now() + START_TIMEOUT;
        }
        let action = async {
            session.check(kind_capability(kind)).await?;
            if pending.0.is_none() {
                pending.0 = Some(
                    session
                        .target
                        .channel_open_session()
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?,
                );
            }
            match queued.frame {
                ClientFrame::Control(ClientControl::Pty {
                    term: new_term,
                    cols: new_cols,
                    rows: new_rows,
                    ..
                }) => {
                    let channel = pending.0.as_mut().unwrap();
                    channel
                        .request_pty(true, &new_term, new_cols, new_rows, 0, 0, &[])
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    accepted(channel).await?;
                    term = new_term;
                    cols = new_cols;
                    rows = new_rows;
                    state.pty = true;
                    session.touch();
                    send(
                        outgoing,
                        ServerControl::PtyReady {
                            v: WEBSOCKET_VERSION,
                            channel_id: id,
                        },
                    )
                    .await?;
                }
                ClientFrame::Control(ClientControl::Shell { .. }) => {
                    if !(session.backend.recording_config().is_none()
                        && session.backend.allows_unrecorded_shell())
                    {
                        recording = Some(
                            ShellRecording::prepare(
                                session.backend.clone(),
                                &session.connection,
                                id,
                                &term,
                                cols,
                                rows,
                            )
                            .await?,
                        );
                    }
                    session.check(Capability::Shell).await?;
                    let channel = pending.0.as_mut().unwrap();
                    channel
                        .request_shell(true)
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    accepted(channel).await?;
                    if let Some(recording) = &recording {
                        recording.streaming().await?;
                    }
                    state.started = true;
                }
                ClientFrame::Control(ClientControl::ExecStart { command_base64, .. }) => {
                    let command = bastion_domain::decode_exec_command(&command_base64)?;
                    lifecycle = Some(ChannelLifecycle::begin(&session, id, kind).await?);
                    session
                        .backend
                        .channel_audit(
                            &session.connection,
                            "exec",
                            Some(format!("{:x}", Sha256::digest(&command))),
                            Some(command.len()),
                        )
                        .await?;
                    let channel = pending.0.as_mut().unwrap();
                    channel
                        .exec(true, command)
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    accepted(channel).await?;
                    state.started = true;
                }
                ClientFrame::Control(ClientControl::SftpOpen { .. }) => {
                    lifecycle = Some(ChannelLifecycle::begin(&session, id, kind).await?);
                    session
                        .backend
                        .channel_audit(&session.connection, "sftp", None, None)
                        .await?;
                    let channel = pending.0.as_mut().unwrap();
                    channel
                        .request_subsystem(true, "sftp")
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    accepted(channel).await?;
                    state.started = true;
                }
                ClientFrame::Control(ClientControl::Close { .. }) => return Ok(false),
                _ => return Err(ErrorCode::InvalidArgument),
            }
            if state.started {
                if let Some(lifecycle) = &lifecycle {
                    lifecycle.streaming().await?;
                }
                session.touch();
                send(
                    outgoing,
                    ServerControl::Ready {
                        v: WEBSOCKET_VERSION,
                        channel_id: id,
                    },
                )
                .await?;
            }
            Ok(true)
        };
        if !tokio::time::timeout_at(deadline, action)
            .await
            .map_err(|_| ErrorCode::TargetTimeout)??
        {
            return Ok(());
        }
        if state.started {
            break;
        }
    }
    let channel = pending.0.take().unwrap();
    let (mut reader, writer) = channel.split();
    let writer = Arc::new(writer);
    let _cleanup = ActiveChannel(writer.clone());
    let input = web_input(incoming, writer, state, session.clone(), recording.clone());
    let output = web_output(
        &mut reader,
        outgoing,
        id,
        session.activity.clone(),
        recording.clone(),
        lifecycle.clone(),
    );
    tokio::pin!(input, output);
    let result = tokio::select! {result=&mut input=>{
        result?; output.await
    },result=&mut output=>result};
    if let Some(lifecycle) = lifecycle {
        lifecycle.finish(result.as_ref().err().copied()).await?;
    }
    if let Some(recording) = recording {
        recording
            .finish(
                if result.is_ok() {
                    "channel_closed"
                } else {
                    "channel_failed"
                },
                if result.is_ok() {
                    bastion_domain::RecordingState::Complete
                } else {
                    bastion_domain::RecordingState::Partial
                },
                result.as_ref().err().copied(),
            )
            .await?;
    }
    result
}
pub(super) async fn accepted(channel: &mut Channel<client::Msg>) -> Result<(), ErrorCode> {
    match timeout(START_TIMEOUT, request_result(channel)).await {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err(ErrorCode::TargetRequestRejected),
        Ok(Err(_)) => Err(ErrorCode::TargetUnreachable),
        Err(_) => Err(ErrorCode::TargetTimeout),
    }
}
async fn web_input(
    mut incoming: mpsc::Receiver<QueuedFrame>,
    writer: Arc<ChannelWriteHalf<client::Msg>>,
    mut state: WebState,
    session: Arc<ConnectionSession>,
    recording: Option<ShellRecording>,
) -> Result<(), ErrorCode> {
    while let Some(queued) = incoming.recv().await {
        state.validate(&queued.frame)?;
        let operation = async {
            match queued.frame {
                ClientFrame::Data { data, .. } => {
                    let business = !data.is_empty();
                    writer
                        .data_bytes(data)
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    if business {
                        session.touch();
                    }
                }
                ClientFrame::Control(ClientControl::Resize { cols, rows, .. }) => {
                    if let Some(recording) = &recording {
                        recording.resize(cols, rows).await?;
                    }
                    writer
                        .window_change(cols, rows, 0, 0)
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    session.touch();
                }
                ClientFrame::Control(ClientControl::Eof { .. }) if !state.eof => {
                    state.eof = true;
                    writer
                        .eof()
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    session.touch();
                }
                ClientFrame::Control(ClientControl::Eof { .. }) => {}
                ClientFrame::Control(ClientControl::Close { .. }) => return Ok(false),
                _ => return Err(ErrorCode::InvalidArgument),
            }
            Ok(true)
        };
        if !timeout(session.registry.limits().stall_timeout, operation)
            .await
            .map_err(|_| ErrorCode::TargetTimeout)??
        {
            return Ok(());
        }
    }
    Ok(())
}
async fn web_output(
    reader: &mut ChannelReadHalf,
    outgoing: &mpsc::Sender<ServerFrame>,
    id: u32,
    activity: watch::Sender<Instant>,
    recording: Option<ShellRecording>,
    lifecycle: Option<Arc<ChannelLifecycle>>,
) -> Result<(), ErrorCode> {
    while let Some(event) = reader.wait().await {
        if let Some(lifecycle) = &lifecycle {
            match &event {
                ChannelMsg::ExitStatus { exit_status } => lifecycle.exit(Some(*exit_status), None),
                ChannelMsg::ExitSignal { signal_name, .. } => lifecycle.exit(
                    None,
                    Some(match signal_name {
                        russh::Sig::Custom(name) => name.clone(),
                        known => format!("{known:?}"),
                    }),
                ),
                _ => {}
            }
        }
        if !forward_output(event, outgoing, id, &activity, recording.as_ref()).await? {
            return Ok(());
        }
    }
    Ok(())
}
async fn forward_output(
    event: ChannelMsg,
    outgoing: &mpsc::Sender<ServerFrame>,
    channel_id: u32,
    activity: &watch::Sender<Instant>,
    recording: Option<&ShellRecording>,
) -> Result<bool, ErrorCode> {
    match event {
        ChannelMsg::Data { data } => {
            if let Some(recording) = recording {
                recording.output(false, &data).await?;
            }
            send_data(outgoing, channel_id, DataStream::Output, &data, activity).await?;
        }
        ChannelMsg::ExtendedData { data, ext: 1 } => {
            if let Some(recording) = recording {
                recording.output(true, &data).await?;
            }
            send_data(outgoing, channel_id, DataStream::Stderr, &data, activity).await?;
        }
        ChannelMsg::ExitStatus { exit_status } => {
            if let Some(recording) = recording {
                recording.exit(Some(exit_status), None).await?;
            }
            send(
                outgoing,
                ServerControl::Exit {
                    v: WEBSOCKET_VERSION,
                    channel_id,
                    exit_code: Some(exit_status),
                    exit_signal: None,
                },
            )
            .await?;
        }
        ChannelMsg::ExitSignal { signal_name, .. } => {
            let name = match signal_name {
                russh::Sig::Custom(name) => name,
                known => format!("{known:?}"),
            };
            if name.len() > 128 || name.chars().any(char::is_control) {
                return Err(ErrorCode::InvalidArgument);
            }
            if let Some(recording) = recording {
                recording.exit(None, Some(name.clone())).await?;
            }
            send(
                outgoing,
                ServerControl::Exit {
                    v: WEBSOCKET_VERSION,
                    channel_id,
                    exit_code: None,
                    exit_signal: Some(name),
                },
            )
            .await?;
        }
        ChannelMsg::Close => return Ok(false),
        ChannelMsg::ExtendedData { .. } => return Err(ErrorCode::InvalidArgument),
        _ => {}
    }
    Ok(true)
}
async fn send_data(
    outgoing: &mpsc::Sender<ServerFrame>,
    channel_id: u32,
    stream: DataStream,
    data: &[u8],
    activity: &watch::Sender<Instant>,
) -> Result<(), ErrorCode> {
    for chunk in data.chunks(MAX_DATA_BYTES) {
        timeout(
            STALL_TIMEOUT,
            outgoing.send(ServerFrame::Data {
                channel_id,
                stream,
                data: chunk.to_vec(),
            }),
        )
        .await
        .map_err(|_| ErrorCode::TargetTimeout)?
        .map_err(|_| ErrorCode::TargetUnreachable)?;
        activity.send_replace(Instant::now());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn channels_validate_independently_and_kind_specific_start() {
        let mut state = WebState {
            id: 7,
            kind: ChannelKind::Exec,
            pty: false,
            started: false,
            eof: false,
        };
        assert!(state
            .validate(&ClientFrame::Control(ClientControl::Shell {
                v: 1,
                channel_id: 7
            }))
            .is_err());
        assert!(state
            .validate(&ClientFrame::Control(ClientControl::ExecStart {
                v: 1,
                channel_id: 7,
                command_base64: "/w==".into()
            }))
            .is_ok());
        state.started = true;
        assert!(state
            .validate(&ClientFrame::Data {
                channel_id: 7,
                data: vec![255]
            })
            .is_ok());
        assert!(state
            .validate(&ClientFrame::Data {
                channel_id: 8,
                data: vec![255]
            })
            .is_err());
        state.eof = true;
        assert!(state
            .validate(&ClientFrame::Data {
                channel_id: 7,
                data: vec![255]
            })
            .is_err());
    }
    #[tokio::test]
    async fn target_eof_does_not_hide_exit_and_arbitrary_output() {
        let (tx, mut rx) = mpsc::channel(8);
        let (activity, _) = watch::channel(Instant::now());
        assert!(forward_output(ChannelMsg::Eof, &tx, 7, &activity, None)
            .await
            .unwrap());
        forward_output(
            ChannelMsg::Data {
                data: vec![0, 255].into(),
            },
            &tx,
            7,
            &activity,
            None,
        )
        .await
        .unwrap();
        forward_output(
            ChannelMsg::ExitStatus { exit_status: 7 },
            &tx,
            7,
            &activity,
            None,
        )
        .await
        .unwrap();
        assert!(!forward_output(ChannelMsg::Close, &tx, 7, &activity, None)
            .await
            .unwrap());
        assert_eq!(
            rx.recv().await.unwrap(),
            ServerFrame::Data {
                channel_id: 7,
                stream: DataStream::Output,
                data: vec![0, 255]
            }
        );
        assert_eq!(
            rx.recv().await.unwrap(),
            ServerFrame::Control(ServerControl::Exit {
                v: 1,
                channel_id: 7,
                exit_code: Some(7),
                exit_signal: None
            })
        );
    }
    #[tokio::test]
    async fn output_is_chunked_and_backpressured() {
        let data = vec![255; MAX_DATA_BYTES * 2 + 1];
        let (tx, mut rx) = mpsc::channel(1);
        let (activity, _) = watch::channel(Instant::now());
        let output = send_data(&tx, 7, DataStream::Stderr, &data, &activity);
        tokio::pin!(output);
        assert!(timeout(Duration::from_millis(10), &mut output)
            .await
            .is_err());
        let drain = async {
            let mut n = 0;
            while n < data.len() {
                if let ServerFrame::Data { data, .. } = rx.recv().await.unwrap() {
                    assert!(data.len() <= MAX_DATA_BYTES);
                    n += data.len();
                }
            }
            n
        };
        let (sent, n) = tokio::join!(output, drain);
        sent.unwrap();
        assert_eq!(n, data.len());
    }
}
