use super::*;
use bastion_domain::{
    ClientControl, ClientFrame, DataStream, ServerControl, ServerFrame, TicketTransport,
    MAX_DATA_BYTES, WEBSOCKET_VERSION,
};
use tokio::{sync::mpsc, time::Instant};

const POLICY_INTERVAL: Duration = Duration::from_secs(1);
const POLICY_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const POLICY_GRACE: Duration = Duration::from_secs(5);
const INPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_DURATION: Duration = Duration::from_secs(8 * 60 * 60);

/// M2 development data plane, NOT production ready: required recording is not implemented.
/// The API must enforce loopback-only entry, authenticated ticket consumption, and queues
/// of at most eight frames (each data payload at most 32 KiB). No extra application queue
/// is allocated here; russh's bounded queues and SSH windows remain separate limits.
/// Idle means 30 minutes without a successful target input/control write, acknowledged
/// PTY/shell startup, or output chunk admitted to the bounded API queue. Ping/keepalive
/// never refresh it. Sustained backpressure without successful forwarding expires idle;
/// target input writes separately time out after 30 seconds and terminate the session.
pub async fn run_web_session(
    connection: Connection,
    target: Target,
    backend: Arc<dyn GatewayBackend>,
    incoming: mpsc::Receiver<ClientFrame>,
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
    let mut handle = None;
    let mut active = false;
    let mut channel_id = None;
    let (activity, activity_rx) = watch::channel(Instant::now());
    let absolute_deadline = Instant::now() + MAX_DURATION;
    let result = {
        let session = async {
            timeout(TARGET_TIMEOUT, async {
                authorize(backend.as_ref(), &connection).await?;
                handle = Some(connect_target(&target).await?);
                authorize(backend.as_ref(), &connection).await?;
                backend
                    .transition(connection.id, ConnectionState::Active, None)
                    .await?;
                active = true;
                Ok::<_, ErrorCode>(())
            })
            .await
            .map_err(|_| ErrorCode::TargetTimeout)??;
            send(
                &outgoing,
                ServerControl::SessionReady {
                    v: WEBSOCKET_VERSION,
                    connection_id: connection.id,
                },
            )
            .await?;
            web_channel(
                handle.as_ref().unwrap(),
                backend.as_ref(),
                &connection,
                incoming,
                &outgoing,
                &mut channel_id,
                activity,
            )
            .await
        };
        let idle = idle_checks(activity_rx, IDLE_TIMEOUT);
        tokio::select! {
            biased;
            _ = stop.cancelled() => Ok(()),
            _ = outgoing.closed() => Ok(()),
            _ = tokio::time::sleep_until(absolute_deadline) => Err(ErrorCode::TargetTimeout),
            code = policy_checks(backend.as_ref(), &connection) => Err(code),
            _ = idle => Err(ErrorCode::TargetTimeout),
            result = session => result,
        }
    };
    // Always disconnect, including failed post-auth authorization and blocked writers.
    if let Some(handle) = handle {
        let _ = timeout(
            Duration::from_secs(2),
            handle.disconnect(Disconnect::ByApplication, "web session closed", "en"),
        )
        .await;
    }
    let failure = result.as_ref().err().copied();
    // Bound cleanup even if the database or browser is unavailable. Never reopen a terminal
    // state, and never pretend these transitions constitute output recording.
    let _ = timeout(Duration::from_secs(2), async {
        if !active && failure.is_some() {
            backend
                .transition(connection.id, ConnectionState::Failed, failure)
                .await
        } else {
            backend
                .transition(connection.id, ConnectionState::Closing, failure)
                .await?;
            backend
                .transition(connection.id, ConnectionState::Closed, failure)
                .await
        }
    })
    .await;
    let _ = timeout(Duration::from_secs(1), async {
        if let Some(code) = failure {
            send(
                &outgoing,
                ServerControl::Error {
                    v: WEBSOCKET_VERSION,
                    channel_id,
                    code,
                },
            )
            .await?;
        }
        if let Some(channel_id) = channel_id {
            send(
                &outgoing,
                ServerControl::Closed {
                    v: WEBSOCKET_VERSION,
                    channel_id,
                },
            )
            .await?;
        }
        Ok::<_, ErrorCode>(())
    })
    .await;
    result
}

async fn idle_checks(mut activity: watch::Receiver<Instant>, budget: Duration) {
    loop {
        let deadline = *activity.borrow_and_update() + budget;
        tokio::select! {
            biased;
            changed = activity.changed() => {
                if changed.is_err() { return; }
            }
            _ = tokio::time::sleep_until(deadline) => return,
        }
    }
}

async fn authorize(backend: &dyn GatewayBackend, connection: &Connection) -> Result<(), ErrorCode> {
    timeout(POLICY_QUERY_TIMEOUT, backend.authorize(connection))
        .await
        .unwrap_or(Err(ErrorCode::PolicyStoreUnavailable))
}

async fn policy_checks(backend: &dyn GatewayBackend, connection: &Connection) -> ErrorCode {
    let mut failure_since: Option<Instant> = None;
    let mut next = Instant::now() + POLICY_INTERVAL;
    loop {
        let grace_end = failure_since.map(|first| first + POLICY_GRACE);
        tokio::time::sleep_until(grace_end.map(|end| end.min(next)).unwrap_or(next)).await;
        if grace_end.is_some_and(|end| Instant::now() >= end) {
            return ErrorCode::PolicyStoreUnavailable;
        }
        let started = Instant::now();
        let budget = grace_end
            .map(|end| {
                end.saturating_duration_since(started)
                    .min(POLICY_QUERY_TIMEOUT)
            })
            .unwrap_or(POLICY_QUERY_TIMEOUT);
        match timeout(budget, backend.authorize(connection))
            .await
            .unwrap_or(Err(ErrorCode::PolicyStoreUnavailable))
        {
            Ok(()) => failure_since = None,
            Err(ErrorCode::PolicyStoreUnavailable) => {
                // Count a hung first query against the grace, not just retries.
                failure_since.get_or_insert(started);
            }
            Err(code) => return code,
        }
        next = started + POLICY_INTERVAL;
    }
}

#[derive(Clone, Copy, Default)]
struct WebState {
    id: Option<u32>,
    pty: bool,
    started: bool,
    eof: bool,
}

impl WebState {
    fn validate(&self, frame: &ClientFrame) -> Result<(), ErrorCode> {
        let id = match frame {
            ClientFrame::Control(control) => {
                control.validate()?;
                match control {
                    ClientControl::Ping { .. } => return Ok(()),
                    ClientControl::Open { channel_id, .. } if self.id.is_none() => {
                        return if *channel_id != 0 {
                            Ok(())
                        } else {
                            Err(ErrorCode::InvalidArgument)
                        };
                    }
                    ClientControl::Pty { channel_id, .. } if !self.pty && !self.started => {
                        *channel_id
                    }
                    ClientControl::Shell { channel_id, .. } if !self.started => *channel_id,
                    ClientControl::Resize { channel_id, .. } if self.pty && self.started => {
                        *channel_id
                    }
                    ClientControl::Eof { channel_id, .. } if self.started => *channel_id,
                    ClientControl::Close { channel_id, .. } => *channel_id,
                    _ => return Err(ErrorCode::InvalidArgument),
                }
            }
            ClientFrame::Data { channel_id, data }
                if self.started && !self.eof && data.len() <= MAX_DATA_BYTES =>
            {
                *channel_id
            }
            _ => return Err(ErrorCode::InvalidArgument),
        };
        if id != 0 && self.id == Some(id) {
            Ok(())
        } else {
            Err(ErrorCode::InvalidArgument)
        }
    }
}

async fn send(
    outgoing: &mpsc::Sender<ServerFrame>,
    control: ServerControl,
) -> Result<(), ErrorCode> {
    outgoing
        .send(ServerFrame::Control(control))
        .await
        .map_err(|_| ErrorCode::TargetUnreachable)
}

async fn web_channel(
    handle: &TargetHandle,
    backend: &dyn GatewayBackend,
    connection: &Connection,
    mut incoming: mpsc::Receiver<ClientFrame>,
    outgoing: &mpsc::Sender<ServerFrame>,
    channel_id: &mut Option<u32>,
    activity: watch::Sender<Instant>,
) -> Result<(), ErrorCode> {
    let mut state = WebState::default();
    let mut pending = PendingChannel(None);
    let mut deadline = Instant::now() + EMPTY_TIMEOUT;
    let mut configuring = false;
    loop {
        let Some(frame) = tokio::time::timeout_at(deadline, incoming.recv())
            .await
            .map_err(|_| ErrorCode::TargetTimeout)?
        else {
            return Ok(());
        };
        state.validate(&frame)?;
        if !configuring
            && matches!(
                frame,
                ClientFrame::Control(ClientControl::Pty { .. } | ClientControl::Shell { .. })
            )
        {
            configuring = true;
            deadline = Instant::now() + START_TIMEOUT;
        }
        // Neither ping nor repeated control frames extend either absolute deadline.
        let action = async {
            match frame {
                ClientFrame::Control(ClientControl::Ping { .. }) => {
                    send(
                        outgoing,
                        ServerControl::Pong {
                            v: WEBSOCKET_VERSION,
                        },
                    )
                    .await?;
                }
                ClientFrame::Control(ClientControl::Open { channel_id: id, .. }) => {
                    if !connection.capabilities.contains(&Capability::Shell) {
                        return Err(ErrorCode::ChannelPermissionDenied);
                    }
                    authorize(backend, connection).await?;
                    state.id = Some(id);
                    *channel_id = Some(id);
                    send(
                        outgoing,
                        ServerControl::Opened {
                            v: WEBSOCKET_VERSION,
                            channel_id: id,
                        },
                    )
                    .await?;
                }
                ClientFrame::Control(ClientControl::Pty {
                    term, cols, rows, ..
                }) => {
                    authorize(backend, connection).await?;
                    if pending.0.is_none() {
                        pending.0 = Some(
                            handle
                                .channel_open_session()
                                .await
                                .map_err(|_| ErrorCode::TargetUnreachable)?,
                        );
                    }
                    let channel = pending.0.as_mut().unwrap();
                    channel
                        .request_pty(true, &term, cols, rows, 0, 0, &[])
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    accepted(channel).await?;
                    activity.send_replace(Instant::now());
                    state.pty = true;
                    send(
                        outgoing,
                        ServerControl::PtyReady {
                            v: WEBSOCKET_VERSION,
                            channel_id: state.id.unwrap(),
                        },
                    )
                    .await?;
                }
                ClientFrame::Control(ClientControl::Shell { .. }) => {
                    authorize(backend, connection).await?;
                    backend
                        .channel_audit(connection, "shell", None, None)
                        .await?;
                    if pending.0.is_none() {
                        pending.0 = Some(
                            handle
                                .channel_open_session()
                                .await
                                .map_err(|_| ErrorCode::TargetUnreachable)?,
                        );
                    }
                    let channel = pending.0.as_mut().unwrap();
                    channel
                        .request_shell(true)
                        .await
                        .map_err(|_| ErrorCode::TargetUnreachable)?;
                    accepted(channel).await?;
                    activity.send_replace(Instant::now());
                    state.started = true;
                    send(
                        outgoing,
                        ServerControl::Ready {
                            v: WEBSOCKET_VERSION,
                            channel_id: state.id.unwrap(),
                        },
                    )
                    .await?;
                }
                ClientFrame::Control(ClientControl::Close { .. }) => return Ok(false),
                _ => return Err(ErrorCode::InvalidArgument),
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
        // Open only allocates browser state, never a target channel or program.
    }
    let channel = pending.0.take().unwrap();
    let (mut reader, writer) = channel.split();
    let writer = Arc::new(writer);
    let _cleanup = ActiveChannel(writer.clone());
    let input = web_input(incoming, writer, outgoing, state, activity.clone());
    let output = web_output(&mut reader, outgoing, state.id.unwrap(), activity);
    tokio::pin!(input, output);
    tokio::select! {
        result = &mut input => result,
        result = &mut output => result,
    }
}

async fn accepted(channel: &mut Channel<client::Msg>) -> Result<(), ErrorCode> {
    match timeout(START_TIMEOUT, request_result(channel)).await {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err(ErrorCode::TargetRequestRejected),
        Ok(Err(_)) => Err(ErrorCode::TargetUnreachable),
        Err(_) => Err(ErrorCode::TargetTimeout),
    }
}

fn input_is_business(frame: &ClientFrame) -> bool {
    match frame {
        ClientFrame::Data { data, .. } => !data.is_empty(),
        ClientFrame::Control(ClientControl::Resize { .. } | ClientControl::Eof { .. }) => true,
        _ => false,
    }
}

async fn write_target(
    write: impl std::future::Future<Output = Result<(), russh::Error>>,
    activity: &watch::Sender<Instant>,
    business: bool,
    budget: Duration,
) -> Result<(), ErrorCode> {
    timeout(budget, write)
        .await
        .map_err(|_| ErrorCode::TargetTimeout)?
        .map_err(|_| ErrorCode::TargetUnreachable)?;
    if business {
        activity.send_replace(Instant::now());
    }
    Ok(())
}

async fn web_input(
    mut incoming: mpsc::Receiver<ClientFrame>,
    writer: Arc<ChannelWriteHalf<client::Msg>>,
    outgoing: &mpsc::Sender<ServerFrame>,
    mut state: WebState,
    activity: watch::Sender<Instant>,
) -> Result<(), ErrorCode> {
    while let Some(frame) = incoming.recv().await {
        state.validate(&frame)?;
        let business = input_is_business(&frame);
        match frame {
            ClientFrame::Data { data, .. } => {
                write_target(
                    writer.data_bytes(data),
                    &activity,
                    business,
                    INPUT_WRITE_TIMEOUT,
                )
                .await?;
            }
            ClientFrame::Control(ClientControl::Resize { cols, rows, .. }) => {
                write_target(
                    writer.window_change(cols, rows, 0, 0),
                    &activity,
                    business,
                    INPUT_WRITE_TIMEOUT,
                )
                .await?;
            }
            ClientFrame::Control(ClientControl::Eof { .. }) if !state.eof => {
                state.eof = true;
                write_target(writer.eof(), &activity, business, INPUT_WRITE_TIMEOUT).await?;
            }
            ClientFrame::Control(ClientControl::Close { .. }) => return Ok(()),
            ClientFrame::Control(ClientControl::Ping { .. }) => {
                send(
                    outgoing,
                    ServerControl::Pong {
                        v: WEBSOCKET_VERSION,
                    },
                )
                .await?;
            }
            ClientFrame::Control(ClientControl::Eof { .. }) => {}
            _ => return Err(ErrorCode::InvalidArgument),
        }
        // EOF only closes target stdin. Keep waiting for close/resize while output drains.
        // A partial timed-out write ends the entire session; never continue a lossy shell.
    }
    Ok(())
}

async fn web_output(
    reader: &mut ChannelReadHalf,
    outgoing: &mpsc::Sender<ServerFrame>,
    channel_id: u32,
    activity: watch::Sender<Instant>,
) -> Result<(), ErrorCode> {
    while let Some(event) = reader.wait().await {
        if !forward_output(event, outgoing, channel_id, &activity).await? {
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
) -> Result<bool, ErrorCode> {
    match event {
        ChannelMsg::Data { data } => {
            send_data(outgoing, channel_id, DataStream::Output, &data, activity).await?
        }
        ChannelMsg::ExtendedData { data, ext: 1 } => {
            send_data(outgoing, channel_id, DataStream::Stderr, &data, activity).await?
        }
        ChannelMsg::ExitStatus { exit_status } => {
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
        ChannelMsg::Eof | ChannelMsg::WindowAdjusted { .. } => {}
        // The M2 protocol has no representation for non-stderr extended streams.
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
        outgoing
            .send(ServerFrame::Data {
                channel_id,
                stream,
                data: chunk.to_vec(),
            })
            .await
            .map_err(|_| ErrorCode::TargetUnreachable)?;
        activity.send_replace(Instant::now());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_wrong_channel_duplicate_start_and_input_after_eof() {
        let open = ClientFrame::Control(ClientControl::Open {
            v: WEBSOCKET_VERSION,
            channel_id: 7,
        });
        let mut state = WebState::default();
        assert!(state.validate(&open).is_ok());
        assert!(state
            .validate(&ClientFrame::Control(ClientControl::Open {
                v: WEBSOCKET_VERSION,
                channel_id: 0,
            }))
            .is_err());
        state.id = Some(7);
        assert!(state.validate(&open).is_err());
        let input = ClientFrame::Data {
            channel_id: 7,
            data: vec![0, 255],
        };
        assert!(state.validate(&input).is_err());
        state.started = true;
        assert!(state.validate(&input).is_ok());
        assert!(state
            .validate(&ClientFrame::Data {
                channel_id: 7,
                data: vec![0; MAX_DATA_BYTES + 1],
            })
            .is_err());
        let resize = ClientFrame::Control(ClientControl::Resize {
            v: WEBSOCKET_VERSION,
            channel_id: 7,
            cols: 80,
            rows: 24,
        });
        assert!(state.validate(&resize).is_err());
        state.pty = true;
        assert!(state.validate(&resize).is_ok());
        assert!(state
            .validate(&ClientFrame::Data {
                channel_id: 8,
                data: vec![1]
            })
            .is_err());
        assert!(state
            .validate(&ClientFrame::Control(ClientControl::Shell {
                v: WEBSOCKET_VERSION,
                channel_id: 7
            }))
            .is_err());
        state.eof = true;
        assert!(state.validate(&input).is_err());
        assert!(state
            .validate(&ClientFrame::Control(ClientControl::Close {
                v: WEBSOCKET_VERSION,
                channel_id: 7
            }))
            .is_ok());
    }

    #[tokio::test]
    async fn target_eof_keeps_output_and_exit_events_until_close() {
        let (tx, mut rx) = mpsc::channel(8);
        let (activity, _) = watch::channel(Instant::now());
        assert!(forward_output(ChannelMsg::Eof, &tx, 7, &activity)
            .await
            .unwrap());
        assert!(forward_output(
            ChannelMsg::Data {
                data: vec![0, 255, 0xe4].into()
            },
            &tx,
            7,
            &activity,
        )
        .await
        .unwrap());
        assert!(
            forward_output(ChannelMsg::ExitStatus { exit_status: 7 }, &tx, 7, &activity)
                .await
                .unwrap()
        );
        assert!(forward_output(
            ChannelMsg::ExitSignal {
                signal_name: russh::Sig::TERM,
                core_dumped: false,
                error_message: String::new(),
                lang_tag: String::new(),
            },
            &tx,
            7,
            &activity
        )
        .await
        .unwrap());
        assert!(!forward_output(ChannelMsg::Close, &tx, 7, &activity)
            .await
            .unwrap());
        assert_eq!(
            rx.recv().await.unwrap(),
            ServerFrame::Data {
                channel_id: 7,
                stream: DataStream::Output,
                data: vec![0, 255, 0xe4],
            }
        );
        assert_eq!(
            rx.recv().await.unwrap(),
            ServerFrame::Control(ServerControl::Exit {
                v: WEBSOCKET_VERSION,
                channel_id: 7,
                exit_code: Some(7),
                exit_signal: None,
            })
        );
        assert_eq!(
            rx.recv().await.unwrap(),
            ServerFrame::Control(ServerControl::Exit {
                v: WEBSOCKET_VERSION,
                channel_id: 7,
                exit_code: None,
                exit_signal: Some("TERM".into()),
            })
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn ping_does_not_extend_business_idle_but_successful_data_does() {
        let initial = Instant::now() - IDLE_TIMEOUT;
        let (activity, rx) = watch::channel(initial);
        let ping = ClientFrame::Control(ClientControl::Ping {
            v: WEBSOCKET_VERSION,
        });
        for _ in 0..10 {
            write_target(
                std::future::ready(Ok(())),
                &activity,
                input_is_business(&ping),
                INPUT_WRITE_TIMEOUT,
            )
            .await
            .unwrap();
        }
        assert_eq!(*activity.borrow(), initial);
        timeout(Duration::from_millis(100), idle_checks(rx, IDLE_TIMEOUT))
            .await
            .unwrap();

        let rx = activity.subscribe();
        let data = ClientFrame::Data {
            channel_id: 7,
            data: vec![0xff],
        };
        write_target(
            std::future::ready(Ok(())),
            &activity,
            input_is_business(&data),
            INPUT_WRITE_TIMEOUT,
        )
        .await
        .unwrap();
        assert!(*activity.borrow() > initial);
        assert!(
            timeout(Duration::from_millis(10), idle_checks(rx, IDLE_TIMEOUT))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn blocked_target_write_times_out_without_marking_activity() {
        let initial = Instant::now();
        let (activity, _) = watch::channel(initial);
        let result = write_target(
            std::future::pending::<Result<(), russh::Error>>(),
            &activity,
            true,
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(result, Err(ErrorCode::TargetTimeout));
        assert_eq!(*activity.borrow(), initial);
    }

    #[tokio::test]
    async fn output_chunks_preserve_arbitrary_bytes_and_apply_backpressure() {
        let data: Vec<u8> = (0..MAX_DATA_BYTES * 2 + 3).map(|i| i as u8).collect();
        let (tx, mut rx) = mpsc::channel(1);
        let (activity, _) = watch::channel(Instant::now());
        let output = send_data(&tx, 7, DataStream::Stderr, &data, &activity);
        tokio::pin!(output);
        // A single-slot queue cannot hold this three-frame output.
        assert!(timeout(Duration::from_millis(10), &mut output)
            .await
            .is_err());
        let drain = async {
            let mut result = Vec::new();
            while result.len() < data.len() {
                match rx.recv().await.unwrap() {
                    ServerFrame::Data {
                        channel_id,
                        stream: DataStream::Stderr,
                        data,
                    } => {
                        assert_eq!(channel_id, 7);
                        assert!(data.len() <= MAX_DATA_BYTES);
                        result.extend_from_slice(&data);
                    }
                    _ => panic!("unexpected output frame"),
                }
            }
            result
        };
        let (sent, received) = tokio::join!(output, drain);
        sent.unwrap();
        assert_eq!(received, data);
    }
}
