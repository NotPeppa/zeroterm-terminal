use super::*;
use super::{
    guacd::{handshake, GuacdStream, TargetBridge},
    policy::InstructionPolicy,
    recording::SessionRecording,
    runtime::authorize,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::{io::AsyncWriteExt, sync::mpsc, time::Instant};
#[allow(clippy::too_many_arguments)]
pub async fn run_web_session(
    connection: Connection,
    target: Target,
    backend: Arc<dyn GatewayBackend>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    stop: CancellationToken,
    config: GuacdConfig,
) -> Result<(), ErrorCode> {
    let registry = backend.registry();
    let limits = registry.limits().clone();
    let capacity = limits.queue_bytes / MAX_DATA_BYTES;
    let valid = if connection.state != ConnectionState::Connecting
        || connection.protocol_version != PROTOCOL_VERSION
        || connection.target_protocol != target.protocol
        || incoming.max_capacity() > capacity
        || outgoing.max_capacity() > capacity
    {
        Err(ErrorCode::InvalidArgument)
    } else {
        connection.display.validate().and_then(|_| {
            if target.protocol == TargetProtocol::Ssh {
                Ok(())
            } else {
                config.validate()
            }
        })
    };
    if let Err(code) = valid {
        let _ = timeout(
            Duration::from_secs(2),
            backend.transition(connection.id, ConnectionState::Failed, Some(code)),
        )
        .await;
        return Err(code);
    }
    let lease = match registry.reserve(&connection, stop.clone()) {
        Ok(lease) => lease,
        Err(code) => {
            let _ = timeout(
                Duration::from_secs(2),
                backend.transition(connection.id, ConnectionState::Failed, Some(code)),
            )
            .await;
            return Err(code);
        }
    };
    let started = Instant::now();
    let deadline = started + limits.startup_timeout;
    let recording = tokio::select! {_ = stop.cancelled()=>Err(ErrorCode::LoginSessionRevoked),result=tokio::time::timeout_at(deadline,SessionRecording::prepare(backend.clone(),&connection))=>result.unwrap_or(Err(ErrorCode::RecordingUnavailable))};
    let recording = match recording {
        Ok(recording) => recording,
        Err(code) => {
            let _ = timeout(
                Duration::from_secs(2),
                backend.transition(connection.id, ConnectionState::Failed, Some(code)),
            )
            .await;
            drop(lease);
            return Err(code);
        }
    };
    let session = async {
        if target.protocol == TargetProtocol::Ssh {
            return super::ssh::run(
                &connection,
                &target,
                backend.as_ref(),
                &recording,
                &mut incoming,
                &outgoing,
                &stop,
                &limits,
                started,
                deadline,
            )
            .await;
        }
        let startup = async {
            authorize(backend.as_ref(), &connection).await?;
            let mut bridge = TargetBridge::start(&config, &target, deadline, &stop).await?;
            let mut stream = tokio::select! {_ = bridge.ended.changed()=>return Err(bridge.ended.borrow().unwrap_or(ErrorCode::TargetUnreachable)),result=handshake(&config,&target,&connection,backend.as_ref(),bridge.port)=>result?};
            let mut policy = InstructionPolicy::for_protocol(target.protocol);
            let mut buffered = Vec::new();
            let mut buffered_bytes = 0;
            // Stock guacd emits ready and even terminal drawing before target authentication.
            // Only the patched engine's post-auth marker permits activation. Never forward it.
            loop {
                let instruction = tokio::select! {_ = bridge.ended.changed()=>return Err(bridge.ended.borrow().unwrap_or(ErrorCode::TargetUnreachable)),result=stream.instruction()=>result?};
                if policy.startup(&instruction)? {
                    break;
                }
                if instruction.opcode() == "disconnect" {
                    return Err(ErrorCode::TargetAuthFailed);
                }
                if buffered_bytes + instruction.bytes.len() > MAX_INSTRUCTION_BYTES {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                buffered_bytes += instruction.bytes.len();
                buffered.push((instruction.bytes.clone(), policy.recordable(&instruction)));
                if instruction.opcode() == "sync" {
                    policy.startup_sync(&instruction)?;
                    stream.send(&["sync", &instruction.args()[0]]).await?;
                }
            }
            authorize(backend.as_ref(), &connection).await?;
            recording.activate().await?;
            Ok::<_, ErrorCode>((stream, bridge, policy, buffered))
        };
        let closed = async {
            while !incoming.is_closed() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        };
        let (mut stream, mut bridge, mut policy, buffered) = tokio::select! {biased;_ = stop.cancelled()=>return Err(ErrorCode::LoginSessionRevoked),_ = closed=>return Err(ErrorCode::LoginSessionRevoked),result=tokio::time::timeout_at(deadline,startup)=>result.unwrap_or(Err(ErrorCode::TargetTimeout))?};
        let live_started = Instant::now();
        let forwarding = tokio::time::timeout_at(started + limits.max_duration, async {
            tokio::time::timeout_at(live_started + limits.idle_timeout, async {
                for (bytes, recordable) in &buffered {
                    output(
                        &recording,
                        &outgoing,
                        bytes,
                        &stop,
                        limits.stall_timeout,
                        *recordable,
                    )
                    .await?;
                }
                Ok::<(), ErrorCode>(())
            })
            .await
            .unwrap_or(Err(ErrorCode::TargetTimeout))?;
            pump(
                &connection,
                backend.as_ref(),
                &mut stream,
                &mut bridge,
                &mut policy,
                &recording,
                &mut incoming,
                &outgoing,
                &stop,
                &limits,
                live_started,
            )
            .await
        })
        .await
        .unwrap_or(Err(ErrorCode::TargetTimeout));
        bridge.close().await;
        forwarding
    };
    let result = tokio::select! {
        biased;
        _ = recording.closed() => Err(ErrorCode::RecordingUnavailable),
        result = session => result,
    };
    let clean = result.is_ok() && !stop.is_cancelled();
    let state = if clean {
        RecordingState::Complete
    } else {
        RecordingState::Partial
    };
    let finished = recording
        .finish(
            if clean { "closed" } else { "interrupted" },
            state,
            result.as_ref().err().copied(),
        )
        .await;
    let final_result = if finished.is_err() {
        Err(ErrorCode::RecordingUnavailable)
    } else {
        result
    };
    let next = if final_result.is_ok() {
        ConnectionState::Closing
    } else {
        ConnectionState::Failed
    };
    let _ = timeout(
        Duration::from_secs(2),
        backend.transition(connection.id, next, final_result.as_ref().err().copied()),
    )
    .await;
    if next == ConnectionState::Closing {
        let _ = timeout(
            Duration::from_secs(2),
            backend.transition(connection.id, ConnectionState::Closed, None),
        )
        .await;
    }
    drop(lease);
    final_result
}
pub(super) async fn output(
    recording: &SessionRecording,
    outgoing: &mpsc::Sender<Vec<u8>>,
    bytes: &[u8],
    stop: &CancellationToken,
    stall: Duration,
    recordable: bool,
) -> Result<(), ErrorCode> {
    for chunk in bytes.chunks(MAX_DATA_BYTES) {
        if recordable {
            tokio::select! {_ = stop.cancelled()=>return Err(ErrorCode::LoginSessionRevoked),result=recording.output(chunk)=>result?};
        }
        tokio::select! {_ = stop.cancelled()=>return Err(ErrorCode::LoginSessionRevoked),result=timeout(stall,outgoing.send(chunk.to_vec()))=>result.map_err(|_|ErrorCode::TargetTimeout)?.map_err(|_|ErrorCode::TargetUnreachable)?};
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn pump(
    connection: &Connection,
    backend: &dyn GatewayBackend,
    stream: &mut GuacdStream,
    bridge: &mut TargetBridge,
    policy: &mut InstructionPolicy,
    recording: &SessionRecording,
    incoming: &mut mpsc::Receiver<Vec<u8>>,
    outgoing: &mpsc::Sender<Vec<u8>>,
    stop: &CancellationToken,
    limits: &RuntimeLimits,
    active_since: Instant,
) -> Result<(), ErrorCode> {
    let mut client = GuacParser::new(MAX_INPUT_INSTRUCTION_BYTES);
    let mut last_input = active_since;
    let mut checks = tokio::time::interval(Duration::from_secs(1));
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
         biased;
         _ = stop.cancelled()=>return Err(ErrorCode::LoginSessionRevoked),

         _ = tokio::time::sleep_until(last_input+limits.idle_timeout)=>return Err(ErrorCode::TargetTimeout),
         _ = bridge.ended.changed()=>return Err(bridge.ended.borrow().unwrap_or(ErrorCode::TargetUnreachable)),
         _ = checks.tick()=>authorize(backend,connection).await?,
         chunk=incoming.recv()=>{
          let Some(chunk)=chunk else {client.finish()?;policy.finish()?;return Ok(());};if chunk.is_empty() || chunk.len()>MAX_DATA_BYTES {return Err(ErrorCode::InvalidArgument);}
          let instructions=client.push(&chunk)?;validate_disconnect(&client,&instructions)?;for instruction in instructions {
           let replayed=policy.replayed_sync(&instruction);let activity=policy.client(&instruction)?;authorize(backend,connection).await?;
           if instruction.opcode()=="disconnect" {policy.finish()?;return Ok(());}
            if replayed {continue;}
           // Buffer paste until end/UTF-8 validation; stock handlers do not ACK and SSH normalizes each blob.
           if matches!(instruction.opcode(),"clipboard"|"blob") {
            let ack=guac_encode(&["ack",&instruction.args()[0],"OK","0"]);
            tokio::select!{biased;_ = stop.cancelled()=>return Err(ErrorCode::LoginSessionRevoked),result=timeout(limits.stall_timeout,outgoing.send(ack))=>result.map_err(|_|ErrorCode::TargetTimeout)?.map_err(|_|ErrorCode::TargetUnreachable)?};
            if activity {last_input=Instant::now();}
            continue;
           }
           if instruction.opcode()=="end" {
            let (id,text)=policy.take_clipboard().ok_or(ErrorCode::TargetRequestRejected)?;
            tokio::select!{biased;_ = stop.cancelled()=>return Err(ErrorCode::LoginSessionRevoked),result=timeout(limits.stall_timeout,send_clipboard(stream,id,&text))=>result.map_err(|_|ErrorCode::TargetTimeout)??};
            continue;
           }
           tokio::select!{biased;_ = stop.cancelled()=>return Err(ErrorCode::LoginSessionRevoked),result=timeout(limits.stall_timeout,stream.socket.write_all(&instruction.bytes))=>result.map_err(|_|ErrorCode::TargetTimeout)?.map_err(|_|ErrorCode::TargetUnreachable)?};
           if activity {last_input=Instant::now();}
          }
         },
         instruction=stream.instruction()=>{
          let instruction=instruction?;policy.server(&instruction)?;let closed=instruction.opcode()=="disconnect";
          if instruction.opcode()=="ack" && instruction.args()[2]=="0" {continue;} // Avoid double-advancing gateway-paced paste.
          tokio::time::timeout_at(last_input+limits.idle_timeout,output(recording,outgoing,&instruction.bytes,stop,limits.stall_timeout,policy.recordable(&instruction))).await.unwrap_or(Err(ErrorCode::TargetTimeout))?;
          if closed {stream.parser.finish()?;if !stream.pending.is_empty(){return Err(ErrorCode::InvalidArgument);}policy.finish()?;return Ok(());}
         },
        }
    }
}
async fn send_clipboard(stream: &mut GuacdStream, id: u32, text: &[u8]) -> Result<(), ErrorCode> {
    let id = id.to_string();
    stream.send(&["clipboard", &id, "text/plain"]).await?;
    let mut offset = 0;
    while offset < text.len() {
        let end = clipboard_boundary(text, offset);
        let encoded = STANDARD.encode(&text[offset..end]);
        stream.send(&["blob", &id, &encoded]).await?;
        offset = end;
    }
    stream.send(&["end", &id]).await
}
fn clipboard_boundary(text: &[u8], offset: usize) -> usize {
    let mut end = (offset + 6048).min(text.len());
    while end < text.len() && text[end] & 0xc0 == 0x80 {
        end -= 1;
    }
    end
}
fn validate_disconnect(
    parser: &GuacParser,
    instructions: &[GuacInstruction],
) -> Result<(), ErrorCode> {
    if let Some(index) = instructions
        .iter()
        .position(|instruction| instruction.opcode() == "disconnect")
    {
        if index + 1 != instructions.len() {
            return Err(ErrorCode::InvalidArgument);
        }
        parser.finish()?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clipboard_chunks_never_split_a_unicode_scalar() {
        let text = "ab中😀\n".repeat(5000);
        let mut offset = 0;
        while offset < text.len() {
            let end = clipboard_boundary(text.as_bytes(), offset);
            assert!(end > offset && end - offset <= 6048);
            assert!(text.is_char_boundary(offset) && text.is_char_boundary(end));
            offset = end;
        }
    }
    #[tokio::test]
    async fn binary_queue_is_bounded_and_incremental() {
        let (tx, mut rx) = mpsc::channel(1);
        let bytes = guac_encode(&["name", "中😀"]);
        let mut parser = GuacParser::new(MAX_INSTRUCTION_BYTES);
        for byte in bytes {
            tx.send(vec![byte]).await.unwrap();
            let chunk = rx.recv().await.unwrap();
            parser.push(&chunk).unwrap();
        }
        parser.finish().unwrap();
        assert_eq!(tx.max_capacity(), 1);
    }
    #[test]
    fn disconnect_must_be_last_and_leave_no_fragment() {
        for bytes in [
            b"10.disconnect;4.sync,".as_slice(),
            b"10.disconnect;9.clipboard,1.0,10.text/plain;".as_slice(),
            b"10.disconnect;10.disconnect;".as_slice(),
        ] {
            let mut parser = GuacParser::new(MAX_INPUT_INSTRUCTION_BYTES);
            let instructions = parser.push(bytes).unwrap();
            assert!(validate_disconnect(&parser, &instructions).is_err());
        }
        let mut parser = GuacParser::new(MAX_INPUT_INSTRUCTION_BYTES);
        let instructions = parser.push(b"10.disconnect;").unwrap();
        validate_disconnect(&parser, &instructions).unwrap();
    }
}
