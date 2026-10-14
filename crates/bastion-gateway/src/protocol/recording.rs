use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use bastion_domain::{RecordingCreate, RecordingState};
use bastion_secrets::recording::{RecordingContext, RecordingHeader, RecordingWriter};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};
use tokio::sync::{mpsc, oneshot, Mutex};

const ACK_TIMEOUT: Duration = Duration::from_secs(5);
#[derive(Clone)]
pub struct RecordingConfig {
    pub server_id: String,
    pub directory: PathBuf,
    pub keys: Arc<KeyRing>,
    pub retention: Duration,
    pub min_free_bytes: u64,
}

/// One connection's concrete bounded sequencer. Each method returns only after the
/// encrypted bytes have been written and flushed; callers must ACK before output.
#[derive(Clone)]
pub struct SessionRecording {
    inner: Arc<RecorderSender>,
}
struct RecorderSender {
    tx: mpsc::Sender<RecordRequest>,
    sequence: Mutex<()>,
    bytes: Arc<Semaphore>,
    recording_id: Uuid,
    connection: Connection,
    backend: Arc<dyn GatewayBackend>,
}
struct RecordRequest {
    event: serde_json::Value,
    finish: Option<(RecordingState, Option<ErrorCode>)>,
    ack: oneshot::Sender<Result<(), ErrorCode>>,
    _bytes: OwnedSemaphorePermit,
}
impl SessionRecording {
    pub(crate) async fn prepare(
        backend: Arc<dyn GatewayBackend>,
        connection: &Connection,
    ) -> Result<Self, ErrorCode> {
        let config = backend
            .recording_config()
            .ok_or(ErrorCode::RecordingUnavailable)?;
        let writer_slot = backend.registry().recording_slot()?;
        let id = Uuid::new_v4();
        let mut header = RecordingHeader::new(id, connection.id, connection.target_protocol);
        header.stream_protocol = connection.target_protocol.stream_protocol().into();
        let (key, envelope) = config
            .keys
            .new_recording_dek(&RecordingContext::new(
                &config.server_id,
                id,
                connection.id,
                connection.target_protocol,
            ))
            .map_err(|_| ErrorCode::RecordingUnavailable)?;
        let relative_path = format!("{id}.ztrec");
        let recording = RecordingCreate {
            id,
            relative_path: relative_path.clone(),
            format_version: 2,
            retention_until: chrono::Utc::now()
                + chrono::Duration::from_std(config.retention)
                    .map_err(|_| ErrorCode::InvalidArgument)?,
            wrapped_dek: envelope.wrapped_dek,
            wrap_nonce: envelope.wrap_nonce,
            key_version: envelope.key_version,
            nonce_prefix: header.nonce_prefix.to_vec(),
        };
        timeout(ACK_TIMEOUT, backend.begin_recording(connection, recording))
            .await
            .map_err(|_| ErrorCode::RecordingUnavailable)??;
        let (ready, receiver) = oneshot::channel();
        let actor_backend = backend.clone();
        let connection_id = connection.id;
        let target_protocol = connection.target_protocol;
        let display = connection.display;
        let connection = connection.clone();
        backend.registry().track(tokio::spawn(async move {
            let directory = config.directory.clone();
            let minimum_free = config.min_free_bytes;
            let created = settle_io(tokio::task::spawn_blocking(move || {
                let file = create_recording_file(&directory, &relative_path, minimum_free)?;
                let mut writer = RecordingWriter::new(
                    HashedFile {
                        file,
                        hash: Sha256::new(),
                        _slot: writer_slot,
                    },
                    header,
                    key,
                )
                .map_err(|_| ErrorCode::RecordingUnavailable)?;
                writer
                    .writer_mut()
                    .file
                    .sync_all()
                    .map_err(|_| ErrorCode::RecordingUnavailable)?;
                Ok::<_, ErrorCode>(writer)
            }))
            .await;
            let writer = match created {
                Ok(Ok(Ok(writer))) => writer,
                _ => {
                    let _ = ready.send(Err(ErrorCode::RecordingUnavailable));
                    let _ = timeout(
                        ACK_TIMEOUT,
                        actor_backend.finish_recording(
                            id,
                            RecordingState::Failed,
                            0,
                            None,
                            Some(ErrorCode::RecordingUnavailable),
                        ),
                    )
                    .await;
                    return;
                }
            };
            if ready.is_closed() {
                let _ = timeout(
                    ACK_TIMEOUT,
                    actor_backend.finish_recording(
                        id,
                        RecordingState::Failed,
                        writer.bytes_written() as i64,
                        None,
                        Some(ErrorCode::RecordingUnavailable),
                    ),
                )
                .await;
                return;
            }
            let (tx, rx) = mpsc::channel(8);
            let result = Self {
                inner: Arc::new(RecorderSender {
                    tx,
                    sequence: Mutex::new(()),
                    bytes: Arc::new(Semaphore::new(256 * 1024)),
                    recording_id: id,
                    connection: connection.clone(),
                    backend: actor_backend.clone(),
                }),
            };
            if ready.send(Ok(result)).is_err() {
                let _ = timeout(
                    ACK_TIMEOUT,
                    actor_backend.finish_recording(
                        id,
                        RecordingState::Failed,
                        writer.bytes_written() as i64,
                        None,
                        Some(ErrorCode::RecordingUnavailable),
                    ),
                )
                .await;
                return;
            }
            recorder_loop(writer, rx, actor_backend, config, id).await;
        }));
        let result = timeout(ACK_TIMEOUT, receiver)
            .await
            .map_err(|_| ErrorCode::RecordingUnavailable)?
            .map_err(|_| ErrorCode::RecordingUnavailable)??;
        result.event(serde_json::json!({"type":"meta","format_version":2,"connection_id":connection_id,"target_protocol":target_protocol,"stream_protocol":target_protocol.stream_protocol(),"width":display.width,"height":display.height,"dpi":display.dpi}), None).await?;
        Ok(result)
    }
    pub(crate) async fn activate(&self) -> Result<(), ErrorCode> {
        timeout(
            Duration::from_secs(2),
            self.inner
                .backend
                .activate_recording(&self.inner.connection, self.inner.recording_id),
        )
        .await
        .unwrap_or(Err(ErrorCode::RecordingUnavailable))
    }
    async fn event(
        &self,
        event: serde_json::Value,
        finish: Option<(RecordingState, Option<ErrorCode>)>,
    ) -> Result<(), ErrorCode> {
        let operation = async {
            let _sequence = self.inner.sequence.lock().await;
            let size = serde_json::to_vec(&event)
                .map_err(|_| ErrorCode::RecordingUnavailable)?
                .len()
                + 128;
            if size > 64 * 1024 {
                return Err(ErrorCode::RecordingUnavailable);
            }
            let bytes = self
                .inner
                .bytes
                .clone()
                .acquire_many_owned(size as u32)
                .await
                .map_err(|_| ErrorCode::RecordingUnavailable)?;
            let (ack, rx) = oneshot::channel();
            self.inner
                .tx
                .send(RecordRequest {
                    event,
                    finish,
                    ack,
                    _bytes: bytes,
                })
                .await
                .map_err(|_| ErrorCode::RecordingUnavailable)?;
            rx.await.map_err(|_| ErrorCode::RecordingUnavailable)?
        };
        timeout(ACK_TIMEOUT, operation)
            .await
            .unwrap_or(Err(ErrorCode::RecordingUnavailable))
    }
    pub(crate) async fn output(&self, bytes: &[u8]) -> Result<(), ErrorCode> {
        for chunk in bytes.chunks(32 * 1024) {
            if chunk.is_empty() {
                continue;
            }
            self.event(
                serde_json::json!({"type":"output","data_base64":STANDARD.encode(chunk)}),
                None,
            )
            .await?;
        }
        Ok(())
    }
    pub(crate) async fn closed(&self) {
        self.inner.tx.closed().await;
    }
    pub(crate) async fn finish(
        &self,
        reason: &str,
        state: RecordingState,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        self.event(
            serde_json::json!({"type":"end","reason":reason}),
            Some((state, failure)),
        )
        .await
    }
}
struct HashedFile {
    file: File,
    hash: Sha256,
    // Held by the actual file owner, including any uncancellable blocking fsync.
    _slot: OwnedSemaphorePermit,
}
impl Write for HashedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.file.write(bytes)?;
        self.hash.update(&bytes[..written]);
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
async fn settle_io<T>(mut task: JoinHandle<T>) -> Result<Result<T, tokio::task::JoinError>, ()> {
    match timeout(ACK_TIMEOUT, &mut task).await {
        Ok(result) => Ok(result),
        Err(_) => {
            tracing::error!(
                "recording IO exceeded ACK deadline; waiting for IO before metadata seal"
            );
            Ok(task.await)
        }
    }
}
const CHECKPOINT_BYTES: i64 = 256 * 1024;
fn checkpoint_due(
    seq: u64,
    finish: bool,
    elapsed: Duration,
    written_bytes: i64,
    synced_bytes: i64,
    next_plaintext_bytes: usize,
) -> bool {
    seq == 0
        || finish
        || elapsed >= Duration::from_secs(1)
        || written_bytes
            .saturating_sub(synced_bytes)
            .saturating_add(next_plaintext_bytes as i64 + 28)
            >= CHECKPOINT_BYTES
}
async fn recorder_loop(
    mut writer: RecordingWriter<HashedFile>,
    mut rx: mpsc::Receiver<RecordRequest>,
    backend: Arc<dyn GatewayBackend>,
    config: RecordingConfig,
    id: Uuid,
) {
    let started = tokio::time::Instant::now();
    let mut seq = 0u64;
    let mut synced = -1i64;
    let mut written = -1i64;
    let mut bytes = writer.bytes_written() as i64;
    let mut last_sync = started;
    let mut last_synced_bytes = bytes;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let state = RecordingState::Partial;
    let mut checksum = None;
    loop {
        let request = tokio::select! {
            request = rx.recv() => request,
            _ = tick.tick(), if written > synced => {
                let synced_writer = settle_io(tokio::task::spawn_blocking(move || {
                    let result = writer.writer_mut().file.sync_all().map_err(|_| ErrorCode::RecordingUnavailable);
                    (writer,result)
                })).await;
                match synced_writer {
                    Ok(Ok((next,Ok(())))) => { writer=next; synced=written; last_sync=tokio::time::Instant::now(); },
                    _ => { rx.close(); let _ = backend.finish_recording(id,RecordingState::Partial,bytes,None,Some(ErrorCode::RecordingUnavailable)).await; return; }
                }
                if timeout(ACK_TIMEOUT, backend.checkpoint_recording(id,written,synced,bytes)).await != Ok(Ok(())) { break; }
                last_synced_bytes=bytes;
                continue;
            }
        };
        let Some(mut request) = request else {
            // A dropped/aborted connection seals a partial prefix, never a complete recording.
            let end = serde_json::json!({"type":"end","reason":"connection_interrupted","seq":seq,"elapsed_us":started.elapsed().as_micros().min(u64::MAX as u128) as u64});
            let mut line = serde_json::to_vec(&end).unwrap();
            line.push(b'\n');
            let final_writer = settle_io(tokio::task::spawn_blocking(move || {
                let result = (|| {
                    let ack = writer
                        .append_ndjson(&line)
                        .map_err(|_| ErrorCode::RecordingUnavailable)?;
                    writer
                        .writer_mut()
                        .file
                        .sync_all()
                        .map_err(|_| ErrorCode::RecordingUnavailable)?;
                    Ok::<_, ErrorCode>(ack)
                })();
                let checksum = if result.is_ok() {
                    Some(format!("{:x}", writer.writer_mut().hash.clone().finalize()))
                } else {
                    None
                };
                (writer, result, checksum)
            }))
            .await;
            if let Ok(Ok((_next, Ok(ack), sum))) = final_writer {
                bytes = ack.bytes_written as i64;
                written = ack.chunk_seq as i64;
                synced = written;
                checksum = sum;
            }
            break;
        };
        request.event["seq"] = seq.into();
        request.event["elapsed_us"] = (if seq == 0 {
            0
        } else {
            started.elapsed().as_micros().min(u64::MAX as u128) as u64
        })
        .into();
        let mut line = match serde_json::to_vec(&request.event) {
            Ok(line) => line,
            Err(_) => {
                let _ = request.ack.send(Err(ErrorCode::RecordingUnavailable));
                break;
            }
        };
        line.push(b'\n');
        let directory = config.directory.clone();
        let minimum = config.min_free_bytes;
        let should_sync = checkpoint_due(
            seq,
            request.finish.is_some(),
            last_sync.elapsed(),
            bytes,
            last_synced_bytes,
            line.len(),
        );
        let result = settle_io(tokio::task::spawn_blocking(move || {
            let result = (|| {
                check_recording_directory(&directory, minimum)?;
                let ack = writer
                    .append_ndjson(&line)
                    .map_err(|_| ErrorCode::RecordingUnavailable)?;
                if should_sync {
                    writer
                        .writer_mut()
                        .file
                        .sync_all()
                        .map_err(|_| ErrorCode::RecordingUnavailable)?;
                }
                Ok::<_, ErrorCode>(ack)
            })();
            (writer, result)
        }))
        .await;
        match result {
            Ok(Ok((next, result))) => {
                writer = next;
                match result {
                    Ok(ack) => {
                        written = ack.chunk_seq as i64;
                        bytes = ack.bytes_written as i64;
                    }
                    Err(error) => {
                        let _ = request.ack.send(Err(error));
                        break;
                    }
                }
            }
            _ => {
                rx.close();
                let _ = request.ack.send(Err(ErrorCode::RecordingUnavailable));
                let _ = backend
                    .finish_recording(
                        id,
                        RecordingState::Partial,
                        bytes,
                        None,
                        Some(ErrorCode::RecordingUnavailable),
                    )
                    .await;
                return;
            }
        }
        seq += 1;
        if should_sync {
            synced = written;
            last_sync = tokio::time::Instant::now();
            if timeout(
                ACK_TIMEOUT,
                backend.checkpoint_recording(id, written, synced, bytes),
            )
            .await
                != Ok(Ok(()))
            {
                let _ = request.ack.send(Err(ErrorCode::RecordingUnavailable));
                break;
            }
        }
        if should_sync {
            last_synced_bytes = bytes;
        }
        if request.ack.is_closed() {
            let _ = timeout(
                ACK_TIMEOUT,
                backend.checkpoint_recording(id, written, synced, bytes),
            )
            .await;
            break;
        }
        if let Some((finish_state, failure)) = request.finish {
            let sealed = settle_io(tokio::task::spawn_blocking(move || {
                let file = writer
                    .finish()
                    .map_err(|_| ErrorCode::RecordingUnavailable)?;
                file.file
                    .sync_all()
                    .map_err(|_| ErrorCode::RecordingUnavailable)?;
                Ok::<_, ErrorCode>(format!("{:x}", file.hash.finalize()))
            }))
            .await;
            let mut finish_state = finish_state;
            let mut failure = failure;
            checksum = match sealed {
                Ok(Ok(Ok(sum))) if !request.ack.is_closed() => Some(sum),
                _ => {
                    finish_state = RecordingState::Partial;
                    failure = Some(ErrorCode::RecordingUnavailable);
                    None
                }
            };
            let finalized = timeout(
                ACK_TIMEOUT,
                backend.finish_recording(id, finish_state, bytes, checksum.clone(), failure),
            )
            .await;
            if finalized != Ok(Ok(())) {
                let _ = timeout(
                    ACK_TIMEOUT,
                    backend.finish_recording(
                        id,
                        RecordingState::Partial,
                        bytes,
                        checksum,
                        Some(ErrorCode::RecordingUnavailable),
                    ),
                )
                .await;
            }
            let final_ok = finalized == Ok(Ok(()));
            let result = if final_ok && failure != Some(ErrorCode::RecordingUnavailable) {
                Ok(())
            } else {
                Err(ErrorCode::RecordingUnavailable)
            };
            let _ = request.ack.send(result);
            return;
        }
        let _ = request.ack.send(Ok(()));
    }
    rx.close();
    let _ = timeout(
        ACK_TIMEOUT,
        backend.checkpoint_recording(id, written, synced, bytes),
    )
    .await;
    let _ = timeout(
        ACK_TIMEOUT,
        backend.finish_recording(
            id,
            state,
            bytes,
            checksum,
            Some(ErrorCode::RecordingUnavailable),
        ),
    )
    .await;
}

#[cfg(unix)]
pub fn check_recording_directory(
    directory: &Path,
    minimum_free_bytes: u64,
) -> Result<(), ErrorCode> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    };
    let path = std::ffi::CString::new(directory.as_os_str().as_bytes())
        .map_err(|_| ErrorCode::RecordingUnavailable)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ErrorCode::RecordingUnavailable);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file
        .metadata()
        .map_err(|_| ErrorCode::RecordingUnavailable)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o777 != 0o700 {
        return Err(ErrorCode::RecordingUnavailable);
    }
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(ErrorCode::RecordingUnavailable);
    }
    let stat = unsafe { stat.assume_init() };
    // statvfs field widths differ across Unix targets; widen before multiplying.
    #[allow(clippy::unnecessary_cast)]
    let available_bytes = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
    if stat.f_flag & libc::ST_RDONLY != 0 || available_bytes < minimum_free_bytes {
        return Err(ErrorCode::RecordingUnavailable);
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn check_recording_directory(
    _directory: &Path,
    _minimum_free_bytes: u64,
) -> Result<(), ErrorCode> {
    // RFC's owner/0600 guarantees are Unix deployment requirements. Windows test
    // builds are supported, but cannot claim equivalent recording ACL readiness.
    Err(ErrorCode::RecordingUnavailable)
}
#[cfg(unix)]
fn create_recording_file(directory: &Path, name: &str, minimum: u64) -> Result<File, ErrorCode> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };
    check_recording_directory(directory, minimum)?;
    let path = std::ffi::CString::new(directory.as_os_str().as_bytes())
        .map_err(|_| ErrorCode::RecordingUnavailable)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ErrorCode::RecordingUnavailable);
    }
    let dir = unsafe { File::from_raw_fd(fd) };
    let name = std::ffi::CString::new(name).map_err(|_| ErrorCode::RecordingUnavailable)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(ErrorCode::RecordingUnavailable);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    // A synced file alone does not make its newly created directory entry durable.
    dir.sync_all()
        .map_err(|_| ErrorCode::RecordingUnavailable)?;
    Ok(file)
}
#[cfg(not(unix))]
fn create_recording_file(_directory: &Path, _name: &str, _minimum: u64) -> Result<File, ErrorCode> {
    Err(ErrorCode::RecordingUnavailable)
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;
    #[test]
    fn ciphertext_byte_boundary_triggers_before_timer() {
        let mut bytes = 512;
        let mut synced = bytes;
        let mut sync_calls = 0;
        let mut checkpoint_calls = 0;
        for seq in 1..=8 {
            let next_plaintext = 44_000;
            let due = checkpoint_due(seq, false, Duration::ZERO, bytes, synced, next_plaintext);
            bytes += next_plaintext as i64 + 28;
            if due {
                sync_calls += 1;
                checkpoint_calls += 1;
                synced = bytes;
            }
        }
        assert_eq!(sync_calls, 1);
        assert_eq!(checkpoint_calls, 1);
        assert!(bytes - synced < CHECKPOINT_BYTES);
        assert!(checkpoint_due(
            2,
            false,
            Duration::from_secs(1),
            bytes,
            bytes,
            0
        ));
        assert!(checkpoint_due(2, true, Duration::ZERO, bytes, bytes, 0));
        assert!(checkpoint_due(0, false, Duration::ZERO, bytes, bytes, 0));
        assert!(!checkpoint_due(
            2,
            false,
            Duration::ZERO,
            bytes,
            bytes,
            32 * 1024
        ));
    }
}
