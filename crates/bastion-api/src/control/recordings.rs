use super::*;
use axum::body::{Body, Bytes};
use bastion_secrets::recording::{
    RecordingContext, RecordingEnvelope, RecordingHeader, RecordingReader,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path as FsPath, PathBuf},
};

pub(super) async fn list(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::Recordings, page)
            .await?,
    ))
}
pub(super) async fn metadata(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
) -> ApiResult<Json<RecordingView>> {
    Ok(Json(
        state
            .store
            .recording_metadata(&identity, id(&value)?)
            .await?,
    ))
}
fn basename(relative: &str) -> anyhow::Result<&str> {
    let mut components = FsPath::new(relative).components();
    if relative.contains('\\')
        || !relative.ends_with(".ztrec")
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        anyhow::bail!("invalid managed recording basename");
    }
    Ok(relative)
}
#[cfg(unix)]
fn root_fd(root: &FsPath) -> anyhow::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.mode() & 0o777 != 0o700 || meta.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("unsafe recording root");
    }
    Ok(file)
}
fn open_private(root: &FsPath, relative: &str) -> anyhow::Result<File> {
    let relative = basename(relative)?;
    #[cfg(unix)]
    {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        };
        let directory = root_fd(root)?;
        let name = std::ffi::CString::new(relative)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.mode() & 0o777 != 0o600
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.nlink() != 1
        {
            anyhow::bail!("unsafe recording file");
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, relative);
        anyhow::bail!("recording storage requires Unix permissions")
    }
}
/// Offline retention helper. Call only after the authority selects an inactive expired recording.
pub fn remove_recording_file(root: &FsPath, relative: &str) -> anyhow::Result<()> {
    let relative = basename(relative)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let directory = root_fd(root)?;
        // Inspect the same anchored file namespace before unlink. Unlink never follows symlinks.
        match open_private(root, relative) {
            Ok(_) => {}
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        }
        let name = std::ffi::CString::new(relative)?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (root, relative);
        anyhow::bail!("recording retention requires Unix permissions")
    }
}
struct CheckedFile {
    file: File,
    hash: Sha256,
    bytes: u64,
    expected: u64,
    checksum: Option<String>,
}
impl Read for CheckedFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let n = self.file.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| std::io::Error::other("recording length overflow"))?;
        if self.bytes > self.expected {
            return Err(std::io::Error::other("recording exceeds metadata size"));
        }
        self.hash.update(&buffer[..n]);
        Ok(n)
    }
}
impl CheckedFile {
    fn finish(self) -> anyhow::Result<()> {
        if self.bytes != self.expected
            || self
                .checksum
                .is_some_and(|checksum| format!("{:x}", self.hash.finalize()) != checksum)
        {
            anyhow::bail!("recording checksum or length mismatch");
        }
        Ok(())
    }
}
fn reader(
    root: PathBuf,
    material: bastion_store::RecordingRead,
    keys: Arc<KeyRing>,
    server_id: String,
) -> anyhow::Result<RecordingReader<CheckedFile>> {
    let file = open_private(&root, &material.relative_path)?;
    let expected = u64::try_from(material.metadata.bytes)?;
    if file.metadata()?.len() != expected {
        anyhow::bail!("recording length mismatch");
    }
    if material.metadata.state == RecordingState::Complete && material.metadata.checksum.is_none() {
        anyhow::bail!("complete recording lacks checksum");
    }
    let context = RecordingContext::new(server_id, material.metadata.id);
    let envelope = RecordingEnvelope {
        wrapped_dek: material.wrapped_dek,
        wrap_nonce: material.wrap_nonce,
        key_version: material.key_version,
    };
    let key = keys.open_recording_dek(&context, &envelope)?;
    let header = RecordingHeader {
        recording_id: material.metadata.id,
        nonce_prefix: material
            .nonce_prefix
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid recording nonce"))?,
    };
    RecordingReader::new(
        CheckedFile {
            file,
            hash: Sha256::new(),
            bytes: 0,
            expected,
            checksum: material.metadata.checksum,
        },
        &header,
        key,
    )
}
/// Constant-memory offline verification; never returns plaintext or keys.
pub fn verify_recording_file(
    root: PathBuf,
    material: bastion_store::RecordingRead,
    keys: Arc<KeyRing>,
    server_id: String,
) -> anyhow::Result<()> {
    let mut reader = reader(root, material, keys, server_id)?;
    while reader.next_chunk()?.is_some() {}
    reader.into_inner().finish()
}
pub(super) async fn content(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if headers.contains_key(header::RANGE) {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    let recording_id = id(&value)?;
    let root = state
        .recording_directory
        .clone()
        .ok_or(ApiError(ErrorCode::RecordingUnavailable))?;
    let material = state
        .store
        .recording_for_replay(&identity, recording_id, ctx.id)
        .await?;
    let keys = state.keys.clone();
    let server_id = state.store.server_id.to_string();
    let prepared = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || reader(root, material, keys, server_id)),
    )
    .await;
    let mut reader = match prepared {
        Ok(Ok(Ok(reader))) => reader,
        Ok(Ok(Err(error))) => {
            let status = if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                RecordingState::Missing
            } else {
                RecordingState::Corrupt
            };
            let _ = state
                .store
                .mark_recording_unavailable(recording_id, status)
                .await;
            return Err(ApiError(ErrorCode::RecordingUnavailable));
        }
        _ => return Err(ApiError(ErrorCode::RecordingUnavailable)),
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        let mut checked = Instant::now();
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            if checked.elapsed() >= Duration::from_secs(1)
                && state
                    .store
                    .recording_metadata(&identity, recording_id)
                    .await
                    .is_err()
            {
                let _ = tx
                    .send(Err(std::io::Error::other("recording authorization ended")))
                    .await;
                break;
            }
            let read = tokio::task::spawn_blocking(move || {
                let result = reader.next_chunk();
                match result {
                    Ok(None) => (None, reader.into_inner().finish().map(|_| None)),
                    result => (Some(reader), result),
                }
            });
            let result = tokio::select! {_=shutdown.cancelled()=>break,result=tokio::time::timeout(Duration::from_secs(5),read)=>result};
            match result {
                Ok(Ok((Some(next), Ok(Some(chunk))))) => {
                    reader = next;
                    let bytes = Bytes::copy_from_slice(&chunk.plaintext);
                    let waiting = Instant::now();
                    let reserved = loop {
                        let result = tokio::select! {
                            _=shutdown.cancelled()=>break None,
                            result=tokio::time::timeout(Duration::from_secs(1),tx.reserve())=>result,
                        };
                        match result {
                            Ok(Ok(permit)) => break Some(permit),
                            Ok(Err(_)) => break None,
                            Err(_) if waiting.elapsed() >= Duration::from_secs(30) => break None,
                            Err(_) => {
                                if state
                                    .store
                                    .recording_metadata(&identity, recording_id)
                                    .await
                                    .is_err()
                                {
                                    let _ = tx.try_send(Err(std::io::Error::other(
                                        "recording authorization ended",
                                    )));
                                    break None;
                                }
                            }
                        }
                    };
                    let Some(permit) = reserved else {
                        break;
                    };
                    // The permit can arrive after a long full-queue wait. Never enqueue
                    // another plaintext chunk on the stale pre-read authorization.
                    if state
                        .store
                        .recording_metadata(&identity, recording_id)
                        .await
                        .is_err()
                    {
                        permit.send(Err(std::io::Error::other("recording authorization ended")));
                        break;
                    }
                    checked = Instant::now();
                    permit.send(Ok(bytes));
                }
                Ok(Ok((None, Ok(None)))) => break,
                _ => {
                    let _ = state
                        .store
                        .mark_recording_unavailable(recording_id, RecordingState::Corrupt)
                        .await;
                    let _ = tx
                        .send(Err(std::io::Error::other(
                            "recording integrity verification failed",
                        )))
                        .await;
                    break;
                }
            }
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_storage_accepts_flat_names_only() {
        assert!(basename("a.ztrec").is_ok());
        for path in [
            "../a.ztrec",
            "a/b.ztrec",
            "a\\b.ztrec",
            "/a.ztrec",
            "a.txt",
            "",
        ] {
            assert!(basename(path).is_err(), "{path}");
        }
    }
}
