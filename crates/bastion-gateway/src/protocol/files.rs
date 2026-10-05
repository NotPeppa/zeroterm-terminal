use super::*;
use russh_sftp::{
    client::{error::Error as SftpError, RawSftpSession},
    protocol::{FileAttributes, OpenFlags, StatusCode},
};
use serde::Serialize;
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
    task::JoinHandle,
};

const MAX_CHUNK: usize = 32 * 1024;
const MAX_PACKET: usize = 64 * 1024;
const MAX_ENTRIES: usize = 1024;
const IO_BUDGET: usize = 256 * 1024;
// Full possible reply plus one decoded DATA payload; never assume an ACK is small.
const META_CREDIT: usize = MAX_PACKET + 4;
const BULK_CREDIT: usize = META_CREDIT + MAX_CHUNK;
const BULK_WINDOW: usize = 2;

#[derive(Serialize)]
pub struct FileMetadata {
    pub size: Option<u64>,
    pub permissions: Option<u32>,
    pub mtime: Option<u32>,
    pub kind: &'static str,
}
impl From<FileAttributes> for FileMetadata {
    fn from(attrs: FileAttributes) -> Self {
        let kind = match attrs.permissions.map(|p| p & 0xf000) {
            Some(0x8000) => "file",
            Some(0x4000) => "directory",
            Some(0xa000) => "symlink",
            _ => "other",
        };
        Self {
            size: attrs.size,
            permissions: attrs.permissions,
            mtime: attrs.mtime,
            kind,
        }
    }
}
#[derive(Serialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub metadata: FileMetadata,
}

/// SFTPv3 lane with serialized metadata and a two-request, shared-credit bulk window.
pub struct SftpSession {
    inner: Arc<SftpInner>,
}
struct SftpInner {
    session: Arc<ConnectionSession>,
    raw: RawSftpSession,
    gate: Mutex<()>,
    bytes: Arc<Semaphore>,
    handles: Arc<Semaphore>,
    _channel: ChannelLease,
    lifecycle: Arc<ChannelLifecycle>,
}
impl Drop for SftpInner {
    fn drop(&mut self) {
        let _ = self.raw.close_session();
    }
}
impl SftpSession {
    pub(crate) async fn open(session: Arc<ConnectionSession>) -> Result<Self, ErrorCode> {
        let canceled = session.stop.clone().drop_guard();
        let permit = session.registry.channel(session.connection.id)?;
        let mut pending = PendingChannel(Some(
            timeout(START_TIMEOUT, session.target.channel_open_session())
                .await
                .map_err(|_| ErrorCode::TargetTimeout)?
                .map_err(|_| ErrorCode::TargetUnreachable)?,
        ));
        let channel = pending.0.as_mut().unwrap();
        let lifecycle = ChannelLifecycle::begin(
            &session,
            u32::from(channel.id()),
            bastion_domain::ChannelKind::Sftp,
        )
        .await?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|_| ErrorCode::TargetUnreachable)?;
        web::accepted(channel).await?;
        let raw = RawSftpSession::new(BoundedSftpStream::new(
            pending.0.take().unwrap().into_stream(),
        ));
        raw.set_timeout(30);
        let version = timeout(START_TIMEOUT, raw.init())
            .await
            .map_err(|_| ErrorCode::TargetTimeout)?
            .map_err(map_error)?;
        if version.version != 3 {
            return Err(ErrorCode::TargetRequestRejected);
        }
        lifecycle.streaming().await?;
        session.touch();
        canceled.disarm();
        Ok(Self {
            inner: Arc::new(SftpInner {
                session,
                raw,
                gate: Mutex::new(()),
                bytes: Arc::new(Semaphore::new(IO_BUDGET)),
                handles: Arc::new(Semaphore::new(8)),
                _channel: permit,
                lifecycle,
            }),
        })
    }
    pub async fn close(self) -> Result<(), ErrorCode> {
        self.inner.raw.close_session().map_err(map_error)?;
        self.inner.lifecycle.finish(None).await
    }
    async fn check(&self) -> Result<(), ErrorCode> {
        self.inner.session.check(Capability::Sftp).await
    }
    async fn request<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, SftpError>>,
    ) -> Result<T, ErrorCode> {
        self.inner.request(future).await
    }
    pub async fn metadata(&self, path: &str) -> Result<FileMetadata, ErrorCode> {
        validate_path(path)?;
        self.check().await?;
        Ok(self.request(self.inner.raw.lstat(path)).await?.attrs.into())
    }
    pub async fn read_dir(&self, path: &str) -> Result<Vec<DirectoryEntry>, ErrorCode> {
        validate_path(path)?;
        self.check().await?;
        let _permit = self
            .inner
            .handles
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::ConnectionLimit)?;
        let handle = self.request(self.inner.raw.opendir(path)).await?.handle;
        if handle.len() > 4096 {
            self.inner.session.cancel();
            let _ = self.inner.raw.close_session();
            return Err(ErrorCode::TargetRequestRejected);
        }
        let result = async {
            let mut entries = Vec::new();
            loop {
                match self
                    .inner
                    .read_request(self.inner.raw.readdir(&handle))
                    .await
                {
                    Ok(Some(batch)) => {
                        if batch.files.is_empty() {
                            return Err(ErrorCode::TargetRequestRejected);
                        }
                        if entries.len() + batch.files.len() > MAX_ENTRIES {
                            return Err(ErrorCode::InvalidArgument);
                        }
                        for entry in batch.files {
                            if entry.filename.len() > 4096 || entry.filename.contains('\0') {
                                return Err(ErrorCode::InvalidArgument);
                            }
                            entries.push(DirectoryEntry {
                                name: entry.filename,
                                metadata: entry.attrs.into(),
                            });
                        }
                    }
                    Ok(None) => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(entries)
        }
        .await;
        let closed = self.request(self.inner.raw.close(handle)).await;
        closed?;
        result
    }
    pub async fn open_download(&self, path: &str) -> Result<SftpDownload, ErrorCode> {
        validate_path(path)?;
        self.check().await?;
        let metadata = self.request(self.inner.raw.lstat(path)).await?.attrs;
        require_regular(&metadata)?;
        let permit = self
            .inner
            .handles
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::ConnectionLimit)?;
        let handle = self
            .request(
                self.inner
                    .raw
                    .open(path, OpenFlags::READ, FileAttributes::empty()),
            )
            .await?
            .handle;
        if handle.len() > 4096 {
            self.inner.session.cancel();
            let _ = self.inner.raw.close_session();
            return Err(ErrorCode::TargetRequestRejected);
        }
        let actual = self.request(self.inner.raw.fstat(&handle)).await;
        if actual.as_ref().is_err()
            || actual.as_ref().is_ok_and(|a| {
                require_regular(&a.attrs).is_err()
                    || a.attrs.size != metadata.size
                    || a.attrs.mtime != metadata.mtime
            })
        {
            let _ = self.request(self.inner.raw.close(handle)).await;
            return Err(ErrorCode::TargetRequestRejected);
        }
        Ok(SftpDownload {
            inner: self.inner.clone(),
            handle: Some(handle),
            offset: 0,
            next_offset: 0,
            eof: false,
            pending: VecDeque::new(),
            failed: None,
            _permit: Some(permit),
        })
    }
    pub async fn begin_upload(&self, path: &str) -> Result<SftpUpload, ErrorCode> {
        validate_path(path)?;
        self.check().await?;
        self.ensure_absent(path).await?;
        let (parent, name) = path.rsplit_once('/').ok_or(ErrorCode::InvalidArgument)?;
        if name.is_empty() || matches!(name, "." | "..") {
            return Err(ErrorCode::InvalidArgument);
        }
        let temp = format!("{parent}/.zt-upload-{}", Uuid::new_v4());
        let permit = self
            .inner
            .handles
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::ConnectionLimit)?;
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(0o600);
        let handle = self
            .request(self.inner.raw.open(
                &temp,
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                attrs,
            ))
            .await?
            .handle;
        if handle.len() > 4096 {
            self.inner.session.cancel();
            let _ = self.inner.raw.close_session();
            return Err(ErrorCode::TargetRequestRejected);
        }
        Ok(SftpUpload {
            inner: self.inner.clone(),
            handle: Some(handle),
            temp: Some(temp),
            destination: path.to_owned(),
            offset: 0,
            pending: VecDeque::new(),
            failed: None,
            _permit: Some(permit),
        })
    }
    async fn ensure_absent(&self, path: &str) -> Result<(), ErrorCode> {
        match self.request(self.inner.raw.lstat(path)).await {
            Err(ErrorCode::ResourceNotFound) => Ok(()),
            Ok(_) => Err(ErrorCode::ResourceConflict),
            Err(error) => Err(error),
        }
    }
    pub async fn remove_file(&self, path: &str) -> Result<(), ErrorCode> {
        validate_path(path)?;
        self.check().await?;
        require_regular(&self.request(self.inner.raw.lstat(path)).await?.attrs)?;
        self.request(self.inner.raw.remove(path)).await?;
        Ok(())
    }
    pub async fn create_dir(&self, path: &str) -> Result<(), ErrorCode> {
        validate_path(path)?;
        self.check().await?;
        self.ensure_absent(path).await?;
        self.request(self.inner.raw.mkdir(path, FileAttributes::empty()))
            .await?;
        Ok(())
    }
    pub async fn rename(&self, source: &str, destination: &str) -> Result<(), ErrorCode> {
        validate_path(source)?;
        validate_path(destination)?;
        self.check().await?;
        self.ensure_absent(destination).await?;
        self.request(self.inner.raw.rename(source, destination))
            .await?;
        Ok(())
    }
}
impl SftpInner {
    async fn bulk_credit(&self) -> Result<OwnedSemaphorePermit, ErrorCode> {
        let canceled = self.session.stop.clone().drop_guard();
        let result = tokio::select! {
            _ = self.session.stop.cancelled() => Err(ErrorCode::LoginSessionRevoked),
            result = timeout(STALL_TIMEOUT, self.bytes.clone().acquire_many_owned(BULK_CREDIT as u32)) =>
                result.map_err(|_| ErrorCode::TargetTimeout).and_then(|permit| permit.map_err(|_| ErrorCode::TargetUnreachable)),
        };
        if result.is_err() {
            self.session.cancel();
            let _ = self.raw.close_session();
        }
        canceled.disarm();
        result
    }
    async fn bulk<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, SftpError>>,
    ) -> Result<T, ErrorCode> {
        let canceled = self.session.stop.clone().drop_guard();
        let result = tokio::select! {
            _ = self.session.stop.cancelled() => Err(ErrorCode::LoginSessionRevoked),
            result = timeout(STALL_TIMEOUT, future) => result.unwrap_or(Err(SftpError::Timeout)).map_err(map_error),
        };
        match &result {
            Ok(_) => self.session.touch(),
            Err(
                ErrorCode::TargetTimeout
                | ErrorCode::TargetUnreachable
                | ErrorCode::LoginSessionRevoked,
            ) => {
                self.session.cancel();
                let _ = self.raw.close_session();
            }
            _ => {}
        }
        canceled.disarm();
        result
    }
    async fn read_request<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, SftpError>>,
    ) -> Result<Option<T>, ErrorCode> {
        let canceled = self.session.stop.clone().drop_guard();
        let operation = async {
            let _gate = self.gate.lock().await;
            let _bytes = self
                .bytes
                .clone()
                .acquire_many_owned(META_CREDIT as u32)
                .await
                .map_err(|_| ErrorCode::TargetUnreachable)?;
            match future.await {
                Ok(value) => Ok(Some(value)),
                Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => Ok(None),
                Err(error) => Err(map_error(error)),
            }
        };
        let result = tokio::select! {_=self.session.stop.cancelled()=>Err(ErrorCode::LoginSessionRevoked),result=timeout(STALL_TIMEOUT,operation)=>result.unwrap_or(Err(ErrorCode::TargetTimeout))};
        if result.is_ok() {
            self.session.touch();
        } else {
            let _ = self.raw.close_session();
            self.session.cancel();
        }
        canceled.disarm();
        result
    }
    async fn request<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, SftpError>>,
    ) -> Result<T, ErrorCode> {
        let canceled = self.session.stop.clone().drop_guard();
        let operation = async {
            let _gate = self.gate.lock().await;
            let _bytes = self
                .bytes
                .clone()
                .acquire_many_owned(META_CREDIT as u32)
                .await
                .map_err(|_| ErrorCode::TargetUnreachable)?;
            future.await.map_err(map_error)
        };
        let result = tokio::select! {
            _ = self.session.stop.cancelled() => Err(ErrorCode::LoginSessionRevoked),
            result = timeout(STALL_TIMEOUT, operation) => result.unwrap_or(Err(ErrorCode::TargetTimeout)),
        };
        match &result {
            Ok(_) => self.session.touch(),
            Err(
                ErrorCode::TargetTimeout
                | ErrorCode::TargetUnreachable
                | ErrorCode::LoginSessionRevoked,
            ) => {
                let _ = self.raw.close_session();
                self.session.cancel();
            }
            _ => {}
        }
        canceled.disarm();
        result
    }
}
struct ReadReply {
    data: Option<Vec<u8>>,
    credit: OwnedSemaphorePermit,
}
struct PendingRead {
    offset: u64,
    len: u32,
    task: JoinHandle<Result<ReadReply, ErrorCode>>,
}
async fn receive_read(
    pending: &mut VecDeque<PendingRead>,
) -> Result<(u64, u32, ReadReply), ErrorCode> {
    let request = pending.front_mut().ok_or(ErrorCode::InvalidArgument)?;
    let (offset, len) = (request.offset, request.len);
    // Await in place: cancellation must not detach the front task.
    let reply = (&mut request.task)
        .await
        .unwrap_or(Err(ErrorCode::TargetUnreachable));
    pending.pop_front();
    reply.map(|reply| (offset, len, reply))
}
fn read_result(
    result: Result<russh_sftp::protocol::Data, SftpError>,
) -> Result<Option<Vec<u8>>, SftpError> {
    match result {
        Ok(data) => Ok(Some(data.data)),
        Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => Ok(None),
        Err(error) => Err(error),
    }
}
fn read_tail(
    offset: u64,
    requested: u32,
    received: usize,
) -> Result<Option<(u64, u32)>, ErrorCode> {
    if received == 0 || received > requested as usize {
        return Err(ErrorCode::TargetRequestRejected);
    }
    let end = offset
        .checked_add(received as u64)
        .ok_or(ErrorCode::InvalidArgument)?;
    Ok((received < requested as usize).then_some((end, requested - received as u32)))
}
fn queue_read(
    inner: Arc<SftpInner>,
    handle: String,
    offset: u64,
    len: u32,
    credit: OwnedSemaphorePermit,
) -> PendingRead {
    let task = tokio::spawn(async move {
        let data = inner
            .bulk(async { read_result(inner.raw.read(handle, offset, len).await) })
            .await?;
        Ok(ReadReply { data, credit })
    });
    PendingRead { offset, len, task }
}
pub struct SftpDownload {
    inner: Arc<SftpInner>,
    handle: Option<String>,
    offset: u64,
    next_offset: u64,
    eof: bool,
    pending: VecDeque<PendingRead>,
    failed: Option<ErrorCode>,
    _permit: Option<OwnedSemaphorePermit>,
}
impl SftpDownload {
    fn queue(&mut self, credit: OwnedSemaphorePermit) -> Result<(), ErrorCode> {
        let end = self
            .next_offset
            .checked_add(MAX_CHUNK as u64)
            .ok_or(ErrorCode::InvalidArgument)?;
        let handle = self
            .handle
            .as_ref()
            .ok_or(ErrorCode::InvalidArgument)?
            .clone();
        self.pending.push_back(queue_read(
            self.inner.clone(),
            handle,
            self.next_offset,
            MAX_CHUNK as u32,
            credit,
        ));
        self.next_offset = end;
        Ok(())
    }
    async fn drain(&mut self, eof: bool) -> Result<(), ErrorCode> {
        let mut first = self.failed;
        while let Some(request) = self.pending.front_mut() {
            let result = (&mut request.task)
                .await
                .unwrap_or(Err(ErrorCode::TargetUnreachable));
            self.pending.pop_front();
            match result {
                Ok(reply) if eof && reply.data.is_some() => {
                    first.get_or_insert(ErrorCode::TargetRequestRejected);
                }
                Err(error) => {
                    first.get_or_insert(error);
                }
                _ => {}
            }
        }
        self.failed = first;
        first.map_or(Ok(()), Err)
    }
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, ErrorCode> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.eof {
            return Ok(None);
        }
        while self.pending.len() < BULK_WINDOW {
            match self
                .inner
                .bytes
                .clone()
                .try_acquire_many_owned(BULK_CREDIT as u32)
            {
                Ok(credit) => self.queue(credit)?,
                Err(_) => break,
            }
        }
        if self.pending.is_empty() {
            self.queue(self.inner.bulk_credit().await?)?;
        }
        let (offset, len, reply) = match receive_read(&mut self.pending).await {
            Ok(reply) => reply,
            Err(error) => {
                self.failed = Some(error);
                return Err(error);
            }
        };
        if offset != self.offset {
            self.failed = Some(ErrorCode::TargetRequestRejected);
            return Err(ErrorCode::TargetRequestRejected);
        }
        let Some(data) = reply.data else {
            drop(reply.credit);
            self.drain(true).await?;
            self.eof = true;
            return Ok(None);
        };
        let tail = match read_tail(offset, len, data.len()) {
            Ok(tail) => tail,
            Err(error) => {
                self.failed = Some(error);
                return Err(error);
            }
        };
        self.offset = offset
            .checked_add(data.len() as u64)
            .ok_or(ErrorCode::InvalidArgument)?;
        if let Some((offset, len)) = tail {
            // Reuse the credit for a short-read gap: never wait behind metadata while owning later replies.
            self.pending.push_front(queue_read(
                self.inner.clone(),
                self.handle.as_ref().unwrap().clone(),
                offset,
                len,
                reply.credit,
            ));
        }
        Ok(Some(data))
    }
    pub async fn close(mut self) -> Result<(), ErrorCode> {
        let result = self.drain(false).await;
        let closed = if let Some(handle) = self.handle.as_ref().cloned() {
            self.inner
                .request(self.inner.raw.close(handle))
                .await
                .map(|_| ())
        } else {
            Ok(())
        };
        if closed.is_ok() {
            self.handle.take();
        }
        result.and(closed)
    }
}
impl Drop for SftpDownload {
    fn drop(&mut self) {
        let inner = self.inner.clone();
        let handle = self.handle.take();
        let mut pending = std::mem::take(&mut self.pending);
        let permit = self._permit.take();
        if handle.is_none() && pending.is_empty() {
            return;
        }
        let registry = inner.session.registry.clone();
        registry.track(tokio::spawn(async move {
            let cleanup = async {
                while let Some(request) = pending.front_mut() {
                    let _ = (&mut request.task).await;
                    pending.pop_front();
                }
                if let Some(handle) = handle {
                    let _ = inner.request(inner.raw.close(handle)).await;
                }
            };
            if timeout(STALL_TIMEOUT, cleanup).await.is_err() {
                for request in &pending {
                    request.task.abort();
                }
                while let Some(request) = pending.pop_front() {
                    let _ = request.task.await;
                }
                inner.session.cancel();
                let _ = inner.raw.close_session();
            }
            drop(permit);
        }));
    }
}
pub struct SftpUpload {
    inner: Arc<SftpInner>,
    handle: Option<String>,
    temp: Option<String>,
    destination: String,
    offset: u64,
    pending: VecDeque<JoinHandle<Result<(), ErrorCode>>>,
    failed: Option<ErrorCode>,
    _permit: Option<OwnedSemaphorePermit>,
}
impl SftpUpload {
    async fn reap(&mut self) -> Result<(), ErrorCode> {
        if let Some(task) = self.pending.front_mut() {
            let result = task.await.unwrap_or(Err(ErrorCode::TargetUnreachable));
            self.pending.pop_front();
            if let Err(error) = result {
                self.failed.get_or_insert(error);
            }
        }
        self.failed.map_or(Ok(()), Err)
    }
    async fn drain(&mut self) -> Result<(), ErrorCode> {
        while !self.pending.is_empty() {
            let _ = self.reap().await;
        }
        self.failed.map_or(Ok(()), Err)
    }
    pub async fn write_chunk(&mut self, data: &[u8]) -> Result<(), ErrorCode> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if data.len() > MAX_CHUNK {
            return Err(ErrorCode::InvalidArgument);
        }
        if data.is_empty() {
            return Ok(());
        }
        let end = self
            .offset
            .checked_add(data.len() as u64)
            .ok_or(ErrorCode::InvalidArgument)?;
        if self.pending.len() >= BULK_WINDOW {
            self.reap().await?;
        }
        let credit = self.inner.bulk_credit().await?;
        let inner = self.inner.clone();
        let handle = self
            .handle
            .as_ref()
            .ok_or(ErrorCode::InvalidArgument)?
            .clone();
        let offset = self.offset;
        let data = data.to_vec();
        self.pending.push_back(tokio::spawn(async move {
            let result = inner
                .bulk(inner.raw.write(handle, offset, data))
                .await
                .map(|_| ());
            drop(credit);
            result
        }));
        self.offset = end;
        Ok(())
    }
    async fn cleanup(&mut self) -> Result<(), ErrorCode> {
        let result = self.drain().await;
        let close = if let Some(handle) = self.handle.as_ref().cloned() {
            self.inner
                .request(self.inner.raw.close(handle))
                .await
                .map(|_| ())
        } else {
            Ok(())
        };
        if close.is_ok() {
            self.handle.take();
        }
        let remove = if let Some(temp) = self.temp.as_ref().cloned() {
            self.inner
                .request(self.inner.raw.remove(temp))
                .await
                .map(|_| ())
        } else {
            Ok(())
        };
        if remove.is_ok() {
            self.temp.take();
        }
        result.and(close).and(remove)
    }
    pub async fn commit(mut self) -> Result<u64, ErrorCode> {
        let result = async {
            self.drain().await?;
            self.inner.session.check(Capability::Sftp).await?;
            let handle = self
                .handle
                .as_ref()
                .cloned()
                .ok_or(ErrorCode::InvalidArgument)?;
            self.inner.request(self.inner.raw.close(handle)).await?;
            self.handle.take();
            match self
                .inner
                .request(self.inner.raw.lstat(&self.destination))
                .await
            {
                Err(ErrorCode::ResourceNotFound) => {}
                Ok(_) => return Err(ErrorCode::ResourceConflict),
                Err(error) => return Err(error),
            }
            // SFTPv3 RENAME is no-overwrite; never commit before every WRITE ACK.
            self.inner
                .request(
                    self.inner
                        .raw
                        .rename(self.temp.as_ref().unwrap(), &self.destination),
                )
                .await?;
            self.temp.take();
            Ok(self.offset)
        }
        .await;
        if result.is_err() {
            let _ = self.cleanup().await;
        }
        result
    }
    pub async fn cancel(mut self) -> Result<(), ErrorCode> {
        match timeout(STALL_TIMEOUT, self.cleanup()).await {
            Ok(result) => result,
            Err(_) => {
                self.inner.session.cancel();
                let _ = self.inner.raw.close_session();
                Err(ErrorCode::TargetTimeout)
            }
        }
    }
}
impl Drop for SftpUpload {
    fn drop(&mut self) {
        let inner = self.inner.clone();
        let handle = self.handle.take();
        let temp = self.temp.take();
        let mut pending = std::mem::take(&mut self.pending);
        let permit = self._permit.take();
        if handle.is_none() && temp.is_none() && pending.is_empty() {
            return;
        }
        let registry = inner.session.registry.clone();
        registry.track(tokio::spawn(async move {
            let cleanup = async {
                while let Some(task) = pending.front_mut() {
                    let _ = task.await;
                    pending.pop_front();
                }
                if let Some(handle) = handle {
                    let _ = inner.request(inner.raw.close(handle)).await;
                }
                if let Some(temp) = temp {
                    let _ = inner.request(inner.raw.remove(temp)).await;
                }
            };
            if timeout(STALL_TIMEOUT, cleanup).await.is_err() {
                for task in &pending {
                    task.abort();
                }
                while let Some(task) = pending.pop_front() {
                    let _ = task.await;
                }
                inner.session.cancel();
                let _ = inner.raw.close_session();
            }
            drop(permit);
        }));
    }
}

/// Copies one regular file, never through a gateway-local command or file.
/// SFTPv3 cannot atomically open with NOFOLLOW; strict copies fail closed rather
/// than pretend an lstat/open race enforces the required invariant.
pub async fn copy_regular_file(
    source: &SftpSession,
    source_path: &str,
    destination: &SftpSession,
    destination_path: &str,
    stop: CancellationToken,
) -> Result<u64, ErrorCode> {
    validate_path(source_path)?;
    validate_path(destination_path)?;
    source.check().await?;
    destination.check().await?;
    if stop.is_cancelled() {
        return Err(ErrorCode::LoginSessionRevoked);
    }
    Err(ErrorCode::TargetRequestRejected)
}
fn validate_path(path: &str) -> Result<(), ErrorCode> {
    if path.is_empty() || path.len() > 4096 || path.contains('\0') {
        Err(ErrorCode::InvalidArgument)
    } else {
        Ok(())
    }
}
fn require_regular(attrs: &FileAttributes) -> Result<(), ErrorCode> {
    if attrs.permissions.map(|p| p & 0xf000) == Some(0x8000) {
        Ok(())
    } else {
        Err(ErrorCode::InvalidArgument)
    }
}
fn map_error(error: SftpError) -> ErrorCode {
    match error {
        SftpError::Status(status) => match status.status_code {
            StatusCode::NoSuchFile => ErrorCode::ResourceNotFound,
            StatusCode::PermissionDenied => ErrorCode::PermissionDenied,
            _ => ErrorCode::TargetRequestRejected,
        },
        SftpError::Timeout => ErrorCode::TargetTimeout,
        _ => ErrorCode::TargetUnreachable,
    }
}

/// Validate only the length prefix before russh-sftp allocates its packet. The
/// crate's decoder still owns all SFTP encoding/decoding; this is an I/O limit.
struct BoundedSftpStream<S> {
    stream: S,
    prefix: [u8; 13],
    have: usize,
    sent: usize,
    header: usize,
    remaining: usize,
    failed: bool,
}
impl<S> BoundedSftpStream<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            prefix: [0; 13],
            have: 0,
            sent: 0,
            header: 4,
            remaining: 0,
            failed: false,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for BoundedSftpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        loop {
            while this.have < this.header {
                let mut prefix = ReadBuf::new(&mut this.prefix[this.have..this.header]);
                match Pin::new(&mut this.stream).poll_read(cx, &mut prefix) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.failed = true;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) => {
                        let n = prefix.filled().len();
                        if n == 0 {
                            this.failed = true;
                            return Poll::Ready(Ok(()));
                        }
                        this.have += n;
                    }
                }
            }
            let length = u32::from_be_bytes(this.prefix[..4].try_into().unwrap()) as usize;
            let invalid = |this: &mut Self| {
                this.failed = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SFTP packet exceeds gateway bound",
                )))
            };
            if length == 0 || length > MAX_PACKET {
                return invalid(this);
            }
            if this.header == 4 {
                this.header = 5;
                continue;
            }
            if matches!(this.prefix[4], 102..=104) {
                if length < 9 {
                    return invalid(this);
                }
                if this.header == 5 {
                    this.header = 13;
                    continue;
                }
                let declared = u32::from_be_bytes(this.prefix[9..13].try_into().unwrap()) as usize;
                if this.prefix[4] == 102 {
                    if declared > 4096 || length != 9 + declared {
                        return invalid(this);
                    }
                } else if this.prefix[4] == 103 {
                    if declared > MAX_CHUNK || length != 9 + declared {
                        return invalid(this);
                    }
                } else if declared > MAX_ENTRIES || declared > (length - 9) / 12 {
                    return invalid(this);
                }
            }
            if this.sent == 0 {
                this.remaining = length - (this.header - 4);
            }
            break;
        }
        if this.sent < this.header {
            let n = (this.header - this.sent).min(buffer.remaining());
            buffer.put_slice(&this.prefix[this.sent..this.sent + n]);
            this.sent += n;
            if this.sent == this.header && this.remaining == 0 {
                this.have = 0;
                this.sent = 0;
                this.header = 4;
            }
            return Poll::Ready(Ok(()));
        }
        let limit = this.remaining.min(buffer.remaining());
        let mut part = ReadBuf::new(buffer.initialize_unfilled_to(limit));
        match Pin::new(&mut this.stream).poll_read(cx, &mut part) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.failed = true;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(())) => {
                let n = part.filled().len();
                buffer.advance(n);
                this.remaining -= n;
                if n == 0 {
                    this.failed = true;
                }
                if this.remaining == 0 {
                    this.have = 0;
                    this.sent = 0;
                    this.header = 4;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for BoundedSftpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn packet_bound_checked_before_allocation_and_framing_preserved() {
        let (mut tx, rx) = tokio::io::duplex(128);
        tx.write_all(&[0, 0, 0, 3, 1, 2, 3, 0, 1, 0, 1])
            .await
            .unwrap();
        drop(tx);
        let mut stream = BoundedSftpStream::new(rx);
        let mut packet = [0; 7];
        stream.read_exact(&mut packet).await.unwrap();
        assert_eq!(packet, [0, 0, 0, 3, 1, 2, 3]);
        let mut prefix = [0; 4];
        assert!(stream.read_exact(&mut prefix).await.is_err());
    }
    #[test]
    fn missing_handle_is_not_eof() {
        let status = |status_code| {
            SftpError::Status(russh_sftp::protocol::Status {
                id: 1,
                status_code,
                error_message: String::new(),
                language_tag: String::new(),
            })
        };
        assert_eq!(
            map_error(status(StatusCode::NoSuchFile)),
            ErrorCode::ResourceNotFound
        );
        assert_eq!(
            map_error(status(StatusCode::Eof)),
            ErrorCode::TargetRequestRejected
        );
    }
    #[test]
    fn regular_file_checks_exact_mode_not_bit_overlap() {
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(0xa000 | 0o600);
        assert!(require_regular(&attrs).is_err());
        attrs.permissions = Some(0x8000 | 0o600);
        assert!(require_regular(&attrs).is_ok());
    }
}

#[cfg(test)]
#[path = "files_perf_tests.rs"]
mod perf_tests;
