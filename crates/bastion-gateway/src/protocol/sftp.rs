//! SFTP v3 proxy. Only VERSION is filtered; other legal frames remain byte-identical.
//! Writes are hashed on request without retaining payloads, and declared only after every ACK.
use super::*;
use bytes::Bytes;
use russh::{client, server, Channel};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::Instant,
};

const MAX_PACKET: usize = 256 * 1024;
const MAX_PENDING: usize = 128;
const MAX_HANDLES: usize = 1024;
type Audit = SftpAudit;
type Result<T> = std::result::Result<T, ErrorCode>;
fn malformed<T>() -> Result<T> {
    Err(ErrorCode::InvalidArgument)
}
struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return malformed();
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn handle(&mut self) -> Result<&'a [u8]> {
        let handle = self.string()?;
        if handle.len() > 256 {
            return malformed();
        }
        Ok(handle)
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            malformed()
        }
    }
    fn attrs(&mut self) -> Result<()> {
        let flags = self.u32()?;
        if flags & !0x8000000f != 0 {
            return malformed();
        }
        if flags & 1 != 0 {
            self.u64()?;
        }
        if flags & 2 != 0 {
            self.take(8)?;
        }
        if flags & 4 != 0 {
            self.u32()?;
        }
        if flags & 8 != 0 {
            self.take(8)?;
        }
        if flags & 0x80000000 != 0 {
            let count = self.u32()?;
            if count as usize > self.0.len() / 8 {
                return malformed();
            }
            for _ in 0..count {
                self.string()?;
                self.string()?;
            }
        }
        Ok(())
    }
}
const EXTENSIONS: &[&[u8]] = &[
    b"posix-rename@openssh.com",
    b"statvfs@openssh.com",
    b"fstatvfs@openssh.com",
    b"fsync@openssh.com",
    b"hardlink@openssh.com",
    b"limits@openssh.com",
];
fn path(bytes: &[u8]) -> Vec<u8> {
    // At most 4096 UTF-8 characters (16 KiB raw); the store owns final lossy/NUL sanitization.
    bytes[..bytes.len().min(4 * 4096)].to_vec()
}
fn string(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}
fn frame_length(bytes: &mut [u8]) {
    let n = (bytes.len() - 4) as u32;
    bytes[..4].copy_from_slice(&n.to_be_bytes());
}
#[derive(Default)]
struct Contents {
    bytes: u64,
    next: u64,
    hash: Sha256,
    discontinuous: bool,
}
impl Contents {
    fn add(&mut self, offset: u64, data: &[u8]) {
        if offset != self.next {
            self.discontinuous = true;
        }
        self.next = offset.saturating_add(data.len() as u64);
        self.hash.update(data);
    }
    fn checksum(&self) -> Option<String> {
        if self.discontinuous {
            None
        } else {
            Some(format!("{:x}", self.hash.clone().finalize()))
        }
    }
}
struct File {
    path: Vec<u8>,
    flags: u32,
    directory: bool,
    read: Contents,
    write: Contents,
    read_issued: u64,
    read_acked: u64,
    next_read: u64,
    write_issued: u64,
    write_acked_ok: u64,
    write_failed: u64,
    completed: BTreeMap<u64, (u64, Option<Vec<u8>>)>,
}
impl File {
    fn new(path: Vec<u8>, flags: u32, directory: bool) -> Self {
        Self {
            path,
            flags,
            directory,
            read: Contents::default(),
            write: Contents::default(),
            read_issued: 0,
            read_acked: 0,
            next_read: 0,
            write_issued: 0,
            write_acked_ok: 0,
            write_failed: 0,
            completed: BTreeMap::new(),
        }
    }
    fn read_response(&mut self, seq: u64, offset: u64, data: Option<&[u8]>) {
        self.read_acked += 1;
        self.read.bytes += data.map_or(0, |d| d.len() as u64);
        if self.read.discontinuous {
            return;
        }
        if seq == self.next_read {
            self.next_read += 1;
            if let Some(data) = data {
                self.read.add(offset, data);
            } else {
                self.read.discontinuous = true;
            }
            while let Some((offset, data)) = self.completed.remove(&self.next_read) {
                self.next_read += 1;
                if let Some(data) = data {
                    self.read.add(offset, &data);
                } else {
                    self.read.discontinuous = true;
                }
            }
        } else {
            self.completed.insert(seq, (offset, data.map(Vec::from)));
        }
        if self.read.discontinuous {
            self.completed.clear();
        }
    }
    fn audit(&self, status: Option<u32>) -> Audit {
        let read_sha = if self.read_acked == self.read_issued {
            self.read.checksum()
        } else {
            None
        };
        let write_sha = if self.write_acked_ok == self.write_issued && self.write_failed == 0 {
            self.write.checksum()
        } else {
            None
        };
        let sha = if read_sha.is_none() || write_sha.is_none() {
            None
        } else if self.write_issued > 0 {
            write_sha.clone()
        } else {
            read_sha.clone()
        };
        SftpAudit::File {
            path: self.path.clone(),
            flags: self.flags,
            status,
            read_bytes: self.read.bytes,
            write_bytes: self.write.bytes,
            sha256: sha,
            read_sha256: read_sha,
            write_sha256: write_sha,
        }
    }
}
enum Request {
    Open {
        path: Vec<u8>,
        flags: u32,
        directory: bool,
    },
    Close(Vec<u8>),
    Io {
        handle: Vec<u8>,
        seq: u64,
        offset: u64,
        length: u32,
        write: bool,
    },
    Mutation(SftpOp, Vec<u8>, Option<Vec<u8>>),
    Metadata(u8),
    Extension(usize),
}
#[derive(Default)]
struct Proxy {
    init: bool,
    version: bool,
    pending: HashMap<u32, Request>,
    handles: HashMap<Vec<u8>, File>,
    counts: BTreeMap<String, u64>,
    input_bytes: u64,
    output_bytes: u64,
}
fn op(kind: u8) -> &'static str {
    match kind {
        3 => "open",
        4 => "close",
        5 => "read",
        6 => "write",
        7 => "lstat",
        8 => "fstat",
        9 => "setstat",
        10 => "fsetstat",
        11 => "opendir",
        12 => "readdir",
        13 => "remove",
        14 => "mkdir",
        15 => "rmdir",
        16 => "realpath",
        17 => "stat",
        18 => "rename",
        19 => "readlink",
        20 => "symlink",
        _ => "extended",
    }
}
impl Proxy {
    /// Returns a local response when an extension is unsupported, otherwise forwards unchanged.
    fn request(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        self.input_bytes += packet.len() as u64;
        let mut f = Fields(&packet[4..]);
        let kind = f.take(1)?[0];
        if !self.init {
            if kind != 1 || f.u32()? != 3 {
                return malformed();
            }
            f.end()?;
            self.init = true;
            return Ok(None);
        }
        if !self.version {
            return malformed();
        }
        let id = f.u32()?;
        if self.pending.contains_key(&id) {
            return malformed();
        }
        let request = match kind {
            3 | 11 => {
                let name = path(f.string()?);
                let flags = if kind == 3 {
                    let flags = f.u32()?;
                    if flags & !63 != 0 {
                        return malformed();
                    }
                    f.attrs()?;
                    flags
                } else {
                    0
                };
                Request::Open {
                    path: name,
                    flags,
                    directory: kind == 11,
                }
            }
            4 => Request::Close(f.handle()?.to_vec()),
            5 | 6 => {
                let handle = f.handle()?.to_vec();
                let offset = f.u64()?;
                let write = kind == 6;
                let data = if write { Some(f.string()?) } else { None };
                let length = if let Some(data) = data {
                    data.len() as u32
                } else {
                    f.u32()?
                };
                if length as usize > MAX_PACKET {
                    return malformed();
                }
                let file = self
                    .handles
                    .get_mut(&handle)
                    .ok_or(ErrorCode::InvalidArgument)?;
                if file.directory {
                    return malformed();
                }
                let seq = if let Some(data) = data {
                    file.write.add(offset, data);
                    file.write_issued += 1;
                    0 // WRITE responses only need their length, never their payload or order.
                } else {
                    let seq = file.read_issued;
                    file.read_issued += 1;
                    seq
                };
                Request::Io {
                    handle,
                    seq,
                    offset,
                    length,
                    write,
                }
            }

            7 | 16 | 17 | 19 => {
                f.string()?;
                Request::Metadata(kind)
            }
            8 | 12 => {
                f.handle()?;
                Request::Metadata(kind)
            }
            9 | 10 | 13 | 14 | 15 | 18 | 20 => {
                let name = if kind == 10 { f.handle()? } else { f.string()? };
                let name = if kind == 10 {
                    self.handles
                        .get(name)
                        .ok_or(ErrorCode::InvalidArgument)?
                        .path
                        .clone()
                } else {
                    path(name)
                };
                let target_path = if matches!(kind, 18 | 20) {
                    Some(path(f.string()?))
                } else {
                    None
                };
                if matches!(kind, 9 | 10 | 14) {
                    f.attrs()?;
                }
                let operation = match kind {
                    9 => SftpOp::Setstat,
                    10 => SftpOp::Fsetstat,
                    13 => SftpOp::Remove,
                    14 => SftpOp::Mkdir,
                    15 => SftpOp::Rmdir,
                    18 => SftpOp::Rename,
                    _ => SftpOp::Symlink,
                };
                Request::Mutation(operation, name, target_path)
            }
            200 => {
                let extension = f.string()?;
                if !EXTENSIONS.contains(&extension) {
                    let response = unsupported(id);
                    self.output_bytes += response.len() as u64;
                    return Ok(Some(response));
                }
                let name =
                    std::str::from_utf8(extension).map_err(|_| ErrorCode::InvalidArgument)?;
                let request = match name {
                    "posix-rename@openssh.com" | "hardlink@openssh.com" => {
                        let source = path(f.string()?);
                        let target = Some(path(f.string()?));
                        Request::Mutation(
                            if name.starts_with("posix") {
                                SftpOp::PosixRename
                            } else {
                                SftpOp::Hardlink
                            },
                            source,
                            target,
                        )
                    }
                    "fsync@openssh.com" | "fstatvfs@openssh.com" => {
                        f.handle()?;
                        Request::Extension(if name.starts_with("fsync") { 0 } else { 88 })
                    }
                    "statvfs@openssh.com" => {
                        f.string()?;
                        Request::Extension(88)
                    }
                    _ => Request::Extension(32),
                };
                *self.counts.entry(name.into()).or_default() += 1;
                request
            }
            _ => return malformed(),
        };
        f.end()?;
        if self.pending.len() >= MAX_PENDING {
            return malformed();
        }
        *self.counts.entry(op(kind).into()).or_default() += 1;
        self.pending.insert(id, request);
        Ok(None)
    }
    fn response(&mut self, packet: &[u8]) -> Result<(Vec<Audit>, Option<Vec<u8>>)> {
        let mut f = Fields(&packet[4..]);
        let kind = f.take(1)?[0];
        if !self.version {
            if !self.init || kind != 2 || f.u32()? != 3 {
                return malformed();
            }
            let mut filtered = vec![0, 0, 0, 0, 2, 0, 0, 0, 3];
            while !f.0.is_empty() {
                let name = f.string()?;
                let version = f.string()?;
                if EXTENSIONS.contains(&name) {
                    string(name, &mut filtered);
                    string(version, &mut filtered);
                }
            }
            frame_length(&mut filtered);
            self.output_bytes += filtered.len() as u64;
            self.version = true;
            return Ok((vec![], Some(filtered)));
        }
        self.output_bytes += packet.len() as u64;
        let id = f.u32()?;
        let request = self.pending.remove(&id).ok_or(ErrorCode::InvalidArgument)?;
        let mut audits = Vec::new();
        let mut status = None;
        let mut handle = None;
        let mut data = None;
        match kind {
            101 => {
                status = Some(f.u32()?);
                f.string()?;
                f.string()?;
            }
            102 => {
                handle = Some(f.handle()?.to_vec());
            }
            103 => {
                data = Some(f.string()?);
            }
            104 => {
                let count = f.u32()?;
                if count as usize > f.0.len() / 12 {
                    return malformed();
                }
                for _ in 0..count {
                    f.string()?;
                    f.string()?;
                    f.attrs()?;
                }
            }
            105 => f.attrs()?,
            201 => {
                f.0 = &[];
            }
            _ => return malformed(),
        }
        f.end()?;
        match request {
            Request::Open {
                path,
                flags,
                directory,
            } => {
                if let Some(handle) = handle {
                    if self.handles.len() >= MAX_HANDLES || self.handles.contains_key(&handle) {
                        return malformed();
                    }
                    self.handles
                        .insert(handle, File::new(path, flags, directory));
                } else {
                    let status = status
                        .filter(|code| *code != 0)
                        .ok_or(ErrorCode::InvalidArgument)?;
                    if !directory && flags & 0x1e != 0 {
                        audits.push(SftpAudit::File {
                            path,
                            flags,
                            status: Some(status),
                            read_bytes: 0,
                            write_bytes: 0,
                            sha256: None,
                            read_sha256: None,
                            write_sha256: None,
                        });
                    }
                }
            }
            Request::Close(handle) => {
                let status = status.ok_or(ErrorCode::InvalidArgument)?;
                if status == 0 {
                    if let Some(file) = self.handles.remove(&handle) {
                        if !file.directory {
                            audits.push(file.audit(Some(status)));
                        }
                    }
                }
            }
            Request::Io {
                handle,
                seq,
                offset,
                length,
                write,
            } => {
                let file = self
                    .handles
                    .get_mut(&handle)
                    .ok_or(ErrorCode::InvalidArgument)?;
                if write {
                    if status.ok_or(ErrorCode::InvalidArgument)? == 0 {
                        file.write_acked_ok += 1;
                        file.write.bytes += length as u64;
                    } else {
                        file.write_failed += 1;
                    }
                } else {
                    let bytes = if let Some(data) = data {
                        if data.len() > length as usize {
                            return malformed();
                        }
                        Some(data)
                    } else {
                        let code = status
                            .filter(|code| *code != 0)
                            .ok_or(ErrorCode::InvalidArgument)?;
                        if code == 1 {
                            Some(&[][..])
                        } else {
                            None
                        }
                    };
                    file.read_response(seq, offset, bytes);
                }
            }
            Request::Mutation(op, path, target_path) => {
                audits.push(SftpAudit::Operation {
                    op,
                    path,
                    target_path,
                    status: status.ok_or(ErrorCode::InvalidArgument)?,
                });
            }
            Request::Metadata(k) => {
                let valid = match k {
                    7 | 8 | 17 => kind == 105,
                    12 | 16 | 19 => kind == 104,
                    _ => false,
                };
                if status.is_none() && !valid {
                    return malformed();
                }
            }
            Request::Extension(length) => {
                if status.is_none() && (length == 0 || kind != 201 || packet.len() != 9 + length) {
                    return malformed();
                }
            }
        }
        // Hash bookkeeping must never abort a valid transfer. A missing early READ reply can
        // otherwise retain arbitrarily many later replies even with only 128 in flight at once.
        let (bytes, records) = self
            .handles
            .values()
            .flat_map(|h| h.completed.values())
            .fold((0, 0), |(bytes, records), (_, data)| {
                (bytes + data.as_ref().map_or(0, Vec::len), records + 1)
            });
        if bytes > 4 * MAX_PACKET || records > MAX_PENDING {
            for file in self
                .handles
                .values_mut()
                .filter(|f| !f.completed.is_empty())
            {
                file.read.discontinuous = true;
                file.completed.clear();
            }
        }
        Ok((audits, None))
    }
    fn finish(&mut self) -> Vec<Audit> {
        let mut audits = Vec::new();
        for (_, file) in self.handles.drain() {
            if !file.directory {
                audits.push(file.audit(None));
            }
        }
        audits.push(SftpAudit::Session {
            requests: self.counts.clone(),
            input_bytes: self.input_bytes,
            output_bytes: self.output_bytes,
        });
        audits
    }
}
fn unsupported(id: u32) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 0, 101];
    bytes.extend(id.to_be_bytes());
    bytes.extend(8u32.to_be_bytes());
    bytes.extend(0u32.to_be_bytes());
    bytes.extend(0u32.to_be_bytes());
    let n = (bytes.len() - 4) as u32;
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    bytes
}
async fn packet(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    // Distinguish clean EOF at a packet boundary from a truncated length/payload.
    if reader
        .read(&mut length[..1])
        .await
        .map_err(|_| ErrorCode::TargetUnreachable)?
        == 0
    {
        return Ok(None);
    }
    reader
        .read_exact(&mut length[1..])
        .await
        .map_err(|_| ErrorCode::InvalidArgument)?;
    let n = u32::from_be_bytes(length) as usize;
    if n == 0 || n > MAX_PACKET {
        return malformed();
    }
    let mut bytes = vec![0; n + 4];
    bytes[..4].copy_from_slice(&length);
    reader
        .read_exact(&mut bytes[4..])
        .await
        .map_err(|_| ErrorCode::InvalidArgument)?;
    Ok(Some(bytes))
}
async fn audits(backend: &dyn GatewayBackend, connection: &Connection, entries: Vec<Audit>) {
    let deadline = Instant::now() + Duration::from_secs(2);
    for entry in entries {
        let action = match &entry {
            SftpAudit::Operation { op, .. } => op.as_action(),
            SftpAudit::File { .. } => "sftp.file",
            SftpAudit::Session { .. } => "sftp.session",
        };
        match tokio::time::timeout_at(deadline, backend.sftp_audit(connection, &entry)).await {
            Ok(Ok(())) => {}
            Ok(Err(code)) => {
                tracing::error!(connection=%connection.id,action,?code,"SFTP audit not recorded")
            }
            Err(_) => {
                tracing::error!(connection=%connection.id,action,"SFTP audit deadline exceeded");
                break;
            }
        }
    }
}
pub(super) async fn run(
    connection: &Connection,
    backend: Arc<dyn GatewayBackend>,
    client: Channel<server::Msg>,
    upstream: Channel<client::Msg>,
    stop: &CancellationToken,
    activity: &Mutex<Instant>,
    stall: Duration,
) {
    let state = Mutex::new(Proxy::default());
    let output_stop = stop.child_token();
    let (mut from_client, to_client) = client.split();
    let (mut from_target, to_target) = upstream.split();
    // Serialize locally generated STATUS with target packets so SSH packet fragmentation cannot
    // interleave two SFTP frames. Mutex is never held while inspecting protocol state.
    let to_client = tokio::sync::Mutex::new(to_client);
    let input = async {
        let mut reader = from_client.make_reader();
        while let Some(bytes) = packet(&mut reader).await? {
            *activity.lock().unwrap() = Instant::now();
            let response = state.lock().unwrap().request(&bytes)?;
            let send = async {
                if let Some(response) = response {
                    to_client
                        .lock()
                        .await
                        .data_bytes(Bytes::from(response))
                        .await
                } else {
                    to_target.data_bytes(Bytes::from(bytes)).await
                }
            };
            timeout(stall, send)
                .await
                .map_err(|_| ErrorCode::TargetTimeout)?
                .map_err(|_| ErrorCode::TargetUnreachable)?;
        }
        let _ = to_target.eof().await;
        Ok::<_, ErrorCode>(())
    };
    let output = async {
        let mut reader = from_target.make_reader();
        loop {
            let bytes = tokio::select! {biased;
                _=output_stop.cancelled()=>return Ok::<_,ErrorCode>(()),
                packet=packet(&mut reader)=>packet?,
            };
            let Some(bytes) = bytes else {
                return Ok(());
            };
            let (entries, filtered) = state.lock().unwrap().response(&bytes)?;
            let bytes = filtered.unwrap_or(bytes);
            audits(backend.as_ref(), connection, entries).await;
            tokio::select! {biased;
                _=output_stop.cancelled()=>return Ok(()),
                written=timeout(stall,async {to_client.lock().await.data_bytes(Bytes::from(bytes)).await})=>
                    written.map_err(|_|ErrorCode::TargetTimeout)?.map_err(|_|ErrorCode::TargetUnreachable)?,
            }
        }
    };
    {
        tokio::pin!(input);
        tokio::pin!(output);
        let output_done = tokio::select! {
            _=stop.cancelled()=>false,
            result=&mut input=> if result.is_ok() {
                tokio::select! {_=stop.cancelled()=>false,result=timeout(stall,&mut output)=>result.is_ok()}
            } else {false},
            _=&mut output=>true,
        };
        output_stop.cancel();
        // A response may already have removed a file from the handle table. Never drop its
        // in-flight audit on disconnect: allow its bounded batch to settle before final summaries.
        if !output_done {
            let _ = (&mut output).await;
        }
    }
    let _ = timeout(Duration::from_secs(1), to_target.close()).await;
    let entries = state.lock().unwrap().finish();
    audits(backend.as_ref(), connection, entries).await;
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub fn frame(kind: u8, id: u32, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0; 4];
        v.push(kind);
        v.extend(id.to_be_bytes());
        v.extend(body);
        frame_length(&mut v);
        v
    }
    pub fn string(value: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        super::string(value, &mut v);
        v
    }
    pub fn status(id: u32, code: u32) -> Vec<u8> {
        let mut b = code.to_be_bytes().to_vec();
        b.extend([0; 8]);
        frame(101, id, &b)
    }
    fn respond(p: &mut Proxy, bytes: &[u8]) -> Vec<Audit> {
        let (audits, _) = p.response(bytes).unwrap();
        audits
    }
    fn proxy() -> Proxy {
        let mut p = Proxy::default();
        p.request(&[0, 0, 0, 5, 1, 0, 0, 0, 3]).unwrap();
        respond(&mut p, &[0, 0, 0, 5, 2, 0, 0, 0, 3]);
        p
    }
    fn open(p: &mut Proxy) {
        let mut b = string(b"/tmp/file");
        b.extend(3u32.to_be_bytes());
        b.extend([0; 4]);
        p.request(&frame(3, 1, &b)).unwrap();
        respond(p, &frame(102, 1, &string(b"h")));
    }
    fn io(p: &mut Proxy, id: u32, write: bool, offset: u64, bytes: &[u8]) {
        let mut b = string(b"h");
        b.extend(offset.to_be_bytes());
        if write {
            b.extend(string(bytes));
        } else {
            b.extend((bytes.len() as u32).to_be_bytes());
        }
        p.request(&frame(if write { 6 } else { 5 }, id, &b))
            .unwrap();
    }
    fn close(p: &mut Proxy) -> SftpAudit {
        p.request(&frame(4, 999, &string(b"h"))).unwrap();
        respond(p, &status(999, 0)).pop().unwrap()
    }
    fn file(entry: SftpAudit) -> (Option<u32>, u64, u64, Option<String>) {
        match entry {
            SftpAudit::File {
                status,
                read_bytes,
                write_bytes,
                sha256,
                ..
            } => (status, read_bytes, write_bytes, sha256),
            _ => panic!("expected file"),
        }
    }
    #[test]
    fn sixty_four_large_writes_keep_only_metadata_and_hash_after_all_acks() {
        let mut p = proxy();
        open(&mut p);
        let data = vec![b'x'; 261120];
        let mut hash = Sha256::new();
        for i in 0..64 {
            io(&mut p, i + 2, true, i as u64 * data.len() as u64, &data);
            hash.update(&data);
        }
        assert!(p.handles[b"h".as_slice()].completed.is_empty());
        assert_eq!(p.pending.len(), 64);
        for id in (2..66).rev() {
            respond(&mut p, &status(id, 0));
        }
        assert_eq!(
            file(close(&mut p)),
            (
                Some(0),
                0,
                64 * data.len() as u64,
                Some(format!("{:x}", hash.finalize()))
            )
        );
    }
    #[test]
    fn sequential_reads_and_reordered_responses_hash_in_request_order() {
        let mut p = proxy();
        open(&mut p);
        io(&mut p, 2, false, 0, b"abc");
        io(&mut p, 3, false, 3, b"def");
        respond(&mut p, &frame(103, 3, &string(b"def")));
        respond(&mut p, &frame(103, 2, &string(b"abc")));
        assert_eq!(
            file(close(&mut p)),
            (
                Some(0),
                6,
                0,
                Some(format!("{:x}", Sha256::digest(b"abcdef")))
            )
        );
    }
    #[test]
    fn random_offsets_failed_writes_and_unacked_writes_never_claim_hashes() {
        for write in [true, false] {
            let mut p = proxy();
            open(&mut p);
            io(&mut p, 2, write, 99, b"abc");
            respond(
                &mut p,
                &if write {
                    status(2, 0)
                } else {
                    frame(103, 2, &string(b"abc"))
                },
            );
            assert!(file(close(&mut p)).3.is_none());
        }
        let mut p = proxy();
        open(&mut p);
        for id in 2..5 {
            io(&mut p, id, true, (id as u64 - 2) * 3, b"abc");
        }
        respond(&mut p, &status(2, 0));
        respond(&mut p, &status(3, 3));
        respond(&mut p, &status(4, 0));
        assert_eq!(file(close(&mut p)), (Some(0), 0, 6, None));
        let mut p = proxy();
        open(&mut p);
        io(&mut p, 2, true, 0, b"abc");
        assert_eq!(file(p.finish().remove(0)), (None, 0, 0, None));
    }
    #[test]
    fn reordered_read_over_budget_discards_hash_without_closing_or_losing_counts() {
        let mut p = proxy();
        open(&mut p);
        let data = vec![1; MAX_PACKET - 64];
        for id in 2..9 {
            io(
                &mut p,
                id,
                false,
                (id as u64 - 2) * data.len() as u64,
                &data,
            );
        }
        for id in 3..9 {
            respond(&mut p, &frame(103, id, &string(&data)));
        }
        assert!(p.handles[b"h".as_slice()].completed.is_empty());
        respond(&mut p, &frame(103, 2, &string(&data)));
        assert_eq!(
            file(close(&mut p)),
            (Some(0), 7 * data.len() as u64, 0, None)
        );
    }
    #[test]
    fn failed_close_preserves_handle_and_failed_write_open_has_file_audit() {
        let mut p = proxy();
        open(&mut p);
        p.request(&frame(4, 2, &string(b"h"))).unwrap();
        assert!(respond(&mut p, &status(2, 4)).is_empty());
        assert_eq!(p.handles.len(), 1);
        assert_eq!(file(p.finish().remove(0)).0, None);
        for (flags, code, expected) in [(0x1a, 3, true), (1, 2, false)] {
            let mut p = proxy();
            let mut b = string(b"/denied");
            b.extend((flags as u32).to_be_bytes());
            b.extend([0; 4]);
            p.request(&frame(3, 7, &b)).unwrap();
            let entries = respond(&mut p, &status(7, code));
            assert_eq!(!entries.is_empty(), expected);
            if expected {
                assert_eq!(file(entries[0].clone()), (Some(3), 0, 0, None));
            }
        }
    }
    #[test]
    fn version_filters_only_six_allowed_extensions_and_preserves_bytes_and_order() {
        let mut p = Proxy::default();
        p.request(&[0, 0, 0, 5, 1, 0, 0, 0, 3]).unwrap();
        let mut version = vec![0, 0, 0, 0, 2, 0, 0, 0, 3];
        let mut expected = version.clone();
        for name in [
            b"copy-data".as_slice(),
            b"posix-rename@openssh.com",
            b"statvfs@openssh.com",
            b"fstatvfs@openssh.com",
            b"fsync@openssh.com",
            b"lsetstat@openssh.com",
            b"hardlink@openssh.com",
            b"limits@openssh.com",
            b"expand-path@openssh.com",
            b"home-directory",
            b"users-groups-by-id@openssh.com",
        ] {
            super::string(name, &mut version);
            super::string(b"version-data\xff", &mut version);
            if EXTENSIONS.contains(&name) {
                super::string(name, &mut expected);
                super::string(b"version-data\xff", &mut expected);
            }
        }
        frame_length(&mut version);
        frame_length(&mut expected);
        assert_eq!(p.response(&version).unwrap().1, Some(expected));
        let mut p = Proxy::default();
        p.request(&[0, 0, 0, 5, 1, 0, 0, 0, 3]).unwrap();
        let bare = [0, 0, 0, 5, 2, 0, 0, 0, 3];
        assert_eq!(p.response(&bare).unwrap().1, Some(bare.to_vec()));
        let mut p = Proxy::default();
        p.request(&[0, 0, 0, 5, 1, 0, 0, 0, 3]).unwrap();
        version.pop();
        assert!(p.response(&version).is_err());
    }
    #[test]
    fn mutations_metadata_extensions_and_fsync_have_expected_audit_policy() {
        let mut p = proxy();
        open(&mut p);
        for (kind, op) in [
            (9, SftpOp::Setstat),
            (10, SftpOp::Fsetstat),
            (13, SftpOp::Remove),
            (14, SftpOp::Mkdir),
            (15, SftpOp::Rmdir),
            (18, SftpOp::Rename),
            (20, SftpOp::Symlink),
        ] {
            let mut b = string(if kind == 10 { b"h" } else { b"/source" });
            if matches!(kind, 9 | 10 | 14) {
                b.extend([0; 4]);
            }
            if matches!(kind, 18 | 20) {
                b.extend(string(b"/target"));
            }
            p.request(&frame(kind, kind as u32, &b)).unwrap();
            assert!(
                matches!(&respond(&mut p,&status(kind as u32,3))[0],SftpAudit::Operation{op:actual,status:3,..} if *actual==op)
            );
        }
        let mut b = string(b"fsync@openssh.com");
        b.extend(string(b"h"));
        p.request(&frame(200, 30, &b)).unwrap();
        assert!(respond(&mut p, &status(30, 0)).is_empty());
        let reply = p
            .request(&frame(200, 31, &string(b"unknown@example")))
            .unwrap()
            .unwrap();
        assert_eq!(reply, unsupported(31));
        p.request(&frame(17, 32, &string(b"/file"))).unwrap();
        assert!(respond(&mut p, &frame(105, 32, &[0; 4])).is_empty());
        assert!(
            matches!(p.finish().last().unwrap(),SftpAudit::Session{requests,..} if requests["fsync@openssh.com"]==1 && requests["stat"]==1 && requests["extended"]==1)
        );
        for (name, size) in [("statvfs@openssh.com", 88), ("limits@openssh.com", 32)] {
            let mut b = string(name.as_bytes());
            if name.starts_with("statvfs") {
                b.extend(string(b"/"));
            }
            p.request(&frame(200, 33, &b)).unwrap();
            assert!(respond(&mut p, &frame(201, 33, &vec![0; size])).is_empty());
        }
    }
    #[test]
    fn malformed_version_fields_ids_and_response_types_are_rejected() {
        let mut p = Proxy::default();
        assert!(p.request(&[0, 0, 0, 5, 1, 0, 0, 0, 4]).is_err());
        let mut p = Proxy::default();
        p.request(&[0, 0, 0, 5, 1, 0, 0, 0, 3]).unwrap();
        assert!(p.response(&[0, 0, 0, 5, 2, 0, 0, 0, 4]).is_err());
        let mut p = proxy();
        assert!(p.request(&frame(42, 1, &[])).is_err());
        let mut p = proxy();
        assert!(p.request(&frame(3, 1, &[0, 0, 0, 99])).is_err());
        let mut p = proxy();
        p.request(&frame(17, 1, &string(b"/"))).unwrap();
        assert!(p.request(&frame(17, 1, &string(b"/"))).is_err());
        assert!(p.response(&frame(102, 1, &string(b"wrong"))).is_err());
        assert!(p.response(&status(900, 0)).is_err());
    }
    #[tokio::test]
    async fn packet_boundary_allows_256k_payload_but_not_256k_plus_one() {
        let mut max = vec![0; MAX_PACKET + 4];
        max[..4].copy_from_slice(&(MAX_PACKET as u32).to_be_bytes());
        assert_eq!(packet(&mut &max[..]).await.unwrap(), Some(max));
        assert!(packet(&mut &[0, 4, 0, 1][..]).await.is_err());
        assert!(packet(&mut &[0, 0][..]).await.is_err());
        assert!(packet(&mut &[0, 0, 0, 5, 1][..]).await.is_err());
        let (mut w, mut r) = tokio::io::duplex(2);
        let bytes = vec![0, 0, 0, 5, 1, 0, 0, 0, 3];
        let expected = bytes.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for b in bytes {
                w.write_all(&[b]).await.unwrap();
            }
        });
        assert_eq!(packet(&mut r).await.unwrap(), Some(expected));
        assert!(packet(&mut r).await.unwrap().is_none());
    }
    #[test]
    fn pending_and_handle_limits_remain_enforced() {
        let mut p = proxy();
        for id in 0..MAX_PENDING {
            p.request(&frame(17, id as u32, &string(b"/"))).unwrap();
        }
        assert!(p.request(&frame(17, 999, &string(b"/"))).is_err());
        // A locally answered extension consumes no upstream slot even with a full pipeline.
        assert_eq!(
            p.request(&frame(200, 1001, &string(b"unsupported@example")))
                .unwrap(),
            Some(unsupported(1001))
        );
        let mut p = proxy();
        for i in 0..MAX_HANDLES {
            p.handles.insert(
                i.to_be_bytes().to_vec(),
                File::new(b"file".to_vec(), 1, false),
            );
        }
        let mut b = string(b"/file");
        b.extend(1u32.to_be_bytes());
        b.extend([0; 4]);
        p.request(&frame(3, 2, &b)).unwrap();
        assert!(p.response(&frame(102, 2, &string(b"new"))).is_err());
    }
}
