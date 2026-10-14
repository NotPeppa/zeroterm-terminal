//! RFC-005 recording keys and bounded ZTREC002 framing. File creation, fsync,
//! checksum/metadata persistence and authorization belong to the caller.
use anyhow::{bail, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use bastion_domain::{
    validate_terminal_output, Display, GuacParser, TargetProtocol, MAX_INSTRUCTION_BYTES,
    SSH_STREAM_PROTOCOL, STREAM_PROTOCOL,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const RECORDING_MAGIC: &[u8; 8] = b"ZTREC002";
pub const RECORDING_FORMAT_VERSION: u32 = 2;
pub const MAX_HEADER_LENGTH: usize = 16 * 1024;
pub const MAX_CHUNK_PLAINTEXT: usize = 256 * 1024;
pub const MAX_CHUNK_CIPHERTEXT: usize = MAX_CHUNK_PLAINTEXT + 16;
pub const MAX_OUTPUT_BYTES: usize = 32 * 1024;

/// Deliberately independent from credential identity and purpose AAD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingContext {
    pub server_id: String,
    pub recording_id: Uuid,
    pub connection_id: Uuid,
    pub target_protocol: TargetProtocol,
}
impl RecordingContext {
    pub fn new(
        server_id: impl Into<String>,
        recording_id: Uuid,
        connection_id: Uuid,
        target_protocol: TargetProtocol,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            recording_id,
            connection_id,
            target_protocol,
        }
    }
    pub(crate) fn aad(&self) -> Result<Vec<u8>> {
        if self.server_id.is_empty() {
            bail!(invalid("empty server identity"));
        }
        Ok(serde_json::to_vec(&(
            "zt-recording-wrap-v2",
            &self.server_id,
            self.recording_id,
            self.connection_id,
            self.target_protocol,
            RECORDING_FORMAT_VERSION,
        ))?)
    }
}

/// Opaque, non-cloneable, redacted and zeroized on drop. Never send to clients.
pub struct RecordingKey(pub(crate) Zeroizing<[u8; 32]>);
impl std::fmt::Debug for RecordingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordingKey([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingEnvelope {
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
    pub key_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingHeader {
    pub recording_id: Uuid,
    pub connection_id: Uuid,
    pub target_protocol: TargetProtocol,
    pub stream_protocol: String,
    pub nonce_prefix: [u8; 16],
}
impl RecordingHeader {
    /// Generate once for each fresh DEK/recording; persist before activating it.
    pub fn new(recording_id: Uuid, connection_id: Uuid, target_protocol: TargetProtocol) -> Self {
        let mut nonce_prefix = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);
        Self {
            recording_id,
            connection_id,
            target_protocol,
            stream_protocol: STREAM_PROTOCOL.into(),
            nonce_prefix,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingAck {
    pub chunk_seq: u64,
    /// Includes the header and all complete frames written so far. Not fsynced.
    pub bytes_written: u64,
}

/// Authenticated complete NDJSON lines; still a prefix until the reader reaches
/// clean EOF after an end event. Plaintext is zeroized when dropped.
pub struct VerifiedChunk {
    pub chunk_seq: u64,
    pub plaintext: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for VerifiedChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedChunk")
            .field("chunk_seq", &self.chunk_seq)
            .field("plaintext_bytes", &self.plaintext.len())
            .finish()
    }
}

#[derive(Debug)]
pub enum RecordingError {
    Io(io::Error),
    Invalid(&'static str),
    Truncated,
    Integrity,
    UnknownKey(i64),
    Poisoned,
}
impl std::fmt::Display for RecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "recording I/O failed: {error}"),
            Self::Invalid(reason) => write!(f, "invalid recording: {reason}"),
            Self::Truncated => f.write_str("truncated recording"),
            Self::Integrity => f.write_str("recording integrity failure"),
            Self::UnknownKey(version) => write!(f, "recording KEK version {version} unavailable"),
            Self::Poisoned => f.write_str("recording codec is unusable after failure"),
        }
    }
}
impl std::error::Error for RecordingError {}
fn invalid(reason: &'static str) -> anyhow::Error {
    RecordingError::Invalid(reason).into()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderJson {
    format_version: u32,
    recording_id: String,
    connection_id: Uuid,
    target_protocol: TargetProtocol,
    #[serde(
        default = "guac_stream_protocol",
        skip_serializing_if = "is_guac_stream_protocol"
    )]
    stream_protocol: String,
    algorithm: String,
    nonce_prefix: String,
}
fn guac_stream_protocol() -> String {
    STREAM_PROTOCOL.into()
}
fn is_guac_stream_protocol(value: &str) -> bool {
    value == STREAM_PROTOCOL
}
fn header_bytes(header: &RecordingHeader) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(&HeaderJson {
        format_version: RECORDING_FORMAT_VERSION,
        recording_id: header.recording_id.to_string(),
        connection_id: header.connection_id,
        target_protocol: header.target_protocol,
        stream_protocol: header.stream_protocol.clone(),
        algorithm: "XChaCha20-Poly1305".into(),
        nonce_prefix: URL_SAFE_NO_PAD.encode(header.nonce_prefix),
    })?;
    let mut result = Vec::with_capacity(12 + json.len());
    result.extend_from_slice(RECORDING_MAGIC);
    result.extend_from_slice(&(json.len() as u32).to_be_bytes());
    result.extend_from_slice(&json);
    Ok(result)
}
fn read_exact<R: Read>(reader: &mut R, target: &mut [u8]) -> Result<()> {
    reader.read_exact(target).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            RecordingError::Truncated.into()
        } else {
            RecordingError::Io(error).into()
        }
    })
}
fn parse_header<R: Read>(reader: &mut R) -> Result<(RecordingHeader, [u8; 32])> {
    let mut prefix = [0u8; 12];
    read_exact(reader, &mut prefix)?;
    if &prefix[..8] != RECORDING_MAGIC {
        bail!(invalid("unknown magic"));
    }
    let length = u32::from_be_bytes(prefix[8..].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_HEADER_LENGTH {
        bail!(invalid("header length must be 1..=16 KiB"));
    }
    let mut json = vec![0u8; length];
    read_exact(reader, &mut json)?;
    let parsed: HeaderJson =
        serde_json::from_slice(&json).map_err(|_| invalid("malformed header JSON"))?;
    if parsed.format_version != 2 || parsed.algorithm != "XChaCha20-Poly1305" {
        bail!(invalid("unsupported format or algorithm"));
    }
    if parsed.stream_protocol != STREAM_PROTOCOL
        && !(parsed.stream_protocol == SSH_STREAM_PROTOCOL
            && parsed.target_protocol == TargetProtocol::Ssh)
    {
        bail!(invalid("unsupported stream protocol"));
    }
    let recording_id =
        Uuid::parse_str(&parsed.recording_id).map_err(|_| invalid("invalid UUID"))?;
    if recording_id.to_string() != parsed.recording_id {
        bail!(invalid("UUID must be canonical text"));
    }
    let nonce_prefix = URL_SAFE_NO_PAD
        .decode(&parsed.nonce_prefix)
        .map_err(|_| invalid("invalid unpadded base64url nonce prefix"))?;
    let nonce_prefix: [u8; 16] = nonce_prefix
        .try_into()
        .map_err(|_| invalid("nonce prefix must contain 16 bytes"))?;
    let mut hash = Sha256::new();
    hash.update(prefix);
    hash.update(json);
    Ok((
        RecordingHeader {
            recording_id,
            connection_id: parsed.connection_id,
            target_protocol: parsed.target_protocol,
            stream_protocol: parsed.stream_protocol,
            nonce_prefix,
        },
        hash.finalize().into(),
    ))
}
fn frame_aad(hash: &[u8; 32], recording_id: Uuid, seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(12 + 32 + 16 + 8);
    aad.extend_from_slice(b"zt-record-v2");
    aad.extend_from_slice(hash);
    aad.extend_from_slice(recording_id.as_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}
fn frame_nonce(prefix: &[u8; 16], seq: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

// Parse only the RFC event shapes, not arbitrary JSON or guessed formats.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Meta {
        seq: u64,
        elapsed_us: u64,
        format_version: u32,
        connection_id: String,
        target_protocol: String,
        #[serde(default)]
        stream_protocol: Option<String>,
        width: u32,
        height: u32,
        dpi: u32,
    },
    Output {
        seq: u64,
        elapsed_us: u64,
        data_base64: String,
    },
    End {
        seq: u64,
        elapsed_us: u64,
        reason: String,
    },
}
#[derive(Clone)]
struct EventState {
    next_seq: u64,
    elapsed_us: u64,
    ended: bool,
    connection_id: Uuid,
    target_protocol: TargetProtocol,
    stream_protocol: String,
    output: GuacParser,
}
impl EventState {
    fn new(header: &RecordingHeader) -> Self {
        Self {
            next_seq: 0,
            elapsed_us: 0,
            ended: false,
            connection_id: header.connection_id,
            target_protocol: header.target_protocol,
            stream_protocol: header.stream_protocol.clone(),
            output: GuacParser::new(MAX_INSTRUCTION_BYTES),
        }
    }
    fn validate(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_CHUNK_PLAINTEXT || !bytes.ends_with(b"\n") {
            bail!(invalid(
                "chunk must contain 1..=256 KiB complete NDJSON lines"
            ));
        }
        for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
            if line.is_empty() || self.ended {
                bail!(invalid("empty event or event after end"));
            }
            let event: Event =
                serde_json::from_slice(line).map_err(|_| invalid("malformed event JSON"))?;
            let is_meta = matches!(event, Event::Meta { .. });
            let (seq, elapsed) = match &event {
                Event::Meta {
                    seq,
                    elapsed_us,
                    format_version,
                    connection_id,
                    target_protocol,
                    stream_protocol,
                    width,
                    height,
                    dpi,
                } => {
                    if self.next_seq != 0
                        || *elapsed_us != 0
                        || *format_version != 2
                        || connection_id != &self.connection_id.to_string()
                        || target_protocol != self.target_protocol.as_str()
                        || stream_protocol.as_deref().unwrap_or(STREAM_PROTOCOL)
                            != self.stream_protocol
                        || (Display {
                            width: *width,
                            height: *height,
                            dpi: *dpi,
                        })
                        .validate()
                        .is_err()
                    {
                        bail!(invalid("invalid initial meta event"));
                    }
                    (*seq, *elapsed_us)
                }
                Event::Output {
                    seq,
                    elapsed_us,
                    data_base64,
                } => {
                    if data_base64.len() > MAX_OUTPUT_BYTES.div_ceil(3) * 4 {
                        bail!(invalid("output exceeds limit"));
                    }
                    let decoded = Zeroizing::new(
                        STANDARD
                            .decode(data_base64)
                            .map_err(|_| invalid("invalid output base64"))?,
                    );
                    if decoded.is_empty() || decoded.len() > MAX_OUTPUT_BYTES {
                        bail!(invalid("output must contain 1..=32 KiB raw bytes"));
                    }
                    if self.stream_protocol == SSH_STREAM_PROTOCOL {
                        validate_terminal_output(&decoded)
                            .map_err(|_| invalid("invalid terminal frame"))?;
                    } else {
                        self.output
                            .push(&decoded)
                            .map_err(|_| invalid("invalid incremental Guacamole output"))?;
                    }
                    (*seq, *elapsed_us)
                }
                Event::End {
                    seq,
                    elapsed_us,
                    reason,
                } => {
                    if reason.is_empty()
                        || reason.len() > 128
                        || reason.chars().any(char::is_control)
                    {
                        bail!(invalid("invalid end reason"));
                    }
                    self.output
                        .finish()
                        .map_err(|_| invalid("incomplete Guacamole output at end"))?;
                    self.ended = true;
                    (*seq, *elapsed_us)
                }
            };
            if seq != self.next_seq || elapsed < self.elapsed_us || (self.next_seq == 0 && !is_meta)
            {
                bail!(invalid("event sequence or monotonic time violation"));
            }
            self.next_seq = self
                .next_seq
                .checked_add(1)
                .ok_or_else(|| invalid("event sequence overflow"))?;
            self.elapsed_us = elapsed;
        }
        Ok(())
    }
}

/// Fresh-only codec. The caller MUST pass an empty create-new sink and a fresh
/// recording DEK/prefix. There is no resume/initial-sequence API.
pub struct RecordingWriter<W> {
    writer: W,
    header: RecordingHeader,
    header_hash: [u8; 32],
    key: RecordingKey,
    next_seq: u64,
    bytes_written: u64,
    events: EventState,
    poisoned: bool,
}
impl<W: Write> RecordingWriter<W> {
    pub fn new(mut writer: W, header: RecordingHeader, key: RecordingKey) -> Result<Self> {
        let bytes = header_bytes(&header)?;
        let header_hash = Sha256::digest(&bytes).into();
        writer.write_all(&bytes).map_err(RecordingError::Io)?;
        writer.flush().map_err(RecordingError::Io)?;
        let events = EventState::new(&header);
        Ok(Self {
            writer,
            header,
            header_hash,
            key,
            next_seq: 0,
            bytes_written: bytes.len() as u64,
            events,
            poisoned: false,
        })
    }
    pub fn header(&self) -> &RecordingHeader {
        &self.header
    }
    /// For caller-owned fsync; do not write to or seek the underlying sink.
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
    pub fn append_ndjson(&mut self, plaintext: &[u8]) -> Result<RecordingAck> {
        if self.poisoned {
            bail!(RecordingError::Poisoned);
        }
        // Burn the writer on ANY failure; retrying a partial write risks reuse.
        self.poisoned = true;
        // Every failure permanently poisons this writer, so rollback is neither
        // possible nor needed. Mutate parser state without copying its growing
        // instruction buffer for each 32 KiB output frame.
        self.events.validate(plaintext)?;
        let chunk_seq = self.next_seq;
        let next_seq = chunk_seq
            .checked_add(1)
            .ok_or_else(|| invalid("chunk sequence overflow"))?;
        let nonce = frame_nonce(&self.header.nonce_prefix, chunk_seq);
        let ciphertext = XChaCha20Poly1305::new_from_slice(self.key.0.as_ref())
            .expect("32-byte DEK")
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &frame_aad(&self.header_hash, self.header.recording_id, chunk_seq),
                },
            )
            .map_err(|_| anyhow::Error::new(RecordingError::Integrity))?;
        let bytes_written = self
            .bytes_written
            .checked_add(12 + ciphertext.len() as u64)
            .ok_or_else(|| invalid("recording size overflow"))?;
        let mut frame = Vec::with_capacity(12 + ciphertext.len());
        frame.extend_from_slice(&chunk_seq.to_be_bytes());
        frame.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        self.writer.write_all(&frame).map_err(RecordingError::Io)?;
        self.writer.flush().map_err(RecordingError::Io)?;
        self.next_seq = next_seq;
        self.bytes_written = bytes_written;
        self.poisoned = false;
        Ok(RecordingAck {
            chunk_seq,
            bytes_written,
        })
    }
    /// Requires a final end event. Caller must fsync and persist final checksum.
    pub fn finish(mut self) -> Result<W> {
        if self.poisoned {
            bail!(RecordingError::Poisoned);
        }
        if !self.events.ended {
            bail!(RecordingError::Truncated);
        }
        self.writer.flush().map_err(RecordingError::Io)?;
        Ok(self.writer)
    }
}

/// Returns only authenticated NDJSON chunks, rejects DB/header mismatch and
/// stops permanently on any failure. Read to `Ok(None)` to verify completion.
pub struct RecordingReader<R> {
    reader: R,
    header: RecordingHeader,
    header_hash: [u8; 32],
    key: RecordingKey,
    next_seq: u64,
    events: EventState,
    finished: bool,
    poisoned: bool,
}
impl<R: Read> RecordingReader<R> {
    pub fn new(reader: R, expected: &RecordingHeader, key: RecordingKey) -> Result<Self> {
        Self::open(reader, expected, key, false)
    }
    /// Existing database rows bind recording identity/protocol/nonce, while the
    /// authenticated file header and meta bind the stream renderer.
    pub fn detect_stream(reader: R, expected: &RecordingHeader, key: RecordingKey) -> Result<Self> {
        Self::open(reader, expected, key, true)
    }
    fn open(
        mut reader: R,
        expected: &RecordingHeader,
        key: RecordingKey,
        detect: bool,
    ) -> Result<Self> {
        let (header, header_hash) = parse_header(&mut reader)?;
        let mut binding = header.clone();
        if detect {
            binding.stream_protocol = expected.stream_protocol.clone();
        }
        if &binding != expected {
            bail!(invalid("header does not match recording metadata"));
        }
        let events = EventState::new(&header);
        Ok(Self {
            reader,
            header,
            header_hash,
            key,
            next_seq: 0,
            events,
            finished: false,
            poisoned: false,
        })
    }
    pub fn header(&self) -> &RecordingHeader {
        &self.header
    }
    pub fn next_chunk(&mut self) -> Result<Option<VerifiedChunk>> {
        if self.poisoned {
            bail!(RecordingError::Poisoned);
        }
        if self.finished {
            return Ok(None);
        }
        self.poisoned = true;
        let mut frame_header = [0u8; 12];
        // read_exact handles Interrupted. One-byte read distinguishes clean EOF
        // from a truncated frame without permitting trailing junk.
        match self.reader.read_exact(&mut frame_header[..1]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                if !self.events.ended {
                    bail!(RecordingError::Truncated);
                }
                self.finished = true;
                self.poisoned = false;
                return Ok(None);
            }
            Err(error) => bail!(RecordingError::Io(error)),
        }
        read_exact(&mut self.reader, &mut frame_header[1..])?;
        let chunk_seq = u64::from_be_bytes(frame_header[..8].try_into().unwrap());
        if chunk_seq != self.next_seq {
            bail!(invalid("chunk sequence is not contiguous"));
        }
        let length = u32::from_be_bytes(frame_header[8..].try_into().unwrap()) as usize;
        if !(17..=MAX_CHUNK_CIPHERTEXT).contains(&length) {
            bail!(invalid("ciphertext length exceeds limits"));
        }
        let mut ciphertext = vec![0u8; length];
        read_exact(&mut self.reader, &mut ciphertext)?;
        let nonce = frame_nonce(&self.header.nonce_prefix, chunk_seq);
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(self.key.0.as_ref())
                .expect("32-byte DEK")
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &ciphertext,
                        aad: &frame_aad(&self.header_hash, self.header.recording_id, chunk_seq),
                    },
                )
                .map_err(|_| anyhow::Error::new(RecordingError::Integrity))?,
        );
        self.events.validate(&plaintext)?;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| invalid("chunk sequence overflow"))?;
        self.poisoned = false;
        Ok(Some(VerifiedChunk {
            chunk_seq,
            plaintext,
        }))
    }
    pub fn into_inner(self) -> R {
        self.reader
    }
}

#[cfg(test)]
#[path = "recording_tests.rs"]
mod tests;
