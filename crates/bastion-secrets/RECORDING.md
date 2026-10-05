# RFC-004 recording codec (`bastion-secrets::recording`)

This module implements recording-only key envelopes and the fixed `ZTREC001`
format. Existing credential purposes and serialized AAD are unchanged. No new
dependency, database integration, filesystem opening or asynchronous queue is
introduced here.

## Credential KEK rotation companion

```rust
KeyRing::rewrap_credential_dek(&self, context: &CipherContext, envelope: &Envelope)
    -> anyhow::Result<Envelope>
```

Authenticates and validates the existing credential via unchanged `open`, then
unwraps the same DEK under its old KEK and rewraps it under the active KEK using
a fresh wrap nonce. `ciphertext`, data `nonce`, identity, kind and revision are
unchanged. The credential AAD tuples and both existing purpose strings remain
unchanged. DEK and temporary decoded credential are zeroized. The caller must
atomically persist only `wrapped_dek`, `wrap_nonce`, and `key_version` using the
original envelope/version as a concurrency guard; never bump credential
revision for a KEK-only rotation. Keep old KEKs configured until every envelope
using them has been rotated and verified. Missing old key, wrong context,
malformed envelope or tampered ciphertext are rejected, not silently migrated.

## Public interfaces

All fallible methods return `anyhow::Result<T>`; errors can be downcast to
`RecordingError`.

```rust
RecordingContext { server_id: String, recording_id: Uuid }
RecordingContext::new(server_id: impl Into<String>, recording_id: Uuid) -> Self
RecordingHeader { recording_id: Uuid, nonce_prefix: [u8; 16] }
RecordingHeader::new(recording_id: Uuid) -> Self // random prefix
RecordingEnvelope { wrapped_dek: Vec<u8>, wrap_nonce: Vec<u8>, key_version: i64 }
// RecordingKey is opaque, non-cloneable, redacted, and zeroized on drop.

KeyRing::new_recording_dek(&self, &RecordingContext)
    -> Result<(RecordingKey, RecordingEnvelope)>
KeyRing::wrap_recording_dek(&self, &RecordingContext, &RecordingKey)
    -> Result<RecordingEnvelope>
KeyRing::open_recording_dek(&self, &RecordingContext, &RecordingEnvelope)
    -> Result<RecordingKey>
KeyRing::rewrap_recording_dek(&self, &RecordingContext, &RecordingEnvelope)
    -> Result<RecordingEnvelope>

RecordingWriter<W: std::io::Write>::new(W, RecordingHeader, RecordingKey)
    -> Result<Self>
RecordingWriter::header(&self) -> &RecordingHeader
RecordingWriter::writer_mut(&mut self) -> &mut W
RecordingWriter::bytes_written(&self) -> u64
RecordingWriter::append_ndjson(&mut self, plaintext: &[u8]) -> Result<RecordingAck>
RecordingWriter::finish(self) -> Result<W>
RecordingAck { chunk_seq: u64, bytes_written: u64 }

RecordingReader<R: std::io::Read>::new(R, expected: &RecordingHeader, RecordingKey)
    -> Result<Self>
RecordingReader::header(&self) -> &RecordingHeader
RecordingReader::next_chunk(&mut self) -> Result<Option<VerifiedChunk>>
RecordingReader::into_inner(self) -> R
VerifiedChunk { chunk_seq: u64, plaintext: Zeroizing<Vec<u8>> }
```

`RecordingAck` means `write_all` and `flush` succeeded, **not** `fsync`.
`bytes_written` includes the header and all acknowledged complete frames.
Callers own create-new owner-only/no-follow file opening, bounded queues,
250ms batching, 5-second timeouts, periodic sync, final sync, checksum, metadata
last-written/last-synced boundaries, and fail-closed channel shutdown. A codec
must never be recreated to retry a failed append; any error poisons that writer.
`writer_mut` is only for syncing or observing the sink: never seek/write through
it. New writers require a fresh recording DEK/prefix and an empty create-new
sink. There is deliberately no initial-sequence, append-existing or resume API.

The reader requires both the expected UUID and 16-byte nonce prefix from trusted
metadata. It releases only authenticated, complete and validated event lines.
A released chunk is a **verified prefix**, not proof of a complete recording.
Call until `Ok(None)`: clean EOF requires a final `end` event. Even truncation at
a whole-frame boundary fails when the final `end` is missing. Check the stored
final bytes/checksum separately, and terminate the HTTP stream with a visible
verification error on any mismatch rather than silently returning a clean
response. Header integrity is established by the first frame's AEAD; a header
alone is incomplete. A malicious rewrite of both database and file by the
trusted gateway administrator is outside the stated RFC checksum guarantees.

## Wire and event validation

Integers are big-endian. Header JSON has exactly `format_version:1`, canonical
UUID `recording_id`, `algorithm:"XChaCha20-Poly1305"` and unpadded base64url
`nonce_prefix`. Header maximum is 16 KiB; ciphertext maximum is 256 KiB + 16-byte
tag. The nonce is prefix + big-endian chunk sequence. AAD is the exact ASCII
`zt-record-v1` + SHA256(magic + encoded header length + **original header bytes**)
+ raw UUID + big-endian chunk sequence. Chunk sequence begins at zero and is
continuous. Recording wrapping AAD is the JSON array
`["zt-recording-wrap-v1", server_id, recording_id]`; rewrapping changes only the
KEK envelope, not the DEK, file, nonce prefix or chunk sequence.

Every plaintext is one or more complete JSON lines ending in LF. Blank lines,
unknown event types/fields, invalid JSON/UTF-8, event sequence gaps and decreasing
`elapsed_us` fail validation. Required shapes (each line ends in LF):

```json
{"seq":0,"elapsed_us":0,"type":"meta","format_version":1,"term":"xterm-256color","cols":80,"rows":24}
{"seq":1,"elapsed_us":123,"type":"output","stream":"stdout","data_base64":"aGVsbG8NCg=="}
{"seq":2,"elapsed_us":124,"type":"resize","cols":100,"rows":30}
{"seq":3,"elapsed_us":125,"type":"exit","exit_code":0}
{"seq":4,"elapsed_us":126,"type":"end","reason":"closed"}
```

The first event must be `meta`, with nonempty `term` and positive dimensions.
`output` accepts `stdout` or `stderr`, standard padded base64 and 1..=32 KiB raw
bytes; no per-chunk UTF-8 decoding is performed. `resize` requires positive
dimensions. `exit` has exactly one non-null `exit_code` (u32) or `exit_signal`
(nonempty string); the other can be absent or null. `end` requires a nonempty
reason and forbids later events. Event sequence and chunk sequence are separate.

## Error classification

- `UnknownKey(version)`: configured ring lacks the envelope KEK, before opening
  file content. Never try another key or credential-purpose AAD.
- `Integrity`: DEK unwrap or frame AEAD authentication failed.
- `Truncated`: incomplete header/frame or clean EOF without final `end`.
- `Invalid(static_reason)`: malformed/unsupported header, trusted metadata
  mismatch, length/sequence bounds or event schema violation.
- `Io(error)`: underlying source/sink failed.
- `Poisoned`: any use following a reader/writer failure; seal and stop, never
  resume under that recording key/sequence.

Map integrity/invalid to corrupt, incomplete tails to partial, and missing KEKs
to an explicit operational failure. The caller decides database status naming;
no failure permits unrecorded shell output or publicly exposed file paths.

## Focused checks and vector

Run `cargo test -p bastion-secrets recording`. The golden codec test pins header,
nonce/AAD layout and a deterministic encrypted file vector. Its UUID is
`00112233-4455-6677-8899-aabbccddeeff`, key is 32 bytes of `42` hex, and prefix is
16 bytes of `10` hex. These fixed values exist only in tests; production uses
OS randomness. The complete two-frame vector (standard base64) is:

```text
WlRSRUMwMDEAAACTeyJmb3JtYXRfdmVyc2lvbiI6MSwicmVjb3JkaW5nX2lkIjoiMDAxMTIyMzMtNDQ1NS02Njc3LTg4OTktYWFiYmNjZGRlZWZmIiwiYWxnb3JpdGhtIjoiWENoYUNoYTIwLVBvbHkxMzA1Iiwibm9uY2VfcHJlZml4IjoiRUJBUUVCQVFFQkFRRUJBUUVCQVFFQSJ9AAAAAAAAAAAAAABtK2gnM7Ps9b+mWSkoKCzyCSSgK+UyCklQkR2mkSQBd5efSnamPo335vEBM9DtGxBomOR9SoHV/QvYAV4KzufSMCOVL8xkMHE3PNh1H4pL9mIXPCvTkXXWQQ0jj/sZBZ9b7DMeGNJluNyaM4mC4wAAAAAAAAABAAAASL/T8EmKSr6OFkdfcGUJbQWVhMLEfqLflOT10KfbHcD/LJlEK5+O5qn0HXG5md11CVVH1OhzMD1my+2VzBNjH6vpt8484CKi/A==
```

Its plaintext frames are respectively:

```json
{"seq":0,"elapsed_us":0,"type":"meta","format_version":1,"term":"xterm","cols":80,"rows":24}
{"seq":1,"elapsed_us":1,"type":"end","reason":"closed"}
```

Each is one line followed by LF. Tests additionally cover arbitrary output bytes, stderr/resize/
exit, multi-event batches, every truncated prefix and flipped byte, header and
metadata mismatch, bounds, poisoned I/O, unknown KEKs, purpose/identity binding
and rewrapping without touching the file.
