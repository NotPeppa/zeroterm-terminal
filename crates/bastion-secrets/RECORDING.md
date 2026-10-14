# RFC-005 encrypted recording codec (`ZTREC002`)

One connection owns one recording directly, through a UNIQUE connection_id foreign
key. SSH/RDP/VNC share this codec and the same offline Guacamole player. There is
no old-format reader or data conversion. Filesystem permissions, fsync, database
checkpoints, checksum, authorization and retention belong to the gateway/API caller.
The gateway excludes clipboard creation/blob/end and client-owned transfer ACKs
from recorded display output. Clipboard text visible in target images is still
recorded as display. Replay never exposes clipboard operations.

## Identity and keys

RecordingContext binds server_id, recording_id, connection_id, target_protocol and
format version 2. RecordingHeader binds recording_id, connection_id, target_protocol
and a random 16-byte nonce_prefix. The recording DEK is fresh, opaque and zeroized;
KEK wrapping uses recording-specific authenticated data, separate from credentials.

```rust
RecordingContext::new(server_id, recording_id, connection_id, target_protocol)
RecordingHeader::new(recording_id, connection_id, target_protocol)
KeyRing::new_recording_dek(&context)
KeyRing::open_recording_dek(&context, &envelope)
KeyRing::rewrap_recording_dek(&context, &envelope)
```

Rewrap authenticates the existing envelope and wraps the same DEK under the active
KEK without rewriting file bytes. Credential-only rewrap also preserves payload,
identity and revision. Keep every referenced KEK until rotation and verification
finish; persist changed envelopes atomically with concurrency/version checks.

## Container and authenticated events

The file begins with eight-byte ZTREC002 magic, a big-endian u32 JSON-header length
and a bounded header (1..16 KiB). It identifies format_version=2, recording_id,
connection_id, target_protocol, algorithm XChaCha20-Poly1305 and nonce_prefix.
The complete header hash is authenticated by each encrypted chunk. Chunk frames
contain contiguous big-endian u64 sequence, big-endian u32 ciphertext length and
ciphertext including the authentication tag. Plaintext is at most 256 KiB.

Plaintext contains complete NDJSON lines with contiguous event seq and monotonic
elapsed_us. Only these events are permitted:

- meta first: seq=0, elapsed_us=0, format_version=2, connection_id,
  target_protocol, width, height and dpi matching authenticated identity/bounds.
- output: seq, elapsed_us and data_base64 encoding at most 32 KiB of approved
  Guacamole display bytes. Unicode/instructions may span output events.
- end last: seq, elapsed_us and a bounded reason; no events may follow it.

Only post-handshake server display output and timing are recorded. Target
credentials, connect arguments and keyboard/mouse input are excluded. Guacamole
output must end on a valid UTF-8/instruction boundary. No terminal-event format,
channel association, resume API, plaintext guacd recording or arbitrary seek index.

## Write ACKs and failure handling

RecordingWriter::new requires a fresh create-new empty sink, fresh DEK and nonce
prefix. append_ndjson validates events, encrypts, write_all+flushes and only then
returns RecordingAck {chunk_seq, bytes_written}. This ACK is not an fsync promise.
The gateway waits for it before forwarding output, performs periodic fsync and
checkpoint updates, and prepares/syncs metadata before atomic activation.

Any append failure permanently poisons the writer. Never retry a partial write or
reuse sequence/nonces. finish requires end and flush; the caller then fsyncs,
persists checksum/final metadata and ACKs finalization. Open/write/flush/fsync/
checkpoint/finalization failure closes required-recording sessions and leaves
partial/failed state. Process interruption is recovered as partial/failed.

## Read and offline replay

RecordingReader::new authenticates against the expected database header and DEK.
next_chunk returns only authenticated bounded plaintext. Tampering, mismatched
metadata, unknown keys, sequence errors, truncation and invalid events poison the
reader. Only next_chunk == Ok(None) after end and clean EOF verifies the codec.
The caller additionally verifies full-file bytes and SHA-256 checksum.

API playback rechecks authorization, uses owner-only no-follow file access, serves
no-store streamed NDJSON without Range and marks failures explicitly. The browser
uses a read-only offline Guacamole Client with display.flush backpressure, supports
play/pause/restart, and waits for end plus clean verified EOF before completion.
It never establishes a target connection or accepts remote input.

## Checks

Codec tests cover all-byte tampering/truncation, header/identity binding, old-magic
rejection, key rotation, event sequence, fragmented Unicode, maximum chunks and
write/flush failure without ACK. Real gateway fault/recovery/retention/backup and
browser acceptance are separately required; see
[execution evidence](../../docs/guacamole-execution.md).
# SSH terminal update

ZTREC002 now binds an optional `stream_protocol` in the authenticated header and
matching encrypted meta. Omission identifies existing Guacamole output; SSH text
uses `bastion.ssh.v1` frames and a read-only xterm player. See
[current SSH recording contract](../../docs/ssh-xterm.md).
