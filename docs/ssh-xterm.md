# Browser SSH terminal

Current contract (2026-10-10): SSH uses the Rust SSH client and official
`@xterm/xterm` 6.0.0, fit 0.11.0 and search 0.16.0. RDP/VNC continue using guacd.
This supersedes the original RFC-005 requirement that SSH use a Guacamole stream.
Only interactive PTY/shell is exposed: no exec API, SFTP, native SSH listener,
agent forwarding, tunnelling or automatic reconnect.

## Admission and security

The existing session request, cookie/Origin/CSRF checks, 30-second one-use
user/login-bound tickets, revision snapshots, exact grants, connection leases,
revocation, network denies and required recording stay in use. The server chooses
`bastion.ssh.v1` for SSH and `bastion.guac.v1` for RDP/VNC. WebSocket subprotocols
are `[stream_protocol, ws_token]`; the response returns only the public protocol.
Wrong stream negotiation cannot consume a valid ticket. No query or Bearer token.

Rust resolves the target through network policy and connects once to that fixed
IP. The approved OpenSSH public key is compared with the same socket's key before
target authentication, including rekeys; certificates are not substituted for
approved raw keys. RSA host keys negotiate SHA-512/SHA-256 signatures. Password
and the existing supported OpenSSH Ed25519 private-key/passphrase credentials stay
in server memory. Authorization is checked before authentication, after shell
establishment and periodically/input-time. Cancelling startup or the active
session shuts down its socket.

## Binary stream

Every WebSocket message is exactly one binary frame, at most 32768 bytes.
Integers use network byte order. The browser's first frame is its measured
terminal size; Rust validates it before opening the PTY/shell. No input is
forwarded before the server's readiness frame.

| Byte 0 | Payload | Direction |
| --- | --- | --- |
| 1 | 1..32767 raw PTY bytes | Both |
| 2 | u16 columns, u16 rows (2..500, 1..200) | Both |
| 3 | Empty; authorized, recorded shell ready | Server only |
| 4 | u32 length of the next rendered data frame, including byte 0 | Browser only |
| 5 | Empty; a trusted local terminal input interaction occurred | Browser only |

The browser emits render ACKs only from xterm's write callback. Outstanding
output, queues, browser write buffers and input are bounded by the existing
256 KiB budget. Unknown frames, wrong ACKs, invalid sizes and overload close the
session. Paste is UTF-8 terminal input, using xterm's bracketed-paste semantics;
input is never silently truncated or automatically replayed. SSH output is raw
terminal bytes; xterm's streaming decoder handles split Unicode and escape codes.
Only local terminal keyboard/paste/composition/pointer/wheel interactions refresh
idle (coalesced once per second). Automatic terminal query replies, resize, render
ACKs and network heartbeats do not.

## UI and encrypted replay

The common console route dispatches to xterm for SSH and Guacamole for RDP/VNC.
SSH supports text selection, selection copy, paste, search over the 10000-line
local scrollback, font sizing, fit and fullscreen. Search is not a whole-recording
index. Native xterm input/IME handles text; target fonts/locale still affect display.
Route disposal cancels requests, closes the socket, disposes the terminal and
disconnects layout observers. Sizing follows the stable outer layout box.

ZTREC002 retains its DEK/KEK, sequence, checksum, owner permissions, ACK and fsync
mechanisms. An authenticated `stream_protocol` header and matching encrypted meta
identify the renderer. SSH output events contain complete type-1/type-2 frames,
including terminal sizes; type-3 readiness, render ACKs, credentials and keyboard
input are never recorded. Encrypted write+flush ACK precedes browser delivery;
required writer/checkpoint/finalization faults close the session as partial/failed.

Existing Guacamole recordings with an omitted stream discriminator remain
Guacamole. Offline readers validate identity, protocol, nonce and authenticated
stream metadata. xterm replay disables stdin and streams output with write
backpressure; it opens no target connection and does not access the clipboard.
Only end, clean EOF and file checks confirm completion. No schema migration or
recording rewrite is needed for this change.

`production_ready=false` remains in effect. Windows NLA and the full new SSH
browser/fault/capacity acceptance are separate release gates. Test-host deployment
verification is limited to HTTPS accessibility at the user's request.
