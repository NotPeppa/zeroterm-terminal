# Guacamole browser stream (`bastion.guac.v1`)

SSH now uses [`bastion.ssh.v1` and xterm.js](ssh-xterm.md). The Guacamole
instructions below apply to RDP/VNC and existing Guacamole recordings.

This is the schema/protocol-family-2 contract. All assets share one browser
console route and encrypted ZTREC002 recording infrastructure.
The complete HTTP schemas are in [OpenAPI](openapi-web.json); trust and lifecycle
requirements are in [RFC-005](RFC-005-guacamole-browser.md).

## Admission and handshake

1. Cookie-authenticated `POST /api/v1/sessions` with exact Origin/CSRF supplies
   only asset_id, account_id and bounded display dimensions.
2. The response contains session_id, connection_id, ws_token, expires_at,
   target_protocol and stream_protocol `bastion.guac.v1`.
3. Connect to same-origin WSS `/api/v1/sessions/{session_id}/stream` with the same
   login cookie, exact Origin and ordered subprotocols `[bastion.guac.v1,ws_token]`.
   Only `bastion.guac.v1` is returned. No query string or Authorization header.
4. Consumption is transactional, single-use, user/login-bound and checks the
   actual clock after lock waits. Wrong identity/secret cannot consume the ticket.
   Startup failure burns the ticket; manual reconnect obtains a new ticket.

Rust constructs the select/args/connect handshake and target parameters from a
revision-bound server snapshot. The browser cannot select addresses/protocols,
submit credentials or join an existing daemon session. The engine requires
`zt-target-ready`; SSH also requires `zt-ssh-display-only`. These are private
engine capabilities, not browser instructions. Missing capabilities fail closed.

Stock ready/first drawing is not target establishment. Rust waits for the internal
argument-free zt-target-ready marker, completes post-authorization, and atomically
activates recording/connection before forwarding output or user input. The marker
is never exposed or recorded. SSH parameter argv streams are suppressed in the
engine and remain forbidden by Rust. TLS RDP readiness can legitimately show an
OS logon screen; Windows NLA and successful OS account login need separate evidence.

## Binary framing and instruction policy

Both directions carry binary UTF-8 data chunks, at most 32 KiB per WebSocket
message/frame. Chunk boundaries have no relationship to Unicode or Guacamole
instruction boundaries. Use a separate streaming fatal UTF-8 decoder per stream
and the official Guacamole Parser. Guacamole element lengths count Unicode
characters, rather than UTF-8 bytes or UTF-16 code units. Invalid UTF-8, truncated
EOF, invalid lengths or exceeded limits close the connection without truncation,
replay or dropped input.

Accumulated output instructions are limited to 8 MiB; input instructions use the
smaller 8 KiB ceiling. Forwarding queues are bounded to 256 KiB per direction.
Drawing streams and text/plain clipboard streams may use blob/end with validated
direction-owned IDs. Clipboard is limited to 256 KiB decoded UTF-8 and four open
streams per direction. Browser blobs are ACK-paced after bounded buffer acceptance; complete text is
validated before forwarding in UTF-8-aligned blobs. The gateway ACK is not target
application acceptance. Standard VNC clipboard
rejects non-Latin-1 Unicode; all protocols reject NUL and malformed text.
RDP target support for non-BMP text is separate from the UTF-8 stream: the old
xrdp fixture supports BMP Chinese but cannot handle emoji clipboard text.
Keyboard, mouse, bounded size and validated sync/ACK instructions are permitted.
Files/filesystem, audio/video, printer/drive, pipe, nested instructions,
argv, connect/select/args/join and unknown stream ownership are rejected.
Native paste, toolbar paste/copy and a permission-independent text editor are
available. Clipboard streams are excluded from recordings; replay never accesses
the system clipboard. Text echoed in target display remains in recorded images.

Initial display is 1280x720 at 96 DPI; ceilings are 3840x2160 and 48..192 DPI.
SSH/RDP resize is engine-driven. VNC uses local scaling with converted mouse
coordinates when remote resizing is unavailable.

## Lifecycle and recording

Defaults: ten global connections, three per user, twenty pending tickets per
user; 45-second startup, 30-minute interactive idle, eight-hour absolute duration
and 30-second stalls. Only actual keyboard/mouse input refreshes idle time.
Sync, drawing, resizing and WebSocket heartbeats do not.

The encrypted recording writer must ACK write+flush before any display chunk
is sent to the browser. Periodic fsync/checkpoints are separate from per-chunk
ACKs. Any required-recording failure closes the connection and leaves partial or
failed metadata, never complete. Credentials and keyboard input are not recorded.

Revocation, logout, route/target change and pagehide release keys, close tunnel/
bridge/daemon sockets and dispose timers/display. Late callbacks cannot affect
a newer session. No automatic reconnect, session sharing or disconnect recovery.
Replay is offline, read-only and streaming; full end, EOF and checksum verification
are required before showing completion.

## Verification

Rust and frontend unit tests exercise parsers, boundaries and policy. Real isolated
PostgreSQL tests cover ticket/identity/revision races, grants and lifecycle.
Engine-only tests cover target identity and actual egress; they do not substitute
for the full Rust API/recording/browser path. Real browser Canvas/IME/input tests,
Windows NLA, failure/recovery, backup and capacity acceptance remain release gates.
[Execution evidence](guacamole-execution.md) records actual runs and limitations;
production_ready remains false until all gates are independently satisfied.
