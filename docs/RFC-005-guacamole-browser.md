# RFC-005: Browser-only SSH / RDP / VNC

Status: approved implementation contract; not production acceptance.

## Scope

All target protocols use guacd. The product has a browser-only interactive session,
not a native SSH bastion, exec API, SFTP manager or general TCP proxy. Each asset
is one protocol endpoint. No old database, client, ticket or recording conversion
is included. Existing databases must never be dropped automatically.

## Frozen public contract

- Asset `protocol`: `ssh | rdp | vnc`, immutable after create.
- Asset `security`: `nla | tls`, RDP only, default `nla`.
- Asset `ssh_host_key`: nullable target SSH public key, SSH only. Null means awaiting
  explicit administrator fingerprint confirmation and blocks session issuance.
  Administrators can discover keys with `POST /admin/assets/{id}/ssh-host-key/scan`
  (Origin/CSRF/If-Match protected, network policy enforced, no credentials), then
  confirm one through asset PATCH with the scanned revision. Manual verified-key
  import remains supported; discovery never silently approves or replaces trust.
- Asset `rdp_certificate_sha256`: approved lowercase 64-hex SHA-256 digest of the
  leaf certificate's DER bytes, RDP only. This is certificate pinning, not a claim
  of public-CA/domain verification.
- Asset organization is a separate flat `asset_groups` catalog with id, unique
  name and revision; `assets.group_id` is nullable. Groups are part of the
  family-2 baseline migration 0001; new assets start ungrouped. Group CRUD is admin-only, revision-checked
  and audited. Moving assets or deleting groups changes only configuration
  revisions; routing/credential revisions and exact grants remain intact.
  Operators see group names only on authorized assets; no group grant exists.
  Group deletion returns assets to ungrouped. Asset list group filters are
  mutually exclusive and included in cursor scope.
- Account: `label`, nullable `username`, nullable `domain`, `credential_kind`,
  `revision`, nullable `credential_revision`, `enabled`. SSH/RDP require username;
  VNC requires null username. Domain is RDP only.
- Credential input: `{type:"none"}` (VNC only), `{type:"password",password}` or
  `{type:"private_key",key_pem,passphrase}` (SSH only). None has no ciphertext row.
  SSH private keys are OpenSSH Ed25519, unencrypted or AES-256-CTR encrypted with
  a valid passphrase. RSA failed the selected engine's real authentication gate
  and is rejected at ingestion; PKCS/ECDSA keys and other ciphers remain rejected.
- Grants authorize an exact asset/account, without capability arrays. Enabled
  administrators have implicit access; operators need a valid grant; auditors
  cannot connect.
- Cookie-only login has no native client_type or bearer response. Access and
  refresh tokens remain in HttpOnly SameSite=Strict cookies, never JSON bodies.
- `POST /api/v1/sessions` accepts only `{asset_id,account_id,display:{width,height,dpi}}`.
- Response: `{session_id,connection_id,ws_token,expires_at,target_protocol,
  stream_protocol:"bastion.guac.v1"}`.
- WebSocket `/api/v1/sessions/{session_id}/stream` requires the same login cookie,
  exact Origin and `["bastion.guac.v1",ws_token]` subprotocols. Only the public
  protocol is echoed. Query strings and Authorization headers are rejected.
- The token expires after 30 seconds and is consumed exactly once. Wrong secret,
  owner or login cannot consume the legitimate ticket. Failed target startup
  never restores a token. Reconnect is manual and obtains a new ticket.
- Both WebSocket directions carry binary UTF-8 Guacamole chunks. A message need
  not contain a whole instruction or Unicode character. Each side uses bounded,
  incremental decoding. Guacamole lengths count Unicode characters, not bytes.
- `/info`: schema_version=2, protocol_version=2,
  stream_protocol="bastion.guac.v1", production_ready=false;
  features.web_ssh/web_rdp/web_vnc/recording_replay/device_sessions;
  recording.required/available/format_version=2. Availability must be honest.

## Runtime model

One connection owns one Guacamole stream and one recording. No channel, exec,
SFTP, copy job, transport enum, native client type or purpose field remains.
Recordings directly reference connections with a unique foreign key. Identity,
login, routing, account-security and credential revisions are frozen at issuance
and rechecked during consumption and snapshot creation. Name/label/tag edits are
metadata edits and should not revoke otherwise valid sessions.

The runtime reserves a connection lease before startup. A short transaction
returns a revision-bound target snapshot; no DB lock spans DNS or network I/O.
Before submitting target credentials, and after guacd becomes ready, policy is
rechecked. Recording and connection activate atomically only after file readiness,
guacd readiness and authorization. No display output or user input passes earlier.
The selected engine additionally advertises a mandatory `zt-target-ready` argument
and emits the internal, argument-free `zt-target-ready` instruction only after the
profile-specific interactive establishment conditions succeed:

- SSH: approved host identity checked on the same socket, SSH user authentication,
  successful channel allocation, PTY request and shell request.
- RDP: approved leaf pinned on that same TLS socket, permitted TLS/NLA security
  negotiation and successful interactive RDP protocol activation. TLS activation
  does **not** prove remote OS/PAM account login: a legitimate logon, expired-password
  or failed-password screen is allowed. Positive OS-login acceptance additionally
  needs real target authentication/session logs and actual desktop painting. Real
  Windows NLA/CredSSP interoperability requires separate evidence.
- VNC: approved trusted-CIDR policy plus successful RFB initialization using the
  tested password or explicitly approved None profile. None intentionally has no
  user authentication; RFB readiness is not an OS-login assertion.

Rust waits for this marker before atomic activation; it never forwards or records
it. Stock `ready`, initial drawing and heartbeat sync are not success evidence,
and unpatched engines remain unavailable. Startup display is bounded while held.
SSH additionally requires `zt-ssh-display-only=true`: the engine suppresses the
shared argv/font/color stream producer for startup and pending joins and disables
its argv input handler. Rust continues rejecting all parameter streams. Engines
from before this fix cannot advertise SSH availability or pass the handshake.
Cancellation closes the WebSocket, guacd socket and bridge, releases its lease,
and finalizes the recording. Revocation cannot recall already transmitted bytes.

## Target reachability and trust

Rust resolves the target, applies deny-first CIDR policy and connects exactly the
approved numeric IP. guacd reaches it through a private, one-use, per-session TCP
bridge; it must not have direct target-network or database reachability. A bridge
accepts only the configured guacd source, with a startup deadline; it never accepts
client-selected addresses or joins existing sessions. Redirect/reconnect to an
unapproved second host fails closed.

Protocol gates must be proved against the selected engine:

1. SSH host key matches the approved key on the same target connection before
   target authentication. Unsupported private-key formats are rejected, not
   silently advertised as supported.
2. RDP validates the exact approved leaf-certificate SHA-256 pin on that same
   target connection before sending target authentication. No ignore-cert, TOFU
   auto-accept, unencrypted RDP or security downgrade. A separate preflight
   connection cannot replace same-socket validation.
3. VNC none/password is explicitly restricted to administrator-configured trusted
   target CIDRs. Classic password authentication has an eight-byte ceiling and
   does not provide SSH/RDP-equivalent identity or encryption guarantees.

If the selected release cannot meet a gate, that protocol stays unavailable until
an independently verified implementation does. Never turn off the check to make
a smoke test pass.

## Instruction policy and limits

Drawing, interaction and bidirectional text/plain clipboard are supported. Disable audio, printing,
files, drives, arbitrary pipe streams, SFTP, shared sessions, join and guacd native
plaintext recording. Filter stream creation by purpose and validate stream-id
ownership; drawing may legitimately use blob/ack/end, so do not blanket-block them.
Guacd connect/select/args are strictly server-side.

Text clipboard streams are direction-owned, at most four open streams per direction
and 256 KiB decoded UTF-8 per stream, with strict base64/UTF-8/NUL validation. Unknown
IDs, images/HTML/files and oversized data fail closed. Incoming browser blobs are
6048 bytes or less; the gateway ACKs only after bounded buffer acceptance, as stock clipboard handlers
do not provide transfer ACKs. Complete input is validated before forwarding with
UTF-8-aligned blobs, preventing truncated paste. This ACK proves buffer acceptance,
not target application acceptance. Failed transfers close the connection and are
never retried. Standard VNC clipboard is Latin-1; unsupported Unicode is explicitly
rejected before completion. SSH/RDP clipboard carries UTF-8. Clipboard contents
still depend on the target application's supported character set. The pinned candidate fixes
guacd 1.6.0's UTF-16 surrogate conversion and reserves the terminator/encoded expansion
at the 256 KiB limit; the Debian xrdp 0.9.x fixture itself uses UCS-2 and does not
interoperate with non-BMP clipboard text. Windows clipboard/NLA interoperability remains unverified.
Clipboard contents are cleared on disconnect/route disposal and never included in offline replay.

Initial defaults (configuration ceilings must be validated): global connections
10, per user 3, pending tickets per user 20; startup 45s, idle 30m, absolute 8h,
stall 30s. Drawing/sync/heartbeats do not reset user-input idle. WebSocket chunks
32KiB, cumulative instruction cap 8MiB, byte-bounded queues, display up to
3840x2160, dpi 48..192. Default display 1280x720 at 96dpi. Fail on over-limit input, do not
truncate, silently drop or replay it. Capacity figures are not acceptance results.

## Unified recording

Encrypted container: ZTREC002. Its authenticated header binds recording id,
connection id, target protocol and format version. Reuse DEK/KEK wrapping,
sequence-derived nonces, owner-only files, bounded writer, retention and recovery;
do not support the old terminal-only codec.

Plaintext consists of complete NDJSON events:

```
{"type":"meta","seq":0,"elapsed_us":0,"format_version":2,"connection_id":"uuid","target_protocol":"ssh","width":1280,"height":720,"dpi":96}
{"type":"output","seq":1,"elapsed_us":1000,"data_base64":"..."}
{"type":"end","seq":2,"elapsed_us":2000,"reason":"closed"}
```

Output is handshake-free, policy-approved guacd-to-browser display bytes, retaining
instruction order and sync timing. Clipboard headers/blob/end and upload ACKs are
excluded; pasted text visible in the target display is still part of the recorded
picture. Do not record connect args, passwords, private keys or keyboard input.
Display output is encrypted and write+flush ACKed before forwarding.
This is not per-frame fsync. Periodic fsync/checkpoint and final checksum/metadata
commit are required. A failure stops the session; incomplete files are partial or
failed, never complete.

Recordings list/detail/content routes remain `/api/v1/recordings`. Content is
verified streaming NDJSON, no-store, no Range. Replay is an offline read-only
Guacamole client, without a target WebSocket or remote input. Only after end,
clean EOF and integrity checks does the UI claim verification. Initial replay
supports play/pause/restart, without unbounded whole-file buffering or seek index.

## Frontend and deployment

Use an official, verified, locally vendored Guacamole JS release, including
LICENSE/NOTICE, served same-origin before the main module. Remove xterm and its
wire/state machine. One workspace handles SSH terminal and RDP/VNC desktop.
Use native Guacamole keyboard/input support, real-browser IME checks, blur key
release, route disposal and old-generation callback isolation. Clipboard is an
explicit user-requested feature, separate from keyboard composition handling. Unsupported VNC remote resize uses
local scaling with correct mouse coordinates.
The fixed SSH terminal ignores non-BMP keysyms and its RDP Unicode event path is
16-bit. SSH/RDP currently accept BMP input (including Chinese), explicitly reject
an entire composition containing non-BMP text, and display that limitation. The
gateway also rejects such key instructions; VNC's full Unicode path is separately
tested. UTF-8 output/recording framing remains Unicode-scalar aware.

Publish only HTTPS. No native SSH listener, gateway SSH host key or development
bearer token. Fresh initialization independently generates KEK and owner/runtime
DB secrets. Keep explicit migration, separated owner/runtime roles, 0700/0600
permissions and a non-root service. guacd has no database password, KEK or recording
volume and no public 4822 port. Test actual egress isolation; internal:true alone
is not evidence.

## Acceptance

Real guacd/OpenSSH/xrdp-TLS/VNC none+password and real browser Canvas/IME tests are
required. Windows NLA is a separate acceptance target, not covered by xrdp-TLS or
mock tests. Test wrong/changed host key or certificate on a malicious target,
showing target authentication was not sent; IP policy and redirect denial;
owner/login/secret/concurrent ticket checks; revision/revocation races; streamed
UTF-8/instruction fragmentation and limits; forbidden streams without breaking
image streams; writer/fsync/finalize faults; restart/partial recovery; backup,
retention, role isolation and vanished legacy routes/listeners. Record executed
commands and limitations. Do not count ignored tests or unavailable environments
as successful acceptance, or set production_ready=true prematurely.
# Current SSH implementation

The approved SSH change uses Rust SSH/PT​​Y + xterm.js. The original unified
Guacamole SSH requirements below are superseded by [the current SSH contract](ssh-xterm.md).
RDP/VNC, authorization, management and encrypted recording requirements remain.
