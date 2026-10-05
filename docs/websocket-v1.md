# WebSocket v1 (RFC-004 M2–M3 candidate)

M2 shipped one authorized PTY/shell channel per WebSocket. The M3 candidate extends the same v1 wire with independently authorized shell, exec and raw SFTP channels; availability is advertised by `/info.features`, not inferred from this document. The server, never the browser, connects to the immutable target SSH account. Production readiness remains false until the integrated required-recording, HTTPS and release acceptance gates pass.

## M3 channel extensions

- `open` accepts `kind:"shell"|"exec"|"sftp"`; omitted kind remains shell for old clients. IDs are nonzero u32, must not be reused in a connection, and live channels share the configured 16/connection and 64/user limits across Web/SSH.
- Exec startup: wait for `opened`, then send `{"v":1,"type":"exec_start","channel_id":2,"command_base64":"..."}`. Standard padded base64 preserves raw command bytes, at most 65,536 decoded bytes, excluding NUL. Only `exec_start` may exceed 8,192 UTF-8 bytes, with an absolute 98,304-byte control limit. All other control messages and server control messages retain 8,192 bytes. Binary frames retain the 32,768-byte payload limit.
- Raw SFTP startup: wait for `opened`, then send `{"v":1,"type":"sftp_open","channel_id":3}`. Browser file management uses the authenticated HTTP SFTP API on the same owned/login-bound connection, not a JavaScript SFTP codec.
- Shell startup still requires target-acknowledged PTY/shell and, when required, successful private recording creation/activation. Every output chunk is written and ACKed before forwarding. Inputs, exec outputs and SFTP bytes are not included in shell recording.
- A channel close/error is isolated unless the underlying target transport, ownership/policy, connection lifetime or gateway fails. stdout and stderr remain distinguishable binary kinds 2 and 3, including invalid/split UTF-8. EOF must drain pending output and exit metadata.
- `/info` has separate `ssh_*` and `web_*` features plus `recording.required/available/format_version`; a development M1 endpoint without recording cannot impersonate a production endpoint. Unsupported strict cross-host copy remains disabled.

The following authentication and legacy-shell examples remain valid; M2-only statements below describe the earlier milestone rather than removing these candidate extensions.

## Authenticate and create

1. `GET /api/v1/auth/csrf` obtains `csrf_token` and the readable `bastion_csrf` SameSite=Strict cookie.
2. `POST /api/v1/auth/login` sends `{username,password,device_label,client_type:"web"}`, exact same-origin `Origin`, and `X-Bastion-CSRF: <csrf_token>`.
3. The response sets HttpOnly SameSite=Strict `bastion_session` and `bastion_refresh` cookies (Secure on HTTPS). Browser response bodies do not contain access/refresh tokens. Native login defaults to `client_type:"zeroterm"` for M1 compatibility and returns bearer tokens instead. Database login families are client-type-bound: web cookies and native bearer tokens cannot authenticate or refresh in the other domain.
4. `POST /api/v1/sessions` with the cookies, exact Origin, CSRF header, and `{asset_id,account_id,capabilities:["shell"],purpose:"terminal"}` returns 201:

```json
{"protocol_version":1,"session_id":"33333333-3333-4333-8333-333333333333","ws_token":"<base64url secret>","connection_id":"44444444-4444-4444-8444-444444444444","expires_at":"2026-10-04T08:00:30Z","capabilities":["shell"]}
```

Keep the secret only in memory; every response is `Cache-Control: no-store`. The token is 32 random bytes, base64url without padding (43 characters), valid for 30 seconds, and never a query parameter, log field, or persistent browser setting.

```javascript
const socket = new WebSocket(
  `${location.origin.replace(/^http/, 'ws')}/api/v1/sessions/${session.session_id}/stream`,
  ['bastion.v1', session.ws_token],
);
socket.binaryType = 'arraybuffer';
```

The upgrade must carry the authenticated owner's **same login_session_id**, exact same-origin Origin, and `Sec-WebSocket-Protocol: bastion.v1, <ws_token>`. The selected response subprotocol is only `bastion.v1` (never echo the secret). No Authorization header, query string, or client-supplied routing is accepted. WebSocket credential/ownership rejection is deliberately uniform; policy store outage remains 503. Cookie login requires HTTPS except explicitly configured loopback development HTTP. The built frontend requires HTTPS even on loopback; only Vite DEV permits that HTTP exception. This milestone has no required recording and is not a production deployment.

## Text control messages

Each text message is a UTF-8 JSON object with mandatory `v:1` and snake_case `type`. Text size is at most **8192 UTF-8 bytes**. Unknown non-critical fields may be ignored; unknown types are rejected. All channel IDs are nonzero unsigned 32-bit integers, independent of target SSH IDs. The M2 session state machine accepts one shell channel; do not open a second one or restart an exited shell in the same session.

| Direction | type | Additional fields |
|---|---|---|
| client | open | channel_id |
| client | pty | channel_id, term, cols, rows |
| client | shell | channel_id |
| client | resize | channel_id, cols, rows |
| client | eof | channel_id |
| client | close | channel_id |
| client | ping | none |
| server | session_ready | connection_id (UUID) |
| server | opened | channel_id |
| server | pty_ready | channel_id |
| server | ready | channel_id |
| server | exit | channel_id, optional exit_code (u32), optional exit_signal (string) |
| server | closed | channel_id |
| server | error | optional channel_id, code (stable error code) |
| server | pong | none |

`term` is 1–128 UTF-8 bytes without control characters. `cols` and `rows` are integers in **1..4096**. No terminal modes or environment fields are part of M2. `ping/pong` measure browser-to-bastion latency, not target latency.

```json
{"v":1,"type":"open","channel_id":1}
{"v":1,"type":"pty","channel_id":1,"term":"xterm-256color","cols":80,"rows":24}
{"v":1,"type":"shell","channel_id":1}
{"v":1,"type":"resize","channel_id":1,"cols":120,"rows":40}
{"v":1,"type":"exit","channel_id":1,"exit_code":7}
```

Wait for `session_ready` (target authentication), then `opened`, then `pty_ready`, then `ready` before sending terminal input. `pty_ready` and `ready` mean the target accepted the request, not just the gateway. `eof` half-closes stdin; output and exit information must still drain before `closed`. `close` closes the channel; WebSocket loss terminates the connection. On reconnect issue a new session: never reuse the token or automatically replay input.

## Binary messages

One WebSocket binary message contains one six-byte header followed by **0..32768 raw payload bytes**. There is no length field, compression, JSON wrapper, base64, UTF-8 conversion, or newline rewrite.

| Offset | Size | Meaning |
|---|---|---|
| 0 | 1 | version u8, exactly 1 |
| 1 | 1 | kind u8: input=1, output=2, stderr=3 |
| 2 | 4 | nonzero channel_id u32, big-endian |
| 6 | remaining | raw data payload |

Client-to-server accepts only kind 1; server-to-client accepts kinds 2 and 3. Messages shorter than 6 or longer than 32774 bytes, channel 0, unknown kind, wrong direction, and unsupported versions are rejected. Empty payloads are valid. Preserve chunk bytes, including invalid UTF-8 and split UTF-8 sequences; feed server output directly to xterm's byte input. Domain decoding failures attempt a bounded stable `error` frame before shutdown; a transport-level over-limit/invalid WebSocket frame may be rejected by the WebSocket library before domain decoding and terminate without that application error.

Rust domain exports `ClientControl`, `ServerControl` (serde `type` tag), `ClientFrame::Control/ Data`, `ServerFrame::Control/ Data`, and `DataStream::Output/ Stderr`. Both frame types provide `decode_text`, `decode_binary`, `encode_text`, `encode_binary`; control types expose `validate`. `encode_text` on Data or `encode_binary` on Control returns INVALID_ARGUMENT. Limits are exported as `WEBSOCKET_VERSION`, `MAX_CONTROL_BYTES`, `MAX_DATA_BYTES`, `BINARY_HEADER_BYTES`.

## Persistence and failure

`connection_tickets` and `connections` both store `transport` (`ssh` or `websocket`) and `protocol_version=1` with PostgreSQL CHECK constraints and a composite FK requiring matching transport/version. Migration 0002 preserves existing rows as SSH v1 and existing login sessions as zeroterm. `server_settings.schema_version=1` remains the compatible schema family; SQLx's migration ledger tracks the additive migration.

SSH ticket wrappers and WebSocket session methods share issuance and consumption transactions. Fixed lock order is policy → user/login → asset/account → ticket. After locks, actual `clock_timestamp()` expiry, current user/login/grants, gateway and revisions are rechecked. Correct consumption atomically transitions issued→consumed and pending→connecting once and persists audits; target connect failures never restore the ticket. Wrong secrets, wrong owner/login or wrong transport do not consume or revoke the legitimate ticket.

Current error serialization uses SESSION_TICKET_INVALID, SESSION_TICKET_USED, SESSION_TICKET_EXPIRED, SESSION_TICKET_STALE and SESSION_EXPIRED. Legacy TICKET_* and ACCESS_TOKEN_EXPIRED values remain accepted on deserialization, including historical stored failure_code. Other stable codes include CLIENT_PROTOCOL_UNSUPPORTED, CHANNEL_PERMISSION_DENIED, TARGET_REQUEST_REJECTED, RECORDING_UNAVAILABLE, POLICY_STORE_UNAVAILABLE and target faults. The HTTP contract is in [openapi-web.json](openapi-web.json); RFC-004 remains the full roadmap rather than a claim that all endpoints/recording/exec/SFTP features are implemented.

## Checks

`cargo test -p bastion-domain` covers byte preservation, header/direction/length checks, control validation and legacy error aliases. `cargo test -p bastion-store --test web_sessions -- --ignored` requires a Unix isolated PostgreSQL fixture (`BASTION_M1_FIXTURE`, same shape as tests/m1_smoke.py). That integration check covers twenty-consumer races, cross-transport/client authentication, owner/login binding, wrong-secret non-consumption, CHECK/FK constraints, actual expiry after row-lock waits, revisions, logout/revocation and refresh replay. Do not run against production data.
