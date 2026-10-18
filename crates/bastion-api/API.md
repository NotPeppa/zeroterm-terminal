# RFC-005 browser API

All routes below are under `/api/v1`. The full request/response schemas and errors are
in [OpenAPI](../../docs/openapi-web.json); the implementation contract is
[RFC-005](../../docs/RFC-005-guacamole-browser.md).

Authentication uses same-origin cookies only. Authorization headers are rejected.
Browser writes require exact Origin and matching `X-Bastion-CSRF`/CSRF cookie.
`GET /auth/csrf`, `POST /auth/login`, and `POST /auth/refresh` are the public login
routes. Login accepts only username, password and device_label; refresh accepts `{}`.
Access/refresh secrets appear only in HttpOnly SameSite=Strict Secure cookies.
Refresh replay revokes the login family. `GET /me` reports `access_expires_at`; the web client
refreshes silently ahead of it, serialised across tabs so a refresh token is never presented twice. Management mutations use quoted positive
`If-Match` revisions; unknown outcomes must be reread, never automatically replayed.

## Asset groups

Asset organization uses one flat group per asset. `group_id:null` means ungrouped;
groups confer no permissions. Operators receive `group_id` / `group_name` only
on assets available through their exact asset/account grants. Auditors cannot
access the asset workspace or the admin group catalog.

- `GET /admin/asset-groups` lists `{items,next_cursor}`; `POST` accepts `{name}`.
  Names are trimmed, unique, 1–128 characters and contain no control characters.
- `GET /admin/asset-groups/{id}` reads a group. `PATCH {name}` and bodyless
  `DELETE` require admin Cookie/Origin/CSRF and positive quoted `If-Match`.
  Duplicate names return 409, stale revisions 412, missing groups 404.
- Asset create accepts optional `group_id`; asset PATCH accepts `group_id` or
  explicit null. Moving an asset increments its configuration revision while
  preserving routing revision, credentials, grants, tickets and active sessions.
- Group deletion atomically returns member assets to ungrouped and increments
  their configuration revisions; assets and accounts remain. Group writes are
  audited. Confirmed writes followed by failed reads must not be replayed.
- `/assets` and `/admin/assets` accept `group_id` or `ungrouped=true`, mutually
  exclusive, with normal pagination and user/filter-bound cursors. Group filtering
  never enlarges the authorized asset set.

## Users, devices and authorization

- `GET /admin/users` returns an admin-only `{items,next_cursor}` page excluding soft-deleted users; disabled but undeleted users remain listed. `GET /admin/users/{id}` reads a live user and returns 404 for missing or deleted identities. Existing `User`/`UserView` fields remain unchanged; no deleted marker is exposed.
- `POST /admin/users` creates `{username,password,role}` with a new UUID and the newly supplied password. Usernames are trimmed and ASCII-lowercased. A deleted username may be reused, but a disabled, undeleted user still reserves its name. Same-name creation never inherits the old UUID's Grants, login sessions or historical ownership.
- `PATCH /admin/users/{id}` accepts role/enabled; `POST /admin/users/{id}/reset-password` accepts `{password}`. Both require quoted positive `If-Match` and target a live user; neither can restore a deleted identity.
- `DELETE /admin/users/{id}` is admin-only, rejects the current login user with 403, has no request body, and retains the existing exact Origin / `X-Bastion-CSRF` / Cookie rules for browser writes. `If-Match` must be a quoted positive current live revision: absent 428 (`PRECONDITION_REQUIRED`), malformed 400 (`INVALID_ARGUMENT`), wrong live revision 412 (`REVISION_CONFLICT`), missing or already deleted 404 (`RESOURCE_NOT_FOUND`), non-admin or self-delete 403 (`PERMISSION_DENIED`); success is 204 with no response body.
- Deletion is soft: the user disappears from the user list/detail, cannot log in, and cannot use old access tokens, refresh tokens or pending tickets; bound runtime connections are revoked. Audit events, historical connections, recordings, approved host keys and old Grants are retained under their original UUIDs, not transferred to a same-name new account. Deleted owners cannot receive new Grants or have old Grants expanded/re-enabled; existing `DELETE /admin/grants/{id}` revocation and a pure `PATCH {enabled:false}` without capabilities/expiry changes remain allowed. There is no restoration, recycle bin, bulk operation or CLI delete command.
- The Web user row requires explicit danger confirmation showing username, ID, revision, access revocation, retained history and username reuse. The current user's delete button is disabled. There is no optimistic row removal or automatic DELETE retry. Unknown outcomes and revision conflicts require rereading instead of resubmitting the same confirmation. After 204, old-row actions are disabled and the list is reread; if that GET fails, the UI preserves the read error and says deletion was confirmed but the list refresh failed. Only refresh the list, never repeat the confirmed DELETE.
- `GET /me/sessions` uses `limit`, `cursor`, `from`, `to`; returns `{items,next_cursor}`. `DELETE /me/sessions/{id}` revokes only the caller's device, returns 204, and cancels bound runtime connections immediately.
- Access is all-or-nothing for one asset/account: enabled admins implicitly access all enabled assets/accounts; operators need any enabled, unexpired exact grant; auditors cannot connect. Asset/account membership and enabled state, current login/user state, host keys, network policy and runtime limits remain enforced. Admin asset lists include enabled assets without enabled accounts as `accounts: []`.

## Assets and accounts

`/admin/assets`, `/admin/assets/{id}`, `/admin/assets/{id}/accounts`,
`/admin/accounts/{id}`, `/admin/accounts/{id}/credential`, and `/admin/grants`
provide the administrative surface. A protocol is mandatory and immutable:
`ssh | rdp | vnc`. Each asset is one endpoint; labels/tags do not affect routing.
SSH assets may be saved without a host key. Before the first session, an administrator
confirms a discovered SHA-256 fingerprint, or imports a verified public key. Missing
trust denies session issuance; changed keys still fail same-socket verification.
`POST /admin/assets/{id}/ssh-host-key/scan` is bodyless, admin-only, Origin/CSRF and
If-Match protected; it discovers keys under the configured network policy without
credentials or automatic approval. Confirm with asset PATCH using the returned revision.
The server requires `ssh-keyscan` (included in Docker). RDP requires a leaf-DER SHA-256
pin, and permits only `nla` (default) or explicit `tls`. SSH and RDP use explicit first-use confirmation; neither trusts automatically. An RDP asset may omit its pin and waits like SSH. `POST /admin/assets/{id}/rdp-certificate/scan` is bodyless with the same Origin/CSRF/If-Match and shared rate limits; it discovers the leaf-DER SHA-256 and the server-selected security mode (`nla` for CredSSP, else `tls`) through the network policy and a signature-verified TLS handshake, then closes before CredSSP: no credentials are sent and nothing is stored. Confirm both with asset PATCH using the returned revision. Account label is mandatory; SSH/RDP require username, VNC requires
null username, and domain is RDP only. Credentials are password, SSH OpenSSH
Ed25519 private key/passphrase (unencrypted or AES-256-CTR), or explicit VNC none.
RSA did not pass the fixed engine's real authentication gate and is rejected.
None stores SQL NULL credential_id,
not an encrypted empty password. VNC passwords are at most eight UTF-8 bytes.
VNC additionally requires administrator-approved trusted target CIDRs.

`GET /assets` and `/assets/{id}` expose authorized target/account metadata without
secret envelopes. Grants contain exact user/asset/account access and expiry, with
no permission arrays. Route, account identity, credential and approved trust changes
invalidate pending tickets and revoke active connections. Name/label/tag edits do not.

## Sessions and connection history

`POST /sessions` accepts exactly:

```json
{"asset_id":"UUID","account_id":"UUID","display":{"width":1280,"height":720,"dpi":96}}
```

Display bounds are width 1..3840, height 1..2160 and DPI 48..192. The response is
`{session_id,connection_id,ws_token,expires_at,target_protocol,stream_protocol}`,
with stream_protocol `bastion.guac.v1`. Protocol, target address, account identity,
credentials and guacd parameters are selected by the server, never the client.
The token has a 30-second deadline and single transactional consumption bound to
both user and login. Wrong owner/login/secret cannot burn a valid token; failed
startup does not restore it. Reconnect requires an explicit new session request.

`GET /sessions/{id}/stream` upgrades with the same cookie, exact Origin and the
ordered subprotocols `[bastion.guac.v1,ws_token]`. The response echoes only the
public protocol. Query strings and Authorization headers are rejected. Both
stream directions carry bounded binary UTF-8 Guacamole chunks; see the
[stream contract](../../docs/websocket-v1.md). Bidirectional text/plain clipboard
is enabled for all target protocols, bounded to 256 KiB with direction-owned
streams. Unsupported VNC non-Latin-1 input, NUL, unknown streams and oversized
data fail explicitly. Clipboard transfer payloads do not enter recordings.

`GET /connections`, `/connections/{id}`, and `POST /connections/{id}/disconnect`
provide authorized history and revocation. `GET /audit-events` provides paginated
sanitized history. Each connection owns one stream and at most one recording.

## Recordings, discovery and deployment

`GET /recordings` and `/recordings/{id}` provide safe metadata.
`GET /recordings/{id}/content` serves verified streaming `application/x-ndjson`,
`no-store`, without Range. It authenticates the ZTREC002 header, every encrypted
chunk, final end, EOF, size and checksum. Partial/truncated output is not a
successful replay. Offline replay accepts no target input or target WebSocket.

`GET /info` reports schema/protocol family 2, `bastion.guac.v1`, protocol-specific
availability, recording availability/format 2 and `production_ready=false`.
Engine or recording failure disables connection availability while management
remains reachable. Browser routes advertise no shell/exec/SFTP capabilities; the
native block below is separate.

Production `serve` requires Unix owner-only 0700/0600 storage and secrets, required
recording, bounded limits, loopback metrics and a trusted HTTPS proxy. Fresh schema
family 2 initialization/migration is explicit; existing family mismatches are
rejected without conversion or DROP. Shutdown drains bounded work and database
ownership loss stops the gateway. The old native SSH server, integrations/tickets,
channels, files, copy jobs, prototype and serve-m1 have been removed; RFC-006 below
replaces native access.
# SSH terminal update

SSH sessions now return `stream_protocol: "bastion.ssh.v1"`; RDP/VNC retain
`bastion.guac.v1`. `/info.stream_protocols` maps each target protocol to its
actual stream. See [SSH framing, recording and lifecycle](../../docs/ssh-xterm.md).
The shared management/session APIs and their security requirements stay in use.

# RFC-006 native ZeroTerm entry (shell / exec / SFTP)

Contract: [RFC-006](../../docs/RFC-006-native-ssh-entry.md). Routes exist only when
`BASTION_NATIVE_SSH_LISTEN` is set (otherwise 404 and no `/info.native`).
`BASTION_NATIVE_SSH_PUBLIC_HOST` (default: the HTTPS origin host) and
`BASTION_NATIVE_SSH_PUBLIC_PORT` (default: the listen port) are the address clients use.
The gateway host key is one unencrypted Ed25519 OpenSSH key in
`secrets/ssh_host_ed25519_key` beside the config file (or `BASTION_NATIVE_SSH_HOST_KEY_FILE`),
owned by the service user with mode 0600. It is never generated at startup: a missing key,
or one with the wrong mode, stops `serve`.

`/api/v1/native/*` accepts only `Authorization: Bearer <access_token>`. Cookies are ignored,
Origin/CSRF is not required and no CORS headers are sent. Browser routes still reject any
Authorization header. A token from one login family (`login_sessions.client_type`
`web | native`) is unknown to the other.

- `POST /native/auth/login` takes exactly `{username,password,device_label}` and returns
  `{access_token,refresh_token,access_expires_at}` in the body. It uses the browser's
  10-minute access / 7-day family policy, and shares IP/username limits and failure audit
  with browser login.
- `POST /native/auth/refresh` takes `{refresh_token}`. Refresh tokens are one-use; replaying
  one revokes the family (401 `LOGIN_SESSION_REVOKED`). `POST /native/auth/logout` (Bearer,
  no body) revokes the current family and its connections.
- `GET /native/assets` and `/native/assets/{id}` use the same paging, cursors, Grant filter
  and `groups` as `/assets`, but return only `protocol=ssh` assets and accounts with a target
  username. Each account adds `capabilities`: every open native capability (currently
  `["shell","exec","sftp"]`) while `/info.native.available`, else `[]`. Grants stay all-or-nothing.
- `POST /native/connection-tickets` takes exactly `{asset_id,account_id,capabilities}`, where
  capabilities is a non-empty subset of the open set `shell`, `exec`, `sftp` in any order, without
  duplicates (unknown or duplicate values are 400; there is no
  `purpose`). The response echoes the requested list in request order. Non-SSH assets
  return 403. It runs the same transaction as `POST /sessions`: binding, revision freeze, and
  pending/concurrent limits shared with browser connections. It returns 201
  `{protocol_version:1,ticket_id,ticket_secret,connection_id,gateway:{host,port,username:"zt1:<ticket_id>"},capabilities,expires_at}`.
  Tickets last 30 s and are single-use. Issuance needs a running listener (503
  `TARGET_PROTOCOL_UNAVAILABLE` / `RECORDING_UNAVAILABLE` otherwise). Never replay after an
  unknown outcome.
- `GET /native/connections/{id}` returns only the caller's own connection, regardless of role,
  with `failure` as `{code}` or null.

`/info.native` reports `{protocol_version:1,minimum_client_protocol_version:1,available,gateway:{id,host,port,public_key},features:{shell,exec,sftp}}`.
`gateway` and `features` are always present. `available` (and `shell`, `exec`, `sftp`) are true only while
the SSH listener reports it is running, the recording requirement is met and the server is
not draining.

Connections carry `transport` (`websocket | native_ssh`). Native rows store no display: the
`/connections` list shows `display:null`, single reads show the nominal 1280×720@96 that the
recording header uses. `ticket.issued/consumed/rejected` payloads include `transport`, and
native issuance adds `capabilities`. `/me/sessions` items include `client_type`; revoking a
native device from the browser disconnects its connections. A native connection without a shell
channel becomes `active` without a recording (`connection.active` with `recording_id:null`).
Each native exec is audited once on the connection (`resource_type:connection`), never its output:
`exec.completed` `{connection_id,transport,command,command_sha256,command_bytes,truncated,exit_status,exit_signal,stdin_bytes,stdout_bytes,stderr_bytes,duration_ms}`
or, when refused before the target ran it, `exec.rejected` with the same command fields plus
`reason_code`. `command` is the first 4 KiB, lossy UTF-8 (invalid bytes and NUL become U+FFFD);
`command_sha256` is the hex SHA-256 of the full command bytes.

The SSH listener (`BASTION_NATIVE_SSH_LISTEN`) accepts exactly one password attempt per connection
(`zt1:<ticket_id>` / `ticket_secret`; `none`/`publickey` probes are refused), a 10 s handshake and at most
`BASTION_NATIVE_SSH_MAX_UNAUTHENTICATED` (64) unauthenticated connections. Failures are audited as
`native.auth_failure` with the source IP and rate limited per IP. Up to 16 concurrent `session`
channels share one pinned/authenticated target socket. One shell is allowed per connection lifetime:
`pty-req`, then `shell` (answered once the target shell is ready); only shell output is recorded.
Exec commands (up to 64 KiB, no NUL) relay stdin/stdout/stderr and target EOF/status/signal.
The `sftp` subsystem proxies v3 packets whose length field is at most 256 KiB (excluding the four-byte prefix); unsupported extensions receive
`SSH_FX_OP_UNSUPPORTED`. File CLOSE (or channel end) writes `sftp.file` with paths, flags, successful
read/write byte counts and continuous-from-zero SHA-256 (null for random or incomplete I/O).
Mutations write `sftp.<op>` with the target status; metadata counts appear in `sftp.session`.
Exec/SFTP may run before, alongside or after the shell. A rejected exec/subsystem request leaves the
channel open. Env, X11, agent, signals and all forwarding are refused. Limits, activity, periodic
authorization, revocation and shutdown apply to the entire connection. A shell ending leaves other
channels usable; the connection closes when the client disconnects (or a connection limit/revocation
interrupts it). `production_ready` remains false pending all release acceptance gates.

SFTP VERSION is the sole rewritten frame: only the six allowed extensions from RFC-006 §14.4
are advertised, preserving target order and version data. All other legal packets remain unchanged.
`fsync@openssh.com` is counted in `sftp.session`, without a separate operation audit.
Typed SFTP audits add `connection_id` and `transport` in the store; paths are lossy UTF-8,
limited to 4096 characters with NUL replaced by U+FFFD. `sftp.file` includes `read_sha256` and
`write_sha256`: status 0 means successful CLOSE, null means channel end before successful CLOSE,
and a nonzero status means a write-intent OPEN was refused (zero bytes and null hashes).
WRITE payloads are hashed on request without retention; only successful ACKs count toward bytes,
and a hash is declared only after every WRITE succeeded. Read reordering uses at most 1 MiB;
overflow abandons the read hash while continuing the transfer. On a mixed read/write handle,
`sha256` uses the write side provided both sides are continuous and acknowledged.
`sftp.rejected` `{connection_id,transport,reason_code}` audits missing capability or subsystem
startup failure; the client channel remains reusable. Other subsystem names are refused without audit.
Audits precede response forwarding with a two-second batch budget. They are best-effort: failure
logs connection/action but preserves client status. Connection authorization polls every second with
a two-second store budget, so store failure may leave approximately three seconds of unaudited operations.
A slow SFTP/exec receiver can temporarily stall other channels on the same SSH connection due to
russh's bounded per-channel delivery; writes are bounded by `stall_timeout`.
