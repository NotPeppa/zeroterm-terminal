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
remains reachable. No shell/exec/SFTP capabilities are advertised.

Production `serve` requires Unix owner-only 0700/0600 storage and secrets, required
recording, bounded limits, loopback metrics and a trusted HTTPS proxy. Fresh schema
family 2 initialization/migration is explicit; existing family mismatches are
rejected without conversion or DROP. Shutdown drains bounded work and database
ownership loss stops the gateway. Native SSH, integrations/tickets, channels,
files, copy jobs, prototype and serve-m1 have been removed.
# SSH terminal update

SSH sessions now return `stream_protocol: "bastion.ssh.v1"`; RDP/VNC retain
`bastion.guac.v1`. `/info.stream_protocols` maps each target protocol to its
actual stream. See [SSH framing, recording and lifecycle](../../docs/ssh-xterm.md).
The shared management/session APIs and their security requirements stay in use.
