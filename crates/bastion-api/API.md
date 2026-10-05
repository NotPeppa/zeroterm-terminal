# Worker D API/server surface

All authenticated routes are under `/api/v1`; browser writes require exact Origin and CSRF, native Bearer authentication never mixes with Cookie credentials.

- `GET /me/sessions` uses `limit`, `cursor`, `from`, `to`; returns `{items,next_cursor}`. `DELETE /me/sessions/{id}` revokes only the caller's device, returns 204, and cancels bound runtime connections immediately.
- `POST /integrations/zeroterm/connection-tickets` is Bearer-only. Legacy `/connection-tickets` remains; both use the existing typed asset/account/capabilities/purpose request and secret-bearing ticket response. No auto-retry.
- `POST /sessions` accepts shell, exec, SFTP capabilities; purpose is audit metadata, not an authorization selector. One-time `/sessions/{id}/stream` handshake binds the consuming login session.
- `GET /connections/{id}/channels` returns `{items}` after authoritative identity/ownership checks.
- Connection and audit lists accept the store's exact `from,to,actor_id,resource_id,resource_type,action,state,transport` subset per collection. Cursor scope incorporates identity revision/role and filters.
- `GET /recordings` lists metadata; `GET /recordings/{id}` returns safe metadata; `GET /recordings/{id}/content` returns verified `application/x-ndjson`, `no-store`, no Range. File permission, authenticated header, every chunk, final end/EOF, bytes and incremental checksum are validated. An incomplete body is not a successful replay; clients must wait for clean EOF before reporting verification. Corrupt/missing metadata is marked without logging paths/plaintext/keys.
- `GET /connections/{id}/files?path=...&operation=list|stat` returns `{items:[{name,metadata}]}` or `{size,permissions,mtime,kind}`. Directory listing is capped at 1024 entries.
- `POST /connections/{id}/files/operations`: `{operation:"mkdir"|"remove",path}` or `{operation:"rename",path,destination}`; no shell or recursive delete; result 204.
- `GET /connections/{id}/files/content?path=...`: raw attachment, no Range, bounded 32 KiB chunks and configured total bytes. Browser should use native download rather than buffering a whole Blob. RFC5987 filenames are percent encoded.
- `PUT /connections/{id}/files/content?path=...`: `application/octet-stream`, not JSON, streams raw bounded chunks to random remote temporary file, closes then no-overwrite commits; result 201 `{bytes}`. No auto-retry. Decoder and runtime policy checks keep ownership/login binding active throughout transfer.
- Copy jobs remain explicitly disabled in discovery. Authorized POST `/copy-jobs` creates then marks unsupported failed, GET list/detail and POST `/{id}/cancel` provide historical metadata. Standard SFTPv3 cannot guarantee atomic NOFOLLOW; no unsafe shell/local-copy fallback is used.

`info` separates SSH/Web features, required/available recording, and always reports `production_ready=false`. JSON requests retain a deadline; file upload has independent bounded stream deadlines. Store calls retain the two-second total budget. Ordinary control messages remain 8 KiB and binary payloads 32 KiB at the domain decoder; only exec-start accepts 96 KiB transport text.

Production `serve` is Unix-only, requires explicit owner0700 recordings / owner0600 keys, required recording, retention/free space, constrained runtime limits, restricted metrics and trusted TLS proxy settings. `serve-m1` is a distinct loopback-only legacy command. No auto-migrate occurs. Shutdown stops admission and drains for at most ten seconds; gateway ownership loss stops the service. Deployment samples do not start or reconfigure any services.
