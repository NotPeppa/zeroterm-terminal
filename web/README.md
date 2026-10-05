# ZeroTerm Web Workbench

Vanilla TypeScript + Vite + xterm.js client for the same-origin Bastion API. The workbench is server-driven: it reads `GET /api/v1/info` before rendering feature navigation and hides capabilities the gateway does not advertise. It does not simulate target health, recording completeness, credentials, or unsupported file operations.

## Build and tests

```sh
cd web
npm ci
npm run check
npm test
npm run build
```

Node >=22.18 is required. Dependencies remain TypeScript, Vite, xterm and fit addon; no React, state library, SFTP parser, or browser credential database is used.

## Routes

Hash routes are lifecycle-managed and dispose their AbortController, WebSocket, xterm instances, resize observers, and pending stream work on navigation:

- `#/assets` — authorized asset/account target selection.
- `#/terminal` — real shell WebSocket (`session_ready → open → pty → shell → ready`) with bounded byte frames, EOF, backpressure, reconnect-by-new-ticket only.
- `#/exec` — target-only capability-gated exec channels; original command bytes are base64 encoded (max 64 KiB, no NUL) and stdout/stderr remain separate raw byte streams.
- `#/files` — server SFTP metadata/list/stat, native same-origin download, streamed octet upload, mkdir/remove-file/no-overwrite rename. The target is bound by the server-side SFTP connection; browser input never chooses a target address or credential.
- `#/connections`, `#/audit` — server-side paged queries with `from`, `to`, actor/resource/action/state/transport filters where supported.
- `#/recordings` — readonly, bounded NDJSON replay; sequence, event types, base64 bytes, monotonic elapsed time, and terminal `end` are validated. Completeness is only stated when server metadata says `state=complete` and the stream has a valid end.
- `#/profile` — password change, logout-all, and advertised device session list/revocation.
- Admin-only `#/users`, `#/admin-assets`, `#/grants` — real CRUD and `If-Match` revisions for users/assets/accounts/credential replacement/host-key scan-import-approve-revoke/grants.

Copy jobs are rendered only when `info.features.copy_jobs === true`; current server capability discovery intentionally disables unsafe no-follow cross-target copying.

## Security and failure semantics

- Production requests require HTTPS/WSS. Login uses same-origin HttpOnly cookies, in-memory CSRF only, same-origin fetch, and no hidden retries or mutation replay. Password and credential input fields are cleared after submission.
- API mutations use explicit method/body and `If-Match`; revision conflicts, forbidden/unavailable features, and result-unknown mutation outcomes are shown as distinct states.
- WebSocket tickets, command bytes, and credentials are memory-only. A closed or lost channel does not automatically replay input, commands, uploads, or file mutations.
- Server strings are inserted with `textContent`; paths and IDs are encoded with `URL`/`URLSearchParams`.
- Native file download is handed to the browser as a same-origin attachment URL because browser fetch cannot prove a large disk stream completed. The UI says so instead of claiming success. Closing the bound connection terminates server-side file work.
- A recording with missing `end`, invalid sequence, invalid bytes, partial/corrupt/missing/expired metadata is never presented as complete.

The client does not replace server authorization, host-key verification, target SFTP safety, recording encryption/integrity validation, or production readiness checks.
