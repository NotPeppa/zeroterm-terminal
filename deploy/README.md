# RFC-005 operations

See [Docker deployment](docker.md) for the reviewed topology, fresh initialization, egress rules,
explicit migration and owner/runtime role separation. Browser-only family 2 has no native SSH listener,
M1/prototype mode, API-token file, exec/SFTP/copy API or channel recordings.

1. Run as a dedicated non-root Linux user. Secrets and recordings directories are owner-only 0700,
   secrets ordinary owner-only 0600 files. Runtime KEK mounts are read-only. TLS proxy is the only public
   listener; the API binds its explicit private ingress address, and metrics binds loopback.
2. Generate KEK and independent owner/runtime DB secrets for a **fresh database only**. Apply migration
   explicitly with the owner connection; old schema families must fail without auto-drop or conversion.
3. Require encrypted `ZTREC002` recording and readiness preflight before accepting sessions. Output is
   acknowledged by the recorder before browser forwarding. Recorder failure stops the session; incomplete
   files are partial/failed, never complete. No keyboard, passwords or connect arguments in recordings.
4. Backup PostgreSQL, encrypted credentials, recordings, all in-use KEKs and both database-auth volumes
   consistently, with a separately preserved manifest:
   ```json
   {"server_id":"stable-server-id","schema_version":2,"credential_count":0,"recording_count":0,"target_pin_count":0,"kek_versions":[1]}
   ```
   Fill counts from the actual consistent backup. `target_pin_count` counts approved SSH/RDP assets,
   not a gateway SSH identity. `verify-backup --config ... --manifest ...` must verify contents in an
   isolated restore before the service is exposed. `recover-restore --config ...` revokes restored login
   families/tickets and interrupts active state; it never resumes connections.
5. Stop admission and allow bounded drain before offline maintenance. `retain-recordings --config ...`
   removes only inactive expired managed files with safe ownership, then marks metadata expired.
   Do not delete active files/DB rows or disable append-only audit guards.
6. Offline audit partition/retention commands remain explicit owner-only actions with `--offline`;
   stop all gateways/other clients first, keep default partitions, and refresh runtime grants after schema
   maintenance. Runtime must not gain DDL or audit UPDATE/DELETE privileges.
7. KEK rotation: preserve all old keys used by recordings/backups, create a new owner0600 key, update
   active version plus `kek_files`, run explicit `rewrap-keys --config ...`, then independently verify the
   backup before retiring keys. Do not rewrite recording files or drop key versions still referenced.
8. After container recreation/reboot, reinstall narrowly scoped host egress rules and **retest** before
   enabling the public proxy. guacd must have only its private bridge, no DB/KEK/recording mounts, and no
   access to host gateway, database or target-network services.

`production_ready=false` until real browser Canvas/IME, Windows NLA, fault injection, recovery, backup,
retention and full resource/capacity release acceptance are complete. Historical M1–M5 evidence is not
schema-family-2 acceptance.
