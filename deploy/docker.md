# RFC-005 Docker deployment (candidate, not production acceptance)

Only HTTPS is public. No SSH listener/2222, development API token, gateway host key or legacy config.
Use a **new Compose project and new volumes** for schema family 2. Existing databases/recordings are
not converted and must not be dropped. Keep old projects offline or separately preserved; never reuse an
existing production/test project name for these steps.

## Fresh setup

`docker compose up bastion` now runs three one-shot services first, each only after the previous one
succeeds: `init` (fresh secrets; skips when all three secret volumes are populated, refuses a partial
state), `migrate` (owner connection) and `grant-runtime` (least-privilege runtime grants). The
application itself still never migrates and never holds owner credentials; it starts only after these
exit 0, and startup rejects a schema older than the binary expects (currently migration 0006). Upgrades
and restored family-2 backups therefore migrate on the next `up`; take a backup first when a release
contains an irreversible migration. The explicit commands below remain valid and are idempotent: run by
hand, the one-shots afterwards find nothing to do. Create the first administrator through `maintenance`
(no fixed IPs), because `run bastion` collides with a running bastion's fixed addresses.

Linux Docker 26 / Compose 2.26 are the tested engine-host versions. Heavy source builds use one job;
low-memory machines should receive prebuilt reviewed images. No 1 GiB runtime or concurrency acceptance
claim follows from these settings.

The TLS proxy and Rust service have separate network namespaces. Only the proxy publishes 443;
it reaches the API at `172.30.63.2:8080` on the dedicated ingress network. Rust trusts forwarding headers
only from the proxy's fixed `172.30.63.3` address and rejects untrusted API requests. The proxy has no
target or guacd bridge network. This permits Rust container restart without stranding the proxy in an
old namespace. guacd's bounded PID limit is 256: ten mixed sessions measured 158 processes/threads,
and the previous limit of 128 caused real failures. These samples are not a production capacity promise.

From the checkout root, after checking that `172.30.61.0/29`, `172.30.62.0/24` and `172.30.63.0/29` conflict with no existing Docker/host subnet:

```sh
export PROJECT=zt-guac-v2-prod
mkdir -p .local/docker/tls
cp config/production.example.toml .local/docker/production.toml
cp deploy/nginx.example.conf .local/docker/nginx.conf
# Edit server_id, HTTPS public_origin/server_name, network.allow/deny and trusted VNC CIDRs.
# If bridge CIDR changes, change both Compose fixed IPs and all guacd config IPs together.
# If ingress CIDR changes, update Compose IPs, API listen/healthcheck, nginx upstream and trusted_proxies together.
sed 's|^database_url_file = .*|database_url_file = "/run/bastion-db/database-url"|' \
    .local/docker/production.toml > .local/docker/maintenance.toml
chmod 644 .local/docker/*.toml .local/docker/nginx.conf
# Install the real trusted certificate chain and private key as:
# .local/docker/tls/bastion-chain.pem / .local/docker/tls/bastion-key.pem

docker build -t zeroterm-guacd:1.6.0-strict-pin -f deploy/guacd/Dockerfile .
python3 -u tests/docker_guacd_acceptance.py --engine-image zeroterm-guacd:1.6.0-strict-pin
# Freeze the exact accepted local image; Compose refuses an unset GUACD_IMAGE.
export GUACD_IMAGE=$(docker image inspect zeroterm-guacd:1.6.0-strict-pin --format '{{.Id}}')
docker compose -p "$PROJECT" build bastion
docker compose -p "$PROJECT" run --rm --no-deps --entrypoint sh maintenance \
    /usr/local/share/zeroterm-bastion/docker-init.sh
docker compose -p "$PROJECT" up -d --wait postgres
docker compose -p "$PROJECT" run --rm --no-deps maintenance migrate \
    --config /etc/zeroterm-bastion/maintenance.toml
docker compose -p "$PROJECT" exec -T postgres sh -c \
    'sed "s/\r$//" /usr/local/share/zeroterm-bastion/docker-runtime-role.sh | sh'
docker compose -p "$PROJECT" run --rm --no-deps bastion create-admin \
    --config /etc/zeroterm-bastion/production.toml --username admin
# Bring up app/guacd WITHOUT the public TLS proxy first.
docker compose -p "$PROJECT" up -d --wait bastion guacd
sudo python3 deploy/guacd/egress.py install "$PROJECT"
# Verify isolation for this deployment before allowing interactive sessions.
docker compose -p "$PROJECT" up -d --wait proxy
curl --fail https://YOUR-EXACT-PUBLIC-ORIGIN/health/ready
```

Initialization refuses nonempty secret volumes or any arguments. `bastion-server init` generates only KEK;
owner/runtime DB passwords are independent `/dev/urandom` 32-byte values, never reused API tokens.
Secrets files are UID 10001/0600, containing directories 0700. Runtime mounts KEK/runtime credentials read-only;
only explicit maintenance can write them. Owner URL is never visible in the app. Runtime grants must be
refreshed explicitly after migrations; runtime owns no schema/table, cannot perform DDL or mutate audit rows.

## Guacd isolation and capability gate

- guacd is non-root UID 10002, read-only, capabilities dropped, tmpfs HOME only. No DB/KEK/recording mount.
- guacd has exactly one IPv4-only private bridge; no default/app/target network and no public 4822.
- Rust/app alone has target network and DB reachability; API binds its ingress IP and metrics binds loopback. Neither binds the guacd bridge IP.
- Root host egress rules match **only this project's guacd IPv4 /32**. An independently hash-named
  chain permits established replies and app-IP TCP ports 32768..60999, then drops everything else.
  Host INPUT is denied for that source, including root-host gateway services. The script never flushes
  global firewall chains. Do not enable container IPv6 without an independently reviewed IPv6 firewall.
- These ports are the kernel ephemeral range, **not a per-connection firewall allowlist**. Rust checks the
  allocated port is within that range, only listens there for a deadline-bound single accept, and validates
  guacd source IP. Do not run another app service on that range; the app namespace is trusted. A stronger
  per-port host allowlist would require a separately privileged lifecycle helper and is not claimed here.
- Docker bridge netfilter must actually process same-bridge traffic; run positive bridge and negative
  app-canary/target/host/Internet checks. `internal: true` by itself proves nothing about host reachability.

Install/remove rules while the matching app/guacd containers still exist. Remove old project rules before
recreating those containers, then install/retest new ones before enabling the proxy. Reinstall after reboot;
otherwise do not open the interactive service. A container-network recreation changes source IP state.

```sh
docker compose -p "$PROJECT" stop proxy
sudo python3 deploy/guacd/egress.py remove "$PROJECT"
# perform reviewed recreation/upgrade; preserve the volumes
sudo python3 deploy/guacd/egress.py install "$PROJECT"
# independently retest before restarting proxy
```

Engine source is official guacamole-server 1.6.0 and FreeRDP 2.11.7, archive SHA-256 checked before extraction.
The patch advertises the separate `zt-strict-cert-pin` RDP argument; missing/malformed/lowercase-64-hex mismatch
is rejected. The OpenSSL callback hashes the leaf DER on the live socket, uses ExternalCertificateManagement,
clears stock accepted fingerprints, and rejects redirect/gateway flags. No ignore-cert, TOFU or RDP security
fallback. The SSH plugin suppresses all outgoing parameter streams at their shared producer,
disables its argv input handler, and requires `zt-ssh-display-only=true` before target contact.
Core must reject engines missing the relevant arguments. Leave `rdp_strict_pin_verified=false` until an
independent reviewer accepts the **exact image ID/hash** and same-socket negative tests. A configured boolean
is not evidence and cannot substitute for the engine capability check.

VNC stays disabled with `vnc_trusted_cidrs=[]`. Administrator approval is required; none/password is only for
trusted CIDRs and password ≤8 bytes, with no TLS/SSH-equivalent confidentiality or server identity claim.
Windows NLA has not been accepted by xrdp-TLS tests. `production_ready` stays false.

## Persistence, recovery and maintenance

Preserve database, database-auth, runtime-auth, secrets and recordings volumes. **Never use `down -v` on a
real deployment.** Backup all five consistently, including all in-use KEKs and a schema-version-2 manifest;
restore to a new isolated project and verify/recover before opening HTTPS. Old `ZTREC001` is not replayable by
this engine; only authenticated `ZTREC002` NDJSON is supported. Keep old backups/KEKs for their original
software, not as an in-place compatibility promise.

Migrations, backup verification/recovery, KEK rewrap, recording retention and offline audit maintenance remain
explicit CLI actions with maintenance/owner credentials. Stop admissions and finish the bounded drain before
offline maintenance; do not delete active recordings or disable audit guards. Keep required recording enabled,
0700/0600 permissions and the default minimum free disk requirement. Plaintext native guacd recording is disabled.

## Isolated engine acceptance

```sh
python3 -u tests/docker_guacd_acceptance.py --engine-image zeroterm-guacd:1.6.0-strict-pin
```

The runner uses only `/var/tmp/zt-guac-v2-{uuid}`, an independent project/networks and fictional credentials.
It checks real OpenSSH correct/wrong keys, xrdp-TLS correct/wrong pin, VNC none/password, a trusted-CA and
matching-hostname real TLS responder with wrong pin and **zero TLS application bytes on that same socket**,
plus positive pin control and actual egress denials. It saves exact image identity/commands/results and
checks the original `zeroterm-test-*` container IDs are unchanged. Cleanup is only project-owned rules and
resources. Do not replace full API/recording/browser/Windows NLA/fault/recovery/capacity acceptance with this
engine-only evidence. See [execution evidence](../docs/guacamole-execution.md).

The additional fault/recovery runner requires a disposable root-owned Docker fixture and a separately
compiled test-only `tests/guacd-fixture/recording-fault.c` shared library. Pass it to
`tests/docker_browser_fixture.py start --recording-fault-library /var/tmp/zt-guac-v2-.../recording-fault.so`,
then run `tests/browser_recovery.mjs <protected-fixture.json> <evidence-directory> <remote-fixture-directory>`.
The runner scopes every Docker operation to that project, uses a dedicated 512 MiB loop filesystem for
real ENOSPC, preserves the production minimum-free-space validation, and checks cold pg_dump/pg_restore,
new-key-only replay, ten mixed sessions, write/fsync/finalization failure and process restart. The shim
does not enter production images. Stop the fixture with its matching `stop --directory` command to
remove its rules, restored PG, volumes and loop mount. Secret fixture/config/backup files must never
be uploaded as public evidence. CI contains the complete commands.
