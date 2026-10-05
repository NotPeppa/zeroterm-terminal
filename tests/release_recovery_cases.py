"""Recovery phases for the stdlib-only isolated release fixture."""
import base64
import contextlib
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import ssl
import subprocess
import sys
import time
import urllib.error
import uuid

from release_recovery import (ROOT, MIN_FREE, Evidence, active_shell, api, certificate,
    chmod_private, complete_shell, config_for, login, port, seed, sha, sql, ssh_args,
    start_pg, start_process, stop_pg, stop_process, target_config, ticket, wait_server)


def run(root, runtime_only=False):
    os.umask(0o077)
    if os.name != "posix" or os.geteuid() == 0:
        raise RuntimeError("non-root Unix execution required")
    if root.is_symlink():
        raise RuntimeError("acceptance root cannot be a symlink")
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError("unique acceptance root must be owned0700")
    if (root / "gateway").exists() or (root / "source-pg").exists():
        raise RuntimeError("acceptance root contains prior fixture state; choose a new unique directory")
    ev = Evidence(root / "evidence.json")
    ev.add("identity", "observed", uid=os.geteuid(), root=str(root), scope="runtime-only" if runtime_only else "full")
    canonical = root / "canonical-manifest.json"
    if canonical.exists():
        manifest = json.loads(canonical.read_text())
        assert set(manifest["added_runner_sha256"]) == {"tests/release_recovery.py", "tests/release_recovery_cases.py"}
        for name, expected in manifest["added_runner_sha256"].items():
            assert sha(ROOT / name) == expected, "added runner hash mismatch"
        ev.add("canonical-input", "verified", canonical_archive_sha256=manifest["canonical_archive_sha256"], added_runner_sha256=manifest["added_runner_sha256"], fresh_target=manifest["fresh_target"])
    pg = Path(os.environ.get("BASTION_PG_BIN", "/usr/lib/postgresql/17/bin"))
    cargo = shutil.which("cargo")
    ssh, sshd, keygen, openssl = (shutil.which(x) for x in ("ssh", "sshd", "ssh-keygen", "openssl"))
    if not all((cargo, ssh, sshd, keygen, openssl)):
        raise RuntimeError("required acceptance tools missing")
    target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target")).resolve()
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(target), NO_PROXY="localhost,127.0.0.1", no_proxy="localhost,127.0.0.1")
    if env.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
        raise RuntimeError("TLS bypass forbidden")
    with (root / "build.log").open("wb") as log:
        built = subprocess.run([cargo, "build", "--locked", "-p", "bastion-server"], cwd=ROOT, env=env, stdout=log, stderr=log, timeout=1800)
    if built.returncode:
        raise RuntimeError("independent target build failed; see protected build.log")
    server = target / "debug/bastion-server"
    ev.add("binary", "observed", binary_sha256=sha(server), source_manifest_sha256=sha(root / "source-manifest.json") if (root / "source-manifest.json").exists() else "not-supplied")
    used = set()
    def ports(names):
        result = {}
        for name in names:
            p = port()
            while p in used or p in (22, 5432):
                p = port()
            used.add(p)
            result[name] = p
        return result
    p = ports(["db", "api", "gateway", "tls", "metrics", "A", "B"])
    local, records = root / "gateway", root / "recordings"
    records.mkdir(mode=0o700)
    subprocess.run([str(server), "init", "--directory", str(local)], check=True, stdout=subprocess.DEVNULL)
    (local / "database-url").write_text(f"postgres://fixture@127.0.0.1:{p['db']}/postgres")
    chmod_private(local / "database-url")
    config = root / "production.toml"
    server_id = "release-recovery-" + uuid.uuid4().hex[:12]
    config_for(config, root, local, p["db"], p, server_id, {1:local / "kek-v1"}, 1, records)
    ca, cert, tlskey = certificate(root, openssl)
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    base = f"https://localhost:{p['tls']}"
    password = "fixture-only-" + uuid.uuid4().hex
    children, clusters = [], []
    source_pg_running = False
    def command(name, configuration, *extra, success=True):
        with (root / f"{name}-{uuid.uuid4().hex[:8]}.log").open("wb") as log:
            result = subprocess.run([str(server), name, "--config", str(configuration), *extra], stdout=log, stderr=log, timeout=30, env=env)
        if (result.returncode == 0) != success:
            raise AssertionError(f"{name}: expected success={success}, actual exit={result.returncode}")
        return result.returncode
    def gateway(configuration, pp, label):
        log = root / f"gateway-{label}.log"
        proc = start_process([str(server), "serve", "--config", str(configuration)], log, env)
        children.append(proc)
        wait_server(pp["api"], proc, log)
        return proc
    def proxy(pp, label):
        log = root / f"tls-{label}.log"
        proc = start_process([sys.executable, str(ROOT / "tests/m3_tls_proxy.py"), "--port", str(pp["tls"]), "--upstream-port", str(pp["api"]), "--certificate", str(cert), "--key", str(tlskey), "--trusted-proxy-headers"], log, env)
        children.append(proc)
        wait_server(pp["tls"], proc, log)
    def recording(token, issued):
        rec_id = sql(pg, p["db"], f"SELECT r.id FROM recordings r JOIN channels ch ON r.channel_id=ch.id WHERE ch.connection_id='{issued['connection_id']}'")
        assert rec_id, "shell recording metadata missing"
        for _ in range(30):
            meta = api(base, context, "GET", f"/recordings/{rec_id}", token=token)
            if meta["state"] == "complete":
                return meta
            time.sleep(.2)
        raise AssertionError("recording not complete after shell completion")
    def replay(at_base, token, rec_id):
        raw, headers = api(at_base, context, "GET", f"/recordings/{rec_id}/content", token=token, raw=True)
        assert headers["Cache-Control"] == "no-store"
        events = [json.loads(line) for line in raw.splitlines()]
        assert events[0]["type"] == "meta" and events[-1]["type"] == "end"
        assert [x["seq"] for x in events] == list(range(len(events)))
        return raw
    def runtime_checks():
        # Source runtime permission loss, revoke, crash/restart and DB loss.
        (root/"known_hosts").write_text(f"[127.0.0.1]:{p['gateway']} "+(local/"ssh_host_ed25519_key.pub").read_text()+"\n")
        gw=gateway(config,p,"runtime")
        operator=login(base,context,"operator",password)
        admin=login(base,context,"admin",password)
        permission_ticket=ticket(base,context,operator,assets[0])
        records.chmod(0o500)
        args,ssh_env=ssh_args(root,permission_ticket,p["gateway"],ssh)
        denied=subprocess.run(args[:-1]+["-T",args[-1]],input=b"printf SHOULD-NOT-RUN; exit\n",capture_output=True,env=ssh_env,timeout=12)
        records.chmod(0o700)
        assert denied.returncode!=0 and b"SHOULD-NOT-RUN" not in denied.stdout
        assert sql(pg,p["db"],f"SELECT count(*) FROM channels WHERE connection_id='{permission_ticket['connection_id']}' AND state='streaming'")=="0"
        ev.add("required-shell-recording-permission-loss", "pass", shell_denied=True, streaming_channels=0)
        # Revoke precisely the current family, with a live recorded shell.
        issued=ticket(base,context,operator,assets[0]);live=active_shell(root,issued,p["gateway"],ssh);children.append(live)
        family=next(x for x in api(base,context,"GET","/me/sessions",token=operator)["items"] if x["current"])
        t=time.monotonic();api(base,context,"DELETE",f"/me/sessions/{family['id']}",token=operator,expected=204)
        live.wait(timeout=7);elapsed=time.monotonic()-t
        assert elapsed<7
        ev.add("active-shell-device-revoke", "pass", close_seconds=round(elapsed,3), exit_code=live.returncode)
        operator=login(base,context,"operator",password)
        unused=ticket(base,context,operator,assets[0])
        crash=ticket(base,context,operator,assets[0]);live=active_shell(root,crash,p["gateway"],ssh);children.append(live)
        stop_process(gw,kill=True);live.wait(timeout=7)
        gw=gateway(config,p,"post-sigkill")
        assert sql(pg,p["db"],f"SELECT state FROM connections WHERE id='{crash['connection_id']}'")=="interrupted"
        assert sql(pg,p["db"],f"SELECT state FROM connection_tickets WHERE connection_id='{unused['connection_id']}'")=="revoked"
        ev.add("sigkill-restart-recovery", "pass", connection_state="interrupted", unused_ticket_revoked=True, old_host_key_unchanged=sha(local/"ssh_host_ed25519_key.pub")==host_hash)
        issued=ticket(base,context,operator,assets[0]);live=active_shell(root,issued,p["gateway"],ssh);children.append(live)
        t=time.monotonic()
        subprocess.run([str(pg/"pg_ctl"),"-D",str(source_data),"-m","fast","-w","stop"],check=True,stdout=subprocess.DEVNULL)
        source_pg_running=False
        live.wait(timeout=7)
        elapsed=time.monotonic()-t
        assert elapsed<=5
        ev.add("database-fast-stop-active-shell", "pass", close_seconds=round(elapsed,3), exit_code=live.returncode, grace_target_seconds=5, fixture_deadline_seconds=7)
        stop_process(gw)

    try:
        source_data = start_pg(pg, root / "source-pg", p["db"])
        clusters.append(source_data)
        source_pg_running = True
        command("migrate", config)
        with (root / "create-admin.log").open("wb") as log:
            subprocess.run([str(server), "create-admin", "--config", str(config), "--username", "admin", "--password-stdin"], input=password + "\n", text=True, check=True, stdout=log, stderr=log)
        for name in ("target-A", "target-B", "target-user"):
            subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        for name in ("A", "B"):
            log = root / f"sshd-{name}.log"
            proc = start_process([sshd, "-D", "-e", "-f", str(target_config(root, name, p[name]))], log, env)
            children.append(proc)
            wait_server(p[name], proc, log)
        host_hash = sha(local / "ssh_host_ed25519_key.pub")
        private_host_hash = sha(local / "ssh_host_ed25519_key")
        (root / "known_hosts").write_text(f"[127.0.0.1]:{p['gateway']} " + (local / "ssh_host_ed25519_key.pub").read_text() + "\n")
        gw = gateway(config, p, "initial")
        proxy(p, "source")
        assets = seed(base, ca, root, password, [("A",p["A"]),("B",p["B"])])
        operator = login(base, context, "operator", password)
        admin = login(base, context, "admin", password)
        info = api(base, context, "GET", "/info")
        assert info["production_ready"] is False and info["recording"]["available"]
        ev.add("required-recording", "pass", production_ready=False, required=info["recording"]["required"], available=True)
        bad_dir = root / "bad-recordings"
        bad_dir.mkdir(mode=0o700);bad_dir.chmod(0o755)
        bad = root / "bad-mode.toml"
        config_for(bad, root, local, p["db"], p, server_id, {1:local/"kek-v1"}, 1, bad_dir)
        command("serve", bad, success=False)
        ev.add("recording-directory-mode", "pass", mode="0755", service_start_rejected=True)
        low = root / "low-space.toml"
        available = shutil.disk_usage(records).free
        low.write_text(config.read_text().replace(f"minimum_free_bytes = {MIN_FREE}", f"minimum_free_bytes = {available + 1024*1024*1024}"))
        command("serve", low, success=False)
        ev.add("low-free-space-preflight", "pass", free_bytes=available, required_bytes=available+1024*1024*1024, service_start_rejected=True, disk_fill=False)
        if runtime_only:
            stop_process(gw)
            runtime_checks()
            ev.add("summary", "pass", scope="runtime-only", production_ready=False, backup_and_complete_replay_not_claimed=True)
            return
        issued = ticket(base, context, operator, assets[0])
        complete_shell(root, issued, p["gateway"], ssh)
        meta = recording(operator, issued)
        rec_id = meta["id"]
        plain = replay(base, operator, rec_id)
        record_file = records / sql(pg,p["db"],f"SELECT relative_path FROM recordings WHERE id='{rec_id}'")
        original_hash = sha(record_file)
        ev.add("recording-complete-replay", "pass", state=meta["state"], encrypted_sha256=original_hash, encrypted_bytes=meta["bytes"], replay_bytes=len(plain))
        # Snapshot a valid complete-only backup with a still-unconsumed ticket and active logins.
        pending = ticket(base, context, operator, assets[0])
        stop_process(gw)
        backup = root / "backup"
        backup.mkdir(mode=0o700)
        snapshot_records = backup / "recordings"
        shutil.copytree(records, snapshot_records)
        dump = backup / "database.dump"
        subprocess.run([str(pg/"pg_dump"),"-Fc","-h","127.0.0.1","-p",str(p["db"]),"-U","fixture","-d","postgres","-f",str(dump)],check=True,capture_output=True)
        counts={"credential_count":int(sql(pg,p["db"],"SELECT count(*) FROM credentials")),"recording_count":int(sql(pg,p["db"],"SELECT count(*) FROM recordings WHERE state<>'expired'")),"host_key_count":int(sql(pg,p["db"],"SELECT count(*) FROM asset_host_keys WHERE state='approved'")),"kek_versions":[int(v) for v in sql(pg,p["db"],"SELECT key_version FROM credentials UNION SELECT key_version FROM recordings WHERE state<>'expired' ORDER BY key_version").splitlines()]}
        manifest=backup/"manifest.json"
        manifest.write_text(json.dumps({"server_id":server_id,"schema_version":1,**counts}));chmod_private(manifest)
        assert counts["recording_count"]==1
        # Restore into a different real PostgreSQL cluster, not the source cluster.
        restored=root/"restore";restored.mkdir(mode=0o700)
        rp=ports(["db","api","gateway","tls","metrics"])
        restore_data=start_pg(pg,restored/"pg",rp["db"]);clusters.append(restore_data)
        subprocess.run([str(pg/"pg_restore"),"-h","127.0.0.1","-p",str(rp["db"]),"-U","fixture","-d","postgres",str(dump)],check=True,capture_output=True)
        rl=restored/"gateway";rl.mkdir(mode=0o700)
        for name in ("kek-v1","ssh_host_ed25519_key","ssh_host_ed25519_key.pub"):
            shutil.copy2(local/name,rl/name)
        (rl/"database-url").write_text(f"postgres://fixture@127.0.0.1:{rp['db']}/postgres");chmod_private(rl/"database-url")
        rr=restored/"recordings";shutil.copytree(snapshot_records,rr)
        rc=restored/"production.toml"
        config_for(rc,restored,rl,rp["db"],rp,server_id,{1:rl/"kek-v1"},1,rr)
        command("verify-backup",rc,"--manifest",str(manifest))
        assert sha(rl/"ssh_host_ed25519_key.pub")==host_hash
        assert sha(rl/"ssh_host_ed25519_key")==private_host_hash
        command("recover-restore",rc)
        assert sql(pg,rp["db"],"SELECT count(*) FROM login_sessions WHERE revoked_at IS NULL")=="0"
        assert sql(pg,rp["db"],"SELECT count(*) FROM connection_tickets WHERE state='issued'")=="0"
        rg=gateway(rc,rp,"restored");proxy(rp,"restore")
        rbase=f"https://localhost:{rp['tls']}"
        api(rbase,context,"GET","/me",token=operator,expected=401)
        (root/"known_hosts").write_text(f"[127.0.0.1]:{rp['gateway']} "+(rl/"ssh_host_ed25519_key.pub").read_text()+"\n")
        old_args,old_env=ssh_args(root,pending,rp["gateway"],ssh)
        old_ticket_result=subprocess.run(old_args[:-1]+["-T",old_args[-1]],input=b"printf REPLAYED-OLD-TICKET; exit\n",capture_output=True,env=old_env,timeout=12)
        assert old_ticket_result.returncode!=0 and b"REPLAYED-OLD-TICKET" not in old_ticket_result.stdout
        restored_operator=login(rbase,context,"operator",password)
        restored_admin=login(rbase,context,"admin",password)
        assert replay(rbase,restored_operator,rec_id)==plain
        account_test=api(rbase,context,"POST",f"/admin/accounts/{assets[0]['account_id']}/test",token=restored_admin,payload={})
        assert account_test["authenticated"]
        ev.add("backup-restore", "pass", counts=counts, host_key_sha256=host_hash, private_host_key_unchanged=True, credential_authentication=True, replay_identical=True, restored_live_login_families=0, restored_pending_tickets=0, old_bearer_rejected=True, old_native_ticket_rejected=True)
        stop_process(rg)
        c_before=sql(pg,rp["db"],"SELECT id||':'||encode(ciphertext,'hex')||':'||encode(nonce,'hex') FROM credentials ORDER BY id")
        n_before=sql(pg,rp["db"],"SELECT id||':'||encode(nonce_prefix,'hex') FROM recordings ORDER BY id")
        w_before=sql(pg,rp["db"],"SELECT id||':'||encode(wrapped_dek,'hex')||':'||encode(wrap_nonce,'hex') FROM recordings ORDER BY id")
        f_before={f.name:sha(f) for f in rr.glob("*.ztrec")}
        key2=rl/"kek-v2";key2.write_bytes(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"="));chmod_private(key2)
        v2=restored/"v2.toml"
        config_for(v2,restored,rl,rp["db"],rp,server_id,{1:rl/"kek-v1",2:key2},2,rr)
        command("rewrap-keys",v2)
        assert c_before==sql(pg,rp["db"],"SELECT id||':'||encode(ciphertext,'hex')||':'||encode(nonce,'hex') FROM credentials ORDER BY id")
        assert n_before==sql(pg,rp["db"],"SELECT id||':'||encode(nonce_prefix,'hex') FROM recordings ORDER BY id")
        assert w_before!=sql(pg,rp["db"],"SELECT id||':'||encode(wrapped_dek,'hex')||':'||encode(wrap_nonce,'hex') FROM recordings ORDER BY id")
        assert f_before=={f.name:sha(f) for f in rr.glob("*.ztrec")}
        newonly=restored/"new-key-only.toml"
        config_for(newonly,restored,rl,rp["db"],rp,server_id,{2:key2},2,rr)
        new_manifest=backup/"manifest-v2.json";new_manifest.write_text(json.dumps({"server_id":server_id,"schema_version":1,**counts,"kek_versions":[2]}))
        command("verify-backup",newonly,"--manifest",str(new_manifest))
        rg=gateway(newonly,rp,"new-key-only")
        restored_operator=login(rbase,context,"operator",password)
        assert replay(rbase,restored_operator,rec_id)==plain
        restored_admin=login(rbase,context,"admin",password)
        assert api(rbase,context,"POST",f"/admin/accounts/{assets[0]['account_id']}/test",token=restored_admin,payload={})["authenticated"]
        ev.add("kek-rewrap", "pass", credential_ciphertext_and_nonce_unchanged=True, recording_nonce_prefix_unchanged=True, file_hash_unchanged=True, new_key_only_decrypt_and_replay=True)
        stop_process(rg)
        missing=restored/"missing-kek.toml"
        config_for(missing,restored,rl,rp["db"],rp,server_id,{1:rl/"kek-v1"},1,rr)
        command("serve",missing,success=False)
        ev.add("missing-in-use-kek", "pass", startup_rejected=True)
        # Corruption runs against restored DB so the valid original backup stays immutable.
        rg=gateway(newonly,rp,"corruption")
        restored_operator=login(rbase,context,"operator",password)
        rf=rr/record_file.name
        good=rf.read_bytes();changed=bytearray(good);changed[-20]^=1;rf.write_bytes(changed)
        failed=False
        try:
            replay(rbase,restored_operator,rec_id)
        except (http.client.IncompleteRead, urllib.error.URLError, OSError, AssertionError):
            failed=True
        assert failed and sql(pg,rp["db"],f"SELECT state FROM recordings WHERE id='{rec_id}'")=="corrupt"
        ev.add("recording-aead-corruption", "pass", clean_eof=False, state="corrupt", complete=False)
        # A separate complete recording proves truncation without resetting metadata by hand.
        second=ticket(rbase,context,restored_operator,assets[0]);
        (root/"known_hosts").write_text(f"[127.0.0.1]:{rp['gateway']} "+(rl/"ssh_host_ed25519_key.pub").read_text()+"\n")
        complete_shell(root,second,rp["gateway"],ssh)
        rid=sql(pg,rp["db"],f"SELECT r.id FROM recordings r JOIN channels ch ON r.channel_id=ch.id WHERE ch.connection_id='{second['connection_id']}'")
        for _ in range(30):
            if sql(pg,rp["db"],f"SELECT state FROM recordings WHERE id='{rid}'")=="complete":break
            time.sleep(.2)
        path=rr/sql(pg,rp["db"],f"SELECT relative_path FROM recordings WHERE id='{rid}'")
        path.write_bytes(path.read_bytes()[:-17])
        error=api(rbase,context,"GET",f"/recordings/{rid}/content",token=restored_operator,expected=503)
        assert error["error"]["code"]=="RECORDING_UNAVAILABLE"
        assert sql(pg,rp["db"],f"SELECT state FROM recordings WHERE id='{rid}'")=="corrupt"
        ev.add("recording-truncation", "pass", http_status=503, safe_code=error["error"]["code"], state="corrupt")
        runtime_checks()
        ev.add("write-blocking-and-disk-full", "not-tested", reason="no safe bounded dedicated filesystem fixture; no host disk fill or fake production bypass")
        ev.add("summary", "pass", production_ready=False, remote_ports=sorted(used))
    except Exception as error:
        import traceback
        ev.add("failure", "fail", exception=type(error).__name__, safe_message=str(error) if isinstance(error,(RuntimeError,AssertionError)) else "subprocess or transport failure", locations=[f"{Path(frame.filename).name}:{frame.lineno}" for frame in traceback.extract_tb(error.__traceback__)])
        raise
    finally:
        started=time.monotonic()
        for proc in reversed(children):
            stop_process(proc)
        for data in reversed(clusters):
            if (data/"postmaster.pid").exists():
                with contextlib.suppress(Exception):stop_pg(pg,data)
        ev.add("cleanup", "observed", elapsed_seconds=round(time.monotonic()-started,3), owned_children_still_running=sum(proc.poll() is None for proc in children), postgres_pid_files_remaining=sum((data/"postmaster.pid").exists() for data in clusters), stops=[getattr(proc,"_release_stop",{"pid":proc.pid,"already_exited":True}) for proc in children])
        print(f"EVIDENCE {ev.path}",flush=True)
