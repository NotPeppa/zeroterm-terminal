#!/usr/bin/env python3
"""UID1000 native recording tests; root supervisor owns only the dedicated loop FS."""
import argparse
import base64
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import ssl
import subprocess
import sys
import time
import uuid


def run(args):
    assert os.name == "posix" and os.geteuid() == 1000
    os.umask(0o077)
    sys.path.insert(0, str(args.helpers))
    import release_recovery as h
    h.ROOT = args.source
    root = args.root.resolve()
    root.mkdir(mode=0o700, exist_ok=True)
    assert root.stat().st_uid == 1000 and root.stat().st_mode & 0o777 == 0o700
    records = args.records.resolve()
    assert records == args.manager.resolve() / "recording-mount"
    assert records.stat().st_uid == 1000 and records.stat().st_mode & 0o777 == 0o700
    assert os.stat(records).st_dev != os.stat(root).st_dev
    ev = h.Evidence(root / "evidence.json")
    ev.add("identity", "verified", uid=os.geteuid(), pid=os.getpid(), fixture_root=str(root), mounted_recordings=str(records), production_ready=False)
    manifest = json.loads((args.manager / "input-manifest.json").read_text())
    assert h.sha(args.server) == args.binary_sha
    ev.add("inputs", "verified", canonical_archive_sha256=manifest["canonical_archive_sha256"], source_overlays=manifest["source_overlays"], binary_sha256=args.binary_sha, driver_sha256=h.sha(Path(__file__)))
    used = set()
    ports = {}
    for name in ("db", "api", "gateway", "tls", "metrics", "A", "B"):
        p = h.port()
        while p in used or p in (22, 5432):
            p = h.port()
        used.add(p); ports[name] = p
    pg = Path("/usr/lib/postgresql/17/bin")
    ssh, sshd, keygen, openssl = (shutil.which(n) for n in ("ssh", "sshd", "ssh-keygen", "openssl"))
    assert all((ssh, sshd, keygen, openssl))
    children = []
    data = None
    local = root / "gateway"
    password = "fixture-" + uuid.uuid4().hex
    context = None
    try:
        subprocess.run([str(args.server), "init", "--directory", str(local)], check=True, stdout=subprocess.DEVNULL)
        (local / "database-url").write_text(f"postgres://fixture@127.0.0.1:{ports['db']}/postgres")
        h.chmod_private(local / "database-url")
        config = root / "production.toml"
        server_id = "record-fault-" + uuid.uuid4().hex[:12]
        h.config_for(config, root, local, ports["db"], ports, server_id, {1: local / "kek-v1"}, 1, records)
        data = h.start_pg(pg, root / "pg", ports["db"])
        with (root / "bootstrap.log").open("wb") as log:
            subprocess.run([str(args.server), "migrate", "--config", str(config)], check=True, stdout=log, stderr=log)
            subprocess.run([str(args.server), "create-admin", "--config", str(config), "--username", "admin", "--password-stdin"], input=password + "\n", text=True, check=True, stdout=log, stderr=log)
        for name in ("target-A", "target-B", "target-user"):
            subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        for name in ("A", "B"):
            log = root / f"sshd-{name}.log"
            child = h.start_process([sshd, "-D", "-e", "-f", str(h.target_config(root, name, ports[name]))], log)
            children.append(child); h.wait_server(ports[name], child, log)
        gateway_log = root / "gateway.log"
        gateway = h.start_process([str(args.server), "serve", "--config", str(config)], gateway_log)
        children.append(gateway); h.wait_server(ports["api"], gateway, gateway_log)
        ca, cert, key = h.certificate(root, openssl)
        tls_log = root / "tls.log"
        tls = h.start_process([sys.executable, str(args.source / "tests/m3_tls_proxy.py"), "--port", str(ports["tls"]), "--upstream-port", str(ports["api"]), "--certificate", str(cert), "--key", str(key), "--trusted-proxy-headers"], tls_log)
        children.append(tls); h.wait_server(ports["tls"], tls, tls_log)
        context = ssl.create_default_context(cafile=str(ca))
        base = f"https://localhost:{ports['tls']}"
        assets = h.seed(base, ca, root, password, [(n, ports[n]) for n in ("A", "B")])
        token = h.login(base, context, "operator", password)
        (root / "known_hosts").write_text(f"[127.0.0.1]:{ports['gateway']} " + (local / "ssh_host_ed25519_key.pub").read_text() + "\n")
        assert shutil.disk_usage(records).free >= h.MIN_FREE
        info = h.api(base, context, "GET", "/info")
        assert info["production_ready"] is False and info["recording"]["required"] and info["recording"]["available"]
        ev.add("production-start", "pass", actual_free_bytes=shutil.disk_usage(records).free, minimum_free_bytes=h.MIN_FREE, gateway_pid=gateway.pid, pg_pid=int((data / "postmaster.pid").read_text().splitlines()[0]), owned_child_pids=[p.pid for p in children])

        def row(connection):
            value = h.sql(pg, ports["db"], f"SELECT r.id||'|'||r.state||'|'||COALESCE(r.checksum,'')||'|'||r.last_written_seq||'|'||r.last_synced_seq||'|'||COALESCE(ch.exit_code::text,'')||'|'||COALESCE(ch.failure_code,'') FROM recordings r JOIN channels ch ON ch.id=r.channel_id WHERE ch.connection_id='{connection}'")
            return value.split("|") if value else []

        # No login loop/rate workaround: one native family, twenty fresh single-use tickets.
        for sample in range(1, 21):
            issued = h.ticket(base, context, token, assets[0])
            h.complete_shell(root, issued, ports["gateway"], ssh)
            observed = row(issued["connection_id"])
            assert len(observed) == 7 and observed[1] == "complete" and len(observed[2]) == 64 and observed[3] == observed[4] and observed[5] == "7" and not observed[6], "healthy close must already have durable Complete metadata"
            assert h.sha(records / (observed[0] + ".ztrec")) == observed[2]
            raw, headers = h.api(base, context, "GET", f"/recordings/{observed[0]}/content", token=token, raw=True)
            frames = [json.loads(line) for line in raw.splitlines()]
            assert frames[0]["type"] == "meta" and frames[-1]["type"] == "end"
            assert [f["seq"] for f in frames] == list(range(len(frames)))
            assert any(f["type"] == "exit" and f["exit_code"] == 7 for f in frames)
            assert headers["Cache-Control"] == "no-store"
            ev.add("healthy-native-close", "pass", sample=sample, state=observed[1], exit_code=7, checksum_present=True, last_written_seq=int(observed[3]), last_synced_seq=int(observed[4]), observed_immediately_after_client_exit=True, authenticated_replay=True, clean_eof=True)

        key_blob = base64.b64decode((local / "ssh_host_ed25519_key.pub").read_text().split()[1])
        pin = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip("=")
        native_fixture = root / "native-fixture.json"
        native_fixture.write_text(json.dumps({"api_url": base, "username": "operator", "password": password, "server_id": server_id, "gateway_host": "127.0.0.1", "gateway_port": ports["gateway"], "gateway_host_key_sha256": pin, "ca_file": str(ca), "fixture_root": str(root), "database_url_file": str(local / "database-url"), "assets": [dict(asset, name="M3 target " + name, username="bastion-acceptance") for asset, name in zip(assets, ("A", "B"))]}) + "\n")
        h.chmod_private(native_fixture)
        ev.add("native-cli-barrier", "ready", fixture_file=str(native_fixture), fixture_owner_uid=native_fixture.stat().st_uid, file_mode="0600", server_binary_sha256=args.binary_sha, continue_file=str(root / "native-continue"), hold_limit_seconds=150)
        until = time.monotonic() + 150
        while not (root / "native-continue").exists() and time.monotonic() < until:
            assert all(child.poll() is None for child in children)
            time.sleep(0.05)
        ev.add("native-cli-barrier-result", "released" if (root / "native-continue").exists() else "not-tested", continuation_received=(root / "native-continue").exists())

        def active(label):
            issued = h.ticket(base, context, token, assets[0])
            command, environment = h.ssh_args(root, issued, ports["gateway"], ssh)
            peer = subprocess.Popen(command[:-1] + ["-T", command[-1]], env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            children.append(peer)
            peer.stdin.write(b"printf '\\nFAULT-READY\\n'\n"); peer.stdin.flush()
            output = b""; deadline = time.monotonic() + 12
            while time.monotonic() < deadline and peer.poll() is None:
                if select.select([peer.stdout], [], [], 0.05)[0]:
                    output += os.read(peer.stdout.fileno(), 65536)
                    if b"\nFAULT-READY\n" in output:
                        observed = row(issued["connection_id"])
                        assert observed[1] == "active"
                        channel_state = h.sql(pg, ports["db"], f"SELECT state FROM channels WHERE connection_id='{issued['connection_id']}'")
                        assert channel_state == "streaming"
                        ev.add(label + "-streaming", "verified", peer_pid=peer.pid, recording_id=observed[0], recording_state=observed[1], channel_state=channel_state, free_bytes=shutil.disk_usage(records).free)
                        return peer, issued["connection_id"], output
            raise AssertionError("native recorded shell did not reach Streaming")

        def closed(peer, initial, marker):
            started = time.monotonic(); peer.stdin.write(b"printf '\\n" + marker + b"\\n'\n"); peer.stdin.flush()
            output = initial; deadline = started + 12
            while time.monotonic() < deadline:
                if select.select([peer.stdout], [], [], 0.005)[0]:
                    chunk = os.read(peer.stdout.fileno(), 65536)
                    if not chunk:
                        elapsed = time.monotonic() - started
                        peer.wait(timeout=2)
                        assert marker not in output, "unrecorded marker was forwarded"
                        return elapsed, output
                    output += chunk
                if peer.poll() is not None:
                    output += peer.stdout.read(); elapsed = time.monotonic() - started
                    assert marker not in output, "unrecorded marker was forwarded"
                    return elapsed, output
            raise AssertionError("faulted native client failed to close")

        def failed_metadata(connection):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                observed = row(connection)
                if observed and observed[1] in ("partial", "failed"):
                    assert observed[6] == "RECORDING_UNAVAILABLE"
                    return observed
                assert not observed or observed[1] != "complete", "faulted recording incorrectly marked Complete"
                time.sleep(0.05)
            raise AssertionError("fault metadata did not settle Partial/Failed within twenty seconds")

        peer, connection, initial = active("full-filesystem")
        filler = records / "bounded-fill"
        fd = os.open(filler, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        allocated = 0; enospc = False; last_failed_block = 0
        try:
            for block in (64 * 1024 * 1024, 1024 * 1024, 4096):
                while allocated + block <= 512 * 1024 * 1024:
                    try:
                        os.posix_fallocate(fd, allocated, block); allocated += block
                    except OSError as error:
                        if error.errno != errno.ENOSPC: raise
                        enospc = True; last_failed_block = block; break
            os.fsync(fd)
        finally:
            os.close(fd)
        available = shutil.disk_usage(records).free
        assert enospc and last_failed_block == 4096 and available < h.MIN_FREE and allocated <= 512 * 1024 * 1024
        elapsed, output = closed(peer, initial, b"FULL-UNRECORDED-MARKER")
        observed = failed_metadata(connection)
        ev.add("real-full-filesystem", "pass", posix_fallocate_errno=errno.ENOSPC, last_allocation_attempt_bytes=last_failed_block, image_capacity_bytes=512 * 1024 * 1024, filler_allocated_bytes=allocated, actual_free_bytes=available, close_seconds=round(elapsed, 6), marker_forwarded=False, recording_state=observed[1], safe_code=observed[6], recorder_write_enospc_branch_claimed=False, gate="real full filesystem plus production free-space gate")
        assert filler.resolve().parent == records and filler.stat().st_uid == 1000
        filler.unlink()
        directory_fd = os.open(records, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        assert shutil.disk_usage(records).free >= h.MIN_FREE
        peer, connection, initial = active("blocked-write")
        request = args.manager / "freeze.request"
        request.write_text(json.dumps({"driver_pid": os.getpid(), "gateway_pid": gateway.pid}))
        deadline = time.monotonic() + 12
        while not (args.manager / "freeze.ready").exists():
            if time.monotonic() >= deadline: raise AssertionError("root supervisor did not confirm verified freeze")
            time.sleep(0.01)
        elapsed, output = closed(peer, initial, b"FROZEN-UNRECORDED-MARKER")
        strict_close = elapsed <= 5
        ev.add("blocked-write-client-close", "pass" if strict_close else "fail", close_seconds=round(elapsed, 6), strict_send_to_close_limit_seconds=5, strict_limit_satisfied=strict_close, marker_forwarded=False, in_process_ack_budget_seconds=5, end_to_end_network_delay_not_subtracted=True)
        deadline = time.monotonic() + 12
        while not (args.manager / "thaw.done").exists():
            if time.monotonic() >= deadline: raise AssertionError("bounded watchdog thaw not confirmed")
            time.sleep(0.01)
        observed = failed_metadata(connection)
        ev.add("blocked-write-post-thaw", "pass", recording_state=observed[1], safe_code=observed[6], complete=False, watchdog_thaw_confirmed=True)
        ev.add("summary", "pass" if strict_close else "fail", healthy_closes=20, true_full_filesystem=True, real_freeze=True, production_ready=False, strict_send_to_close_five_seconds_passed=strict_close)
        return 0 if strict_close else 1
    except Exception as error:
        import traceback
        ev.add("failure", "fail", exception=type(error).__name__, locations=[f"{Path(f.filename).name}:{f.lineno}" for f in traceback.extract_tb(error.__traceback__)])
        return 1
    finally:
        # Never spend the seven-second child cleanup budget while the filesystem is frozen.
        if (args.manager / "freeze.request").exists():
            until = time.monotonic() + 15
            while not (args.manager / "thaw.done").exists() and time.monotonic() < until: time.sleep(0.05)
        for child in reversed(children): h.stop_process(child)
        if data is not None and (data / "postmaster.pid").exists(): h.stop_pg(pg, data)
        ev.add("cleanup", "observed", owned_children_still_running=sum(p.poll() is None for p in children), postgres_pid_file_remaining=bool(data is not None and (data / "postmaster.pid").exists()), stops=[getattr(p, "_release_stop", {"pid": p.pid, "already_exited": True}) for p in children])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "manager", "source", "helpers", "records", "server"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha", required=True)
    raise SystemExit(run(parser.parse_args()))
