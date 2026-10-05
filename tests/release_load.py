#!/usr/bin/env python3
"""Owned non-root release load fixture. Never reuse a DB/listener or relax gateway caps.

Full mode runs >=3600 seconds with 50 required-recording shells plus four 1GiB
streamed file transfers and20 extra terminals. --preflight is explicitly NOT
release evidence. All transient keys/passwords stay in the isolated0700 fixture.
"""
import argparse
import contextlib
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from unittest.mock import patch

from m3_https_smoke import certificate, pg_directory, private_json, production_config, seed, target_config
from m1_smoke import database, request
from openssh_smoke import port, process, wait_port

GIB = 1024 ** 3
STAGE='validation'


def public_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(32768):
            digest.update(chunk)
    return digest.hexdigest()


def make_random_file(path, size):
    digest = hashlib.sha256()
    with path.open("xb") as output:
        path.chmod(0o600)
        remaining = size
        while remaining:
            chunk = secrets.token_bytes(min(32768, remaining))
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def seed_load_users(base, ca, password, asset):
    original_opener = urllib.request.build_opener
    context = ssl.create_default_context(cafile=str(ca))
    def verified_opener(*handlers):
        return original_opener(*handlers, urllib.request.HTTPSHandler(context=context))
    with patch("urllib.request.build_opener", verified_opener):
        admin = request(base, "/auth/login", {"username": "admin", "password": password, "device_label": "isolated load seed", "client_type": "zeroterm"})
        token = admin["access_token"]
        try:
            users = []
            for index in range(13):
                username = f"load{index}"
                user = request(base, "/admin/users", {"username": username, "password": password, "role": "operator"}, token=token, expected=201)
                request(base, "/admin/grants", {"user_id": user["id"], **asset, "capabilities": ["shell", "exec", "sftp"]}, token=token, expected=201)
                users.append(username)
            request(base, "/auth/logout", {}, token=token, expected=204)
            return users
        except AssertionError:
            raise RuntimeError("isolated load seed validation failed; no response body logged") from None
        finally:
            admin.clear()
            token = ""


def baseline(root, data, target_port, log):
    known = root / "known_hosts"
    public = " ".join((root / "target-A.pub").read_text().split()[:2])
    known.write_text(f"[127.0.0.1]:{target_port} {public}\n", encoding="utf-8")
    known.chmod(0o600)
    remote, output = root / "baseline-remote.bin", root / "baseline-download.bin"
    args = ["sftp", "-B", "32768", "-F", "/dev/null", "-q", "-i", str(root / "target-user"), "-P", str(target_port), "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-b"]
    results = {}
    for name, command in (("upload", f'put "{data["local"]}" "{remote}"\n'), ("download", f'get "{remote}" "{output}"\n')):
        batch = root / f"baseline-{name}.batch"
        batch.write_text(command, encoding="utf-8")
        batch.chmod(0o600)
        started = time.monotonic()
        completed = subprocess.run([*args, str(batch), f"{getpass.getuser()}@127.0.0.1"], stdout=log, stderr=log, timeout=900)
        if completed.returncode:
            raise RuntimeError(f"pinned direct SFTP {name} baseline failed")
        seconds = time.monotonic() - started
        results[name] = {"seconds": seconds, "bytes": data["size"], "bytes_per_second": data["size"] / seconds}
    results["sha256_equal"] = hash_file(output) == data["sha256"] == hash_file(remote)
    if not results["sha256_equal"]:
        raise RuntimeError("direct SFTP baseline SHA256 mismatch")
    output.unlink()
    remote.unlink()
    return results


def sample_processes(root, children, destination, stopped):
    previous = {}
    ticks = os.sysconf("SC_CLK_TCK")
    page = os.sysconf("SC_PAGE_SIZE")
    with destination.open("w", encoding="utf-8") as output:
        destination.chmod(0o600)
        while not stopped.wait(5):
            item = {"timestamp": time.time(), "disk_free_bytes": shutil.disk_usage(root).free, "host_load_average":list(os.getloadavg()), "processes": {}}
            memory=Path('/proc/meminfo').read_text().splitlines()
            item['host_mem_available_bytes']=next(int(line.split()[1])*1024 for line in memory if line.startswith('MemAvailable:'))
            for name, child in list(children.items()):
                try:
                    raw = Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()
                    cpu = (int(raw[11]) + int(raw[12])) / ticks
                    memory = Path(f"/proc/{child.pid}/statm").read_text().split()
                    before = previous.get(name)
                    now = time.monotonic()
                    previous[name] = (now, cpu)
                    item["processes"][name] = {"pid": child.pid, "rss_bytes": int(memory[1]) * page, "fd_count": len(list(Path(f"/proc/{child.pid}/fd").iterdir())), "cpu_percent": 0 if not before else 100 * (cpu - before[1]) / (now - before[0]), "alive": child.poll() is None}
                except (FileNotFoundError, ProcessLookupError):
                    item["processes"][name] = {"alive": False}
            files = list((root / "recordings").glob("*.ztrec"))
            item["recording_files"] = len(files)
            item["recording_bytes"] = sum(path.stat().st_size for path in files if path.exists())
            output.write(json.dumps(item) + "\n")
            output.flush()


def run(args):
    global STAGE
    STAGE='validation'
    if os.name != "posix" or os.geteuid() == 0 or os.geteuid() != 1000:
        raise RuntimeError("load fixture requires isolated acceptance UID1000, not root")
    if os.environ.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
        raise RuntimeError("TLS bypass is forbidden")
    source, workspace = args.source.resolve(), args.root.resolve()
    if workspace.is_symlink() or workspace.stat().st_uid != os.geteuid() or workspace.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError("owned load root must be0700 and not a symlink")
    if args.perf_check and (args.preflight or not 30 <= args.seconds <= 600):
        raise RuntimeError('short mixed performance checks require30..600seconds and are not full-hour evidence')
    if not args.preflight and not args.perf_check and args.seconds < 3600:
        raise RuntimeError("release evidence requires full one-hour duration")
    binaries = {name: shutil.which(name) for name in ("cargo", "node", "sshd", "ssh-keygen", "openssl", "sftp")}
    if not all(binaries.values()):
        raise RuntimeError("isolated fixture dependencies missing")
    pg = pg_directory()
    identity={'source_path':str(source),'build_profile':'release' if args.release else 'dev','perf_check':args.perf_check,'acceptance_scope':'short mixed performance check, NOT one-hour acceptance' if args.perf_check else ('short preflight, NOT one-hour acceptance' if args.preflight else 'full one-hour workload'),'runner_sha256':{name:hash_file(Path(__file__).with_name(name)) for name in ('release_load.py','release_load.mjs')}}
    if args.source_archive:
        identity['source_archive_sha256']=hash_file(args.source_archive)
        if identity['source_archive_sha256']!=args.source_archive_sha256:raise RuntimeError('canonical source archive SHA256 mismatch')
    public_json(workspace/'source-identity.json',identity)
    public_json(workspace/'status.json',{'state':'building','preflight':args.preflight,'started_at':time.time(),'runner_pid':os.getpid(),**identity})
    STAGE='candidate_build'
    build_log = workspace / "build.log"
    with build_log.open("wb") as log:
        build_log.chmod(0o600)
        command=[binaries["cargo"], "build", "--locked", "--offline", "-p", "bastion-server"]
        if args.release:command.extend(['--release'])
        subprocess.run(command, cwd=source, env={**os.environ,'CARGO_TARGET_DIR':str(source/'target')}, stdout=log, stderr=log, check=True)
    target = source / 'target'
    if not target.is_absolute():
        target = source / target
    server = target / ("release/bastion-server" if args.release else "debug/bastion-server")
    if not server.is_file():
        raise RuntimeError("freshly built candidate not found")
    STAGE='isolated_fixture_setup'
    run_id = secrets.token_hex(8)
    root = workspace / (('p' if args.preflight else 'f') + run_id[:8])
    root.mkdir(parents=True, mode=0o700)
    if shutil.disk_usage(root).free < 16 * GIB:
        raise RuntimeError("load requires >=16GiB free fixture space")
    public_json(workspace / "status.json", {"state": "preparing", "preflight": args.preflight, "started_at": time.time(), "run_id": run_id, "binary_sha256": hash_file(server), **identity})
    ports = {}
    while len(ports) < 7:
        candidate = port()
        if candidate not in ports.values():
            ports[("db", "A", "B", "api", "gateway", "tls", "metrics")[len(ports)]] = candidate
    local = root / "gateway"
    subprocess.run([str(server), "init", "--directory", str(local)], check=True, stdout=subprocess.DEVNULL)
    (local / "database-url").write_text(f"postgres://fixture@127.0.0.1:{ports['db']}/postgres", encoding="utf-8")
    (local / "database-url").chmod(0o600)
    (root / "recordings").mkdir(mode=0o700)
    ca, cert, key = certificate(root, binaries["openssl"])
    base = f"https://localhost:{ports['tls']}"
    config = root / "production.toml"
    production_config(config, root, local, base, ports)
    config.write_text(config.read_text().replace("absolute_seconds = 3600", "absolute_seconds = 28800"), encoding="utf-8")
    for name in ("target-A", "target-B", "target-user"):
        subprocess.run([binaries["ssh-keygen"], "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
    targets = [(name, ports[name]) for name in ("A", "B")]
    password = "fixture-only-" + secrets.token_urlsafe(24)
    stopped = threading.Event()
    try:
        with database(pg, root, ports["db"]):
            subprocess.run([str(server), "migrate", "--config", str(config)], stdout=subprocess.DEVNULL, check=True)
            subprocess.run([str(server), "create-admin", "--config", str(config), "--username", "admin", "--password-stdin"], input=password + "\n", text=True, stdout=subprocess.DEVNULL, check=True)
            with contextlib.ExitStack() as stack:
                children = {}
                for name, value in targets:
                    child = stack.enter_context(process([binaries["sshd"], "-D", "-e", "-f", str(target_config(root, name, value))], root / f"sshd-{name}.log"))
                    children[f"target-{name}"] = child
                    wait_port(value, child, root / f"sshd-{name}.log")
                gateway = stack.enter_context(process([str(server), "serve", "--config", str(config)], root / "gateway.log"))
                children["gateway"] = gateway
                wait_port(ports["api"], gateway, root / "gateway.log")
                proxy = stack.enter_context(process([sys.executable, str(source / "tests/m3_tls_proxy.py"), "--port", str(ports["tls"]), "--upstream-port", str(ports["api"]), "--certificate", str(cert), "--key", str(key), "--trusted-proxy-headers"], root / "tls.log"))
                children["tls-proxy"] = proxy
                wait_port(ports["tls"], proxy, root / "tls.log")
                assets = seed(base, ca, root, password, targets)
                users = seed_load_users(base, ca, password, assets[0])
                size = 64 * 1024 * 1024 if args.preflight else GIB
                data = []
                reused = None
                if args.reuse_files_fixture:
                    donor = args.reuse_files_fixture.resolve()
                    if not args.perf_check or donor.stat().st_uid != os.geteuid() or donor.stat().st_mode & 0o777 != 0o600:
                        raise RuntimeError('source-file reuse requires an owned0600 fixture and explicit short performance mode')
                    reused = json.loads(donor.read_text())['files']
                    if len(reused) != 4: raise RuntimeError('matched reuse requires exactly four sources')
                for index in range(4):
                    path = Path(reused[index]['local']).resolve() if reused else root / f"random-{index}.bin"
                    if reused:
                        if donor.parent not in path.parents or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o777 != 0o600 or path.stat().st_size != size:
                            raise RuntimeError('reused source ownership/mode/size mismatch')
                        digest = hash_file(path)
                        if digest != reused[index]['sha256']: raise RuntimeError('reused source SHA256 mismatch')
                    else:
                        digest = make_random_file(path, size)
                    data.append({"local": str(path), "remote": str(root / f"remote-{index}.bin"), "sha256": digest, "size": size})
                STAGE='direct_sftp_baseline'
                with (root / "direct-sftp.log").open("wb") as log:
                    direct = baseline(root, data[0], ports["A"], log)
                public_json(workspace / "direct-baseline.json", direct)
                fixture = root / "fixture.json"
                private_json(fixture, {"api_url": base, "password": password, "users": users, "asset": assets[0], "files": data, "baseline": direct, "seconds": args.seconds if not args.preflight else 15, "preflight": args.preflight, "workdir": str(workspace), "target_id": "A", "binary_sha256":hash_file(server), **identity})
                public_json(workspace / "owned-runtime.json", {"root": str(root), "ports": ports, "gateway_pid": gateway.pid, "target_pids": {name: child.pid for name, child in children.items()}, "preflight": args.preflight})
                sampler = threading.Thread(target=sample_processes, args=(root, children, workspace / "resources.jsonl", stopped), daemon=True)
                sampler.start()
                env = os.environ.copy()
                env.update(BASTION_RELEASE_LOAD_FIXTURE=str(fixture), NODE_EXTRA_CA_CERTS=str(ca), NO_PROXY="localhost,127.0.0.1", no_proxy="localhost,127.0.0.1")
                STAGE='streaming_workload'
                with (workspace / "client.log").open("wb") as log:
                    (workspace / "client.log").chmod(0o600)
                    client=subprocess.Popen([binaries["node"], str(Path(__file__).with_suffix('.mjs'))], cwd=source, env=env, stdout=log, stderr=log)
                    children['load-client']=client
                    try:
                        client_code=client.wait(timeout=args.seconds+2400)
                    finally:
                        if client.poll() is None:
                            client.terminate()
                            try:client.wait(timeout=7)
                            except subprocess.TimeoutExpired:client.kill();client.wait(timeout=2)
                if client_code:
                    result=json.loads((workspace/'result.json').read_text()) if (workspace/'result.json').exists() else {}
                    raise RuntimeError(f"load client failed in phase {result.get('phase','startup')}; sanitized errors: {json.dumps(result.get('errors',[]))}")
                STAGE='resource_reclamation'
                query="SELECT json_build_object('active_connections',(SELECT count(*) FROM connections WHERE state IN ('connecting','active','closing')),'active_channels',(SELECT count(*) FROM channels WHERE state NOT IN ('closed','failed')),'active_recordings',(SELECT count(*) FROM recordings WHERE state IN ('preparing','active')),'recording_states',(SELECT json_object_agg(state,n) FROM (SELECT state,count(*) n FROM recordings GROUP BY state) counts))"
                for attempt in range(30):
                    sql=subprocess.run([str(pg/'psql'),'-X','-h','127.0.0.1','-p',str(ports['db']),'-U','fixture','-d','postgres','-At','-c',query],check=True,capture_output=True,text=True,timeout=5)
                    reclamation=json.loads(sql.stdout)
                    if all(reclamation[key]==0 for key in ('active_connections','active_channels','active_recordings')):break
                    time.sleep(1)
                public_json(workspace/'reclamation.json',reclamation)
                if any(reclamation[key] for key in ('active_connections','active_channels','active_recordings')):
                    raise RuntimeError('gateway resources did not reclaim within30seconds')
                time.sleep(10)
                stopped.set()
                sampler.join(timeout=10)
                public_json(workspace / "status.json", {"state": "completed", "preflight": args.preflight, "finished_at": time.time(), "run_id": run_id, "binary_sha256": hash_file(server), **identity, "result": "result.json", "resources": "resources.jsonl"})
    finally:
        stopped.set()
        password = ""
    # Preserve private fixture data for evidence inspection; no listener survives.
    print("Owned release fixture exited; public metrics retained, secrets remain private", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument('--perf-check', action='store_true', help='30..600second mixed70-shell matched performance check; NOT one-hour acceptance')
    parser.add_argument('--reuse-files-fixture', type=Path, help='owned private fixture whose exact four1GiB source files are reused')
    parser.add_argument('--release', action='store_true')
    parser.add_argument('--source-archive', type=Path)
    parser.add_argument('--source-archive-sha256', default='bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9')
    args = parser.parse_args()
    try:
        run(args)
    except BaseException as error:
        if args.root.is_dir():
            public_json(args.root / "status.json", {"state": "failed", "preflight": args.preflight, "finished_at": time.time(), "error_class": type(error).__name__, "stage":STAGE, "reason": str(error) if isinstance(error, RuntimeError) else "fixture subprocess failed; inspect private log"})
        print("Owned release load failed; no performance acceptance claimed", file=sys.stderr)
        raise SystemExit(1)
