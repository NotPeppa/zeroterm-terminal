#!/usr/bin/env python3
"""Real, disposable RFC-004 recovery acceptance; never uses the host PG/SSH services."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from m3_https_smoke import certificate, seed, target_config
from openssh_smoke import port, wait_port

ROOT = Path(__file__).resolve().parents[1]
MIN_FREE = 256 * 1024 * 1024


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Evidence:
    def __init__(self, path: Path):
        self.path = path
        self.rows = []

    def add(self, phase, status, **data):
        row = {"time": now(), "phase": phase, "status": status, **data}
        self.rows.append(row)
        print(f"{phase}: {status} " + " ".join(f"{k}={v}" for k, v in data.items()), flush=True)
        self.path.write_text(json.dumps(self.rows, indent=2) + "\n", encoding="utf-8")


def chmod_private(path: Path, mode=0o600):
    path.chmod(mode)


def sha(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def start_process(args, log: Path, env=None):
    output = log.open("wb")
    proc = subprocess.Popen(args, cwd=ROOT, stdout=output, stderr=output, env=env)
    proc._release_log = output
    proc._release_args = list(map(str, args))
    return proc


def stop_process(proc, kill=False):
    if proc is None or proc.poll() is not None:
        if proc is not None and hasattr(proc, "_release_log"):
            proc._release_log.close()
        return
    started = time.monotonic()
    forced = False
    proc.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
    try:
        proc.wait(timeout=7 if not kill else 3)
    except subprocess.TimeoutExpired:
        forced = True
        proc.kill()
        proc.wait(timeout=3)
    proc._release_stop = {"pid": proc.pid, "requested_sigkill": kill, "deadline_sigkill": forced, "elapsed_seconds": round(time.monotonic() - started, 3)}
    if hasattr(proc, "_release_log"):
        proc._release_log.close()


def start_pg(pg: Path, root: Path, port_number: int):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = root / "pgdata"
    subprocess.run([str(pg / "initdb"), "-D", str(data), "-A", "trust", "--no-locale", "-U", "fixture"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([str(pg / "pg_ctl"), "-D", str(data), "-l", str(root / "postgres.log"), "-o", f"-h 127.0.0.1 -p {port_number} -k {root}", "-w", "start"], check=True, stdout=subprocess.DEVNULL)
    return data


def stop_pg(pg: Path, data: Path):
    subprocess.run([str(pg / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"], check=True, stdout=subprocess.DEVNULL)


def sql(pg: Path, port_number: int, statement: str, check=True):
    result = subprocess.run([str(pg / "psql"), "-X", "-h", "127.0.0.1", "-p", str(port_number), "-U", "fixture", "-d", "postgres", "-At", "-c", statement], capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError("isolated SQL command failed")
    return result.stdout.strip()


def config_for(path: Path, root: Path, local: Path, db_port: int, ports: dict, server_id: str, keys: dict[int, Path], active: int, record_dir: Path):
    quote = lambda value: json.dumps(str(value))
    text = f'''server_id = {quote(server_id)}
gateway_id = "main"
api_listen = "127.0.0.1:{ports["api"]}"
public_origin = {quote("https://localhost:" + str(ports["tls"]))}
web_root = {quote(ROOT / "web" / "dist")}
ssh_listen = "127.0.0.1:{ports["gateway"]}"
ssh_public_host = "127.0.0.1"
ssh_public_port = {ports["gateway"]}
database_url_file = {quote(local / "database-url")}
ssh_host_key_file = {quote(local / "ssh_host_ed25519_key")}
active_kek_version = {active}
[kek_files]
'''
    for version, key in sorted(keys.items()):
        text += f'"{version}" = {quote(key)}\n'
    text += f'''[network]
allow = ["127.0.0.1/32"]
deny = []
[production]
recording_directory = {quote(record_dir)}
recording_required = true
retention_days = 1
minimum_free_bytes = {MIN_FREE}
metrics_listen = "127.0.0.1:{ports["metrics"]}"
trusted_proxies = ["127.0.0.1/32"]
[production.limits]
connections_global = 100
connections_per_user = 10
pending_connections = 20
channels_per_connection = 16
channels_per_user = 64
queue_bytes = 262144
absolute_seconds = 3600
idle_seconds = 600
stalled_seconds = 30
file_max_bytes = 1073741824
'''
    path.write_text(text, encoding="utf-8")
    chmod_private(path)


def api(base, context, method, path, token=None, payload=None, expected=200, raw=False, revision=None):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if revision is not None:
        headers["If-Match"] = f'"{revision}"'
    data = None if payload is None else json.dumps(payload).encode()
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + "/api/v1" + path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    try:
        response = opener.open(req, timeout=18)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        if response.status != expected:
            raise AssertionError(f"unexpected API status {method} {path}: {response.status}, expected {expected}")
        if raw:
            return body, response.headers
        if expected >= 400:
            if not body:
                raise AssertionError(f"empty error body: {method} {path}, status {response.status}")
            value = json.loads(body)
            assert value["error"]["request_id"] == response.headers["X-Request-Id"]
            assert response.headers["Cache-Control"] == "no-store"
            return value
        return json.loads(body) if body else None


def login(base, context, username, password):
    result = api(base, context, "POST", "/auth/login", payload={"username": username, "password": password, "device_label": "release recovery", "client_type": "zeroterm"})
    return result["access_token"]


def ticket(base, context, token, asset):
    return api(base, context, "POST", "/connection-tickets", token=token, payload={"asset_id": asset["asset_id"], "account_id": asset["account_id"], "capabilities": ["shell"], "purpose": "terminal"}, expected=201)


def ssh_args(root, ticket_data, gateway_port, ssh_binary):
    secret = root / "ticket-secret"
    secret.write_text(ticket_data["ticket_secret"], encoding="utf-8")
    chmod_private(secret)
    askpass = root / "askpass"
    if not askpass.exists():
        askpass.write_text('#!/bin/sh\nexec cat "$BASTION_TEST_TICKET_FILE"\n', encoding="utf-8")
        askpass.chmod(0o700)
    env = os.environ.copy()
    env.update(SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force", DISPLAY="release-recovery", BASTION_TEST_TICKET_FILE=str(secret))
    known = root / "known_hosts"
    return [str(ssh_binary), "-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5", "-p", str(gateway_port), "-l", ticket_data["gateway"]["username"], "127.0.0.1"], env


def active_shell(root, ticket_data, gateway_port, ssh_binary):
    args, env = ssh_args(root, ticket_data, gateway_port, ssh_binary)
    proc = subprocess.Popen(args[:-1] + ["-T", args[-1]], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(b"printf '\\nREADY\\n'; sleep 30\n")
    proc.stdin.flush()
    deadline = time.monotonic() + 12
    data = b""
    import select
    while time.monotonic() < deadline:
        if select.select([proc.stdout], [], [], 0.2)[0]:
            data += os.read(proc.stdout.fileno(), 65536)
            if b"\r\nREADY\r\n" in data or b"\nREADY\n" in data:
                return proc
        if proc.poll() is not None:
            break
    stop_process(proc, kill=True)
    raise RuntimeError("isolated active shell did not reach READY")


def complete_shell(root, ticket_data, gateway_port, ssh_binary):
    args, env = ssh_args(root, ticket_data, gateway_port, ssh_binary)
    result = subprocess.run(args[:-1] + ["-T", args[-1]], env=env, input=b"printf '\\nRELEASE-RECOVERY\\n'; exit 7\n", capture_output=True, timeout=20)
    if result.returncode != 7 or b"RELEASE-RECOVERY" not in result.stdout:
        raise RuntimeError("isolated required shell did not complete")


def wait_server(port_number, proc, log):
    wait_port(port_number, proc, log)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="unique owned0700 fixture root")
    parser.add_argument("--runtime-only", action="store_true", help="independent permission/revoke/crash/DB-loss phases; no backup/replay pass implied")
    args = parser.parse_args()
    from release_recovery_cases import run
    try:
        run(args.root, runtime_only=args.runtime_only)
    except Exception:
        print("Recovery acceptance failed; consult secret-free evidence.json and protected logs", file=sys.stderr)
        raise SystemExit(1)
