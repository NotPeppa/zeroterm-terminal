#!/usr/bin/env python3
"""Disposable, non-root Unix HTTPS/WSS candidate fixture; not browser acceptance.

Requires PostgreSQL bin tools, OpenSSH sshd/ssh-keygen, OpenSSL, Cargo and Node
>=24. All listeners and target traffic are loopback-only. TLS verification uses
an isolated CA; no bypass, production database, or global certificate install.
"""
import argparse
import contextlib
import getpass
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from unittest.mock import patch

from m1_smoke import database, request
from openssh_smoke import port, process, wait_port

ROOT = Path(__file__).resolve().parents[1]
MIN_FREE_BYTES = 256 * 1024 * 1024  # Production.validate minimum, not a test bypass.


def private_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output)


def pg_directory():
    configured = os.environ.get("BASTION_PG_BIN")
    if configured:
        directory = Path(configured).resolve()
    elif shutil.which("postgres"):
        directory = Path(shutil.which("postgres")).resolve().parent
    elif shutil.which("pg_config"):
        directory = Path(subprocess.check_output(["pg_config", "--bindir"], text=True).strip()).resolve()
    else:
        raise RuntimeError("set BASTION_PG_BIN to an isolated PostgreSQL bin tool directory")
    if not all((directory / binary).is_file() for binary in ("postgres", "initdb", "pg_ctl", "psql")):
        raise RuntimeError("PostgreSQL initdb/pg_ctl/postgres/psql are required; no existing DB fallback")
    return directory


def certificate(root, openssl):
    ca, ca_key, cert, key = (root / name for name in ("ca.pem", "ca.key", "localhost.pem", "localhost.key"))
    commands = [
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256", "-subj", "/CN=Disposable M3 fixture CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca_key), "-out", str(ca)],
        [openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(root / "localhost.csr")],
    ]
    extensions = root / "localhost.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="utf-8")
    commands.append([openssl, "x509", "-req", "-sha256", "-days", "1", "-in", str(root / "localhost.csr"), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial", "-extfile", str(extensions), "-out", str(cert)])
    with (root / "certificate.log").open("wb") as log:
        for command in commands:
            subprocess.run(command, check=True, stdout=log, stderr=log, timeout=30)
    ca_key.chmod(0o600)
    key.chmod(0o600)
    return ca, cert, key


def production_config(path, root, local, base, ports):
    # JSON quoted strings are valid TOML basic strings for these Unix paths.
    quote = lambda value: json.dumps(str(value))
    path.write_text(f'''server_id = "m3-https-isolated"
gateway_id = "main"
api_listen = "127.0.0.1:{ports['api']}"
public_origin = {quote(base)}
web_root = {quote(ROOT / 'web' / 'dist')}
ssh_listen = "127.0.0.1:{ports['gateway']}"
ssh_public_host = "127.0.0.1"
ssh_public_port = {ports['gateway']}
database_url_file = {quote(local / 'database-url')}
ssh_host_key_file = {quote(local / 'ssh_host_ed25519_key')}
active_kek_version = 1
[kek_files]
"1" = {quote(local / 'kek-v1')}
[network]
allow = ["127.0.0.1/32"]
deny = []
[production]
recording_directory = {quote(root / 'recordings')}
recording_required = true
retention_days = 1
minimum_free_bytes = {MIN_FREE_BYTES}
metrics_listen = "127.0.0.1:{ports['metrics']}"
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
''', encoding="utf-8")
    path.chmod(0o600)


def target_config(root, name, value):
    path = root / f"sshd-{name}.conf"
    path.write_text(f'''ListenAddress 127.0.0.1
Port {value}
HostKey {root}/target-{name}
PidFile {root}/sshd-{name}.pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
StrictModes no
AuthorizedKeysFile {root}/target-user.pub
Subsystem sftp internal-sftp
AcceptEnv LANG LC_ALL LC_CTYPE
SetEnv BASTION_TARGET_ID={name} ZDOTDIR={root} HISTFILE=/dev/null
AllowUsers {getpass.getuser()}
LogLevel VERBOSE
''', encoding="utf-8")
    return path


def seed(base, ca, root, password, targets):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    original_opener = urllib.request.build_opener
    # Reuse M1 request assertions, injecting trust only for this synchronous seed.
    def verified_opener(*handlers):
        return original_opener(*handlers, urllib.request.HTTPSHandler(context=context))
    def call(path, payload=None, token=None, expected=200):
        try:
            return request(base, path, payload, token=token, expected=expected)
        except AssertionError:
            # Helper failure bodies may contain login responses: never echo them.
            raise RuntimeError(f"HTTPS seed response validation failed: {path}") from None
    with patch("urllib.request.build_opener", verified_opener):
        admin = call("/auth/login", {"username": "admin", "password": password, "device_label": "M3 fixture seed", "client_type": "zeroterm"})
        token = admin["access_token"]
        operator = call("/admin/users", {"username": "operator", "password": password, "role": "operator"}, token, 201)
        assets = []
        credential = {"type": "private_key", "key_pem": (root / "target-user").read_text(), "passphrase": None}
        try:
            for name, target_port in targets:
                asset = call("/admin/assets", {"name": f"M3 target {name}", "host": "127.0.0.1", "port": target_port, "tags": ["isolated", f"target-{name}"]}, token, 201)
                account = call(f"/admin/assets/{asset['id']}/accounts", {"username": getpass.getuser(), "credential": credential}, token, 201)
                public_key = " ".join((root / f"target-{name}.pub").read_text().split()[:2])
                call(f"/admin/assets/{asset['id']}/host-keys", {"algorithm": "ssh-ed25519", "public_key": public_key}, token, 201)
                call("/admin/grants", {"user_id": operator["id"], "asset_id": asset["id"], "account_id": account["id"], "capabilities": ["shell", "exec", "sftp"]}, token, 201)
                assets.append({"asset_id": asset["id"], "account_id": account["id"]})
            info = call("/info")
            if info.get("production_ready") is not False or info.get("recording", {}).get("required") is not True or info.get("recording", {}).get("available") is not True:
                raise RuntimeError("candidate discovery did not report required recording available")
            call("/auth/logout", {}, token, 204)
            return assets
        finally:
            credential["key_pem"] = ""
            admin.clear()
            token = ""


def hold(control, root, base, ca, fixture, ports, assets, processes):
    ready = control / "ready.json"
    private_json(ready, {"api_url": base, "browser_port": ports["tls"], "remote_frontend_port": ports["tls"], "api_port": ports["api"], "fixture_root": str(root), "ca_file": str(ca), "fixture_file": str(fixture), "assets": assets})
    try:
        print("BROWSER_READY: isolated HTTPS fixture active; trust ca_file and tunnel browser_port at the same localhost port; credentials remain in the protected fixture file", flush=True)
        deadline = time.monotonic() + 1800
        while not (control / "stop").exists() and time.monotonic() < deadline:
            if any(child.poll() is not None for child in processes):
                raise RuntimeError("a held isolated fixture process exited unexpectedly")
            time.sleep(1)
    finally:
        ready.unlink(missing_ok=True)


def run(browser_control_dir=None):
    if os.name != "posix" or os.geteuid() == 0:
        raise RuntimeError("run as a non-root Unix user; the fixture never reuses a privileged/existing PostgreSQL service")
    if os.environ.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
        raise RuntimeError("TLS verification bypass is not permitted")
    binaries = {name: shutil.which(name) for name in ("cargo", "node", "sshd", "ssh-keygen", "openssl")}
    if not all(binaries.values()):
        raise RuntimeError("Cargo, Node >=24, sshd, ssh-keygen and OpenSSL are required; no skipped acceptance")
    node_major = subprocess.check_output([binaries["node"], "-p", "process.versions.node.split('.')[0]"], text=True).strip()
    if int(node_major) < 24:
        raise RuntimeError("Node >=24 is required for native WebSocketInit headers")
    pg = pg_directory()
    if not (ROOT / "web/dist/index.html").is_file():
        raise RuntimeError("build web/dist first: cd web && npm ci && npm run build")
    control = None
    if browser_control_dir is not None:
        if browser_control_dir.is_symlink():
            raise RuntimeError("browser control directory cannot be a symlink")
        control = browser_control_dir.resolve()
        control.mkdir(mode=0o700, parents=True, exist_ok=True)
        if control.stat().st_uid != os.geteuid() or control.stat().st_mode & 0o777 != 0o700 or any(control.iterdir()):
            raise RuntimeError("browser control directory must be owned, empty, and mode0700")
    subprocess.run([binaries["cargo"], "build", "--locked", "-p", "bastion-server"], cwd=ROOT, check=True)
    target_directory = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target_directory.is_absolute():
        target_directory = ROOT / target_directory
    server = target_directory.resolve() / "debug/bastion-server"
    if not server.is_file():
        raise RuntimeError("built bastion-server not found under CARGO_TARGET_DIR/debug")
    with tempfile.TemporaryDirectory(prefix="bastion-m3-https-") as directory:
        root = Path(directory).resolve()
        root.chmod(0o700)
        if shutil.disk_usage(root).free < MIN_FREE_BYTES + 32 * 1024 * 1024:
            raise RuntimeError("isolated fixture requires at least288MiB free space for required recording")
        ports, used = {}, set()
        for name in ("db", "A", "B", "api", "gateway", "tls", "metrics"):
            value = port()
            while value in used:
                value = port()
            ports[name] = value
            used.add(value)
        local = root / "gateway"
        subprocess.run([str(server), "init", "--directory", str(local)], check=True)
        database_url = local / "database-url"
        database_url.write_text(f"postgres://fixture@127.0.0.1:{ports['db']}/postgres", encoding="utf-8")
        database_url.chmod(0o600)
        (root / "recordings").mkdir(mode=0o700)
        ca, cert, key = certificate(root, binaries["openssl"])
        base = f"https://localhost:{ports['tls']}"
        config = root / "production.toml"
        production_config(config, root, local, base, ports)
        for name in ("target-A", "target-B", "target-user"):
            subprocess.run([binaries["ssh-keygen"], "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        targets = [(name, ports[name]) for name in ("A", "B")]
        password = "fixture-only-" + secrets.token_urlsafe(24)
        with database(pg, root, ports["db"]):
            subprocess.run([str(server), "migrate", "--config", str(config)], check=True)
            subprocess.run([str(server), "create-admin", "--config", str(config), "--username", "admin", "--password-stdin"], input=password + "\n", text=True, check=True)
            with contextlib.ExitStack() as stack:
                children = []
                for name, value in targets:
                    log = root / f"sshd-{name}.log"
                    child = stack.enter_context(process([binaries["sshd"], "-D", "-e", "-f", str(target_config(root, name, value))], log))
                    children.append(child)
                    wait_port(value, child, log)
                gateway_log = root / "gateway.log"
                gateway = stack.enter_context(process([str(server), "serve", "--config", str(config)], gateway_log))
                children.append(gateway)
                wait_port(ports["api"], gateway, gateway_log)
                wait_port(ports["metrics"], gateway, gateway_log)
                tls_log = root / "tls.log"
                tls = stack.enter_context(process([sys.executable, str(ROOT / "tests/m3_tls_proxy.py"), "--port", str(ports["tls"]), "--upstream-port", str(ports["api"]), "--certificate", str(cert), "--key", str(key), "--trusted-proxy-headers"], tls_log))
                children.append(tls)
                wait_port(ports["tls"], tls, tls_log)
                assets = seed(base, ca, root, password, targets)
                fixture = root / "fixture.json"
                private_json(fixture, {"api_url": base, "username": "operator", "password": password, "assets": assets, "remote_file": str(root / "remote-upload.bin"), "database_url_file": str(database_url), "server_id": "m3-https-isolated", "gateway_id": "main", "gateway_port": ports["gateway"], "ca_file": str(ca)})
                env = os.environ.copy()
                env.update(BASTION_M3_FIXTURE=str(fixture), NODE_EXTRA_CA_CERTS=str(ca), NO_PROXY="localhost,127.0.0.1", no_proxy="localhost,127.0.0.1")
                # Failure output stays private: synthetic-client assertions may include response data.
                with (root / "node-smoke.log").open("wb") as log:
                    result = subprocess.run([binaries["node"], str(ROOT / "tests/m3_web_smoke.mjs")], cwd=ROOT, env=env, stdout=log, stderr=log, timeout=30)
                if result.returncode:
                    raise RuntimeError("M3 HTTPS/WSS candidate smoke failed; no browser acceptance claimed")
                print("M3 isolated HTTPS/WSS candidate automated smoke passed; not browser or production release acceptance", flush=True)
                if control is not None:
                    hold(control, root, base, ca, fixture, ports, assets, children)
                password = ""
    print("Isolated PostgreSQL, SSH targets, gateway, TLS proxy and temporary files cleaned up", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-control-dir", type=Path, help="after automated smoke, hold loopback fixture until stop file or30-minute deadline; directory must be empty0700")
    try:
        run(parser.parse_args().browser_control_dir)
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # Do not print command argv/response bodies from exceptions.
        print(f"M3 fixture failed: {error}" if isinstance(error, RuntimeError) else "M3 fixture subprocess failed or exceeded its deadline", file=sys.stderr)
        sys.exit(1)
