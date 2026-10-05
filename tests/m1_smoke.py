#!/usr/bin/env python3
"""Isolated PostgreSQL + real OpenSSH M1 integration. No user database is touched."""
import contextlib
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import select
from openssh_smoke import port, process, wait_port

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "test-only-long-password-2026"

def request(base, path, payload=None, token=None, method=None, revision=None, expected=200):
    headers = {"Content-Type": "application/json"}
    if token: headers["Authorization"] = "Bearer " + token
    if revision is not None: headers["If-Match"] = '"' + str(revision) + '"'
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base + "/api/v1" + path, body, headers, method=method)
    try:
        response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=18)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        data = json.loads(raw) if raw else None
        assert response.status == expected, (path, response.status, data)
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Request-Id"]
        if expected >= 400: assert data["error"]["request_id"] == response.headers["X-Request-Id"]
        return data

@contextlib.contextmanager
def database(pg, root, db_port):
    data = root / "pgdata"
    subprocess.run([str(pg / "initdb"), "-D", str(data), "-A", "trust", "--no-locale", "-U", "fixture"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([str(pg / "pg_ctl"), "-D", str(data), "-l", str(root / "postgres.log"), "-o", f"-h 127.0.0.1 -p {db_port} -k {root}", "-w", "start"], check=True, stdout=subprocess.DEVNULL)
    try:
        yield
    finally:
        subprocess.run([str(pg / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"], check=True, stdout=subprocess.DEVNULL)

def run(browser_control_dir=None):
    pg = Path(os.environ.get("BASTION_PG_BIN", "/opt/homebrew/opt/postgresql@17/bin"))
    if not (pg / "postgres").exists():
        binary = shutil.which("postgres")
        if not binary: raise RuntimeError("set BASTION_PG_BIN to PostgreSQL 17 bin directory")
        pg = Path(binary).parent
    subprocess.run(["cargo", "build", "--locked", "-p", "bastion-server"], cwd=ROOT, check=True)
    server = ROOT / "target/debug/bastion-server"
    with tempfile.TemporaryDirectory(prefix="bastion-m1-") as directory:
        root = Path(directory)
        db_port, sshd_port, api_port, gateway_port = port(), port(), port(), port()
        local = root / "gateway"
        subprocess.run([str(server), "init", "--directory", str(local)], check=True)
        url = f"postgres://fixture@127.0.0.1:{db_port}/postgres"
        url_file = local / "database-url"
        url_file.write_text(url)
        url_file.chmod(0o600)
        config = root / "m1.toml"
        config.write_text(f'''server_id = "m1-test"
gateway_id = "main"
api_listen = "127.0.0.1:{api_port}"
public_origin = "http://127.0.0.1:{api_port}"
ssh_listen = "127.0.0.1:{gateway_port}"
database_url_file = "{url_file}"
ssh_host_key_file = "{local}/ssh_host_ed25519_key"
active_kek_version = 1
[kek_files]
"1" = "{local}/kek-v1"
[network]
allow = ["127.0.0.1/32"]
deny = []
''')
        for name in ("target_host", "target_user", "wrong_host"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        sshd_config = root / "sshd_config"
        sshd_config.write_text(f'''ListenAddress 127.0.0.1
Port {sshd_port}
HostKey {root}/target_host
PidFile {root}/sshd.pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
AuthorizedKeysFile {root}/target_user.pub
Subsystem sftp internal-sftp
AcceptEnv LANG LC_ALL LC_CTYPE
SetEnv ZDOTDIR={root} HISTFILE=/dev/null
AllowUsers {getpass.getuser()}
LogLevel VERBOSE
''')
        known_hosts = root / "known_hosts"
        known_hosts.write_text(f"[127.0.0.1]:{gateway_port} " + (local / "ssh_host_ed25519_key.pub").read_text() + "\n")
        askpass = root / "askpass"
        askpass.write_text('#!/bin/sh\nexec cat "$BASTION_TEST_TICKET_FILE"\n')
        askpass.chmod(0o700)
        secret_file = root / "ticket_secret"
        secret_file.touch(mode=0o600)
        env = os.environ.copy()
        env.update(SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force", DISPLAY="fixture", BASTION_TEST_TICKET_FILE=str(secret_file))
        options = ["-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5"]
        def ssh(issued, command, wait=True):
            secret_file.write_text(issued["ticket_secret"])
            args = ["ssh", *options, "-p", str(gateway_port), "-l", issued["gateway"]["username"], "127.0.0.1", command]
            if wait: return subprocess.run(args, env=env, capture_output=True, timeout=15)
            return subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with database(pg, root, db_port):
            def sql(statement, expect=True):
                result = subprocess.run([str(pg / "psql"), "-X", "-h", "127.0.0.1", "-p", str(db_port), "-U", "fixture", "-d", "postgres", "-At", "-c", statement], capture_output=True, text=True)
                if expect: assert result.returncode == 0, result.stderr
                return result.stdout.strip() if expect else result
            subprocess.run([str(server), "migrate", "--config", str(config)], check=True)
            subprocess.run([str(server), "migrate", "--config", str(config)], check=True)
            create_args = [str(server), "create-admin", "--config", str(config), "--username", "admin", "--password-stdin"]
            subprocess.run(create_args, input=PASSWORD + "\n", text=True, check=True)
            duplicate = subprocess.run(create_args, input=PASSWORD + "\n", text=True, capture_output=True)
            assert duplicate.returncode != 0
            with process([shutil.which("sshd"), "-D", "-e", "-f", str(sshd_config)], root / "sshd.log") as sshd, process([str(server), "serve-m1", "--config", str(config)], root / "gateway.log") as gateway:
                wait_port(sshd_port, sshd, root / "sshd.log")
                wait_port(api_port, gateway, root / "gateway.log")
                base = f"http://127.0.0.1:{api_port}"
                def login(username): return request(base, "/auth/login", {"username":username,"password":PASSWORD,"device_label":"M1 integration"})
                info = request(base, "/info")
                assert not info["production_ready"]
                # The dedicated DB lease must reject a duplicate process before it can recover state.
                duplicate = subprocess.run([str(server), "serve-m1", "--config", str(config)], capture_output=True, timeout=8)
                assert duplicate.returncode != 0 and b"ResourceConflict" in duplicate.stderr
                admin = login(" ADMIN ")
                a = admin["access_token"]
                request(base, "/me", expected=401)
                request(base, "/auth/login", {"username":"../admin","password":PASSWORD,"device_label":"test"}, expected=401)
                op = request(base, "/admin/users", {"username":"operator","password":PASSWORD,"role":"operator"}, a, expected=201)
                other = request(base, "/admin/users", {"username":"other","password":PASSWORD,"role":"operator"}, a, expected=201)
                auditor = request(base, "/admin/users", {"username":"auditor","password":PASSWORD,"role":"auditor"}, a, expected=201)
                operator = login("operator")
                other_login = login("other")
                auditor_login = login("auditor")
                token = operator["access_token"]
                first_page = request(base, "/admin/users?limit=1", token=a)
                assert len(first_page["items"]) == 1 and first_page["next_cursor"]
                second_page = request(base, "/admin/users?limit=1&cursor=" + first_page["next_cursor"], token=a)
                assert second_page["items"][0]["id"] != first_page["items"][0]["id"]
                request(base, "/admin/assets?cursor=" + first_page["next_cursor"], token=a, expected=400)
                request(base, "/admin/users?limit=201", token=a, expected=400)
                request(base, "/admin/users", token=token, expected=403)
                asset = request(base, "/admin/assets", {"name":"OpenSSH fixture","host":"127.0.0.1","port":sshd_port,"tags":["test"]}, a, expected=201)
                asset_id = asset["id"]
                credential = {"type":"private_key","key_pem":(root / "target_user").read_text(),"passphrase":None}
                account = request(base, f"/admin/assets/{asset_id}/accounts", {"username":getpass.getuser(),"credential":credential}, a, expected=201)
                account_id = account["id"]
                payload = {"asset_id":asset_id,"account_id":account_id,"capabilities":["exec"],"purpose":"terminal"}
                request(base, "/connection-tickets", payload, a, expected=403)
                request(base, "/connection-tickets", payload, token, expected=403)
                assert request(base, "/assets", token=token)["items"] == []
                grant = request(base, "/admin/grants", {"user_id":op["id"],"asset_id":asset_id,"account_id":account_id,"capabilities":["shell","exec","sftp"]}, a, expected=201)
                assert len(request(base, "/assets", token=token)["items"]) == 1
                request(base, "/connection-tickets", payload, auditor_login["access_token"], expected=403)
                assert request(base, "/connections", token=other_login["access_token"])["items"] == []
                request(base, f"/admin/accounts/{account_id}/test", {}, a, expected=409)
                scanned = request(base, f"/admin/assets/{asset_id}/host-key-scan", {}, a)
                assert scanned["state"] == "candidate"
                expected_key = " ".join((root / "target_host.pub").read_text().split()[:2])
                assert scanned["public_key"] == expected_key
                approved = request(base, f"/admin/assets/{asset_id}/host-keys", {"algorithm":"ssh-ed25519","public_key":expected_key}, a, expected=201)
                assert approved["state"] == "approved"
                assert request(base, f"/admin/assets/{asset_id}/host-key-scan", {}, a)["state"] == "approved"
                assert request(base, f"/admin/accounts/{account_id}/test", {}, a)["authenticated"]
                request(base, f'/admin/assets/{asset_id}/host-keys/{approved["id"]}', token=a, method="DELETE", revision=approved["revision"], expected=204)
                wrong_key = " ".join((root / "wrong_host.pub").read_text().split()[:2])
                wrong = request(base, f"/admin/assets/{asset_id}/host-keys", {"algorithm":"ssh-ed25519","public_key":wrong_key}, a, expected=201)
                before = (root / "sshd.log").read_text().count("Accepted publickey")
                denied = request(base, f"/admin/accounts/{account_id}/test", {}, a, expected=409)
                assert denied["error"]["code"] == "TARGET_HOST_KEY_CHANGED"
                assert (root / "sshd.log").read_text().count("Accepted publickey") == before
                request(base, f'/admin/assets/{asset_id}/host-keys/{wrong["id"]}', token=a, method="DELETE", revision=wrong["revision"], expected=204)
                approved = request(base, f"/admin/assets/{asset_id}/host-keys", {"algorithm":"ssh-ed25519","public_key":expected_key}, a, expected=201)
                issued = request(base, "/connection-tickets", payload, token, expected=201)
                request(base, f'/connections/{issued["connection_id"]}', token=other_login["access_token"], expected=404)
                result = ssh(issued, "printf 'M1-你好-✓'; printf 'stderr-ok' >&2; exit 7")
                assert result.returncode == 7 and result.stdout == "M1-你好-✓".encode() and b"stderr-ok" in result.stderr, result
                assert ssh(issued, "true").returncode != 0
                # Token and credential contents must never be stored in plaintext.
                assert sql(f"SELECT encode(token_hash,'hex') FROM access_tokens WHERE login_session_id='{operator['login_session_id']}'") == hashlib.sha256(token.encode()).hexdigest()
                assert sql("SELECT bool_and(octet_length(wrapped_dek)=48 AND octet_length(nonce)=24) FROM credentials") == "t"
                serialized = sql("SELECT row_to_json(c)::text FROM credentials c")
                assert "OPENSSH PRIVATE KEY" not in serialized and credential["key_pem"] not in serialized
                assert sql("UPDATE audit_events SET action='tamper'", expect=False).returncode != 0
                # Optimistic updates require If-Match and reject stale revisions.
                request(base, f"/admin/accounts/{account_id}", {"enabled":True}, a, method="PATCH", expected=428)
                request(base, f"/admin/accounts/{account_id}", {"enabled":True}, a, method="PATCH", revision=999, expected=412)
                # Rotating a credential invalidates pending tickets, keeps established target connections.
                pending = request(base, "/connection-tickets", payload, token, expected=201)
                long = request(base, "/connection-tickets", payload, token, expected=201)
                live = ssh(long, "printf 'READY\\n'; sleep 30", wait=False)
                try:
                    assert select.select([live.stdout], [], [], 12)[0] and live.stdout.readline() == b"READY\n"
                    account = request(base, f"/admin/accounts/{account_id}/credential", credential, a, method="PUT", revision=account["revision"])
                    assert live.poll() is None
                    assert ssh(pending, "true").returncode != 0
                    assert request(base, f'/connections/{pending["connection_id"]}', token=token)["failure"]["code"] == "SESSION_TICKET_STALE"
                    refreshed = request(base, "/auth/refresh", {"refresh_token":operator["refresh_token"]})
                    assert refreshed["refresh_token"] != operator["refresh_token"]
                    request(base, "/auth/refresh", {"refresh_token":operator["refresh_token"]}, expected=401)
                    started = time.monotonic()
                    live.communicate(timeout=3)
                    assert time.monotonic() - started < 3 and live.returncode != 0
                    request(base, "/me", token=refreshed["access_token"], expected=401)
                finally:
                    if live.poll() is None: live.kill();live.communicate()
                operator = login("operator")
                token = operator["access_token"]
                # SFTP transports the full binary protocol through the persisted policy backend.
                issued = request(base, "/connection-tickets", {**payload,"capabilities":["sftp"],"purpose":"sftp"}, token, expected=201)
                secret_file.write_text(issued["ticket_secret"])
                source, remote, downloaded = root / "source", root / "remote", root / "downloaded"
                source.write_bytes(os.urandom(1024*1024))
                result = subprocess.run(["sftp", *options, "-P", str(gateway_port), "-o", "User=" + issued["gateway"]["username"], "127.0.0.1"], input=f"put {source} {remote}\nget {remote} {downloaded}\nbye\n".encode(), env=env, capture_output=True, timeout=20)
                assert result.returncode == 0 and source.read_bytes() == downloaded.read_bytes(), result.stderr
                # Grant revocation closes an existing session promptly.
                issued = request(base, "/connection-tickets", payload, token, expected=201)
                live = ssh(issued, "printf 'READY\\n'; sleep 30", wait=False)
                try:
                    assert select.select([live.stdout], [], [], 12)[0] and live.stdout.readline() == b"READY\n"
                    started = time.monotonic()
                    request(base, f'/admin/grants/{grant["id"]}', token=a, method="DELETE", revision=grant["revision"], expected=204)
                    live.communicate(timeout=3)
                    assert time.monotonic() - started < 3
                finally:
                    if live.poll() is None: live.kill();live.communicate()
                request(base, "/connection-tickets", payload, token, expected=403)
                events = request(base, "/audit-events", token=auditor_login["access_token"])
                assert any(event["action"] == "exec.requested" for event in events["items"])
                assert PASSWORD not in json.dumps(events) and credential["key_pem"] not in json.dumps(events)
                assert PASSWORD not in (root / "gateway.log").read_text()
                # A user disable revokes outstanding access and ticket authorization.
                request(base, f'/admin/users/{other["id"]}', {"enabled":False}, a, method="PATCH", revision=other["revision"])
                request(base, "/me", token=other_login["access_token"], expected=403)
                request(base, "/auth/logout", token=auditor_login["access_token"], method="POST", expected=204)
                request(base, "/auth/logout", token=auditor_login["access_token"], method="POST", expected=204)
                # Nullable grant expiry can be set and cleared with optimistic concurrency.
                grant = request(base, f'/admin/grants/{grant["id"]}', {"expires_at":"2099-01-01T00:00:00Z"}, a, method="PATCH", revision=grant["revision"]+1)
                assert grant["expires_at"]
                grant = request(base, f'/admin/grants/{grant["id"]}', {"expires_at":None}, a, method="PATCH", revision=grant["revision"])
                assert grant["expires_at"] is None
                # Run the transaction race checks against this same temporary database.
                fixture = root / "fixture.json"
                fixture.write_text(json.dumps({"database_url_file":str(url_file),"server_id":"m1-test","gateway_id":"main","username":"admin","password":PASSWORD,"asset_id":asset_id,"account_id":account_id,"operator_id":op["id"],"api_url":base}))
                fixture.chmod(0o600)
                test_env = os.environ.copy()
                test_env["BASTION_M1_FIXTURE"] = str(fixture)
                test_env["BASTION_M1_GATEWAY_LOG"] = str(root / "gateway.log")
                subprocess.run(["cargo", "test", "--locked", "-p", "bastion-server", "--test", "postgres", "--", "--ignored", "--nocapture"], cwd=ROOT, env=test_env, check=True)
                subprocess.run(["cargo", "test", "--locked", "-p", "bastion-store", "--test", "web_sessions", "--", "--ignored", "--nocapture"], cwd=ROOT, env=test_env, check=True)
                subprocess.run(["cargo", "test", "--locked", "-p", "bastion-server", "--test", "websocket", "--", "--ignored", "--nocapture"], cwd=ROOT, env=test_env, check=True)
                if browser_control_dir is not None:
                    control = browser_control_dir.resolve()
                    control.mkdir(mode=0o700, parents=True, exist_ok=True)
                    if (control / "ready.json").exists() or (control / "stop").exists():
                        raise RuntimeError("browser control directory must be fresh")
                    browser_admin = login("admin")
                    request(base, "/admin/grants", {"user_id":op["id"],"asset_id":asset_id,"account_id":account_id,"capabilities":["shell"]}, browser_admin["access_token"], expected=201)
                    front_port = port()
                    vite_config = ROOT / "web" / (".acceptance-vite-" + str(api_port) + ".mjs")
                    try:
                        with vite_config.open("x") as config_output:
                            config_output.write("export default " + json.dumps({"root":str(ROOT / "web"),"server":{"host":"127.0.0.1","port":front_port,"strictPort":True,"proxy":{"/api":{"target":base,"ws":True}}}}))
                        with process(["node", str(ROOT / "web/node_modules/vite/bin/vite.js"), "--config", str(vite_config)], root / "vite.log") as vite:
                            wait_port(front_port, vite, root / "vite.log")
                            (control / "ready.json").write_text(json.dumps({"browser_port":api_port,"remote_frontend_port":front_port,"api_port":api_port,"fixture_root":str(root),"asset_id":asset_id,"account_id":account_id}))
                            print("BROWSER_READY: isolated fixture active; username=operator; test password defined by PASSWORD constant", flush=True)
                            deadline = time.monotonic() + 1800
                            while not (control / "stop").exists() and time.monotonic() < deadline:
                                if any(p.poll() is not None for p in (vite, gateway, sshd)):
                                    raise RuntimeError("browser fixture process exited unexpectedly")
                                time.sleep(1)
                    finally:
                        vite_config.unlink(missing_ok=True)
                        (control / "ready.json").unlink(missing_ok=True)
            # Restart cannot resurrect consumed tickets; recovery marks in-flight history interrupted.
            sql("UPDATE connections SET state='active' WHERE id='" + issued["connection_id"] + "'")
            with process([str(server), "serve-m1", "--config", str(config)], root / "restart.log") as gateway:
                wait_port(api_port, gateway, root / "restart.log")
                assert sql("SELECT state FROM connections WHERE id='" + issued["connection_id"] + "'") == "interrupted"
                assert ssh(issued, "true").returncode != 0
    print("M1 PostgreSQL + OpenSSH integration passed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-control-dir", type=Path, help="after backend checks, hold the isolated Vite/PG/sshd fixture until a stop file or 30-minute deadline")
    run(parser.parse_args().browser_control_dir)
