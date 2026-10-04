#!/usr/bin/env python3
"""Self-contained M0 integration test. All secrets stay in temp files or memory."""
import contextlib
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import select
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ASSET = "11111111-1111-4111-8111-111111111111"
ACCOUNT = "22222222-2222-4222-8222-222222222222"


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(value, process, log):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(f"fixture stopped: {log.read_text()}")
        try:
            with socket.create_connection(("127.0.0.1", value), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"fixture failed to listen: {log.read_text()}")


@contextlib.contextmanager
def process(args, log):
    with log.open("wb") as output:
        proc = subprocess.Popen(args, cwd=ROOT, stdout=output, stderr=output)
        try:
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=7)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)


def api(base, bearer, path, payload=None):
    headers = {"Authorization": "Bearer " + bearer}
    data = None if payload is None else json.dumps(payload).encode()
    if data:
        headers["Content-Type"] = "application/json"
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request(base + path, data, headers), timeout=10) as response:
        assert response.headers["Cache-Control"] == "no-store"
        return json.load(response)


def ticket(base, bearer, caps):
    return api(base, bearer, "/api/v1/connection-tickets", {
        "asset_id": ASSET, "account_id": ACCOUNT, "capabilities": caps, "purpose": "terminal"
    })


def zeroterm_shell(binary, issued, gateway_port, known_hosts):
    import fcntl
    import pty
    import signal
    import struct
    import termios

    pid, master = pty.fork()
    if pid == 0:
        os.execv(str(binary), [str(binary), "--known-hosts", str(known_hosts), "-p", str(gateway_port),
                              issued["gateway"]["username"] + "@127.0.0.1"])
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    output, entered, sent, reaped = b"", False, False, False
    entered_at = None
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                output += data
                if not entered and b"password:" in output.lower():
                    os.write(master, issued["ticket_secret"].encode() + b"\n")
                    entered = True
                    entered_at = time.monotonic()
            if entered_at and not sent and time.monotonic() - entered_at > 1:
                os.write(master, b"printf '\\nZERO'; printf 'TERM-CLIENT-OK\\n'; exit\n")
                sent = True
        # Wait boundedly; errors never dump the PTY buffer (it may contain secrets).
        for _ in range(20):
            result, status = os.waitpid(pid, os.WNOHANG)
            if result:
                reaped = True
                assert os.waitstatus_to_exitcode(status) == 0, "ZeroTerm CLI exited with an error"
                break
            time.sleep(0.05)
        assert reaped and sent and b"ZEROTERM-CLIENT-OK" in output, "ZeroTerm CLI shell did not complete: " + output.replace(issued["ticket_secret"].encode(), b"[REDACTED]").decode(errors="replace")
    finally:
        if not reaped:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        os.close(master)


def run(zeroterm_cli=None):
    binaries = {name: shutil.which(name) for name in ("sshd", "ssh", "sftp", "ssh-keygen")}
    if not all(binaries.values()):
        raise RuntimeError("OpenSSH server and client binaries are required (no tests skipped)")
    subprocess.run(["cargo", "build", "--locked", "-p", "bastion-server", "--features", "dev-prototype"], cwd=ROOT, check=True)
    gateway = ROOT / "target/debug/bastion-server"
    with tempfile.TemporaryDirectory(prefix="bastion-openssh-") as directory:
        root = Path(directory)
        for name in ("target_host", "target_user", "wrong_host"):
            subprocess.run([binaries["ssh-keygen"], "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        sshd_port, api_port, gateway_port = port(), port(), port()
        sshd_config = root / "sshd_config"
        sshd_config.write_text(f"""ListenAddress 127.0.0.1
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
MaxSessions 2
AllowUsers {getpass.getuser()}
LogLevel VERBOSE
""")
        local = root / "gateway"
        subprocess.run([str(gateway), "init", "--directory", str(local)], check=True)
        config = root / "prototype.toml"
        config.write_text(f"""server_id = "smoke-test"
api_listen = "127.0.0.1:{api_port}"
ssh_listen = "127.0.0.1:{gateway_port}"
api_token_file = "{local}/api-token"
ssh_host_key_file = "{local}/ssh_host_ed25519_key"
[target]
asset_id = "{ASSET}"
account_id = "{ACCOUNT}"
name = "OpenSSH fixture"
address = "127.0.0.1:{sshd_port}"
username = "{getpass.getuser()}"
host_key_file = "{root}/target_host.pub"
capabilities = ["shell", "exec", "sftp"]
[target.credentials]
auth = "private_key"
private_key_file = "{root}/target_user"
""")
        known_hosts = root / "known_hosts"
        known_hosts.write_text(f"[127.0.0.1]:{gateway_port} " + (local / "ssh_host_ed25519_key.pub").read_text() + "\n")
        askpass = root / "askpass"
        askpass.write_text('#!/bin/sh\nexec cat "$BASTION_TEST_TICKET_FILE"\n')
        askpass.chmod(0o700)
        secret_file = root / "ticket_secret"
        env = os.environ.copy()
        env.update(SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force", DISPLAY="bastion-test",
                   BASTION_TEST_TICKET_FILE=str(secret_file))
        options = ["-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password",
                   "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5"]
        base = f"http://127.0.0.1:{api_port}"
        bearer = (local / "api-token").read_text()

        def ssh(connection_ticket, command=None, data=b"", tty=False):
            secret_file.write_text(connection_ticket["ticket_secret"])
            secret_file.chmod(0o600)
            args = [binaries["ssh"], *options, "-p", str(gateway_port), "-l", connection_ticket["gateway"]["username"],
                    "-tt" if tty else "-T", "127.0.0.1"]
            if command is not None:
                args.append(command)
            return subprocess.run(args, input=data, capture_output=True, env=env, timeout=20)

        with process([binaries["sshd"], "-D", "-e", "-f", str(sshd_config)], root / "sshd.log") as target:
            wait_port(sshd_port, target, root / "sshd.log")
            with process([str(gateway), "prototype", "--config", str(config)], root / "gateway.log") as server:
                wait_port(api_port, server, root / "gateway.log")
                assert api(base, bearer, "/api/v1/info")["production_ready"] is False
                issued = ticket(base, bearer, ["exec"])
                result = ssh(issued, "printf '你好 😀'; printf error >&2; exit 7")
                assert result.returncode == 7, result.stderr.decode(errors="replace")
                assert result.stdout == "你好 😀".encode()
                assert result.stderr == b"error"
                replay = ssh(issued, "printf replayed")
                assert replay.returncode != 0 and b"replayed" not in replay.stdout
                print("PASS: OpenSSH exec, Unicode, stderr, exit status and ticket replay rejection")

                raw = os.urandom(1024 * 1024)
                result = ssh(ticket(base, bearer, ["exec"]), "cat; printf after-eof", raw)
                assert result.returncode == 0 and result.stdout == raw + b"after-eof"
                result = ssh(ticket(base, bearer, ["shell"]), data=b"printf '\\nCLI-SHELL\\n'; exit\n", tty=True)
                assert result.returncode == 0 and b"CLI-SHELL" in result.stdout, (result.returncode, result.stdout, result.stderr)
                print("PASS: raw binary stdin/EOF and standard OpenSSH PTY shell")
                if zeroterm_cli:
                    zeroterm_shell(zeroterm_cli, ticket(base, bearer, ["shell"]), gateway_port, known_hosts)
                    print("PASS: existing ZeroTerm CLI connects with ticket and opens target shell")

                issued = ticket(base, bearer, ["sftp"])
                secret_file.write_text(issued["ticket_secret"])
                source, remote, downloaded = root / "source.bin", root / "remote.bin", root / "download.bin"
                source.write_bytes(os.urandom(4 * 1024 * 1024))
                batch = root / "sftp.batch"
                batch.write_text(f'put "{source}" "{remote}"\nget "{remote}" "{downloaded}"\nrm "{remote}"\n')
                result = subprocess.run([binaries["sftp"], *options, "-o", "BatchMode=no", "-P", str(gateway_port),
                                         "-b", str(batch), "-o", f'User={issued["gateway"]["username"]}', "127.0.0.1"],
                                        capture_output=True, env=env, timeout=30)
                assert result.returncode == 0, result.stderr.decode(errors="replace")
                assert hashlib.sha256(source.read_bytes()).digest() == hashlib.sha256(downloaded.read_bytes()).digest()
                print("PASS: standard OpenSSH SFTP random binary upload/download SHA-256")

                fixture = root / "fixture.json"
                fixture.write_text(json.dumps(dict(api=base, ssh_port=gateway_port, api_token_file=str(local / "api-token"),
                                                  gateway_public_key_file=str(local / "ssh_host_ed25519_key.pub"),
                                                  asset_id=ASSET, account_id=ACCOUNT, scratch=str(root))))
                rust_env = os.environ.copy()
                rust_env["BASTION_TEST_FIXTURE"] = str(fixture)
                subprocess.run(["cargo", "test", "--locked", "-p", "bastion-server", "--features", "dev-prototype",
                                "--test", "openssh", "--", "--ignored", "--nocapture"], cwd=ROOT, env=rust_env, check=True, timeout=120)
                print("PASS: Rust multi-channel, capabilities, PTY resize, request replies, EOF and SFTP")

            # The same endpoint with an unapproved key must fail before target authentication.
            config.write_text(config.read_text().replace(str(root / "target_host.pub"), str(root / "wrong_host.pub")))
            before = (root / "sshd.log").read_text().count("Accepted publickey")
            with process([str(gateway), "prototype", "--config", str(config)], root / "wrong-key.log") as server:
                wait_port(api_port, server, root / "wrong-key.log")
                issued = ticket(base, bearer, ["exec"])
                result = ssh(issued, "printf forbidden")
                assert result.returncode != 0 and b"forbidden" not in result.stdout
                state = api(base, bearer, f'/api/v1/connections/{issued["connection_id"]}')
                assert state["failure"]["code"] == "TARGET_HOST_KEY_CHANGED", state
                assert (root / "sshd.log").read_text().count("Accepted publickey") == before
                print("PASS: wrong target host key blocked before authentication")

        logs = (root / "gateway.log").read_text() + (root / "wrong-key.log").read_text()
        assert bearer not in logs and issued["ticket_secret"] not in logs
        assert "BEGIN OPENSSH PRIVATE KEY" not in logs
        print("PASS: runtime logs contain no test bearer, ticket secret or private key")
        print("M0 real OpenSSH suite passed; temporary processes and files cleaned up.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zeroterm-cli", type=Path, help="also test an existing ZeroTerm CLI binary")
    run(parser.parse_args().zeroterm_cli)
