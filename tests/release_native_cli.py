#!/usr/bin/env python3
"""Real Linux ZeroTerm CLI Managed acceptance; no mock and no OpenSSH substitute.

Run as the non-root fixture owner with BASTION_NATIVE_FIXTURE (0600 JSON),
ZEROTERM_CLI (built binary), and BASTION_NATIVE_WORKDIR (isolated 0700 directory).
The fixture must provide api_url, username/password, server_id, gateway_host/port,
gateway_host_key_sha256, ca_file and assets[{name,username,asset_id,account_id}].
Secrets are read into memory and sent only to hidden controlling-terminal prompts.
"""
import base64
import fcntl
import hashlib
import http.cookies
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import signal
import ssl
import struct
import sys
import tempfile
import termios
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request


class CheckFailed(RuntimeError):
    pass


def check(condition, label):
    if not condition:
        raise CheckFailed(label)


def protected(path, directory=False):
    path = Path(path)
    check(not path.is_symlink(), 'fixture/work path must not be a symlink')
    path = path.resolve()
    stat = path.stat()
    check(stat.st_uid == os.geteuid() and not stat.st_mode & 0o077, 'fixture/work path must be owned and private')
    check(path.is_dir() if directory else path.is_file(), 'fixture/work path has wrong type')
    return path


def digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


class Cli:
    """PTY for real /dev/tty password/dialoguer input; separate raw stdout pipe."""
    def __init__(self, binary, args, env, forbidden):
        self.out, self.tty, self.status = bytearray(), bytearray(), None
        self.forbidden = forbidden
        read, write = os.pipe()
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            os.close(read)
            os.dup2(write, 1)
            os.close(write)
            attrs = termios.tcgetattr(0)
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            attrs[3] &= ~termios.ECHO
            attrs[1] &= ~termios.OPOST  # Preserve stderr bytes; do not expand LF.
            termios.tcsetattr(0, termios.TCSANOW, attrs)
            os.execvpe(str(binary), [str(binary), *args], env)
        os.close(write)
        self.stdout = read
        self.fds = {self.master: self.tty, self.stdout: self.out}

    def pump(self, timeout=.1):
        if self.fds:
            for fd in select.select(list(self.fds), [], [], timeout)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    chunk = b''
                if chunk:
                    self.fds[fd].extend(chunk)
                else:
                    self.fds.pop(fd)
        if self.status is None:
            child, status = os.waitpid(self.pid, os.WNOHANG)
            if child:
                self.status = os.waitstatus_to_exitcode(status)

    def wait(self, marker, timeout=45, stdout=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            data = self.out if stdout else self.tty
            if marker.lower() in bytes(data).lower():
                return
            check(self.status is None, 'CLI exited before expected public prompt/output')
        raise CheckFailed('CLI public prompt/output deadline')

    def answer(self, marker, value):
        self.wait(marker)
        os.write(self.master, value + b'\n')

    def authenticate(self, master, fixture, create=False, import_profile=False):
        self.answer(b'Master password:', master.encode())
        if create:
            self.answer(b'Confirm:', master.encode())
        if import_profile:
            self.answer(b'Bastion', b'')  # Real profile picker, default first profile.
        self.answer(b'Bastion username', fixture['username'].encode())
        self.answer(b'Bastion password:', fixture['password'].encode())
        if import_profile:
            self.answer(b'Asset/account', b'')  # Fixture catalog ordered A then B.

    def finish(self, timeout=45):
        deadline = time.monotonic() + timeout
        while (self.status is None or self.fds) and time.monotonic() < deadline:
            self.pump()
        check(self.status is not None, 'CLI completion deadline')
        for index, secret in enumerate(self.forbidden):
            check(secret.encode() not in self.out and secret.encode() not in self.tty, 'credential echoed by native CLI [' + ('vault-master' if index == 0 else 'fixture-password') + ']')
        return self.status, bytes(self.out), bytes(self.tty)

    def close(self):
        if self.status is None:
            os.kill(self.pid, signal.SIGTERM)
            deadline = time.monotonic() + 3
            while self.status is None and time.monotonic() < deadline:
                self.pump()
            if self.status is None:
                os.kill(self.pid, signal.SIGKILL)
                _, status = os.waitpid(self.pid, 0)
                self.status = os.waitstatus_to_exitcode(status)
        for fd in (self.master, self.stdout):
            os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class Api:
    def __init__(self, fixture):
        self.base = fixture['api_url']
        context = ssl.create_default_context(cafile=fixture['ca_file'])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        self.cookies, self.csrf = {}, ''

    def call(self, path, payload=None, expected=200):
        headers = {'Origin': self.base, 'Cookie': '; '.join(k + '=' + v for k, v in self.cookies.items())}
        if payload is not None:
            headers.update({'Content-Type': 'application/json', 'X-Bastion-CSRF': self.csrf})
        request = urllib.request.Request(self.base + '/api/v1' + path, None if payload is None else json.dumps(payload).encode(), headers)
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            check(response.status == expected, 'HTTPS isolation ' + path + ' expected=' + str(expected) + ' actual=' + str(response.status))
            for raw in response.headers.get_all('Set-Cookie', []):
                cookie = http.cookies.SimpleCookie(raw)
                for name, value in cookie.items():
                    check(value['secure'] and value['samesite'].lower() == 'strict', 'cookie security flags')
                    self.cookies[name] = value.value
            body = response.read()
            return json.loads(body) if body else None


def main():
    check(os.name == 'posix' and os.geteuid() != 0, 'use the non-root fixture owner')
    fixture_path = protected(os.environ['BASTION_NATIVE_FIXTURE'])
    work = protected(os.environ['BASTION_NATIVE_WORKDIR'], directory=True)
    fixture = json.loads(fixture_path.read_text())
    binary = Path(os.environ['ZEROTERM_CLI']).resolve()
    check(binary.is_file() and os.access(binary, os.X_OK), 'actual ZeroTerm CLI binary required')
    url = urllib.parse.urlsplit(fixture['api_url'])
    check(url.scheme == 'https' and url.hostname in ('localhost', '127.0.0.1') and not url.username and not url.password and url.path in ('', '/') and not url.query and not url.fragment, 'strict loopback HTTPS fixture required')
    check(fixture['gateway_host'] in ('localhost', '127.0.0.1'), 'loopback gateway fixture required')
    check(os.environ.get('NODE_TLS_REJECT_UNAUTHORIZED') != '0', 'TLS bypass is prohibited')
    target = fixture['assets'][0]
    alias = target['name'] + ' · ' + target['username']
    check(target['name'] == 'M3 target A', 'first selector entry must be authorized target A')
    master = secrets.token_urlsafe(24)
    results = {'production_ready': False, 'cli_sha256': digest(binary), 'checks': {}, 'not_tested': ['desktop Tauri WebView: manual verification required', 'native logout-close: CLI has no logout command']}
    env = os.environ.copy()
    env.update(NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1', RUST_LOG='warn,zeroterm=info')
    api = Api(fixture)
    info = api.call('/info')
    check(info['production_ready'] is False and info['recording']['required'] is True and info['recording']['available'] is True, 'real candidate required recording discovery')
    check(all(info['features'][key] is True for key in ('ssh_terminal', 'ssh_exec', 'ssh_sftp')), 'real SSH feature discovery')
    profile = {'name': 'RFC-004 native release fixture', 'api_url': fixture['api_url'], 'server_id': fixture['server_id'], 'ssh_host': fixture['gateway_host'], 'ssh_port': fixture['gateway_port'], 'ssh_host_key_sha256': fixture['gateway_host_key_sha256'], 'ca_pem': Path(fixture['ca_file']).read_text()}
    last_login = 0.
    with tempfile.TemporaryDirectory(prefix='cli-', dir=work) as directory:
        root = Path(directory)
        vault = root / 'native.vault'
        profile_file = root / 'profile.json'
        profile_file.write_text(json.dumps(profile))
        profile_file.chmod(0o600)
        def command(args, expected=0, import_profile=False, path=vault, create=False, negative=None):
            nonlocal last_login
            # Pace intentional authentication tests below the shared 10/min IP limit.
            time.sleep(max(0, 7 - (time.monotonic() - last_login)))
            last_login = time.monotonic()
            if '--debug-safe' in sys.argv:
                label = args[0] + (' ' + args[1] if args[0] == 'sftp' else '')
                print('STAGE ' + label + (' ' + negative if negative else ''), flush=True)
            child = Cli(binary, ['--vault', str(path), *args], env, (master, fixture['password']))
            try:
                if negative == 'ca':
                    child.answer(b'Master password:', master.encode())
                    child.answer(b'Confirm:', master.encode())
                    child.answer(b'Bastion', b'')
                    child.answer(b'Bastion username', fixture['username'].encode())
                    child.answer(b'Bastion password:', fixture['password'].encode())
                else:
                    child.authenticate(master, fixture, create, import_profile)
                if import_profile and negative is None:
                    # Wait for actual target prompt/output, then send a split marker:
                    # echoed input cannot itself contain the successful output marker.
                    deadline = time.monotonic() + 15
                    while not child.out and time.monotonic() < deadline:
                        child.pump()
                    check(child.out, 'Managed target shell output was not opened')
                    os.write(child.master, b"printf '\\nNATIVE-'; printf 'SHELL-%s\\n' \"$BASTION_TARGET_ID\"; exit 7\r")
                status, out, err = child.finish()
                if '--debug-safe' in sys.argv:
                    codes = [code for code in ('API_UNREACHABLE', 'GATEWAY_HOST_KEY_CHANGED', 'CHANNEL_PERMISSION_DENIED') if code.encode() in err]
                    print('STAGE status=' + str(status) + (' code=' + ','.join(codes) if codes else ''), flush=True)
                check(status == expected if expected is not None else status != 0, 'real CLI exit status mismatch')
                return out, err
            finally:
                child.close()
        out, err = command(['bastion', '--profile', str(profile_file)], import_profile=True, create=True, expected=7)
        check(b'NATIVE-SHELL-A' in out, 'real Managed shell target identity A')
        results['checks']['managed_profile_login_asset_shell_A'] = 'passed'
        shell_ids = re.findall(re.escape(alias.encode()) + rb' \xc2\xb7 [^\r\n]* \xc2\xb7 ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', err)
        check(len(shell_ids) == 1, 'actual Managed shell public connection identity')
        results['checks']['managed_shell_connection_id'] = shell_ids[0].decode()
        raw, rawerr = command(['exec', alias, "printf '\\377\\000'; printf 'NATIVE-ERR:\\200\\000:END' >&2; exit 7"], expected=7)
        check(raw == bytes([255, 0]), 'exec raw stdout bytes or exit7')
        check(b'NATIVE-ERR:\x80\x00:END' in rawerr, 'exec raw stderr bytes')
        out, eoferr = command(['exec', alias, 'cat; printf NATIVE-EOF'])
        check(out == b'NATIVE-EOF', 'exec stdin EOF/output drain')
        ids = []
        for stream in (rawerr, eoferr):
            lines = re.findall(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', stream)
            check(len(lines) == 1, 'actual CLI must expose one public connection identity')
            ids.append(lines[0].decode())
        check(ids[0] != ids[1], 'new CLI Managed connection/ticket identity')
        results['checks']['exec_raw_stdout_stderr_exit7_stdinEOF'] = 'passed'
        results['checks']['reconnect_fresh_connection_ids'] = ids
        remote = str(Path(fixture['fixture_root']) / ('native-upload-' + secrets.token_hex(8) + '.bin'))
        upload, download = root / 'upload.bin', root / 'download.bin'
        upload.write_bytes(secrets.token_bytes(1024 * 1024))
        command(['sftp', 'put', alias, str(upload), remote])
        command(['sftp', 'get', alias, remote, str(download)])
        check(digest(upload) == digest(download), 'real Managed SFTP 1MiB hash')
        results['checks']['sftp_1MiB_sha256'] = digest(download)
        command(['sftp', 'rm', alias, remote])
        out, err = command(['-L', '10000:localhost:10000', 'exec', alias, 'printf ESCAPE'], expected=None)
        check(b'CHANNEL_PERMISSION_DENIED' in err and b'ESCAPE' not in out, 'real Managed CLI forwarding escape must fail closed')
        results['checks']['managed_cli_forward_escape_rejected'] = 'passed'
        badpin = root / 'wrong-pin.json'
        badpin.write_text(json.dumps(dict(profile, ssh_host_key_sha256='SHA256:' + base64.b64encode(bytes(32)).decode().rstrip('='))))
        badpin.chmod(0o600)
        _, err = command(['bastion', '--profile', str(badpin)], path=root / 'wrong-pin.vault', create=True, import_profile=True, expected=None, negative='pin')
        check(b'GATEWAY_HOST_KEY_CHANGED' in err, 'valid-but-wrong SSH pin must reject at key check')
        results['checks']['wrong_gateway_ssh_pin_rejected'] = 'passed'
        badca = root / 'missing-ca.json'
        badca.write_text(json.dumps(dict(profile, ca_pem=None)))
        badca.chmod(0o600)
        _, err = command(['bastion', '--profile', str(badca)], path=root / 'missing-ca.vault', create=True, import_profile=True, expected=None, negative='ca')
        check(b'API_UNREACHABLE' in err, 'private TLS CA omission must reject verified HTTPS')
        results['checks']['untrusted_private_CA_rejected'] = 'passed'
        check(master.encode() not in vault.read_bytes() and fixture['password'].encode() not in vault.read_bytes(), 'credentials not plaintext in native vault')
        results['checks']['no_password_echo_argv_public_profile_or_plaintext_vault'] = 'passed'
        for name in ('gateway.log', 'tls.log', 'node-smoke.log'):
            path = Path(fixture['fixture_root']) / name
            if path.is_file():
                contents = path.read_bytes()
                check(all(secret.encode() not in contents for secret in (master, fixture['password'])), 'known password leaked in fixture logs')
        results['checks']['known_passwords_absent_from_fixture_logs'] = 'passed'
        time.sleep(max(0, 7 - (time.monotonic() - last_login)))
        api.csrf = api.call('/auth/csrf')['csrf_token']
        login = api.call('/auth/login', {'username': fixture['username'], 'password': fixture['password'], 'device_label': 'native-release-cookie-isolation', 'client_type': 'web'})
        check('access_token' not in login and 'refresh_token' not in login, 'Web login may not return native tokens')
        denied = api.call('/integrations/zeroterm/connection-tickets', {'asset_id': target['asset_id'], 'account_id': target['account_id'], 'capabilities': ['shell'], 'purpose': 'terminal'}, expected=401)
        check('ticket_secret' not in denied, 'Web Cookie may not obtain SSH tickets')
        api.call('/auth/logout', {}, expected=204)
        results['checks']['web_cookie_cannot_issue_native_ssh_ticket'] = 'passed'
    (work / 'native-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    try:
        main()
    except CheckFailed as error:
        print('FAIL real ZeroTerm native CLI release check: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        # Never print exception argv, response bodies or the PTY transcript.
        try:
            diagnostic = Path(os.environ.get('BASTION_NATIVE_WORKDIR', '.')) / 'native-debug-trace.txt'
            diagnostic.write_text(traceback.format_exc(), encoding='utf-8')
            diagnostic.chmod(0o600)
        except OSError:
            pass
        print('FAIL real ZeroTerm native CLI release check (private fixture retained for diagnosis)', file=sys.stderr)
        raise SystemExit(1)
