#!/usr/bin/env python3
"""Disposable RFC-006 N3 acceptance: real PostgreSQL, TLS, serve, sshd, OpenSSH and optional ZeroTerm.

Requires initdb/pg_ctl/psql, openssl, ssh/sshd/sftp and a built target/debug/bastion-server.
No existing database, SSH configuration, vault, trust store or keychain entry is modified.
All service ports are loopback high ports; all private files are removed in finally.
"""
import argparse
import base64
import getpass
import hashlib
import http.client
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(probe, budget=20):
    deadline = time.monotonic() + budget
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = probe()
            if result:
                return result
        except (OSError, ValueError, http.client.HTTPException) as exc:
            last_error = exc
        time.sleep(.05)
    raise AssertionError(f'readiness/verification deadline exceeded ({last_error})')


class Fixture:
    def __init__(self, base):
        self.base = base
        self.processes = []
        self.proxy = None
        self.pg_started = False
        self.env = {**os.environ, 'LC_ALL': 'C', 'TMPDIR': '/private/tmp'}
        self.evidence = {'production_ready': False}

    def run(self, args, **kwargs):
        return subprocess.run([str(a) for a in args], cwd=ROOT, env=self.env,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

    def private(self, name, contents):
        path = self.base / name
        path.write_text(contents)
        path.chmod(0o600)
        return path

    def spawn(self, args, name, **kwargs):
        log = open(self.base / (name + '.log'), 'ab')
        process = subprocess.Popen([str(a) for a in args], cwd=ROOT, stdout=log, stderr=log,
                                   env=kwargs.pop('env', self.env), **kwargs)
        log.close()
        self.processes.append(process)
        return process

    def setup(self):
        self.pg_port, self.api_port, self.tls_port, self.ssh_port, self.gateway_port, self.metrics_port = [port() for _ in range(6)]
        self.origin = f'https://localhost:{self.tls_port}'
        self.run(['initdb', '-D', self.base/'data', '-U', 'n3', '-A', 'trust', '--no-locale', '-E', 'UTF8'])
        self.run(['pg_ctl', '-D', self.base/'data', '-l', self.base/'postgres.log', '-o',
                  f'-h 127.0.0.1 -p {self.pg_port} -k {self.base}', '-w', 'start'])
        self.pg_started = True
        self.url = f'postgresql://n3@127.0.0.1:{self.pg_port}/postgres'
        self.private('url', self.url)
        for key in ('target', 'client', 'gateway'):
            self.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', self.base/key])
        self.target_public = ' '.join((self.base/'target.pub').read_text().split()[:2])
        self.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', self.base/'ca.key',
                  '-out', self.base/'ca.crt', '-subj', '/CN=Disposable-N3-CA', '-days', '1',
                  '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
        self.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', self.base/'tls.key',
                  '-out', self.base/'tls.csr', '-subj', '/CN=localhost'])
        extensions = self.private('tls.ext', 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nauthorityKeyIdentifier=keyid,issuer\n')
        self.run(['openssl', 'x509', '-req', '-in', self.base/'tls.csr', '-CA', self.base/'ca.crt',
                  '-CAkey', self.base/'ca.key', '-CAcreateserial', '-out', self.base/'tls.crt', '-days', '1', '-extfile', extensions])
        for name in ('ca.key', 'tls.key'):
            (self.base/name).chmod(0o600)
        self.private('sshd_config', f'''Port {self.ssh_port}
ListenAddress 127.0.0.1
HostKey {self.base}/target
PidFile {self.base}/sshd.pid
AuthorizedKeysFile {self.base}/client.pub
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
Subsystem sftp internal-sftp
''')
        self.spawn(['/usr/sbin/sshd', '-D', '-e', '-f', self.base/'sshd_config'], 'sshd')
        self.private('openssh.json', json.dumps({'address': f'127.0.0.1:{self.ssh_port}', 'username': getpass.getuser(),
                                               'approved_key': self.target_public, 'private_key_file': str(self.base/'client')}))
        (self.base/'recordings').mkdir(mode=0o700)
        self.private('kek', base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))
        self.config = self.private('config.toml', f'''server_id="n3-disposable"
gateway_id="main"
api_listen="127.0.0.1:{self.api_port}"
public_origin="{self.origin}"
database_url_file="{self.base}/url"
active_kek_version=1
[kek_files]
"1"="{self.base}/kek"
[network]
allow=["127.0.0.0/8"]
deny=[]
[guacd]
address="127.0.0.1:9"
bridge_bind="10.99.99.1:0"
bridge_advertise_host="10.99.99.1"
allowed_source_ips=["127.0.0.1"]
version="1.6.0"
[production]
recording_directory="{self.base}/recordings"
recording_required=true
retention_days=1
minimum_free_bytes=268435456
metrics_listen="127.0.0.1:{self.metrics_port}"
trusted_proxies=["127.0.0.1/32"]
[production.limits]
connections_global=10
connections_per_user=3
pending_connections=20
startup_seconds=15
queue_bytes=262144
absolute_seconds=1800
idle_seconds=600
stalled_seconds=5
''')
        self.server = ROOT/'target/debug/bastion-server'
        self.run([self.server, 'migrate', '--config', self.config])
        self.password = base64.urlsafe_b64encode(os.urandom(24)).decode()
        self.run([self.server, 'create-admin', '--config', self.config, '--username', 'n3admin', '--password-stdin'],
                 input=(self.password+'\n').encode())
        native_env = {**self.env, 'BASTION_NATIVE_SSH_LISTEN': f'127.0.0.1:{self.gateway_port}',
                      'BASTION_NATIVE_SSH_PUBLIC_HOST': '127.0.0.1', 'BASTION_NATIVE_SSH_HOST_KEY_FILE': str(self.base/'gateway')}
        self.spawn([self.server, 'serve', '--config', self.config], 'serve', env=native_env)
        fixture = self

        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def forward(self):
                connection = http.client.HTTPConnection('127.0.0.1', fixture.api_port, timeout=20)
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ('connection', 'host', 'forwarded', 'x-forwarded-proto', 'x-forwarded-for')}
                headers.update({'Host': f'localhost:{fixture.tls_port}', 'X-Forwarded-Proto': 'https',
                                'X-Forwarded-For': '127.0.0.1', 'Connection': 'close'})
                try:
                    connection.request(self.command, self.path, body, headers)
                    response = connection.getresponse()
                    data = response.read()
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in ('transfer-encoding', 'connection', 'content-length'):
                            self.send_header(key, value)
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    self.send_error(502)
                finally:
                    connection.close()

            do_GET = do_POST = do_DELETE = do_PATCH = do_PUT = forward

        self.proxy = http.server.ThreadingHTTPServer(('127.0.0.1', self.tls_port), Proxy)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.base/'tls.crt', self.base/'tls.key')
        self.proxy.socket = context.wrap_socket(self.proxy.socket, server_side=True)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        jar = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar),
                                                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=self.base/'ca.crt')))
        wait_for(lambda: self.api('/info')['native']['available'])
        self.csrf = self.api('/auth/csrf')['csrf_token']
        self.api('/auth/login', {'username': 'n3admin', 'password': self.password, 'device_label': 'N3 acceptance'})
        self.asset = self.api('/admin/assets', {'name': 'N3 target', 'host': '127.0.0.1', 'port': self.ssh_port,
                                                'protocol': 'ssh', 'ssh_host_key': self.target_public})
        self.account = self.api(f'/admin/assets/{self.asset["id"]}/accounts',
                                {'label': 'fixture', 'username': getpass.getuser(),
                                 'credential': {'type': 'private_key', 'key_pem': (self.base/'client').read_text(), 'passphrase': None}})
        self.access = self.api('/native/auth/login', {'username': 'n3admin', 'password': self.password,
                                                     'device_label': 'N3 native acceptance'})['access_token']

    def api(self, path, body=None, bearer=False):
        headers = {'Content-Type': 'application/json', 'Origin': self.origin}
        if hasattr(self, 'csrf'):
            headers['X-Bastion-CSRF'] = self.csrf
        if bearer:
            headers['Authorization'] = 'Bearer '+self.access
        request = urllib.request.Request(self.origin+'/api/v1'+path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        with self.http.open(request, timeout=20) as response:
            data = response.read()
            return json.loads(data) if data else None

    def ticket(self, capabilities):
        ticket = self.api('/native/connection-tickets', {'asset_id': self.asset['id'], 'account_id': self.account['id'],
                                                        'capabilities': capabilities}, bearer=True)
        askpass = self.private('askpass', "#!/bin/sh\nprintf '%s\\n' '"+ticket['ticket_secret']+"'\n")
        askpass.chmod(0o700)
        known = self.private('known', f'[127.0.0.1]:{self.gateway_port} '+(self.base/'gateway.pub').read_text())
        common = ['-F', '/dev/null', '-q', '-o', 'ProxyCommand=none', '-o', 'BatchMode=no',
                  '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
                  '-o', 'NumberOfPasswordPrompts=1', '-o', 'StrictHostKeyChecking=yes',
                  '-o', f'UserKnownHostsFile={known}', '-o', 'User='+ticket['gateway']['username']]
        env = {**self.env, 'SSH_ASKPASS': str(askpass), 'SSH_ASKPASS_REQUIRE': 'force', 'DISPLAY': ':0'}
        return ticket, common, env

    def rows(self):
        output = self.run(['psql', self.url, '-At', '-c',
                          "SELECT coalesce(json_agg(json_build_object('action',action,'payload',sanitized_payload) ORDER BY occurred_at,id),'[]') FROM audit_events WHERE action LIKE 'sftp.%'"])
        return json.loads(output.stdout)

    def openssh(self):
        content = bytes(i % 251 for i in range(8*1024*1024))
        (self.base/'upload').write_bytes(content)
        (self.base/'short').write_bytes(content[:1024])
        (self.base/'resume-local').write_bytes(content[:4096])
        expected = hashlib.sha256(content).hexdigest()
        ticket, common, env = self.ticket(['sftp'])
        deny = self.base/'deny'
        deny.mkdir(mode=0o500)
        batch = self.private('batch', '\n'.join([
            f'put -f {self.base}/upload {self.base}/remote', f'get {self.base}/remote {self.base}/back',
            f'put {self.base}/short {self.base}/resume-remote', f'reput {self.base}/upload {self.base}/resume-remote',
            f'reget {self.base}/remote {self.base}/resume-local', f'ls -l {self.base}',
            f'-cp {self.base}/remote {self.base}/copy',
            f'-put {self.base}/short {deny}/file', f'rename {self.base}/remote {self.base}/renamed',
            f'rm {self.base}/renamed', f'mkdir {self.base}/folder', f'rmdir {self.base}/folder', 'bye', '']))
        output = subprocess.run(['sftp', *common, '-P', str(self.gateway_port), '-b', str(batch), '127.0.0.1'],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        assert output.returncode == 0, 'OpenSSH SFTP failed'
        assert b'Operation unsupported' not in output.stderr
        assert b'copy-data' in output.stderr, 'unsupported copy must be rejected locally by the client'
        assert (self.base/'back').read_bytes() == content
        assert (self.base/'resume-local').read_bytes() == content
        wait_for(lambda: any(r['action'] == 'sftp.session' and r['payload']['connection_id'] == ticket['connection_id'] for r in self.rows()))
        files = [r['payload'] for r in self.rows() if r['action'] == 'sftp.file' and r['payload']['connection_id'] == ticket['connection_id']]
        assert len(files) == 6
        assert sum(r['sha256'] == expected for r in files) == 2
        assert sum(r['sha256'] is None and r['status'] == 0 for r in files) == 2
        assert any(r['status'] == 3 and r['write_bytes'] == 0 for r in files)
        assert not any(r['action'] == 'sftp.fsync' for r in self.rows())
        count = self.run(['psql', self.url, '-At', '-c', 'SELECT count(*) FROM recordings']).stdout.strip()
        assert count == b'0'
        self.evidence['openssh'] = {'bytes': len(content), 'sha256': expected, 'default_request_concurrency': True,
                                    'resumed_upload_download': True, 'write_open_denied_audit': True, 'sftp_only_no_recording': True}

    def pty_cli(self, binary, args, *, create=False, import_profile=False):
        # A separate vault path means no existing profile or saved credential can be changed.
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(self.base)
            os.execve(str(binary), [str(binary), *args, '--vault', str(self.base/'vault')], {**self.env, 'TERM': 'xterm', 'NO_PROXY': '*'})
        pending = b''
        transcript = b''
        steps = [(b'Master password:', b'N3-test-vault-password\n')]
        if create:
            steps.append((b'Confirm:', b'N3-test-vault-password\n'))
        if import_profile:
            steps.append((b'Bastion', b'\r'))
        steps.extend([(b'Bastion username', b'\r'), (b'Bastion password:', self.password.encode()+b'\n')])
        if import_profile:
            steps.append((b'Asset/account', b'\r'))
        deadline = time.monotonic()+60
        exit_sent = False
        try:
            while time.monotonic() < deadline:
                if not steps and import_profile and not exit_sent:
                    time.sleep(1)
                    os.write(fd, b'exit\r')
                    exit_sent = True
                ready, _, _ = select.select([fd], [], [], .1)
                if ready:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    pending += chunk
                    transcript += chunk
                    if b'\x1b[6n' in pending:
                        os.write(fd,b'\x1b[1;1R')
                        pending=pending.replace(b'\x1b[6n',b'')
                    if steps and steps[0][0] in pending:
                        _, reply = steps.pop(0)
                        os.write(fd, reply)
                        pending = b''
                status_pid, status = os.waitpid(pid, os.WNOHANG)
                if status_pid:
                    assert os.waitstatus_to_exitcode(status) == 0, 'ZeroTerm CLI failed'
                    return
            if time.monotonic()>=deadline:
                os.kill(pid,signal.SIGTERM)
            _, status = os.waitpid(pid, 0)
            assert not steps and os.waitstatus_to_exitcode(status) == 0, 'ZeroTerm CLI interaction failed'
        finally:
            # Never save a transcript: prompts can echo a mistimed password. Only public outcomes
            # and file hashes are recorded as evidence.
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            os.close(fd)

    def zeroterm(self, binary):
        public = self.api('/info')['native']['gateway']
        fingerprint = self.run(['ssh-keygen', '-lf', self.base/'gateway.pub', '-E', 'sha256']).stdout.decode().split()[1]
        profile = self.private('profile.json', json.dumps({'name': 'N3 isolated', 'api_url': self.origin,
                               'server_id': 'n3-disposable', 'ssh_host': public['host'], 'ssh_port': public['port'],
                               'ssh_host_key_sha256': fingerprint, 'ca_pem': (self.base/'ca.crt').read_text(), 'username': 'n3admin'}))
        self.pty_cli(binary, ['bastion', '--profile', str(profile)], create=True, import_profile=True)
        alias = 'N3 target · fixture'
        for args in [['sftp', 'ls', alias, str(self.base)],
                     ['sftp', 'put', alias, str(self.base/'upload'), str(self.base/'cli-remote')],
                     ['sftp', 'get', alias, str(self.base/'cli-remote'), str(self.base/'cli-back')],
                     ['sftp', 'mv', alias, str(self.base/'cli-remote'), str(self.base/'cli-renamed')],
                     ['sftp', 'rm', alias, str(self.base/'cli-renamed')],
                     ['sftp', 'mkdir', alias, str(self.base/'cli-folder')]]:
            print('ZeroTerm CLI '+args[1],flush=True)
            self.pty_cli(binary, args)
        expected = hashlib.sha256((self.base/'upload').read_bytes()).hexdigest()
        assert hashlib.sha256((self.base/'cli-back').read_bytes()).hexdigest() == expected
        def cli_files():
            return [r['payload'] for r in self.rows() if r['action']=='sftp.file' and r['payload']['path']==str(self.base/'cli-remote')]
        try:
            wait_for(lambda: sum(r['sha256']==expected for r in cli_files())==2)
        finally:
            self.evidence['cli_file_audits']=cli_files()
        files=cli_files()
        assert any(r['sha256']==expected and r['read_bytes']==8*1024*1024 for r in files)
        assert any(r['sha256']==expected and r['write_bytes']==8*1024*1024 for r in files)
        rows=self.rows()
        assert not any(r['action'] == 'sftp.fsync' for r in rows)
        self.evidence['zeroterm_cli'] = {'bytes': 8*1024*1024, 'sha256': expected, 'ls_put_get_mv_rm_mkdir': True,
                                         'private_ca_verified': True, 'isolated_vault': True}

    def multiplex(self):
        _, common, env = self.ticket(['shell', 'exec', 'sftp'])
        control = self.base/'control'
        master = subprocess.Popen(['ssh', *common, '-M', '-S', str(control), '-tt', '-p', str(self.gateway_port), '127.0.0.1'],
                                  env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.processes.append(master)
        received = bytearray()
        condition = threading.Condition()

        def collect():
            while True:
                data = os.read(master.stdout.fileno(), 65536)
                if not data:
                    return
                with condition:
                    received.extend(data)
                    condition.notify_all()

        threading.Thread(target=collect, daemon=True).start()

        def marker(value):
            started = time.monotonic()
            master.stdin.write(("printf '"+value+"\\n'\n").encode())
            master.stdin.flush()
            with condition:
                assert condition.wait_for(lambda: (value+'\r\n').encode() in received, timeout=10), 'shell echo timeout'
            return (time.monotonic()-started)*1000

        wait_for(control.exists)
        master.stdin.write(b'stty -echo\n')
        master.stdin.flush()
        marker('N3-READY')
        common += ['-o', f'ControlPath={control}', '-o', 'ControlMaster=no']
        output = subprocess.run(['ssh', *common, '-p', str(self.gateway_port), '127.0.0.1', 'printf MIXED-EXEC'],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        assert output.returncode == 0 and output.stdout == b'MIXED-EXEC'
        batch = self.private('mixed-batch', f'put {self.base}/upload {self.base}/mixed-remote\nbye\n')
        upload = subprocess.Popen(['sftp', *common, '-P', str(self.gateway_port), '-b', str(batch), '127.0.0.1'],
                                  env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.processes.append(upload)
        started = time.monotonic()
        samples = []
        while upload.poll() is None:
            samples.append(marker('N3-ECHO-'+str(len(samples))))
            time.sleep(.02)
        assert upload.returncode == 0, 'multiplexed SFTP failed'
        elapsed = time.monotonic()-started
        master.stdin.write(b'exit\n')
        master.stdin.flush()
        assert master.wait(timeout=15) == 0
        self.evidence['multiplex'] = {'bytes': 8*1024*1024, 'shell_exec_sftp': True,
            'echo_samples': len(samples), 'max_echo_ms': round(max(samples), 3),
            'median_echo_ms': round(sorted(samples)[len(samples)//2], 3), 'transfer_seconds': round(elapsed, 3),
            'scope': 'healthy loopback target; does not measure a stalled target'}

    def rejected_and_revoked(self):
        ticket, common, env = self.ticket(['exec'])
        control = self.base/'exec-control'
        master = subprocess.Popen(['ssh', *common, '-M', '-N', '-S', str(control), '-p', str(self.gateway_port), '127.0.0.1'],
                                  env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(master)
        wait_for(control.exists)
        common += ['-o', f'ControlPath={control}', '-o', 'ControlMaster=no']
        batch = self.private('reject-batch', 'ls\nbye\n')
        output = subprocess.run(['sftp', *common, '-P', str(self.gateway_port), '-b', str(batch), '127.0.0.1'],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        assert output.returncode != 0
        output = subprocess.run(['ssh', *common, '-p', str(self.gateway_port), '127.0.0.1', 'printf STILL-EXEC'],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        assert output.returncode == 0 and output.stdout == b'STILL-EXEC'
        master.terminate()
        master.wait(timeout=10)
        wait_for(lambda: any(r['action']=='sftp.rejected' and r['payload']['connection_id']==ticket['connection_id']
                             and r['payload']['reason_code']=='PERMISSION_DENIED' for r in self.rows()))
        ticket, common, env = self.ticket(['sftp'])
        remote = self.base/'revoked-upload'
        batch = self.private('revoke-batch', f'put {self.base}/upload {remote}\nbye\n')
        upload = subprocess.Popen(['sftp', *common, '-l', '1024', '-P', str(self.gateway_port), '-b', str(batch), '127.0.0.1'],
                                  env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(upload)
        wait_for(lambda: remote.exists() and remote.stat().st_size>0)
        self.api('/connections/'+ticket['connection_id']+'/disconnect', {})
        assert upload.wait(timeout=10) != 0
        wait_for(lambda: any(r['action']=='sftp.session' and r['payload']['connection_id']==ticket['connection_id'] for r in self.rows()))
        rows = [r for r in self.rows() if r['payload']['connection_id']==ticket['connection_id']]
        assert any(r['action']=='sftp.file' and r['payload']['status'] is None for r in rows)
        connection = self.api('/native/connections/'+ticket['connection_id'], bearer=True)
        assert connection['state']=='failed'
        self.evidence['rejection_revocation'] = {'exec_only_rejection_audited': True, 'same_connection_exec_usable': True,
                                                 'admin_disconnect_during_upload': True, 'connection_failed': True,
                                                 'unfinished_file_and_session_audits': True}

    def cleanup(self):
        if self.proxy:
            self.proxy.shutdown()
            self.proxy.server_close()
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if self.pg_started:
            self.run(['pg_ctl', '-D', self.base/'data', '-m', 'fast', '-w', 'stop'])
        (self.base/'deny').chmod(0o700) if (self.base/'deny').exists() else None
        shutil.rmtree(self.base)
        self.evidence['cleanup'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zeroterm', type=Path, help='Existing built ZeroTerm CLI; no client source is changed')
    parser.add_argument('--evidence', type=Path, default=ROOT/'target/native-sftp-evidence.json')
    parser.add_argument('--pg-suites', action='store_true')
    parser.add_argument('--gateway-test', action='store_true')
    args = parser.parse_args()
    base = Path(tempfile.mkdtemp(prefix='zt3-', dir='/private/tmp'))
    fixture = Fixture(base)
    try:
        print("Starting disposable PostgreSQL/TLS/sshd/serve",flush=True)
        fixture.setup()
        print("OpenSSH SFTP 8 MiB and resume acceptance",flush=True)
        fixture.openssh()
        print("ControlMaster mixed-channel echo latency",flush=True)
        fixture.multiplex()
        print("Exec-only capability rejection and administrator revocation",flush=True)
        fixture.rejected_and_revoked()
        if args.zeroterm:
            print("ZeroTerm CLI with isolated vault",flush=True)
            fixture.zeroterm(args.zeroterm.resolve())
        if args.gateway_test:
            env = {**fixture.env, 'BASTION_NATIVE_OPENSSH_FIXTURE': str(base/'openssh.json')}
            subprocess.run(['cargo', 'test', '-p', 'bastion-gateway', '--lib', 'real_openssh_exec_and_sftp_roundtrip',
                            '--', '--ignored', '--nocapture'], cwd=ROOT, env=env, check=True)
            fixture.evidence['gateway_real_openssh'] = True
        if args.pg_suites:
            subprocess.run(['python3', str(ROOT/'tests/pg_acceptance.py'), '--database-url-file', str(base/'url')],
                           cwd=ROOT, env=fixture.env, check=True)
            fixture.evidence['postgres_suites'] = 8
    finally:
        fixture.cleanup()
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(fixture.evidence, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(fixture.evidence, ensure_ascii=False))


if __name__ == '__main__':
    main()
