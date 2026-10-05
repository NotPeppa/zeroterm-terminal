#!/usr/bin/env python3
"""Loopback TLS fixture with an explicit validity window, without changing clocks."""
import argparse
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def run(args):
    root = args.work.resolve()
    if os.geteuid() == 0 or root.is_symlink() or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077:
        raise RuntimeError('owned non-root0700 work directory required')
    start = dt.datetime.strptime(args.valid_from, '%Y%m%d%H%M%SZ')
    end = start + dt.timedelta(days=4)
    if not start < dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) < end:
        raise RuntimeError('certificate window does not cover server clock')
    os.umask(0o077)
    certificates = root / 'browser-tls'
    certificates.mkdir(mode=0o700)
    (certificates / 'index').write_text('')
    (certificates / 'serial').write_text('1000\n')
    (certificates / 'issued').mkdir(mode=0o700)
    config = certificates / 'openssl.conf'
    config.write_text(f'''[ca]
default_ca=local
[local]
database={certificates}/index
serial={certificates}/serial
new_certs_dir={certificates}/issued
private_key={certificates}/ca.key
certificate={certificates}/ca.pem
default_md=sha256
default_days=4
policy=names
unique_subject=no
[names]
commonName=supplied
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
[v3_leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''')
    commands = [
        ['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=Disposable release browser CA','-keyout',str(certificates/'ca.key'),'-out',str(certificates/'ca.csr')],
        ['openssl','ca','-batch','-selfsign','-notext','-config',str(config),'-extensions','v3_ca','-startdate',args.valid_from,'-enddate',end.strftime('%Y%m%d%H%M%SZ'),'-in',str(certificates/'ca.csr'),'-out',str(certificates/'ca.pem')],
        ['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(certificates/'localhost.key'),'-out',str(certificates/'localhost.csr')],
        ['openssl','ca','-batch','-notext','-config',str(config),'-extensions','v3_leaf','-startdate',args.valid_from,'-enddate',end.strftime('%Y%m%d%H%M%SZ'),'-in',str(certificates/'localhost.csr'),'-out',str(certificates/'localhost.pem')],
        ['openssl','verify','-CAfile',str(certificates/'ca.pem'),str(certificates/'localhost.pem')],
    ]
    with (certificates/'certificate.log').open('wb') as log:
        for command in commands:
            subprocess.run(command, stdout=log, stderr=log, check=True, timeout=30)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
    with (certificates/'proxy.log').open('wb') as log:
        child = subprocess.Popen(['python3',str(args.source/'tests/m3_tls_proxy.py'),'--port',str(port),'--upstream-port',str(args.upstream_port),'--certificate',str(certificates/'localhost.pem'),'--key',str(certificates/'localhost.key'),'--trusted-proxy-headers'], stdout=log, stderr=log)
        ready = certificates/'ready.json'
        try:
            for _ in range(100):
                if child.poll() is not None:
                    raise RuntimeError('TLS fixture exited before ready')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('TLS fixture listen timeout')
            ready.write_text(json.dumps({'tls_port':port,'pid':child.pid,'ca_file':str(certificates/'ca.pem'),'valid_from':args.valid_from,'valid_until':end.strftime('%Y%m%d%H%M%SZ')}))
            print('BROWSER_TLS_READY: strict CA/SAN verification; explicit test validity window', flush=True)
            deadline = time.monotonic()+7200
            while not (certificates/'stop').exists() and time.monotonic()<deadline:
                if child.poll() is not None:
                    raise RuntimeError('TLS fixture exited')
                time.sleep(1)
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
            ready.unlink(missing_ok=True)
            print('BROWSER_TLS_CLEANED: tracked proxy exited', flush=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--upstream-port',type=int,required=True)
    parser.add_argument('--valid-from',required=True)
    arguments=parser.parse_args()
    if not 1<=arguments.upstream_port<=65535:
        parser.error('invalid upstream port')
    try:
        run(arguments)
    except Exception as error:
        print('FAIL browser TLS fixture: '+type(error).__name__,flush=True)
        raise SystemExit(1)
