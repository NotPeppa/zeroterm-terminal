#!/usr/bin/env python3
"""Manual two-hour M3 fixture with an explicitly approved copied test TLS identity.

No TLS bypass: verify chain, hostname, validity and key match before startup.
The reused CA is for the existing user's browser trust; gateway SSH keys stay fresh.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import ssl
import subprocess

import release_native_fixture as native


def run(work, control, tls, ca_sha256):
    tls = tls.resolve()
    files = tuple(tls / name for name in ('ca.pem', 'localhost.pem', 'localhost.key'))
    if tls.parent != work.resolve() or tls.stat().st_uid != os.geteuid() or tls.stat().st_mode & 0o077:
        raise RuntimeError('copied TLS directory must be private and under owned work root')
    for path in files:
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o777 != 0o600:
            raise RuntimeError('copied TLS files must be owned regular mode0600 files')
    ca, cert, key = files
    if hashlib.sha256(ca.read_bytes()).hexdigest() != ca_sha256:
        raise RuntimeError('copied CA differs from explicitly approved digest')
    openssl = shutil.which('openssl')
    if not openssl:
        raise RuntimeError('OpenSSL is required for strict copied-certificate validation')
    subprocess.run([openssl, 'verify', '-purpose', 'sslserver', '-verify_hostname', 'localhost', '-CAfile', str(ca), str(cert)], check=True, capture_output=True, timeout=20)
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(certfile=cert, keyfile=key)
    # Only this fixture's startup certificate factory changes; no live config mutation.
    native.m3.certificate = lambda root, openssl: files
    native.run(work, control)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--control-dir', type=Path, required=True)
    parser.add_argument('--tls-dir', type=Path, required=True)
    parser.add_argument('--ca-sha256', required=True)
    args = parser.parse_args()
    try:
        run(args.work_dir, args.control_dir, args.tls_dir, args.ca_sha256)
    except Exception:
        print('FAIL private manual fixture: copied TLS validation or fixture startup', flush=True)
        raise SystemExit(1)
