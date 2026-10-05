#!/usr/bin/env python3
"""Reuse the canonical M3 HTTPS fixture, held for up to two hours for native/UI checks.

Run from an isolated non-root work directory. PYTHONPATH must name the canonical
candidate's tests directory and CARGO_TARGET_DIR must belong to that one source
snapshot. This wrapper changes no gateway implementation or TLS policy.
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

import m3_https_smoke as m3


def run(work, control):
    if work.is_symlink():
        raise RuntimeError('isolated work root cannot be a symlink')
    work = work.resolve()
    if os.geteuid() == 0 or work.stat().st_uid != os.geteuid() or work.stat().st_mode & 0o077:
        raise RuntimeError('isolated work root must be owned by the non-root user and mode0700')
    target = os.environ.get('CARGO_TARGET_DIR')
    if not target or not Path(target).resolve().is_relative_to(work):
        raise RuntimeError('CARGO_TARGET_DIR must be isolated under this one work/source root')
    # PostgreSQL's Unix socket pathname limit also applies to the isolation root.
    # Keep only the generated child prefix short; never fall back to a global DB.
    original_temporary = tempfile.TemporaryDirectory
    def temporary(*args, **kwargs):
        kwargs.update(prefix='f-', dir=work)
        return original_temporary(*args, **kwargs)
    m3.tempfile.TemporaryDirectory = temporary

    def hold(directory, root, base, ca, fixture, ports, assets, processes):
        value = json.loads(fixture.read_text())
        key = (root / 'gateway/ssh_host_ed25519_key.pub').read_text().split()[1]
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(key)).digest()).decode().rstrip('=')
        enriched = [dict(asset, name='M3 target ' + chr(ord('A') + index), username=getpass.getuser()) for index, asset in enumerate(assets)]
        value.update(gateway_host='127.0.0.1', gateway_host_key_sha256=fingerprint, fixture_root=str(root), assets=enriched)
        native_fixture = directory / 'native-fixture.json'
        m3.private_json(native_fixture, value)
        profile = {'name':'RFC-004 release fixture', 'api_url':base, 'server_id':value['server_id'], 'ssh_host':'127.0.0.1', 'ssh_port':ports['gateway'], 'ssh_host_key_sha256':fingerprint, 'ca_pem':ca.read_text()}
        profile_file = directory / 'native-profile.json'
        m3.private_json(profile_file, profile)
        ready = directory / 'ready.json'
        m3.private_json(ready, {'api_url':base, 'browser_port':ports['tls'], 'remote_frontend_port':ports['tls'], 'api_port':ports['api'], 'gateway_port':ports['gateway'], 'fixture_root':str(root), 'ca_file':str(ca), 'fixture_file':str(fixture), 'native_fixture_file':str(native_fixture), 'native_profile_file':str(profile_file), 'assets':enriched, 'production_ready':False})
        try:
            print('RELEASE_NATIVE_READY: verified private-CA HTTPS and pinned SSH fixture; protected credentials file only; hold <=2h', flush=True)
            deadline = time.monotonic() + 7200
            while not (directory / 'stop').exists() and time.monotonic() < deadline:
                if any(child.poll() is not None for child in processes):
                    raise RuntimeError('isolated fixture child exited unexpectedly')
                time.sleep(1)
        finally:
            ready.unlink(missing_ok=True)
    m3.hold = hold
    m3.run(control)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--control-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.work_dir, args.control_dir)
    except Exception:
        # Startup errors must not dump argv, response bodies, private files/logs.
        print('FAIL isolated release native HTTPS fixture (private logs only)', flush=True)
        raise SystemExit(1)
