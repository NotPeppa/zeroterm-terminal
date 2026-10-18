#!/usr/bin/env python3
"""Run all opt-in PostgreSQL suites against separately created disposable databases."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--database-url-file', required=True)
parser.add_argument('--release', action='store_true')
args = parser.parse_args()
path = Path(args.database_url_file)
assert path.is_file() and not path.is_symlink()
if os.name == 'posix':
    stat = path.stat()
    assert stat.st_uid == os.getuid() and stat.st_mode & 0o777 == 0o600
url = path.read_text().strip()
command = ['cargo', 'test', '--locked', '--workspace', '--no-run', '--message-format=json']
if args.release: command += ['--release']
build = subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
binaries = {}
for line in build.stdout.splitlines():
    item = json.loads(line)
    if item.get('reason') != 'compiler-artifact' or not item.get('executable'): continue
    target = item['target']
    if target['kind'] == ['test'] and target['name'] in ('postgres', 'web_sessions', 'lifecycle', 'implicit_access', 'user_deletion', 'audit_partitions', 'asset_groups', 'native_sessions'):
        binaries['server-postgres' if target['name'] == 'postgres' else target['name']] = item['executable']
suites = ('server-postgres', 'web_sessions', 'lifecycle', 'implicit_access', 'user_deletion', 'audit_partitions', 'asset_groups', 'native_sessions')
assert set(binaries) == set(suites), 'missing real PostgreSQL test binaries'
command = ['cargo', 'run', '--locked', '-p', 'bastion-store', '--example', 'local_pg_acceptance']
if args.release: command += ['--release']
command += ['--']
for suite in suites: command += [suite, binaries[suite]]
subprocess.run(command, cwd=ROOT, check=True, input=json.dumps({'database_url':url}), text=True)
