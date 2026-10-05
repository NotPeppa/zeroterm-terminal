#!/usr/bin/env python3
"""Verify an actual ZeroTerm shell's sealed recording in the isolated PostgreSQL fixture.

Run after release_native_cli.py against the SAME healthy fixture, before faults.
Uses only public metadata; never selects wrapped keys, tokens or passwords.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import uuid

from release_native_cli import CheckFailed, check, digest, protected


def main():
    check(os.geteuid() != 0, 'recording proof must run as non-root fixture owner')
    work = protected(os.environ['BASTION_NATIVE_WORKDIR'], directory=True)
    fixture = json.loads(protected(os.environ['BASTION_NATIVE_FIXTURE']).read_text())
    results_file = protected(work / 'native-results.json')
    result = json.loads(results_file.read_text())
    connection = str(uuid.UUID(result['checks']['managed_shell_connection_id']))
    database = urllib.parse.urlsplit(protected(fixture['database_url_file']).read_text().strip())
    check(database.scheme in ('postgres', 'postgresql') and database.hostname == '127.0.0.1' and database.port != 5432 and database.password is None and database.username == 'fixture' and database.path == '/postgres', 'only isolated passwordless fixture PostgreSQL may be queried')
    env = os.environ.copy()
    env.update(PGHOST=database.hostname, PGPORT=str(database.port), PGUSER=database.username, PGDATABASE='postgres')
    query = """BEGIN TRANSACTION READ ONLY;
SELECT json_build_object('connection_id',c.id,'ticket_id',c.ticket_id,
'asset_id',c.asset_id,'account_id',c.account_id,'transport',c.transport,
'connection_state',c.state,'channel_id',ch.id,'kind',ch.kind,
'channel_state',ch.state,'exit_code',ch.exit_code,'channel_failure',ch.failure_code,
'recording_id',r.id,'recording_state',r.state,'checksum',r.checksum,
'last_written_seq',r.last_written_seq,'last_synced_seq',r.last_synced_seq,
'ended',r.ended_at IS NOT NULL,'relative_path',r.relative_path)
FROM connections c JOIN channels ch ON ch.connection_id=c.id
JOIN recordings r ON r.channel_id=ch.id
WHERE c.id='""" + connection + "' AND ch.kind='shell'; COMMIT;"
    answer = subprocess.run(['/usr/lib/postgresql/17/bin/psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', query], env=env, capture_output=True, text=True, timeout=20)
    check(answer.returncode == 0, 'isolated recording metadata query failed')
    rows = [json.loads(line) for line in answer.stdout.splitlines() if line.strip()]
    check(len(rows) == 1, 'actual native shell must have exactly one recording')
    row = rows[0]
    check(row['asset_id'] == fixture['assets'][0]['asset_id'] and row['account_id'] == fixture['assets'][0]['account_id'] and row['transport'] == 'ssh', 'recording must belong to actual authorized native target')
    check(row['connection_state'] == row['channel_state'] == 'closed' and row['kind'] == 'shell' and row['exit_code'] == 7 and row['channel_failure'] is None, 'actual shell must close normally with exit7 and no failure')
    check(row['recording_state'] == 'complete' and row['ended'] and row['checksum'] and row['last_written_seq'] == row['last_synced_seq'] and row['last_synced_seq'] >= 1, 'native shell recording must be Complete with sealed synchronized metadata')
    recording_root = protected(Path(fixture['fixture_root']) / 'recordings', directory=True)
    path = recording_root / row['relative_path']
    check(not path.is_symlink() and path.resolve().is_relative_to(recording_root), 'recording file must stay inside isolated recording root')
    actual_checksum = digest(path)
    check(actual_checksum == row['checksum'], 'sealed encrypted recording checksum must match actual file bytes')
    row['file_checksum_verified'] = True
    row.pop('relative_path')
    result['checks']['managed_shell_recording_complete'] = row
    results_file.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'managed_shell_recording_complete': row, 'production_ready': False}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except CheckFailed as error:
        print('FAIL native recording proof: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        # Never dump DB stderr, fixture secrets or key metadata.
        print('FAIL native recording proof: private diagnostic category only', file=sys.stderr)
        raise SystemExit(1)
