#!/usr/bin/env python3
"""M3 store regression on a disposable PostgreSQL cluster, no network target."""
import getpass
import json
import os
from pathlib import Path
import subprocess
import tempfile
from m1_smoke import database, request, PASSWORD
from openssh_smoke import port, process, wait_port

ROOT = Path(__file__).resolve().parents[1]


def run():
    pg = Path(os.environ.get('BASTION_PG_BIN', '/usr/lib/postgresql/17/bin'))
    subprocess.run(['cargo', 'build', '--locked', '-p', 'bastion-server'], cwd=ROOT, check=True)
    server = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')) / 'debug/bastion-server'
    with tempfile.TemporaryDirectory(prefix='bastion-m3-pg-') as directory:
        root = Path(directory)
        db_port, api_port, ssh_port = port(), port(), port()
        local = root / 'gateway'
        subprocess.run([str(server), 'init', '--directory', str(local)], check=True)
        url_file = local / 'database-url'
        url_file.write_text(f'postgres://fixture@127.0.0.1:{db_port}/postgres')
        url_file.chmod(0o600)
        config = root / 'fixture.toml'
        config.write_text(f'''server_id = "m3-pg-test"
gateway_id = "main"
api_listen = "127.0.0.1:{api_port}"
public_origin = "http://127.0.0.1:{api_port}"
ssh_listen = "127.0.0.1:{ssh_port}"
database_url_file = "{url_file}"
ssh_host_key_file = "{local}/ssh_host_ed25519_key"
active_kek_version = 1
[kek_files]
"1" = "{local}/kek-v1"
[network]
allow = ["127.0.0.1/32"]
deny = []
''')
        with database(pg, root, db_port):
            for _ in range(2):
                subprocess.run([str(server), 'migrate', '--config', str(config)], check=True)
            subprocess.run([str(server), 'create-admin', '--config', str(config), '--username', 'admin', '--password-stdin'], input=PASSWORD+'\n', text=True, check=True)
            with process([str(server), 'serve-m1', '--config', str(config)], root/'gateway.log') as gateway:
                wait_port(api_port, gateway, root/'gateway.log')
                base = f'http://127.0.0.1:{api_port}'
                login = request(base, '/auth/login', {'username':'admin','password':PASSWORD,'device_label':'M3 disposable PG'})
                token = login['access_token']
                asset = request(base, '/admin/assets', {'name':'No network fixture','host':'127.0.0.1','port':22,'tags':[]}, token, expected=201)
                account = request(base, f'/admin/assets/{asset["id"]}/accounts', {'username':getpass.getuser(),'credential':{'type':'password','password':'fixture-inert-password-only'}}, token, expected=201)
                fixture = root/'fixture.json'
                fixture.write_text(json.dumps({'database_url_file':str(url_file),'server_id':'m3-pg-test','gateway_id':'main','username':'admin','asset_id':asset['id'],'account_id':account['id']}))
                fixture.chmod(0o600)
            # Gateway stopped before recovery regression; no concurrent ownership tasks.
            env = os.environ.copy()
            env['BASTION_M1_FIXTURE'] = str(fixture)
            subprocess.run(['cargo','test','--locked','-p','bastion-store','--test','lifecycle','--','--ignored','--nocapture','--test-threads=1'], cwd=ROOT, env=env, check=True)
            def sql(statement, expected=0):
                result = subprocess.run([str(pg/'psql'),'-X','-h','127.0.0.1','-p',str(db_port),'-U','fixture','-d','postgres','-At','-c',statement], capture_output=True, text=True)
                assert (result.returncode == 0) if expected == 0 else (result.returncode != 0), 'isolated audit SQL assertion failed'
                return result.stdout.strip()
            expired = sql("SELECT 'audit_events_m_'||to_char(date_trunc('month',clock_timestamp())-interval '8 months','YYYYMM')")
            sql("INSERT INTO audit_events(id,occurred_at,action,resource_type,request_id) VALUES(gen_random_uuid(),date_trunc('month',clock_timestamp())-interval '8 months'+interval '1 day','fixture.expired','fixture',gen_random_uuid())")
            subprocess.run([str(server), 'partition-audit', '--config', str(config), '--offline'], check=True)
            sql("INSERT INTO audit_events(id,occurred_at,action,resource_type,request_id) VALUES(gen_random_uuid(),clock_timestamp()-interval '50 years','fixture.default','fixture',gen_random_uuid())")
            subprocess.run([str(server), 'retain-audit', '--config', str(config), '--offline', '--days', '180'], check=True)
            assert sql(f"SELECT to_regclass('public.{expired}') IS NULL") == 't'
            assert sql("SELECT count(*) FROM audit_events WHERE action='fixture.expired'") == '0'
            assert sql("SELECT count(*) FROM audit_events_default WHERE action='fixture.default'") == '1'
            assert sql("SELECT count(*) FROM audit_events WHERE action='audit.partition_dropped'") == '1'
            sql("UPDATE audit_events SET action='fixture.tamper'", expected=1)
            sql("DELETE FROM audit_events", expected=1)
            sql("CREATE ROLE fixture_runtime NOLOGIN; GRANT USAGE ON SCHEMA public TO fixture_runtime; GRANT SELECT,INSERT ON audit_events TO fixture_runtime")
            sql("SET ROLE fixture_runtime; SELECT count(*) FROM audit_events")
            sql("SET ROLE fixture_runtime; UPDATE audit_events SET action='tamper'", expected=1)
            sql("SET ROLE fixture_runtime; DELETE FROM audit_events", expected=1)
            sql("SET ROLE fixture_runtime; TRUNCATE audit_events", expected=1)
            sql("SET ROLE fixture_runtime; DROP TABLE audit_events", expected=1)
            # Upgrade is idempotent; retention never drops the default partition.
            subprocess.run([str(server), 'partition-audit', '--config', str(config), '--offline'], check=True)
            subprocess.run([str(server), 'retain-audit', '--config', str(config), '--offline', '--days', '180'], check=True)
            subprocess.run([str(server), 'migrate', '--config', str(config)], check=True)
    print('M3 0001–0005 migrations + isolated store lifecycle/revisions/devices/recovery + offline audit guard passed')


if __name__ == '__main__':
    run()
