#!/usr/bin/env python3
"""Fault/recovery controls for one explicitly owned Docker browser fixture only."""
import base64,errno,hashlib,json,os,re,shutil,subprocess,sys,time,uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
root=Path(sys.argv[1]).resolve()
assert root.parent==Path('/var/tmp') and re.fullmatch(r'zt-guac-v2-[a-z0-9-]+',root.name)
fixture=json.loads((root/'browser-fixture.json').read_text())
assert fixture['server_id']==root.name and fixture['recording_faults_enabled']
data=json.loads(sys.stdin.read() or '{}');operation=sys.argv[2]
env=dict(os.environ,GUACD_IMAGE=fixture['engine_image_id'],BASTION_HTTPS_PORT='127.0.0.1:'+str(fixture['port']))
# Same rule as docker_browser_fixture.py: a --subnet-offset fixture writes its own compose.yaml.
compose=['docker','compose','-p',root.name,'-f',str(root/'compose.yaml' if (root/'compose.yaml').exists() else ROOT/'compose.yaml'),'-f',str(root/'override.json')]

def run(*args,**kwargs):
    return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs)
def out(*args):return run(*args).stdout.decode().strip()
def dc(*args):return run(*compose,*args,env=env)
def service(name):
    identity=out('docker','ps','-aq','--filter','label=com.docker.compose.project='+root.name,'--filter','label=com.docker.compose.service='+name)
    assert re.fullmatch('[0-9a-f]{12,64}',identity)
    row=json.loads(out('docker','inspect',identity))[0]
    assert row['Config']['Labels']['com.docker.compose.project']==root.name
    return row['Id']
def database():return out('docker','exec',service('postgres'),'printenv','POSTGRES_DB')
def pg():
    return root.name+'-restored-postgres' if (root/'restored').exists() else service('postgres')
def sql(query):
    return out('docker','exec',pg(),'psql','-X','-U','bastion','-d',database(),'-v','ON_ERROR_STOP=1','-At','-c',query)
def uuid_value(name):return str(uuid.UUID(data[name]))
def off():
    path=root/'fault/control';number=int(path.read_text().split()[0])+1
    path.write_text(str(number)+' off\n')
def app_up():
    dc('up','-d','--force-recreate','--wait','--wait-timeout','90','bastion')
    dc('up','-d','--force-recreate','--wait','--wait-timeout','90','proxy')
def app_stop():dc('stop','proxy','bastion')
def maintenance(command,config='maintenance.toml',extra=(),expect_success=True):
    (root/config).chmod(0o644)
    args=['docker','run','--rm','--network',root.name+'_app','--user','10001:10001',
          '--cap-drop','ALL','--security-opt','no-new-privileges:true','--read-only',
          '-v',str(root/config)+':/etc/zeroterm-bastion/maintenance.toml:ro',
          '-v',str(root/'restored/secrets')+':/etc/zeroterm-bastion/secrets:ro',
          '-v',str(root/'restored/database-auth')+':/run/bastion-db:ro',
          '-v',str(root/'restored/runtime-auth')+':/run/bastion-runtime:ro',
          '-v',str(root/'recordings')+':/var/lib/zeroterm-bastion/recordings']
    if extra:
        assert extra[0]=='--manifest' and re.fullmatch(r'manifest(?:-v2)?\.json',extra[1])
        (root/extra[1]).chmod(0o644)
        args+=['-v',str(root/extra[1])+':/run/fixture-manifest.json:ro']
        extra=('--manifest','/run/fixture-manifest.json')
    args += [fixture['application_image_id'],command,'--config','/etc/zeroterm-bastion/maintenance.toml',*extra]
    done=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if expect_success:assert done.returncode==0,done.stderr.decode()
    else:assert done.returncode!=0
    return {'exit':done.returncode}
def fingerprint():
    rows=json.loads(sql("SELECT json_build_object('credentials',(SELECT json_agg(json_build_array(id,md5(ciphertext::text),md5(nonce::text)) ORDER BY id) FROM credentials),'recordings',(SELECT json_agg(json_build_array(id,md5(nonce_prefix::text)) ORDER BY id) FROM recordings))"))
    rows['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'recordings').glob('*.ztrec')}
    return rows
def restored_config(text,owner=False):
    return text.replace('/run/bastion-runtime/database-url','/run/bastion-db/database-url') if owner else text

result={}
if operation=='limits':
    row=json.loads(out('docker','inspect',service('guacd')))[0]
    log=out('docker','exec',service('target'),'cat','/var/log/xrdp-sesman.log')
    for username in ('fixture','fixture2','fixture3'):
        assert 'access granted): username '+username+',' in log
        assert 'Session started successfully for user '+username+' on display ' in log
    result={'guacd_pids_limit':row['HostConfig']['PidsLimit'],'guacd_pid_events':out('docker','exec',row['Id'],'cat','/sys/fs/cgroup/pids.events'),'three_rdp_os_logins_verified':True}
elif operation=='arm':
    selected=data['mode'];assert selected in ['off','open','write','short-write','file-fsync','dir-fsync','blocked-write','blocked-fsync','stuck-write','stuck-fsync']
    control=root/'fault/control';number=int(control.read_text().split()[0])+1
    (root/'fault/hits').write_text('');control.write_text(str(number)+' '+selected+'\n')
    result={'armed':selected}
elif operation=='hits':result={'hits':(root/'fault/hits').read_text().splitlines()}
elif operation=='fill':
    stat=os.statvfs(root/'recordings');assert stat.f_blocks*stat.f_frsize<=512*1024*1024
    assert (root/'recording-filesystem').exists()
    filled=0
    with (root/'recordings/filler').open('xb',buffering=0) as file:
        while True:
            try:filled+=file.write(bytes(65536))
            except OSError as error:
                assert error.errno==errno.ENOSPC;break
    result={'real_enospc':True,'filled_bytes':filled,'filesystem_limit_bytes':stat.f_blocks*stat.f_frsize}
elif operation=='clear-fill':(root/'recordings/filler').unlink();result={'cleared':True}
elif operation in ['fail-finalize','clear-finalize']:
    if operation=='fail-finalize':sql("CREATE FUNCTION zt_fixture_finalization() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='complete' THEN RAISE EXCEPTION 'controlled finalization failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER zt_fixture_finalization BEFORE UPDATE OF state ON recordings FOR EACH ROW EXECUTE FUNCTION zt_fixture_finalization();")
    else:sql('DROP TRIGGER IF EXISTS zt_fixture_finalization ON recordings; DROP FUNCTION IF EXISTS zt_fixture_finalization();')
    result={'controlled_finalization':operation=='fail-finalize'}
elif operation=='kill-app':
    off();identity=service('bastion');run('docker','kill','--signal','KILL',identity)
    # Restart policy may already start it; docker start is idempotent.
    run('docker','start',identity);result={'killed_owned_app':True}
elif operation=='backup-restore':
    off();app_stop();backup=root/'backup';backup.mkdir(mode=0o700)
    original_pg=service('postgres');db=database();assert re.fullmatch('zt_guac_v2_[a-f0-9]+',db)
    with (backup/'database.dump').open('xb') as file:
        subprocess.run(['docker','exec',original_pg,'pg_dump','-Fc','-U','bastion','-d',db],stdout=file,check=True)
    shutil.copytree(root/'recordings',backup/'recordings')
    original_files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'recordings').glob('*.ztrec')}
    for path in (root/'recordings').glob('*.ztrec'):
        assert path.resolve().parent==root/'recordings' and uuid.UUID(path.stem)
        path.unlink()
    for path in (backup/'recordings').glob('*.ztrec'):
        target=root/'recordings'/path.name;shutil.copyfile(path,target);os.chown(target,10001,10001);target.chmod(0o600)
    assert original_files=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'recordings').glob('*.ztrec')}
    run('docker','cp','-a',service('bastion')+':/etc/zeroterm-bastion/secrets',str(backup/'secrets'))
    run('docker','cp','-a',service('bastion')+':/run/bastion-runtime',str(backup/'runtime-auth'))
    run('docker','cp','-a',original_pg+':/run/bastion-db',str(backup/'database-auth'))
    manifest=json.loads(sql("SELECT json_build_object('server_id',(SELECT server_id FROM server_settings WHERE singleton),'schema_version',2,'credential_count',(SELECT count(*) FROM credentials),'recording_count',(SELECT count(*) FROM recordings),'target_pin_count',(SELECT count(*) FROM assets WHERE protocol IN ('ssh','rdp')),'kek_versions',(SELECT json_agg(key_version ORDER BY key_version) FROM (SELECT key_version FROM credentials UNION SELECT key_version FROM recordings WHERE state<>'expired') k))"))
    (root/'manifest.json').write_text(json.dumps(manifest))
    restored=root/'restored';restored.mkdir(mode=0o755)
    for name in ['secrets','database-auth','runtime-auth']:
        shutil.copytree(backup/name,restored/name)
        for path in [restored/name,*list((restored/name).rglob('*'))]:
            os.chown(path,10001,10001);path.chmod(0o700 if path.is_dir() else 0o600)
    for name in ['database-auth','runtime-auth']:
        url=restored/name/'database-url';url.write_text(url.read_text().replace('@postgres:','@restored-postgres:'))
    name=root.name+'-restored-postgres'
    restored_pg=out('docker','run','-d','--name',name,'--label','zeroterm.acceptance='+root.name,'--network',root.name+'_app','--network-alias','restored-postgres',
        '--memory','128m','--memory-swap','256m','--cpus','0.5','-e','POSTGRES_USER=bastion','-e','POSTGRES_DB='+db,'-e','POSTGRES_PASSWORD_FILE=/run/bastion-db/password',
        '-v',str(restored/'database-auth')+':/run/bastion-db:ro','-v',str(restored/'runtime-auth')+':/run/bastion-runtime:ro',
        '-v',str(ROOT/'deploy/docker-runtime-role.sh')+':/role.sh:ro','postgres:17-bookworm')
    for _ in range(60):
        # The image's temporary init server accepts sockets before creating POSTGRES_DB.
        if subprocess.run(['docker','exec',restored_pg,'psql','-X','-h','127.0.0.1','-U','bastion','-d',db,'-At','-c','SELECT 1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
        time.sleep(1)
    else:raise RuntimeError('restored PG readiness timed out')
    run('docker','exec',restored_pg,'psql','-X','-U','bastion','-d',db,'-c',"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='bastion_runtime') THEN CREATE ROLE bastion_runtime LOGIN; END IF; END $$;")
    with (backup/'database.dump').open('rb') as file:run('docker','exec','-i',restored_pg,'pg_restore','--exit-on-error','--no-owner','-U','bastion','-d',db,stdin=file)
    run('docker','exec',restored_pg,'sh','-c','sed "s/\r$//" /role.sh | sh')
    # The directory itself is the marker selecting the restored cluster.
    original=(root/'production.toml').read_text();(root/'restore-maintenance.toml').write_text(restored_config(original,True))
    verified=maintenance('verify-backup','restore-maintenance.toml',('--manifest','manifest.json'))
    recovered=maintenance('recover-restore','restore-maintenance.toml')
    assert sql("SELECT count(*) FROM login_sessions WHERE revoked_at IS NULL")=='0'
    assert sql("SELECT count(*) FROM connection_tickets WHERE state='issued'")=='0'
    production=original
    (root/'production.toml').write_text(production)
    override=json.loads((root/'override.json').read_text())
    override['services']['bastion']['volumes'] += [
        {'type':'bind','source':str(restored/'secrets'),'target':'/etc/zeroterm-bastion/secrets','read_only':True},
        {'type':'bind','source':str(restored/'runtime-auth'),'target':'/run/bastion-runtime','read_only':True}]
    (root/'override.json').write_text(json.dumps(override));app_up()
    result={'cold_restore_separate_pg_cluster':True,'manifest':manifest,'verify_backup':verified,'recover_restore':recovered,'old_login_families_revoked':True,'issued_tickets_revoked':True}
elif operation=='rewrap':
    off();app_stop();before=fingerprint();secrets_dir=root/'restored/secrets'
    key=secrets_dir/'kek-v2';key.write_bytes(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'='));os.chown(key,10001,10001);key.chmod(0o600)
    original=(root/'production.toml').read_text()
    changed=original.replace('active_kek_version = 1','active_kek_version = 2').replace('"1" = "/etc/zeroterm-bastion/secrets/kek-v1"','"1" = "/etc/zeroterm-bastion/secrets/kek-v1"\n"2" = "/etc/zeroterm-bastion/secrets/kek-v2"')
    (root/'rewrap-maintenance.toml').write_text(restored_config(changed,True))
    maintenance('rewrap-keys','rewrap-maintenance.toml');assert before==fingerprint()
    assert sql("SELECT count(*) FROM credentials WHERE key_version<>2")=='0'
    assert sql("SELECT count(*) FROM recordings WHERE key_version<>2")=='0'
    manifest=json.loads((root/'manifest.json').read_text());manifest['kek_versions']=[2];(root/'manifest-v2.json').write_text(json.dumps(manifest))
    only=changed.replace('"1" = "/etc/zeroterm-bastion/secrets/kek-v1"\n','')
    (root/'new-key-maintenance.toml').write_text(restored_config(only,True))
    maintenance('verify-backup','new-key-maintenance.toml',('--manifest','manifest-v2.json'))
    (root/'missing-key.toml').write_text(restored_config(only,True).replace('secrets/kek-v2','secrets/missing-kek'))
    maintenance('verify-backup','missing-key.toml',('--manifest','manifest-v2.json'),expect_success=False)
    (root/'production.toml').write_text(only);app_up()
    result={'credential_ciphertext_and_nonce_unchanged':True,'recording_nonce_and_ciphertext_unchanged':True,'new_key_only_backup_verified':True,'missing_key_rejected':True}
elif operation in ['tamper','truncate']:
    path=root/'recordings'/((uuid_value('recording_id'))+'.ztrec');assert path.is_file() and not path.is_symlink()
    with path.open('r+b',buffering=0) as file:
        if operation=='tamper':
            file.seek(-1,2);byte=file.read(1);file.seek(-1,2);file.write(bytes([byte[0]^1]))
        else:file.truncate(path.stat().st_size-1)
        os.fsync(file.fileno())
    result={'mutated_owned_recording':operation}
elif operation=='retention':
    off();app_stop();recording_id=uuid_value('recording_id');kept_id=uuid_value('kept_id')
    sql("UPDATE recordings SET retention_until=clock_timestamp()-interval '1 day' WHERE id='"+recording_id+"'")
    maintenance('retain-recordings','new-key-maintenance.toml')
    assert sql("SELECT state FROM recordings WHERE id='"+recording_id+"'")=='expired'
    assert not (root/'recordings'/(recording_id+'.ztrec')).exists()
    assert (root/'recordings'/(kept_id+'.ztrec')).exists()
    assert sql("SELECT count(*) FROM connections WHERE id=(SELECT connection_id FROM recordings WHERE id='"+recording_id+"')")=='1'
    assert int(sql("SELECT count(*) FROM audit_events WHERE action='recording.finalized'"))>0
    app_up();result={'expired_file_removed':True,'unexpired_file_kept':True,'connection_and_audit_history_kept':True}
else:raise RuntimeError('unknown controlled fixture operation')
print(json.dumps(result))
