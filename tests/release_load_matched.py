"""Four concurrent pinned direct SFTP streams on the live owned fixture only."""
import concurrent.futures, getpass, hashlib, json, os, subprocess, time
from pathlib import Path
ROOT=Path(os.environ['BASTION_RELEASE_LOAD_ROOT']).resolve()
assert os.geteuid()==1000 and ROOT.stat().st_uid==1000 and ROOT.stat().st_mode&0o777==0o700
runtime=json.loads((ROOT/'owned-runtime.json').read_text());fixture_root=Path(runtime['root']).resolve()
assert ROOT in fixture_root.parents
fixture=json.loads((fixture_root/'fixture.json').read_text());port=runtime['ports']['A'];assert port!=22
args=['sftp','-B','32768','-F','/dev/null','-q','-i',str(fixture_root/'target-user'),'-P',str(port),'-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={fixture_root/"known_hosts"}','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-b']
label=f'matched-direct-{time.time_ns()}'
files=[{**file,'remote':str(fixture_root/f'{label}-{i}.bin'),'download':str(fixture_root/f'{label}-{i}.download')} for i,file in enumerate(fixture['files'])]
reports={}
def flow(direction,index,file):
    batch=fixture_root/f'{label}-{direction}-{index}.batch';batch.write_text((f'put "{file["local"]}" "{file["remote"]}"\n' if direction=='upload' else f'get "{file["remote"]}" "{file["download"]}"\n'));batch.chmod(0o600)
    log=fixture_root/f'{label}-{direction}-{index}.log'
    start=time.monotonic_ns()
    with log.open('wb') as output:
        log.chmod(0o600);subprocess.run([*args,str(batch),f'{getpass.getuser()}@127.0.0.1'],stdout=output,stderr=output,check=True,timeout=600)
    end=time.monotonic_ns()
    return {'index':index,'bytes':file['size'],'first_started_monotonic_ns':start,'last_finished_monotonic_ns':end}
try:
    def pair(item):
        index,file=item
        return {direction:flow(direction,index,file) for direction in ['upload','download']}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pairs=list(pool.map(pair,enumerate(files)))
    for direction in ['upload','download']:
        samples=[item[direction] for item in pairs]
        start=min(row['first_started_monotonic_ns'] for row in samples);end=max(row['last_finished_monotonic_ns'] for row in samples);total=sum(row['bytes'] for row in samples)
        reports[direction]={'flows':samples,'total_bytes':total,'first_started_monotonic_ns':start,'last_finished_monotonic_ns':end,'wall_seconds':(end-start)/1e9,'bytes_per_second':total*1e9/(end-start)}
    def digest(path):
        value=hashlib.sha256()
        with Path(path).open('rb') as source:
            while block:=source.read(32768):value.update(block)
        return value.hexdigest()
    hashes=[{'index':index,'bytes':file['size'],'expected_sha256':file['sha256'],'source_sha256':digest(file['local']),'remote_sha256':digest(file['remote']),'download_sha256':digest(file['download'])} for index,file in enumerate(files)]
    assert all(row['expected_sha256']==row['source_sha256']==row['remote_sha256']==row['download_sha256'] for row in hashes)
    result={'stage':'completed','concurrency':4,'chunk_bytes':32768,'target_port':port,'source_archive_sha256':fixture['source_archive_sha256'],'hashes':hashes,**reports,'method':'total bytes divided by first-start to last-finish wallclock, default native OpenSSH request pipelining'}
    path=ROOT/'matched-direct-baseline4.json';path.write_text(json.dumps(result,indent=2)+'\n');path.chmod(0o600)
    print(json.dumps({'stage':'completed',**{key:reports[key] for key in ['upload','download']}}))
finally:
    for file in files:
        for key in ['remote','download']:
            path=Path(file[key]).resolve();assert path.parent==fixture_root and path.name.startswith(label)
            path.unlink(missing_ok=True)
