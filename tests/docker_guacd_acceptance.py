#!/usr/bin/env python3
"""Isolated real-engine acceptance. Run on the authorized Docker host, never old projects."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--engine-image', default='zeroterm-guacd:1.6.0-strict-pin')
parser.add_argument('--project', default='zt-guac-v2-'+str(uuid.uuid4()))
parser.add_argument('--directory')
parser.add_argument('--builder', help='optional isolated BuildKit builder')
args = parser.parse_args()
assert re.fullmatch(r'zt-guac-v2-[a-z0-9-]+', args.project)
if args.builder: assert re.fullmatch(r'zt-guac-v2-[a-z0-9-]+', args.builder)
project = args.project
root = Path(args.directory or '/var/tmp/'+project).resolve()
assert str(root).startswith('/var/tmp/zt-guac-v2-') and root != Path('/var/tmp')
root.mkdir(mode=0o700, exist_ok=True)
certs = root/'certs'; certs.mkdir(exist_ok=True)

def run(*command, check=True, **kwargs):
    return subprocess.run(command, check=check, text=True, **kwargs)

def output(*command):
    return subprocess.check_output(command, text=True).strip()

# Snapshot old containers BEFORE doing anything; never operate on their names/project.
before = json.loads(output('docker','ps','--format','json').replace('\n',',').join(['[',']']))
old = {c['ID']:c['Names'] for c in before if c['Names'].startswith('zeroterm-test-')}
net_ids = output('docker','network','ls','-q').split()
networks = json.loads(output('docker','network','inspect',*net_ids))
occupied = [ipaddress.ip_network(cfg['Subnet']) for net in networks for cfg in (net['IPAM']['Config'] or []) if 'Subnet' in cfg]
subnet = next(ipaddress.ip_network(f'172.30.{n}.0/29') for n in range(61,255)
    if all(not ipaddress.ip_network(f'172.30.{n}.0/29').overlaps(other) for other in occupied if other.version==4))
app_subnet = next(ipaddress.ip_network(f'172.30.{n}.0/29') for n in range(61,255)
    if not ipaddress.ip_network(f'172.30.{n}.0/29').overlaps(subnet)
    and all(not ipaddress.ip_network(f'172.30.{n}.0/29').overlaps(other) for other in occupied if other.version==4))
app, guacd = str(subnet[2]), str(subnet[3])
for name, command in [
    ('ca', ['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=ZT-guac-test-CA',
        '-keyout',str(certs/'ca.key'),'-out',str(certs/'ca.pem')]),
    ('leaf', ['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+app,
        '-keyout',str(certs/'leaf.key'),'-out',str(certs/'leaf.csr')]),
]:
    run(*command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
(certs/'extensions').write_text('subjectAltName=IP:'+app+',DNS:'+app+'\nextendedKeyUsage=serverAuth\n')
run('openssl','x509','-req','-in',str(certs/'leaf.csr'),'-CA',str(certs/'ca.pem'),'-CAkey',str(certs/'ca.key'),
    '-CAcreateserial','-days','1','-extfile',str(certs/'extensions'),'-out',str(certs/'leaf.pem'),
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
run('openssl','verify','-CAfile',str(certs/'ca.pem'),'-verify_hostname',app,str(certs/'leaf.pem'))
run('openssl','verify','-CAfile',str(certs/'ca.pem'),'-verify_ip',app,str(certs/'leaf.pem'))
der = subprocess.check_output(['openssl','x509','-in',str(certs/'leaf.pem'),'-outform','DER'])
pin = hashlib.sha256(der).hexdigest()
fixture_image = project+':fixture'
redirect_image = project+':redirect-peer'
trust_image = project+':guacd-trusted'
# Only build independent project images; heavy compilation was --parallel 1 in engine Dockerfile.
build = ['docker','buildx','build','--builder',args.builder,'--load'] if args.builder else ['docker','build']
run(*build,'--progress','plain','--target','redirect-fixture','-t',redirect_image,
    '-f',str(ROOT/'deploy/guacd/Dockerfile'),str(ROOT))
run(*build,'--progress','plain','-t',fixture_image,'-f',str(ROOT/'tests/guacd-fixture/Dockerfile'),str(ROOT))
(root/'Dockerfile.trust').write_text(f'FROM {args.engine_image}\nUSER root\nCOPY certs/ca.pem /usr/local/share/ca-certificates/zt-test-ca.crt\nRUN update-ca-certificates\nUSER 10002:10002\n')
# The Docker driver can resolve the locally loaded candidate; this step only adds a test CA.
run('docker','build','--progress','plain','-t',trust_image,'-f',str(root/'Dockerfile.trust'),str(root))
config = {
    'services': {
        'bastion': {'image':fixture_image,'entrypoint':['sleep','infinity'],
            'networks':{'app':{},'guac_bridge':{'ipv4_address':app}},
            'volumes':[f'{ROOT}/tests/guacd-fixture:/checks:ro',f'{certs}:/certs:ro']},
        'guacd': {'image':trust_image,'networks':{'guac_bridge':{'ipv4_address':guacd}},
            'command':['-f','-b','0.0.0.0','-l','4822','-L','debug'], 'environment':{'WLOG_LEVEL':'INFO'},
            'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
            'tmpfs':['/tmp:uid=10002,gid=10002,mode=0700,size=16m']},
        'target': {'image':fixture_image,'networks':['app'],
            'volumes':[f'{certs}:/certs'], 'shm_size':'32m'},
    },
    'networks':{'app':{'ipam':{'config':[{'subnet':str(app_subnet)}]}},'guac_bridge':{'internal':True,'enable_ipv6':False,
        'ipam':{'config':[{'subnet':str(subnet)}]}}},
}
(root/'engine-compose.json').write_text(json.dumps(config))
dc = ['docker','compose','-p',project,'-f',str(root/'engine-compose.json')]
installed = False
redirect_process = None
redirect_name = project+'-redirect-probe'
result = {'production_ready':False,'project':project,'subnet':str(subnet),
    'engine_image':args.engine_image,'engine_image_id':output('docker','image','inspect',args.engine_image,'--format','{{.Id}}'),
    'test_guacd_image_id':output('docker','image','inspect',trust_image,'--format','{{.Id}}'),
    'test_only_trusted_ca':True,'resource_limitations':'heavy builds one job; /var/tmp not /tmp',
    'host_memory_kib':{line.split(':')[0]:int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:', 'SwapTotal:'))},
    'windows_nla_verified':False,'application_api_browser_recording_verified':False}
try:
    run(*dc,'up','-d')
    run('python3',str(ROOT/'deploy/guacd/egress.py'),'install',project)
    installed = True
    target_id = output(*dc,'ps','-q','target')
    target = json.loads(output('docker','inspect',target_id))[0]
    target_ip = target['NetworkSettings']['Networks'][project+'_app']['IPAddress']
    # Wait for ONLY these new fixture processes, not any old host services.
    for attempt in range(30):
        status = run(*dc,'exec','-T','target','sh','-c',
            'test -s /etc/ssh/ssh_host_ed25519_key.pub && ss -lnt | grep -q :3389 && ss -lnt | grep -q :5902',
            check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if status.returncode==0: break
        time.sleep(1)
    else: raise AssertionError('new three-protocol fixture did not become ready')
    host_key = output(*dc,'exec','-T','target','cat','/etc/ssh/ssh_host_ed25519_key.pub').split()
    wrong_key = output(*dc,'exec','-T','target','cat','/var/log/fixture/wrong-host-key.pub').split()
    client_key = certs/'ssh-client-key'
    client_key.write_text(output(*dc,'exec','-T','target','cat','/var/log/fixture/client-key')+'\n')
    client_key.chmod(0o600)
    for filename in ('client-ed25519-encrypted','client-rsa','client-rsa-encrypted'):
        keyfile=certs/filename
        keyfile.write_text(output(*dc,'exec','-T','target','cat','/var/log/fixture/'+filename)+'\n')
        keyfile.chmod(0o600)
    redirect_port = output(*dc,'exec','-T','bastion','python3','-c',
        'import socket;s=socket.socket();s.bind(("'+app+'",0));print(s.getsockname()[1]);s.close()')
    app_id = output(*dc,'ps','-q','bastion')
    with (root/'redirect-peer.stdout').open('w') as redirect_out, (root/'redirect-peer.stderr').open('w') as redirect_err:
        redirect_process = subprocess.Popen(['docker','run','--rm','--name',redirect_name,
            '--network','container:'+app_id,'--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--user','0:0','-v',str(certs)+':/certs:ro','--entrypoint','/usr/local/bin/zt-rdp-redirect-fixture',
            redirect_image,app,redirect_port,'/certs/leaf.pem','/certs/leaf.key',app],stdout=redirect_out,stderr=redirect_err)
    for attempt in range(50):
        if 'LISTENING' in (root/'redirect-peer.stdout').read_text(): break
        assert redirect_process.poll() is None, 'actual redirect-peer failed to start'
        time.sleep(0.1)
    else: raise AssertionError('actual redirect-peer did not listen')
    command = [*dc,'exec','-T']
    for name,value in {'APP_IP':app,'GUACD_IP':guacd,'TARGET_IP':target_ip,'LEAF_PIN':pin,'REDIRECT_PORT':redirect_port,'SSH_PRIVATE_KEY_FILE':'/certs/ssh-client-key',
        'SSH_HOST_KEY':' '.join(host_key[:2]),'SSH_WRONG_KEY':' '.join(wrong_key[:2])}.items():
        command += ['-e',name+'='+value]
    completed = run(*command,'bastion','python3','/checks/check.py',capture_output=True,check=False)
    (root/'engine-check.stdout').write_text(completed.stdout)
    (root/'engine-check.stderr').write_text(completed.stderr)
    assert completed.returncode==0, completed.stderr
    result['engine_checks'] = json.loads(completed.stdout)
    assert redirect_process.wait(timeout=15)==0, 'real redirect peer failed to send protocol PDU'
    redirect_rows = [json.loads(line) for line in (root/'redirect-peer.stdout').read_text().splitlines() if line.startswith('{')]
    assert redirect_rows and redirect_rows[-1]['redirect_sent'] and redirect_rows[-1]['primary_credentials_received']
    guac_log = output(*dc,'logs','--no-color','guacd')
    (root/'guacd-protocol.log').write_text(guac_log)
    assert 'ZeroTerm RDP redirect/reconnect denied' in guac_log, 'redirect was not rejected by protocol guard'
    result['real_redirect_pdu_denied_before_routing'] = redirect_rows[-1]
    ssh_log = output(*dc,'exec','-T','target','cat','/var/log/fixture/sshd.log')
    (root/'ssh-auth.log').write_text(ssh_log)
    assert ssh_log.count('Accepted password for fixture')==1, 'wrong SSH key sent authentication or positive missing'
    assert ssh_log.count('Accepted publickey for fixture')==2, 'real OpenSSH Ed25519 encrypted/plain private-key authentication missing'
    assert 'Failed password' not in ssh_log, 'unexpected target password authentication attempt'
    result['ssh_same_socket_no_auth_wrong_key'] = True
    rdp_log = output(*dc,'exec','-T','target','cat','/var/log/xrdp-sesman.log')
    (root/'xrdp-auth.log').write_text(rdp_log)
    assert 'negative-do-not-auth' not in rdp_log, 'wrong pin reached xrdp target authentication'
    assert '++ created session (access granted): username fixture' in rdp_log, 'xrdp positive lacks account authentication grant'
    assert 'Session started successfully for user fixture' in rdp_log, 'xrdp positive lacks OS session start'
    assert 'AUTHFAIL: user=badpassfixture' in rdp_log, 'TLS bad-password diagnostic lacks real account authentication failure'
    assert 'access granted): username badpassfixture' not in rdp_log and 'Session started successfully for user badpassfixture' not in rdp_log
    result['tls_marker_is_not_os_login']={'wrong_password_account_rejected':True,'new_os_session_started':False}
    result['xrdp_wrong_pin_no_auth'] = True
    # Egress checks execute in guacd network namespace using Python from a separate
    # disposable utility process; they DO NOT add a network to guacd.
    guac_id = output(*dc,'ps','-q','guacd')
    net = json.loads(output('docker','inspect',guac_id))[0]
    assert list(net['NetworkSettings']['Networks'])==[project+'_guac_bridge']
    assert not net['Mounts'] or all(m['Type']=='tmpfs' for m in net['Mounts'])
    canary = 'import socket,time;s=socket.socket();s.bind(("'+app+'",8080));s.listen(8);time.sleep(60)'
    run(*dc,'exec','-d','bastion','python3','-c',canary)
    for attempt in range(20):
        positive = run(*dc,'exec','-T','bastion','python3','-c',
            'import socket;s=socket.create_connection(("'+app+'",8080),timeout=1);s.close()',
            check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if positive.returncode==0: break
        time.sleep(0.1)
    else: raise AssertionError('app canary not listening; denial would be inconclusive')
    host_canary = socket.socket()
    host_canary.bind((str(subnet[1]),0)); host_canary.listen(8)
    host_port = host_canary.getsockname()[1]
    with socket.create_connection((str(subnet[1]),host_port),timeout=1): pass
    tests = {'app-live-canary':(app,8080), 'app-metrics':(app,9090), 'app-ssh':(app,2222),
        'target-ssh':(target_ip,22), 'target-rdp':(target_ip,3389), 'host-live-canary':(str(subnet[1]),host_port),
        'internet':('1.1.1.1',443)}
    probe = 'import socket,json; tests='+repr(tests)+'; results={};\nfor name,address in tests.items():\n try:\n  s=socket.create_connection(address,timeout=1);s.close();results[name]=True\n except OSError:results[name]=False\nprint(json.dumps(results));assert not any(results.values())'
    isolation = output('docker','run','--rm','--network','container:'+guac_id,'--cap-drop','ALL',
        '--entrypoint','python3',fixture_image,'-c',probe)
    result['egress_denials'] = json.loads(isolation)
    result['engine_image_id'] = output('docker','image','inspect',args.engine_image,'--format','{{.Id}}')
    result['status']='passed-engine-only'
except BaseException as error:
    result['status']='failed'; result['error']=str(error)
    run(*dc,'logs','--no-color','--tail','100',check=False)
    for log in ('/var/log/fixture/vnc-none.log','/var/log/fixture/vnc-password.log','/var/log/fixture/sshd.log','/var/log/xrdp-sesman.log'):
        captured = run(*dc,'exec','-T','target','cat',log,check=False,capture_output=True)
        (root/('failed-'+Path(log).name)).write_text(captured.stdout+captured.stderr)
    raise
finally:
    if redirect_process is not None:
        if redirect_process.poll() is None:
            run('docker','rm','--force',redirect_name,check=False)
        redirect_process.wait(timeout=15)
    # Remove ONLY rules owned by this project before removing its containers.
    if installed: run('python3',str(ROOT/'deploy/guacd/egress.py'),'remove',project,check=False)
    run(*dc,'down','--volumes','--remove-orphans',check=False)
    after = json.loads(output('docker','ps','--format','json').replace('\n',',').join(['[',']']))
    current = {c['ID']:c['Names'] for c in after if c['Names'].startswith('zeroterm-test-')}
    result['existing_test_containers_unchanged'] = current==old
    (root/'evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    assert current==old, 'existing zeroterm-test containers changed during isolated test'
print(json.dumps(result,indent=2))
