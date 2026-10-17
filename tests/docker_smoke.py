#!/usr/bin/env python3
"""Fresh family-2 deployment smoke; isolated volumes, no legacy conversion/native fixtures."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--image', help='use an already built candidate app image')
parser.add_argument('--engine-image', default='zeroterm-guacd:1.6.0-strict-pin')
args = parser.parse_args()
project = 'zt-guac-v2-'+str(uuid.uuid4())
root = Path('/var/tmp')/project
root.mkdir(mode=0o700)
certs = root/'tls'; certs.mkdir(mode=0o700)
with socket.socket() as sock:
    sock.bind(('127.0.0.1',0)); https_port=sock.getsockname()[1]
origin = f'https://localhost:{https_port}'
database = 'zt_guac_v2_'+uuid.uuid4().hex[:12]
config = '/etc/zeroterm-bastion/production.toml'
maintenance = '/etc/zeroterm-bastion/maintenance.toml'
image = args.image or project+':app'
production = (ROOT/'config/production.example.toml').read_text().replace('replace-with-stable-server-id',project).replace('https://bastion.example.invalid',origin)
(root/'production.toml').write_text(production)
(root/'maintenance.toml').write_text(production.replace('/run/bastion-runtime/database-url','/run/bastion-db/database-url'))
(root/'nginx.conf').write_text((ROOT/'deploy/nginx.example.conf').read_text().replace('bastion.example.invalid','localhost'))
for name in ('production.toml','maintenance.toml','nginx.conf'): (root/name).chmod(0o644)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
    '-addext','subjectAltName=DNS:localhost','-keyout',str(certs/'bastion-key.pem'),'-out',str(certs/'bastion-chain.pem')],
    check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
override = {
    'configs':{'bastion_config':{'file':str(root/'production.toml')},
        'bastion_maintenance_config':{'file':str(root/'maintenance.toml')},'nginx_config':{'file':str(root/'nginx.conf')}},
    'services':{'bastion':{'image':image},'maintenance':{'image':image,'environment':{'BASTION_DATABASE_NAME':database}},
        'guacd':{'image':args.engine_image},
        'postgres':{'environment':{'POSTGRES_DB':database},
            'healthcheck':{'test':['CMD-SHELL',f'pg_isready -U bastion -d {database}']}},
        'proxy':{'volumes':[{'type':'bind','source':str(certs),'target':'/etc/nginx/tls','read_only':True,
            'bind':{'create_host_path':False}}]}},
}
(root/'override.json').write_text(json.dumps(override))
compose = ['docker','compose','-p',project,'-f',str(ROOT/'compose.yaml'),'-f',str(root/'override.json')]
engine_id = subprocess.check_output(['docker','image','inspect',args.engine_image,'--format','{{.Id}}'],text=True).strip()
assert re.fullmatch(r'sha256:[0-9a-f]{64}',engine_id)
env = dict(os.environ,BASTION_HTTPS_PORT=f'127.0.0.1:{https_port}',CARGO_BUILD_JOBS='1',GUACD_IMAGE=engine_id)

def dc(*command,check=True,**kwargs):
    return subprocess.run(compose+list(command),env=env,cwd=ROOT,check=check,text=True,**kwargs)

browser = urllib.request.build_opener(urllib.request.ProxyHandler({}),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(certs/'bastion-chain.pem'))))
csrf = None

def request(path,body=None):
    headers={'Origin':origin}
    if csrf: headers['X-Bastion-CSRF']=csrf
    if body is not None: headers['Content-Type']='application/json'
    return browser.open(urllib.request.Request(origin+path,
        data=json.dumps(body).encode() if body is not None else None,headers=headers),timeout=10)

def existing_containers():
    rows=subprocess.check_output(['docker','ps','--format','{{json .}}'],text=True).splitlines()
    return {row['ID']:row['Names'] for row in map(json.loads,rows) if row['Names'].startswith('zeroterm-test-')}
original_containers=existing_containers()
installed=False
result={'production_ready':False,'project':project,'database':database,'engine_image_id':engine_id,
    'target_protocol_acceptance':False,'windows_nla_verified':False,'browser_canvas_ime_verified':False}
try:
    dc('config','--quiet')
    if not args.image: dc('build','bastion')
    # The strict engine must already be separately built/tested; no fallback to stock.
    subprocess.run(['docker','image','inspect',args.engine_image],check=True,stdout=subprocess.DEVNULL)
    dc('run','--rm','--no-deps','-T','--entrypoint','sh','maintenance','/usr/local/share/zeroterm-bastion/docker-init.sh')
    duplicate=dc('run','--rm','--no-deps','-T','--entrypoint','sh','maintenance','/usr/local/share/zeroterm-bastion/docker-init.sh',
        check=False,capture_output=True)
    assert duplicate.returncode != 0 and 'refusing to overwrite' in duplicate.stderr
    dc('run','--rm','--no-deps','-T','--entrypoint','sh','maintenance','-eu','-c',
        'test "$(id -u)" = 10001; test "$(stat -c %a /etc/zeroterm-bastion/secrets)" = 700; '
        'test "$(stat -c %a /etc/zeroterm-bastion/secrets/kek-v1)" = 600; '
        'test ! -e /etc/zeroterm-bastion/secrets/api-token; test ! -e /etc/zeroterm-bastion/secrets/ssh_host_ed25519_key; '
        'test "$(cat /run/bastion-db/password)" != "$(cat /run/bastion-runtime/password)"')
    dc('up','-d','--wait','--wait-timeout','90','postgres')
    dc('run','--rm','--no-deps','-T','maintenance','migrate','--config',maintenance)
    dc('run','--rm','--no-deps','-T','maintenance','migrate','--config',maintenance)
    dc('exec','-T','postgres','sh',input=(ROOT/'deploy/docker-runtime-role.sh').read_text().replace('\r',''))
    rights=dc('exec','-T','postgres','psql','-X','-U','bastion','-d',database,'-At','-c',
        "SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication "
        "AND NOT rolbypassrls AND NOT rolinherit AND NOT has_schema_privilege(rolname,'public','CREATE') "
        "AND NOT has_table_privilege(rolname,'audit_events','UPDATE') "
        "AND NOT has_table_privilege(rolname,'audit_events','DELETE') "
        "FROM pg_roles WHERE rolname='bastion_runtime'",capture_output=True)
    assert rights.stdout.strip()=='t'
    dc('run','--rm','--no-deps','-T','maintenance','create-admin','--config',maintenance,'--username','admin','--password-stdin',
        input='fictional-deployment-password-123\n')
    dc('up','-d','--wait','--wait-timeout','90','bastion','guacd')
    subprocess.run(['python3',str(ROOT/'deploy/guacd/egress.py'),'install',project],check=True)
    installed=True
    dc('up','-d','--wait','--wait-timeout','90','proxy')
    with request('/health/ready') as response: assert response.read()==b'ok'
    with request('/api/v1/info') as response: info=json.load(response)
    assert info['schema_version']==2 and info['protocol_version']==2
    assert info['server_id']==project, 'refusing to authenticate against any other service'
    assert info['stream_protocol']=='bastion.guac.v1' and info['production_ready'] is False
    assert not info['features']['web_rdp'] and not info['features']['web_vnc'], 'unverified features advertised'
    assert 'gateway' not in info and 'native' not in json.dumps(info).lower()
    assert info['recording']['available'] and info['recording']['required']
    try:
        dc('exec','-T','bastion','chmod','0500','/var/lib/zeroterm-bastion/recordings')
        with request('/api/v1/info') as response: degraded_info=json.load(response)
        assert degraded_info['recording']['available'] is False
        assert not any(degraded_info['features'][feature] for feature in ('web_ssh','web_rdp','web_vnc'))
        assert degraded_info['features']['recording_replay'] is False
        try: request('/health/ready'); raise AssertionError('unwritable recording directory stayed ready')
        except urllib.error.HTTPError as error: assert error.code==503, error.code
    finally:
        dc('exec','-T','bastion','chmod','0700','/var/lib/zeroterm-bastion/recordings')
    with request('/health/ready') as response: assert response.read()==b'ok'
    with request('/api/v1/info') as response: restored_info=json.load(response)
    assert restored_info['recording']['available'] is True
    assert restored_info['features']['recording_replay'] is True
    assert all(restored_info['features'][feature]==info['features'][feature] for feature in ('web_ssh','web_rdp','web_vnc'))
    result['recording_directory_degradation_verified']={'info_unavailable':degraded_info,'health_unready':503,'restored':True}
    with request('/') as response: html=response.read().decode()
    for path in re.findall(r'(?:src|href)="([^\"]+\.js)"',html):
        if path.startswith('/'):
            with request(path) as response: assert response.read()
    with request('/api/v1/auth/csrf') as response: csrf=json.load(response)['csrf_token']
    with request('/api/v1/auth/login',{'username':'admin','password':'fictional-deployment-password-123','device_label':'Guac v2 smoke'}) as response:
        cookies=response.headers.get_all('Set-Cookie',[])
        assert any('HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=Strict' in cookie for cookie in cookies)
        body=json.load(response); assert 'access_token' not in body and 'refresh_token' not in body
    with request('/api/v1/me') as response: assert json.load(response)['user']['username']=='admin'
    for path in ('/api/v1/connection-tickets','/api/v1/files','/api/v1/channels','/api/v1/copy-jobs'):
        try:
            request(path,{})
        except urllib.error.HTTPError as error: assert error.code in (404,405), (path,error.code)
        else: raise AssertionError('retired route is still active: '+path)
    dc('exec','-T','bastion','sh','-eu','-c',
        'test "$(id -u)" = 10001; test ! -e /run/bastion-db/password; '
        'test ! -w /etc/zeroterm-bastion/secrets/kek-v1; '
        'test ! -e /etc/zeroterm-bastion/secrets/api-token; '
        'test ! -e /etc/zeroterm-bastion/secrets/ssh_host_ed25519_key')
    bastion_id=dc('ps','-q','bastion',capture_output=True).stdout.strip()
    inspected=json.loads(subprocess.check_output(['docker','inspect',bastion_id],text=True))[0]
    assert inspected['HostConfig']['ReadonlyRootfs'] and 'ALL' in inspected['HostConfig']['CapDrop']
    assert not inspected['NetworkSettings']['Ports']
    proxy_id=dc('ps','-q','proxy',capture_output=True).stdout.strip()
    proxy=json.loads(subprocess.check_output(['docker','inspect',proxy_id],text=True))[0]
    assert {port for port,bindings in proxy['NetworkSettings']['Ports'].items() if bindings}=={'443/tcp'}
    assert set(proxy['NetworkSettings']['Networks'])=={project+'_ingress'}
    spoofed=dc('exec','-T','bastion','curl','--silent','--output','/dev/null','--write-out','%{http_code}',
        '-H','X-Forwarded-For: 192.0.2.10','-H','X-Forwarded-Proto: https','http://172.30.63.2:8080/api/v1/info',capture_output=True).stdout
    assert spoofed=='403', 'untrusted source spoofed TLS proxy headers'
    result['independent_proxy_namespace_and_untrusted_forwarding_denied']=True
    result.update(status='passed-deployment-smoke',info=info)
except BaseException as error:
    result.update(status='failed',error=str(error)); dc('logs','--no-color','--tail','80',check=False)
    raise
finally:
    if installed: subprocess.run(['python3',str(ROOT/'deploy/guacd/egress.py'),'remove',project],check=True)
    dc('down','--volumes','--remove-orphans',check=False)
    result['existing_test_containers_unchanged']=existing_containers()==original_containers
    (root/'deployment-evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    assert result['existing_test_containers_unchanged'], 'existing zeroterm-test containers changed'
print(json.dumps(result,indent=2))
