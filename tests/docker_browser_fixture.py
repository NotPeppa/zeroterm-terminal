#!/usr/bin/env python3
"""Create/stop a disposable real-protocol HTTPS fixture; never operate on old projects."""
import argparse,hashlib,http.cookiejar,ipaddress,json,os,re,secrets,shutil,socket,ssl,subprocess,time,urllib.error,urllib.request,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('action',choices=['start','stop'])
parser.add_argument('--directory',required=True)
parser.add_argument('--app-image')
parser.add_argument('--engine-image')
parser.add_argument('--target-image')
parser.add_argument('--subnet-offset',type=int,default=0,help='offset the three fixed fixture subnets to test alongside a live deployment')
parser.add_argument('--recording-fault-library',help='test-only preload library; enables a bounded 512 MiB recording filesystem')
args=parser.parse_args()
assert 0<=args.subnet_offset<=160
root=Path(args.directory).resolve()
assert str(root).startswith('/var/tmp/zt-guac-v2-') and root.parent==Path('/var/tmp')
root.mkdir(mode=0o700,exist_ok=True)
project=root.name
assert re.fullmatch(r'zt-guac-v2-[a-z0-9-]+',project)
def run(*command,**kwargs):return subprocess.run(command,check=True,text=True,**kwargs)
def output(*command):return subprocess.check_output(command,text=True).strip()
def old():
    return {row['ID']:row['Names'] for row in map(json.loads,output('docker','ps','--format','{{json .}}').splitlines()) if row['Names'].startswith('zeroterm-test-')}
def dc(*command,**kwargs):return run('docker','compose','-p',project,'-f',str(root/'compose.yaml' if (root/'compose.yaml').exists() else ROOT/'compose.yaml'),'-f',str(root/'override.json'),*command,env=env,cwd=ROOT,**kwargs)
if args.action=='stop':
    fixture=json.loads((root/'browser-fixture.json').read_text())
    assert fixture['server_id']==project
    env=dict(os.environ,BASTION_HTTPS_PORT='127.0.0.1:'+str(fixture['port']),GUACD_IMAGE=fixture['engine_image_id'],BASTION_IMAGE=fixture['application_image_id'])
    ids=output('docker','ps','-aq','--filter','label=com.docker.compose.project='+project).splitlines()
    for identity in ids:
        row=json.loads(output('docker','inspect',identity))[0]
        assert row['Config']['Labels']['com.docker.compose.project']==project
    if (root/'egress-installed').exists():run('python3',str(ROOT/'deploy/guacd/egress.py'),'remove',project)
    restored=project+'-restored-postgres'
    owned=run('docker','ps','-aq','--filter','name=^'+restored+'$',capture_output=True).stdout.strip()
    if owned:
        row=json.loads(output('docker','inspect',owned))[0]
        assert row['Name']=='/'+restored and row['Config']['Labels'].get('zeroterm.acceptance')==project
        run('docker','rm','-f','-v',owned)
    dc('down','--volumes','--remove-orphans')
    if (root/'recording-filesystem').exists():
        assert (root/'recordings').resolve().parent==root
        run('umount',str(root/'recordings'))
        (root/'recording-filesystem').unlink()
    assert old()==json.loads((root/'original.json').read_text())
    print('Owned browser fixture removed; original containers unchanged')
    raise SystemExit(0)
assert args.app_image and args.engine_image and args.target_image
assert not (root/'browser-fixture.json').exists(),'fixture already exists'
(root/'original.json').write_text(json.dumps(old()))
net_ids=output('docker','network','ls','-q').split()
for network in json.loads(output('docker','network','inspect',*net_ids)):
    for config in network['IPAM']['Config'] or []:
        if 'Subnet' not in config:continue
        occupied=ipaddress.ip_network(config['Subnet'])
        for required in (f'172.30.{61+args.subnet_offset}.0/29',f'172.30.{62+args.subnet_offset}.0/24',f'172.30.{63+args.subnet_offset}.0/29'):
            if occupied.version==4:assert not occupied.overlaps(ipaddress.ip_network(required)),'fixture CIDR is already occupied'
with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
origin='https://localhost:'+str(port)
engine=output('docker','image','inspect',args.engine_image,'--format','{{.Id}}')
assert re.fullmatch(r'sha256:[0-9a-f]{64}',engine)
certs=root/'certs';certs.mkdir(mode=0o755)
for name,subject,san in [('proxy','localhost','DNS:localhost'),('leaf','fixture-target','DNS:fixture-target')]:
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN='+subject,'-addext','subjectAltName='+san,'-keyout',str(certs/(name+'.key')),'-out',str(certs/(name+'.pem')),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
pin=hashlib.sha256(subprocess.check_output(['openssl','x509','-in',str(certs/'leaf.pem'),'-outform','DER'])).hexdigest()
production=(ROOT/'config/production.example.toml').read_text().replace('replace-with-stable-server-id',project).replace('https://bastion.example.invalid',origin).replace('rdp_strict_pin_verified = false','rdp_strict_pin_verified = true').replace('vnc_trusted_cidrs = []','vnc_trusted_cidrs = ["172.30.62.0/24"]').replace('allow = ["0.0.0.0/0", "::/0"]','allow = ["172.30.62.0/24"]')
if args.subnet_offset:
    for part in [61,62,63]:production=production.replace(f'172.30.{part}.',f'172.30.{part+args.subnet_offset}.')
if args.recording_fault_library:
    library=Path(args.recording_fault_library).resolve()
    assert library.is_file() and str(library).startswith('/var/tmp/zt-guac-v2-')
    fault=root/'fault';fault.mkdir(mode=0o755)
    shutil.copyfile(library,fault/'recording-fault.so');(fault/'recording-fault.so').chmod(0o555)
    (fault/'control').write_text('0 off\n');(fault/'control').chmod(0o644)
    (fault/'hits').touch();(fault/'hits').chmod(0o666)
    recordings=root/'recordings';recordings.mkdir(mode=0o700)
    assert shutil.disk_usage(root).free>2*1024*1024*1024
    disk=root/'recordings.ext4'
    with disk.open('xb') as file:file.truncate(512*1024*1024)
    disk.chmod(0o600)
    run('mkfs.ext4','-q','-F','-m','0',str(disk))
    run('mount','-t','ext4','-o','loop,nodev,nosuid,noexec',str(disk),str(recordings))
    os.chown(recordings,10001,10001);recordings.chmod(0o700)
    (root/'recording-filesystem').touch()
    production=production.replace('minimum_free_bytes = 1073741824','minimum_free_bytes = 268435456')
(root/'production.toml').write_text(production)
(root/'maintenance.toml').write_text(production.replace('/run/bastion-runtime/database-url','/run/bastion-db/database-url'))
nginx=(ROOT/'deploy/nginx.example.conf').read_text().replace('bastion.example.invalid','localhost')
nginx=nginx.replace('/etc/nginx/tls/bastion-chain.pem','/etc/nginx/tls/proxy.pem').replace('/etc/nginx/tls/bastion-key.pem','/etc/nginx/tls/proxy.key')
if args.subnet_offset:nginx=nginx.replace('172.30.63.',f'172.30.{63+args.subnet_offset}.')
(root/'nginx.conf').write_text(nginx)
for name in ('production.toml','maintenance.toml','nginx.conf'):(root/name).chmod(0o644)
database='zt_guac_v2_'+uuid.uuid4().hex[:12]
override={'configs':{'bastion_config':{'file':str(root/'production.toml')},'bastion_maintenance_config':{'file':str(root/'maintenance.toml')},'nginx_config':{'file':str(root/'nginx.conf')}},'services':{'bastion':{'image':args.app_image},'maintenance':{'image':args.app_image,'environment':{'BASTION_DATABASE_NAME':database}},'guacd':{'image':engine},'grant-runtime':{'environment':{'POSTGRES_DB':database}},'postgres':{'environment':{'POSTGRES_DB':database},'healthcheck':{'test':['CMD-SHELL','pg_isready -U bastion -d '+database]}},'proxy':{'volumes':[{'type':'bind','source':str(certs),'target':'/etc/nginx/tls','read_only':True,'bind':{'create_host_path':False}}]},'target':{'image':args.target_image,'networks':['app'],'volumes':[str(certs)+':/certs'],'shm_size':'32m','mem_limit':'192m','memswap_limit':'384m','cpus':0.5}}}
if args.subnet_offset:
    compose=(ROOT/'compose.yaml').read_text()
    for part in [61,62,63]:compose=compose.replace(f'172.30.{part}.',f'172.30.{part+args.subnet_offset}.')
    (root/'compose.yaml').write_text(compose)
if args.recording_fault_library:
    mount={'type':'bind','source':str(root/'recordings'),'target':'/var/lib/zeroterm-bastion/recordings','bind':{'create_host_path':False}}
    override['services']['bastion']['volumes']=[mount,{'type':'bind','source':str(root/'fault'),'target':'/fault','bind':{'create_host_path':False}}]
    override['services']['bastion']['environment']={'LD_PRELOAD':'/fault/recording-fault.so'}
    override['services']['maintenance']['volumes']=[mount]
(root/'override.json').write_text(json.dumps(override))
env=dict(os.environ,BASTION_HTTPS_PORT='127.0.0.1:'+str(port),GUACD_IMAGE=engine,BASTION_IMAGE=args.app_image)
(root/'browser-fixture.json').write_text(json.dumps({'server_id':project,'port':port,'engine_image_id':engine}))
(root/'browser-fixture.json').chmod(0o600)
dc('config','--quiet')
dc('run','--rm','--no-deps','-T','--entrypoint','sh','maintenance','/usr/local/share/zeroterm-bastion/docker-init.sh')
dc('up','-d','--wait','--wait-timeout','90','postgres','target')
dc('run','--rm','--no-deps','-T','maintenance','migrate','--config','/etc/zeroterm-bastion/maintenance.toml')
dc('exec','-T','postgres','sh',input=(ROOT/'deploy/docker-runtime-role.sh').read_text().replace('\r',''))
password=secrets.token_urlsafe(24)
dc('run','--rm','--no-deps','-T','maintenance','create-admin','--config','/etc/zeroterm-bastion/maintenance.toml','--username','admin','--password-stdin',input=password+'\n')
dc('up','-d','--wait','--wait-timeout','90','bastion','guacd')
run('python3',str(ROOT/'deploy/guacd/egress.py'),'install',project)
(root/'egress-installed').touch()
dc('up','-d','--wait','--wait-timeout','90','proxy')
browser=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(certs/'proxy.pem'))))
csrf=None
def request(path,body=None):
    headers={'Origin':origin}
    if csrf:headers['X-Bastion-CSRF']=csrf
    if body is not None:headers['Content-Type']='application/json'
    with browser.open(urllib.request.Request(origin+path,data=json.dumps(body).encode() if body is not None else None,headers=headers),timeout=15) as response:return json.load(response)
info=request('/api/v1/info');assert info['server_id']==project and all(info['features'][name] for name in ('web_ssh','web_rdp','web_vnc'))
csrf=request('/api/v1/auth/csrf')['csrf_token']
request('/api/v1/auth/login',{'username':'admin','password':password,'device_label':'fixture administration'})
target=dc('ps','-q','target',capture_output=True).stdout.strip()
for attempt in range(30):
    ready=subprocess.run(['docker','exec',target,'sh','-c','test -s /etc/ssh/ssh_host_ed25519_key.pub && test -S /tmp/.X11-unix/X100'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if ready.returncode==0:break
    time.sleep(1)
else:raise RuntimeError('real target fixture did not initialize')
host_key=' '.join(output('docker','exec',target,'cat','/etc/ssh/ssh_host_ed25519_key.pub').split()[:2])
private_key=output('docker','exec',target,'cat','/var/log/fixture/client-key')+'\n'
encrypted_key=output('docker','exec',target,'cat','/var/log/fixture/client-ed25519-encrypted')+'\n'
rsa=output('docker','exec',target,'cat','/var/log/fixture/client-rsa')+'\n'
rejected_asset=request('/api/v1/admin/assets',{'name':'rejected-rsa-input','protocol':'ssh','host':'target','port':22,'ssh_host_key':host_key})
try:
    request('/api/v1/admin/assets/'+rejected_asset['id']+'/accounts',{'label':'must-reject-rsa','username':'fixture','credential':{'type':'private_key','key_pem':rsa,'passphrase':None}})
    raise AssertionError('unsupported RSA key was accepted by the application')
except urllib.error.HTTPError as error:assert error.code==400
assert request('/api/v1/admin/assets/'+rejected_asset['id']+'/accounts')['items']==[]
profiles=[]
for label,protocol,remote_port,credential in [('ssh-password','ssh',22,{'type':'password','password':'fictional-Guac-pass-123'}),('ssh-private-key','ssh',22,{'type':'private_key','key_pem':private_key,'passphrase':None}),('ssh-encrypted-key','ssh',22,{'type':'private_key','key_pem':encrypted_key,'passphrase':'fictional-key-passphrase'}),('rdp-tls','rdp',3389,{'type':'password','password':'fictional-Guac-pass-123'}),('vnc-none','vnc',5901,{'type':'none'}),('vnc-password','vnc',5902,{'type':'password','password':'testpass'})]:
    data={'name':label,'protocol':protocol,'host':'target','port':remote_port,'tags':[]}
    if protocol=='ssh':data['ssh_host_key']=host_key
    if protocol=='rdp':data.update(security='tls',rdp_certificate_sha256=pin)
    asset=request('/api/v1/admin/assets',data)
    account=request('/api/v1/admin/assets/'+asset['id']+'/accounts',{'label':label,'username':'fixture' if protocol!='vnc' else None,'domain':None,'credential':credential})
    profiles.append({'label':label,'protocol':protocol,'asset_id':asset['id'],'account_id':account['id']})
public_key=subprocess.check_output(['openssl','x509','-in',str(certs/'proxy.pem'),'-pubkey','-noout'])
rdp_profile=next(profile for profile in profiles if profile['protocol']=='rdp')
capacity_rdp_profiles=[rdp_profile]
for username in ('fixture2','fixture3'):
    assert int(output('docker','exec',target,'id','-u',username))>=1000
    account=request('/api/v1/admin/assets/'+rdp_profile['asset_id']+'/accounts',{'label':'capacity-'+username,'username':username,'domain':None,'credential':{'type':'password','password':'fictional-Guac-pass-123'}})
    capacity_rdp_profiles.append(dict(rdp_profile,account_id=account['id'],label='rdp-'+username))
public_der=subprocess.check_output(['openssl','pkey','-pubin','-outform','DER'],input=public_key)
import base64
fixture={'server_id':project,'origin':origin,'port':port,'username':'admin','password':password,'profiles':profiles,'capacity_rdp_profiles':capacity_rdp_profiles,'engine_image_id':engine,'application_image_id':output('docker','image','inspect',args.app_image,'--format','{{.Id}}'),'target_container_id':target,'public_spki':base64.b64encode(hashlib.sha256(public_der).digest()).decode(),'production_ready':False,'windows_nla_verified':False,'native_os_ime_verified':False,'unsupported_rsa_rejected_before_storage':True,'recording_faults_enabled':bool(args.recording_fault_library)}
path=root/'browser-fixture.json';path.write_text(json.dumps(fixture,indent=2)+'\n');path.chmod(0o600)
assert old()==json.loads((root/'original.json').read_text())
print(json.dumps({'status':'ready','fixture_path':str(path),'origin':origin,'server_id':project}))
