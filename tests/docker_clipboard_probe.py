#!/usr/bin/env python3
"""Read/set synthetic target evidence only inside one owned clipboard fixture."""
import json,re,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();assert root.parent==Path('/var/tmp') and re.fullmatch('zt-guac-v2-[a-z0-9-]+',root.name)
fixture=json.loads((root/'browser-fixture.json').read_text());assert fixture['server_id']==root.name
target=fixture['target_container_id'];assert re.fullmatch('[0-9a-f]{64}',target)
row=json.loads(subprocess.check_output(['docker','inspect',target],text=True))[0]
assert row['Config']['Labels']['com.docker.compose.project']==root.name and row['Config']['Labels']['com.docker.compose.service']=='target'
request=json.loads(sys.stdin.read());action=request['action']
if action=='file':
    name=request['path'];assert re.fullmatch('/tmp/ztclip-[a-f0-9]+',name)
    result=subprocess.run(['docker','exec',target,'cat',name],capture_output=True,timeout=10)
    print(json.dumps({'found':result.returncode==0,'text':result.stdout.decode('utf8') if result.returncode==0 else None}))
else:
    display={'rdp':':10','vnc-none':':99','vnc-password':':100'}[request['profile']]
    command=['docker','exec','-i','--user','fixture' if request['profile']=='rdp' else 'root','-e','DISPLAY='+display]
    if request['profile']=='rdp':command+=['-e','XAUTHORITY=/home/fixture/.Xauthority']
    command+=[target,'xclip','-selection','clipboard']
    if action=='read':
        result=subprocess.run(command+['-out','-target','UTF8_STRING'],capture_output=True,timeout=10)
        print(json.dumps({'ok':result.returncode==0,'text':result.stdout.decode('utf8') if result.returncode==0 else None}))
    elif action=='set':
        assert len(request['text'].encode())<=256*1024
        subprocess.run(command+['-in','-target','UTF8_STRING'],input=request['text'].encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
        print(json.dumps({'set':True}))
    else:raise RuntimeError('unknown synthetic clipboard probe')
