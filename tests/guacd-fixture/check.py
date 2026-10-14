#!/usr/bin/env python3
"""Run inside the isolated app namespace, against real guacd via one-use bridges."""
import base64
import codecs
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import ssl
import threading
import time

APP = os.environ['APP_IP']
GUACD = os.environ['GUACD_IP']
TARGET = os.environ['TARGET_IP']
PIN = os.environ['LEAF_PIN']
PASSWORD = 'fictional-Guac-pass-123'

class Wire:
    def __init__(self, connection):
        self.socket = connection
        self.buffer = ''
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
    def send(self, *args):
        self.socket.sendall((','.join(str(len(a))+'.'+a for a in args)+';').encode())
    def read(self):
        while True:
            values, offset = [], 0
            while True:
                dot = self.buffer.find('.', offset)
                if dot == -1: break
                length = int(self.buffer[offset:dot])
                end = dot+1+length
                if end >= len(self.buffer): break
                values.append(self.buffer[dot+1:end])
                delimiter = self.buffer[end]
                assert delimiter in ',;'
                offset = end+1
                if delimiter == ';':
                    self.buffer = self.buffer[offset:]
                    return values
            data = self.socket.recv(32768)
            if not data: raise EOFError()
            self.buffer += self.decoder.decode(data)
            assert len(self.buffer) < 8*1024*1024

def listener():
    sock = socket.socket()
    sock.bind((APP, 0))
    sock.listen(1)
    sock.settimeout(15)
    assert 32768 <= sock.getsockname()[1] <= 60999
    return sock

def bridge(port):
    sock = listener()
    state = {'accepts': 0, 'source': None, 'errors': [], 'to_target':0, 'from_target':0}
    def serve():
        try:
            conn, peer = sock.accept()
            state['accepts'] += 1
            state['source'] = peer[0]
            assert peer[0] == GUACD
            sock.close() # exact one accept, before upstream connect
            with conn, socket.create_connection((TARGET, port), timeout=10) as target:
                conn.settimeout(None); target.settimeout(None)
                while True:
                    readable, _, _ = select.select([conn,target],[],[],30)
                    if not readable: break
                    for incoming in readable:
                        data = incoming.recv(32768)
                        if not data: return
                        state['to_target' if incoming is conn else 'from_target'] += len(data)
                        (target if incoming is conn else conn).sendall(data)
        except Exception as error:
            state['errors'].append(str(error))
        finally:
            sock.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return sock.getsockname()[1] if sock.fileno() >= 0 else state.get('port'), state, thread

def connect(protocol, port, extra):
    conn = socket.create_connection((GUACD, 4822), timeout=10)
    conn.settimeout(15)
    wire = Wire(conn)
    wire.send('select', protocol)
    args = wire.read()
    assert args[0] == 'args'
    version, names = args[1], args[2:]
    values = {'hostname': APP, 'port': str(port), 'username': 'fixture', 'password': PASSWORD,
        'security': 'tls', 'zt-strict-cert-pin': PIN, 'zt-target-ready':'true', 'zt-ssh-display-only':'true', 'width': '1024', 'height': '768',
        'dpi': '96', 'disable-audio': 'true', 'disable-copy': 'true', 'disable-paste': 'true',
        'enable-sftp': 'false', 'enable-drive': 'false', 'enable-printing': 'false',
        'resize-method': 'none', 'ignore-cert': 'false', 'cert-tofu': 'false'}
    values.update(extra)
    assert 'zt-target-ready' in names, 'stock guacd lacks explicit target interactive startup evidence'
    if protocol == 'ssh': assert 'zt-ssh-display-only' in names, 'SSH engine still exposes forbidden parameter streams'
    if protocol == 'rdp': assert 'zt-strict-cert-pin' in names, 'stock guacd cannot pass strict pin gate'
    wire.send('size','1024','768','96'); wire.send('audio'); wire.send('video'); wire.send('image','image/png')
    wire.send('connect', version, *[values.get(name,'') for name in names])
    return wire

def observe(wire, expect_display, seconds=15, diagnostic=False):
    deadline = time.monotonic()+seconds
    seen = []
    desktop_images = {}
    try:
        while time.monotonic() < deadline:
            instruction = wire.read()
            opcode = instruction[0]
            seen.append(opcode)
            assert opcode != 'argv', 'engine exposed a forbidden parameter stream'
            if opcode == 'sync': wire.send(*instruction)
            if opcode == 'zt-target-ready':
                assert len(instruction)==1 and (expect_display or diagnostic), 'rejected target emitted success marker'
            if (expect_display or diagnostic) and 'zt-target-ready' in seen:
                paint = (opcode=='cfill' and int(instruction[2])>=0) or (opcode=='copy' and int(instruction[7])>=0)
                image_bytes = 0
                if opcode=='img' and int(instruction[3])>=0: desktop_images[instruction[1]]=bytearray()
                if opcode=='blob' and instruction[1] in desktop_images:
                    desktop_images[instruction[1]].extend(base64.b64decode(instruction[2],validate=True))
                    assert len(desktop_images[instruction[1]]) <= 8*1024*1024
                if opcode=='end' and instruction[1] in desktop_images:
                    image = desktop_images.pop(instruction[1])
                    assert image[:8]==b'\x89PNG\r\n\x1a\n', 'desktop stream is not an actual PNG'
                    paint=True; image_bytes=len(image)
                if paint:
                    return {'target_ready': True, 'display': True, 'post_marker_desktop_paint':opcode,
                        'desktop_image_bytes':image_bytes,'opcodes': sorted(set(seen))}
            if opcode == 'error':
                if expect_display: raise AssertionError('guacd startup error: '+repr(instruction))
                return {'rejected': True, 'opcodes': sorted(set(seen))}
    except (EOFError, TimeoutError, ConnectionError):
        if expect_display: raise
        return {'rejected': True, 'opcodes': sorted(set(seen))}
    finally:
        wire.socket.close()
    if not expect_display:
        return {'rejected':True,'no_target_ready':True,'opcodes':sorted(set(seen))}
    raise AssertionError('startup never produced expected display/error: '+repr(sorted(set(seen))))

results = {}
for name, protocol, port, extra in [
    ('ssh-password', 'ssh', 22, {}),
    ('ssh-ed25519-private-key', 'ssh',22,{'password':'','private-key':Path(os.environ['SSH_PRIVATE_KEY_FILE']).read_text()}),
    ('ssh-ed25519-encrypted', 'ssh',22,{'password':'','private-key':Path('/certs/client-ed25519-encrypted').read_text(),'passphrase':'fictional-key-passphrase'}),
    ('xrdp-tls', 'rdp', 3389, {}),
    ('vnc-none', 'vnc', 5901, {'username':'','password':''}),
    ('vnc-password', 'vnc', 5902, {'username':'','password':'testpass'}),
]:
    bridge_port, state, thread = bridge(port)
    if protocol == 'ssh':
        extra['host-key'] = '['+APP+']:'+str(bridge_port)+' '+os.environ['SSH_HOST_KEY']
    try:
        results[name] = observe(connect(protocol, bridge_port, extra), True)
    except BaseException:
        print('FAILED '+name+' bridge='+repr(state), file=__import__('sys').stderr)
        raise
    thread.join(3)
    assert state['accepts'] == 1 and state['source'] == GUACD
    results[name]['bridge'] = state

# TLS activation may expose a legal failed-password/logon UI, never OS-login proof.
port, state, thread = bridge(3389)
diagnostic = observe(connect('rdp',port,{'username':'badpassfixture','password':'intentionally-wrong-password'}),False,diagnostic=True)
thread.join(3)
diagnostic.update(target_ready='zt-target-ready' in diagnostic['opcodes'],os_login_success_not_inferred=True,bridge=state)
results['xrdp-tls-bad-password-diagnostic']=diagnostic

# Real xrdp wrong pin, with an unmistakable never-authenticate username.
port, state, thread = bridge(3389)
results['xrdp-wrong-pin'] = observe(connect('rdp', port,
    {'zt-strict-cert-pin':'0'*64, 'username':'negative-do-not-auth'}), False)
thread.join(3)
results['xrdp-wrong-pin']['bridge'] = state

# Real OpenSSH wrong key: authentication count is independently checked by host runner.
port, state, thread = bridge(22)
results['ssh-wrong-key'] = observe(connect('ssh', port,
    {'host-key':'['+APP+']:'+str(port)+' '+os.environ['SSH_WRONG_KEY']}), False)
thread.join(3)
results['ssh-wrong-key']['bridge'] = state

# Minimal real RDP X.224/TLS responder: count EVERY application byte on this same socket.
# Its CA is trusted inside guacd and CN/SAN match the bridge hostname.
for label, pin in [('rdp-wrong-pin-ca-valid','0'*64), ('rdp-match-pin-probe',PIN)]:
    server = listener()
    port = server.getsockname()[1]
    state = {'accepted':0, 'tls_established':False, 'application_bytes':0, 'source':None}
    def probe():
        try:
            conn, peer = server.accept()
            state['accepted'] += 1; state['source']=peer[0]
            assert peer[0] == GUACD
            server.close()
            with conn:
                conn.settimeout(10)
                head = conn.recv(4)
                assert len(head)==4 and head[:2]==b'\x03\x00'
                length = int.from_bytes(head[2:], 'big')
                payload = b''
                while len(payload)<length-4: payload += conn.recv(length-4-len(payload))
                conn.sendall(bytes.fromhex('030000130ed000001234000200080001000000'))
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain('/certs/leaf.pem','/certs/leaf.key')
                with context.wrap_socket(conn, server_side=True) as tls:
                    state['tls_established'] = True
                    try:
                        state['application_bytes'] = len(tls.recv(32768))
                    except (ssl.SSLError, TimeoutError, ConnectionError): pass
        except Exception as error: state['error']=str(error)
        finally: server.close()
    thread = threading.Thread(target=probe, daemon=True)
    thread.start()
    results[label] = observe(connect('rdp', port, {'zt-strict-cert-pin':pin}), False)
    thread.join(15)
    assert not thread.is_alive()
    assert state['accepted']==1 and state['source']==GUACD and state['tls_established'], state
    assert (state['application_bytes'] > 0) == (pin == PIN), state
    results[label]['same_socket_tls'] = state

# Real FreeRDP TLS peer sends an actual redirection PDU; source guard must reject it.
assert os.environ.get('REDIRECT_PORT'), 'real redirect-PDU fixture is required'
results['rdp-real-redirect-pdu'] = observe(connect('rdp',int(os.environ['REDIRECT_PORT']),{'disable-gfx':'true'}),False)

# Missing/invalid pin must fail before contacting even the one-use bridge.
for label, pin in [('rdp-missing-pin',''),('rdp-invalid-pin','sha256:'+PIN),('rdp-insecure-mode',PIN)]:
    server = listener()
    port = server.getsockname()[1]
    result = observe(connect('rdp',port,{'zt-strict-cert-pin':pin,
        **({'security':'rdp'} if label=='rdp-insecure-mode' else {})}), False)
    server.settimeout(0.3)
    try: server.accept(); raise AssertionError('bad pin/security reached target')
    except TimeoutError: pass
    finally: server.close()
    results[label] = result
# Every protocol rejects missing/false startup capability before target contact.
for protocol in ('ssh','rdp','vnc'):
    for flag in ('','false'):
        server = listener(); port = server.getsockname()[1]
        extra = {'zt-target-ready':flag}
        if protocol=='ssh': extra['host-key']='['+APP+']:'+str(port)+' '+os.environ['SSH_HOST_KEY']
        results[protocol+'-ready-flag-'+(flag or 'missing')] = observe(connect(protocol,port,extra),False)
        server.settimeout(0.3)
        try: server.accept(); raise AssertionError('bad ready capability reached target')
        except TimeoutError: pass
        finally: server.close()

for flag in ('','false'):
    server = listener(); port = server.getsockname()[1]
    results['ssh-display-only-'+(flag or 'missing')] = observe(connect('ssh',port,{
        'zt-ssh-display-only':flag,'host-key':'['+APP+']:'+str(port)+' '+os.environ['SSH_HOST_KEY']}),False)
    server.settimeout(0.3)
    try: server.accept(); raise AssertionError('bad SSH display-only capability reached target')
    except TimeoutError: pass
    finally: server.close()

print(json.dumps({'production_ready':False,'engine':'guacd 1.6.0 / FreeRDP 2.11.7 / zt-pin-v4-ssh-display-only',
    'windows_nla_verified':False,'results':results}, indent=2))
