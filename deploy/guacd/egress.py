#!/usr/bin/env python3
"""Host-root, narrowly project-scoped egress rules. Never flush global chains."""
import hashlib
import ipaddress
import json
import re
import subprocess
import sys

operation, project = sys.argv[1:]
assert operation in ('install', 'remove')
assert re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', project)
chain = 'ZTGUAC_' + hashlib.sha256(project.encode()).hexdigest()[:12]

def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)

def ipt(*args, check=True):
    return run('iptables', '-w', '10', *args, check=check)

ids = run('docker', 'ps', '-aq' if operation == 'remove' else '-q', '--filter', f'label=com.docker.compose.project={project}').stdout.split()
containers = json.loads(run('docker', 'inspect', *ids).stdout) if ids else []
services = {c['Config']['Labels'].get('com.docker.compose.service'): c for c in containers}
assert 'guacd' in services and 'bastion' in services, 'exact project containers required for rule ownership'
networks = services['guacd']['NetworkSettings']['Networks']
assert len(networks) == 1, 'guacd must have exactly one isolated network'
network, info = next(iter(networks.items()))
assert network in services['bastion']['NetworkSettings']['Networks']
def address(endpoint):
    # A stopped container loses its runtime IP; Compose's explicit assignment remains.
    assigned = endpoint.get('IPAddress') or (endpoint.get('IPAMConfig') or {}).get('IPv4Address')
    assert assigned, 'exact project-owned network address required'
    return str(ipaddress.IPv4Address(assigned))
guacd = address(info)
app = address(services['bastion']['NetworkSettings']['Networks'][network])
assert guacd != app and not info.get('GlobalIPv6Address'), 'IPv6 guacd egress is not supported'
assert json.loads(run('docker', 'network', 'inspect', network).stdout)[0]['Internal']
forward = ['-s', guacd+'/32', '-j', chain]
host = ['-s', guacd+'/32', '-m', 'comment', '--comment', chain, '-j', 'DROP']
if operation == 'install':
    assert ipt('-L', chain, check=False).returncode != 0, 'rules already exist; no overwrite'
    ipt('-N', chain)
    ipt('-A', chain, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
    ipt('-A', chain, '-d', app+'/32', '-p', 'tcp', '--dport', '32768:60999', '-j', 'ACCEPT')
    ipt('-A', chain, '-j', 'DROP')
    ipt('-I', 'DOCKER-USER', '1', *forward)
    ipt('-I', 'INPUT', '1', *host)
else:
    if ipt('-C', 'DOCKER-USER', *forward, check=False).returncode == 0:
        ipt('-D', 'DOCKER-USER', *forward)
    if ipt('-C', 'INPUT', *host, check=False).returncode == 0:
        ipt('-D', 'INPUT', *host)
    # Only this exact, hash-named project-owned chain is flushed/deleted.
    ipt('-F', chain)
    ipt('-X', chain)
print(json.dumps({'operation': operation, 'project': project, 'chain': chain,
    'guacd': guacd, 'app': app, 'allowed_tcp_ports': '32768:60999'}))
