#!/usr/bin/env python3
"""Compile the exact plugin digest helper; reject malformed pins and non-leaf pins."""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='zt-pin-unit-') as tmp:
    root = Path(tmp)
    for name in ('leaf', 'other'):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN='+name, '-keyout', str(root/(name+'.key')), '-out', str(root/(name+'.pem'))],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    der = subprocess.check_output(['openssl', 'x509', '-in', str(root/'leaf.pem'), '-outform', 'DER'])
    pin = hashlib.sha256(der).hexdigest()
    source = root/'test.c'
    source.write_text('''#include <assert.h>
#include <stdio.h>
#include "zt-strict-pin.h"
int main(int argc, char** argv) {
    assert(argc == 3); unsigned char pem[16384];
    FILE* f = fopen(argv[1], "rb"); assert(f);
    size_t n = fread(pem, 1, sizeof(pem), f); fclose(f);
    assert(zt_leaf_pin_matches(pem,n,argv[2]));
    assert(!zt_leaf_pin_matches(pem,n,NULL));
    assert(!zt_leaf_pin_matches(pem,n,""));
    assert(!zt_leaf_pin_matches(pem,n,"garbage"));
    assert(!zt_leaf_pin_matches(pem,n,"0000000000000000000000000000000000000000000000000000000000000000"));
    assert(!zt_leaf_pin_matches((const unsigned char*)"not PEM",7,argv[2]));
    assert(!zt_leaf_pin_matches(NULL,n,argv[2]));
    char uppercase[65]; memset(uppercase,'A',64); uppercase[64]=0;
    assert(!zt_leaf_pin_matches(pem,n,uppercase));
    return 0;
}
''')
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-I'+os.environ.get('ZT_PIN_INCLUDE', str(ROOT/'deploy/guacd')),
        str(source), '-o', str(root/'check'), '-lcrypto'], check=True)
    subprocess.run([str(root/'check'), str(root/'leaf.pem'), pin], check=True)
    (root/'chain.pem').write_bytes((root/'leaf.pem').read_bytes()+(root/'other.pem').read_bytes())
    subprocess.run([str(root/'check'), str(root/'chain.pem'), pin], check=True)
    wrong_leaf = subprocess.run([str(root/'check'), str(root/'other.pem'), pin], capture_output=True)
    assert wrong_leaf.returncode != 0, 'different leaf was accepted'
print('PASS exact DER digest, absent/invalid/wrong/uppercase pin, invalid PEM, leaf-first chain')
