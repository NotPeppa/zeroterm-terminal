#!/usr/bin/env python3
"""Minimal immutable-tag guard: never parse redirect PDU or attempt redirect/reconnect."""
from pathlib import Path
import sys
root = Path(sys.argv[1])
for file, signature, denied in [
    ('libfreerdp/core/redirection.c', 'int rdp_recv_enhanced_security_redirection_packet(rdpRdp* rdp, wStream* s)', '-1'),
    ('libfreerdp/core/connection.c', 'BOOL rdp_client_redirect(rdpRdp* rdp)', 'FALSE'),
    ('libfreerdp/core/connection.c', 'BOOL rdp_client_reconnect(rdpRdp* rdp)', 'FALSE'),
]:
    path = root/file
    text = path.read_text()
    anchor = signature+'\n{\n'
    if text.count(anchor) != 1:
        raise SystemExit('unexpected FreeRDP 2.11.7 source: '+file)
    # Guard before parsing untrusted routing/credentials or touching network state.
    text = text.replace(anchor, anchor+'\tWLog_ERR(TAG, "ZeroTerm RDP redirect/reconnect denied");\n\treturn '+denied+';\n')
    path.write_text(text)
print('Applied FreeRDP 2.11.7 unconditional redirect-PDU/redirect/reconnect fail-closed guard')
