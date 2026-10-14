#!/usr/bin/env python3
"""Apply the strict leaf pin delta ONLY to the verified guacamole-server 1.6.0 tag."""
from pathlib import Path
import sys

root = Path(sys.argv[1])

def replace(path, old, new):
    file = root / path
    text = file.read_text()
    if text.count(old) != 1:
        raise SystemExit(f'unexpected official source at {path}: patch anchor differs')
    file.write_text(text.replace(old, new))

base = 'src/protocols/rdp/'
replace(base+'settings.c', '    "normalize-clipboard",\n    NULL', '    "normalize-clipboard",\n    "zt-strict-cert-pin",\n    NULL')
replace(base+'settings.c', '    RDP_ARGS_COUNT\n', '    IDX_ZT_STRICT_CERT_PIN,\n    RDP_ARGS_COUNT\n')
replace(base+'settings.h', '    char* certificate_fingerprints;\n', '    char* certificate_fingerprints;\n\n    /* Required lowercase SHA-256 of leaf DER; never a CA/TOFU fallback. */\n    char* zt_strict_cert_pin;\n')
replace(base+'settings.c', '    guac_rdp_settings* settings = guac_mem_zalloc(sizeof(guac_rdp_settings));', '''    /* Validate before allocating or contacting the target. */
    const char* pin = argv[IDX_ZT_STRICT_CERT_PIN];
    if (strlen(pin) != 64 || strspn(pin, "0123456789abcdef") != 64
            || (strcmp(argv[IDX_SECURITY], "nla") && strcmp(argv[IDX_SECURITY], "tls"))
            || (argv[IDX_IGNORE_CERT][0] && strcmp(argv[IDX_IGNORE_CERT], "false"))
            || (argv[IDX_CERTIFICATE_TOFU][0] && strcmp(argv[IDX_CERTIFICATE_TOFU], "false"))
            || argv[IDX_CERTIFICATE_FINGERPRINTS][0]
            || argv[IDX_GATEWAY_HOSTNAME][0] || argv[IDX_LOAD_BALANCE_INFO][0]
            || argv[IDX_PRECONNECTION_ID][0] || argv[IDX_PRECONNECTION_BLOB][0]) {
        guac_user_log(user, GUAC_LOG_ERROR, "Strict RDP pin/security configuration rejected");
        return NULL;
    }
    guac_rdp_settings* settings = guac_mem_zalloc(sizeof(guac_rdp_settings));
    settings->zt_strict_cert_pin = guac_strdup(pin);''')
replace(base+'settings.c', '    guac_mem_free(settings->certificate_fingerprints);', '    guac_mem_free(settings->certificate_fingerprints);\n    guac_mem_free(settings->zt_strict_cert_pin);')
replace(base+'settings.c', '''    freerdp_settings_set_bool(rdp_settings, FreeRDP_IgnoreCertificate, guac_settings->ignore_certificate);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_AutoAcceptCertificate, guac_settings->certificate_tofu);
    if (guac_settings->certificate_fingerprints != NULL)
        freerdp_settings_set_string(rdp_settings, FreeRDP_CertificateAcceptedFingerprints, 
                guac_strdup(guac_settings->certificate_fingerprints));''', '''    freerdp_settings_set_bool(rdp_settings, FreeRDP_IgnoreCertificate, FALSE);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_AutoAcceptCertificate, FALSE);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_ExternalCertificateManagement, TRUE);
    freerdp_settings_set_string(rdp_settings, FreeRDP_CertificateAcceptedFingerprints, NULL);''')
replace(base+'settings.c', '''    rdp_settings->IgnoreCertificate = guac_settings->ignore_certificate;
    rdp_settings->AutoAcceptCertificate = guac_settings->certificate_tofu;
    if (guac_settings->certificate_fingerprints != NULL)
        rdp_settings->CertificateAcceptedFingerprints = guac_strdup(guac_settings->certificate_fingerprints);''', '''    rdp_settings->IgnoreCertificate = FALSE;
    rdp_settings->AutoAcceptCertificate = FALSE;
    rdp_settings->ExternalCertificateManagement = TRUE;
    free(rdp_settings->CertificateAcceptedFingerprints);
    rdp_settings->CertificateAcceptedFingerprints = NULL;''')
replace(base+'rdp.c', '#include <stdlib.h>', '#include "zt-strict-pin.h"\n#include <freerdp/version.h>\n#if FREERDP_VERSION_MAJOR != 2 || FREERDP_VERSION_MINOR != 11 || FREERDP_VERSION_REVISION != 7\n#error Strict RDP gate requires FreeRDP 2.11.7\n#endif\n\n#include <stdlib.h>')
replace(base+'rdp.c', 'static int rdp_guac_client_wait_for_events(guac_client* client,', '''static int zt_verify_x509(freerdp* instance, const BYTE* pem, size_t length,
        const char* hostname, UINT16 port, DWORD flags) {
    guac_client* client = ((rdp_freerdp_context*) GUAC_RDP_CONTEXT(instance))->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;
    if (flags & (VERIFY_CERT_FLAG_REDIRECT | VERIFY_CERT_FLAG_GATEWAY))
        return 0;
    int match = zt_leaf_pin_matches(pem, length, rdp_client->settings->zt_strict_cert_pin);
    guac_client_log(client, match ? GUAC_LOG_DEBUG : GUAC_LOG_ERROR,
            match ? "Strict RDP leaf pin matched" : "Strict RDP leaf pin rejected");
    return match ? 2 : 0;
}

static int rdp_guac_client_wait_for_events(guac_client* client,''')
replace(base+'rdp.c', '    rdp_inst->Authenticate = rdp_freerdp_authenticate;', '    rdp_inst->Authenticate = rdp_freerdp_authenticate;\n    rdp_inst->VerifyX509Certificate = zt_verify_x509;')
replace(base+'Makefile.am', '    @CAIRO_LIBS@                \\\n    @PTHREAD_LIBS@              \\\n    @RDP_LIBS@', '    @CAIRO_LIBS@                \\\n    @PTHREAD_LIBS@              \\\n    @RDP_LIBS@ -lcrypto')
(root/base/'zt-strict-pin.h').write_text(Path(__file__).with_name('zt-strict-pin.h').read_text())
# All protocols require this patch's explicit startup evidence, not Guacamole ready/display.
for protocol in ('ssh', 'rdp', 'vnc'):
    prefix = 'src/protocols/'+protocol+'/'
    tag = protocol.upper()
    replace(prefix+'settings.c', '    NULL\n};', '    "zt-target-ready",\n    NULL\n};')
    replace(prefix+'settings.c', '    '+tag+'_ARGS_COUNT\n', '    IDX_ZT_TARGET_READY,\n    '+tag+'_ARGS_COUNT\n')
    anchor = '    guac_'+protocol+'_settings* settings = guac_mem_zalloc(sizeof(guac_'+protocol+'_settings));'
    guard = 'strcmp(argv[IDX_ZT_TARGET_READY], "true")'
    if protocol == 'ssh':
        guard += ' || !argv[IDX_HOST_KEY][0] || argv[IDX_COMMAND][0]'
    replace(prefix+'settings.c', anchor, '''    if ('''+guard+''') {
        guac_user_log(user, GUAC_LOG_ERROR, "Target-ready capability/trust configuration rejected");
        return NULL;
    }
'''+anchor)
    code = protocol+'.c'
    replace(prefix+code, '#include "config.h"', '#include "config.h"\n#include "zt-target-ready.h"')
    (root/prefix/'zt-target-ready.h').write_text(Path(__file__).with_name('zt-target-ready.h').read_text())
# SSH exposes font/color parameters as argv/blob/end streams on startup and join.
# Suppress their shared producer; the gateway continues rejecting parameter streams.
replace('src/protocols/ssh/argv.c', '''    guac_ssh_client* ssh_client = (guac_ssh_client*) client->data;
    guac_terminal* terminal = ssh_client->term;

    /* Send current color scheme */
    guac_client_stream_argv(client, socket, "text/plain",
            GUAC_SSH_ARGV_COLOR_SCHEME,
            guac_terminal_get_color_scheme(terminal));

    /* Send current font name */
    guac_client_stream_argv(client, socket, "text/plain",
            GUAC_SSH_ARGV_FONT_NAME,
            guac_terminal_get_font_name(terminal));

    /* Send current font size */
    char font_size[64];
    sprintf(font_size, "%i", guac_terminal_get_font_size(terminal));
    guac_client_stream_argv(client, socket, "text/plain",
            GUAC_SSH_ARGV_FONT_SIZE, font_size);''', '''    /* Only display streams are permitted after the server-side handshake. */
    (void) client;
    (void) socket;''')
replace('src/protocols/ssh/user.c', '        user->argv_handler = guac_argv_handler;',
        '        user->argv_handler = NULL;')
replace('src/protocols/ssh/settings.c', '    "zt-target-ready",\n    NULL',
        '    "zt-target-ready",\n    "zt-ssh-display-only",\n    NULL')
replace('src/protocols/ssh/settings.c', '    IDX_ZT_TARGET_READY,\n    SSH_ARGS_COUNT',
        '    IDX_ZT_TARGET_READY,\n    IDX_ZT_SSH_DISPLAY_ONLY,\n    SSH_ARGS_COUNT')
replace('src/protocols/ssh/settings.c', 'strcmp(argv[IDX_ZT_TARGET_READY], "true")',
        'strcmp(argv[IDX_ZT_TARGET_READY], "true") || strcmp(argv[IDX_ZT_SSH_DISPLAY_ONLY], "true")')
replace('src/protocols/ssh/ssh.c', '    /* Logged in */', '''    if (zt_target_ready(client->socket)) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR, "Target readiness write failed");
        return NULL;
    }

    /* Logged in */''')
replace('src/protocols/rdp/rdp.c', '    /* Upgrade to write lock again for further exclusive operations */', '''    if (zt_target_ready(client->socket)) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR, "Target readiness write failed");
        goto fail;
    }

    /* Upgrade to write lock again for further exclusive operations */''')
replace('src/protocols/vnc/vnc.c', '''    if (rfbInitClient(rfb_client, NULL, NULL))
        return rfb_client;''', '''    if (rfbInitClient(rfb_client, NULL, NULL)) {
        if (zt_target_ready(client->socket)) {
            guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR, "Target readiness write failed");
            rfbClientCleanup(rfb_client);
            return NULL;
        }
        return rfb_client;
    }''')
replace('src/common-ssh/ssh.c', '#include "common-ssh/key.h"',
        '#include "common-ssh/key.h"\n#include "zt-ssh-host-key.h"')
(root/'src/common-ssh/zt-ssh-host-key.h').write_text(Path(__file__).with_name('zt-ssh-host-key.h').read_text())
replace('src/common-ssh/ssh.c', '    /* Perform handshake */', '''    const char* host_key_methods = zt_ssh_host_key_methods(host_key);
    if (!host_key_methods || libssh2_session_method_pref(session,
            LIBSSH2_METHOD_HOSTKEY, host_key_methods)) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
                "Approved SSH host key algorithm is unavailable.");
        libssh2_session_free(session);
        guac_mem_free(common_session);
        close(fd);
        return NULL;
    }

    /* Perform handshake */''')
print('Applied zt-pin-v4: SSH approved-key negotiation / display-only + target-ready + strict RDP leaf pin / FreeRDP 2.11.7')
