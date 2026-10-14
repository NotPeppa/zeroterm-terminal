#ifndef ZT_SSH_HOST_KEY_H
#define ZT_SSH_HOST_KEY_H
#include <string.h>

/* Negotiate the approved key type even when the target offers several keys. */
static const char* zt_ssh_host_key_methods(const char* known_host) {
    const char* key = known_host ? strchr(known_host, ' ') : NULL;
    if (!key) return NULL;
    key++;
    if (!strncmp(key, "ssh-ed25519 ", 12)) return "ssh-ed25519";
    if (!strncmp(key, "ecdsa-sha2-nistp256 ", 20)) return "ecdsa-sha2-nistp256";
    if (!strncmp(key, "ecdsa-sha2-nistp384 ", 20)) return "ecdsa-sha2-nistp384";
    if (!strncmp(key, "ecdsa-sha2-nistp521 ", 20)) return "ecdsa-sha2-nistp521";
    /* Preserve the engine's RSA compatibility, preferring SHA-2 when supported. */
    if (!strncmp(key, "ssh-rsa ", 8)) return "rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    return NULL;
}
#endif
