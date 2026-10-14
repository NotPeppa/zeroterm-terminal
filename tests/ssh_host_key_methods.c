#include <assert.h>
#include "zt-ssh-host-key.h"

int main(void) {
    assert(!strcmp(zt_ssh_host_key_methods("[10.0.0.1]:2222 ssh-ed25519 AAAA"), "ssh-ed25519"));
    assert(!strcmp(zt_ssh_host_key_methods("host ecdsa-sha2-nistp256 AAAA"), "ecdsa-sha2-nistp256"));
    assert(!strcmp(zt_ssh_host_key_methods("host ecdsa-sha2-nistp384 AAAA"), "ecdsa-sha2-nistp384"));
    assert(!strcmp(zt_ssh_host_key_methods("host ecdsa-sha2-nistp521 AAAA"), "ecdsa-sha2-nistp521"));
    assert(!strcmp(zt_ssh_host_key_methods("host ssh-rsa AAAA"), "rsa-sha2-512,rsa-sha2-256,ssh-rsa"));
    assert(!zt_ssh_host_key_methods(NULL));
    assert(!zt_ssh_host_key_methods(""));
    assert(!zt_ssh_host_key_methods("ssh-ed25519 AAAA"));
    assert(!zt_ssh_host_key_methods("host ssh-ed25519-extra AAAA"));
    assert(!zt_ssh_host_key_methods("host ssh-dss AAAA"));
    return 0;
}
