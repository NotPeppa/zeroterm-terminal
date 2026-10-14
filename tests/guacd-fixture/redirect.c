/* Isolated fictional TLS peer: send a real redirect PDU, never a production server. */
#include <freerdp/freerdp.h>
#include <freerdp/peer.h>
#include <freerdp/constants.h>
#include <winpr/synch.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char* redirect_host;
static BOOL redirect_sent;
static BOOL after_connect(freerdp_peer* peer) {
    redirect_sent = peer->SendServerRedirection(peer, 42, redirect_host,
            NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, 0, NULL);
    printf("{\"redirect_sent\":%s,\"primary_credentials_received\":%s}\n",
            redirect_sent ? "true" : "false",
            peer->settings->Username && peer->settings->Username[0] ? "true" : "false");
    fflush(stdout);
    return redirect_sent;
}

int main(int argc, char** argv) {
    if (argc != 6) return 2;
    int port = atoi(argv[2]);
    if (port < 32768 || port > 60999) return 2;
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 3;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1
            || bind(server, (struct sockaddr*)&address, sizeof(address)) || listen(server,1)) return 3;
    printf("LISTENING\n"); fflush(stdout);
    int fd = accept(server,NULL,NULL);
    close(server); /* exactly one connection */
    if (fd < 0) return 3;
    redirect_host = argv[5];
    freerdp_peer* peer = freerdp_peer_new(fd);
    if (!peer) return 3;
    peer->ContextSize = sizeof(rdpContext);
    if (!freerdp_peer_context_new(peer)) return 3;
    peer->settings->CertificateFile = strdup(argv[3]);
    peer->settings->PrivateKeyFile = strdup(argv[4]);
    peer->settings->RdpKeyFile = strdup(argv[4]);
    peer->settings->RdpSecurity = FALSE;
    peer->settings->TlsSecurity = TRUE;
    peer->settings->NlaSecurity = FALSE; /* This is TLS, NEVER Windows NLA acceptance. */
    peer->settings->EncryptionLevel = ENCRYPTION_LEVEL_NONE;
    peer->settings->ColorDepth = 32;
    peer->settings->DesktopWidth = 1024;
    peer->settings->DesktopHeight = 768;
    peer->ClientCapabilities = after_connect; /* Before finalization / interactive marker. */
    if (!peer->Initialize(peer)) return 3;
    for (int iteration = 0; iteration < 45; iteration++) {
        HANDLE events[32];
        DWORD count = peer->GetEventHandles(peer,events,32);
        if (!count || WaitForMultipleObjects(count,events,FALSE,1000) == WAIT_FAILED
                || !peer->CheckFileDescriptor(peer)) break;
    }
    peer->Disconnect(peer);
    freerdp_peer_context_free(peer);
    freerdp_peer_free(peer);
    return redirect_sent ? 0 : 4;
}
