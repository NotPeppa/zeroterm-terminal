/* Private engine startup evidence. Core consumes this; never forward/record it. */
#ifndef ZT_TARGET_READY_H
#define ZT_TARGET_READY_H
#include <guacamole/socket.h>
static int zt_target_ready(guac_socket* socket) {
    guac_socket_instruction_begin(socket);
    int result = guac_socket_write_string(socket, "15.zt-target-ready;");
    guac_socket_instruction_end(socket);
    if (result)
        return result;
    return guac_socket_flush(socket);
}
#endif
