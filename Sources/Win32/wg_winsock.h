#ifndef WG_WINSOCK_H
#define WG_WINSOCK_H

#include <stdint.h>
#include <stdbool.h>

typedef struct WGWinsock WGWinsock;

WGWinsock *wg_winsock_create(void);
void       wg_winsock_destroy(WGWinsock *ws);

// Handle a WS2_32/WSOCK32 function call. Returns true if handled.
// args[] are the stdcall arguments (32-bit, read from guest stack).
// *out_ret receives the return value to place in EAX.
bool wg_winsock_handle(WGWinsock *ws, const char *fn,
                       uint32_t *args, uint64_t *out_ret,
                       void *blink);

#endif
