#ifndef WG_SCHANNEL_H
#define WG_SCHANNEL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct WGSchannel WGSchannel;

WGSchannel *wg_schannel_create(void);
void        wg_schannel_destroy(WGSchannel *sc);

bool wg_schannel_handle(WGSchannel *sc, const char *fn,
                        uint32_t *args, uint64_t *out_ret,
                        void *blink);

// Check if a socket FD has an active TLS session and use it for send/recv.
// Returns -1 if no TLS context exists for this fd (caller uses plain I/O).
ssize_t wg_schannel_send(WGSchannel *sc, int fd, const void *buf, size_t len);
ssize_t wg_schannel_recv(WGSchannel *sc, int fd, void *buf, size_t len);
bool    wg_schannel_has_tls(WGSchannel *sc, int fd);

#endif
