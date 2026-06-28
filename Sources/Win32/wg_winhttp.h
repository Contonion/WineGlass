#ifndef WG_WINHTTP_H
#define WG_WINHTTP_H

#include <stdint.h>
#include <stdbool.h>

typedef struct WGWinHttp WGWinHttp;

WGWinHttp *wg_winhttp_create(void);
void       wg_winhttp_destroy(WGWinHttp *wh);

bool wg_winhttp_handle(WGWinHttp *wh, const char *fn,
                       uint32_t *args, uint64_t *out_ret,
                       void *blink);

#endif
