#include "wg_nsis_extract.h"
#include "wg_log.h"
#include "LzmaDec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "NSIS"

static void *lzma_alloc(ISzAllocPtr p, size_t s) { (void)p; return malloc(s); }
static void  lzma_free(ISzAllocPtr p, void *a)   { (void)p; free(a); }

bool wg_nsis_prefill_datatmp(const char *exe_path, const char *out_path) {
    FILE *f = fopen(exe_path, "rb");
    if (!f) { WG_LOGE(TAG, "prefill: can't open exe %s", exe_path); return false; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return false; }
    uint8_t *d = (uint8_t *)malloc(n);
    if (!d) { fclose(f); return false; }
    if (fread(d, 1, n, f) != (size_t)n) { free(d); fclose(f); return false; }
    fclose(f);

    // Locate the NSIS firstheader via the "NullsoftInst" magic.
    long i = -1;
    for (long k = 0; k < n - 16; k++) {
        if (memcmp(d + k, "NullsoftInst", 12) == 0) { i = k; break; }
    }
    if (i < 0) { WG_LOGW(TAG, "prefill: no NullsoftInst marker"); free(d); return false; }

    uint32_t len_all;
    memcpy(&len_all, d + i + 16, 4);   // length of all following (compressed) data
    long ds = i + 20;                   // datablock start = solid LZMA stream
    if (ds + (long)len_all > n) len_all = (uint32_t)(n - ds);
    if (len_all < 6) { free(d); return false; }

    // The stream is raw LZMA1: 5 prop bytes then compressed data, no size field.
    // Decode with a generous output cap; LzmaDecode stops at the stream's end.
    SizeT destCap = 64u * 1024 * 1024;  // 64MB cap (Steam decompresses to ~7.9MB)
    uint8_t *dest = (uint8_t *)malloc(destCap);
    if (!dest) { free(d); return false; }

    ISzAlloc alloc = { lzma_alloc, lzma_free };
    SizeT destLen = destCap;
    SizeT srcLen  = len_all - 5;
    ELzmaStatus status;
    SRes r = LzmaDecode(dest, &destLen,
                        d + ds + 5, &srcLen,
                        d + ds, 5,
                        LZMA_FINISH_ANY, &status, &alloc);
    free(d);

    if (r != SZ_OK || destLen == 0) {
        WG_LOGE(TAG, "prefill: LzmaDecode failed (res=%d status=%d)", (int)r, (int)status);
        free(dest);
        return false;
    }

    FILE *o = fopen(out_path, "wb");
    if (!o) { WG_LOGE(TAG, "prefill: can't open out %s", out_path); free(dest); return false; }
    size_t wrote = fwrite(dest, 1, destLen, o);
    fclose(o);
    free(dest);

    if (wrote != destLen) { WG_LOGE(TAG, "prefill: short write %zu/%lu", wrote, (unsigned long)destLen); return false; }
    WG_LOGI(TAG, "prefill: wrote %lu bytes of decompressed data -> %s",
            (unsigned long)destLen, out_path);
    return true;
}
