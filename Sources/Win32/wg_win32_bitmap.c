#include "wg_win32_bitmap.h"
#include "wg_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "BMP"

typedef struct {
    bool      used;
    uint32_t  handle;
    int       w, h;
    uint32_t *px;   // RGBA8, top-down, w*h words
} WGBitmap;

#define MAX_BITMAPS 64
static WGBitmap s_bmps[MAX_BITMAPS];
static uint32_t s_next = WG_HBITMAP_BASE;

static WGBitmap *find(uint32_t h) {
    for (int i = 0; i < MAX_BITMAPS; i++)
        if (s_bmps[i].used && s_bmps[i].handle == h) return &s_bmps[i];
    return NULL;
}

static WGBitmap *alloc_slot(int w, int h) {
    if (w <= 0 || h <= 0 || w > 16384 || h > 16384) return NULL;
    for (int i = 0; i < MAX_BITMAPS; i++) {
        if (!s_bmps[i].used) {
            s_bmps[i].px = (uint32_t *)calloc((size_t)w * h, 4);
            if (!s_bmps[i].px) return NULL;
            s_bmps[i].used = true;
            s_bmps[i].handle = s_next++;
            s_bmps[i].w = w;
            s_bmps[i].h = h;
            return &s_bmps[i];
        }
    }
    return NULL;
}

static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
static inline uint32_t pack(uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    return (uint32_t)r | ((uint32_t)g << 8) | ((uint32_t)b << 16) | ((uint32_t)a << 24);
}

// Decode an uncompressed DIB (BITMAPINFOHEADER + optional palette + rows) into a
// new bitmap object. `bih` -> info header; `bits` -> pixel data; `cap` bounds
// how many bytes of pixel data may be read (0 = unbounded/trusted). The palette
// (for <=8bpp) sits immediately after the BITMAPINFOHEADER, before `bits`.
static uint32_t decode_dib(const uint8_t *bih, const uint8_t *bits, size_t cap) {
    uint32_t biSize   = rd32(bih + 0);
    int32_t  biW      = (int32_t)rd32(bih + 4);
    int32_t  biH      = (int32_t)rd32(bih + 8);
    uint16_t biBpp    = rd16(bih + 14);
    uint32_t biComp   = rd32(bih + 16);
    uint32_t biClrUsed = rd32(bih + 32);

    if (biSize < 40) { WG_LOGW(TAG, "unsupported header size %u", biSize); return 0; }
    if (biComp != 0) { WG_LOGW(TAG, "unsupported compression %u", biComp); return 0; }

    bool top_down = biH < 0;
    int W = biW;
    int H = top_down ? -biH : biH;
    if (W <= 0 || H <= 0 || W > 16384 || H > 16384) return 0;
    if (biBpp != 8 && biBpp != 24 && biBpp != 32) {
        WG_LOGW(TAG, "unsupported bpp %u", biBpp);
        return 0;
    }

    // Palette (BGRA quads) for 8-bit images.
    const uint8_t *pal = bih + biSize;
    uint32_t pal_n = biClrUsed ? biClrUsed : (biBpp <= 8 ? (1u << biBpp) : 0);

    WGBitmap *bm = alloc_slot(W, H);
    if (!bm) return 0;

    int bytespp = biBpp / 8;
    size_t stride = ((size_t)W * bytespp + 3) & ~(size_t)3; // rows padded to 4 bytes
    if (cap && stride * (size_t)H > cap) {
        // Not enough source data — keep the blank bitmap rather than overrun.
        WG_LOGW(TAG, "DIB pixel data truncated (need %zu, have %zu)", stride * H, cap);
        return bm->handle;
    }

    for (int y = 0; y < H; y++) {
        const uint8_t *row = bits + (size_t)y * stride;
        // BMP rows are bottom-up unless height is negative.
        int dy = top_down ? y : (H - 1 - y);
        uint32_t *dst = bm->px + (size_t)dy * W;
        for (int x = 0; x < W; x++) {
            uint8_t r, g, b, a = 0xFF;
            if (biBpp == 8) {
                uint8_t idx = row[x];
                const uint8_t *pe = pal + (size_t)idx * 4;
                if (idx < pal_n) { b = pe[0]; g = pe[1]; r = pe[2]; }
                else { r = g = b = idx; }
            } else if (biBpp == 24) {
                const uint8_t *pe = row + (size_t)x * 3;
                b = pe[0]; g = pe[1]; r = pe[2];
            } else { // 32
                const uint8_t *pe = row + (size_t)x * 4;
                b = pe[0]; g = pe[1]; r = pe[2];
                // Many 32-bit BMPs store 0 in the alpha byte; treat as opaque.
                a = pe[3] ? pe[3] : 0xFF;
            }
            dst[x] = pack(r, g, b, a);
        }
    }
    return bm->handle;
}

uint32_t wg_bitmap_from_bmp_memory(const uint8_t *data, uint32_t len) {
    if (!data || len < 54 || data[0] != 'B' || data[1] != 'M') return 0;
    uint32_t off_bits = rd32(data + 10);
    if (off_bits >= len) return 0;
    size_t cap = len - off_bits;
    uint32_t h = decode_dib(data + 14, data + off_bits, cap);
    if (h) {
        WGBitmap *bm = find(h);
        WG_LOGI(TAG, "decoded BMP %dx%d -> HBITMAP 0x%X", bm->w, bm->h, h);
    }
    return h;
}

uint32_t wg_bitmap_from_dib(const uint8_t *bih, const uint8_t *bits) {
    return decode_dib(bih, bits, 0);
}

uint32_t wg_bitmap_load_file(const char *path) {
    if (!path) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) { WG_LOGW(TAG, "can't open %s", path); return 0; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 54 || n > 64 * 1024 * 1024) { fclose(f); return 0; }
    uint8_t *d = (uint8_t *)malloc(n);
    if (!d) { fclose(f); return 0; }
    size_t got = fread(d, 1, n, f);
    fclose(f);
    uint32_t h = (got == (size_t)n) ? wg_bitmap_from_bmp_memory(d, (uint32_t)n) : 0;
    free(d);
    return h;
}

uint32_t wg_bitmap_create(int w, int h) {
    WGBitmap *bm = alloc_slot(w, h);
    return bm ? bm->handle : 0;
}

uint32_t *wg_bitmap_pixels(uint32_t hbitmap, int *w, int *h) {
    WGBitmap *bm = find(hbitmap);
    if (!bm) return NULL;
    if (w) *w = bm->w;
    if (h) *h = bm->h;
    return bm->px;
}

bool wg_bitmap_is(uint32_t handle) { return find(handle) != NULL; }

void wg_bitmap_delete(uint32_t hbitmap) {
    WGBitmap *bm = find(hbitmap);
    if (bm) { free(bm->px); bm->px = NULL; bm->used = false; }
}

void wg_bitmap_reset_all(void) {
    for (int i = 0; i < MAX_BITMAPS; i++) {
        if (s_bmps[i].used) { free(s_bmps[i].px); s_bmps[i].px = NULL; s_bmps[i].used = false; }
    }
    s_next = WG_HBITMAP_BASE;
}
