#ifndef WG_WIN32_BITMAP_H
#define WG_WIN32_BITMAP_H

#include <stdint.h>
#include <stdbool.h>

// Minimal HBITMAP subsystem. Bitmaps are decoded to RGBA8, stored top-down
// (row 0 = top), one word per pixel: byte0=R, byte1=G, byte2=B, byte3=A — the
// exact layout the window client framebuffer and the Metal compositor expect
// (see wg_win32_gdi.c / WGCompositor.m).

#define WG_HBITMAP_BASE 0x0B170000u

// Decode a BMP file from disk (BITMAPFILEHEADER + BITMAPINFOHEADER, 8/24/32-bit,
// BI_RGB, top-down or bottom-up). Returns an HBITMAP handle, or 0 on failure.
uint32_t wg_bitmap_load_file(const char *path);

// Decode a BMP image already sitting in host memory (full file: starts with the
// 'BM' BITMAPFILEHEADER). Returns a handle or 0.
uint32_t wg_bitmap_from_bmp_memory(const uint8_t *data, uint32_t len);

// Build a bitmap from a packed DIB: a BITMAPINFOHEADER followed (after any
// palette) by pixel rows, as passed to SetDIBitsToDevice/StretchDIBits/
// CreateDIBitmap. `bih` points at the BITMAPINFOHEADER, `bits` at the pixels.
// Returns a handle or 0.
uint32_t wg_bitmap_from_dib(const uint8_t *bih, const uint8_t *bits);

// Allocate a blank (transparent) RGBA8 bitmap, for CreateCompatibleBitmap.
uint32_t wg_bitmap_create(int w, int h);

// Look up a bitmap's pixels and size. Returns NULL for an unknown handle.
// The returned buffer is writable (memory DCs render into it).
uint32_t *wg_bitmap_pixels(uint32_t hbitmap, int *w, int *h);

// True if `handle` is a live bitmap object.
bool wg_bitmap_is(uint32_t handle);

void wg_bitmap_delete(uint32_t hbitmap);

// Free every bitmap (call when loading a new program).
void wg_bitmap_reset_all(void);

#endif
