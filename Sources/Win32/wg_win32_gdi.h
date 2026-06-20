#ifndef WG_WIN32_GDI_H
#define WG_WIN32_GDI_H

#include <stdint.h>
#include <stdbool.h>

// Minimal GDI implementation that renders into a window's client-area
// framebuffer (see wg_wm_get_client). Pure C with an embedded 8x16 font,
// so it has zero external dependencies and is fully deterministic.

#define WG_DC_BASE 0x00DC0000

// Create a device context bound to a window. Returns a DC handle, or 0.
uint32_t wg_gdi_get_dc(uint32_t hwnd);
void     wg_gdi_release_dc(uint32_t hdc);

// DC state.
void wg_gdi_set_text_color(uint32_t hdc, uint32_t colorref); // 0x00BBGGRR
void wg_gdi_set_bk_mode(uint32_t hdc, int mode);             // 1=TRANSPARENT? (we treat !=2 as opaque)
void wg_gdi_set_bk_color(uint32_t hdc, uint32_t colorref);

// Drawing primitives (coords are client-area pixels).
void wg_gdi_fill_rect(uint32_t hdc, int l, int t, int r, int b, uint32_t colorref);
void wg_gdi_text_out(uint32_t hdc, int x, int y, const uint16_t *utf16, int count);
void wg_gdi_move_to(uint32_t hdc, int x, int y);
void wg_gdi_line_to(uint32_t hdc, int x, int y);

// Brush handles encode their color directly (handle = 0x00BR0000 | color is
// awkward; instead we keep a small table). Returns a brush handle.
uint32_t wg_gdi_create_solid_brush(uint32_t colorref);
uint32_t wg_gdi_brush_color(uint32_t hbrush, bool *found);

#endif
