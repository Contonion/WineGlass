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
// Like wg_gdi_text_out but strips '&' mnemonic markers (for control captions).
void wg_gdi_text_out_caption(uint32_t hdc, int x, int y, const uint16_t *utf16, int count);
// Word-wrapped text inside a rectangle (DT_WORDBREAK); strips '&' mnemonics.
void wg_gdi_text_box(uint32_t hdc, int x, int y, int w, int h, const uint16_t *utf16, int count);
// Measured pixel width / line height of text in the DC's current font.
int  wg_gdi_text_width(uint32_t hdc, const uint16_t *utf16, int count);
int  wg_gdi_line_height(uint32_t hdc);
// Select a font (pixel height, bold, face name; name NULL/"" = default sans).
void wg_gdi_select_font(uint32_t hdc, int px, bool bold, const char *name);
void wg_gdi_move_to(uint32_t hdc, int x, int y);
void wg_gdi_line_to(uint32_t hdc, int x, int y);

// Brush handles encode their color directly (handle = 0x00BR0000 | color is
// awkward; instead we keep a small table). Returns a brush handle.
uint32_t wg_gdi_create_solid_brush(uint32_t colorref);
uint32_t wg_gdi_brush_color(uint32_t hbrush, bool *found);

// ---- Bitmaps / blitting -------------------------------------------------
// A memory DC has no window; it renders into whatever HBITMAP is selected into
// it (CreateCompatibleDC + SelectObject), which is how Win32 code prepares an
// image before BitBlt'ing it onto a window.
uint32_t wg_gdi_create_memory_dc(void);
void     wg_gdi_delete_dc(uint32_t hdc);

// Select a bitmap into a DC; returns the previously-selected bitmap handle.
uint32_t wg_gdi_select_bitmap(uint32_t hdc, uint32_t hbitmap);
// The bitmap currently selected into a DC (0 if none).
uint32_t wg_gdi_selected_bitmap(uint32_t hdc);

// Copy (and stretch, nearest-neighbour) the source DC's selected bitmap into
// the destination DC. Destination is a window framebuffer or another DC's
// bitmap. Pass sw==dw && sh==dh for a 1:1 BitBlt.
void wg_gdi_blit(uint32_t hdc_dst, int dx, int dy, int dw, int dh,
                 uint32_t hdc_src, int sx, int sy, int sw, int sh);

// Draw a bitmap object straight into a DC (used by StretchDIBits / STM_SETIMAGE
// where there is no source DC). dw/dh may differ from sw/sh to stretch.
void wg_gdi_draw_bitmap(uint32_t hdc_dst, int dx, int dy, int dw, int dh,
                        uint32_t hbitmap, int sx, int sy, int sw, int sh);

#endif
