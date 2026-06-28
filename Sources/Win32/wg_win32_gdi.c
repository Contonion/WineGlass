#include "wg_win32_gdi.h"
#include "wg_win32_windows.h"
#include "wg_win32_bitmap.h"
#include "wg_log.h"
#include <string.h>
#include <ctype.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreText/CoreText.h>

#define TAG "GDI"


// ---- DC table ----------------------------------------------------------
typedef struct {
    bool     used;
    uint32_t handle;
    uint32_t hwnd;        // 0 for a memory DC
    bool     is_memdc;
    uint32_t sel_bitmap;  // HBITMAP selected into this DC (0 = none)
    uint32_t text_color;  // 0x00BBGGRR (COLORREF)
    uint32_t bk_color;
    int      bk_mode;     // 1=TRANSPARENT, 2=OPAQUE
    int      cur_x, cur_y;
    int      font_px;     // pixel height of the selected font
    bool     font_bold;
    char     font_name[64];
} WGDC;

#define MAX_DCS 32
static WGDC s_dcs[MAX_DCS];
static uint32_t s_next_dc = WG_DC_BASE;

#define MAX_BRUSHES 64
static uint32_t s_brush_color[MAX_BRUSHES];
static bool     s_brush_used[MAX_BRUSHES];
static uint32_t s_next_brush = 0x00B0000;

// COLORREF (0x00BBGGRR) -> RGBA8 little-endian word stored in the framebuffer.
// Framebuffer word layout matches what the compositor uploads as RGBA8Unorm:
// byte0=R, byte1=G, byte2=B, byte3=A.
static inline uint32_t colorref_to_rgba(uint32_t cr) {
    uint32_t r = cr & 0xFF;
    uint32_t g = (cr >> 8) & 0xFF;
    uint32_t b = (cr >> 16) & 0xFF;
    return r | (g << 8) | (b << 16) | (0xFFu << 24);
}

static WGDC *find_dc(uint32_t hdc) {
    for (int i = 0; i < MAX_DCS; i++)
        if (s_dcs[i].used && s_dcs[i].handle == hdc) return &s_dcs[i];
    return NULL;
}

uint32_t wg_gdi_get_dc(uint32_t hwnd) {
    for (int i = 0; i < MAX_DCS; i++) {
        if (!s_dcs[i].used) {
            s_dcs[i].used = true;
            s_dcs[i].handle = s_next_dc++;
            s_dcs[i].hwnd = hwnd;
            s_dcs[i].text_color = 0x00000000; // black
            s_dcs[i].bk_color = 0x00FFFFFF;    // white
            s_dcs[i].bk_mode = 2;              // OPAQUE
            s_dcs[i].cur_x = 0;
            s_dcs[i].cur_y = 0;
            s_dcs[i].font_px = 13;             // ~MS Shell Dlg 8pt @ our scale
            s_dcs[i].font_bold = false;
            s_dcs[i].font_name[0] = '\0';      // empty -> default proportional
            return s_dcs[i].handle;
        }
    }
    return 0;
}

void wg_gdi_release_dc(uint32_t hdc) {
    WGDC *dc = find_dc(hdc);
    if (dc) dc->used = false;
}

void wg_gdi_set_text_color(uint32_t hdc, uint32_t cr) {
    WGDC *dc = find_dc(hdc); if (dc) dc->text_color = cr;
}
void wg_gdi_set_bk_mode(uint32_t hdc, int mode) {
    WGDC *dc = find_dc(hdc); if (dc) dc->bk_mode = mode;
}
void wg_gdi_set_bk_color(uint32_t hdc, uint32_t cr) {
    WGDC *dc = find_dc(hdc); if (dc) dc->bk_color = cr;
}

static void put_px(uint32_t *fb, int w, int h, int x, int y, uint32_t rgba) {
    if (x < 0 || y < 0 || x >= w || y >= h) return;
    fb[y * w + x] = rgba;
}

void wg_gdi_fill_rect(uint32_t hdc, int l, int t, int r, int b, uint32_t cr) {
    WGDC *dc = find_dc(hdc); if (!dc) return;
    int32_t w, h;
    uint32_t *fb = wg_wm_get_client(dc->hwnd, &w, &h);
    if (!fb) return;
    uint32_t rgba = colorref_to_rgba(cr);
    if (l < 0) l = 0; if (t < 0) t = 0;
    if (r > w) r = w; if (b > h) b = h;
    for (int y = t; y < b; y++)
        for (int x = l; x < r; x++)
            fb[y * w + x] = rgba;
    WGWin32Window *win = wg_wm_find(dc->hwnd);
    if (win) win->client_dirty = true;
}

// ---- Core Text glyph rasterizer ----------------------------------------
// The old path stamped a public-domain 8x8 bitmap font, which looked blocky
// and was monospaced. We now rasterize real proportional, anti-aliased glyphs
// with Core Text straight into the window's RGBA8 client framebuffer. iOS
// ships Verdana/Arial/Times/Courier, so we map common Windows face names onto
// the closest built-in font (no Microsoft fonts shipped).

// Map a Windows font face name (lowercased) onto an iOS PostScript font name.
static const char *map_font_name(const char *name, bool bold) {
    char low[64] = {0};
    if (name) for (int i = 0; i < 63 && name[i]; i++) low[i] = (char)tolower((unsigned char)name[i]);
    if (strstr(low, "courier") || strstr(low, "consol") || strstr(low, "mono"))
        return bold ? "CourierNewPS-BoldMT" : "CourierNewPSMT";
    if (strstr(low, "times") || strstr(low, "serif"))
        return bold ? "TimesNewRomanPS-BoldMT" : "TimesNewRomanPSMT";
    if (strstr(low, "arial"))
        return bold ? "Arial-BoldMT" : "ArialMT";
    if (strstr(low, "trebuchet"))
        return bold ? "TrebuchetMS-Bold" : "TrebuchetMS";
    if (strstr(low, "georgia"))
        return bold ? "Georgia-Bold" : "Georgia";
    // Tahoma / Segoe UI / MS Shell Dlg / MS Sans Serif / default -> Verdana,
    // which closely matches Tahoma's humanist-sans look and is on iOS.
    return bold ? "Verdana-Bold" : "Verdana";
}

static CTFontRef make_font(const char *name, double px, bool bold) {
    const char *ps = map_font_name(name, bold);
    CFStringRef cf = CFStringCreateWithCString(NULL, ps, kCFStringEncodingUTF8);
    CTFontRef f = CTFontCreateWithName(cf, px, NULL);
    if (cf) CFRelease(cf);
    if (!f) f = CTFontCreateUIFontForLanguage(kCTFontUIFontSystem, px, NULL);
    return f;
}

// Build a CTLine for a UTF-16 run in the given font/color. Caller releases
// both the returned line and *out_font.
static CTLineRef build_line(const uint16_t *utf16, int count, double px,
                            bool bold, const char *name, uint32_t fg_rgba,
                            CTFontRef *out_font) {
    CTFontRef font = make_font(name, px, bold);
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGFloat comps[4] = { (fg_rgba & 0xFF) / 255.0, ((fg_rgba >> 8) & 0xFF) / 255.0,
                         ((fg_rgba >> 16) & 0xFF) / 255.0, 1.0 };
    CGColorRef col = CGColorCreate(cs, comps);
    CFStringRef keys[2] = { kCTFontAttributeName, kCTForegroundColorAttributeName };
    CFTypeRef   vals[2] = { font, col };
    CFDictionaryRef attr = CFDictionaryCreate(NULL, (const void **)keys,
        (const void **)vals, 2, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFStringRef str = CFStringCreateWithCharacters(NULL, (const UniChar *)utf16, count);
    CFAttributedStringRef as = CFAttributedStringCreate(NULL, str, attr);
    CTLineRef line = CTLineCreateWithAttributedString(as);
    CFRelease(as); CFRelease(str); CFRelease(attr); CFRelease(col);
    CGColorSpaceRelease(cs);
    *out_font = font;
    return line;
}

void wg_gdi_text_out(uint32_t hdc, int x, int y, const uint16_t *utf16, int count) {
    WGDC *dc = find_dc(hdc); if (!dc || count <= 0) return;
    int32_t w, h;
    uint32_t *fb = wg_wm_get_client(dc->hwnd, &w, &h);
    if (!fb) return;
    uint32_t fg = colorref_to_rgba(dc->text_color);
    bool opaque = (dc->bk_mode == 2);
    double px = dc->font_px > 0 ? dc->font_px : 13;

    CTFontRef font = NULL;
    CTLineRef line = build_line(utf16, count, px, dc->font_bold, dc->font_name, fg, &font);
    CGFloat ascent = CTFontGetAscent(font);
    CGFloat descent = CTFontGetDescent(font);

    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(fb, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGContextSetShouldAntialias(ctx, true);
    CGContextSetShouldSmoothFonts(ctx, false); // grayscale AA (no color fringes)

    if (opaque) {
        double tw = CTLineGetTypographicBounds(line, NULL, NULL, NULL);
        uint32_t bg = colorref_to_rgba(dc->bk_color);
        CGFloat bgc[4] = { (bg & 0xFF) / 255.0, ((bg >> 8) & 0xFF) / 255.0,
                           ((bg >> 16) & 0xFF) / 255.0, 1.0 };
        CGContextSetFillColor(ctx, bgc);
        CGContextFillRect(ctx, CGRectMake(x, h - y - (ascent + descent), tw, ascent + descent));
    }

    // Framebuffer row 0 is the top; CG's origin is bottom-left, so flip y and
    // offset by the ascent to place (x,y) at the text's top-left (GDI semantics).
    CGContextSetTextMatrix(ctx, CGAffineTransformIdentity);
    CGContextSetTextPosition(ctx, x, h - y - ascent);
    CTLineDraw(line, ctx);

    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
    CFRelease(line);
    CFRelease(font);
    WGWin32Window *win = wg_wm_find(dc->hwnd);
    if (win) win->client_dirty = true;
}

// Measured pixel width of a run in the DC's current font.
int wg_gdi_text_width(uint32_t hdc, const uint16_t *utf16, int count) {
    WGDC *dc = find_dc(hdc); if (!dc || count <= 0) return 0;
    double px = dc->font_px > 0 ? dc->font_px : 13;
    CTFontRef font = NULL;
    CTLineRef line = build_line(utf16, count, px, dc->font_bold, dc->font_name,
                                0xFFFFFFFFu, &font);
    double tw = CTLineGetTypographicBounds(line, NULL, NULL, NULL);
    CFRelease(line); CFRelease(font);
    return (int)(tw + 0.5);
}

// Full line height (ascent + descent) of the DC's current font, in pixels.
int wg_gdi_line_height(uint32_t hdc) {
    WGDC *dc = find_dc(hdc);
    double px = (dc && dc->font_px > 0) ? dc->font_px : 13;
    CTFontRef font = make_font(dc ? dc->font_name : "", px, dc ? dc->font_bold : false);
    int lh = (int)(CTFontGetAscent(font) + CTFontGetDescent(font) + 0.5);
    CFRelease(font);
    return lh;
}

// Select a font into a DC (pixel height, bold flag, face name).
void wg_gdi_select_font(uint32_t hdc, int px, bool bold, const char *name) {
    WGDC *dc = find_dc(hdc); if (!dc) return;
    if (px > 0) dc->font_px = px;
    dc->font_bold = bold;
    if (name) { strncpy(dc->font_name, name, sizeof(dc->font_name) - 1);
                dc->font_name[sizeof(dc->font_name) - 1] = '\0'; }
    else dc->font_name[0] = '\0';
}

// Draw a control caption: strips '&' mnemonic markers ("&&" -> literal '&').
void wg_gdi_text_out_caption(uint32_t hdc, int x, int y,
                             const uint16_t *utf16, int count) {
    uint16_t clean[256]; int n = 0;
    for (int i = 0; i < count && n < 255; i++) {
        if (utf16[i] == '&') {
            if (i + 1 < count && utf16[i + 1] == '&') { clean[n++] = '&'; i++; }
            // else: drop the single '&' (mnemonic marker)
        } else {
            clean[n++] = utf16[i];
        }
    }
    wg_gdi_text_out(hdc, x, y, clean, n);
}

// Word-wrapped text within a rectangle (GDI DT_WORDBREAK). Strips '&' mnemonics
// so it can render static labels. Used where single-line TextOut would clip.
void wg_gdi_text_box(uint32_t hdc, int x, int y, int bw, int bh,
                     const uint16_t *utf16, int count) {
    WGDC *dc = find_dc(hdc); if (!dc || count <= 0 || bw <= 0 || bh <= 0) return;
    int32_t w, h;
    uint32_t *fb = wg_wm_get_client(dc->hwnd, &w, &h);
    if (!fb) return;
    uint16_t clean[512]; int n = 0;
    for (int i = 0; i < count && n < 511; i++) {
        if (utf16[i] == '&') { if (i + 1 < count && utf16[i + 1] == '&') { clean[n++] = '&'; i++; } }
        else clean[n++] = utf16[i];
    }
    if (n == 0) return;

    uint32_t fg = colorref_to_rgba(dc->text_color);
    double px = dc->font_px > 0 ? dc->font_px : 13;
    CTFontRef font = make_font(dc->font_name, px, dc->font_bold);
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGFloat comps[4] = { (fg & 0xFF)/255.0, ((fg>>8)&0xFF)/255.0, ((fg>>16)&0xFF)/255.0, 1.0 };
    CGColorRef col = CGColorCreate(cs, comps);
    CFStringRef keys[2] = { kCTFontAttributeName, kCTForegroundColorAttributeName };
    CFTypeRef   vals[2] = { font, col };
    CFDictionaryRef attr = CFDictionaryCreate(NULL, (const void **)keys,
        (const void **)vals, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef str = CFStringCreateWithCharacters(NULL, (const UniChar *)clean, n);
    CFAttributedStringRef as = CFAttributedStringCreate(NULL, str, attr);

    CGContextRef ctx = CGBitmapContextCreate(fb, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGContextSetShouldAntialias(ctx, true);
    CGContextSetShouldSmoothFonts(ctx, false);
    CGContextSetTextMatrix(ctx, CGAffineTransformIdentity);

    CTFramesetterRef fs = CTFramesetterCreateWithAttributedString(as);
    // Flip the rect into CG's bottom-left space so the box top sits at y.
    CGRect rect = CGRectMake(x, h - y - bh, bw, bh);
    CGMutablePathRef path = CGPathCreateMutable();
    CGPathAddRect(path, NULL, rect);
    CTFrameRef frame = CTFramesetterCreateFrame(fs, CFRangeMake(0, 0), path, NULL);
    CTFrameDraw(frame, ctx);

    CFRelease(frame); CGPathRelease(path); CFRelease(fs);
    CGContextRelease(ctx);
    CFRelease(as); CFRelease(str); CFRelease(attr); CFRelease(col);
    CGColorSpaceRelease(cs); CFRelease(font);
    WGWin32Window *win = wg_wm_find(dc->hwnd);
    if (win) win->client_dirty = true;
}

void wg_gdi_move_to(uint32_t hdc, int x, int y) {
    WGDC *dc = find_dc(hdc); if (dc) { dc->cur_x = x; dc->cur_y = y; }
}

void wg_gdi_line_to(uint32_t hdc, int x, int y) {
    WGDC *dc = find_dc(hdc); if (!dc) return;
    int32_t w, h;
    uint32_t *fb = wg_wm_get_client(dc->hwnd, &w, &h);
    if (!fb) return;
    uint32_t rgba = colorref_to_rgba(dc->text_color);
    // Bresenham from (cur) to (x,y).
    int x0 = dc->cur_x, y0 = dc->cur_y, x1 = x, y1 = y;
    int dx = x1 - x0, dy = y1 - y0;
    int adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
    int sx = dx < 0 ? -1 : 1, sy = dy < 0 ? -1 : 1;
    int err = (adx > ady ? adx : -ady) / 2, e2;
    for (;;) {
        put_px(fb, w, h, x0, y0, rgba);
        if (x0 == x1 && y0 == y1) break;
        e2 = err;
        if (e2 > -adx) { err -= ady; x0 += sx; }
        if (e2 <  ady) { err += adx; y0 += sy; }
    }
    dc->cur_x = x; dc->cur_y = y;
    WGWin32Window *win = wg_wm_find(dc->hwnd);
    if (win) win->client_dirty = true;
}

uint32_t wg_gdi_create_solid_brush(uint32_t cr) {
    for (int i = 0; i < MAX_BRUSHES; i++) {
        if (!s_brush_used[i]) {
            s_brush_used[i] = true;
            s_brush_color[i] = cr;
            return s_next_brush + i;
        }
    }
    return s_next_brush; // fallback
}

uint32_t wg_gdi_brush_color(uint32_t hbrush, bool *found) {
    int idx = (int)(hbrush - s_next_brush);
    if (idx >= 0 && idx < MAX_BRUSHES && s_brush_used[idx]) {
        if (found) *found = true;
        return s_brush_color[idx];
    }
    if (found) *found = false;
    return 0x00FFFFFF;
}

// ---- Bitmaps / blitting -------------------------------------------------

uint32_t wg_gdi_create_memory_dc(void) {
    for (int i = 0; i < MAX_DCS; i++) {
        if (!s_dcs[i].used) {
            memset(&s_dcs[i], 0, sizeof(s_dcs[i]));
            s_dcs[i].used = true;
            s_dcs[i].handle = s_next_dc++;
            s_dcs[i].is_memdc = true;
            s_dcs[i].bk_color = 0x00FFFFFF;
            s_dcs[i].bk_mode = 2;
            return s_dcs[i].handle;
        }
    }
    return 0;
}

void wg_gdi_delete_dc(uint32_t hdc) {
    WGDC *dc = find_dc(hdc);
    if (dc) dc->used = false;
}

uint32_t wg_gdi_select_bitmap(uint32_t hdc, uint32_t hbitmap) {
    WGDC *dc = find_dc(hdc);
    if (!dc) return 0;
    uint32_t prev = dc->sel_bitmap;
    dc->sel_bitmap = hbitmap;
    return prev;
}

uint32_t wg_gdi_selected_bitmap(uint32_t hdc) {
    WGDC *dc = find_dc(hdc);
    return dc ? dc->sel_bitmap : 0;
}

// Resolve a DC to the pixel buffer it draws into: a window's client framebuffer
// or, for a memory DC, its selected bitmap. *out_win receives the HWND to mark
// dirty afterwards (0 for a memory DC).
static uint32_t *dc_target(uint32_t hdc, int *w, int *h, uint32_t *out_win) {
    WGDC *dc = find_dc(hdc);
    if (out_win) *out_win = 0;
    if (!dc) return NULL;
    if (dc->is_memdc) {
        return wg_bitmap_pixels(dc->sel_bitmap, w, h);
    }
    int32_t cw, ch;
    uint32_t *fb = wg_wm_get_client(dc->hwnd, &cw, &ch);
    if (!fb) return NULL;
    if (w) *w = cw;
    if (h) *h = ch;
    if (out_win) *out_win = dc->hwnd;
    return fb;
}

// Core stretch-blit from an RGBA8 source rect into a DC's target, nearest
// neighbour, with simple straight-alpha "over" compositing.
static void blit_pixels(uint32_t hdc_dst, int dx, int dy, int dw, int dh,
                        const uint32_t *src, int src_w, int src_h,
                        int sx, int sy, int sw, int sh) {
    if (!src || dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0) return;
    int tw, th; uint32_t win = 0;
    uint32_t *dst = dc_target(hdc_dst, &tw, &th, &win);
    if (!dst) return;

    for (int j = 0; j < dh; j++) {
        int ddy = dy + j;
        if (ddy < 0 || ddy >= th) continue;
        int ssy = sy + (j * sh) / dh;
        if (ssy < 0 || ssy >= src_h) continue;
        for (int i = 0; i < dw; i++) {
            int ddx = dx + i;
            if (ddx < 0 || ddx >= tw) continue;
            int ssx = sx + (i * sw) / dw;
            if (ssx < 0 || ssx >= src_w) continue;
            uint32_t s = src[(size_t)ssy * src_w + ssx];
            uint8_t a = (s >> 24) & 0xFF;
            if (a == 0xFF) {
                dst[(size_t)ddy * tw + ddx] = s;
            } else if (a != 0) {
                uint32_t d = dst[(size_t)ddy * tw + ddx];
                uint32_t sr = s & 0xFF, sg = (s >> 8) & 0xFF, sb = (s >> 16) & 0xFF;
                uint32_t dr = d & 0xFF, dg = (d >> 8) & 0xFF, db = (d >> 16) & 0xFF;
                uint32_t r = (sr * a + dr * (255 - a)) / 255;
                uint32_t g = (sg * a + dg * (255 - a)) / 255;
                uint32_t b = (sb * a + db * (255 - a)) / 255;
                dst[(size_t)ddy * tw + ddx] = r | (g << 8) | (b << 16) | (0xFFu << 24);
            }
        }
    }
    if (win) {
        WGWin32Window *wn = wg_wm_find(win);
        if (wn) wn->client_dirty = true;
    }
}

void wg_gdi_draw_bitmap(uint32_t hdc_dst, int dx, int dy, int dw, int dh,
                        uint32_t hbitmap, int sx, int sy, int sw, int sh) {
    int bw, bh;
    const uint32_t *src = wg_bitmap_pixels(hbitmap, &bw, &bh);
    if (!src) return;
    if (sw <= 0) sw = bw;
    if (sh <= 0) sh = bh;
    if (dw <= 0) dw = sw;
    if (dh <= 0) dh = sh;
    blit_pixels(hdc_dst, dx, dy, dw, dh, src, bw, bh, sx, sy, sw, sh);
}

void wg_gdi_blit(uint32_t hdc_dst, int dx, int dy, int dw, int dh,
                 uint32_t hdc_src, int sx, int sy, int sw, int sh) {
    uint32_t hbmp = wg_gdi_selected_bitmap(hdc_src);
    if (!hbmp) return;
    wg_gdi_draw_bitmap(hdc_dst, dx, dy, dw, dh, hbmp, sx, sy, sw, sh);
}
