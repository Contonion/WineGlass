#include "wg_win32_windows.h"
#include "wg_log.h"
#include <string.h>

#define TAG "WM"

static WGWindowManager s_wm = {0};

WGWindowManager *wg_wm_get(void) {
    if (s_wm.next_handle == 0) {
        s_wm.next_handle = WG_HWND_BASE;
    }
    return &s_wm;
}

static int utf16_len(const uint16_t *s) {
    if (!s) return 0;
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void utf16_to_ascii(const uint16_t *src, char *dst, int max) {
    int i;
    for (i = 0; src && src[i] && i < max - 1; i++) {
        dst[i] = (src[i] < 128) ? (char)src[i] : '?';
    }
    dst[i] = '\0';
}

uint32_t wg_wm_create_window(uint32_t ex_style, uint32_t class_atom,
                              const uint16_t *title,
                              uint32_t style,
                              int32_t x, int32_t y, int32_t w, int32_t h,
                              uint32_t parent) {
    WGWindowManager *wm = wg_wm_get();
    if (wm->count >= WG_MAX_WINDOWS) return 0;

    // Default sizes for CW_USEDEFAULT
    if (x == (int32_t)0x80000000) x = 100;
    if (y == (int32_t)0x80000000) y = 100;
    if (w == (int32_t)0x80000000) w = 640;
    if (h == (int32_t)0x80000000) h = 480;
    if (w <= 0) w = 640;
    if (h <= 0) h = 480;

    WGWin32Window *win = &wm->windows[wm->count++];
    memset(win, 0, sizeof(*win));
    win->handle = wm->next_handle++;
    win->x = x;
    win->y = y;
    win->w = w;
    win->h = h;
    win->style = style;
    win->ex_style = ex_style;
    win->parent = parent;
    win->class_atom = class_atom;
    win->alive = true;
    win->visible = (style & 0x10000000) != 0; // WS_VISIBLE
    win->bg_color = 0x2D2D2D; // dark gray default
    win->needs_paint = true;

    if (title) {
        int len = utf16_len(title);
        if (len > 255) len = 255;
        memcpy(win->title, title, len * 2);
        win->title[len] = 0;
    }

    char ascii_title[64];
    utf16_to_ascii(win->title, ascii_title, sizeof(ascii_title));
    WG_LOGI(TAG, "CreateWindow: HWND=0x%X '%s' %dx%d at (%d,%d) parent=0x%X",
            win->handle, ascii_title, w, h, x, y, parent);

    wm->dirty = true;
    return win->handle;
}

WGWin32Window *wg_wm_find(uint32_t hwnd) {
    WGWindowManager *wm = wg_wm_get();
    for (int i = 0; i < wm->count; i++) {
        if (wm->windows[i].handle == hwnd && wm->windows[i].alive)
            return &wm->windows[i];
    }
    return NULL;
}

void wg_wm_show(uint32_t hwnd, int cmd) {
    WGWin32Window *w = wg_wm_find(hwnd);
    if (!w) return;
    bool was_visible = w->visible;
    w->visible = (cmd != 0); // SW_HIDE = 0, everything else shows
    if (w->visible != was_visible) {
        WG_LOGI(TAG, "ShowWindow: HWND=0x%X visible=%d", hwnd, w->visible);
        wg_wm_get()->dirty = true;
    }
}

void wg_wm_destroy(uint32_t hwnd) {
    WGWin32Window *w = wg_wm_find(hwnd);
    if (w) {
        w->alive = false;
        w->visible = false;
        wg_wm_get()->dirty = true;
    }
}

void wg_wm_set_text(uint32_t hwnd, const uint16_t *text) {
    WGWin32Window *w = wg_wm_find(hwnd);
    if (!w) return;
    if (text) {
        int len = utf16_len(text);
        if (len > 255) len = 255;
        memcpy(w->title, text, len * 2);
        w->title[len] = 0;
    }
    wg_wm_get()->dirty = true;
}

int wg_wm_visible_count(void) {
    WGWindowManager *wm = wg_wm_get();
    int n = 0;
    for (int i = 0; i < wm->count; i++) {
        if (wm->windows[i].alive && wm->windows[i].visible) n++;
    }
    return n;
}
