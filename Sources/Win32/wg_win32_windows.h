#ifndef WG_WIN32_WINDOWS_H
#define WG_WIN32_WINDOWS_H

#include <stdint.h>
#include <stdbool.h>

#define WG_MAX_WINDOWS 64
#define WG_HWND_BASE   0x00010000

typedef struct {
    uint32_t handle;        // HWND
    int32_t  x, y, w, h;   // position and size
    uint16_t title[256];    // UTF-16 title
    bool     visible;
    bool     alive;
    uint32_t style;
    uint32_t ex_style;
    uint32_t bg_color;      // RGB background
    uint32_t parent;        // parent HWND or 0
    uint32_t class_atom;
    bool     needs_paint;
} WGWin32Window;

typedef struct {
    WGWin32Window windows[WG_MAX_WINDOWS];
    int           count;
    uint32_t      next_handle;
    bool          dirty;    // set when any window changes
} WGWindowManager;

WGWindowManager *wg_wm_get(void);

uint32_t wg_wm_create_window(uint32_t ex_style, uint32_t class_atom,
                              const uint16_t *title,
                              uint32_t style,
                              int32_t x, int32_t y, int32_t w, int32_t h,
                              uint32_t parent);

WGWin32Window *wg_wm_find(uint32_t hwnd);
void     wg_wm_show(uint32_t hwnd, int cmd);
void     wg_wm_destroy(uint32_t hwnd);
void     wg_wm_set_text(uint32_t hwnd, const uint16_t *text);
int      wg_wm_visible_count(void);

#endif
