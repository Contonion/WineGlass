#include "wg_engine.h"
#include "wg_log.h"
#include "wg_pe_loader.h"
#include "wg_x86_state.h"
#include "wg_x86_interp.h"
#include "wg_memory.h"
#include "wg_dll_mapper.h"
#include "wg_blink_bridge.h"
#include "wg_win32_windows.h"
#include "wg_win32_files.h"
#include "wg_win32_gdi.h"
#include "wg_win32_bitmap.h"
#include "wg_nsis_extract.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>

// Recursively delete a directory and its contents (used to give NSIS a fresh
// plugins temp dir when a stale one survives from a prior run).
static void wg_rmtree(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *e;
        char child[1024];
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            struct stat st;
            if (stat(child, &st) == 0 && S_ISDIR(st.st_mode)) wg_rmtree(child);
            else unlink(child);
        }
        closedir(d);
    }
    rmdir(path);
}

#define TAG "Engine"

typedef enum {
    WG_BACKEND_BUILTIN,
    WG_BACKEND_BLINK,
} WGBackend;

static uint32_t s_last_error = 0;
static bool s_nsis_data_patched = false;
// A/B diagnostic toggle for the NSIS solid-LZMA data section.
//   1 = pre-decompress the data .tmp natively (LzmaDec) and ignore the guest's
//       own writes to it. The current workaround, on the theory that blink
//       truncates NSIS's in-guest decode.
//   0 = let NSIS decompress the stream itself, so we can test whether its
//       native decode actually works (blink CALL/RET is confirmed fine — the
//       failing self-test was a no-stack harness artifact). When 0,
//       s_nsis_data_tmp_handle stays 0, which also makes the "ignore writes"
//       branch in WriteFile inert, so NSIS's decode lands on disk normally.
// Flip this and rebuild to compare the two paths on-device. Overridable from
// the build (e.g. OTHER_CFLAGS: -DWG_NSIS_PREFILL_HACK=0) without editing here.
#ifndef WG_NSIS_PREFILL_HACK
#define WG_NSIS_PREFILL_HACK 0
#endif

// Guest heap pointer for GlobalAlloc/etc. Reset per program load so behavior
// is deterministic (not dependent on prior runs in the same app session).
#define WG_GUEST_HEAP_BASE 0x20000000u
static uint32_t s_heap_ptr = WG_GUEST_HEAP_BASE;
static uint32_t s_nsis_exe_data_offset = 0;
static uint32_t s_nsis_data_tmp_handle = 0;    // handle to the NSIS data .tmp file
static uint32_t s_nsis_last_data_seek = 0;     // last seek position in data .tmp
static char s_nsis_data_tmp_path[1024] = {0};  // real path of data .tmp

#ifdef WG_DECODE_DIAG
// Local-repro diagnostic: diff NSIS's own in-guest decode (written to the data
// .tmp when prefill is off) against the reference stream in /tmp/ref.bin, to
// find the first byte where blink's decode diverges. Zero-cost unless defined.
static uint32_t s_diag_data_tmp_handle = 0;
static uint8_t *s_diag_ref = NULL;
static long     s_diag_ref_len = 0;
static int      s_diag_reported = 0;
static void wg_diag_check(uint32_t pos, const uint8_t *buf, uint32_t n) {
    if (s_diag_reported) return;
    if (!s_diag_ref) {
        FILE *r = fopen("/tmp/ref.bin", "rb");
        if (!r) { s_diag_reported = 1; return; }
        fseek(r, 0, SEEK_END); s_diag_ref_len = ftell(r); fseek(r, 0, SEEK_SET);
        s_diag_ref = (uint8_t *)malloc(s_diag_ref_len);
        if (!s_diag_ref || fread(s_diag_ref, 1, s_diag_ref_len, r) != (size_t)s_diag_ref_len) {
            s_diag_reported = 1; fclose(r); return;
        }
        fclose(r);
        WG_LOGI("DIAG", "ref.bin loaded (%ld bytes)", s_diag_ref_len);
    }
    for (uint32_t i = 0; i < n; i++) {
        long off = (long)pos + i;
        if (off >= s_diag_ref_len) break;
        if (buf[i] != s_diag_ref[off]) {
            WG_LOGE("DIAG", "DECODE DIVERGES at decompressed offset %ld: "
                    "guest=0x%02X ref=0x%02X (correct for %ld bytes)",
                    off, buf[i], s_diag_ref[off], off);
            // dump a little context
            WG_LOGE("DIAG", "  ref [%ld..]: %02X %02X %02X %02X %02X %02X %02X %02X",
                    off, s_diag_ref[off], s_diag_ref[off+1], s_diag_ref[off+2],
                    s_diag_ref[off+3], s_diag_ref[off+4], s_diag_ref[off+5],
                    s_diag_ref[off+6], s_diag_ref[off+7]);
            WG_LOGE("DIAG", "  got [%ld..]: %02X %02X %02X %02X %02X %02X %02X %02X",
                    off, buf[i], (i+1<n?buf[i+1]:0), (i+2<n?buf[i+2]:0),
                    (i+3<n?buf[i+3]:0), (i+4<n?buf[i+4]:0), (i+5<n?buf[i+5]:0),
                    (i+6<n?buf[i+6]:0), (i+7<n?buf[i+7]:0));
            s_diag_reported = 1;
            return;
        }
    }
}
#endif

struct WGEngine {
    WGEngineState   state;
    WGBackend       backend;

    // Builtin interpreter
    WGMemorySpace  *memory;
    WGx86State     *cpu;

    // Blink engine
    WGBlinkInstance *blink;

    // Shared
    WGPEImage      *pe_image;
    WGDllMapper    *dll_mapper;
    uint64_t        tick_count;
    int             instructions_per_tick;
    bool            thunks_mapped; // whether HLT stubs are in blink memory
};

WGEngine *wg_engine_create(void) {
    WGEngine *e = calloc(1, sizeof(WGEngine));
    if (!e) return NULL;
    e->state = WG_ENGINE_IDLE;
    e->instructions_per_tick = 100000;
    e->backend = WG_BACKEND_BLINK;
    return e;
}

void wg_engine_destroy(WGEngine *engine) {
    if (!engine) return;
    wg_engine_stop(engine);
    if (engine->cpu) wg_x86_state_destroy(engine->cpu);
    if (engine->memory) wg_memory_destroy(engine->memory);
    if (engine->pe_image) wg_pe_image_free(engine->pe_image);
    if (engine->dll_mapper) wg_dll_mapper_destroy(engine->dll_mapper);
    if (engine->blink) wg_blink_destroy(engine->blink);
    free(engine);
}

// Map Win32 API thunk addresses into blink's memory.
// Each thunk is a tiny x86 stub: RET (pop return address and go back).
// When the engine detects RIP landed on a thunk after a step, it
// calls the Win32 stub handler before resuming.
//
// Layout at each thunk address (8 bytes apart):
//   [thunk+0] HLT   (0xF4) — stops execution
// The engine sees the halt, checks if RIP is in the thunk range,
// runs the stub, pops the return address, and resumes.
static void map_thunks_to_blink(WGEngine *engine) {
    if (!engine->blink || !engine->dll_mapper || engine->thunks_mapped) return;

    // For 32-bit PEs, thunks must be within 16MB (kRealSize).
    // Use 0xC00000 (12MB mark) for 32-bit, WG_THUNK_BASE for 64-bit.
    bool is_32bit = (engine->pe_image && !engine->pe_image->is_64bit);
    uint64_t thunk_base = is_32bit ? 0xC00000ULL : WG_THUNK_BASE;

    // Reassign thunk addresses to the correct range
    engine->dll_mapper->next_thunk = thunk_base;
    for (int i = 0; i < engine->dll_mapper->count; i++) {
        engine->dll_mapper->entries[i].thunk_addr = thunk_base + i * 8;
    }
    engine->dll_mapper->next_thunk = thunk_base + engine->dll_mapper->count * 8;

    uint32_t thunk_region_size = 0x20000; // 128KB
    uint8_t *thunk_page = calloc(1, thunk_region_size);
    if (!thunk_page) return;

    memset(thunk_page, 0xF4, thunk_region_size); // fill with HLT

    wg_blink_load_code(engine->blink, thunk_base, thunk_page,
                       thunk_region_size, 0);
    free(thunk_page);

    engine->thunks_mapped = true;
    WG_LOGI(TAG, "Win32 API thunks mapped at 0x%llX (%d stubs)",
            (unsigned long long)thunk_base, engine->dll_mapper->count);
}

// ============================================================
//  Modal dialogs + control rendering (NSIS wizard UI)
// ============================================================
#define WG_DLG_SENTINEL    0xC10000u    // dlgproc return trap (HLT-filled page)
#define WG_CTRL_HWND_BASE  0x00C70000u  // synthetic control HWND range

static bool     s_dlg_active = false;
static uint32_t s_dlg_ret_addr = 0;     // WinMain return for DialogBoxParamW
static uint32_t s_dlg_ret_rsp  = 0;     // RSP to restore on EndDialog
static uint32_t s_dlg_hwnd     = 0;     // the modal dialog window
static uint32_t s_dlg_proc     = 0;     // the dialog procedure (for WM_COMMAND)
static uint32_t s_dlg_result   = 1;

typedef struct {
    uint32_t hwnd;            // owning dialog window
    uint32_t id;              // control id
    uint32_t style;
    int16_t  x, y, cx, cy;    // dialog units
    int16_t  dlg_cx, dlg_cy;  // this dialog's unit extent (for scaling)
    uint16_t cls;             // 0x80 button, 0x82 static, 0x81 edit, ...
    bool     is_bitmap;       // SS_BITMAP static
    uint32_t hbitmap;
    uint16_t text[80];
} WGDlgCtrl;
static WGDlgCtrl s_ctrls[160];
static int       s_ctrl_count = 0;
static int       s_dlg_cx = 331, s_dlg_cy = 222; // last-parsed dialog-unit extent

static WGDlgCtrl *wg_find_ctrl(uint32_t hwnd, uint32_t id) {
    for (int i = 0; i < s_ctrl_count; i++)
        if (s_ctrls[i].hwnd == hwnd && s_ctrls[i].id == id) return &s_ctrls[i];
    return NULL;
}
static WGDlgCtrl *wg_ctrl_from_handle(uint32_t h) {
    if (h >= WG_CTRL_HWND_BASE && h < WG_CTRL_HWND_BASE + 160) {
        int idx = (int)(h - WG_CTRL_HWND_BASE);
        if (idx < s_ctrl_count) return &s_ctrls[idx];
    }
    return NULL;
}

// ---- PE resource access (parse the dialog template from the .rsrc) ----
static const uint8_t *pe_rva(WGPEImage *pe, uint32_t rva) {
    for (int i = 0; i < pe->num_sections; i++) {
        WGPESection *s = &pe->sections[i];
        if (rva >= s->virtual_address && rva < s->virtual_address + s->raw_size)
            return pe->raw_data + s->raw_offset + (rva - s->virtual_address);
    }
    return NULL;
}
static const uint8_t *pe_find_dialog(WGPEImage *pe, uint32_t dlg_id) {
    if (!pe->raw_data) return NULL;
    uint32_t e_lfanew; memcpy(&e_lfanew, pe->raw_data + 0x3C, 4);
    uint32_t rsrc_rva; memcpy(&rsrc_rva, pe->raw_data + e_lfanew + 24 + 112, 4);
    const uint8_t *base = pe_rva(pe, rsrc_rva);
    if (!base) return NULL;
    uint16_t nN, nI;
    memcpy(&nN, base + 12, 2); memcpy(&nI, base + 14, 2);
    for (int i = 0; i < nN + nI; i++) {
        const uint8_t *e = base + 16 + i * 8;
        uint32_t nameid, off; memcpy(&nameid, e, 4); memcpy(&off, e + 4, 4);
        if (nameid != 5 /*RT_DIALOG*/ || !(off & 0x80000000u)) continue;
        const uint8_t *l1 = base + (off & 0x7fffffff);
        uint16_t a, b; memcpy(&a, l1 + 12, 2); memcpy(&b, l1 + 14, 2);
        for (int j = 0; j < a + b; j++) {
            const uint8_t *e1 = l1 + 16 + j * 8;
            uint32_t id, o1; memcpy(&id, e1, 4); memcpy(&o1, e1 + 4, 4);
            if ((id & 0x7fffffff) != dlg_id || !(o1 & 0x80000000u)) continue;
            const uint8_t *l2 = base + (o1 & 0x7fffffff);
            uint32_t o2; memcpy(&o2, l2 + 16 + 4, 4);          // first lang's data-entry off
            const uint8_t *de = base + (o2 & 0x7fffffff);
            uint32_t data_rva; memcpy(&data_rva, de, 4);
            return pe_rva(pe, data_rva);
        }
    }
    return NULL;
}
static const uint8_t *res_skip_sz(const uint8_t *p, uint16_t *out, int cap) {
    uint16_t v; memcpy(&v, p, 2);
    if (v == 0)      { if (out) out[0] = 0; return p + 2; }
    if (v == 0xFFFF) { if (out) out[0] = 0; return p + 4; }
    int k = 0;
    for (;;) { uint16_t c; memcpy(&c, p, 2); p += 2; if (!c) break;
               if (out && k < cap - 1) out[k++] = c; }
    if (out) out[k] = 0;
    return p;
}
static void wg_remove_ctrls(uint32_t hwnd) {
    int n = 0;
    for (int i = 0; i < s_ctrl_count; i++)
        if (s_ctrls[i].hwnd != hwnd) s_ctrls[n++] = s_ctrls[i];
    s_ctrl_count = n;
}
static void wg_parse_dialog(WGEngine *engine, uint32_t hwnd, uint32_t dlg_id) {
    wg_remove_ctrls(hwnd);          // replace this window's controls
    if (!engine->pe_image) return;
    const uint8_t *t = pe_find_dialog(engine->pe_image, dlg_id);
    if (!t) { WG_LOGI(TAG, "dialog %u: no template", dlg_id); return; }
    uint16_t dlgVer, sig; memcpy(&dlgVer, t, 2); memcpy(&sig, t + 2, 2);
    if (dlgVer != 1 || sig != 0xFFFF) return;   // only DLGTEMPLATEEX
    const uint8_t *p = t + 4 + 4 + 4;           // skip dlgVer/sig, helpID, exStyle
    uint32_t style; memcpy(&style, p, 4); p += 4;
    uint16_t cItems; memcpy(&cItems, p, 2); p += 2;
    p += 4;                                     // x, y
    int16_t dcx, dcy;
    memcpy(&dcx, p, 2); p += 2;
    memcpy(&dcy, p, 2); p += 2;
    s_dlg_cx = dcx; s_dlg_cy = dcy;
    p = res_skip_sz(p, NULL, 0);                // menu
    p = res_skip_sz(p, NULL, 0);                // class
    p = res_skip_sz(p, NULL, 0);                // title
    if (style & 0x40 /*DS_SETFONT*/) { p += 6; p = res_skip_sz(p, NULL, 0); }
    for (int i = 0; i < cItems && s_ctrl_count < 160; i++) {
        size_t aoff = ((size_t)(p - t) + 3) & ~(size_t)3; p = t + aoff;  // dword align
        p += 4 + 4;                             // helpID, exStyle
        uint32_t cstyle; memcpy(&cstyle, p, 4); p += 4;
        WGDlgCtrl *c = &s_ctrls[s_ctrl_count++];
        memset(c, 0, sizeof(*c));
        c->hwnd = hwnd; c->style = cstyle;
        c->dlg_cx = dcx; c->dlg_cy = dcy;
        memcpy(&c->x, p, 2); memcpy(&c->y, p + 2, 2);
        memcpy(&c->cx, p + 4, 2); memcpy(&c->cy, p + 6, 2); p += 8;
        memcpy(&c->id, p, 4); p += 4;
        uint16_t w0; memcpy(&w0, p, 2);
        if (w0 == 0xFFFF) { memcpy(&c->cls, p + 2, 2); p += 4; }
        else { p = res_skip_sz(p, NULL, 0); c->cls = 0; }
        c->is_bitmap = (c->cls == 0x0082) && ((cstyle & 0x0F) == 0x0E /*SS_BITMAP*/);
        p = res_skip_sz(p, c->text, 80);        // title
        uint16_t extra; memcpy(&extra, p, 2); p += 2 + extra;
    }
    WG_LOGI(TAG, "dialog %u parsed: %d controls (%dx%d du)",
            dlg_id, s_ctrl_count, s_dlg_cx, s_dlg_cy);
}

// Paint the parsed controls into the dialog's client framebuffer.
static void wg_render_dialog(WGEngine *engine, uint32_t hwnd) {
    (void)engine;
    int32_t cw = 0, ch = 0;
    if (!wg_wm_get_client(hwnd, &cw, &ch)) return;
    uint32_t dc = wg_gdi_get_dc(hwnd);
    if (!dc) return;
    wg_gdi_fill_rect(dc, 0, 0, cw, ch, 0x00FFFFFF);          // white dialog bg
    for (int i = 0; i < s_ctrl_count; i++) {
        WGDlgCtrl *c = &s_ctrls[i];
        if (c->hwnd != hwnd) continue;
        if (!(c->style & 0x10000000u /*WS_VISIBLE*/)) continue;
        float sx = c->dlg_cx ? (float)cw / c->dlg_cx : 1.0f;
        float sy = c->dlg_cy ? (float)ch / c->dlg_cy : 1.0f;
        int px = (int)(c->x * sx), py = (int)(c->y * sy);
        int pw = (int)(c->cx * sx), ph = (int)(c->cy * sy);
        int tlen = 0; while (tlen < 79 && c->text[tlen]) tlen++;
        if (c->cls == 0x0080) {                 // button (incl. group box)
            if ((c->style & 0x07) == 0x07 /*BS_GROUPBOX*/) {
                // frame + caption, no fill
                wg_gdi_fill_rect(dc, px, py, px + pw, py + 1, 0x00A0A0A0);
                if (tlen) wg_gdi_text_out(dc, px + 6, py - 4, c->text, tlen);
            } else {
                wg_gdi_fill_rect(dc, px, py, px + pw, py + ph, 0x00E1E1E1);
                int tx = px + 6;
                if (tlen) wg_gdi_text_out(dc, tx, py + (ph - 8) / 2, c->text, tlen);
            }
        } else if (c->cls == 0x0082) {          // static
            if (c->is_bitmap && c->hbitmap)
                wg_gdi_draw_bitmap(dc, px, py, pw, ph, c->hbitmap, 0, 0, 0, 0);
            else if (tlen)
                wg_gdi_text_out(dc, px, py, c->text, tlen);
        } else if (c->cls == 0x0081) {          // edit box
            wg_gdi_fill_rect(dc, px, py, px + pw, py + ph, 0x00FFFFFF);
            wg_gdi_fill_rect(dc, px, py, px + pw, py + 1, 0x00808080);   // top border
            wg_gdi_fill_rect(dc, px, py, px + 1, py + ph, 0x00808080);   // left border
            if (tlen) wg_gdi_text_out(dc, px + 3, py + (ph - 8) / 2, c->text, tlen);
        }
    }
    wg_gdi_release_dc(dc);
    WGWin32Window *w = wg_wm_find(hwnd);
    if (w) w->client_dirty = true;
}

// ---- Synchronous SendMessage / wndproc dispatch ----
// SendMessage must call the target window's procedure and return its result.
// We do this by jumping into the wndproc with a dedicated sentinel return; when
// it returns, the sentinel restores the SendMessage caller with the result. A
// small stack handles nested SendMessages (NSIS nests them heavily).
#define WG_SENDMSG_SENTINEL 0xC10010u
typedef struct { uint32_t ret_addr, ret_rsp, ovr_eax; bool ovr; } WGPendingCall;
static WGPendingCall s_callstack[64];
static int           s_callstack_depth = 0;

static uint32_t wg_resolve_wndproc(uint32_t hwnd) {
    if (hwnd == s_dlg_hwnd && s_dlg_proc) return s_dlg_proc;
    WGWin32Window *w = wg_wm_find(hwnd);
    return (w && w->wndproc) ? w->wndproc : 0;
}

// Set up a nested call proc(hwnd, msg, wParam, lParam) returning to the given
// caller (ret_addr/clean_rsp) with the proc's EAX. Returns true if armed.
static bool wg_call_wndproc_ovr(WGEngine *engine, uint32_t proc, uint32_t hwnd,
                                uint32_t msg, uint32_t wp, uint32_t lp,
                                uint32_t ret_addr, uint32_t clean_rsp,
                                bool ovr, uint32_t ovr_eax) {
    if (!proc || s_callstack_depth >= 64) return false;
    s_callstack[s_callstack_depth].ret_addr = ret_addr;
    s_callstack[s_callstack_depth].ret_rsp  = clean_rsp;
    s_callstack[s_callstack_depth].ovr      = ovr;
    s_callstack[s_callstack_depth].ovr_eax  = ovr_eax;
    s_callstack_depth++;
    uint32_t new_rsp = clean_rsp - 20;
    uint32_t sd[5] = { WG_SENDMSG_SENTINEL, hwnd, msg, wp, lp };
    wg_blink_write_mem(engine->blink, new_rsp, sd, 20);
    wg_blink_set_reg(engine->blink, 4, new_rsp);
    wg_blink_set_rip(engine->blink, proc);
    wg_blink_set_reg(engine->blink, 0, 0);
    return true;
}
static bool wg_call_wndproc(WGEngine *engine, uint32_t proc, uint32_t hwnd,
                            uint32_t msg, uint32_t wp, uint32_t lp,
                            uint32_t ret_addr, uint32_t clean_rsp) {
    return wg_call_wndproc_ovr(engine, proc, hwnd, msg, wp, lp,
                               ret_addr, clean_rsp, false, 0);
}

// Check if RIP is in the thunk range and handle the Win32 API call.
// Returns true if a thunk was handled.
static bool handle_blink_thunk(WGEngine *engine) {
    uint64_t rip = wg_blink_get_rip(engine->blink);

    // Check both 32-bit (0xC00000) and 64-bit (0xDEAD0000) thunk ranges
    bool in_thunk_range = false;
    if (rip >= 0xC00000ULL && rip < 0xC00000ULL + 0x20000) in_thunk_range = true;
    if (rip >= WG_THUNK_BASE && rip < WG_THUNK_BASE + 0x20000) in_thunk_range = true;
    if (!in_thunk_range) return false;

    // Modal-dialog return trap: the dlgproc has returned from WM_INITDIALOG, so
    // the dialog is now up. Paint its controls and pause (modal) — we stay here
    // until the guest calls EndDialog (which returns control to WinMain).
    if (rip == WG_DLG_SENTINEL) {
        if (s_dlg_active && s_dlg_hwnd) wg_render_dialog(engine, s_dlg_hwnd);
        engine->state = WG_ENGINE_PAUSED;
        WG_LOGI(TAG, "Dialog up (HWND=0x%X) — modal, waiting", s_dlg_hwnd);
        return true;
    }
    // A SendMessage'd wndproc just returned — hand its result back to the
    // SendMessage caller (and re-render in case the page content changed).
    if (rip == WG_SENDMSG_SENTINEL) {
        uint32_t result = (uint32_t)wg_blink_get_reg(engine->blink, 0);
        if (s_callstack_depth > 0) {
            s_callstack_depth--;
            WGPendingCall *pc = &s_callstack[s_callstack_depth];
            // CreateDialog dispatches WM_INITDIALOG but must still return the
            // HWND, not the dlgproc's result — that's what ovr_eax carries.
            if (pc->ovr) result = pc->ovr_eax;
            wg_blink_set_reg(engine->blink, 4, pc->ret_rsp);
            wg_blink_set_rip(engine->blink, pc->ret_addr);
            wg_blink_set_reg(engine->blink, 0, result);
            if (s_dlg_active && s_dlg_hwnd) wg_render_dialog(engine, s_dlg_hwnd);
        } else {
            wg_blink_set_rip(engine->blink, 0);
        }
        return true;
    }

    WGWin32StubFunc handler = wg_dll_mapper_get_handler(
        engine->dll_mapper, rip);

    // Find the entry for this thunk
    WGDllEntry *entry = NULL;
    for (int i = 0; i < engine->dll_mapper->count; i++) {
        if (engine->dll_mapper->entries[i].thunk_addr == rip) {
            entry = &engine->dll_mapper->entries[i];
            break;
        }
    }

    if (entry) {
        // Suppress noisy repetitive calls
        static const char *quiet_funcs[] = {
            "GetTickCount", "CharNextW", "CharNextA",
            "CharPrevW", "lstrcpynW", "lstrlenW", "lstrcatW",
            "lstrcmpiW", "GlobalAlloc", "GlobalFree",
            "ReadFile", "WriteFile",
            "PeekMessageW", "lstrlenA", NULL
        };
        bool quiet = false;
        for (int i = 0; quiet_funcs[i]; i++) {
            if (strcmp(entry->func_name, quiet_funcs[i]) == 0) { quiet = true; break; }
        }
        if (!quiet) {
            WG_LOGI(TAG, "Win32: %s!%s", entry->dll_name, entry->func_name);
        }
    }

    // Determine pointer size (32-bit PE uses 4-byte pointers)
    bool is_32bit = (engine->pe_image && !engine->pe_image->is_64bit);
    int ptr_size = is_32bit ? 4 : 8;

    // Read return address from stack
    uint64_t rsp = wg_blink_get_reg(engine->blink, 4); // RSP
    uint64_t ret_addr = 0;
    if (is_32bit) {
        uint32_t r32;
        wg_blink_read_mem(engine->blink, rsp, &r32, 4);
        ret_addr = r32;
    } else {
        wg_blink_read_mem(engine->blink, rsp, &ret_addr, 8);
    }

    // For 32-bit cdecl/stdcall, arguments are on the stack after the return address
    // Read up to 12 args (enough for CreateWindowExW which has 12 params)
    uint32_t args[12] = {0};
    if (is_32bit) {
        wg_blink_read_mem(engine->blink, rsp + 4, args, sizeof(args));
    }

    // Default return value
    uint64_t ret_val = 0;

    // Handle specific Win32 functions that affect visual output
    if (entry) {
        const char *fn = entry->func_name;

        if (strcmp(fn, "CreateWindowExW") == 0) {
            // stdcall CreateWindowExW(exStyle, className, windowName, style,
            //                         x, y, w, h, parent, menu, instance, param)
            // args[0]=exStyle, args[1]=className, args[2]=windowName, args[3]=style
            // args[4]=x, args[5]=y, args[6]=w, args[7]=h, args[8]=parent
            uint16_t title_buf[256] = {0};
            if (args[2]) {
                wg_blink_read_mem(engine->blink, args[2], title_buf, 510);
            }
            ret_val = wg_wm_create_window(args[0], args[1], title_buf,
                                          args[3], (int32_t)args[4], (int32_t)args[5],
                                          (int32_t)args[6], (int32_t)args[7], args[8]);
        } else if (strcmp(fn, "ShowWindow") == 0) {
            wg_wm_show(args[0], args[1]);
            ret_val = 1;
        } else if (strcmp(fn, "DestroyWindow") == 0) {
            wg_wm_destroy(args[0]);
            wg_remove_ctrls(args[0]);   // drop the page's controls
            ret_val = 1;
        } else if (strcmp(fn, "SetWindowTextW") == 0) {
            uint16_t text_buf[256] = {0};
            if (args[1]) {
                wg_blink_read_mem(engine->blink, args[1], text_buf, 510);
            }
            wg_wm_set_text(args[0], text_buf);
            ret_val = 1;
        } else if (strcmp(fn, "GetClientRect") == 0 || strcmp(fn, "GetWindowRect") == 0) {
            WGWin32Window *w = wg_wm_find(args[0]);
            if (w && args[1]) {
                int32_t rect[4] = {0, 0, w->w, w->h};
                if (strcmp(fn, "GetWindowRect") == 0) {
                    rect[0] = w->x; rect[1] = w->y;
                    rect[2] = w->x + w->w; rect[3] = w->y + w->h;
                }
                wg_blink_write_mem(engine->blink, args[1], rect, 16);
            }
            ret_val = 1;
        } else if (strcmp(fn, "GetDC") == 0 || strcmp(fn, "BeginPaint") == 0) {
            uint32_t dc = wg_gdi_get_dc(args[0]);
            // BeginPaint: fill PAINTSTRUCT.hdc (offset 0) if provided
            if (strcmp(fn, "BeginPaint") == 0 && args[1]) {
                wg_blink_write_mem(engine->blink, args[1], &dc, 4);
            }
            ret_val = dc;
        } else if (strcmp(fn, "ReleaseDC") == 0) {
            wg_gdi_release_dc(args[1]);
            ret_val = 1;
        } else if (strcmp(fn, "CreateSolidBrush") == 0) {
            ret_val = wg_gdi_create_solid_brush(args[0]);
        } else if (strcmp(fn, "SetTextColor") == 0) {
            wg_gdi_set_text_color(args[0], args[1]);
            ret_val = 0;
        } else if (strcmp(fn, "SetBkColor") == 0) {
            wg_gdi_set_bk_color(args[0], args[1]);
            ret_val = 0;
        } else if (strcmp(fn, "SetBkMode") == 0) {
            wg_gdi_set_bk_mode(args[0], (int)args[1]);
            ret_val = 1;
        } else if (strcmp(fn, "FillRect") == 0) {
            int32_t rc[4] = {0,0,0,0};
            if (args[1]) wg_blink_read_mem(engine->blink, args[1], rc, 16);
            bool found = false;
            uint32_t color = wg_gdi_brush_color(args[2], &found);
            // System color brushes (COLOR_WINDOW+1 etc.) come in as small ints
            if (!found) color = 0x00FFFFFF; // default white
            wg_gdi_fill_rect(args[0], rc[0], rc[1], rc[2], rc[3], color);
            ret_val = 1;
        } else if (strcmp(fn, "TextOutW") == 0) {
            int count = (int)args[4];
            if (count < 0) count = 0;
            if (count > 1024) count = 1024;
            uint16_t buf[1025];
            if (args[3] && count > 0)
                wg_blink_read_mem(engine->blink, args[3], buf, count * 2);
            wg_gdi_text_out(args[0], (int)args[1], (int)args[2], buf, count);
            ret_val = 1;
        } else if (strcmp(fn, "MoveToEx") == 0) {
            wg_gdi_move_to(args[0], (int)args[1], (int)args[2]);
            ret_val = 1;
        } else if (strcmp(fn, "LineTo") == 0) {
            wg_gdi_line_to(args[0], (int)args[1], (int)args[2]);
            ret_val = 1;
        } else if (strcmp(fn, "LoadImageW") == 0) {
            // LoadImageW(hInst, name, type, cx, cy, fuLoad)
            // We support IMAGE_BITMAP (type 0) loaded from a file
            // (LR_LOADFROMFILE = 0x10) — that's how NSIS pulls in the wizard's
            // header/branding BMPs it just extracted to $PLUGINSDIR.
            uint32_t type = args[2];
            uint32_t fuLoad = args[5];
            ret_val = 0;
            if (type == 0 /*IMAGE_BITMAP*/ && (fuLoad & 0x10) && args[1]) {
                uint16_t wpath[260] = {0};
                char apath[260] = {0};
                wg_blink_read_mem(engine->blink, args[1], wpath, 518);
                for (int i = 0; i < 259 && wpath[i]; i++)
                    apath[i] = wpath[i] < 128 ? (char)wpath[i] : '_';
                const char *real = wg_files_map_path(args[1], engine->blink,
                                                     apath, sizeof(apath));
                if (real) ret_val = wg_bitmap_load_file(real);
                WG_LOGI(TAG, "LoadImageW('%s') -> HBITMAP 0x%X", apath,
                        (uint32_t)ret_val);
            }
        } else if (strcmp(fn, "CreateCompatibleDC") == 0) {
            ret_val = wg_gdi_create_memory_dc();
        } else if (strcmp(fn, "DeleteDC") == 0) {
            wg_gdi_delete_dc(args[0]);
            ret_val = 1;
        } else if (strcmp(fn, "CreateCompatibleBitmap") == 0) {
            // (hdc, w, h)
            ret_val = wg_bitmap_create((int)args[1], (int)args[2]);
        } else if (strcmp(fn, "SelectObject") == 0) {
            // (hdc, hgdiobj) — we only track bitmaps; for anything else return
            // a benign non-zero "previous object" the caller can restore.
            if (wg_bitmap_is(args[1])) {
                uint32_t prev = wg_gdi_select_bitmap(args[0], args[1]);
                ret_val = prev ? prev : 1;
            } else {
                ret_val = 1;
            }
        } else if (strcmp(fn, "DeleteObject") == 0) {
            if (wg_bitmap_is(args[0])) wg_bitmap_delete(args[0]);
            ret_val = 1;
        } else if (strcmp(fn, "GetObjectW") == 0) {
            // (hgdiobj, cb, lpvObject) — fill a BITMAP struct for bitmaps.
            int bw, bh;
            if (wg_bitmap_pixels(args[0], &bw, &bh) && args[2] && args[1] >= 24) {
                int32_t bm[6] = {
                    0,                  // bmType
                    bw,                 // bmWidth
                    bh,                 // bmHeight
                    bw * 4,             // bmWidthBytes
                    (int32_t)((1u << 16) | 32u), // bmPlanes=1, bmBitsPixel=32
                    0                   // bmBits (NULL)
                };
                wg_blink_write_mem(engine->blink, args[2], bm, 24);
                ret_val = 24;
            } else {
                ret_val = 0;
            }
        } else if (strcmp(fn, "BitBlt") == 0) {
            // (hdcDst, x, y, w, h, hdcSrc, sx, sy, rop)
            wg_gdi_blit(args[0], (int)args[1], (int)args[2], (int)args[3],
                        (int)args[4], args[5], (int)args[6], (int)args[7],
                        (int)args[3], (int)args[4]);
            ret_val = 1;
        } else if (strcmp(fn, "StretchBlt") == 0) {
            // (hdcDst, x, y, w, h, hdcSrc, sx, sy, sw, sh, rop)
            wg_gdi_blit(args[0], (int)args[1], (int)args[2], (int)args[3],
                        (int)args[4], args[5], (int)args[6], (int)args[7],
                        (int)args[8], (int)args[9]);
            ret_val = 1;
        } else if (strcmp(fn, "StretchDIBits") == 0 ||
                   strcmp(fn, "SetDIBitsToDevice") == 0) {
            // StretchDIBits(hdc, xD,yD,wD,hD, xS,yS,wS,hS, bits, bmi, usage, rop)
            // SetDIBitsToDevice(hdc, xD,yD, w,h, xS,yS, startScan,scanLines,
            //                   bits, bmi, usage)
            // Both hand us a packed DIB in guest memory; decode and blit it.
            // (StretchDIBits' stretch to a different src size is approximated by
            // drawing the DIB at its natural size into the dest rect.)
            // lpBits and lpbmi sit at the same arg slots (9, 10) in both APIs,
            // as do the destination width/height (3, 4).
            uint32_t bits_addr = args[9];
            uint32_t bmi_addr  = args[10];
            if (bmi_addr && bits_addr) {
                uint8_t bih[40] = {0};
                wg_blink_read_mem(engine->blink, bmi_addr, bih, 40);
                int32_t biW = (int32_t)(bih[4] | (bih[5]<<8) | (bih[6]<<16) | (bih[7]<<24));
                int32_t biH = (int32_t)(bih[8] | (bih[9]<<8) | (bih[10]<<16) | (bih[11]<<24));
                uint16_t biBpp = (uint16_t)(bih[14] | (bih[15]<<8));
                int aH = biH < 0 ? -biH : biH;
                if (biW > 0 && aH > 0 && biW <= 16384 && aH <= 16384 &&
                    (biBpp == 8 || biBpp == 24 || biBpp == 32)) {
                    size_t stride = ((size_t)biW * (biBpp/8) + 3) & ~(size_t)3;
                    size_t total = stride * aH;
                    if (total <= 64u*1024*1024) {
                        uint8_t *px = (uint8_t *)malloc(total);
                        if (px) {
                            wg_blink_read_mem(engine->blink, bits_addr, px, (uint32_t)total);
                            uint32_t hb = wg_bitmap_from_dib(bih, px);
                            free(px);
                            if (hb) {
                                wg_gdi_draw_bitmap(args[0], (int)args[1], (int)args[2],
                                                   (int)args[3], (int)args[4],
                                                   hb, 0, 0, 0, 0);
                                wg_bitmap_delete(hb);
                            }
                        }
                    }
                }
                ret_val = aH;
            }
        } else if (strcmp(fn, "SetStretchBltMode") == 0) {
            ret_val = 1;
        } else if (strcmp(fn, "DefWindowProcW") == 0 ||
                   strcmp(fn, "TranslateMessage") == 0 ||
                   strcmp(fn, "DispatchMessageW") == 0) {
            ret_val = 0;
        } else if (strcmp(fn, "GetMessageW") == 0) {
            // Blocking message pump. Zero the MSG (WM_NULL) so the guest's
            // Translate/Dispatch are benign, return 1 to keep the loop alive,
            // and pause so the window stays on screen for the user.
            if (args[0]) {
                uint8_t zero[28] = {0};
                wg_blink_write_mem(engine->blink, args[0], zero, 28);
            }
            engine->state = WG_ENGINE_PAUSED;
            WG_LOGI(TAG, "GetMessageW — window up, pausing for UI");
            ret_val = 1;
        } else if (strcmp(fn, "ExitProcess") == 0) {
            WG_LOGI(TAG, "ExitProcess(%u) called", args[0]);
            wg_blink_set_reg(engine->blink, 4, rsp + ptr_size);
            wg_blink_set_rip(engine->blink, 0);
            return true;
        } else if (strcmp(fn, "GetProcAddress") == 0) {
            // GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
            uint32_t hmod = args[0];
            uint32_t name_ptr = args[1];

            // Figure out which DLL this module handle might be
            const char *dll = "KERNEL32.dll";
            // TODO: track module handles to DLL names properly

            if (name_ptr > 0xFFFF) {
                char func_name[256] = {0};
                wg_blink_read_mem(engine->blink, name_ptr, func_name, 255);

                ret_val = wg_dll_mapper_resolve(engine->dll_mapper, dll, func_name);

                if (ret_val >= 0xC00000ULL && ret_val < 0xC00000ULL + 0x20000) {
                    uint8_t hlt = 0xF4;
                    wg_blink_write_mem(engine->blink, ret_val, &hlt, 1);
                }

                WG_LOGI(TAG, "GetProcAddress(%s) -> 0x%llx",
                        func_name, (unsigned long long)ret_val);
            } else {
                // Ordinal import — map known ordinals
                char ordinal_name[64];
                uint16_t ord = (uint16_t)name_ptr;

                // Known SHELL32 ordinals
                if (ord == 680) snprintf(ordinal_name, sizeof(ordinal_name), "IsUserAnAdmin");
                else snprintf(ordinal_name, sizeof(ordinal_name), "Ordinal_%u", ord);

                ret_val = wg_dll_mapper_resolve(engine->dll_mapper, "SHELL32.dll", ordinal_name);
                if (ret_val >= 0xC00000ULL && ret_val < 0xC00000ULL + 0x20000) {
                    uint8_t hlt = 0xF4;
                    wg_blink_write_mem(engine->blink, ret_val, &hlt, 1);
                }

                WG_LOGI(TAG, "GetProcAddress(ordinal %u -> %s) -> 0x%llx",
                        ord, ordinal_name, (unsigned long long)ret_val);
            }
        } else if (strcmp(fn, "LoadLibraryExW") == 0) {
            // LoadLibraryExW(lpLibFileName, hFile, dwFlags)
            uint16_t libname[256] = {0};
            if (args[0]) {
                wg_blink_read_mem(engine->blink, args[0], libname, 510);
            }
            char ascii[256] = {0};
            for (int i = 0; i < 255 && libname[i]; i++)
                ascii[i] = libname[i] < 128 ? (char)libname[i] : '?';
            WG_LOGI(TAG, "LoadLibraryExW('%s')", ascii);
            // Return a fake module handle (different from the main exe)
            ret_val = 0x10000000 + (uint32_t)(engine->dll_mapper->count * 0x1000);
        } else if (strcmp(fn, "GetModuleHandleA") == 0) {
            if (args[0]) {
                char modname[256] = {0};
                wg_blink_read_mem(engine->blink, args[0], modname, 255);
                WG_LOGD(TAG, "GetModuleHandleA('%s')", modname);
            }
            ret_val = engine->pe_image ? engine->pe_image->image_base : 0x400000;
        } else if (strcmp(fn, "GetModuleHandleW") == 0) {
            if (args[0]) {
                uint16_t modname[256] = {0};
                wg_blink_read_mem(engine->blink, args[0], modname, 510);
                char ascii[256] = {0};
                for (int i = 0; i < 255 && modname[i]; i++)
                    ascii[i] = modname[i] < 128 ? (char)modname[i] : '?';
                WG_LOGD(TAG, "GetModuleHandleW('%s')", ascii);
            }
            ret_val = engine->pe_image ? engine->pe_image->image_base : 0x400000;
        } else if (strcmp(fn, "GetVersion") == 0) {
            ret_val = 0x00000A00;
        } else if (strcmp(fn, "GetCommandLineW") == 0) {
            // Write a minimal command line into guest memory
            uint16_t cmdline[] = {'"', 'a', '.', 'e', 'x', 'e', '"', 0};
            uint64_t cmd_addr = 0xA00000;
            wg_blink_load_code(engine->blink, cmd_addr, (uint8_t*)cmdline, sizeof(cmdline), 0);
            ret_val = cmd_addr;
        } else if (strcmp(fn, "GetCommandLineA") == 0) {
            char cmdline[] = "\"a.exe\"";
            uint64_t cmd_addr = 0xA00100;
            wg_blink_load_code(engine->blink, cmd_addr, (uint8_t*)cmdline, sizeof(cmdline), 0);
            ret_val = cmd_addr;
        } else if (strcmp(fn, "GetModuleFileNameW") == 0) {
            // GetModuleFileNameW(hModule, lpFilename, nSize)
            uint16_t path[] = {'C',':','\\','a','.','e','x','e',0};
            if (args[1] && args[2] > 0) {
                uint32_t copy = sizeof(path);
                if (copy > args[2] * 2) copy = args[2] * 2;
                wg_blink_write_mem(engine->blink, args[1], path, copy);
            }
            ret_val = 8; // length
        } else if (strcmp(fn, "GetTempPathW") == 0) {
            // GetTempPathW(nBufferLength=args[0], lpBuffer=args[1]). Only write
            // if the caller's buffer is big enough; never overflow it.
            uint16_t tmp[] = {'C',':','\\','T','e','m','p','\\',0};
            int n = 9; // chars incl NUL
            if (args[1] && args[0] >= (uint32_t)n)
                wg_blink_write_mem(engine->blink, args[1], tmp, n * 2);
            ret_val = (args[0] >= (uint32_t)n) ? (uint32_t)(n - 1) : (uint32_t)n;
        } else if (strcmp(fn, "GetWindowsDirectoryW") == 0) {
            // GetWindowsDirectoryW(lpBuffer=args[0], uSize=args[1] in chars).
            uint16_t windir[] = {'C',':','\\','W','i','n','d','o','w','s',0};
            int n = 11;
            if (args[0] && args[1] >= (uint32_t)n)
                wg_blink_write_mem(engine->blink, args[0], windir, n * 2);
            ret_val = (args[1] >= (uint32_t)n) ? (uint32_t)(n - 1) : (uint32_t)n;
        } else if (strcmp(fn, "GetSystemDirectoryW") == 0) {
            // GetSystemDirectoryW(lpBuffer=args[0], uSize=args[1] in chars).
            uint16_t sysdir[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2',0};
            int n = 20;
            if (args[0] && args[1] >= (uint32_t)n)
                wg_blink_write_mem(engine->blink, args[0], sysdir, n * 2);
            ret_val = (args[1] >= (uint32_t)n) ? (uint32_t)(n - 1) : (uint32_t)n;
        } else if (strcmp(fn, "RegisterClassW") == 0) {
            ret_val = 0xC001;
        } else if (strcmp(fn, "GetSystemMetrics") == 0) {
            // SM_CXSCREEN=0 -> 800, SM_CYSCREEN=1 -> 600
            if (args[0] == 0) ret_val = 800;
            else if (args[0] == 1) ret_val = 600;
            else ret_val = 0;
        } else if (strcmp(fn, "GetSysColor") == 0) {
            ret_val = 0x00F0F0F0; // light gray
        } else if (strcmp(fn, "GetDeviceCaps") == 0) {
            ret_val = 96; // LOGPIXELSX/Y
        } else if (strcmp(fn, "PeekMessageW") == 0) {
            ret_val = 0; // no messages
        } else if (strcmp(fn, "CharNextW") == 0) {
            // CharNextW(LPCWSTR p) — advance to next char, don't go past null
            if (args[0]) {
                uint16_t ch = 0;
                wg_blink_read_mem(engine->blink, args[0], &ch, 2);
                ret_val = (ch != 0) ? args[0] + 2 : args[0];
            }
        } else if (strcmp(fn, "CharNextA") == 0) {
            if (args[0]) {
                uint8_t ch = 0;
                wg_blink_read_mem(engine->blink, args[0], &ch, 1);
                ret_val = (ch != 0) ? args[0] + 1 : args[0];
            }
        } else if (strcmp(fn, "CharPrevW") == 0) {
            // CharPrevW(LPCWSTR start, LPCWSTR current)
            if (args[1] > args[0]) ret_val = args[1] - 2;
            else ret_val = args[0];
        } else if (strcmp(fn, "lstrlenW") == 0) {
            if (args[0]) {
                uint16_t buf[1024];
                wg_blink_read_mem(engine->blink, args[0], buf, sizeof(buf));
                int len = 0;
                while (len < 1023 && buf[len]) len++;
                ret_val = len;
            }
        } else if (strcmp(fn, "lstrlenA") == 0) {
            if (args[0]) {
                char buf[1024];
                wg_blink_read_mem(engine->blink, args[0], buf, sizeof(buf));
                buf[1023] = 0;
                int len = 0;
                while (len < 1023 && buf[len]) len++;
                ret_val = len;
            }
        } else if (strcmp(fn, "lstrcpyW") == 0) {
            if (args[0] && args[1]) {
                uint16_t buf[1024];
                wg_blink_read_mem(engine->blink, args[1], buf, sizeof(buf));
                buf[1023] = 0;
                int len = 0;
                while (len < 1023 && buf[len]) len++;
                wg_blink_write_mem(engine->blink, args[0], buf, (len + 1) * 2);
                ret_val = args[0];
            }
        } else if (strcmp(fn, "lstrcpyA") == 0) {
            if (args[0] && args[1]) {
                char buf[1024];
                wg_blink_read_mem(engine->blink, args[1], buf, sizeof(buf));
                buf[1023] = 0;
                int len = 0;
                while (len < 1023 && buf[len]) len++;
                wg_blink_write_mem(engine->blink, args[0], buf, len + 1);
                ret_val = args[0];
            }
        } else if (strcmp(fn, "lstrcpynW") == 0) {
            // lstrcpynW(dst, src, maxlen): copy AT MOST maxlen-1 chars, stopping
            // at the NUL, then NUL-terminate. Writing the full maxlen (as we used
            // to) overflows the destination with garbage and corrupts adjacent
            // guest memory — e.g. it was smashing NSIS's LZMA decoder context.
            if (args[0] && args[1] && (int32_t)args[2] > 0) {
                int maxlen = args[2];
                if (maxlen > 1024) maxlen = 1024;
                uint16_t buf[1024];
                wg_blink_read_mem(engine->blink, args[1], buf, maxlen * 2);
                int len = 0;
                while (len < maxlen - 1 && buf[len]) len++;
                buf[len] = 0;
                wg_blink_write_mem(engine->blink, args[0], buf, (len + 1) * 2);
                ret_val = args[0];
            }
        } else if (strcmp(fn, "lstrcatW") == 0) {
            if (args[0] && args[1]) {
                // Find end of dst
                uint16_t dst[1024], src[1024];
                wg_blink_read_mem(engine->blink, args[0], dst, sizeof(dst));
                wg_blink_read_mem(engine->blink, args[1], src, sizeof(src));
                dst[1023] = src[1023] = 0;
                int dlen = 0; while (dlen < 1023 && dst[dlen]) dlen++;
                int slen = 0; while (slen < 1023 && src[slen]) slen++;
                int copylen = slen;
                if (dlen + copylen > 1022) copylen = 1022 - dlen;
                for (int i = 0; i <= copylen; i++) dst[dlen + i] = src[i];
                dst[dlen + copylen] = 0;
                wg_blink_write_mem(engine->blink, args[0], dst, (dlen + copylen + 1) * 2);
                ret_val = args[0];
            }
        } else if (strcmp(fn, "lstrcmpW") == 0 || strcmp(fn, "lstrcmpiW") == 0) {
            ret_val = 0; // equal
        } else if (strcmp(fn, "lstrcmpiA") == 0) {
            ret_val = 0;
        } else if (strcmp(fn, "GetTempFileNameW") == 0) {
            // GetTempFileNameW(lpPathName, lpPrefixString, uUnique, lpTempFileName)
            // Windows creates the file on disk! NSIS depends on this.
            static uint32_t s_temp_counter = 1;
            uint32_t unique = args[2] ? args[2] : s_temp_counter++;
            uint16_t tmpname[260];
            int pos = 0;
            if (args[0]) {
                uint16_t path[260] = {0};
                wg_blink_read_mem(engine->blink, args[0], path, 518);
                for (int i = 0; path[i] && pos < 240; i++) tmpname[pos++] = path[i];
            }
            if (pos > 0 && tmpname[pos-1] != '\\' && tmpname[pos-1] != '/') {
                tmpname[pos++] = '\\';
            }
            uint16_t pfx[4] = {'t','m','p'};
            if (args[1]) {
                wg_blink_read_mem(engine->blink, args[1], pfx, 6);
            }
            for (int i = 0; i < 3 && pfx[i]; i++) tmpname[pos++] = pfx[i];
            char numstr[16];
            snprintf(numstr, sizeof(numstr), "%05X", unique & 0xFFFFF);
            for (int i = 0; numstr[i] && pos < 250; i++) tmpname[pos++] = numstr[i];
            tmpname[pos++] = '.'; tmpname[pos++] = 't'; tmpname[pos++] = 'm'; tmpname[pos++] = 'p';
            tmpname[pos] = 0;
            if (args[3]) {
                wg_blink_write_mem(engine->blink, args[3], tmpname, (pos + 1) * 2);
            }
            // Convert to ASCII and create the file on disk (like Windows does)
            char aname[520] = {0};
            for (int i = 0; i < pos && i < 519; i++)
                aname[i] = tmpname[i] < 128 ? (char)tmpname[i] : '_';
            const char *real = wg_files_map_path(0, engine->blink, aname, sizeof(aname));
            if (real) {
                FILE *f = fopen(real, "wb");
                if (f) fclose(f);
            }
            ret_val = unique;
        } else if (strcmp(fn, "MessageBoxIndirectW") == 0) {
            // MSGBOXPARAMSW struct: cbSize(4), hwndOwner(4), hInstance(4),
            // lpszText(4), lpszCaption(4), ...
            // lpszText is at offset 12 in the struct
#ifdef WG_DECODE_DIAG
            WG_LOGE("DIAG", "MessageBoxIndirectW called from RIP=0x%llx",
                    (unsigned long long)ret_addr);
#endif
            if (args[0]) {
                uint32_t text_ptr = 0, caption_ptr = 0;
                wg_blink_read_mem(engine->blink, args[0] + 12, &text_ptr, 4);
                wg_blink_read_mem(engine->blink, args[0] + 16, &caption_ptr, 4);
                if (text_ptr) {
                    uint16_t text[512] = {0};
                    wg_blink_read_mem(engine->blink, text_ptr, text, 1022);
                    char atext[512] = {0};
                    for (int i = 0; i < 511 && text[i]; i++)
                        atext[i] = text[i] < 128 ? (char)text[i] : '?';
                    WG_LOGI(TAG, "MessageBox: \"%s\"", atext);
                }
                if (caption_ptr) {
                    uint16_t cap[256] = {0};
                    wg_blink_read_mem(engine->blink, caption_ptr, cap, 510);
                    char acap[256] = {0};
                    for (int i = 0; i < 255 && cap[i]; i++)
                        acap[i] = cap[i] < 128 ? (char)cap[i] : '?';
                    WG_LOGI(TAG, "MessageBox caption: \"%s\"", acap);
                }
            }
            ret_val = 1; // IDOK
        } else if (strcmp(fn, "DialogBoxParamW") == 0) {
            // DialogBoxParamW(hInstance, lpTemplateName=args[1], hWndParent,
            //                 lpDialogFunc=args[3], dwInitParam=args[4])
            uint32_t dlg_id  = args[1];   // MAKEINTRESOURCE id
            uint32_t dlgproc = args[3];
            uint32_t initParam = args[4];
            WG_LOGI(TAG, "DialogBoxParamW(id=%u, dlgproc=0x%X)", dlg_id, dlgproc);

            uint16_t title[] = {'S','t','e','a','m',' ','S','e','t','u','p',0};
            uint32_t hwnd = wg_wm_create_window(0, 0, title, 0x10CF0000,
                                                50, 50, 500, 360, 0);
            // Parse the dialog template so we can render its controls.
            wg_parse_dialog(engine, hwnd, dlg_id);

            // Clean up DialogBoxParamW's stack frame (5 args stdcall)
            uint64_t clean_rsp = rsp + ptr_size + (5 * ptr_size);

            // Call dlgproc(hwnd, WM_INITDIALOG, 0, initParam). The return address
            // is a SENTINEL in the HLT thunk page — when the dlgproc returns the
            // engine catches it and goes modal (instead of falling back into
            // WinMain, which would make it exit). EndDialog later returns to the
            // real WinMain call site (s_dlg_ret_*).
            if (dlgproc && is_32bit) {
                s_dlg_active = true;
                s_dlg_hwnd = hwnd;
                s_dlg_proc = dlgproc;
                s_dlg_ret_addr = (uint32_t)ret_addr;
                s_dlg_ret_rsp  = (uint32_t)clean_rsp;
                s_dlg_result = 1;
                uint32_t new_rsp = (uint32_t)clean_rsp - 20;
                uint32_t stack_data[5] = {
                    WG_DLG_SENTINEL, hwnd, 0x0110 /*WM_INITDIALOG*/, 0, initParam
                };
                wg_blink_write_mem(engine->blink, new_rsp, stack_data, 20);
                wg_blink_set_reg(engine->blink, 4, new_rsp);
                wg_blink_set_rip(engine->blink, dlgproc);
                wg_blink_set_reg(engine->blink, 0, 0);
                return true;
            }

            engine->state = WG_ENGINE_PAUSED;
            wg_blink_set_reg(engine->blink, 4, clean_rsp);
            wg_blink_set_rip(engine->blink, ret_addr);
            wg_blink_set_reg(engine->blink, 0, 0);
            return true;
        } else if (strcmp(fn, "EndDialog") == 0) {
            // EndDialog(hDlg, nResult=args[1]) — return modally to WinMain.
            if (s_dlg_active) {
                s_dlg_result = args[1];
                s_dlg_active = false;
                s_callstack_depth = 0;   // abandon any nested SendMessage frames
                wg_blink_set_reg(engine->blink, 4, s_dlg_ret_rsp);
                wg_blink_set_rip(engine->blink, s_dlg_ret_addr);
                wg_blink_set_reg(engine->blink, 0, s_dlg_result);
                WG_LOGI(TAG, "EndDialog(%u) -> return to WinMain", s_dlg_result);
                return true;
            }
            ret_val = 1;
        } else if (strcmp(fn, "GetDlgItem") == 0) {
            // GetDlgItem(hDlg=args[0], id=args[1]) -> synthetic control HWND.
            WGDlgCtrl *c = wg_find_ctrl(args[0], args[1]);
            ret_val = c ? (WG_CTRL_HWND_BASE + (uint32_t)(c - s_ctrls)) : 0;
        } else if (strcmp(fn, "SetDlgItemTextW") == 0) {
            // SetDlgItemTextW(hDlg=args[0], id=args[1], lpString=args[2])
            WGDlgCtrl *c = wg_find_ctrl(args[0], args[1]);
            if (c && args[2]) {
                wg_blink_read_mem(engine->blink, args[2], c->text, sizeof(c->text));
                c->text[79] = 0;
                if (s_dlg_active) wg_render_dialog(engine, c->hwnd);
            }
            ret_val = 1;
        } else if (strcmp(fn, "SendMessageW") == 0 ||
                   strcmp(fn, "SendDlgItemMessageW") == 0) {
            // SendDlgItemMessageW(hDlg, id, msg, wParam, lParam): redirect to the
            // child control's handle, then fall through to SendMessage logic.
            uint32_t hwnd, msg, wParam, lParam;
            if (strcmp(fn, "SendDlgItemMessageW") == 0) {
                WGDlgCtrl *c = wg_find_ctrl(args[0], args[1]);
                hwnd = c ? (WG_CTRL_HWND_BASE + (uint32_t)(c - s_ctrls)) : 0;
                msg = args[2]; wParam = args[3]; lParam = args[4];
            } else {
                hwnd = args[0]; msg = args[1]; wParam = args[2]; lParam = args[3];
            }
            // STM_SETIMAGE on one of our synthetic static controls: attach the
            // bitmap (these controls have no guest wndproc to dispatch to).
            if (msg == 0x0172 /*STM_SETIMAGE*/ && wg_ctrl_from_handle(hwnd)) {
                WGDlgCtrl *c = wg_ctrl_from_handle(hwnd);
                c->hbitmap = lParam; c->is_bitmap = true;
                if (s_dlg_active) wg_render_dialog(engine, c->hwnd);
                ret_val = 0;
            } else {
                // Real dispatch: call the target window's procedure and return
                // its result. This is what drives NSIS's page navigation
                // (e.g. SendMessage(hDlg, 0x408, ...) = "show next page").
                uint32_t proc = wg_resolve_wndproc(hwnd);
                int nargs = (strcmp(fn, "SendDlgItemMessageW") == 0) ? 5 : 4;
                uint64_t caller_clean = rsp + ptr_size + (nargs * ptr_size);
                if (proc && is_32bit &&
                    wg_call_wndproc(engine, proc, hwnd, msg, wParam, lParam,
                                    (uint32_t)ret_addr, (uint32_t)caller_clean)) {
                    return true;
                }
                ret_val = 0;
            }
        } else if (strcmp(fn, "CreateDialogParamW") == 0) {
            // CreateDialogParamW(hInstance, lpTemplateName=args[1], hWndParent=args[2],
            //                    lpDialogFunc=args[3], dwInitParam=args[4])
            uint32_t dlg_id = args[1], parent = args[2], dlgproc = args[3];
            uint32_t initParam = args[4];
            // Position the inner page in the IDD_INST inner-dialog placeholder
            // (id 1018) so the parent's header/buttons stay visible around it.
            int px = 0, py = 0, pw = 480, ph = 320;
            WGDlgCtrl *placeholder = wg_find_ctrl(parent, 1018);
            if (placeholder) {
                int32_t cw = 0, chh = 0;
                wg_wm_get_client(parent, &cw, &chh);
                float sx = placeholder->dlg_cx ? (float)cw / placeholder->dlg_cx : 1.0f;
                float sy = placeholder->dlg_cy ? (float)chh / placeholder->dlg_cy : 1.0f;
                px = (int)(placeholder->x * sx); py = (int)(placeholder->y * sy);
                pw = (int)(placeholder->cx * sx); ph = (int)(placeholder->cy * sy);
            }
            uint16_t title[] = {0};
            uint32_t hwnd = wg_wm_create_window(0, 0, title, 0x50000000,
                                                px, py, pw, ph, parent);
            WGWin32Window *pw_win = wg_wm_find(hwnd);
            if (pw_win) pw_win->wndproc = dlgproc;
            (void)initParam;
            // Parse the page's own dialog template (e.g. the directory page) so
            // we can render its controls — these are built-in NSIS dialogs, not
            // nsDialogs plugin pages. NSIS drives the page's WM_INITDIALOG /
            // SetDlgItemText itself (which our handlers render), so we just
            // create the window, render the template, and return the HWND.
            wg_parse_dialog(engine, hwnd, dlg_id);
            wg_render_dialog(engine, hwnd);
            WG_LOGI(TAG, "CreateDialogParamW(template=%u) -> page HWND=0x%X", dlg_id, hwnd);
            ret_val = hwnd;
        } else if (strcmp(fn, "GetLastError") == 0) {
            ret_val = s_last_error;
        } else if (strcmp(fn, "SetLastError") == 0) {
            s_last_error = args[0];
        } else if (strcmp(fn, "IsUserAnAdmin") == 0) {
            ret_val = 1; // yes, admin
        } else if (strcmp(fn, "CreateDirectoryW") == 0) {
            // CreateDirectoryW(lpPathName, lpSecurityAttributes)
            uint16_t wpath[260] = {0};
            char apath[260] = {0};
            if (args[0]) {
                wg_blink_read_mem(engine->blink, args[0], wpath, 518);
                for (int i = 0; i < 259 && wpath[i]; i++)
                    apath[i] = wpath[i] < 128 ? (char)wpath[i] : '_';
            }
            const char *real = wg_files_map_path(args[0], engine->blink, apath, sizeof(apath));
            if (real) {
                int r = mkdir(real, 0755);
                if (r == 0) {
                    ret_val = 1;
                    s_last_error = 0;
                } else if (errno == EEXIST) {
                    // NSIS needs a FRESH plugins dir (it creates one with a
                    // restricted ACL and bails if it already exists). Stale
                    // ns*.tmp dirs survive across runs, so clear and recreate.
                    if (strstr(apath, ".tmp")) {
                        wg_rmtree(real);
                        if (mkdir(real, 0755) == 0) {
                            ret_val = 1;
                            s_last_error = 0;
                            WG_LOGI(TAG, "CreateDirectoryW: cleared stale %s", apath);
                        } else {
                            ret_val = 0;
                            s_last_error = 183;
                        }
                    } else {
                        ret_val = 0;
                        s_last_error = 183; // ERROR_ALREADY_EXISTS
                    }
                } else {
                    ret_val = 0;
                    s_last_error = 3; // ERROR_PATH_NOT_FOUND
                }
                WG_LOGI(TAG, "CreateDirectoryW('%s') -> %s", apath, ret_val ? "OK" : "exists/fail");
            } else {
                ret_val = 1;
                s_last_error = 0;
            }
        } else if (strcmp(fn, "PeekMessageW") == 0) {
            // PeekMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg)
            // This is the Windows message pump. On Windows, this returns TRUE
            // if a message is available. We return FALSE (no messages) which
            // makes the app idle. After many consecutive calls, pause for UI.
            static int peek_count = 0;
            peek_count++;
            if (peek_count > 5) {
                // Pause to let the user see the rendered windows
                peek_count = 0;
                engine->state = WG_ENGINE_PAUSED;
                WG_LOGI(TAG, "Message loop — pausing for UI");
            }
            ret_val = 0; // no messages
        } else if (strcmp(fn, "GetTickCount") == 0) {
            // Seed from a real clock so it varies across launches — NSIS
            // derives its temp-dir names from this, and a fixed seed makes
            // every run collide on the same stale directory.
            static uint32_t s_tick = 0;
            if (s_tick == 0) s_tick = (uint32_t)(time(NULL) * 1000u) | 1u;
            ret_val = s_tick;
            s_tick += 16;
        } else if (strcmp(fn, "GetCurrentProcess") == 0) {
            ret_val = (uint64_t)-1;
        } else if (strcmp(fn, "CloseHandle") == 0) {
            wg_files_close(args[0]);
            ret_val = 1;
        } else if (strcmp(fn, "GlobalUnlock") == 0 || strcmp(fn, "FindClose") == 0) {
            ret_val = 1;
        } else if (strcmp(fn, "CreateFileW") == 0) {
            // CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecAttr,
            //             dwCreationDisposition, dwFlagsAndAttrs, hTemplate)
            // args[0]=filename, [1]=access, [4]=creation
            uint16_t wpath[260] = {0};
            char apath[260] = {0};
            if (args[0]) {
                wg_blink_read_mem(engine->blink, args[0], wpath, 518);
                for (int i = 0; i < 259 && wpath[i]; i++)
                    apath[i] = wpath[i] < 128 ? (char)wpath[i] : '_';
            }
            const char *real = wg_files_map_path(args[0], engine->blink, apath, sizeof(apath));
            if (real) {
                ret_val = wg_files_create(real, args[1], args[4]);
            } else {
                ret_val = 0xFFFFFFFF;
            }
            WG_LOGI(TAG, "CreateFileW('%s') -> 0x%X", apath, (uint32_t)ret_val);

            // NSIS decompresses its whole data section (one solid raw-LZMA
            // stream) into a temp file, then reads each packed file from it by
            // offset. blink's in-guest decode of that stream truncates, so when
            // NSIS creates that data temp file (the first ns*.tmp opened
            // CREATE_ALWAYS that is NOT inside a plugin dir), we pre-fill it
            // with the correct full decompression done natively (LzmaDec), and
            // then ignore the guest's own (truncated) writes to it.
#if WG_NSIS_PREFILL_HACK
            if (ret_val != 0xFFFFFFFF && real &&
                s_nsis_data_tmp_handle == 0 && args[4] == 2 /* CREATE_ALWAYS */ &&
                strstr(apath, ".tmp") &&
                !strstr(apath, ".tmp\\") && !strstr(apath, ".tmp/")) {
                const char *exe_real = wg_files_map_path(0, engine->blink,
                                                         (char *)"C:\\a.exe", 260);
                if (exe_real && wg_nsis_prefill_datatmp(exe_real, real)) {
                    s_nsis_data_tmp_handle = (uint32_t)ret_val;
                    strncpy(s_nsis_data_tmp_path, real, sizeof(s_nsis_data_tmp_path) - 1);
                    // Reset the guest handle to offset 0 so the guest's reads
                    // (and ignored writes) line up; our data is already on disk.
                    wg_files_set_pointer((uint32_t)ret_val, 0, 0);
                    WG_LOGI(TAG, "NSIS data tmp pre-filled (handle=0x%X)",
                            s_nsis_data_tmp_handle);
                }
            }
#endif
#ifdef WG_DECODE_DIAG
            if (ret_val != 0xFFFFFFFF && args[4] == 2 && strstr(apath, ".tmp") &&
                !strstr(apath, ".tmp\\") && !strstr(apath, ".tmp/")) {
                s_diag_data_tmp_handle = (uint32_t)ret_val;
            }
#endif
        } else if (strcmp(fn, "ReadFile") == 0) {
            uint32_t handle = args[0];
            uint32_t buf_addr = args[1];
            uint32_t nbytes = args[2];
            uint32_t bytes_read_addr = args[3];
            if (nbytes > 0x100000) nbytes = 0x100000;
            uint32_t pos_before = wg_files_set_pointer(handle, 0, 1); // SEEK_CUR
            uint8_t *tmpbuf = malloc(nbytes);
            uint32_t first4 = 0, nread = 0;
            if (tmpbuf) {
                if (wg_files_read(handle, tmpbuf, nbytes, &nread)) {
                    wg_blink_write_mem(engine->blink, buf_addr, tmpbuf, nread);
                    if (bytes_read_addr) {
                        wg_blink_write_mem(engine->blink, bytes_read_addr, &nread, 4);
                    }
                    if (nread >= 4) memcpy(&first4, tmpbuf, 4);
                    ret_val = 1;
                }
                free(tmpbuf);
            }
            // Log small control reads always, and ANY short read (nread <
            // nbytes) — a short read on the .exe would starve the decoder.
            if (nbytes <= 64 || nread < nbytes) {
                WG_LOGI(TAG, "ReadFile(h=0x%X, pos=%u, n=%u) -> nread=%u first4=0x%08X",
                        handle, pos_before, nbytes, nread, first4);
            }
#ifdef WG_DECODE_DIAG
            else if (handle == 0x100 || handle == 0x101) {
                WG_LOGI("RD", "ReadFile(h=0x%X, pos=%u, n=%u) -> nread=%u first4=0x%08X",
                        handle, pos_before, nbytes, nread, first4);
            }
#endif
        } else if (strcmp(fn, "WriteFile") == 0) {
            uint32_t handle = args[0];
            uint32_t buf_addr = args[1];
            uint32_t nbytes = args[2];
            uint32_t bytes_written_addr = args[3];
            if (nbytes > 0x100000) nbytes = 0x100000;
            // Ignore writes to the pre-filled NSIS data tmp — our native
            // decompression already put the correct full data there; the
            // guest's own (truncated) decode would corrupt it.
            if (handle == s_nsis_data_tmp_handle && s_nsis_data_tmp_handle != 0) {
                if (bytes_written_addr)
                    wg_blink_write_mem(engine->blink, bytes_written_addr, &nbytes, 4);
                ret_val = 1;
                goto wf_done;
            }
            uint8_t *tmpbuf = malloc(nbytes);
            if (tmpbuf) {
                wg_blink_read_mem(engine->blink, buf_addr, tmpbuf, nbytes);
#ifdef WG_DECODE_DIAG
                if (handle == s_diag_data_tmp_handle && s_diag_data_tmp_handle != 0) {
                    uint32_t pos = wg_files_set_pointer(handle, 0, 1); // SEEK_CUR
                    wg_diag_check(pos, tmpbuf, nbytes);
                }
#endif
                uint32_t nwritten = 0;
                if (wg_files_write(handle, tmpbuf, nbytes, &nwritten)) {
                    if (bytes_written_addr) {
                        wg_blink_write_mem(engine->blink, bytes_written_addr, &nwritten, 4);
                    }
                    ret_val = 1;
                    WG_LOGI(TAG, "WriteFile(0x%X, %u bytes) -> wrote %u", handle, nbytes, nwritten);
                } else {
                    WG_LOGE(TAG, "WriteFile(0x%X, %u bytes) FAILED", handle, nbytes);
                }
                free(tmpbuf);
            }
            wf_done:;
        } else if (strcmp(fn, "GetFileSize") == 0) {
            ret_val = wg_files_get_size(args[0]);
            WG_LOGI(TAG, "GetFileSize(0x%X) -> %u", args[0], (uint32_t)ret_val);
        } else if (strcmp(fn, "SetFilePointer") == 0) {
            // Detect when NSIS finishes its truncated copy and patch the .tmp
            // Track seeks on the data .tmp to know extraction offsets.
            // Only capture large seeks (>1000) — small ones (0, 4) are header reads.
            if (s_nsis_data_tmp_handle != 0 && args[0] == s_nsis_data_tmp_handle &&
                args[3] == 0 && (int32_t)args[1] > 1000) {
                s_nsis_last_data_seek = (uint32_t)args[1];
                WG_LOGI(TAG, "NSIS data seek: offset=%u", s_nsis_last_data_seek);
            }

            // Track seeks on the EXE file (not .tmp) to find raw data offset.
            // Only consider seeks on files larger than 1MB (that's the .exe).
            if (!s_nsis_data_patched && args[3] == 0 &&
                (int32_t)args[1] > 100000 && (int32_t)args[1] < 2000000) {
                uint32_t file_size = wg_files_get_size(args[0]);
                if (file_size > 1000000) {
                    // This is the exe — track the last seek position
                    s_nsis_exe_data_offset = (uint32_t)args[1];
                }
            }

            if (false && !s_nsis_data_patched && s_nsis_exe_data_offset > 0) {
                // DISABLED: old .tmp patching — now using full outer stream decompression
                uint32_t current_size = wg_files_get_size(args[0]);
                if (current_size > 200000 && current_size < 500000) {
                    WG_LOGI(TAG, "Patching .tmp: handle=0x%X, size=%u, exe_data_off=%u",
                            args[0], current_size, s_nsis_exe_data_offset);
                    const char *exe_real = wg_files_map_path(0, engine->blink,
                        (char*)"C:\\a.exe", 260);
                    if (exe_real) {
                        FILE *exe_fp = fopen(exe_real, "rb");
                        if (exe_fp) {
                            fseek(exe_fp, 0, SEEK_END);
                            long exe_size = ftell(exe_fp);
                            fseek(exe_fp, 0, SEEK_SET);
                            uint8_t *exe_data = malloc(exe_size);
                            if (exe_data) {
                                fread(exe_data, 1, exe_size, exe_fp);
                                // Find the end of NSIS data (NullsoftInst + archive_size)
                                long nsi = -1;
                                for (long i = 0; i < exe_size - 16; i++) {
                                    if (memcmp(exe_data + i, "NullsoftInst", 12) == 0) {
                                        nsi = i; break;
                                    }
                                }
                                if (nsi >= 0) {
                                    uint32_t arc_size;
                                    memcpy(&arc_size, exe_data + nsi + 16, 4);
                                    long data_start = nsi + 20;
                                    // Raw data starts at s_nsis_exe_data_offset in the exe
                                    // NSIS copied current_size bytes from that position
                                    // Total raw data: from exe_data_offset to data_start + arc_size
                                    long total_raw = (data_start + arc_size) - s_nsis_exe_data_offset;
                                    if ((long)current_size < total_raw) {
                                        long src_offset = s_nsis_exe_data_offset + current_size;
                                        long append_size = total_raw - current_size;
                                        if (src_offset + append_size <= exe_size && append_size > 0) {
                                            wg_files_set_pointer(args[0], 0, 2);
                                            uint32_t written = 0;
                                            wg_files_write(args[0], exe_data + src_offset, (uint32_t)append_size, &written);
                                            WG_LOGI(TAG, "Patched .tmp: appended %u bytes (was %u, now %u, from exe@%ld)",
                                                    written, current_size, current_size + written, src_offset);
                                            s_nsis_data_patched = true;
                                        }
                                    }
                                }
                                free(exe_data);
                            }
                            fclose(exe_fp);
                        }
                    }
                }
            }
            ret_val = wg_files_set_pointer(args[0], (int32_t)args[1], args[3]);
            WG_LOGI(TAG, "SetFilePointer(h=0x%X, dist=%d, method=%u) -> %u",
                    args[0], (int32_t)args[1], args[3], (uint32_t)ret_val);
        } else if (strcmp(fn, "GetFileAttributesW") == 0) {
            uint16_t wpath[260] = {0};
            char apath[260] = {0};
            if (args[0]) {
                wg_blink_read_mem(engine->blink, args[0], wpath, 518);
                for (int i = 0; i < 259 && wpath[i]; i++)
                    apath[i] = wpath[i] < 128 ? (char)wpath[i] : '_';
            }

            const char *real = wg_files_map_path(args[0], engine->blink, apath, sizeof(apath));
            if (real) {
                struct stat st;
                if (stat(real, &st) == 0) {
                    ret_val = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
                } else {
                    ret_val = 0xFFFFFFFF;
                    s_last_error = 2;
                }
            } else {
                ret_val = 0xFFFFFFFF;
                s_last_error = 2;
            }
        } else if (strcmp(fn, "DeleteFileW") == 0) {
            uint16_t wpath[260] = {0};
            char apath[260] = {0};
            if (args[0]) {
                wg_blink_read_mem(engine->blink, args[0], wpath, 518);
                for (int i = 0; i < 259 && wpath[i]; i++)
                    apath[i] = wpath[i] < 128 ? (char)wpath[i] : '_';
            }
            const char *real = wg_files_map_path(args[0], engine->blink, apath, sizeof(apath));
            if (real) {
                ret_val = (unlink(real) == 0) ? 1 : 0;
            } else {
                ret_val = 1;
            }
        } else if (strcmp(fn, "FindFirstFileW") == 0) {
            ret_val = 0xFFFFFFFF; // INVALID_HANDLE_VALUE
        } else if (strcmp(fn, "GlobalAlloc") == 0) {
            uint32_t size = args[1];
            if (size == 0) size = 4096;
            // A size with the top bit set (or one that's absurdly large) is
            // garbage that NSIS's broken in-guest LZMA decoder derived. NSIS
            // uses it as a real length (it allocs then zero-terminates at
            // buf[size-1]), so no buffer we return can satisfy it — masking the
            // size and handing back a smaller buffer just turns the clean
            // "Error decompressing data" abort into an out-of-bounds SIGSEGV.
            // Return NULL and let NSIS take its own error path.
            if ((size & 0x80000000u) || size > 512u * 1024 * 1024) {
                WG_LOGW(TAG, "GlobalAlloc FAILED: corrupt size %u (in-guest "
                        "decoder produced garbage)", size);
#ifdef WG_DECODE_DIAG
                // Who called GlobalAlloc with the bad size, and what's on the
                // guest stack right now? (32-bit: args already read from stack.)
                WG_LOGE("DIAG", "corrupt GlobalAlloc: caller RIP=0x%llx "
                        "EAX=0x%llx ECX=0x%llx EDX=0x%llx EBX=0x%llx "
                        "EBP=0x%llx ESP=0x%llx",
                        (unsigned long long)ret_addr,
                        wg_blink_get_reg(engine->blink, 0),
                        wg_blink_get_reg(engine->blink, 1),
                        wg_blink_get_reg(engine->blink, 2),
                        wg_blink_get_reg(engine->blink, 3),
                        wg_blink_get_reg(engine->blink, 5),
                        wg_blink_get_reg(engine->blink, 4));
                uint32_t stk[12] = {0};
                wg_blink_read_mem(engine->blink, rsp, stk, sizeof(stk));
                for (int si = 0; si < 12; si += 4)
                    WG_LOGE("DIAG", "  [ESP+%2d]: %08X %08X %08X %08X",
                            si*4, stk[si], stk[si+1], stk[si+2], stk[si+3]);
                // The size came from 4 bytes at [ebp-0x70]. Dump that pointer and
                // the bytes around it to see where the garbage lives.
                uint32_t ebp = (uint32_t)wg_blink_get_reg(engine->blink, 5);
                uint32_t pInput = 0, vAccum = 0, vCount = 0;
                wg_blink_read_mem(engine->blink, ebp - 0x70, &pInput, 4);
                wg_blink_read_mem(engine->blink, ebp - 0x40, &vAccum, 4);
                wg_blink_read_mem(engine->blink, ebp - 0x6c, &vCount, 4);
                WG_LOGE("DIAG", "locals: [ebp-0x70](inPtr)=0x%08X [ebp-0x40](accum)=0x%08X [ebp-0x6c]=0x%08X",
                        pInput, vAccum, vCount);
                if (pInput) {
                    uint8_t around[32] = {0};
                    wg_blink_read_mem(engine->blink, pInput - 8, around, 32);
                    WG_LOGE("DIAG", "  inPtr-8: %02X %02X %02X %02X %02X %02X %02X %02X | "
                            "%02X %02X %02X %02X %02X %02X %02X %02X",
                            around[0],around[1],around[2],around[3],around[4],around[5],around[6],around[7],
                            around[8],around[9],around[10],around[11],around[12],around[13],around[14],around[15]);
                }
#endif
                ret_val = 0;
            } else {
                size = (size + 0xFFF) & ~0xFFF;
                uint32_t addr = s_heap_ptr;
                uint8_t *zeros = calloc(1, size);
                if (zeros) {
                    wg_blink_load_code(engine->blink, addr, zeros, size, 0);
                    free(zeros);
                    s_heap_ptr += size;
                    s_heap_ptr = (s_heap_ptr + 0xFFF) & ~0xFFF;
                    ret_val = addr;
                }
            }
        } else if (strcmp(fn, "GlobalLock") == 0) {
            ret_val = args[0]; // GMEM_FIXED: handle == pointer
        }
    }

    // Stdcall: callee pops return address + all arguments
    int num_args = entry ? entry->num_args : 0;
    uint64_t new_rsp = rsp + ptr_size + (num_args * ptr_size);
    wg_blink_set_reg(engine->blink, 4, new_rsp); // RSP
    wg_blink_set_rip(engine->blink, ret_addr);
    wg_blink_set_reg(engine->blink, 0, ret_val); // EAX = return value

    return true;
}

bool wg_engine_init(WGEngine *engine) {
    WG_LOGI(TAG, "Initializing translation engine...");

    engine->memory = wg_memory_create(0x100000000ULL);
    if (!engine->memory) {
        WG_LOGE(TAG, "Failed to create virtual memory space");
        engine->state = WG_ENGINE_ERROR;
        return false;
    }
    WG_LOGI(TAG, "Virtual memory: 4GB address space created");

    engine->cpu = wg_x86_state_create();
    if (!engine->cpu) {
        WG_LOGE(TAG, "Failed to create CPU state");
        engine->state = WG_ENGINE_ERROR;
        return false;
    }
    WG_LOGI(TAG, "Builtin x86-64 interpreter ready (fallback)");

    // Blink VM creation is deferred until we know if the PE is 32 or 64-bit
    engine->blink = NULL;
    engine->backend = WG_BACKEND_BLINK;

    engine->dll_mapper = wg_dll_mapper_create();
    if (!engine->dll_mapper) {
        WG_LOGE(TAG, "Failed to create DLL mapper");
        engine->state = WG_ENGINE_ERROR;
        return false;
    }
    wg_dll_mapper_register_defaults(engine->dll_mapper);
    WG_LOGI(TAG, "Win32 DLL mapper initialized");

    // Blink init is deferred — thunks will be mapped when a PE is loaded

    WG_LOGI(TAG, "NSIS data mode: %s",
            WG_NSIS_PREFILL_HACK ? "native LzmaDec prefill (workaround)"
                                 : "guest in-VM decode (prefill DISABLED)");
    WG_LOGI(TAG, "Engine ready");
    return true;
}

static bool ensure_blink_vm(WGEngine *engine, bool is_64bit) {
    // Always create a fresh VM for each PE load
    if (engine->blink) {
        wg_blink_destroy(engine->blink);
        engine->blink = NULL;
        engine->thunks_mapped = false;
    }

    if (is_64bit) {
        engine->blink = wg_blink_create();
    } else {
        engine->blink = wg_blink_create32();
    }

    if (!engine->blink) {
        WG_LOGW(TAG, "Blink unavailable, falling back to builtin");
        engine->backend = WG_BACKEND_BUILTIN;
        return false;
    }

    // Warm-up
    uint8_t warmup[] = { 0x90, 0xC3 };
    wg_blink_load_code(engine->blink, 0x3F0000, warmup, sizeof(warmup), 0x3F0000);
    WGBlinkResult wr = wg_blink_run(engine->blink, 10);
    WG_LOGI(TAG, "Blink JIT warm-up: %s",
            wr == WG_BLINK_HALT ? "OK" : "absorbed first-run init");

    map_thunks_to_blink(engine);
    return true;
}

static bool load_pe_blink(WGEngine *engine) {
    WGPEImage *pe = engine->pe_image;

    if (!ensure_blink_vm(engine, pe->is_64bit)) {
        return false;
    }

    WG_LOGI(TAG, "Loading %s PE via blink", pe->is_64bit ? "64-bit" : "32-bit");
    s_nsis_data_patched = false;
    s_nsis_exe_data_offset = 0;

    for (int i = 0; i < pe->num_sections; i++) {
        WGPESection *sec = &pe->sections[i];
        uint64_t base = pe->image_base + sec->virtual_address;

        WG_LOGI(TAG, "  Section '%s': VA=0x%llx Size=0x%x",
                sec->name, (unsigned long long)base, sec->virtual_size);

        if (sec->virtual_size > 0) {
            uint8_t *zeros = calloc(1, sec->virtual_size);
            if (zeros) {
                wg_blink_load_code(engine->blink, base, zeros, sec->virtual_size, 0);
                free(zeros);
            }
            if (sec->data && sec->raw_size > 0) {
                uint32_t copy_size = sec->raw_size < sec->virtual_size
                    ? sec->raw_size : sec->virtual_size;
                wg_blink_write_mem(engine->blink, base, sec->data, copy_size);
            }
        }
    }

    // Resolve imports — write thunk addresses into the IAT
    if (pe->num_imports > 0) {
        WG_LOGI(TAG, "Resolving %d DLL imports...", pe->num_imports);
        for (int i = 0; i < pe->num_imports; i++) {
            WGPEImportDll *imp = &pe->imports[i];
            WG_LOGI(TAG, "  %s: %d functions", imp->dll_name, imp->num_functions);

            for (int j = 0; j < imp->num_functions; j++) {
                uint64_t stub_addr = wg_dll_mapper_resolve(
                    engine->dll_mapper, imp->dll_name, imp->functions[j].name);
                if (stub_addr) {
                    uint64_t iat_entry = pe->image_base + imp->functions[j].iat_rva;
                    uint8_t addr_bytes[8];
                    memcpy(addr_bytes, &stub_addr, 8);
                    wg_blink_write_mem(engine->blink, iat_entry, addr_bytes, 8);
                }
            }
        }
    }

    uint64_t entry = pe->image_base + pe->entry_point;

    // Set up stack BEFORE switching to 32-bit (stack setup uses ReserveVirtual)
    if (!wg_blink_setup_stack(engine->blink, entry)) {
        WG_LOGE(TAG, "Failed to set up stack");
        return false;
    }

    // NOW switch to 32-bit mode if this is a 32-bit PE
    if (!pe->is_64bit) {
        wg_blink_switch_to_32bit(engine->blink);
    }

    WG_LOGI(TAG, "PE mapped via blink. Entry: 0x%llx", (unsigned long long)entry);
    return true;
}

static bool load_pe_builtin(WGEngine *engine) {
    WGPEImage *pe = engine->pe_image;

    for (int i = 0; i < pe->num_sections; i++) {
        WGPESection *sec = &pe->sections[i];
        uint64_t base = pe->image_base + sec->virtual_address;

        uint32_t prot = WG_MEM_READ;
        if (sec->characteristics & 0x20000000) prot |= WG_MEM_EXEC;
        if (sec->characteristics & 0x80000000) prot |= WG_MEM_WRITE;

        if (!wg_memory_map(engine->memory, base, sec->virtual_size, prot))
            return false;
        if (sec->data && sec->raw_size > 0) {
            uint32_t copy_size = sec->raw_size < sec->virtual_size
                ? sec->raw_size : sec->virtual_size;
            wg_memory_write(engine->memory, base, sec->data, copy_size);
        }
    }

    if (pe->num_imports > 0) {
        for (int i = 0; i < pe->num_imports; i++) {
            WGPEImportDll *imp = &pe->imports[i];
            for (int j = 0; j < imp->num_functions; j++) {
                uint64_t stub_addr = wg_dll_mapper_resolve(
                    engine->dll_mapper, imp->dll_name, imp->functions[j].name);
                if (stub_addr) {
                    uint64_t iat_entry = pe->image_base + imp->functions[j].iat_rva;
                    wg_memory_write_u64(engine->memory, iat_entry, stub_addr);
                }
            }
        }
    }

    uint64_t entry = pe->image_base + pe->entry_point;
    wg_x86_set_rip(engine->cpu, entry);
    uint64_t stack_base = 0x7FFE0000;
    wg_memory_map(engine->memory, stack_base - 0x100000, 0x100000,
                  WG_MEM_READ | WG_MEM_WRITE);
    wg_x86_set_reg(engine->cpu, WG_REG_RSP, stack_base - 0x100);
    wg_x86_set_reg(engine->cpu, WG_REG_RBP, stack_base - 0x100);

    return true;
}

bool wg_engine_load_pe(WGEngine *engine, const char *path) {
    WG_LOGI(TAG, "Loading PE: %s", path);

    // Clear any windows left over from a previous program so the UI doesn't
    // get stuck behind a lingering window.
    wg_wm_reset();

    // Reset the guest heap so every run has an identical, deterministic layout.
    s_heap_ptr = WG_GUEST_HEAP_BASE;
    s_nsis_data_patched = false;
    s_last_error = 0;
    s_nsis_data_tmp_handle = 0;
    s_nsis_data_tmp_path[0] = 0;
    s_nsis_last_data_seek = 0;
    s_dlg_active = false;
    s_dlg_hwnd = 0;
    s_dlg_proc = 0;
    s_ctrl_count = 0;
    s_callstack_depth = 0;
    wg_bitmap_reset_all();

    // Set the exe path for file I/O mapping
    wg_files_set_exe_path(path);

    engine->pe_image = wg_pe_load_file(path);
    if (!engine->pe_image) {
        WG_LOGE(TAG, "Failed to parse PE file");
        engine->state = WG_ENGINE_ERROR;
        return false;
    }

    WG_LOGI(TAG, "PE parsed: %d sections, entry=0x%x, image_base=0x%llx",
            engine->pe_image->num_sections,
            engine->pe_image->entry_point,
            (unsigned long long)engine->pe_image->image_base);

    bool ok = false;
    if (engine->backend == WG_BACKEND_BLINK) {
        ok = load_pe_blink(engine); // this creates the blink VM on demand
    }
    if (!ok) {
        ok = load_pe_builtin(engine);
    }

    if (ok) engine->state = WG_ENGINE_LOADED;
    else    engine->state = WG_ENGINE_ERROR;
    return ok;
}

bool wg_engine_load_pe_memory(WGEngine *engine, const uint8_t *data, size_t size) {
    WG_LOGI(TAG, "Loading PE from memory (%zu bytes)", size);

    engine->pe_image = wg_pe_load_memory(data, size);
    if (!engine->pe_image) {
        WG_LOGE(TAG, "Failed to parse PE");
        engine->state = WG_ENGINE_ERROR;
        return false;
    }

    WG_LOGI(TAG, "PE parsed: %d sections, entry=0x%x, imports=%d",
            engine->pe_image->num_sections,
            engine->pe_image->entry_point,
            engine->pe_image->num_imports);

    bool ok = false;
    if (engine->backend == WG_BACKEND_BLINK) {
        ok = load_pe_blink(engine);
    }
    if (!ok) {
        ok = load_pe_builtin(engine);
    }

    if (ok) engine->state = WG_ENGINE_LOADED;
    else    engine->state = WG_ENGINE_ERROR;
    return ok;
}

bool wg_engine_run(WGEngine *engine) {
    if (engine->state != WG_ENGINE_LOADED) {
        WG_LOGE(TAG, "Cannot run: no PE loaded (state=%d)", engine->state);
        return false;
    }
    engine->state = WG_ENGINE_RUNNING;
    WG_LOGI(TAG, "Execution started (backend: %s)",
            engine->backend == WG_BACKEND_BLINK ? "blink" : "builtin");
    return true;
}

void wg_engine_tick(WGEngine *engine) {
    if (!engine || engine->state != WG_ENGINE_RUNNING) return;

    engine->tick_count++;

    if (engine->blink) {
        WGBlinkResult r = wg_blink_run(engine->blink, engine->instructions_per_tick);
        switch (r) {
            case WG_BLINK_OK:
                break;
            case WG_BLINK_HALT: {
                if (handle_blink_thunk(engine)) break;
                uint64_t halt_rip = wg_blink_get_rip(engine->blink);
                if (halt_rip == 0) {
                    WG_LOGI(TAG, "Program exited normally after %llu ticks",
                            (unsigned long long)engine->tick_count);
                } else {
                    WG_LOGE(TAG, "Crash at RIP=0x%llx (SIGSEGV — bad pointer or unmapped memory)",
                            (unsigned long long)halt_rip);
                }
                engine->state = WG_ENGINE_STOPPED;
                break;
            }
            case WG_BLINK_SYSCALL:
                WG_LOGD(TAG, "Syscall intercepted (blink)");
                break;
            case WG_BLINK_ERROR:
                if (handle_blink_thunk(engine)) break;
                WG_LOGE(TAG, "Crash at RIP=0x%llx",
                        (unsigned long long)wg_blink_get_rip(engine->blink));
                engine->state = WG_ENGINE_STOPPED;
                break;
        }
    } else {
        WGInterpResult r = wg_x86_exec_block(
            engine->cpu, engine->memory, engine->instructions_per_tick);
        switch (r) {
            case WG_INTERP_OK: break;
            case WG_INTERP_HALT:
                engine->state = WG_ENGINE_STOPPED;
                break;
            case WG_INTERP_SYSCALL:
                break;
            case WG_INTERP_ERROR:
                engine->state = WG_ENGINE_ERROR;
                break;
        }
    }
}

// Run the engine synchronously until it halts or errors.
// Uses small instruction batches so thunks are caught promptly.
WGEngineState wg_engine_run_sync(WGEngine *engine, int max_ticks) {
    if (!wg_engine_run(engine)) return engine->state;

    int saved = engine->instructions_per_tick;
    engine->instructions_per_tick = 1000; // smaller batches for thunk detection

    for (int i = 0; i < max_ticks; i++) {
        wg_engine_tick(engine);
        if (engine->state != WG_ENGINE_RUNNING) break;
    }

    engine->instructions_per_tick = saved;
    return engine->state;
}

void wg_engine_resume(WGEngine *engine) {
    if (!engine || engine->state != WG_ENGINE_PAUSED) return;
    WG_LOGI(TAG, "Resuming from dialog pause");
    engine->state = WG_ENGINE_RUNNING;
}

// True when a modal dialog is up and waiting for input (Next/Cancel/...).
bool wg_engine_dialog_active(WGEngine *engine) {
    (void)engine;
    return s_dlg_active;
}

// Deliver a button click to the modal dialog: WM_COMMAND(ctrl_id, BN_CLICKED).
// Re-enters the dialog proc so NSIS advances the wizard (and eventually calls
// EndDialog). Common ids: 1 = Next/Install (IDOK), 2 = Cancel, 3 = Back.
void wg_engine_dialog_command(WGEngine *engine, uint32_t ctrl_id) {
    if (!engine || !s_dlg_active || !s_dlg_proc) return;
    if (engine->state != WG_ENGINE_PAUSED) return;
    WGDlgCtrl *c = wg_find_ctrl(s_dlg_hwnd, ctrl_id);
    uint32_t ctrl_hwnd = c ? (WG_CTRL_HWND_BASE + (uint32_t)(c - s_ctrls)) : 0;
    uint32_t esp = (uint32_t)wg_blink_get_reg(engine->blink, 4);
    uint32_t new_rsp = esp - 20;
    uint32_t stack_data[5] = {
        WG_DLG_SENTINEL,          // return trap
        s_dlg_hwnd,               // hwnd
        0x0111,                   // WM_COMMAND
        ctrl_id,                  // wParam = MAKEWPARAM(id, BN_CLICKED=0)
        ctrl_hwnd                 // lParam = control handle
    };
    wg_blink_write_mem(engine->blink, new_rsp, stack_data, 20);
    wg_blink_set_reg(engine->blink, 4, new_rsp);
    wg_blink_set_rip(engine->blink, s_dlg_proc);
    wg_blink_set_reg(engine->blink, 0, 0);
    engine->state = WG_ENGINE_RUNNING;
    WG_LOGI(TAG, "Dialog command: WM_COMMAND id=%u -> dlgproc 0x%X", ctrl_id, s_dlg_proc);
}

// Hit-test a point (in the compositor's 800x600 virtual space) against the
// modal dialog's buttons. Returns the button control id under the point (so the
// caller can wg_engine_dialog_command it), or 0. Lets the user tap the actual
// Back/Next/Cancel rendered in the window instead of native overlay buttons.
uint32_t wg_engine_hit_test(WGEngine *engine, int virt_x, int virt_y) {
    (void)engine;
    if (!s_dlg_active || !s_dlg_hwnd) return 0;
    WGWin32Window *w = wg_wm_find(s_dlg_hwnd);
    if (!w) return 0;
    int32_t cw = 0, ch = 0;
    if (!wg_wm_get_client(s_dlg_hwnd, &cw, &ch)) return 0;
    int tb = (w->parent == 0) ? WG_TITLEBAR_H : 0;
    int cx = virt_x - w->x;
    int cy = virt_y - (w->y + tb);            // into client coords
    if (cx < 0 || cy < 0 || cx >= cw || cy >= ch) return 0;
    for (int i = 0; i < s_ctrl_count; i++) {
        WGDlgCtrl *c = &s_ctrls[i];
        if (c->hwnd != s_dlg_hwnd || c->cls != 0x0080) continue;  // buttons only
        if (!(c->style & 0x10000000u)) continue;                  // WS_VISIBLE
        float sx = c->dlg_cx ? (float)cw / c->dlg_cx : 1.0f;
        float sy = c->dlg_cy ? (float)ch / c->dlg_cy : 1.0f;
        int px = (int)(c->x * sx), py = (int)(c->y * sy);
        int pw = (int)(c->cx * sx), ph = (int)(c->cy * sy);
        if (cx >= px && cx < px + pw && cy >= py && cy < py + ph) return c->id;
    }
    return 0;
}

void wg_engine_stop(WGEngine *engine) {
    if (!engine) return;
    if (engine->state == WG_ENGINE_RUNNING) {
        engine->state = WG_ENGINE_STOPPED;
    }
}

WGEngineState wg_engine_get_state(const WGEngine *engine) {
    return engine ? engine->state : WG_ENGINE_ERROR;
}
