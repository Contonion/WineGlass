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
#include "wg_winsock.h"
#include "wg_threading.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>

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

// ===== Real in-VM DLL / NSIS-plug-in loading ==============================
// NSIS calls a plug-in as GetModuleHandle(dll) -> (NULL) LoadLibrary ->
// GetProcAddress(export) -> call. A faked module handle can't satisfy that, so
// we actually map the DLL into the blink VM (sections, base relocations,
// imports wired to our thunks) and parse its export table. This is also the
// foundation for eventually running steam.exe's own DLLs.
typedef struct {
    bool       in_use;
    char       name[64];   // lowercased base filename, e.g. "nsprocess.dll"
    uint32_t   base;       // load address in guest space
    uint32_t   size;       // image size
    WGPEImage *img;        // kept for export-table lookups
} WGLoadedModule;
static WGLoadedModule s_modules[16];
static uint32_t s_dll_next_base = 0x60000000u;  // bump allocator for DLL bases

// Lowercased base filename from a Windows- or unix-style path.
static void dll_basename(const char *path, char *out, int outsz) {
    const char *p = path;
    for (const char *q = path; *q; q++)
        if (*q == '/' || *q == '\\') p = q + 1;
    int i = 0;
    for (; p[i] && i < outsz - 1; i++) out[i] = (char)tolower((unsigned char)p[i]);
    out[i] = '\0';
}

// Resolve an RVA to a pointer into the parsed file image (raw_data + sections).
static const uint8_t *pe_rva_ptr(WGPEImage *img, uint32_t rva, uint32_t need) {
    if (rva + need <= img->size_of_headers && rva + need <= img->raw_size)
        return img->raw_data + rva;
    for (int i = 0; i < img->num_sections; i++) {
        WGPESection *s = &img->sections[i];
        uint32_t vs = s->virtual_size ? s->virtual_size : s->raw_size;
        if (rva >= s->virtual_address && rva + need <= s->virtual_address + vs) {
            uint32_t off = rva - s->virtual_address;
            if (s->data && off + need <= s->raw_size) return s->data + off;
            return NULL;  // lives in uninitialized (bss) space
        }
    }
    return NULL;
}

// Load a DLL file into the VM. Returns the guest load base, or 0 on failure.
// Takes blink + mapper explicitly (rather than WGEngine, whose struct is
// defined further down) so it can live up here next to its helpers.
static uint32_t wg_load_dll(WGBlinkInstance *blink, WGDllMapper *mapper,
                            const char *real_path, const char *guest_name) {
    char base_name[64];
    dll_basename(guest_name, base_name, sizeof base_name);
    for (int i = 0; i < 16; i++)
        if (s_modules[i].in_use && strcmp(s_modules[i].name, base_name) == 0)
            return s_modules[i].base;   // same plug-in already mapped

    WGPEImage *img = wg_pe_load_file(real_path);
    if (!img) return 0;
    if (img->is_64bit) { wg_pe_image_free(img); return 0; }

    uint32_t preferred = (uint32_t)img->image_base;
    uint32_t img_size  = img->size_of_image ? img->size_of_image : 0x100000;
    uint32_t load_base;
    int32_t  delta;
    if (img->reloc_rva && img->reloc_size) {
        load_base = s_dll_next_base;
        s_dll_next_base = (s_dll_next_base + img_size + 0xFFFF) & ~0xFFFFu;
        delta = (int32_t)(load_base - preferred);
    } else {
        // No relocations — must load at the preferred base.
        load_base = preferred;
        delta = 0;
    }

    // Map headers, then each section (zero-fill then copy raw bytes).
    if (img->size_of_headers && img->raw_size >= img->size_of_headers)
        wg_blink_write_mem(blink, load_base, img->raw_data, img->size_of_headers);
    for (int i = 0; i < img->num_sections; i++) {
        WGPESection *s = &img->sections[i];
        if (!s->virtual_size) continue;
        uint64_t va = load_base + s->virtual_address;
        uint8_t *zeros = calloc(1, s->virtual_size);
        if (zeros) { wg_blink_load_code(blink, va, zeros, s->virtual_size, 0); free(zeros); }
        if (s->data && s->raw_size) {
            uint32_t n = s->raw_size < s->virtual_size ? s->raw_size : s->virtual_size;
            wg_blink_write_mem(blink, va, s->data, n);
        }
    }

    // Apply base relocations (HIGHLOW only — 32-bit DLLs).
    if (delta && img->reloc_rva && img->reloc_size) {
        uint32_t off = 0;
        while (off + 8 <= img->reloc_size) {
            const uint8_t *blk = pe_rva_ptr(img, img->reloc_rva + off, 8);
            if (!blk) break;
            uint32_t page_rva, blk_size;
            memcpy(&page_rva, blk, 4); memcpy(&blk_size, blk + 4, 4);
            if (blk_size < 8 || off + blk_size > img->reloc_size) break;
            uint32_t nent = (blk_size - 8) / 2;
            const uint8_t *ents = pe_rva_ptr(img, img->reloc_rva + off + 8, nent * 2);
            if (!ents) break;
            for (uint32_t e = 0; e < nent; e++) {
                uint16_t v; memcpy(&v, ents + e * 2, 2);
                if ((v >> 12) == 3 /*IMAGE_REL_BASED_HIGHLOW*/) {
                    uint32_t target = load_base + page_rva + (v & 0xFFF);
                    uint32_t val = 0;
                    wg_blink_read_mem(blink, target, &val, 4);
                    val += (uint32_t)delta;
                    wg_blink_write_mem(blink, target, &val, 4);
                }
            }
            off += blk_size;
        }
    }

    // Resolve the DLL's own imports against our Win32 thunk table.
    for (int i = 0; i < img->num_imports; i++) {
        WGPEImportDll *imp = &img->imports[i];
        for (int j = 0; j < imp->num_functions; j++) {
            uint64_t stub = wg_dll_mapper_resolve(mapper,
                                                  imp->dll_name, imp->functions[j].name);
            if (stub) {
                uint32_t iat = load_base + imp->functions[j].iat_rva;
                uint32_t s32 = (uint32_t)stub;
                wg_blink_write_mem(blink, iat, &s32, 4);
            }
        }
    }

    for (int i = 0; i < 16; i++) {
        if (!s_modules[i].in_use) {
            s_modules[i].in_use = true;
            strncpy(s_modules[i].name, base_name, sizeof(s_modules[i].name) - 1);
            s_modules[i].base = load_base;
            s_modules[i].size = img_size;
            s_modules[i].img  = img;
            WG_LOGI(TAG, "Loaded DLL %s at 0x%X (size 0x%X, reloc delta 0x%X)",
                    base_name, load_base, img_size, (uint32_t)delta);
            return load_base;
        }
    }
    wg_pe_image_free(img);   // module table full — leave it mapped, drop record
    return load_base;
}

// Look up an export by name in a loaded module; returns its guest address or 0.
static uint32_t wg_module_export(uint32_t base, const char *func) {
    for (int m = 0; m < 16; m++) {
        if (!s_modules[m].in_use || s_modules[m].base != base) continue;
        // nsProcess is loaded for real, but its process-enumeration exports are
        // meaningless on iOS (no Windows processes exist) and the real path
        // doesn't work here. Return 0 so GetProcAddress falls through to our
        // emulated FindProcess/KillProcess thunk (reports "not running").
        if (strcmp(s_modules[m].name, "nsprocess.dll") == 0) return 0;
        // nsExec runs an external process (steamservice.exe) and reads its
        // stdout in a loop — we can't run child processes, and the real loop
        // hangs. Emulate its exports (Exec/ExecToLog/ExecToStack) instead.
        if (strcmp(s_modules[m].name, "nsexec.dll") == 0) return 0;
        WGPEImage *img = s_modules[m].img;
        if (!img->export_rva || !img->export_size) return 0;
        const uint8_t *ed = pe_rva_ptr(img, img->export_rva, 40);
        if (!ed) return 0;
        uint32_t nfuncs, nnames, func_rva, name_rva, ord_rva;
        memcpy(&nfuncs,   ed + 20, 4);
        memcpy(&nnames,   ed + 24, 4);
        memcpy(&func_rva, ed + 28, 4);
        memcpy(&name_rva, ed + 32, 4);
        memcpy(&ord_rva,  ed + 36, 4);
        const uint8_t *names = pe_rva_ptr(img, name_rva, nnames * 4);
        const uint8_t *ords  = pe_rva_ptr(img, ord_rva,  nnames * 2);
        const uint8_t *funcs = pe_rva_ptr(img, func_rva, nfuncs * 4);
        if (!names || !ords || !funcs) return 0;
        for (uint32_t k = 0; k < nnames; k++) {
            uint32_t nrva; memcpy(&nrva, names + k * 4, 4);
            const char *nm = (const char *)pe_rva_ptr(img, nrva, 1);
            if (nm && strcmp(nm, func) == 0) {
                uint16_t idx; memcpy(&idx, ords + k * 2, 2);
                if (idx >= nfuncs) return 0;
                uint32_t frva; memcpy(&frva, funcs + idx * 4, 4);
                return base + frva;
            }
        }
        return 0;
    }
    return 0;
}

// Return the load base of an already-loaded module matching a path, or 0.
static uint32_t wg_module_find(const char *path) {
    char base_name[64];
    dll_basename(path, base_name, sizeof base_name);
    for (int i = 0; i < 16; i++)
        if (s_modules[i].in_use && strcmp(s_modules[i].name, base_name) == 0)
            return s_modules[i].base;
    return 0;
}

typedef enum {
    WG_BACKEND_BUILTIN,
    WG_BACKEND_BLINK,
} WGBackend;

static uint32_t s_last_error = 0;

// Ring buffer of recent Win32 API calls for crash diagnostics
#define WG_CALL_RING_SIZE 256
static struct { const char *fn; uint64_t ret; } s_call_ring[WG_CALL_RING_SIZE];
static int s_call_ring_idx = 0;
static inline void wg_call_ring_push(const char *name, uint64_t ret) {
    // Filter out noisy cleanup/infrastructure calls
    if (name[0] == 'H' && (name[4] == 'F' || name[4] == 'S' || name[4] == 'A'))
        return; // HeapFree, HeapSize, HeapAlloc
    if (name[0] == 'D' && name[1] == 'e') return; // DeleteCriticalSection
    if (name[0] == 'E' && name[5] == 'C') return; // EnterCriticalSection
    if (name[0] == 'L' && name[5] == 'C') return; // LeaveCriticalSection
    if (name[0] == 'T' && name[3] == 'E') return; // TryEnterCriticalSection
    if (name[0] == 'G' && name[3] == 'L') return; // GetLastError
    if (name[0] == 'S' && name[3] == 'L') return; // SetLastError
    if (name[0] == 'F' && name[3] == 'G') return; // FlsGetValue
    if (name[0] == 'F' && name[3] == 'S') return; // FlsSetValue
    int idx = s_call_ring_idx % WG_CALL_RING_SIZE;
    s_call_ring[idx].fn = name;
    s_call_ring[idx].ret = ret;
    s_call_ring_idx++;
}
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

// Dynamic TLS (TlsAlloc/TlsGetValue/TlsSetValue). Single guest thread -> one
// global slot array. Windows guarantees at least 1088 TLS slots.
static uint32_t s_tls_slots[1088] = {0};
static uint32_t s_tls_next = 0;
static uint32_t s_fls_slots[1088] = {0};   // Fiber-Local Storage (CRT uses it)
static uint32_t s_fls_next = 0;

// Fake event/mutex/semaphore handles. Single-threaded, so events are just
// signalled/unsignalled flags. Handles start at 0x200 to avoid collisions.
#define WG_EVENT_BASE   0x200u
#define WG_MAX_EVENTS   256
static bool s_event_signalled[WG_MAX_EVENTS];
static uint32_t s_event_next = 0;
static uint32_t s_main_teb = 0; // TEB address of main thread
static bool s_cmdpage_mapped = false;
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
    WGWinsock          *winsock;
    WGThreadScheduler  *scheduler;
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
    e->winsock = wg_winsock_create();
    e->scheduler = wg_sched_create();
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
    if (engine->winsock) wg_winsock_destroy(engine->winsock);
    if (engine->scheduler) wg_sched_destroy(engine->scheduler);
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

// Synthetic control classes for runtime-styled instfiles controls so the
// renderer can draw them (the dialog template stores these as class-NAME
// strings, not atoms).
#define WG_CLS_PROGRESS 0x0090   // msctls_progress32
#define WG_CLS_LISTVIEW 0x0091   // SysListView32 (the "details" log)

// Install-progress + details-log state (driven by PBM_SETPOS / LVM_INSERTITEM).
static uint32_t s_pb_pos = 0, s_pb_max = 100;
static char     s_detail_lines[256][120];
static int      s_detail_count = 0;
static uint32_t s_page_hwnd = 0;   // current inner page (where progress/list live)

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
        else {
            // String class name — capture it so we can render the progress bar
            // and the "details" list (which have name classes, not atoms).
            uint16_t clsname[40] = {0};
            p = res_skip_sz(p, clsname, 40);
            char ca[40] = {0};
            for (int k = 0; k < 39 && clsname[k]; k++)
                ca[k] = clsname[k] < 128 ? (char)tolower((unsigned char)clsname[k]) : '?';
            if (strstr(ca, "progress"))       c->cls = WG_CLS_PROGRESS;
            else if (strstr(ca, "listview") || strstr(ca, "syslistview"))
                                              c->cls = WG_CLS_LISTVIEW;
            else                              c->cls = 0;
        }
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
        // Always show the progress bar + details log even if NSIS left them
        // initially hidden (the "Show details" toggle isn't wired for synthetic
        // controls); seeing the install log/progress is more useful than hiding.
        bool force = (c->cls == WG_CLS_PROGRESS) ||
                     (c->cls == WG_CLS_LISTVIEW && s_detail_count > 0);
        if (!force && !(c->style & 0x10000000u /*WS_VISIBLE*/)) continue;
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
        } else if (c->cls == WG_CLS_PROGRESS) {     // msctls_progress32
            wg_gdi_fill_rect(dc, px, py, px + pw, py + ph, 0x00C8C8C8);   // trough
            uint32_t mx = s_pb_max ? s_pb_max : 100;
            int fill = (int)((float)pw * (s_pb_pos > mx ? mx : s_pb_pos) / mx);
            if (fill > 0) wg_gdi_fill_rect(dc, px, py, px + fill, py + ph, 0x00D77800);
            wg_gdi_fill_rect(dc, px, py, px + pw, py + 1, 0x00808080);    // top border
        } else if (c->cls == WG_CLS_LISTVIEW) {     // the "details" install log
            wg_gdi_fill_rect(dc, px, py, px + pw, py + ph, 0x00FFFFFF);
            wg_gdi_fill_rect(dc, px, py, px + pw, py + 1, 0x00808080);
            int lh = 11, rows = ph / lh;             // show the most recent lines
            int first = s_detail_count > rows ? s_detail_count - rows : 0;
            for (int r = first; r < s_detail_count; r++) {
                uint16_t wline[120]; int n = 0;
                for (; n < 119 && s_detail_lines[r][n]; n++) wline[n] = (uint8_t)s_detail_lines[r][n];
                wline[n] = 0;
                if (n) wg_gdi_text_out(dc, px + 3, py + 2 + (r - first) * lh, wline, n);
            }
        }
    }
    wg_gdi_release_dc(dc);
    WGWin32Window *w = wg_wm_find(hwnd);
    if (w) w->client_dirty = true;
}

// Register a control created at runtime via CreateWindowExW (e.g. an nsDialogs
// label/button/edit) so it paints on its parent page. Coordinates are pixels;
// we set the control's "dialog extent" to the parent's client size so the
// (scale = client/extent = 1) render path draws it at those exact pixels.
static void wg_register_child_control(uint32_t parent, uint32_t id, uint32_t style,
                                      uint16_t cls, int x, int y, int w, int h,
                                      const uint16_t *text) {
    if (s_ctrl_count >= 160) return;
    int32_t cw = 0, chh = 0;
    wg_wm_get_client(parent, &cw, &chh);
    WGDlgCtrl *c = &s_ctrls[s_ctrl_count++];
    memset(c, 0, sizeof(*c));
    c->hwnd  = parent;
    c->id    = id;
    c->style = style | 0x10000000u;          // force WS_VISIBLE so it paints
    c->dlg_cx = (int16_t)(cw  > 0 ? cw  : 1);
    c->dlg_cy = (int16_t)(chh > 0 ? chh : 1);
    c->x = (int16_t)x; c->y = (int16_t)y;
    c->cx = (int16_t)w; c->cy = (int16_t)h;
    c->cls = cls;
    if (text) for (int i = 0; i < 79 && text[i]; i++) c->text[i] = text[i];
}

// ---- Synchronous SendMessage / wndproc dispatch ----
// SendMessage must call the target window's procedure and return its result.
// We do this by jumping into the wndproc with a dedicated sentinel return; when
// it returns, the sentinel restores the SendMessage caller with the result. A
// small stack handles nested SendMessages (NSIS nests them heavily).
#define WG_SENDMSG_SENTINEL 0xC10010u
// A real Win32 call (SendMessage, CreateDialogParamW) preserves the caller's
// nonvolatile registers. Our synchronous dispatch jumps straight into the guest
// wndproc, so we snapshot the caller's GPRs here and restore them when the
// sentinel fires — otherwise the wndproc clobbers e.g. ESI and the caller faults
// (NSIS's CreateDialogParamW caller does `push [esi+0x2c]` right after the call).
typedef struct {
    uint32_t ret_addr, ret_rsp, ovr_eax; bool ovr;
    uint64_t saved_regs[16];
} WGPendingCall;
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
    WGPendingCall *fr = &s_callstack[s_callstack_depth];
    fr->ret_addr = ret_addr;
    fr->ret_rsp  = clean_rsp;
    fr->ovr      = ovr;
    fr->ovr_eax  = ovr_eax;
    // Snapshot the caller's registers so the wndproc can't leak clobbered
    // nonvolatile regs (ESI/EDI/EBX/EBP) back to the caller.
    for (int i = 0; i < 16; i++)
        fr->saved_regs[i] = wg_blink_get_reg(engine->blink, i);
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

// Allocation size tracking for HeapSize
#define WG_MAX_ALLOCS 8192
static struct { uint32_t addr; uint32_t size; } s_alloc_sizes[WG_MAX_ALLOCS];
static int s_alloc_count = 0;

static void track_alloc(uint32_t addr, uint32_t size) {
    if (s_alloc_count < WG_MAX_ALLOCS) {
        s_alloc_sizes[s_alloc_count].addr = addr;
        s_alloc_sizes[s_alloc_count].size = size;
        s_alloc_count++;
    }
}

static uint32_t lookup_alloc_size(uint32_t addr) {
    for (int i = s_alloc_count - 1; i >= 0; i--) {
        if (s_alloc_sizes[i].addr == addr)
            return s_alloc_sizes[i].size;
    }
    return 0;
}

// Bump-allocate `size` bytes of zeroed guest heap (shared with GlobalAlloc).
// Returns the guest address, or 0 on failure. Used by the CRT allocators that
// real DLLs (StdUtils, and eventually steam.exe) call.
static uint32_t wg_guest_alloc(WGEngine *engine, uint32_t size) {
    if (size == 0) size = 1;
    if ((size & 0x80000000u) || size > 512u * 1024 * 1024) return 0;
    uint32_t alloc = (size + 0xFFF) & ~0xFFFu;
    uint32_t addr = s_heap_ptr;
    uint8_t *zeros = calloc(1, alloc);
    if (!zeros) return 0;
    wg_blink_load_code(engine->blink, addr, zeros, alloc, 0);
    free(zeros);
    s_heap_ptr += alloc;
    s_heap_ptr = (s_heap_ptr + 0xFFF) & ~0xFFFu;
    track_alloc(addr, size);
    return addr;
}

// ---- Fake COM IShellLink / IPersistFile -----------------------------------
// NSIS CreateShortcut does CoCreateInstance(IShellLink) -> Set*/QueryInterface
// (IPersistFile) -> Save. Failing CoCreateInstance makes it log "Error creating
// shortcut". Shortcuts are meaningless on iOS, but we hand back a minimal COM
// object whose methods all return S_OK (QueryInterface yields the IPersistFile)
// so the wizard finishes cleanly. Method thunks are registered with the correct
// stdcall arg counts (so the stack stays balanced); all but QueryInterface just
// return S_OK via default_ret=0.
static uint32_t s_com_qi, s_com_a1, s_com_a2, s_com_a3, s_com_a4, s_com_a5;
static uint32_t s_com_shelllink = 0, s_com_persistfile = 0;

// Real path of a program the guest asked to launch (the Steam bootstrapper);
// the app chain-loads it after the current program exits.
static char s_pending_exec[1024] = {0};

static void wg_build_fake_com(WGEngine *engine) {
    WGDllMapper *m = engine->dll_mapper;
    if (!s_com_qi) {   // register method thunks once (mapper persists across loads)
        s_com_qi = (uint32_t)wg_dll_mapper_register(m, "COM", "__comQI", NULL, 3);
        s_com_a1 = (uint32_t)wg_dll_mapper_register(m, "COM", "__comA1", NULL, 1);
        s_com_a2 = (uint32_t)wg_dll_mapper_register(m, "COM", "__comA2", NULL, 2);
        s_com_a3 = (uint32_t)wg_dll_mapper_register(m, "COM", "__comA3", NULL, 3);
        s_com_a4 = (uint32_t)wg_dll_mapper_register(m, "COM", "__comA4", NULL, 4);
        s_com_a5 = (uint32_t)wg_dll_mapper_register(m, "COM", "__comA5", NULL, 5);
    }
    if (s_com_shelllink) return;   // guest objects already built this run
    // IShellLinkW vtable (21 slots): QI, AddRef, Release, GetPath, GetIDList,
    // SetIDList, Get/SetDescription, Get/SetWorkingDirectory, Get/SetArguments,
    // Get/SetHotkey, Get/SetShowCmd, GetIconLocation, SetIconLocation,
    // SetRelativePath, Resolve, SetPath.
    uint32_t SL[21] = {
        s_com_qi, s_com_a1, s_com_a1,
        s_com_a5, s_com_a2, s_com_a2,
        s_com_a3, s_com_a2, s_com_a3, s_com_a2,
        s_com_a3, s_com_a2, s_com_a2, s_com_a2,
        s_com_a2, s_com_a2, s_com_a4, s_com_a3,
        s_com_a3, s_com_a3, s_com_a2,
    };
    // IPersistFile vtable (9 slots): QI, AddRef, Release, GetClassID, IsDirty,
    // Load, Save, SaveCompleted, GetCurFile.
    uint32_t PF[9] = {
        s_com_qi, s_com_a1, s_com_a1, s_com_a2,
        s_com_a1, s_com_a3, s_com_a3, s_com_a2, s_com_a2,
    };
    uint32_t slv = wg_guest_alloc(engine, sizeof SL);
    uint32_t pfv = wg_guest_alloc(engine, sizeof PF);
    s_com_shelllink   = wg_guest_alloc(engine, 8);
    s_com_persistfile = wg_guest_alloc(engine, 8);
    wg_blink_write_mem(engine->blink, slv, SL, sizeof SL);
    wg_blink_write_mem(engine->blink, pfv, PF, sizeof PF);
    wg_blink_write_mem(engine->blink, s_com_shelllink,   &slv, 4);
    wg_blink_write_mem(engine->blink, s_com_persistfile, &pfv, 4);
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
            // Restore the caller's registers (the wndproc may have clobbered
            // nonvolatile ones). RSP and RAX are set explicitly below.
            for (int i = 1; i < 16; i++) {
                if (i == 4) continue;            // RSP set from ret_rsp
                wg_blink_set_reg(engine->blink, i, pc->saved_regs[i]);
            }
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

    // Default return value: the registered stub's intent (R1S->1, etc.). The
    // explicit handlers below override this; functions NOT handled explicitly
    // now honor their registration instead of always returning 0 (the dead-stub
    // trap that silently broke IsWindowEnabled/CreateThread/GetExitCodeProcess…).
    uint64_t ret_val = entry ? (uint64_t)(int64_t)(int32_t)entry->default_ret : 0;

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
            // If this is a child control with a known window class (nsDialogs
            // builds its page body this way), register it so its text/box paints
            // on the parent page. args[8]=parent, args[9]=hMenu(=child id),
            // args[1]=class (string ptr for STATIC/BUTTON/EDIT, or an atom).
            if (args[8] && args[1] > 0xFFFF) {
                uint16_t clsw[40] = {0}; char clsa[40] = {0};
                wg_blink_read_mem(engine->blink, args[1], clsw, 78);
                for (int i = 0; i < 39 && clsw[i]; i++)
                    clsa[i] = clsw[i] < 128 ? (char)tolower((unsigned char)clsw[i]) : '?';
                uint16_t cls = 0;
                if (strstr(clsa, "static"))      cls = 0x0082;
                else if (strstr(clsa, "button")) cls = 0x0080;
                else if (strstr(clsa, "edit"))   cls = 0x0081;
                if (cls) {
                    wg_register_child_control(args[8], args[9], args[3], cls,
                                              (int32_t)args[4], (int32_t)args[5],
                                              (int32_t)args[6], (int32_t)args[7], title_buf);
                    if (s_dlg_active) wg_render_dialog(engine, args[8]);
                }
            }
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
            // Render text into the window's client area
            WGWin32Window *tw = wg_wm_find(args[0]);
            if (tw && tw->w > 0 && tw->h > 0 && text_buf[0]) {
                int32_t cw, ch;
                uint32_t *client = wg_wm_get_client(args[0], &cw, &ch);
                if (client && cw > 0 && ch > 0) {
                    // Fill with light gray background
                    for (int p = 0; p < cw * ch; p++)
                        client[p] = 0xFFF0F0F0;
                    // Count chars for text
                    int tlen = 0;
                    while (tlen < 255 && text_buf[tlen]) tlen++;
                    // Render text (use GDI text_out on this window's DC)
                    uint32_t dc = wg_gdi_get_dc(args[0]);
                    wg_gdi_set_text_color(dc, 0x00000000);
                    wg_gdi_text_out(dc, 4, (ch - 8) / 2, text_buf, tlen);
                    wg_gdi_release_dc(dc);
                    tw->client_dirty = true;
                }
            }
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
            WG_LOGI(TAG, "ExitProcess(%u) called from 0x%llX",
                    args[0], (unsigned long long)ret_addr);
            WG_LOGI(TAG, "  last API calls before exit:");
            for (int ri = 0; ri < WG_CALL_RING_SIZE; ri++) {
                int idx = (s_call_ring_idx - WG_CALL_RING_SIZE + ri) % WG_CALL_RING_SIZE;
                if (idx < 0) idx += WG_CALL_RING_SIZE;
                if (s_call_ring[idx].fn)
                    WG_LOGI(TAG, "    %s -> 0x%llX",
                        s_call_ring[idx].fn,
                        (unsigned long long)s_call_ring[idx].ret);
            }
            wg_blink_set_reg(engine->blink, 4, rsp + ptr_size);
            wg_blink_set_rip(engine->blink, 0);
            return true;
        } else if (strcmp(fn, "TerminateProcess") == 0) {
            // Real apps call TerminateProcess(GetCurrentProcess(), code) to die
            // (e.g. the CRT's __report_gsfailure / unhandled-exception path).
            // Halt the VM instead of returning (a no-op return runs into garbage
            // and SIGSEGVs). args[0]=hProcess, args[1]=exitCode.
            WG_LOGI(TAG, "TerminateProcess(0x%X, %u) -> halt", args[0], args[1]);
            wg_blink_set_rip(engine->blink, 0);
            return true;
        } else if (strcmp(fn, "GetStartupInfoW") == 0 ||
                   strcmp(fn, "GetStartupInfoA") == 0) {
            // Zero the STARTUPINFO(W) and set cb so the CRT reads sane values
            // (no STARTF_USESTDHANDLES, default show). Struct is 68 bytes (32-bit).
            if (args[0]) {
                uint8_t zero[68] = {0};
                uint32_t cb = 68; memcpy(zero, &cb, 4);
                wg_blink_write_mem(engine->blink, args[0], zero, 68);
            }
            ret_val = 0;
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

                // If hModule is a DLL we actually mapped, resolve from its real
                // export table so the plug-in's own code runs (e.g. nsProcess).
                uint32_t exp = wg_module_export(hmod, func_name);
                if (exp) {
                    ret_val = exp;
                    WG_LOGI(TAG, "GetProcAddress(%s) -> 0x%X (module export)",
                            func_name, exp);
                } else {
                    // Try the specific DLL first, then search all registered
                    // DLLs (GetProcAddress is often called with ws2_32/user32
                    // handles but we only have one mapper namespace).
                    ret_val = wg_dll_mapper_find_any(engine->dll_mapper, func_name);
                    if (!ret_val) {
                        ret_val = wg_dll_mapper_resolve(engine->dll_mapper, dll, func_name);
                    }
                    if (ret_val >= 0xC00000ULL && ret_val < 0xC00000ULL + 0x20000) {
                        uint8_t hlt = 0xF4;
                        wg_blink_write_mem(engine->blink, ret_val, &hlt, 1);
                    }
                    WG_LOGI(TAG, "GetProcAddress(%s) -> 0x%llx",
                            func_name, (unsigned long long)ret_val);
                }
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
        } else if (strcmp(fn, "LoadLibraryExW") == 0 ||
                   strcmp(fn, "LoadLibraryW") == 0) {
            // LoadLibrary[Ex]W(lpLibFileName, [hFile, dwFlags])
            uint16_t libname[512] = {0};
            char ascii[512] = {0};
            if (args[0]) {
                wg_blink_read_mem(engine->blink, args[0], libname, 1022);
                for (int i = 0; i < 511 && libname[i]; i++)
                    ascii[i] = libname[i] < 128 ? (char)libname[i] : '?';
            }
            WG_LOGI(TAG, "%s('%s')", fn, ascii);
            // Try to actually map the DLL from disk (NSIS plug-ins live in the
            // bottle). On success we return its real load base so GetProcAddress
            // + the call execute the plug-in's own code; otherwise (system DLLs
            // we don't have) fall back to a fake handle.
            uint32_t base = 0;
            char mapbuf[512];
            strncpy(mapbuf, ascii, sizeof(mapbuf) - 1);
            mapbuf[sizeof(mapbuf) - 1] = '\0';
            const char *real = wg_files_map_path(args[0], engine->blink,
                                                 mapbuf, sizeof(mapbuf));
            if (real) base = wg_load_dll(engine->blink, engine->dll_mapper, real, ascii);
            ret_val = base ? base
                           : 0x10000000 + (uint32_t)(engine->dll_mapper->count * 0x1000);
        } else if (strcmp(fn, "GetModuleHandleA") == 0) {
            uint32_t base = engine->pe_image ? (uint32_t)engine->pe_image->image_base : 0x400000;
            if (args[0] == 0) {
                ret_val = base;
            } else {
                char modname[256] = {0};
                wg_blink_read_mem(engine->blink, args[0], modname, 255);
                WG_LOGD(TAG, "GetModuleHandleA('%s')", modname);
                if (strcasestr(modname, "kernel32") ||
                    strcasestr(modname, "kernelbase") ||
                    strcasestr(modname, "ntdll") ||
                    strcasestr(modname, "ws2_32") ||
                    strcasestr(modname, "wsock32") ||
                    strcasestr(modname, "advapi32") ||
                    strcasestr(modname, "user32") ||
                    strcasestr(modname, "gdi32") ||
                    strcasestr(modname, "shell32") ||
                    strcasestr(modname, "ole32") ||
                    strcasestr(modname, "crypt32") ||
                    strcasestr(modname, "bcrypt") ||
                    strcasestr(modname, "msvcrt") ||
                    strcasestr(modname, "ucrtbase") ||
                    strcasestr(modname, "api-ms-win")) {
                    ret_val = 0xBFFF0000u;
                } else {
                    ret_val = 0;
                }
            }
        } else if (strcmp(fn, "GetModuleHandleW") == 0) {
            uint32_t base = engine->pe_image ? (uint32_t)engine->pe_image->image_base : 0x400000;
            if (args[0] == 0) {
                ret_val = base;
            } else {
                uint16_t modname[256] = {0};
                wg_blink_read_mem(engine->blink, args[0], modname, 510);
                char ascii[256] = {0};
                for (int i = 0; i < 255 && modname[i]; i++)
                    ascii[i] = modname[i] < 128 ? (char)modname[i] : '?';
                WG_LOGD(TAG, "GetModuleHandleW('%s')", ascii);
                uint32_t loaded = wg_module_find(ascii);
                if (strcasestr(ascii, "nsdialogs") || strstr(ascii, "nsDialogs")) {
                    // nsDialogs must NOT run for real — its message loop
                    // fights our DialogBoxParamW modal path. Return a fake
                    // handle so NSIS skips LoadLibrary; GetProcAddress on
                    // this handle auto-stubs harmlessly.
                    ret_val = 0xBFFF0000u;
                } else if (loaded) {
                    ret_val = loaded;
                } else if (strcasestr(ascii, "kernel32") ||
                           strcasestr(ascii, "kernelbase") ||
                           strcasestr(ascii, "ntdll") ||
                           strcasestr(ascii, "ws2_32") ||
                           strcasestr(ascii, "wsock32") ||
                           strcasestr(ascii, "advapi32") ||
                           strcasestr(ascii, "user32") ||
                           strcasestr(ascii, "gdi32") ||
                           strcasestr(ascii, "shell32") ||
                           strcasestr(ascii, "ole32") ||
                           strcasestr(ascii, "crypt32") ||
                           strcasestr(ascii, "bcrypt") ||
                           strcasestr(ascii, "msvcrt") ||
                           strcasestr(ascii, "ucrtbase") ||
                           strcasestr(ascii, "api-ms-win")) {
                    ret_val = 0xBFFF0000u;
                } else {
                    ret_val = 0;
                }
            }
        } else if (strstr(fn, "FindProcess") || strstr(fn, "KillProcess")) {
            // nsProcess plug-in (exports are _FindProcess/_KillProcess/
            // _FindProcessId/... in v1.6). Process enumeration is meaningless on
            // iOS — there is never a real Steam process — and the real DLL's
            // enumeration path doesn't work here (it bails after GetVersionEx and
            // reports "running"), so we emulate the result directly. Plug-in ABI:
            //   void f(HWND parent, int string_size, TCHAR *vars,
            //          stack_t **stacktop, extra_parameters *extra)
            // It pops the process name and pushes a result code. We reuse the top
            // node (struct stack_t { stack_t *next; TCHAR text[]; } — text at +4
            // in 32-bit) and overwrite its text:
            //   FindProcess: "603" = not found (it returns "0" when RUNNING)
            //   KillProcess: "0"   = success
            bool is_find = strstr(fn, "FindProcess") != NULL;
            uint32_t head = 0;
            if (args[3]) wg_blink_read_mem(engine->blink, args[3], &head, 4);
            if (head) {
                static const uint16_t notfound[] = {'6','0','3',0};
                static const uint16_t okstr[]    = {'0',0};
                wg_blink_write_mem(engine->blink, head + 4,
                                   is_find ? notfound : okstr,
                                   is_find ? sizeof(notfound) : sizeof(okstr));
            }
            WG_LOGI(TAG, "nsProcess::%s -> %s (emulated)", fn,
                    is_find ? "not running" : "ok");
            ret_val = 0;
        } else if (strcmp(fn, "Exec") == 0 || strcmp(fn, "ExecToLog") == 0 ||
                   strcmp(fn, "ExecToStack") == 0) {
            // nsExec plug-in. The real DLL spawns a child process (e.g.
            // steamservice.exe) and reads its stdout in a loop — we can't run
            // children, and that loop hangs the install. Emulate: pop the command
            // and push "0" (exit code success) onto the NSIS stack so the
            // installer proceeds. (Same stack-node trick as nsProcess.)
            uint32_t head = 0;
            if (args[3]) wg_blink_read_mem(engine->blink, args[3], &head, 4);
            if (head) {
                static const uint16_t okstr[] = {'0',0};
                wg_blink_write_mem(engine->blink, head + 4, okstr, sizeof(okstr));
            }
            WG_LOGI(TAG, "nsExec::%s -> 0 (emulated, child not run)", fn);
            ret_val = 0;
        } else if (strcmp(fn, "GetVersionExW") == 0 ||
                   strcmp(fn, "GetVersionExA") == 0) {
            // Fill a Windows 10 OSVERSIONINFO(EX) and return TRUE. Was unhandled
            // (returned garbage), which broke OS-version checks (nsProcess bailed,
            // and the bootstrapper can reject "unsupported OS"). args[0]=lpVI;
            // [+4]=major,[+8]=minor,[+12]=build,[+16]=platformId(2=NT),[+20]=CSD.
            uint32_t vi = args[0];
            if (vi) {
                uint32_t major = 10, minor = 0, build = 19045, plat = 2, zero = 0;
                wg_blink_write_mem(engine->blink, vi + 4,  &major, 4);
                wg_blink_write_mem(engine->blink, vi + 8,  &minor, 4);
                wg_blink_write_mem(engine->blink, vi + 12, &build, 4);
                wg_blink_write_mem(engine->blink, vi + 16, &plat,  4);
                wg_blink_write_mem(engine->blink, vi + 20, &zero,  4); // szCSDVersion[0]=0
            }
            ret_val = 1; // TRUE
        } else if (strcmp(fn, "GetVersion") == 0) {
            ret_val = 0x00000A00;
        } else if (strcmp(fn, "GetCommandLineW") == 0 ||
                   strcmp(fn, "GetCommandLineA") == 0) {
            // Map a page at 0xA00000 on first call (W at +0, A at +0x100)
            if (!s_cmdpage_mapped) {
                const char *winpath = wg_files_exe_win_path();
                uint8_t page[0x1000];
                memset(page, 0, sizeof(page));
                // Wide command line at offset 0
                uint16_t *wcmd = (uint16_t *)page;
                wcmd[0] = '"';
                int i = 0;
                for (; winpath[i] && i < 250; i++)
                    wcmd[i + 1] = (uint8_t)winpath[i];
                wcmd[i + 1] = '"'; wcmd[i + 2] = 0;
                // ANSI command line at offset 0x100
                char *acmd = (char *)(page + 0x100);
                snprintf(acmd, 256, "\"%s\"", winpath);
                wg_blink_load_code(engine->blink, 0xA00000, page, 0x1000, 0);
                s_cmdpage_mapped = true;
            }
            ret_val = (fn[14] == 'W') ? 0xA00000 : 0xA00100;
        } else if (strcmp(fn, "CommandLineToArgvW") == 0) {
            // CommandLineToArgvW(lpCmdLine=args[0], pNumArgs=args[1])
            // Read the wide command line from guest memory
            uint16_t cmdw[512] = {0};
            if (args[0])
                wg_blink_read_mem(engine->blink, args[0], cmdw, sizeof(cmdw) - 2);
            // Count wchars
            int len = 0;
            while (len < 511 && cmdw[len]) len++;
            // Allocate guest memory: argv[0] pointer (4 bytes) + string data
            uint32_t base = s_heap_ptr;
            uint32_t str_off = base + 4; // argv[0] string right after pointer
            uint32_t str_bytes = (len + 1) * 2;
            uint32_t total = 4 + str_bytes;
            total = (total + 0xFFF) & ~0xFFFu;
            uint8_t *buf = calloc(1, total);
            if (buf) {
                // argv[0] = pointer to the string
                uint32_t str_addr = str_off;
                memcpy(buf, &str_addr, 4);
                memcpy(buf + 4, cmdw, str_bytes);
                wg_blink_load_code(engine->blink, base, buf, total, 0);
                free(buf);
                s_heap_ptr += total;
                // Write argc = 1
                if (args[1]) {
                    uint32_t one = 1;
                    wg_blink_write_mem(engine->blink, args[1], &one, 4);
                }
                ret_val = base;
            }
        } else if (strcmp(fn, "GetModuleFileNameA") == 0) {
            // GetModuleFileNameA(hModule, lpFilename, nSize)
            uint32_t base = engine->pe_image ? (uint32_t)engine->pe_image->image_base : 0x400000;
            const char *path;
            if (args[0] == 0 || args[0] == base)
                path = wg_files_exe_win_path();
            else
                path = "C:\\Windows\\System32\\kernel32.dll";
            int len = (int)strlen(path);
            if (args[1] && args[2] > 0) {
                int max = (int)args[2] - 1;
                if (len > max) len = max;
                wg_blink_write_mem(engine->blink, args[1], path, len + 1);
            }
            ret_val = len;
        } else if (strcmp(fn, "GetModuleFileNameW") == 0) {
            // GetModuleFileNameW(hModule, lpFilename, nSize)
            uint32_t base = engine->pe_image ? (uint32_t)engine->pe_image->image_base : 0x400000;
            const char *winpath;
            if (args[0] == 0 || args[0] == base)
                winpath = wg_files_exe_win_path();
            else
                winpath = "C:\\Windows\\System32\\kernel32.dll";
            int len = (int)strlen(winpath);
            if (args[1] && args[2] > 0) {
                int max = (int)args[2] - 1;
                if (len > max) len = max;
                uint16_t wbuf[520] = {0};
                for (int i = 0; i < len; i++)
                    wbuf[i] = (uint8_t)winpath[i];
                wbuf[len] = 0;
                wg_blink_write_mem(engine->blink, args[1], wbuf, (len + 1) * 2);
            }
            ret_val = len;
        } else if (strcmp(fn, "GetTempPathW") == 0) {
            // GetTempPathW(nBufferLength=args[0], lpBuffer=args[1]). Only write
            // if the caller's buffer is big enough; never overflow it.
            uint16_t tmp[] = {'C',':','\\','T','e','m','p','\\',0};
            int n = 9; // chars incl NUL
            if (args[1] && args[0] >= (uint32_t)n)
                wg_blink_write_mem(engine->blink, args[1], tmp, n * 2);
            ret_val = (args[0] >= (uint32_t)n) ? (uint32_t)(n - 1) : (uint32_t)n;
        } else if (strcmp(fn, "GetCurrentDirectoryW") == 0 ||
                   strcmp(fn, "GetCurrentDirectoryA") == 0) {
            const char *winpath = wg_files_exe_win_path();
            char dir[520] = {0};
            const char *last = strrchr(winpath, '\\');
            int dirlen = last ? (int)(last - winpath) : (int)strlen(winpath);
            memcpy(dir, winpath, dirlen);
            // Ensure trailing backslash for root dirs (C: -> C:\)
            if (dirlen >= 2 && dir[dirlen-1] == ':') {
                dir[dirlen++] = '\\';
            }
            dir[dirlen] = 0;
            bool wide = (fn[19] == 'W');
            if (wide) {
                if (args[1] && args[0] > (uint32_t)dirlen) {
                    uint16_t wbuf[520] = {0};
                    for (int i = 0; i < dirlen; i++)
                        wbuf[i] = (uint8_t)dir[i];
                    wbuf[dirlen] = 0;
                    wg_blink_write_mem(engine->blink, args[1], wbuf, (dirlen + 1) * 2);
                }
            } else {
                if (args[1] && args[0] > (uint32_t)dirlen) {
                    wg_blink_write_mem(engine->blink, args[1], dir, dirlen + 1);
                }
            }
            ret_val = dirlen;
        } else if (strcmp(fn, "GetFullPathNameW") == 0) {
            // GetFullPathNameW(lpFileName=args[0], nBufferLength=args[1],
            //                   lpBuffer=args[2], lpFilePart=args[3])
            uint16_t fname[520] = {0};
            if (args[0]) wg_blink_read_mem(engine->blink, args[0], fname, 1038);
            // Convert to ASCII for processing
            char aname[520] = {0};
            for (int i = 0; i < 519 && fname[i]; i++)
                aname[i] = fname[i] < 128 ? (char)fname[i] : '?';
            char full[520] = {0};
            if (aname[0] && aname[1] == ':') {
                // Already absolute (C:\...)
                snprintf(full, sizeof(full), "%s", aname);
            } else {
                // Relative — prepend current directory
                const char *winpath = wg_files_exe_win_path();
                const char *last = strrchr(winpath, '\\');
                int dirlen = last ? (int)(last - winpath) : (int)strlen(winpath);
                char dir[520] = {0};
                memcpy(dir, winpath, dirlen);
                if (dirlen >= 2 && dir[dirlen-1] == ':')
                    dir[dirlen++] = '\\';
                dir[dirlen] = 0;
                snprintf(full, sizeof(full), "%s%s%s",
                    dir, (dir[dirlen-1] == '\\') ? "" : "\\", aname);
            }
            // Fix separators
            for (char *p = full; *p; p++) { if (*p == '/') *p = '\\'; }
            int len = (int)strlen(full);
            if (args[2] && args[1] > (uint32_t)len) {
                uint16_t wfull[520] = {0};
                for (int i = 0; i <= len; i++)
                    wfull[i] = (uint8_t)full[i];
                wg_blink_write_mem(engine->blink, args[2], wfull, (len + 1) * 2);
                // Set lpFilePart to point to the filename portion
                if (args[3]) {
                    const char *fp = strrchr(full, '\\');
                    uint32_t fp_off = fp ? (uint32_t)(fp - full + 1) : 0;
                    uint32_t fp_addr = args[2] + fp_off * 2;
                    wg_blink_write_mem(engine->blink, args[3], &fp_addr, 4);
                }
            }
            ret_val = len;
        } else if (strcmp(fn, "GetFullPathNameA") == 0) {
            char aname[520] = {0};
            if (args[0]) wg_blink_read_mem(engine->blink, args[0], aname, 519);
            char full[520] = {0};
            if (aname[0] && aname[1] == ':') {
                snprintf(full, sizeof(full), "%s", aname);
            } else {
                const char *winpath = wg_files_exe_win_path();
                const char *last = strrchr(winpath, '\\');
                int dirlen = last ? (int)(last - winpath) : (int)strlen(winpath);
                char dir[520] = {0};
                memcpy(dir, winpath, dirlen);
                if (dirlen >= 2 && dir[dirlen-1] == ':')
                    dir[dirlen++] = '\\';
                dir[dirlen] = 0;
                snprintf(full, sizeof(full), "%s%s%s",
                    dir, (dir[dirlen-1] == '\\') ? "" : "\\", aname);
            }
            for (char *p = full; *p; p++) { if (*p == '/') *p = '\\'; }
            int len = (int)strlen(full);
            if (args[2] && args[1] > (uint32_t)len) {
                wg_blink_write_mem(engine->blink, args[2], full, len + 1);
                if (args[3]) {
                    const char *fp = strrchr(full, '\\');
                    uint32_t fp_off = fp ? (uint32_t)(fp - full + 1) : 0;
                    uint32_t fp_addr = args[2] + fp_off;
                    wg_blink_write_mem(engine->blink, args[3], &fp_addr, 4);
                }
            }
            ret_val = len;
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
        } else if (strcmp(fn, "GetDlgItemTextW") == 0) {
            // GetDlgItemTextW(hDlg=args[0], id=args[1], lpString=args[2], cch=args[3])
            // Return the control's stored text. Without this it returned 0/empty,
            // so NSIS read an empty install path from the directory page's edit
            // field -> $INSTDIR/$OUTDIR empty -> files extracted to the drive_c
            // root instead of C:\Program Files\Steam.
            WGDlgCtrl *c = wg_find_ctrl(args[0], args[1]);
            int n = 0;
            if (args[2] && args[3] > 0) {
                uint16_t tmp[80] = {0};
                if (c) while (n < 79 && c->text[n] && (uint32_t)(n + 1) < args[3])
                           { tmp[n] = c->text[n]; n++; }
                tmp[n] = 0;
                wg_blink_write_mem(engine->blink, args[2], tmp, (n + 1) * 2);
            }
            ret_val = n;
        } else if (strcmp(fn, "SetDlgItemTextW") == 0) {
            // SetDlgItemTextW(hDlg=args[0], id=args[1], lpString=args[2])
            WGDlgCtrl *c = wg_find_ctrl(args[0], args[1]);
            if (c && args[2]) {
                wg_blink_read_mem(engine->blink, args[2], c->text, sizeof(c->text));
                c->text[79] = 0;
                if (s_dlg_active) wg_render_dialog(engine, c->hwnd);
            }
            // Surface the install status line (NSIS sets it to "Installing…",
            // file names, or error text) so we can see what the installer is
            // doing in the instfiles page.
            if (args[2]) {
                uint16_t w[128] = {0}; char a[128] = {0};
                wg_blink_read_mem(engine->blink, args[2], w, 254);
                for (int i = 0; i < 127 && w[i]; i++) a[i] = w[i] < 128 ? (char)w[i] : '?';
                if (a[0]) WG_LOGI(TAG, "  status[id=%u]: \"%s\"", args[1], a);
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
            // NSIS instfiles "details" lines go to a SysListView32 via
            // LVM_INSERTITEMW(0x104D)/A(0x1007). Log the inserted text — this is
            // the install log ("Output folder:", "Extract: steam.exe", errors…)
            // shown behind the "show details" button.
            if (msg == 0x104D || msg == 0x1007) {
                uint32_t lvitem = lParam;            // LVITEM*: pszText at +20
                uint32_t psz = 0;
                wg_blink_read_mem(engine->blink, lvitem + 20, &psz, 4);
                if (psz) {
                    char line[256] = {0};
                    if (msg == 0x104D) {             // wide
                        uint16_t w[256] = {0};
                        wg_blink_read_mem(engine->blink, psz, w, 510);
                        for (int i = 0; i < 255 && w[i]; i++)
                            line[i] = w[i] < 128 ? (char)w[i] : '?';
                    } else {
                        wg_blink_read_mem(engine->blink, psz, line, 255);
                    }
                    if (line[0]) {
                        WG_LOGI(TAG, "  detail: \"%s\"", line);
                        if (s_detail_count < 256) {
                            strncpy(s_detail_lines[s_detail_count], line,
                                    sizeof(s_detail_lines[0]) - 1);
                            s_detail_count++;
                            if (s_dlg_active && s_page_hwnd)
                                wg_render_dialog(engine, s_page_hwnd);
                        }
                    }
                }
            }
            // Progress bar position: PBM_SETPOS(0x402, wParam=pos),
            // PBM_SETRANGE32(0x406, lParam=max), PBM_DELTAPOS(0x403, wParam=delta).
            if (msg == 0x0402 || msg == 0x0403 || msg == 0x0406) {
                if (msg == 0x0402) s_pb_pos = wParam;
                else if (msg == 0x0403) s_pb_pos += wParam;
                else if (lParam) s_pb_max = lParam;
                if (s_dlg_active && s_page_hwnd) wg_render_dialog(engine, s_page_hwnd);
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
            // Parse the page's own dialog template (e.g. the directory page) so
            // we can render its controls — these are built-in NSIS dialogs, not
            // nsDialogs plugin pages.
            wg_parse_dialog(engine, hwnd, dlg_id);
            s_page_hwnd = hwnd;       // progress/details updates re-render this
            wg_render_dialog(engine, hwnd);
            WG_LOGI(TAG, "CreateDialogParamW(template=%u) -> page HWND=0x%X", dlg_id, hwnd);

            // Dispatch the page's WM_INITDIALOG so NSIS fills the dynamic text
            // (install path in the edit field, disk-space numbers). This must
            // still return the HWND to the caller, so use the override form
            // (ovr_eax=hwnd). The register snapshot in wg_call_wndproc_ovr keeps
            // the caller's ESI intact across the dispatch (its very next
            // instruction is `push [esi+0x2c]`).
            if (dlgproc && is_32bit) {
                uint64_t clean_rsp = rsp + ptr_size + (5 * ptr_size);
                if (wg_call_wndproc_ovr(engine, dlgproc, hwnd,
                                        0x0110 /*WM_INITDIALOG*/, 0, initParam,
                                        (uint32_t)ret_addr, (uint32_t)clean_rsp,
                                        true, hwnd)) {
                    return true;
                }
            }
            ret_val = hwnd;
        } else if (strcmp(fn, "GetLastError") == 0) {
            ret_val = s_last_error;
        } else if (strcmp(fn, "SetLastError") == 0) {
            s_last_error = args[0];
        } else if (strcmp(fn, "GetEnvironmentVariableW") == 0 ||
                   strcmp(fn, "GetEnvironmentVariableA") == 0) {
            // GetEnvironmentVariable(lpName, lpBuffer, nSize)
            // No environment set — always "not found"
            s_last_error = 203; // ERROR_ENVVAR_NOT_FOUND
            ret_val = 0;
        } else if (strcmp(fn, "GetModuleHandleExW") == 0 ||
                   strcmp(fn, "GetModuleHandleExA") == 0) {
            // GetModuleHandleEx(dwFlags, lpModuleName, phModule)
            // Write a module handle to *phModule
            uint32_t base = engine->pe_image ? (uint32_t)engine->pe_image->image_base : 0x400000;
            if (args[2]) {
                uint32_t handle = (args[1] == 0) ? base : 0xBFFF0000u;
                wg_blink_write_mem(engine->blink, args[2], &handle, 4);
            }
            ret_val = 1; // TRUE
        } else if (strcmp(fn, "CreateFontW") == 0 ||
                   strcmp(fn, "CreateFontA") == 0 ||
                   strcmp(fn, "CreateFontIndirectW") == 0 ||
                   strcmp(fn, "CreateFontIndirectA") == 0) {
            static uint32_t s_next_font = 0xF0000;
            ret_val = s_next_font++;
        } else if (strcmp(fn, "MulDiv") == 0) {
            // MulDiv(nNumber=args[0], nNumerator=args[1], nDenominator=args[2])
            int32_t a = (int32_t)args[0];
            int32_t b = (int32_t)args[1];
            int32_t d = (int32_t)args[2];
            if (d == 0) ret_val = (uint64_t)(int64_t)-1;
            else ret_val = (uint64_t)(int64_t)((int64_t)a * b / d);
        } else if (strcmp(fn, "RegisterClassExW") == 0 ||
                   strcmp(fn, "RegisterClassExA") == 0 ||
                   strcmp(fn, "RegisterClassW") == 0 ||
                   strcmp(fn, "RegisterClassA") == 0) {
            static uint32_t s_next_atom = 0xC000;
            ret_val = s_next_atom++;
        } else if (strcmp(fn, "OutputDebugStringA") == 0) {
            if (args[0]) {
                char dbg[512] = {0};
                wg_blink_read_mem(engine->blink, args[0], dbg, 511);
                WG_LOGI(TAG, "DbgPrint: %s", dbg);
            }
        } else if (strcmp(fn, "OutputDebugStringW") == 0) {
            if (args[0]) {
                uint16_t wdbg[256] = {0};
                wg_blink_read_mem(engine->blink, args[0], wdbg, 510);
                char dbg[256] = {0};
                for (int i = 0; i < 255 && wdbg[i]; i++)
                    dbg[i] = wdbg[i] < 128 ? (char)wdbg[i] : '?';
                WG_LOGI(TAG, "DbgPrint: %s", dbg);
            }
        } else if (strcmp(fn, "AppPolicyGetProcessTerminationMethod") == 0) {
            // AppPolicyGetProcessTerminationMethod(token, *policy)
            // Write 0 (ExitProcess) to *policy, return ERROR_SUCCESS
            if (args[1]) {
                uint32_t zero = 0;
                wg_blink_write_mem(engine->blink, args[1], &zero, 4);
            }
            ret_val = 0;
        } else if (strcmp(fn, "GetCurrentPackageId") == 0) {
            // GetCurrentPackageId(*bufferLength, buffer)
            // Not packaged — return APPMODEL_ERROR_NO_PACKAGE (15700)
            ret_val = 15700;
        } else if (strcmp(fn, "IsUserAnAdmin") == 0) {
            ret_val = 1; // yes, admin
        } else if (strcmp(fn, "IsWindowEnabled") == 0 ||
                   strcmp(fn, "IsWindowVisible") == 0) {
            // The registered stub_return_1 is dead under blink (it writes the
            // builtin-interpreter CPU state, which we don't use), so without an
            // explicit case these default to 0. NSIS's WM_COMMAND handler bails
            // out when IsWindowEnabled(nextButton) is 0 — i.e. every wizard
            // button tap was silently ignored. Report our controls as enabled
            // and visible so navigation proceeds.
            ret_val = 1;
        } else if (strcmp(fn, "IsWindow") == 0) {
            ret_val = (args[0] != 0) ? 1 : 0;
        } else if (strcmp(fn, "WideCharToMultiByte") == 0) {
            // WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr=args[2],
            //   cchWideChar=args[3], lpMultiByteStr=args[4], cbMultiByte=args[5], ...)
            // MUST actually convert + return the byte count: NSIS's plug-in
            // export resolver (exe 0x4065c7) converts the wide function name to
            // ANSI here and bails to NULL (skipping GetProcAddress) if this
            // returns 0 — which is exactly why nsProcess::FindProcess was never
            // resolved/called and the installer looped.
            uint32_t wstr = args[2];
            int32_t  cch  = (int32_t)args[3];
            uint32_t mbstr = args[4];
            int32_t  cbmb = (int32_t)args[5];
            uint16_t wbuf[2048]; int wlen = 0;
            if (wstr) {
                if (cch < 0) {
                    for (; wlen < 2047; wlen++) {
                        uint16_t c = 0;
                        wg_blink_read_mem(engine->blink, wstr + wlen * 2, &c, 2);
                        wbuf[wlen] = c;
                        if (!c) { wlen++; break; }   // null-terminated: include NUL
                    }
                } else {
                    wlen = cch < 2047 ? cch : 2047;
                    wg_blink_read_mem(engine->blink, wstr, wbuf, wlen * 2);
                }
            }
            char abuf[2048]; int alen = 0;
            for (int i = 0; i < wlen; i++)
                abuf[alen++] = wbuf[i] < 128 ? (char)wbuf[i] : '?';
            if (cbmb == 0) {
                ret_val = alen;                      // query required size
            } else {
                int n = alen < cbmb ? alen : cbmb;
                if (mbstr) wg_blink_write_mem(engine->blink, mbstr, abuf, n);
                ret_val = n;
            }
        } else if (strcmp(fn, "MultiByteToWideChar") == 0) {
            // MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr=args[2],
            //   cbMultiByte=args[3], lpWideCharStr=args[4], cchWideChar=args[5])
            uint32_t mbstr = args[2];
            int32_t  cbmb  = (int32_t)args[3];
            uint32_t wstr  = args[4];
            int32_t  cch   = (int32_t)args[5];
            char abuf[2048]; int alen = 0;
            if (mbstr) {
                if (cbmb < 0) {
                    for (; alen < 2047; alen++) {
                        uint8_t c = 0;
                        wg_blink_read_mem(engine->blink, mbstr + alen, &c, 1);
                        abuf[alen] = (char)c;
                        if (!c) { alen++; break; }   // null-terminated: include NUL
                    }
                } else {
                    alen = cbmb < 2047 ? cbmb : 2047;
                    wg_blink_read_mem(engine->blink, mbstr, abuf, alen);
                }
            }
            if (cch == 0) {
                ret_val = alen;                      // query required size (chars)
            } else {
                int n = alen < cch ? alen : cch;
                if (wstr) {
                    uint16_t wbuf[2048];
                    for (int i = 0; i < n; i++) wbuf[i] = (uint8_t)abuf[i];
                    wg_blink_write_mem(engine->blink, wstr, wbuf, n * 2);
                }
                ret_val = n;
            }
        } else if (strcmp(fn, "TlsAlloc") == 0) {
            // Dynamic TLS. Single guest thread, so one global slot array.
            ret_val = (s_tls_next < 1088) ? s_tls_next++ : 0xFFFFFFFF;
        } else if (strcmp(fn, "TlsGetValue") == 0) {
            ret_val = (args[0] < 1088) ? s_tls_slots[args[0]] : 0;
            s_last_error = 0;
        } else if (strcmp(fn, "TlsSetValue") == 0) {
            if (args[0] < 1088) s_tls_slots[args[0]] = args[1];
            ret_val = 1;
        } else if (strcmp(fn, "TlsFree") == 0) {
            ret_val = 1;
        } else if (strcmp(fn, "FlsAlloc") == 0) {
            // Fiber-Local Storage (the CRT uses it like TLS). args[0]=callback
            // (ignored). Same single-thread slot model as Tls.
            ret_val = (s_fls_next < 1088) ? s_fls_next++ : 0xFFFFFFFF;
        } else if (strcmp(fn, "FlsGetValue") == 0) {
            ret_val = (args[0] < 1088) ? s_fls_slots[args[0]] : 0;
            s_last_error = 0;
        } else if (strcmp(fn, "FlsSetValue") == 0) {
            if (args[0] < 1088) s_fls_slots[args[0]] = args[1];
            ret_val = 1;
        } else if (strcmp(fn, "FlsFree") == 0) {
            ret_val = 1;
        } else if (strcmp(fn, "GetACP") == 0) {
            ret_val = 1252;   // Windows-1252; ACP=0 trips the CRT _invalid_parameter
        } else if (strcmp(fn, "GetOEMCP") == 0) {
            ret_val = 437;
        } else if (strcmp(fn, "GetConsoleOutputCP") == 0 ||
                   strcmp(fn, "GetConsoleCP") == 0) {
            ret_val = 437;
        } else if (strcmp(fn, "IsValidCodePage") == 0) {
            ret_val = 1;      // accept whatever codepage the CRT probes
        } else if (strcmp(fn, "GetCPInfo") == 0) {
            // GetCPInfo(CodePage, lpCPInfo=args[1]) -> CPINFO{MaxCharSize, DefaultChar[2], LeadByte[12]}
            if (args[1]) {
                uint8_t cp[18] = {0};
                uint32_t mcs = 1; memcpy(cp, &mcs, 4);  // MaxCharSize=1
                cp[4] = '?';                              // DefaultChar[0]
                wg_blink_write_mem(engine->blink, args[1], cp, 18);
            }
            ret_val = 1;
        } else if (strcmp(fn, "EncodePointer") == 0 ||
                   strcmp(fn, "DecodePointer") == 0) {
            // MUST be identity: the CRT stores EncodePointer(fnptr) and later
            // DecodePointer+calls it. Returning 0 would null function pointers.
            ret_val = args[0];
        } else if (strcmp(fn, "GetCurrentThread") == 0) {
            ret_val = 0xFFFFFFFE;   // pseudo-handle for the current thread
        } else if (strcmp(fn, "GetProcessHeap") == 0) {
            ret_val = 0x00D00000;   // matches PEB->ProcessHeap in the TEB setup
        } else if (strcmp(fn, "HeapCreate") == 0) {
            ret_val = 0x00D10000;   // a distinct non-null fake heap handle
        } else if (strcmp(fn, "HeapAlloc") == 0) {
            // HeapAlloc(hHeap, dwFlags, dwBytes=args[2]) -> real guest heap
            // (always zeroed; HEAP_ZERO_MEMORY is then satisfied). The CRT's
            // malloc/startup heap-init goes through here — returning 0 crashed
            // steam.exe right after the TEB setup.
            ret_val = wg_guest_alloc(engine, args[2]);
        } else if (strcmp(fn, "HeapSize") == 0) {
            // HeapSize(hHeap, dwFlags, lpMem=args[2])
            ret_val = lookup_alloc_size(args[2]);
        } else if (strcmp(fn, "HeapReAlloc") == 0) {
            // HeapReAlloc(hHeap, dwFlags, lpMem=args[2], dwBytes=args[3])
            uint32_t np = wg_guest_alloc(engine, args[3]);
            if (np && args[2] && args[3]) {
                uint8_t *tmp = malloc(args[3]);
                if (tmp) {
                    wg_blink_read_mem(engine->blink, args[2], tmp, args[3]);
                    wg_blink_write_mem(engine->blink, np, tmp, args[3]);
                    free(tmp);
                }
            }
            ret_val = np;
        } else if (strcmp(fn, "??2@YAPAXI@Z") == 0 ||   // operator new(uint)
                   strcmp(fn, "malloc") == 0) {
            // CRT allocators used by real DLLs (StdUtils, etc.). Returning 0
            // (the old auto-stub default) made the plug-in deref a NULL buffer
            // and SIGSEGV. Hand back real guest heap.
            ret_val = wg_guest_alloc(engine, args[0]);
        } else if (strcmp(fn, "calloc") == 0) {
            ret_val = wg_guest_alloc(engine, args[0] * args[1]);  // already zeroed
        } else if (strcmp(fn, "realloc") == 0) {
            // Bump allocator can't grow in place; allocate fresh and copy. We
            // don't know the old size, so copy a bounded amount (new size).
            uint32_t np = wg_guest_alloc(engine, args[1]);
            if (np && args[0] && args[1]) {
                uint8_t *tmp = malloc(args[1]);
                if (tmp) {
                    wg_blink_read_mem(engine->blink, args[0], tmp, args[1]);
                    wg_blink_write_mem(engine->blink, np, tmp, args[1]);
                    free(tmp);
                }
            }
            ret_val = np;
        } else if (strcmp(fn, "??3@YAXPAX@Z") == 0 ||   // operator delete(void*)
                   strcmp(fn, "free") == 0) {
            ret_val = 0;   // bump allocator: free is a no-op
        } else if (strcmp(fn, "memset") == 0) {
            // memset(dest=args[0], c=args[1], n=args[2]) -> returns dest (cdecl)
            uint32_t dst = args[0], n = args[2];
            if (dst && n && n <= 64u * 1024 * 1024) {
                uint8_t *tmp = malloc(n);
                if (tmp) {
                    memset(tmp, (int)args[1], n);
                    wg_blink_write_mem(engine->blink, dst, tmp, n);
                    free(tmp);
                }
            }
            ret_val = dst;
        } else if (strcmp(fn, "memcpy") == 0 || strcmp(fn, "memmove") == 0) {
            // mem(c)py(dest=args[0], src=args[1], n=args[2]) -> returns dest
            uint32_t dst = args[0], src = args[1], n = args[2];
            if (dst && src && n && n <= 64u * 1024 * 1024) {
                uint8_t *tmp = malloc(n);
                if (tmp) {
                    wg_blink_read_mem(engine->blink, src, tmp, n);
                    wg_blink_write_mem(engine->blink, dst, tmp, n);
                    free(tmp);
                }
            }
            ret_val = dst;
        } else if (strcmp(fn, "CreateEventA") == 0 ||
                   strcmp(fn, "CreateEventW") == 0) {
            // CreateEvent(lpSecurityAttributes, bManualReset, bInitialState, lpName)
            uint32_t handle = 0;
            if (s_event_next < WG_MAX_EVENTS) {
                uint32_t idx = s_event_next++;
                s_event_signalled[idx] = (args[2] != 0);
                handle = WG_EVENT_BASE + idx;
            }
            ret_val = handle;
        } else if (strcmp(fn, "SetEvent") == 0) {
            uint32_t h = args[0];
            if (h >= WG_EVENT_BASE && h < WG_EVENT_BASE + WG_MAX_EVENTS)
                s_event_signalled[h - WG_EVENT_BASE] = true;
            wg_sched_wake(engine->scheduler, h);
            ret_val = 1;
        } else if (strcmp(fn, "ResetEvent") == 0) {
            uint32_t h = args[0];
            if (h >= WG_EVENT_BASE && h < WG_EVENT_BASE + WG_MAX_EVENTS)
                s_event_signalled[h - WG_EVENT_BASE] = false;
            ret_val = 1;
        } else if (strcmp(fn, "WaitForSingleObject") == 0) {
            uint32_t h = args[0];
            uint32_t timeout = args[1];
            // Check if the handle is already signalled
            bool signalled = false;
            if (h >= WG_EVENT_BASE && h < WG_EVENT_BASE + WG_MAX_EVENTS)
                signalled = s_event_signalled[h - WG_EVENT_BASE];
            // Check if it's a thread handle that has exited
            WGThread *wt = wg_sched_find(engine->scheduler, h);
            if (wt && wt->state == WG_THREAD_EXITED) signalled = true;
            if (signalled) {
                ret_val = 0; // WAIT_OBJECT_0
            } else if (timeout == 0) {
                ret_val = 258; // WAIT_TIMEOUT
            } else {
                // Block and try to switch to another thread
                WGThread *cur = wg_sched_current(engine->scheduler);
                if (cur) {
                    cur->wait_handle = h;
                    cur->wait_timeout = timeout;
                }
                if (wg_sched_yield(engine->scheduler, engine->blink, WG_THREAD_WAITING)) {
                    return true; // switched to another thread
                }
                ret_val = 0; // no other threads, just return signalled
            }
        } else if (strcmp(fn, "WaitForMultipleObjects") == 0) {
            ret_val = 0; // WAIT_OBJECT_0
        } else if (strcmp(fn, "CreateMutexW") == 0 ||
                   strcmp(fn, "CreateMutexA") == 0) {
            // Return a unique fake handle. Steam uses mutexes for single-instance.
            if (s_event_next < WG_MAX_EVENTS) {
                ret_val = WG_EVENT_BASE + s_event_next++;
            }
            s_last_error = 0; // not ERROR_ALREADY_EXISTS
        } else if (strcmp(fn, "OpenMutexW") == 0 ||
                   strcmp(fn, "OpenMutexA") == 0) {
            ret_val = 0; // mutex not found
            s_last_error = 2; // ERROR_FILE_NOT_FOUND
        } else if (strcmp(fn, "ReleaseMutex") == 0) {
            ret_val = 1;
        } else if (strcmp(fn, "CreateThread") == 0) {
            // CreateThread(secAttr, stackSize, start=args[2], param=args[3],
            //              flags=args[4], lpThreadId=args[5]).
            uint32_t start = args[2], param = args[3], flags = args[4];
            uint32_t tid = 0;
            uint32_t hthread = wg_sched_create_thread(
                engine->scheduler, engine->blink,
                start, param, flags, &tid);
            if (args[5] && tid) {
                wg_blink_write_mem(engine->blink, args[5], &tid, 4);
            }
            if (!hthread) {
                // Fallback: run synchronously (for NSIS compatibility)
                hthread = 0x7100;
                uint64_t clean_rsp = rsp + ptr_size + (6 * ptr_size);
                if (start && is_32bit && !(flags & 0x4u)) {
                    wg_call_wndproc_ovr(engine, start, param, 0, 0, 0,
                                        (uint32_t)ret_addr, (uint32_t)clean_rsp,
                                        true, hthread);
                    WG_LOGI(TAG, "CreateThread: fallback sync start=0x%X", start);
                    return true;
                }
            }
            ret_val = hthread;
        } else if (strcmp(fn, "GetExitCodeThread") == 0) {
            // The worker already ran to completion synchronously; report exit
            // code 0 (not STILL_ACTIVE) so any wait loop sees it as finished.
            if (args[1]) { uint32_t code = 0;
                wg_blink_write_mem(engine->blink, args[1], &code, 4); }
            ret_val = 1;
        } else if (strcmp(fn, "CreateProcessW") == 0 ||
                   strcmp(fn, "CreateProcessA") == 0) {
            // We can't run a child .exe (steam.exe), but the install section's
            // final step launches it. Report SUCCESS with a fake, already-exited
            // process so any Exec/ExecWait/nsExec path completes immediately and
            // the install worker RETURNS (otherwise the single guest thread stays
            // inside the worker and the UI never pumps → buttons dead).
            uint32_t pi = args[9];   // lpProcessInformation
            if (pi) {
                uint32_t info[4] = { 0x00007200 /*hProcess*/, 0x00007201 /*hThread*/,
                                     0x00001200 /*pid*/, 0x00001201 /*tid*/ };
                wg_blink_write_mem(engine->blink, pi, info, sizeof(info));
            }
            ret_val = 1; // TRUE
            // If the installer is launching the Steam bootstrapper (steam.exe,
            // NOT steamservice.exe), remember it so the app can chain-load and
            // run it once the installer exits — that's the "fancier" Steam UI.
            {
                char cl[512] = {0};
                uint32_t cl_ptr = args[1] ? args[1] : args[0]; // cmdline or appname
                if (cl_ptr) {
                    uint16_t w[512] = {0};
                    wg_blink_read_mem(engine->blink, cl_ptr, w, 1022);
                    for (int i = 0; i < 511 && w[i]; i++)
                        cl[i] = w[i] < 128 ? (char)w[i] : '?';
                }
                // lowercase copy for matching
                char low[512]; int li = 0;
                for (; cl[li] && li < 511; li++)
                    low[li] = (char)tolower((unsigned char)cl[li]);
                low[li] = 0;
                if (strstr(low, "steam.exe") && !strstr(low, "steamservice")) {
                    // Extract the .exe path (strip a leading quote; stop at the
                    // closing quote or the space before args), then map to real.
                    char win[512]; int wi = 0; const char *p = cl;
                    if (*p == '"') p++;
                    while (*p && *p != '"' && wi < 511) {
                        // stop at " .exe" boundary + following space
                        win[wi++] = *p;
                        if (wi >= 9 && strncasecmp(win + wi - 9, "steam.exe", 9) == 0) break;
                        p++;
                    }
                    win[wi] = 0;
                    char mapbuf[512];
                    strncpy(mapbuf, win, sizeof(mapbuf) - 1); mapbuf[sizeof(mapbuf)-1] = 0;
                    const char *real = wg_files_map_path(0, engine->blink, mapbuf, sizeof(mapbuf));
                    if (real) {
                        strncpy(s_pending_exec, real, sizeof(s_pending_exec) - 1);
                        s_pending_exec[sizeof(s_pending_exec)-1] = 0;
                        WG_LOGI(TAG, "Steam bootstrapper launch queued: %s", s_pending_exec);
                    }
                }
            }
        } else if (strcmp(fn, "CreatePipe") == 0) {
            // CreatePipe(hReadPipe=args[0], hWritePipe=args[1], attrs, size).
            // Succeed with fake handles so nsExec's pipe loop is well-formed and
            // (with PeekNamedPipe=no-data + GetExitCodeProcess=done) exits at once.
            uint32_t hr = 0x00007300, hw = 0x00007301;
            if (args[0]) wg_blink_write_mem(engine->blink, args[0], &hr, 4);
            if (args[1]) wg_blink_write_mem(engine->blink, args[1], &hw, 4);
            ret_val = 1; // TRUE
        } else if (strcmp(fn, "GetExitCodeProcess") == 0) {
            // The (fake) child "exited" with code 0 — NOT STILL_ACTIVE — so
            // nsExec's "while child running" pipe-read loop terminates instead
            // of spinning forever (which froze the installer after launching
            // steam.exe and made Back/Next/Cancel unresponsive).
            if (args[1]) { uint32_t code = 0;
                wg_blink_write_mem(engine->blink, args[1], &code, 4); }
            ret_val = 1;
        } else if (strcmp(fn, "PeekNamedPipe") == 0) {
            // Report no data available (and success) so nsExec sees "no output,
            // child done" and stops reading. args[3]=lpBytesRead,
            // args[4]=lpTotalBytesAvail, args[5]=lpBytesLeftThisMessage.
            uint32_t zero = 0;
            if (args[3]) wg_blink_write_mem(engine->blink, args[3], &zero, 4);
            if (args[4]) wg_blink_write_mem(engine->blink, args[4], &zero, 4);
            if (args[5]) wg_blink_write_mem(engine->blink, args[5], &zero, 4);
            ret_val = 1;
        } else if (strcmp(fn, "SHGetFolderPathW") == 0) {
            // SHGetFolderPathW(hwnd, csidl=args[1], hToken, dwFlags, pszPath=args[4]).
            // MUST write a valid path; otherwise NSIS reuses a stale buffer as
            // the Start-Menu/Desktop folder ("Create folder: Error creating
            // shortcut\Steam"). Map common CSIDLs into the bottle.
            int csidl = (int)(args[1] & 0xFF);
            const char *path;
            switch (csidl) {
                case 0x00: case 0x10: path = "C:\\users\\steamuser\\Desktop"; break;
                case 0x02:            path = "C:\\users\\steamuser\\Start Menu\\Programs"; break;
                case 0x0B:            path = "C:\\users\\steamuser\\Start Menu"; break;
                case 0x17:            path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs"; break;
                case 0x05:            path = "C:\\users\\steamuser\\Documents"; break;
                case 0x1A: case 0x23: path = "C:\\users\\steamuser\\AppData\\Roaming"; break;
                case 0x1C:            path = "C:\\users\\steamuser\\AppData\\Local"; break;
                case 0x24:            path = "C:\\Windows"; break;
                case 0x25:            path = "C:\\Windows\\System32"; break;
                case 0x26:            path = "C:\\Program Files"; break;
                default:              path = "C:\\users\\steamuser"; break;
            }
            if (args[4]) {
                uint16_t w[260]; int i = 0;
                for (; path[i] && i < 259; i++) w[i] = (uint8_t)path[i];
                w[i] = 0;
                wg_blink_write_mem(engine->blink, args[4], w, (i + 1) * 2);
            }
            ret_val = 0; // S_OK
        } else if (strcmp(fn, "CoCreateInstance") == 0) {
            // CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv=args[4]).
            // Hand back our minimal fake IShellLink so NSIS CreateShortcut runs
            // its Set*/Save sequence and succeeds (shortcuts are no-ops on iOS,
            // but this avoids the "Error creating shortcut" log and any null
            // deref from a half-failed COM path).
            wg_build_fake_com(engine);
            if (args[4]) wg_blink_write_mem(engine->blink, args[4], &s_com_shelllink, 4);
            ret_val = s_com_shelllink ? 0 : 0x80004002; // S_OK if built
            s_last_error = 0;
        } else if (strcmp(fn, "__comQI") == 0) {
            // IShellLink/IPersistFile::QueryInterface(this, riid, ppv) — hand
            // back the IPersistFile object (NSIS QIs the link for it before Save).
            if (args[2]) wg_blink_write_mem(engine->blink, args[2], &s_com_persistfile, 4);
            ret_val = 0; // S_OK
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
                wg_files_ensure_parents(real);   // deep bottle paths: make parents
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
            // PeekMessageW — idle point in the message loop. If worker
            // threads are READY, yield to them before returning.
            bool has_ready = false;
            for (int ti = 0; ti < WG_MAX_THREADS; ti++) {
                if (engine->scheduler->threads[ti].state == WG_THREAD_READY) {
                    has_ready = true;
                    break;
                }
            }
            if (has_ready) {
                // Yield to worker threads (e.g. NSIS install thread)
                if (wg_sched_yield(engine->scheduler, engine->blink, WG_THREAD_READY)) {
                    return true; // switched to worker
                }
            }
            static int peek_count = 0;
            peek_count++;
            if (peek_count > 5) {
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
        } else if (strcmp(fn, "GetSystemTimeAsFileTime") == 0 ||
                   strcmp(fn, "GetSystemTimePreciseAsFileTime") == 0) {
            // *args[0] = FILETIME (8 bytes). Jan 1 2024 00:00 UTC in 100ns ticks.
            if (args[0]) {
                uint64_t ft = 133484064000000000ULL;
                wg_blink_write_mem(engine->blink, args[0], &ft, 8);
            }
            ret_val = 0;
        } else if (strcmp(fn, "GetCurrentThreadId") == 0) {
            ret_val = wg_sched_current_tid(engine->scheduler);
            if (!ret_val) ret_val = 1;
        } else if (strcmp(fn, "Sleep") == 0 || strcmp(fn, "SleepEx") == 0) {
            // Try to yield to another thread during sleep
            if (args[0] > 0 &&
                wg_sched_yield(engine->scheduler, engine->blink, WG_THREAD_READY)) {
                return true;
            }
            ret_val = 0;
        } else if (strcmp(fn, "ExitThread") == 0) {
            WG_LOGI(TAG, "ExitThread(%u)", args[0]);
            wg_sched_exit_thread(engine->scheduler, engine->blink, args[0]);
            WGThread *cur_after = wg_sched_current(engine->scheduler);
            if (cur_after) {
                return true; // switched to another thread
            }
            // No more threads — halt
            wg_blink_set_rip(engine->blink, 0);
            return true;
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
        } else if (strcmp(fn, "LocalAlloc") == 0) {
            // LocalAlloc(uFlags=args[0], uBytes=args[1])
            uint32_t size = args[1];
            ret_val = wg_guest_alloc(engine, size ? size : 1);
        } else if (strcmp(fn, "LocalFree") == 0) {
            ret_val = 0; // success
        }

        // WS2_32 / WSOCK32 dispatch — map ordinal names to function names
        // and forward to the winsock handler.
        if (entry && entry->dll_name &&
            (strcasecmp(entry->dll_name, "WS2_32.dll") == 0 ||
             strcasecmp(entry->dll_name, "WSOCK32.dll") == 0)) {
            const char *ws_fn = fn;
            // Map WS2_32 ordinals to function names
            if (strncmp(fn, "Ordinal_", 8) == 0) {
                int ord = atoi(fn + 8);
                switch (ord) {
                    case 1: ws_fn = "accept"; break;
                    case 2: ws_fn = "bind"; break;
                    case 3: ws_fn = "closesocket"; break;
                    case 4: ws_fn = "connect"; break;
                    case 5: ws_fn = "getpeername"; break;
                    case 6: ws_fn = "getsockname"; break;
                    case 7: ws_fn = "getsockopt"; break;
                    case 8: ws_fn = "htonl"; break;
                    case 9: ws_fn = "htons"; break;
                    case 10: ws_fn = "ioctlsocket"; break;
                    case 11: ws_fn = "inet_addr"; break;
                    case 12: ws_fn = "inet_ntoa"; break;
                    case 13: ws_fn = "listen"; break;
                    case 14: ws_fn = "ntohl"; break;
                    case 15: ws_fn = "ntohs"; break;
                    case 16: ws_fn = "recv"; break;
                    case 17: ws_fn = "recvfrom"; break;
                    case 18: ws_fn = "select"; break;
                    case 19: ws_fn = "send"; break;
                    case 20: ws_fn = "sendto"; break;
                    case 21: ws_fn = "setsockopt"; break;
                    case 22: ws_fn = "shutdown"; break;
                    case 23: ws_fn = "socket"; break;
                    case 52: ws_fn = "gethostbyname"; break;
                    case 111: ws_fn = "WSAEnumNetworkEvents"; break;
                    case 112: ws_fn = "WSAEventSelect"; break;
                    case 113: ws_fn = "WSAGetLastError"; break;
                    case 115: ws_fn = "WSAStartup"; break;
                    case 116: ws_fn = "WSACleanup"; break;
                    case 1142: ws_fn = "WSAStartup"; break; // WSOCK32
                    default: break;
                }
            }
            uint64_t ws_ret = 0;
            WG_LOGI(TAG, "WS2_32 dispatch: %s -> %s", fn, ws_fn);
            if (wg_winsock_handle(engine->winsock, ws_fn, args, &ws_ret, engine->blink)) {
                ret_val = ws_ret;
            } else {
                WG_LOGW(TAG, "WS2_32 unhandled: %s", ws_fn);
            }
        }
    }

    // Stdcall: callee pops return address + all arguments
    int num_args = entry ? entry->num_args : 0;
    uint64_t new_rsp = rsp + ptr_size + (num_args * ptr_size);
    wg_blink_set_reg(engine->blink, 4, new_rsp); // RSP
    wg_blink_set_rip(engine->blink, ret_addr);
    wg_blink_set_reg(engine->blink, 0, ret_val); // EAX = return value

    wg_call_ring_push(entry ? entry->func_name : "?", ret_val);
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

// Build a minimal 32-bit TEB/PEB + TLS and point FS at the TEB. MSVC's CRT reads
// fs:[0x18] (TEB self), fs:[0x2C] (TLS pointer) and fs:[0x30] (PEB) during
// startup, plus PEB->ProcessHeap / OS version fields — without these a real
// app (steam.exe) faults in CRT init. NSIS never touched FS so it ran without.
static void wg_setup_win32_teb(WGEngine *engine) {
    WGPEImage *pe = engine->pe_image;
    if (!pe || pe->is_64bit) return;   // 64-bit (GS-based) TEB is a later stage

    uint32_t teb = wg_guest_alloc(engine, 0x1000);
    uint32_t peb = wg_guest_alloc(engine, 0x1000);
    uint32_t tls_array = wg_guest_alloc(engine, 0x400);   // 256 TLS slots
    if (!teb || !peb || !tls_array) return;

    uint32_t image_base  = (uint32_t)pe->image_base;
    uint32_t stack_base  = 0x7FFF0000, stack_limit = 0x7FEF0000;
    uint32_t heap_handle = 0x00D00000;   // fake ProcessHeap handle
    uint32_t v;

    // TEB (NT_TIB first)
    v = 0xFFFFFFFF; wg_blink_write_mem(engine->blink, teb + 0x00, &v, 4); // ExceptionList
    wg_blink_write_mem(engine->blink, teb + 0x04, &stack_base, 4);        // StackBase
    wg_blink_write_mem(engine->blink, teb + 0x08, &stack_limit, 4);       // StackLimit
    wg_blink_write_mem(engine->blink, teb + 0x18, &teb, 4);              // Self
    v = 0x1000; wg_blink_write_mem(engine->blink, teb + 0x20, &v, 4);     // ClientId.UniqueProcess
    v = 0x1004; wg_blink_write_mem(engine->blink, teb + 0x24, &v, 4);     // ClientId.UniqueThread
    wg_blink_write_mem(engine->blink, teb + 0x2C, &tls_array, 4);         // ThreadLocalStoragePointer
    wg_blink_write_mem(engine->blink, teb + 0x30, &peb, 4);               // ProcessEnvironmentBlock
    v = 0; wg_blink_write_mem(engine->blink, teb + 0x34, &v, 4);          // LastErrorValue

    // PEB
    uint8_t bd = 0; wg_blink_write_mem(engine->blink, peb + 0x02, &bd, 1);   // BeingDebugged
    wg_blink_write_mem(engine->blink, peb + 0x08, &image_base, 4);           // ImageBaseAddress
    wg_blink_write_mem(engine->blink, peb + 0x18, &heap_handle, 4);          // ProcessHeap
    v = 4;     wg_blink_write_mem(engine->blink, peb + 0x64, &v, 4);         // NumberOfProcessors
    v = 10;    wg_blink_write_mem(engine->blink, peb + 0xA4, &v, 4);         // OSMajorVersion
    v = 0;     wg_blink_write_mem(engine->blink, peb + 0xA8, &v, 4);         // OSMinorVersion
    uint16_t bld = 19045; wg_blink_write_mem(engine->blink, peb + 0xAC, &bld, 2); // OSBuildNumber
    v = 2;     wg_blink_write_mem(engine->blink, peb + 0xB0, &v, 4);         // OSPlatformId (NT)

    // PE TLS directory (IMAGE_TLS_DIRECTORY32; fields are VAs at the preferred
    // base, where the main exe is loaded). Allocate the TLS data block, copy the
    // template, put its pointer in slot 0 of the TLS array, and write index 0.
    if (pe->tls_rva) {
        uint32_t tls[6] = {0};
        wg_blink_read_mem(engine->blink, image_base + pe->tls_rva, tls, 24);
        uint32_t raw_start = tls[0], raw_end = tls[1], addr_index = tls[2];
        uint32_t zerofill = tls[4];
        uint32_t tpl = (raw_end > raw_start) ? raw_end - raw_start : 0;
        uint32_t data_size = tpl + zerofill; if (!data_size) data_size = 4;
        uint32_t tls_data = wg_guest_alloc(engine, data_size);
        if (tls_data && tpl) {
            uint8_t *tmp = malloc(tpl);
            if (tmp) {
                wg_blink_read_mem(engine->blink, raw_start, tmp, tpl);
                wg_blink_write_mem(engine->blink, tls_data, tmp, tpl);
                free(tmp);
            }
        }
        wg_blink_write_mem(engine->blink, tls_array, &tls_data, 4);   // array[0]
        if (addr_index) { uint32_t z = 0; wg_blink_write_mem(engine->blink, addr_index, &z, 4); }
        WG_LOGI(TAG, "TLS: data@0x%X size 0x%X (index 0)", tls_data, data_size);
    }

    wg_blink_set_fs_base(engine->blink, teb);
    s_main_teb = teb;
    WG_LOGI(TAG, "Win32 TEB@0x%X PEB@0x%X fs-base set", teb, peb);
}

static bool load_pe_blink(WGEngine *engine) {
    WGPEImage *pe = engine->pe_image;

    if (!ensure_blink_vm(engine, pe->is_64bit)) {
        return false;
    }

    WG_LOGI(TAG, "Loading %s PE via blink", pe->is_64bit ? "64-bit" : "32-bit");
    s_nsis_data_patched = false;
    s_nsis_exe_data_offset = 0;

    // Map PE headers at image base — programs walk their own MZ/PE header
    if (pe->num_sections > 0 && pe->sections[0].virtual_address > 0) {
        uint32_t hdr_size = pe->sections[0].virtual_address;
        if (hdr_size > pe->raw_size) hdr_size = (uint32_t)pe->raw_size;
        wg_blink_load_code(engine->blink, pe->image_base, pe->raw_data, hdr_size, 0);
    }

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

    // Set up the Win32 thread environment (TEB/PEB/TLS + FS base) so real MSVC
    // CRT startup (steam.exe) doesn't fault reading fs:[…].
    wg_setup_win32_teb(engine);

    // Map zero pages so reads from unmapped addresses return 0 instead of
    // faulting. Real Windows catches these via SEH; without it, programs
    // crash on NULL dereferences and stale pointers (e.g. vtable entries
    // referencing unloaded DLLs). We map:
    //   0x00000000-0x0000FFFF  — NULL dereferences
    //   0x10000000-0x10000FFF  — low DLL range (fake load addresses)
    //   0x50000000-0x5FFFFFFF  — covers stale DLL pointers from .rdata
    //     (e.g. 0x53572073 "CNet::BFrame..." network handler tables)
    {
        uint8_t *zp = calloc(1, 0x10000);
        if (zp) {
            // NULL dereferences
            wg_blink_load_code(engine->blink, 0, zp, 0x10000, 0);
            // Stale DLL pointers: map specific 4KB pages covering known
            // addresses from steam's .rdata (0x53572073 etc.)
            wg_blink_load_code(engine->blink, 0x53572000u, zp, 0x1000, 0);
            wg_blink_load_code(engine->blink, 0x5ECF7000u, zp, 0x1000, 0);
            free(zp);
        }
    }

    // Map a minimal PE stub at the fake system-DLL handle (0xBFFF0000) so
    // programs that walk kernel32's PE export table (GetModuleHandle +
    // manual export parsing) find valid headers but an empty export dir.
    {
        uint8_t fake[0x200];
        memset(fake, 0, sizeof(fake));
        // DOS header
        fake[0] = 'M'; fake[1] = 'Z';
        // e_lfanew at offset 0x3C -> PE header at 0x80
        uint32_t pe_off = 0x80;
        memcpy(fake + 0x3C, &pe_off, 4);
        // PE signature
        fake[0x80] = 'P'; fake[0x81] = 'E';
        // COFF: Machine=0x14C (i386), NumberOfSections=0
        uint16_t machine = 0x14C;
        memcpy(fake + 0x84, &machine, 2);
        // SizeOfOptionalHeader = 0xE0 (standard PE32)
        uint16_t opt_sz = 0xE0;
        memcpy(fake + 0x94, &opt_sz, 2);
        // Optional header magic = PE32 (0x10B)
        uint16_t magic = 0x10B;
        memcpy(fake + 0x98, &magic, 2);
        // Export directory RVA at OptionalHeader + 0x60 (offset 0x98+0x60=0xF8)
        // Leave it 0 (no exports)
        wg_blink_load_code(engine->blink, 0xBFFF0000u, fake, sizeof(fake), 0);
    }

    // Register the main thread (thread 0) with the scheduler
    if (engine->scheduler) {
        WGThread *mt = &engine->scheduler->threads[0];
        memset(mt, 0, sizeof(*mt));
        mt->state = WG_THREAD_RUNNING;
        mt->id = 1;
        mt->handle = 0x7000;
        mt->exit_code = 259;
        // Save FS base from the TEB we just set up
        mt->regs.fs_base = s_main_teb;
        mt->teb = s_main_teb;
        engine->scheduler->current = 0;
        engine->scheduler->count = 1;
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
    s_detail_count = 0;
    s_pb_pos = 0; s_pb_max = 100;
    s_page_hwnd = 0;
    s_com_shelllink = 0; s_com_persistfile = 0;  // rebuilt in the fresh heap
    s_pending_exec[0] = 0;
    s_tls_next = 0;
    memset(s_tls_slots, 0, sizeof(s_tls_slots));
    s_fls_next = 0;
    memset(s_fls_slots, 0, sizeof(s_fls_slots));
    s_event_next = 0;
    memset(s_event_signalled, 0, sizeof(s_event_signalled));
    s_alloc_count = 0;
    s_cmdpage_mapped = false;
    wg_bitmap_reset_all();

    // Reset the loaded-DLL table (fresh VM => previous mappings are gone).
    for (int i = 0; i < 16; i++) {
        if (s_modules[i].in_use && s_modules[i].img) wg_pe_image_free(s_modules[i].img);
        s_modules[i].in_use = false;
        s_modules[i].img = NULL;
    }
    s_dll_next_base = 0x60000000u;

    // Set the exe path for file I/O mapping (also anchors the bottle's drive_c).
    wg_files_set_exe_path(path);
    // Clear stale NSIS plug-in dirs from the bottle's Temp so this run gets a
    // fresh plug-ins directory (NSIS bails if one already exists).
    wg_files_reset_temp();

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
    if (!engine) return;
    // Allow ticking when PAUSED if worker threads need to run
    if (engine->state == WG_ENGINE_PAUSED && engine->scheduler) {
        bool has_ready = false;
        for (int ti = 0; ti < WG_MAX_THREADS; ti++) {
            if (engine->scheduler->threads[ti].state == WG_THREAD_READY) {
                has_ready = true;
                break;
            }
        }
        if (has_ready) {
            // Switch to a worker thread and run it
            wg_sched_save_current(engine->scheduler, engine->blink, WG_THREAD_WAITING);
            if (wg_sched_switch_next(engine->scheduler, engine->blink)) {
                engine->state = WG_ENGINE_RUNNING;
            }
        }
    }
    if (engine->state != WG_ENGINE_RUNNING) return;

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
                    // RIP=0 can mean: (a) ExitProcess set it, or (b) a
                    // worker thread returned from its start function.
                    // Check if there are other threads to run.
                    WGThread *cur = wg_sched_current(engine->scheduler);
                    if (cur && cur->id != 1) {
                        // Worker thread returned — exit it and switch
                        uint32_t eax = (uint32_t)wg_blink_get_reg(engine->blink, 0);
                        wg_sched_exit_thread(engine->scheduler, engine->blink, eax);
                        wg_sched_wake(engine->scheduler, cur->handle);
                        if (wg_sched_switch_next(engine->scheduler, engine->blink))
                            break;
                    }
                    WG_LOGI(TAG, "Program exited normally after %llu ticks",
                            (unsigned long long)engine->tick_count);
                } else {
                    // Try auto-recovery for calls to unmapped addresses (bad
                    // vtable / uninitialized function pointer): if RIP is
                    // outside all PE sections and the return address on the
                    // stack points into .text, return 0 to the caller.
                    uint32_t pe_end = engine->pe_image
                        ? (uint32_t)(engine->pe_image->image_base + 0x4C0000)
                        : 0x8C0000;
                    if (halt_rip > pe_end) {
                        uint32_t esp = (uint32_t)wg_blink_get_reg(engine->blink, 4);
                        uint32_t ret = 0;
                        wg_blink_read_mem(engine->blink, esp, &ret, 4);
                        uint32_t text_lo = engine->pe_image
                            ? (uint32_t)engine->pe_image->image_base + 0x1000
                            : 0x401000;
                        if (ret >= text_lo && ret < pe_end) {
                            WG_LOGW(TAG, "Auto-recover: call to unmapped 0x%llx, "
                                    "returning 0 to 0x%X",
                                    (unsigned long long)halt_rip, ret);
                            wg_blink_set_reg(engine->blink, 0, 0); // EAX = 0
                            wg_blink_set_reg(engine->blink, 4, esp + 4);
                            wg_blink_set_rip(engine->blink, ret);
                            break;
                        }
                    }
                    WG_LOGE(TAG, "Crash at RIP=0x%llx (SIGSEGV — bad pointer or unmapped memory)",
                            (unsigned long long)halt_rip);
                    // Dump registers for debugging
                    WG_LOGE(TAG, "  EAX=%08X ECX=%08X EDX=%08X EBX=%08X",
                        (uint32_t)wg_blink_get_reg(engine->blink, 0),
                        (uint32_t)wg_blink_get_reg(engine->blink, 1),
                        (uint32_t)wg_blink_get_reg(engine->blink, 2),
                        (uint32_t)wg_blink_get_reg(engine->blink, 3));
                    WG_LOGE(TAG, "  ESP=%08X EBP=%08X ESI=%08X EDI=%08X",
                        (uint32_t)wg_blink_get_reg(engine->blink, 4),
                        (uint32_t)wg_blink_get_reg(engine->blink, 5),
                        (uint32_t)wg_blink_get_reg(engine->blink, 6),
                        (uint32_t)wg_blink_get_reg(engine->blink, 7));
                    // Bytes at crash RIP
                    uint8_t code[16] = {0};
                    wg_blink_read_mem(engine->blink, halt_rip, code, 16);
                    WG_LOGE(TAG, "  code@RIP: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                        code[0],code[1],code[2],code[3],code[4],code[5],code[6],code[7],
                        code[8],code[9],code[10],code[11],code[12],code[13],code[14],code[15]);
                    // Stack dump
                    uint32_t stk[8] = {0};
                    uint32_t esp = (uint32_t)wg_blink_get_reg(engine->blink, 4);
                    wg_blink_read_mem(engine->blink, esp, stk, sizeof(stk));
                    WG_LOGE(TAG, "  stack: %08X %08X %08X %08X  %08X %08X %08X %08X",
                        stk[0],stk[1],stk[2],stk[3],stk[4],stk[5],stk[6],stk[7]);
                    // Bytes before return address (call instruction)
                    if (stk[0] >= 8 && stk[0] < 0x8C0000) {
                        uint8_t caller[16] = {0};
                        wg_blink_read_mem(engine->blink, stk[0] - 8, caller, 16);
                        WG_LOGE(TAG, "  caller@%08X-8: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                            stk[0], caller[0],caller[1],caller[2],caller[3],caller[4],caller[5],caller[6],caller[7],
                            caller[8],caller[9],caller[10],caller[11],caller[12],caller[13],caller[14],caller[15]);
                    }
                    // EBP-based frame: dump caller's return addr and locals
                    uint32_t ebp = (uint32_t)wg_blink_get_reg(engine->blink, 5);
                    if (ebp >= 0x7FFE0000 && ebp < 0x80000000) {
                        uint32_t frame[8] = {0};
                        wg_blink_read_mem(engine->blink, ebp, frame, 32);
                        WG_LOGE(TAG, "  [EBP+00]: %08X %08X %08X %08X  %08X %08X %08X %08X",
                            frame[0],frame[1],frame[2],frame[3],frame[4],frame[5],frame[6],frame[7]);
                        // Dump caller's code at return address
                        if (frame[1] >= 0x401000 && frame[1] < 0x8C0000) {
                            uint8_t callercode[16] = {0};
                            wg_blink_read_mem(engine->blink, frame[1] - 8, callercode, 16);
                            WG_LOGE(TAG, "  retaddr@%08X-8: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                                frame[1], callercode[0],callercode[1],callercode[2],callercode[3],
                                callercode[4],callercode[5],callercode[6],callercode[7],
                                callercode[8],callercode[9],callercode[10],callercode[11],
                                callercode[12],callercode[13],callercode[14],callercode[15]);
                        }
                    }
                    // Dump [EDI] (often the heap buffer being operated on)
                    uint32_t edi = (uint32_t)wg_blink_get_reg(engine->blink, 7);
                    if (edi >= 0x20000000 && edi < 0x30000000) {
                        uint32_t dibuf[8] = {0};
                        wg_blink_read_mem(engine->blink, edi, dibuf, 32);
                        WG_LOGE(TAG, "  [EDI+00]: %08X %08X %08X %08X  %08X %08X %08X %08X",
                            dibuf[0],dibuf[1],dibuf[2],dibuf[3],dibuf[4],dibuf[5],dibuf[6],dibuf[7]);
                    }
                    // Memory at ESI (likely object with bad vtable)
                    uint32_t esi = (uint32_t)wg_blink_get_reg(engine->blink, 6);
                    if (esi) {
                        uint32_t obj[16] = {0};
                        wg_blink_read_mem(engine->blink, esi, obj, sizeof(obj));
                        WG_LOGE(TAG, "  [ESI+00]: %08X %08X %08X %08X  %08X %08X %08X %08X",
                            obj[0],obj[1],obj[2],obj[3],obj[4],obj[5],obj[6],obj[7]);
                        WG_LOGE(TAG, "  [ESI+20]: %08X %08X %08X %08X  %08X %08X %08X %08X",
                            obj[8],obj[9],obj[10],obj[11],obj[12],obj[13],obj[14],obj[15]);
                    }
                    // Last Win32 API calls before crash
                    WG_LOGE(TAG, "  last API calls:");
                    for (int ri = 0; ri < WG_CALL_RING_SIZE; ri++) {
                        int idx = (s_call_ring_idx - WG_CALL_RING_SIZE + ri) % WG_CALL_RING_SIZE;
                        if (idx < 0) idx += WG_CALL_RING_SIZE;
                        if (s_call_ring[idx].fn)
                            WG_LOGE(TAG, "    %s -> 0x%llX",
                                s_call_ring[idx].fn,
                                (unsigned long long)s_call_ring[idx].ret);
                    }
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

const char *wg_engine_take_pending_exec(WGEngine *engine) {
    (void)engine;
    if (!s_pending_exec[0]) return NULL;
    static char path[1024];
    strncpy(path, s_pending_exec, sizeof(path) - 1);
    path[sizeof(path) - 1] = 0;
    s_pending_exec[0] = 0;   // one-shot
    return path;
}
