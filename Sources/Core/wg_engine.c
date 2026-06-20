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
#include "wg_nsis_extract.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define TAG "Engine"

typedef enum {
    WG_BACKEND_BUILTIN,
    WG_BACKEND_BLINK,
} WGBackend;

static uint32_t s_last_error = 0;
static bool s_nsis_data_patched = false;
static uint32_t s_nsis_exe_data_offset = 0;
static uint32_t s_nsis_data_tmp_handle = 0;    // handle to the NSIS data .tmp file
static uint32_t s_nsis_last_data_seek = 0;     // last seek position in data .tmp
static char s_nsis_data_tmp_path[1024] = {0};  // real path of data .tmp

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

// Check if RIP is in the thunk range and handle the Win32 API call.
// Returns true if a thunk was handled.
static bool handle_blink_thunk(WGEngine *engine) {
    uint64_t rip = wg_blink_get_rip(engine->blink);

    // Check both 32-bit (0xC00000) and 64-bit (0xDEAD0000) thunk ranges
    bool in_thunk_range = false;
    if (rip >= 0xC00000ULL && rip < 0xC00000ULL + 0x20000) in_thunk_range = true;
    if (rip >= WG_THUNK_BASE && rip < WG_THUNK_BASE + 0x20000) in_thunk_range = true;
    if (!in_thunk_range) return false;

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
            // GetTempPathW(nBufferLength, lpBuffer)
            uint16_t tmp[] = {'C',':','\\','T','e','m','p','\\',0};
            if (args[1]) {
                wg_blink_write_mem(engine->blink, args[1], tmp, sizeof(tmp));
            }
            ret_val = 8;
        } else if (strcmp(fn, "GetWindowsDirectoryW") == 0) {
            uint16_t windir[] = {'C',':','\\','W','i','n','d','o','w','s',0};
            if (args[1]) {
                wg_blink_write_mem(engine->blink, args[1], windir, sizeof(windir));
            }
            ret_val = 10;
        } else if (strcmp(fn, "GetSystemDirectoryW") == 0) {
            uint16_t sysdir[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2',0};
            if (args[1]) {
                wg_blink_write_mem(engine->blink, args[1], sysdir, sizeof(sysdir));
            }
            ret_val = 19;
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
            // lstrcpynW(dst, src, maxlen)
            if (args[0] && args[1] && args[2] > 0) {
                int maxlen = args[2];
                if (maxlen > 1024) maxlen = 1024;
                uint16_t buf[1024];
                wg_blink_read_mem(engine->blink, args[1], buf, maxlen * 2);
                buf[maxlen - 1] = 0;
                wg_blink_write_mem(engine->blink, args[0], buf, maxlen * 2);
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
            // DialogBoxParamW(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam)
            uint32_t dlgproc = args[3];
            uint32_t initParam = args[4];
            WG_LOGI(TAG, "DialogBoxParamW(dlgproc=0x%X, initParam=0x%X)", dlgproc, initParam);

            // Create a dialog window
            uint16_t title[] = {'S','t','e','a','m',' ','S','e','t','u','p',0};
            uint32_t hwnd = wg_wm_create_window(0, 0, title,
                                                  0x10CF0000,
                                                  50, 50, 500, 360, 0);
            WG_LOGI(TAG, "Created dialog HWND=0x%X, calling dlgproc with WM_INITDIALOG", hwnd);

            // Clean up DialogBoxParamW's stack frame (5 args stdcall)
            uint64_t clean_rsp = rsp + ptr_size + (5 * ptr_size);

            // Now call the dialog proc: dlgproc(hwnd, WM_INITDIALOG, 0, initParam)
            // Push a return address that will be our "dialog done" sentinel
            // Use the original return address so after the dlgproc returns,
            // execution continues at the DialogBoxParamW call site
            if (dlgproc && is_32bit) {
                // Set up stdcall args for dlgproc on the stack:
                // [ESP] = return_addr, [ESP+4] = hwnd, [ESP+8] = WM_INITDIALOG,
                // [ESP+12] = wParam(0), [ESP+16] = lParam(initParam)
                uint32_t new_rsp = (uint32_t)clean_rsp - 20; // 4 args + ret addr
                uint32_t stack_data[5] = {
                    (uint32_t)ret_addr,  // return address
                    hwnd,                // HWND
                    0x0110,              // WM_INITDIALOG
                    0,                   // wParam
                    initParam            // lParam
                };
                wg_blink_write_mem(engine->blink, new_rsp, stack_data, 20);
                wg_blink_set_reg(engine->blink, 4, new_rsp); // ESP
                wg_blink_set_rip(engine->blink, dlgproc);     // jump to dialog proc
                wg_blink_set_reg(engine->blink, 0, 0);

                // After the dlgproc returns (via RET 16 for stdcall 4 args),
                // execution continues at ret_addr. We DON'T pause here —
                // let the dlgproc run so it creates buttons and controls.
                // We'll pause when we see PeekMessageW (the message loop).
                return true;
            }

            // Fallback: pause as before
            engine->state = WG_ENGINE_PAUSED;
            wg_blink_set_reg(engine->blink, 4, clean_rsp);
            wg_blink_set_rip(engine->blink, ret_addr);
            wg_blink_set_reg(engine->blink, 0, 0);
            return true;
        } else if (strcmp(fn, "CreateDialogParamW") == 0) {
            // CreateDialogParamW(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam)
            // Create a window entry for the compositor
            uint32_t parent = args[2];
            uint16_t title[] = {0};
            ret_val = wg_wm_create_window(0, 0, title, 0x50000000, // WS_CHILD|WS_VISIBLE
                                           0, 0, 480, 320, parent);
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
                    ret_val = 0;
                    s_last_error = 183; // ERROR_ALREADY_EXISTS
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
            static uint32_t s_tick = 1000;
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
            // NOTE: NSIS uses a solid raw-LZMA stream that blink's x86
            // decompressor decodes correctly (the dialog/strings/fonts all
            // come from the decompressed header). We deliberately do NOT
            // intercept extraction here — Apple's COMPRESSION_LZMA can't read
            // NSIS's raw stream, and intercepting only discards blink's
            // correct output. Let the guest do the decompression.
        } else if (strcmp(fn, "ReadFile") == 0) {
            uint32_t handle = args[0];
            uint32_t buf_addr = args[1];
            uint32_t nbytes = args[2];
            uint32_t bytes_read_addr = args[3];
            if (nbytes > 0x100000) nbytes = 0x100000;
            uint8_t *tmpbuf = malloc(nbytes);
            if (tmpbuf) {
                uint32_t nread = 0;
                if (wg_files_read(handle, tmpbuf, nbytes, &nread)) {
                    wg_blink_write_mem(engine->blink, buf_addr, tmpbuf, nread);
                    if (bytes_read_addr) {
                        wg_blink_write_mem(engine->blink, bytes_read_addr, &nread, 4);
                    }
                    ret_val = 1;
                }
                free(tmpbuf);
            }
            // Log first few reads per handle
            static int read_log_count = 0;
            if (read_log_count < 30) {
                WG_LOGI(TAG, "ReadFile(0x%X, dst=0x%X, %u bytes) -> %s",
                        handle, buf_addr, nbytes, ret_val ? "OK" : "FAIL");
                read_log_count++;
            }
        } else if (strcmp(fn, "WriteFile") == 0) {
            uint32_t handle = args[0];
            uint32_t buf_addr = args[1];
            uint32_t nbytes = args[2];
            uint32_t bytes_written_addr = args[3];
            if (nbytes > 0x100000) nbytes = 0x100000;
            uint8_t *tmpbuf = malloc(nbytes);
            if (tmpbuf) {
                wg_blink_read_mem(engine->blink, buf_addr, tmpbuf, nbytes);
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
            static uint32_t s_heap_ptr = 0x10000000;
            uint32_t size = args[1];
            if (size == 0) size = 4096;
            // Only reject truly insane sizes (>512MB) as corrupt. NSIS
            // legitimately allocates multi-MB buffers (e.g. 8MB LZMA dict).
            if (size > 512u * 1024 * 1024) {
                WG_LOGW(TAG, "GlobalAlloc FAILED: corrupt size %u", size);
                ret_val = 0; // return NULL — let caller handle the error
                goto skip_alloc;
            }
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
            skip_alloc:;
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

void wg_engine_stop(WGEngine *engine) {
    if (!engine) return;
    if (engine->state == WG_ENGINE_RUNNING) {
        engine->state = WG_ENGINE_STOPPED;
    }
}

WGEngineState wg_engine_get_state(const WGEngine *engine) {
    return engine ? engine->state : WG_ENGINE_ERROR;
}
