#include "wg_dll_mapper.h"
#include "wg_log.h"
#include "wg_x86_state.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define TAG "DLL"

// Default stub — returns 0 in RAX and logs the call
static void stub_default(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0;
}

static void stub_return_1(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 1;
}

static void stub_return_neg1(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = (uint64_t)-1;
}

static void stub_ExitProcess(void *cpu, void *mem) {
    WGx86State *c = cpu;
    WG_LOGI(TAG, "ExitProcess(%llu)", (unsigned long long)c->gpr[WG_REG_RCX]);
    c->halted = true;
}

static void stub_GetModuleHandleA(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0x00400000;
}

static void stub_GetModuleHandleW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0x00400000;
}

static void stub_GetCurrentProcess(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = (uint64_t)-1;
}

static void stub_GetVersion(void *cpu, void *mem) {
    // Windows 10 = 0x0A000000 (major 10, minor 0)
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0x00000A00;
}

static void stub_GetTickCount(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 10000;
}

static void stub_GetDeviceCaps(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 96; // default DPI
}

static void stub_GetSysColor(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0x00FFFFFF;
}

static void stub_RegisterClassW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0xC001;
}

static void stub_CreateWindowExW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0x00010001; // fake HWND
}

static void stub_MessageBoxIndirectW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 1; // IDOK
}

static void stub_ShellExecuteW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 33; // success > 32
}

static void stub_RegOpenKeyExW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 2; // ERROR_FILE_NOT_FOUND
}

static void stub_RegQueryValueExW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 2;
}

static void stub_RegEnumValueW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 259; // ERROR_NO_MORE_ITEMS
}

static void stub_RegEnumKeyW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 259;
}

static void stub_CoCreateInstance(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0x80004002; // E_NOINTERFACE
}

static void stub_SHGetSpecialFolderLocation(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0x80004005; // E_FAIL
}

static void stub_CreateFileW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = (uint64_t)-1; // INVALID_HANDLE_VALUE
}

static void stub_FindFirstFileW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = (uint64_t)-1; // INVALID_HANDLE_VALUE
}

static void stub_GetFileAttributesW(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0xFFFFFFFF; // INVALID_FILE_ATTRIBUTES
}

static void stub_GlobalAlloc(void *cpu, void *mem) {
    // NSIS uses GlobalAlloc for temporary buffers
    void *p = calloc(1, 65536);
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = (uint64_t)(uintptr_t)p;
}

static void stub_GlobalLock(void *cpu, void *mem) {
    // GlobalLock on GMEM_FIXED returns the pointer itself
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = ((WGx86State*)cpu)->gpr[WG_REG_RCX];
}

static void stub_GlobalFree(void *cpu, void *mem) {
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0;
}

static void stub_MulDiv(void *cpu, void *mem) {
    WGx86State *c = cpu;
    int32_t a = (int32_t)c->gpr[WG_REG_RCX];
    int32_t b = (int32_t)c->gpr[WG_REG_RDX];
    int32_t d = (int32_t)c->gpr[WG_REG_R8];
    if (d == 0) { c->gpr[WG_REG_RAX] = (uint64_t)-1; return; }
    c->gpr[WG_REG_RAX] = (uint64_t)(int64_t)((int64_t)a * b / d);
}

static void stub_GetDiskFreeSpaceW(void *cpu, void *mem) {
    // Return true with large fake disk space
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 1;
}

static void stub_PeekMessageW(void *cpu, void *mem) {
    // No messages available
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = 0;
}

static void stub_GetCommandLineW(void *cpu, void *mem) {
    // Return a pointer to a static empty command line
    static uint16_t empty_cmdline[] = { '"', 'a', '.', 'e', 'x', 'e', '"', 0 };
    ((WGx86State*)cpu)->gpr[WG_REG_RAX] = (uint64_t)(uintptr_t)empty_cmdline;
}

// --- Mapper implementation ---

WGDllMapper *wg_dll_mapper_create(void) {
    WGDllMapper *m = calloc(1, sizeof(WGDllMapper));
    if (!m) return NULL;
    m->capacity = 4096;
    m->entries = calloc(m->capacity, sizeof(WGDllEntry));
    if (!m->entries) { free(m); return NULL; }
    m->next_thunk = WG_THUNK_BASE;
    return m;
}

void wg_dll_mapper_destroy(WGDllMapper *mapper) {
    if (!mapper) return;
    free(mapper->entries);
    free(mapper);
}

uint64_t wg_dll_mapper_register(WGDllMapper *mapper, const char *dll,
                                 const char *func, WGWin32StubFunc handler,
                                 int num_args) {
    if (mapper->count >= mapper->capacity) return 0;

    WGDllEntry *e = &mapper->entries[mapper->count++];
    strncpy(e->dll_name, dll, sizeof(e->dll_name) - 1);
    strncpy(e->func_name, func, sizeof(e->func_name) - 1);
    e->thunk_addr = mapper->next_thunk;
    e->handler = handler ? handler : stub_default;
    e->num_args = num_args;
    mapper->next_thunk += 8;
    return e->thunk_addr;
}

uint64_t wg_dll_mapper_resolve(WGDllMapper *mapper, const char *dll, const char *func) {
    // Try exact match first
    for (int i = 0; i < mapper->count; i++) {
        if (strcasecmp(mapper->entries[i].dll_name, dll) == 0 &&
            strcmp(mapper->entries[i].func_name, func) == 0) {
            return mapper->entries[i].thunk_addr;
        }
    }
    // Try without .dll suffix
    char dll_stripped[64], entry_stripped[64];
    strncpy(dll_stripped, dll, sizeof(dll_stripped) - 1);
    char *dot = strrchr(dll_stripped, '.');
    if (dot) *dot = '\0';

    for (int i = 0; i < mapper->count; i++) {
        strncpy(entry_stripped, mapper->entries[i].dll_name, sizeof(entry_stripped) - 1);
        char *edot = strrchr(entry_stripped, '.');
        if (edot) *edot = '\0';

        if (strcasecmp(entry_stripped, dll_stripped) == 0 &&
            strcmp(mapper->entries[i].func_name, func) == 0) {
            return mapper->entries[i].thunk_addr;
        }
    }

    WG_LOGD(TAG, "Auto-stub: %s!%s", dll, func);
    return wg_dll_mapper_register(mapper, dll, func, stub_default, 0);
}

WGWin32StubFunc wg_dll_mapper_get_handler(WGDllMapper *mapper, uint64_t thunk_addr) {
    for (int i = 0; i < mapper->count; i++) {
        if (mapper->entries[i].thunk_addr == thunk_addr)
            return mapper->entries[i].handler;
    }
    return NULL;
}

// R(dll, name, fn, nargs) — register with handler and arg count
// RS(dll, name, nargs) — register with stub_default and arg count
// R1S(dll, name, nargs) — register with stub_return_1 and arg count
#define R(dll, name, fn, n)  wg_dll_mapper_register(m, dll, #name, fn, n)
#define RS(dll, name, n)     wg_dll_mapper_register(m, dll, #name, stub_default, n)
#define R1S(dll, name, n)    wg_dll_mapper_register(m, dll, #name, stub_return_1, n)

void wg_dll_mapper_register_defaults(WGDllMapper *m) {
    // === KERNEL32.dll === (function, handler, num_stdcall_args)
    R1S("KERNEL32.dll", SetCurrentDirectoryW, 1);
    R("KERNEL32.dll", GetFileAttributesW, stub_GetFileAttributesW, 1);
    RS("KERNEL32.dll", GetFullPathNameW, 4);
    RS("KERNEL32.dll", Sleep, 1);
    R("KERNEL32.dll", GetTickCount, stub_GetTickCount, 0);
    R("KERNEL32.dll", CreateFileW, stub_CreateFileW, 7);
    RS("KERNEL32.dll", GetFileSize, 2);
    R1S("KERNEL32.dll", MoveFileW, 2);
    R1S("KERNEL32.dll", SetFileAttributesW, 2);
    RS("KERNEL32.dll", GetModuleFileNameW, 3);
    R1S("KERNEL32.dll", CopyFileW, 3);
    R("KERNEL32.dll", ExitProcess, stub_ExitProcess, 1);
    R1S("KERNEL32.dll", SetEnvironmentVariableW, 2);
    RS("KERNEL32.dll", GetWindowsDirectoryW, 2);
    RS("KERNEL32.dll", GetTempPathW, 2);
    R("KERNEL32.dll", GetCommandLineW, stub_GetCommandLineW, 0);
    R("KERNEL32.dll", GetVersion, stub_GetVersion, 0);
    RS("KERNEL32.dll", SetErrorMode, 1);
    RS("KERNEL32.dll", WaitForSingleObject, 2);
    R("KERNEL32.dll", GetCurrentProcess, stub_GetCurrentProcess, 0);
    RS("KERNEL32.dll", CompareFileTime, 2);
    R1S("KERNEL32.dll", GlobalUnlock, 1);
    R("KERNEL32.dll", GlobalLock, stub_GlobalLock, 1);
    R1S("KERNEL32.dll", CreateThread, 6);
    RS("KERNEL32.dll", GetLastError, 0);
    R1S("KERNEL32.dll", CreateDirectoryW, 2);
    RS("KERNEL32.dll", CreateProcessW, 10);
    R1S("KERNEL32.dll", RemoveDirectoryW, 1);
    RS("KERNEL32.dll", lstrcmpiA, 2);
    RS("KERNEL32.dll", GetTempFileNameW, 4);
    R1S("KERNEL32.dll", WriteFile, 5);
    RS("KERNEL32.dll", lstrcpyA, 2);
    RS("KERNEL32.dll", lstrcpyW, 2);
    R1S("KERNEL32.dll", MoveFileExW, 3);
    RS("KERNEL32.dll", lstrcatW, 2);
    RS("KERNEL32.dll", GetSystemDirectoryW, 2);
    RS("KERNEL32.dll", GetProcAddress, 2);
    R("KERNEL32.dll", GetModuleHandleA, stub_GetModuleHandleA, 1);
    R("KERNEL32.dll", GlobalFree, stub_GlobalFree, 1);
    R("KERNEL32.dll", GlobalAlloc, stub_GlobalAlloc, 2);
    RS("KERNEL32.dll", GetShortPathNameW, 3);
    RS("KERNEL32.dll", SearchPathW, 6);
    RS("KERNEL32.dll", lstrcmpiW, 2);
    R1S("KERNEL32.dll", SetFileTime, 4);
    R1S("KERNEL32.dll", CloseHandle, 1);
    RS("KERNEL32.dll", ExpandEnvironmentStringsW, 3);
    RS("KERNEL32.dll", lstrcmpW, 2);
    R("KERNEL32.dll", GetDiskFreeSpaceW, stub_GetDiskFreeSpaceW, 5);
    RS("KERNEL32.dll", lstrlenW, 1);
    RS("KERNEL32.dll", lstrcpynW, 3);
    R1S("KERNEL32.dll", GetExitCodeProcess, 2);
    R("KERNEL32.dll", FindFirstFileW, stub_FindFirstFileW, 2);
    RS("KERNEL32.dll", FindNextFileW, 2);
    R1S("KERNEL32.dll", DeleteFileW, 1);
    RS("KERNEL32.dll", SetFilePointer, 4);
    R1S("KERNEL32.dll", ReadFile, 5);
    R1S("KERNEL32.dll", FindClose, 1);
    R("KERNEL32.dll", MulDiv, stub_MulDiv, 3);
    RS("KERNEL32.dll", MultiByteToWideChar, 6);
    RS("KERNEL32.dll", lstrlenA, 1);
    RS("KERNEL32.dll", WideCharToMultiByte, 8);
    RS("KERNEL32.dll", GetPrivateProfileStringW, 6);
    R1S("KERNEL32.dll", WritePrivateProfileStringW, 4);
    R1S("KERNEL32.dll", FreeLibrary, 1);
    RS("KERNEL32.dll", LoadLibraryExW, 3);
    R("KERNEL32.dll", GetModuleHandleW, stub_GetModuleHandleW, 1);
    RS("KERNEL32.dll", GetCurrentProcessId, 0);
    RS("KERNEL32.dll", GetCurrentThreadId, 0);
    RS("KERNEL32.dll", SetLastError, 1);
    RS("KERNEL32.dll", IsDebuggerPresent, 0);
    RS("KERNEL32.dll", OutputDebugStringA, 1);
    RS("KERNEL32.dll", VirtualAlloc, 4);
    R1S("KERNEL32.dll", VirtualFree, 3);
    RS("KERNEL32.dll", HeapCreate, 3);
    RS("KERNEL32.dll", HeapAlloc, 3);
    R1S("KERNEL32.dll", HeapFree, 3);
    RS("KERNEL32.dll", GetProcessHeap, 0);
    R1S("KERNEL32.dll", QueryPerformanceCounter, 1);
    R1S("KERNEL32.dll", QueryPerformanceFrequency, 1);
    RS("KERNEL32.dll", GetSystemInfo, 1);
    R1S("KERNEL32.dll", GetVersionExA, 1);

    // === USER32.dll ===
    RS("USER32.dll", GetSystemMenu, 2);
    RS("USER32.dll", SetClassLongW, 3);
    R1S("USER32.dll", IsWindowEnabled, 1);
    RS("USER32.dll", EnableMenuItem, 3);
    R1S("USER32.dll", SetWindowPos, 7);
    R("USER32.dll", GetSysColor, stub_GetSysColor, 1);
    RS("USER32.dll", GetWindowLongW, 2);
    RS("USER32.dll", SetCursor, 1);
    R1S("USER32.dll", LoadCursorW, 2);
    R1S("USER32.dll", CheckDlgButton, 3);
    RS("USER32.dll", GetMessagePos, 0);
    RS("USER32.dll", LoadBitmapW, 2);
    RS("USER32.dll", CallWindowProcW, 5);
    RS("USER32.dll", IsWindowVisible, 1);
    R1S("USER32.dll", CloseClipboard, 0);
    RS("USER32.dll", SetClipboardData, 2);
    R1S("USER32.dll", EmptyClipboard, 0);
    R1S("USER32.dll", OpenClipboard, 1);
    RS("USER32.dll", wsprintfW, 0); // cdecl variadic — caller cleans
    R1S("USER32.dll", ScreenToClient, 2);
    R1S("USER32.dll", GetWindowRect, 2);
    RS("USER32.dll", GetSystemMetrics, 1);
    R1S("USER32.dll", SetDlgItemTextW, 3);
    RS("USER32.dll", GetDlgItemTextW, 4);
    R("USER32.dll", MessageBoxIndirectW, stub_MessageBoxIndirectW, 1);
    RS("USER32.dll", CharPrevW, 2);
    RS("USER32.dll", CharNextA, 1);
    RS("USER32.dll", wsprintfA, 0); // cdecl variadic — caller cleans
    RS("USER32.dll", DispatchMessageW, 1);
    R("USER32.dll", PeekMessageW, stub_PeekMessageW, 5);
    R1S("USER32.dll", GetDC, 1);
    R1S("USER32.dll", ReleaseDC, 2);
    RS("USER32.dll", EnableWindow, 2);
    R1S("USER32.dll", InvalidateRect, 3);
    RS("USER32.dll", SendMessageW, 4);
    RS("USER32.dll", DefWindowProcW, 4);
    R1S("USER32.dll", BeginPaint, 2);
    R1S("USER32.dll", GetClientRect, 2);
    R1S("USER32.dll", FillRect, 3);
    R1S("USER32.dll", EndDialog, 2);
    R("USER32.dll", RegisterClassW, stub_RegisterClassW, 1);
    R1S("USER32.dll", SystemParametersInfoW, 4);
    R("USER32.dll", CreateWindowExW, stub_CreateWindowExW, 12);
    R1S("USER32.dll", GetClassInfoW, 3);
    RS("USER32.dll", DialogBoxParamW, 5);
    RS("USER32.dll", CharNextW, 1);
    R1S("USER32.dll", ExitWindowsEx, 2);
    R1S("USER32.dll", DestroyWindow, 1);
    RS("USER32.dll", LoadImageW, 6);
    R1S("USER32.dll", SetTimer, 4);
    R1S("USER32.dll", SetWindowTextW, 2);
    RS("USER32.dll", PostQuitMessage, 1);
    R1S("USER32.dll", ShowWindow, 2);
    RS("USER32.dll", GetDlgItem, 2);
    RS("USER32.dll", IsWindow, 1);
    RS("USER32.dll", SetWindowLongW, 3);
    RS("USER32.dll", FindWindowExW, 4);
    RS("USER32.dll", TrackPopupMenu, 7);
    R1S("USER32.dll", AppendMenuW, 4);
    R1S("USER32.dll", CreatePopupMenu, 0);
    RS("USER32.dll", DrawTextW, 5);
    R1S("USER32.dll", EndPaint, 2);
    RS("USER32.dll", CreateDialogParamW, 5);
    RS("USER32.dll", SendMessageTimeoutW, 7);
    R1S("USER32.dll", SetForegroundWindow, 1);
    RS("USER32.dll", GetMessageA, 4);

    // === GDI32.dll ===
    RS("GDI32.dll", SelectObject, 2);
    RS("GDI32.dll", SetBkMode, 2);
    R1S("GDI32.dll", CreateFontIndirectW, 1);
    RS("GDI32.dll", SetTextColor, 2);
    R1S("GDI32.dll", DeleteObject, 1);
    R("GDI32.dll", GetDeviceCaps, stub_GetDeviceCaps, 2);
    R1S("GDI32.dll", CreateBrushIndirect, 1);
    RS("GDI32.dll", SetBkColor, 2);

    // === SHELL32.dll ===
    R1S("SHELL32.dll", IsUserAnAdmin, 0);
    R("SHELL32.dll", SHGetSpecialFolderLocation, stub_SHGetSpecialFolderLocation, 3);
    RS("SHELL32.dll", SHGetPathFromIDListW, 2);
    RS("SHELL32.dll", SHBrowseForFolderW, 1);
    RS("SHELL32.dll", SHGetFileInfoW, 5);
    R("SHELL32.dll", ShellExecuteW, stub_ShellExecuteW, 6);
    RS("SHELL32.dll", SHFileOperationW, 1);

    // === ADVAPI32.dll ===
    RS("ADVAPI32.dll", RegDeleteKeyW, 2);
    R1S("ADVAPI32.dll", SetFileSecurityW, 3);
    R1S("ADVAPI32.dll", OpenProcessToken, 3);
    R1S("ADVAPI32.dll", LookupPrivilegeValueW, 3);
    R1S("ADVAPI32.dll", AdjustTokenPrivileges, 6);
    R("ADVAPI32.dll", RegOpenKeyExW, stub_RegOpenKeyExW, 5);
    R("ADVAPI32.dll", RegEnumValueW, stub_RegEnumValueW, 8);
    RS("ADVAPI32.dll", RegDeleteValueW, 2);
    RS("ADVAPI32.dll", RegCloseKey, 1);
    RS("ADVAPI32.dll", RegCreateKeyExW, 9);
    RS("ADVAPI32.dll", RegSetValueExW, 6);
    R("ADVAPI32.dll", RegQueryValueExW, stub_RegQueryValueExW, 6);
    R("ADVAPI32.dll", RegEnumKeyW, stub_RegEnumKeyW, 4);

    // === COMCTL32.dll ===
    RS("COMCTL32.dll", ImageList_AddMasked, 3);
    RS("COMCTL32.dll", Ordinal_17, 1);
    R1S("COMCTL32.dll", ImageList_Destroy, 1);
    R1S("COMCTL32.dll", ImageList_Create, 5);

    // === ole32.dll ===
    RS("ole32.dll", OleUninitialize, 0);
    RS("ole32.dll", OleInitialize, 1);
    RS("ole32.dll", CoTaskMemFree, 1);
    R("ole32.dll", CoCreateInstance, stub_CoCreateInstance, 5);

    // === ntdll.dll ===
    RS("ntdll.dll", RtlInitializeCriticalSection, 1);

    WG_LOGI(TAG, "Registered %d Win32 API stubs", m->count);
}
