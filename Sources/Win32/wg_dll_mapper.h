#ifndef WG_DLL_MAPPER_H
#define WG_DLL_MAPPER_H

#include <stdint.h>
#include <stdbool.h>

// Each Win32 API stub gets a unique address in 0xDEAD0000-0xDEAF0000.
// When the interpreter CALLs one of these addresses, it triggers a
// syscall/thunk handler instead of executing x86 code.

#define WG_THUNK_BASE 0xDEAD0000

typedef void (*WGWin32StubFunc)(void *cpu_state, void *memory);

typedef struct {
    char     dll_name[64];
    char     func_name[128];
    uint64_t thunk_addr;
    WGWin32StubFunc handler;
    int      num_args;     // stdcall argument count (for stack cleanup)
    int      default_ret;  // EAX for funcs not in the engine's explicit chain
                           // (the registered stub's intent: R1S->1, RnegS->-1).
                           // Legacy stub fns are dead under blink; this is how a
                           // bare registration actually "returns".
} WGDllEntry;

typedef struct {
    WGDllEntry *entries;
    int         count;
    int         capacity;
    uint64_t    next_thunk;
} WGDllMapper;

WGDllMapper *wg_dll_mapper_create(void);
void         wg_dll_mapper_destroy(WGDllMapper *mapper);

uint64_t wg_dll_mapper_register(WGDllMapper *mapper, const char *dll,
                                 const char *func, WGWin32StubFunc handler,
                                 int num_args);

uint64_t wg_dll_mapper_resolve(WGDllMapper *mapper, const char *dll, const char *func);

// Like resolve but searches ALL registered DLLs for `func`. Returns 0 if not found.
uint64_t wg_dll_mapper_find_any(WGDllMapper *mapper, const char *func);

WGWin32StubFunc wg_dll_mapper_get_handler(WGDllMapper *mapper, uint64_t thunk_addr);

void wg_dll_mapper_register_defaults(WGDllMapper *mapper);

#endif
