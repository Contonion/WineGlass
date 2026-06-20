#ifndef WG_X86_INTERP_H
#define WG_X86_INTERP_H

#include "wg_x86_state.h"
#include "wg_memory.h"

typedef enum {
    WG_INTERP_OK,
    WG_INTERP_HALT,
    WG_INTERP_SYSCALL,
    WG_INTERP_ERROR,
} WGInterpResult;

WGInterpResult wg_x86_exec_one(WGx86State *cpu, WGMemorySpace *mem);
WGInterpResult wg_x86_exec_block(WGx86State *cpu, WGMemorySpace *mem, int max_insns);

#endif
