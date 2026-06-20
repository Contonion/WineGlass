#ifndef WG_X86_STATE_H
#define WG_X86_STATE_H

#include <stdint.h>
#include <stdbool.h>

// General purpose registers
typedef enum {
    WG_REG_RAX = 0, WG_REG_RCX, WG_REG_RDX, WG_REG_RBX,
    WG_REG_RSP,     WG_REG_RBP, WG_REG_RSI, WG_REG_RDI,
    WG_REG_R8,      WG_REG_R9,  WG_REG_R10, WG_REG_R11,
    WG_REG_R12,     WG_REG_R13, WG_REG_R14, WG_REG_R15,
    WG_REG_COUNT
} WGx86Reg;

// RFLAGS bits
#define WG_FLAG_CF  (1 << 0)
#define WG_FLAG_PF  (1 << 2)
#define WG_FLAG_AF  (1 << 4)
#define WG_FLAG_ZF  (1 << 6)
#define WG_FLAG_SF  (1 << 7)
#define WG_FLAG_TF  (1 << 8)
#define WG_FLAG_IF  (1 << 9)
#define WG_FLAG_DF  (1 << 10)
#define WG_FLAG_OF  (1 << 11)

typedef struct {
    uint64_t gpr[WG_REG_COUNT];
    uint64_t rip;
    uint64_t rflags;

    // SSE registers (128-bit, stored as pairs of uint64)
    uint64_t xmm[16][2];
    uint32_t mxcsr;

    // Segment registers (mostly unused in 64-bit flat model)
    uint16_t cs, ds, es, fs, gs, ss;

    // FPU state
    long double st[8];
    uint16_t fpu_control;
    uint16_t fpu_status;
    int      fpu_top;

    // Execution state
    bool     halted;
    bool     interrupt_pending;
    uint8_t  interrupt_vector;
    uint64_t instruction_count;
} WGx86State;

WGx86State *wg_x86_state_create(void);
void        wg_x86_state_destroy(WGx86State *state);
void        wg_x86_state_reset(WGx86State *state);

void     wg_x86_set_reg(WGx86State *s, WGx86Reg r, uint64_t val);
uint64_t wg_x86_get_reg(const WGx86State *s, WGx86Reg r);
void     wg_x86_set_rip(WGx86State *s, uint64_t rip);
uint64_t wg_x86_get_rip(const WGx86State *s);

void wg_x86_set_flag(WGx86State *s, uint64_t flag, bool val);
bool wg_x86_get_flag(const WGx86State *s, uint64_t flag);

void wg_x86_update_flags_add(WGx86State *s, uint64_t a, uint64_t b, uint64_t result, int bits);
void wg_x86_update_flags_sub(WGx86State *s, uint64_t a, uint64_t b, uint64_t result, int bits);
void wg_x86_update_flags_logic(WGx86State *s, uint64_t result, int bits);

void wg_x86_dump_state(const WGx86State *s);

#endif
