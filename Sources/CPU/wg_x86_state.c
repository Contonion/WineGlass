#include "wg_x86_state.h"
#include "wg_log.h"
#include <stdlib.h>
#include <string.h>

#define TAG "CPU"

static const char *reg_names[] = {
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15"
};

WGx86State *wg_x86_state_create(void) {
    WGx86State *s = calloc(1, sizeof(WGx86State));
    if (!s) return NULL;
    wg_x86_state_reset(s);
    return s;
}

void wg_x86_state_destroy(WGx86State *state) {
    free(state);
}

void wg_x86_state_reset(WGx86State *state) {
    memset(state, 0, sizeof(WGx86State));
    state->rflags = WG_FLAG_IF | 0x2; // IF set, bit 1 always set
    state->cs = 0x33;
    state->ds = state->es = state->ss = 0x2B;
    state->mxcsr = 0x1F80;
    state->fpu_control = 0x037F;
}

void wg_x86_set_reg(WGx86State *s, WGx86Reg r, uint64_t val) {
    if (r < WG_REG_COUNT) s->gpr[r] = val;
}

uint64_t wg_x86_get_reg(const WGx86State *s, WGx86Reg r) {
    return (r < WG_REG_COUNT) ? s->gpr[r] : 0;
}

void wg_x86_set_rip(WGx86State *s, uint64_t rip) { s->rip = rip; }
uint64_t wg_x86_get_rip(const WGx86State *s) { return s->rip; }

void wg_x86_set_flag(WGx86State *s, uint64_t flag, bool val) {
    if (val) s->rflags |= flag;
    else     s->rflags &= ~flag;
}

bool wg_x86_get_flag(const WGx86State *s, uint64_t flag) {
    return (s->rflags & flag) != 0;
}

static bool parity(uint8_t v) {
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return !(v & 1);
}

static uint64_t sign_bit(int bits) {
    return 1ULL << (bits - 1);
}

static uint64_t mask_for_bits(int bits) {
    if (bits >= 64) return ~0ULL;
    return (1ULL << bits) - 1;
}

void wg_x86_update_flags_add(WGx86State *s, uint64_t a, uint64_t b, uint64_t result, int bits) {
    uint64_t m = mask_for_bits(bits);
    uint64_t sb = sign_bit(bits);
    uint64_t r = result & m;

    wg_x86_set_flag(s, WG_FLAG_CF, result > m);
    wg_x86_set_flag(s, WG_FLAG_ZF, r == 0);
    wg_x86_set_flag(s, WG_FLAG_SF, (r & sb) != 0);
    wg_x86_set_flag(s, WG_FLAG_OF, ((a ^ result) & (b ^ result) & sb) != 0);
    wg_x86_set_flag(s, WG_FLAG_AF, ((a ^ b ^ result) & 0x10) != 0);
    wg_x86_set_flag(s, WG_FLAG_PF, parity((uint8_t)r));
}

void wg_x86_update_flags_sub(WGx86State *s, uint64_t a, uint64_t b, uint64_t result, int bits) {
    uint64_t m = mask_for_bits(bits);
    uint64_t sb = sign_bit(bits);
    uint64_t r = result & m;

    wg_x86_set_flag(s, WG_FLAG_CF, a < b);
    wg_x86_set_flag(s, WG_FLAG_ZF, r == 0);
    wg_x86_set_flag(s, WG_FLAG_SF, (r & sb) != 0);
    wg_x86_set_flag(s, WG_FLAG_OF, ((a ^ b) & (a ^ result) & sb) != 0);
    wg_x86_set_flag(s, WG_FLAG_AF, ((a ^ b ^ result) & 0x10) != 0);
    wg_x86_set_flag(s, WG_FLAG_PF, parity((uint8_t)r));
}

void wg_x86_update_flags_logic(WGx86State *s, uint64_t result, int bits) {
    uint64_t m = mask_for_bits(bits);
    uint64_t sb = sign_bit(bits);
    uint64_t r = result & m;

    wg_x86_set_flag(s, WG_FLAG_CF, false);
    wg_x86_set_flag(s, WG_FLAG_OF, false);
    wg_x86_set_flag(s, WG_FLAG_ZF, r == 0);
    wg_x86_set_flag(s, WG_FLAG_SF, (r & sb) != 0);
    wg_x86_set_flag(s, WG_FLAG_PF, parity((uint8_t)r));
}

void wg_x86_dump_state(const WGx86State *s) {
    WG_LOGI(TAG, "RIP = 0x%016llx  RFLAGS = 0x%016llx",
            (unsigned long long)s->rip, (unsigned long long)s->rflags);
    WG_LOGI(TAG, "  CF=%d ZF=%d SF=%d OF=%d",
            wg_x86_get_flag(s, WG_FLAG_CF), wg_x86_get_flag(s, WG_FLAG_ZF),
            wg_x86_get_flag(s, WG_FLAG_SF), wg_x86_get_flag(s, WG_FLAG_OF));
    for (int i = 0; i < WG_REG_COUNT; i += 4) {
        WG_LOGI(TAG, "  %3s=0x%016llx  %3s=0x%016llx  %3s=0x%016llx  %3s=0x%016llx",
                reg_names[i],   (unsigned long long)s->gpr[i],
                reg_names[i+1], (unsigned long long)s->gpr[i+1],
                reg_names[i+2], (unsigned long long)s->gpr[i+2],
                reg_names[i+3], (unsigned long long)s->gpr[i+3]);
    }
}
