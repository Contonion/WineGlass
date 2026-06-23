#ifndef WG_BLINK_BRIDGE_H
#define WG_BLINK_BRIDGE_H

// Bridge between WineGlass engine and blink's x86-64 emulation.
// This replaces our hand-rolled interpreter with blink's full
// x86-64 implementation including JIT (via MAP_JIT on iOS).

#include <stdint.h>
#include <stdbool.h>

typedef struct WGBlinkInstance WGBlinkInstance;

WGBlinkInstance *wg_blink_create(void);     // 64-bit mode
WGBlinkInstance *wg_blink_create32(void);  // 32-bit protected mode
void             wg_blink_destroy(WGBlinkInstance *inst);

bool wg_blink_load_binary(WGBlinkInstance *inst, const char *path);
bool wg_blink_setup_stack(WGBlinkInstance *inst, uint64_t entry_rip);
void wg_blink_switch_to_32bit(WGBlinkInstance *inst);

// Load raw x86-64 code at a specific address and set RIP
bool wg_blink_load_code(WGBlinkInstance *inst, uint64_t addr,
                         const uint8_t *code, uint32_t size,
                         uint64_t entry_rip);

// Execute instructions
typedef enum {
    WG_BLINK_OK,
    WG_BLINK_HALT,
    WG_BLINK_SYSCALL,
    WG_BLINK_ERROR,
} WGBlinkResult;

WGBlinkResult wg_blink_run(WGBlinkInstance *inst, int max_instructions);
WGBlinkResult wg_blink_step(WGBlinkInstance *inst);

// Register access
uint64_t wg_blink_get_reg(WGBlinkInstance *inst, int reg_index);
void     wg_blink_set_reg(WGBlinkInstance *inst, int reg_index, uint64_t val);
uint64_t wg_blink_get_rip(WGBlinkInstance *inst);
void     wg_blink_set_rip(WGBlinkInstance *inst, uint64_t rip);

// Set the FS (32-bit TEB) / GS (64-bit TEB) segment base linear address.
void     wg_blink_set_fs_base(WGBlinkInstance *inst, uint64_t base);
void     wg_blink_set_gs_base(WGBlinkInstance *inst, uint64_t base);

// Memory access
bool wg_blink_write_mem(WGBlinkInstance *inst, uint64_t addr,
                         const void *buf, uint32_t len);
bool wg_blink_read_mem(WGBlinkInstance *inst, uint64_t addr,
                        void *buf, uint32_t len);

// Info
bool wg_blink_has_jit(void);
const char *wg_blink_version(void);

#endif
