// Full blink integration — compiled with blink's header paths.
// Must be compiled separately from the WineGlass Xcode project
// because blink's headers shadow system headers.

// System headers MUST come before blink includes because blink
// shadows signal.h, string.h, etc.
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Force system signal.h via the SDK sysroot path
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
typedef int sig_atomic_t_placeholder_;
#include <sys/signal.h>
#pragma clang diagnostic pop

#include "blink/machine.h"
#include "blink/pml4t.h"
#include "blink/bus.h"
#include "blink/endian.h"
#include "blink/x86.h"
#include "blink/map.h"
#include "blink/tunables.h"

struct WGBlinkVM {
    struct Machine *m;
    struct System  *s;
    int last_stop;   // last siglongjmp code from onhalt (kMachine* / -1 halt)
};

// Real-threads rearchitecture: each guest thread runs its OWN blink Machine on
// its own pthread, all sharing one System (guest memory). We keep blink built
// with DISABLE_THREADS (its SMP pagelocks deadlock our manual per-instruction
// stepping; and blink's g_machine is a plain global there). blink's interpreter
// hot path uses the `m` we PASS (not g_machine — verified: memory.c has zero
// g_machine reads), so we track the current thread's Machine in OUR OWN real
// TLS (`__thread`, which blink's `#define _Thread_local` macro does NOT touch)
// and route every per-thread accessor through cur_m(). The main engine thread
// gets wg_tls_m == vm->m (identical to the old behaviour); a worker pthread gets
// its own. We also mirror into blink's global g_machine for the rare paths that
// read it (diagnostics/FreeMachine/asserts).
static __thread struct Machine *wg_tls_m = (struct Machine *)0;
static inline struct Machine *cur_m(struct WGBlinkVM *vm) {
    if (wg_tls_m) return wg_tls_m;
    return vm ? vm->m : (struct Machine *)0;
}

static int s_blink_initialized = 0;

static void ensure_initialized(void) {
    if (!s_blink_initialized) {
        extern bool FLAG_nolinear;
        FLAG_nolinear = true;

        InitMap();
        s_blink_initialized = 1;
    }
}

static struct WGBlinkVM *create_vm_with_mode(struct XedMachineMode mode) {
    ensure_initialized();

    struct WGBlinkVM *vm = calloc(1, sizeof(struct WGBlinkVM));
    if (!vm) return NULL;

    vm->s = NewSystem(mode);
    if (!vm->s) { free(vm); return NULL; }

    if (!vm->s->real) {
        long pagesize = FLAG_pagesize;
        long real_size = (kRealSize + pagesize - 1) & ~(pagesize - 1);
        vm->s->real = Mmap(NULL, real_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS_, -1, 0, "real");
        if (!vm->s->real) { FreeSystem(vm->s); free(vm); return NULL; }
    }

    vm->m = NewMachine(vm->s, NULL);
    if (!vm->m) { FreeSystem(vm->s); free(vm); return NULL; }
    wg_tls_m = vm->m;    // this (main engine) thread's current Machine (real TLS)
    g_machine = vm->m;   // mirror into blink's global for its diagnostic paths

    if (mode.omode == XED_MODE_LONG) {
        // 64-bit: paging required, set up page tables
        vm->s->cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_PG;
        vm->s->cr3 = AllocatePageTable(vm->s);
        if (vm->s->cr3 == (u64)-1) {
            FreeMachine(vm->m); FreeSystem(vm->s); free(vm); return NULL;
        }
    } else if (mode.omode == XED_MODE_LEGACY) {
        // 32-bit: protected mode, NO paging — use s->real as flat memory
        vm->s->cr0 = CR0_PE | CR0_MP | CR0_ET;
    }
    vm->m->flags |= (1 << 9); // IF

    return vm;
}

struct WGBlinkVM *WGBlinkVM_Create(void) {
    return create_vm_with_mode(XED_MACHINE_MODE_LONG);
}

struct WGBlinkVM *WGBlinkVM_Create32(void) {
    // Always create System in LONG mode (page tables work).
    // We switch ONLY the Machine's decoder to 32-bit later.
    return create_vm_with_mode(XED_MACHINE_MODE_LONG);
}

void WGBlinkVM_SwitchTo32(struct WGBlinkVM *vm) {
    if (!vm) return;
    // Set ONLY the Machine's instruction decoder to 32-bit.
    // Do NOT call SetMachineMode() — that changes the System mode
    // too, which breaks ReserveVirtual permanently.
    vm->m->mode = XED_MACHINE_MODE_LEGACY_32;
}

// (Old create flow moved into create_vm_with_mode above)

void WGBlinkVM_Destroy(struct WGBlinkVM *vm) {
    if (!vm) return;
    if (vm->m) FreeMachine(vm->m);
    if (vm->s) FreeSystem(vm->s);
    free(vm);
}

int WGBlinkVM_LoadCode(struct WGBlinkVM *vm, unsigned long long addr,
                        const void *code, unsigned int size,
                        unsigned long long entry_rip) {
    if (!vm) return 0;

    // Always use long mode page tables (System is always XED_MODE_LONG)
    long long page_addr = addr & -4096LL;
    unsigned long long page_size = ((addr + size + 4095) & -4096LL) - page_addr;
    if (ReserveVirtual(vm->s, page_addr, page_size,
                       PAGE_U | PAGE_RW, -1, 0, false, false) == -1) {
        return 0;
    }
    CopyToUser(vm->m, addr, (void *)code, size);

    if (entry_rip) {
        vm->m->ip = entry_rip;
    }

    return 1;
}

int WGBlinkVM_SetupStack(struct WGBlinkVM *vm, unsigned long long entry_rip) {
    if (!vm) return 0;

    // Determine if machine is in 32-bit decode mode
    int is_32bit = (vm->m->mode.omode == XED_MODE_LEGACY ||
                    vm->m->mode.omode == XED_MODE_REAL);

    // Allocate stack via long mode page tables
    long long stack_base = 0x7FFF0000LL;
    long long stack_size = 0x100000LL;
    if (ReserveVirtual(vm->s, stack_base - stack_size, stack_size,
                       PAGE_U | PAGE_RW, -1, 0, false, false) == -1) {
        return 0;
    }

    if (is_32bit) {
        // 32-bit: 4-byte stack frames
        unsigned int sp = (unsigned int)(stack_base - 0x100);
        sp -= 4;
        unsigned int zero = 0;
        CopyToUser(vm->m, sp, &zero, 4);
        Put32(vm->m->sp, sp);
        Put32(vm->m->bp, sp + 4);
    } else {
        // 64-bit: 8-byte stack frames
        unsigned long long sp = stack_base - 0x100;
        sp -= 8;
        unsigned char zero[8] = {0};
        CopyToUser(vm->m, sp, zero, 8);
        Put64(vm->m->sp, sp);
        Put64(vm->m->bp, sp + 8);
    }

    vm->m->ip = entry_rip;
    return 1;
}

// Set the FS/GS segment base (linear address). Windows uses FS for the 32-bit
// TEB and GS for the 64-bit TEB; the MSVC CRT reads fs:[0x18]/[0x2C]/[0x30]
// during startup, so without a real base + TEB it faults immediately.
void WGBlinkVM_SetFsBase(struct WGBlinkVM *vm, unsigned long long base) {
    if (vm) cur_m(vm)->fs.base = base;
}
void WGBlinkVM_SetGsBase(struct WGBlinkVM *vm, unsigned long long base) {
    if (vm) cur_m(vm)->gs.base = base;
}


// Defined in wg_blink_stubs.c — lets TerminateSignal longjmp back to us
extern void wg_blink_set_onhalt(sigjmp_buf *buf);

int WGBlinkVM_Step(struct WGBlinkVM *vm) {
    if (!vm) return -1;
    struct Machine *m = cur_m(vm);

    m->canhalt = true;

    int rc = sigsetjmp(m->onhalt, 0);
    wg_blink_set_onhalt(&m->onhalt);

    if (rc) {
        vm->last_stop = rc;
        m->canhalt = false;
        wg_blink_set_onhalt(NULL);
        return 1; // any signal/halt = stop
    }

    LoadInstruction(m, GetPc(m));
    ExecuteInstruction(m);

    vm->last_stop = 0;
    m->canhalt = false;
    wg_blink_set_onhalt(NULL);

    if (m->ip == 0) return 1;
    return 0;
}

int WGBlinkVM_Run(struct WGBlinkVM *vm, int max_insns) {
    if (!vm) return -1;
    struct Machine *m = cur_m(vm);

    m->canhalt = true;

    int rc = sigsetjmp(m->onhalt, 0);
    wg_blink_set_onhalt(&m->onhalt);

    if (rc) {
        vm->last_stop = rc;
        m->canhalt = false;
        wg_blink_set_onhalt(NULL);
        return 1; // halt/signal
    }

    for (int i = 0; i < max_insns; i++) {
        if (m->ip == 0) {
            vm->last_stop = 0;
            m->canhalt = false;
            wg_blink_set_onhalt(NULL);
            return 1;
        }
        LoadInstruction(m, GetPc(m));
        ExecuteInstruction(m);
    }

    vm->last_stop = 0;
    m->canhalt = false;
    wg_blink_set_onhalt(NULL);
    return 0;
}

unsigned long long WGBlinkVM_GetReg(struct WGBlinkVM *vm, int idx) {
    if (!vm || idx < 0 || idx >= 16) return 0;
    return Get64(cur_m(vm)->weg[idx]);
}

void WGBlinkVM_SetReg(struct WGBlinkVM *vm, int idx, unsigned long long val) {
    if (!vm || idx < 0 || idx >= 16) return;
    Put64(cur_m(vm)->weg[idx], val);
}

unsigned long long WGBlinkVM_GetRIP(struct WGBlinkVM *vm) {
    return vm ? cur_m(vm)->ip : 0;
}

void WGBlinkVM_SetRIP(struct WGBlinkVM *vm, unsigned long long rip) {
    if (vm) cur_m(vm)->ip = rip;
}

// Last stop reason: 0 = ran/clean, -1 = halt, kMachineSegmentationFault (-4),
// kMachineProtectionFault (-8), etc. Lets the engine tell a memory fault (which
// should become a guest exception) from a normal halt.
int WGBlinkVM_GetStopReason(struct WGBlinkVM *vm) {
    return vm ? vm->last_stop : 0;
}

// Faulting guest virtual address recorded on the last memory fault.
unsigned long long WGBlinkVM_GetFaultAddr(struct WGBlinkVM *vm) {
    return vm ? (unsigned long long)cur_m(vm)->faultaddr : 0;
}

int WGBlinkVM_WriteMem(struct WGBlinkVM *vm, unsigned long long addr,
                        const void *buf, unsigned int len) {
    if (!vm) return 0;
    CopyToUser(cur_m(vm), addr, (void *)buf, len);
    return 1;
}

int WGBlinkVM_ReadMem(struct WGBlinkVM *vm, unsigned long long addr,
                       void *buf, unsigned int len) {
    if (!vm) return 0;
    CopyFromUser(cur_m(vm), buf, addr, len);
    return 1;
}

// ── Real-threads support: a Machine per guest thread, shared System ──────────
//
// Each guest CreateThread/_beginthreadex maps to a real pthread running its own
// blink Machine over the SAME System (shared guest memory + page tables). The
// engine's worker-pthread entry calls NewThreadMachine on the parent thread,
// then (on the new pthread) AdoptMachine to make it current, seeds regs via the
// normal wg_blink_set_* accessors (which route through g_machine), and drives it.

// Create a Machine sharing vm's System. NewMachine memcpy's the parent (so it
// inherits fs/gs base, cr3 via System, etc.) but resets its mode to the System
// mode (LONG); restore the parent's actual decode mode (LEGACY_32 for a 32-bit
// guest). Returns an opaque Machine* (NULL on failure). Caller reseeds regs/rip.
void *WGBlinkVM_NewThreadMachine(struct WGBlinkVM *vm) {
    if (!vm || !vm->s || !vm->m) return (void *)0;
    struct Machine *m = NewMachine(vm->s, vm->m);
    if (!m) return (void *)0;
    m->mode = vm->m->mode;   // match the main Machine's 32/64-bit decode mode
    m->ip = 0;
    m->canhalt = false;
    return m;
}

// Make Machine `mp` the calling pthread's current Machine. Call this FIRST on
// the worker pthread, before any wg_blink_* accessor (they route via g_machine).
void WGBlinkVM_AdoptMachine(void *mp) {
    struct Machine *m = (struct Machine *)mp;
    wg_tls_m = m;        // this worker pthread's current Machine (real TLS)
    g_machine = m;       // mirror into blink's global (racy but only diagnostics use it)
    if (m) m->thread = pthread_self();
}

void WGBlinkVM_FreeThreadMachine(void *mp) {
    if (mp) FreeMachine((struct Machine *)mp);
}
