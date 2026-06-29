#include "wg_threading.h"
#include "wg_blink_bridge.h"
#include "wg_log.h"
#include <stdlib.h>
#include <string.h>

#define TAG "Thread"

WGThreadScheduler *wg_sched_create(void) {
    WGThreadScheduler *s = calloc(1, sizeof(WGThreadScheduler));
    if (!s) return NULL;
    s->current = -1;
    s->next_id = 0x1000;
    s->next_handle = 0x7100;
    s->next_stack_addr = 0x30000000u;
    return s;
}

void wg_sched_destroy(WGThreadScheduler *sched) {
    free(sched);
}

static void save_regs(WGThreadRegs *regs, void *blink) {
    for (int i = 0; i < 8; i++)
        regs->gpr[i] = (uint32_t)wg_blink_get_reg(blink, i);
    regs->rip = (uint32_t)wg_blink_get_rip(blink);
}

static void restore_regs(const WGThreadRegs *regs, void *blink) {
    for (int i = 0; i < 8; i++)
        wg_blink_set_reg(blink, i, regs->gpr[i]);
    wg_blink_set_rip(blink, regs->rip);
    wg_blink_set_fs_base(blink, regs->fs_base);
}

uint32_t wg_sched_create_thread(WGThreadScheduler *sched, void *blink,
                                 uint32_t start_addr, uint32_t param,
                                 uint32_t flags, uint32_t *out_tid) {
    // Find a free slot
    int slot = -1;
    for (int i = 0; i < WG_MAX_THREADS; i++) {
        if (sched->threads[i].state == WG_THREAD_FREE) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        WG_LOGE(TAG, "No free thread slots");
        return 0;
    }

    WGThread *t = &sched->threads[slot];
    memset(t, 0, sizeof(*t));
    t->id = sched->next_id++;
    t->handle = sched->next_handle++;
    t->start_addr = start_addr;
    t->param = param;
    t->exit_code = 259; // STILL_ACTIVE

    // Allocate guest stack (1MB, grows downward)
    t->stack_base = sched->next_stack_addr;
    t->stack_size = WG_THREAD_STACK;
    sched->next_stack_addr += WG_THREAD_STACK + 0x1000; // guard page gap

    // Map the stack in blink (zeroed)
    uint8_t *zstack = calloc(1, t->stack_size);
    if (zstack) {
        wg_blink_load_code(blink, t->stack_base, zstack, t->stack_size, 0);
        free(zstack);
    }

    // Set up initial register state:
    // ESP = top of stack minus space for return address + arg
    uint32_t sp = t->stack_base + t->stack_size - 0x100;
    // Push the thread parameter and a fake return address (ExitThread)
    // Stack layout: [ret_addr=0] [param]
    // The thread function is __stdcall: DWORD WINAPI ThreadProc(LPVOID)
    uint32_t ret_sentinel = 0; // will cause HLT/exit when thread returns
    wg_blink_write_mem(blink, sp, &ret_sentinel, 4);
    wg_blink_write_mem(blink, sp + 4, &param, 4);

    t->regs.gpr[0] = 0;         // EAX
    t->regs.gpr[1] = 0;         // ECX
    t->regs.gpr[2] = 0;         // EDX
    t->regs.gpr[3] = 0;         // EBX
    t->regs.gpr[4] = sp;        // ESP
    t->regs.gpr[5] = sp;        // EBP
    t->regs.gpr[6] = 0;         // ESI
    t->regs.gpr[7] = 0;         // EDI
    t->regs.rip = start_addr;

    // TEB — reuse the main thread's TEB for now (same FS base)
    // TODO: allocate per-thread TEB with unique ThreadId
    WGThread *main_t = (sched->current >= 0) ? &sched->threads[sched->current] : NULL;
    t->regs.fs_base = main_t ? main_t->regs.fs_base : 0;
    t->teb = t->regs.fs_base;

    if (flags & 0x4) { // CREATE_SUSPENDED
        t->state = WG_THREAD_SUSPENDED;
    } else {
        t->state = WG_THREAD_READY;
    }

    if (out_tid) *out_tid = t->id;
    sched->count++;

    WG_LOGI(TAG, "CreateThread: slot=%d id=0x%X handle=0x%X start=0x%X param=0x%X stack=0x%X-0x%X %s",
            slot, t->id, t->handle, start_addr, param,
            t->stack_base, t->stack_base + t->stack_size,
            (flags & 0x4) ? "(suspended)" : "(ready)");

    return t->handle;
}

void wg_sched_save_current(WGThreadScheduler *sched, void *blink,
                            WGThreadState new_state) {
    if (sched->current < 0) return;
    WGThread *t = &sched->threads[sched->current];
    save_regs(&t->regs, blink);
    t->state = new_state;
}

bool wg_sched_switch_next(WGThreadScheduler *sched, void *blink) {
    int start = (sched->current >= 0) ? sched->current + 1 : 0;

    for (int i = 0; i < WG_MAX_THREADS; i++) {
        int idx = (start + i) % WG_MAX_THREADS;
        WGThread *t = &sched->threads[idx];
        if (t->state == WG_THREAD_READY) {
            int prev = sched->current;
            sched->current = idx;
            t->state = WG_THREAD_RUNNING;
            restore_regs(&t->regs, blink);
            // Only log real context switches, not self-reswitches in a spin loop.
            if (prev != idx)
                WG_LOGD(TAG, "Switched to thread %d (id=0x%X, rip=0x%X)",
                        idx, t->id, t->regs.rip);
            return true;
        }
    }
    return false;
}

bool wg_sched_yield(WGThreadScheduler *sched, void *blink,
                     WGThreadState block_reason) {
    wg_sched_save_current(sched, blink, block_reason);
    if (wg_sched_switch_next(sched, blink)) {
        return true;
    }
    // No other threads — restore the current one
    if (sched->current >= 0) {
        WGThread *t = &sched->threads[sched->current];
        t->state = WG_THREAD_RUNNING;
        restore_regs(&t->regs, blink);
    }
    return false;
}

void wg_sched_wake(WGThreadScheduler *sched, uint32_t handle) {
    for (int i = 0; i < WG_MAX_THREADS; i++) {
        WGThread *t = &sched->threads[i];
        if (t->state == WG_THREAD_WAITING && t->wait_handle == handle) {
            t->state = WG_THREAD_READY;
            t->wait_handle = 0;
            WG_LOGD(TAG, "Woke thread %d (id=0x%X) waiting on handle 0x%X",
                    i, t->id, handle);
        }
    }
}

void wg_sched_exit_thread(WGThreadScheduler *sched, void *blink,
                           uint32_t exit_code) {
    if (sched->current < 0) return;
    WGThread *t = &sched->threads[sched->current];
    t->state = WG_THREAD_EXITED;
    t->exit_code = exit_code;
    WG_LOGI(TAG, "Thread %d (id=0x%X) exited with code %u",
            sched->current, t->id, exit_code);

    // Switch to another thread
    sched->current = -1;
    wg_sched_switch_next(sched, blink);
}

WGThread *wg_sched_find(WGThreadScheduler *sched, uint32_t handle) {
    for (int i = 0; i < WG_MAX_THREADS; i++) {
        if (sched->threads[i].handle == handle &&
            sched->threads[i].state != WG_THREAD_FREE)
            return &sched->threads[i];
    }
    return NULL;
}

WGThread *wg_sched_current(WGThreadScheduler *sched) {
    if (sched->current < 0) return NULL;
    return &sched->threads[sched->current];
}

uint32_t wg_sched_current_tid(WGThreadScheduler *sched) {
    if (sched->current < 0) return 0;
    return sched->threads[sched->current].id;
}
