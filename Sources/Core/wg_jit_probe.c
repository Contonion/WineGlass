// wg_jit_probe.c — standalone MAP_JIT capability probe for iOS/macOS.
//
// Answers ONE question definitively, isolated from all of blink's complexity:
// does THIS device + OS permit executing JIT-compiled code right now?
//
// The Apple-sanctioned JIT path is mmap(MAP_JIT) + pthread_jit_write_protect_np
// (the W^X toggle) + sys_icache_invalidate. On iOS this is permitted for a
// get-task-allow app *while a debugger is attached* — i.e. when Run from Xcode.
// (iOS 26/27 tightened writable-executable memory, so this is exactly the thing
// worth measuring on-device rather than assuming.)
//
// This file deliberately includes ONLY clean system headers (no blink headers,
// which shadow libc), so it compiles as a normal translation unit.

#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>  // sys_icache_invalidate

#ifndef MAP_JIT
#define MAP_JIT 0x0800
#endif

static sigjmp_buf s_probe_jmp;
static void wg_probe_sig(int sig) { (void)sig; siglongjmp(s_probe_jmp, 1); }

// Returns 42 if JIT works. Failure codes:
//   -1  mmap(MAP_JIT) was denied (no JIT memory at all)
//   -3  the write+toggle succeeded but EXECUTING the code faulted (W^X denied)
int wg_jit_smoke_test(void) {
    const size_t sz = 16384;  // one 16KB Apple page
    void *mem = mmap(NULL, sz, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_JIT | MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED || !mem) return -1;

    // Minimal ARM64 function:  movz w0, #42  ;  ret   -> returns 42
    const uint32_t code[] = { 0x52800540u, 0xd65f03c0u };

    int wxp = pthread_jit_write_protect_supported_np();
    if (wxp) pthread_jit_write_protect_np(0);   // make MAP_JIT pages writable
    memcpy(mem, code, sizeof(code));
    if (wxp) pthread_jit_write_protect_np(1);   // make them executable again
    sys_icache_invalidate(mem, sizeof(code));

    // Guard the call: if execution is denied, the CPU raises SIGSEGV/SIGBUS and
    // we longjmp back out instead of crashing the app.
    struct sigaction sa, old_segv, old_bus;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = wg_probe_sig;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS,  &sa, &old_bus);

    int result;
    if (sigsetjmp(s_probe_jmp, 1) == 0) {
        int (*fn)(void) = (int (*)(void))mem;
        result = fn();          // <- faults here if execution is not permitted
    } else {
        result = -3;
    }

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus, NULL);
    munmap(mem, sz);
    return result;              // 42 == device permits JIT
}
