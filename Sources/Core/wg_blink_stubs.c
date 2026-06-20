// Overrides for blink symbols needed in library mode.

#include <stdio.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// TerminateSignal is called when blink wants to kill the emulated process.
// In standalone blink, this calls exit(). In library mode, we longjmp back
// to the execution context (m->onhalt) so the caller sees it as a halt.

// We need access to the machine's onhalt jmp_buf. Since we can't include
// blink's headers here (they shadow system headers), we access it through
// a known struct offset. The onhalt field is a sigjmp_buf inside Machine.

// Forward declaration of Machine - we just need the onhalt field
struct Machine;

// From blink's machine.h: onhalt is at a specific offset.
// We get it by having our bridge store a pointer for us.
static _Thread_local sigjmp_buf *s_current_onhalt = NULL;

void wg_blink_set_onhalt(sigjmp_buf *buf) {
    s_current_onhalt = buf;
}

void TerminateSignal(struct Machine *m, int sig, int code) {
    // Signal 4 (SIGILL from HLT) is normal — it's how thunks work.
    // Only log unexpected signals.
    if (sig != 4 && sig != 11) {
        fprintf(stderr, "[WineGlass] Signal %d (code %d) — halting emulated process\n", sig, code);
    }
    // Try to longjmp back to the execution context
    if (s_current_onhalt) {
        siglongjmp(*s_current_onhalt, -1); // -1 = kMachineHalt
    }
}

// Override blink's Abort() — longjmp to recovery instead of abort()
static _Thread_local sigjmp_buf *s_abort_recovery = NULL;
static _Thread_local bool s_abort_recovery_active = false;

void wg_blink_set_abort_recovery(sigjmp_buf *buf) {
    s_abort_recovery = buf;
    s_abort_recovery_active = (buf != NULL);
}

void Abort(void) {
    fprintf(stderr, "[WineGlass] Blink Abort() called\n");
    if (s_abort_recovery_active && s_abort_recovery) {
        s_abort_recovery_active = false;
        siglongjmp(*s_abort_recovery, 99);
    }
    fprintf(stderr, "[WineGlass] Abort() with no recovery — returning\n");
}
