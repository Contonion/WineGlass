#ifndef WG_SYNC_H
#define WG_SYNC_H

// Real pthread-backed Win32 synchronization objects for the real-threads mode
// (see docs/threads_rearchitect.md). Each guest thread is a real pthread, so
// WaitForSingleObject must BLOCK the calling pthread on a real condition
// variable until another thread signals it — not cooperatively yield. This
// module is a handle-keyed table of EVENT / MUTEX / SEMAPHORE / THREAD objects
// implemented with a single global mutex + condvar (monitor pattern: any state
// change broadcasts; waiters re-check their predicate). Object counts are small
// (a few dozen threads), so the coarse lock is simple and correct.
//
// Only active when the engine runs in s_use_real_threads mode. Untouched by the
// legacy cooperative scheduler.

#include <stdint.h>
#include <stdbool.h>

#define WG_SYNC_INFINITE   0xFFFFFFFFu

// Wait return codes (match Win32 WAIT_*).
#define WG_WAIT_OBJECT_0   0x00000000u
#define WG_WAIT_ABANDONED  0x00000080u
#define WG_WAIT_TIMEOUT    0x00000102u
#define WG_WAIT_FAILED     0xFFFFFFFFu

void wg_sync_init(void);

// Creation — return a nonzero Win32-style handle, or 0 on failure. Handles are
// allocated from a distinct range (won't collide with file/socket/thread handles).
uint32_t wg_sync_create_event(bool manual_reset, bool initial_signalled);
uint32_t wg_sync_create_mutex(bool initially_owned, uint32_t owner_tid);
uint32_t wg_sync_create_semaphore(long initial_count, long max_count);
uint32_t wg_sync_create_thread_obj(uint32_t tid);  // waitable handle for a guest thread
uint32_t wg_sync_create_cv(void);                  // Win32 CONDITION_VARIABLE

// Condition variables (Win32 SleepConditionVariableCS semantics). cv_sleep
// atomically releases the critical-section mutex `cs_mtx` (held by caller_tid),
// blocks on `cv` until woken (or timeout), then RE-ACQUIRES `cs_mtx` before
// returning (unconditionally, as Windows does). Returns WG_WAIT_OBJECT_0 (woken)
// or WG_WAIT_TIMEOUT. cv_wake wakes one (all=false) or all (all=true) waiters.
uint32_t wg_sync_cv_sleep(uint32_t cv, uint32_t cs_mtx, uint32_t timeout_ms, uint32_t caller_tid);
void     wg_sync_cv_wake(uint32_t cv, bool wake_all);

// Signalling.
bool wg_sync_set_event(uint32_t h);
bool wg_sync_reset_event(uint32_t h);
bool wg_sync_pulse_event(uint32_t h);
bool wg_sync_release_mutex(uint32_t h, uint32_t owner_tid);
bool wg_sync_release_semaphore(uint32_t h, long count, long *prev_count);
// Mark a thread object exited (wakes all joiners). Idempotent.
void wg_sync_thread_exit(uint32_t h, uint32_t exit_code);

// Waiting. timeout_ms == WG_SYNC_INFINITE blocks forever. caller_tid is used for
// mutex ownership/recursion. Returns WG_WAIT_OBJECT_0(+i) / WG_WAIT_TIMEOUT /
// WG_WAIT_ABANDONED / WG_WAIT_FAILED.
uint32_t wg_sync_wait_single(uint32_t h, uint32_t timeout_ms, uint32_t caller_tid);
uint32_t wg_sync_wait_multiple(const uint32_t *handles, int count, bool wait_all,
                               uint32_t timeout_ms, uint32_t caller_tid);

// Introspection / lifecycle.
bool wg_sync_is_known(uint32_t h);        // is h a live wg_sync object?
uint32_t wg_sync_thread_exit_code(uint32_t h);
bool wg_sync_close(uint32_t h);

#endif
