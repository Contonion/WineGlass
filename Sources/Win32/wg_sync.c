// Real pthread-backed Win32 sync objects — see wg_sync.h.
#include "wg_sync.h"

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define WG_SYNC_MAX   256
#define WG_SYNC_BASE  0x00090000u   // distinct from file(0x1xx)/socket(0x1xxx)/thread(0x71xx) handles

enum { WGO_FREE = 0, WGO_EVENT, WGO_MUTEX, WGO_SEM, WGO_THREAD };

typedef struct {
    int      type;
    uint32_t handle;
    // EVENT
    bool     manual;
    bool     signalled;
    // MUTEX
    uint32_t owner_tid;   // 0 = unowned
    int      recursion;
    // SEMAPHORE
    long     count;
    long     max;
    // THREAD
    bool     exited;
    uint32_t exit_code;
} WGSyncObj;

// One global monitor: any state change broadcasts g_cond; waiters re-check their
// predicate. Coarse but simple and correct for our small object/thread counts.
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cond = PTHREAD_COND_INITIALIZER;
static WGSyncObj       g_objs[WG_SYNC_MAX];
static bool            g_inited = false;

void wg_sync_init(void) {
    pthread_mutex_lock(&g_lock);
    if (!g_inited) { memset(g_objs, 0, sizeof(g_objs)); g_inited = true; }
    pthread_mutex_unlock(&g_lock);
}

// Caller must hold g_lock.
static WGSyncObj *alloc_obj_locked(int type) {
    for (int i = 0; i < WG_SYNC_MAX; i++) {
        if (g_objs[i].type == WGO_FREE) {
            WGSyncObj *o = &g_objs[i];
            memset(o, 0, sizeof(*o));
            o->type = type;
            o->handle = WG_SYNC_BASE + (uint32_t)i;
            return o;
        }
    }
    return NULL;
}

// Caller must hold g_lock.
static WGSyncObj *find_locked(uint32_t h) {
    if (h < WG_SYNC_BASE || h >= WG_SYNC_BASE + WG_SYNC_MAX) return NULL;
    WGSyncObj *o = &g_objs[h - WG_SYNC_BASE];
    return (o->type != WGO_FREE && o->handle == h) ? o : NULL;
}

// ── Creation ────────────────────────────────────────────────────────────────

uint32_t wg_sync_create_event(bool manual_reset, bool initial_signalled) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = alloc_obj_locked(WGO_EVENT);
    uint32_t h = 0;
    if (o) { o->manual = manual_reset; o->signalled = initial_signalled; h = o->handle; }
    pthread_mutex_unlock(&g_lock);
    return h;
}

uint32_t wg_sync_create_mutex(bool initially_owned, uint32_t owner_tid) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = alloc_obj_locked(WGO_MUTEX);
    uint32_t h = 0;
    if (o) {
        if (initially_owned) { o->owner_tid = owner_tid; o->recursion = 1; }
        h = o->handle;
    }
    pthread_mutex_unlock(&g_lock);
    return h;
}

uint32_t wg_sync_create_semaphore(long initial_count, long max_count) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = alloc_obj_locked(WGO_SEM);
    uint32_t h = 0;
    if (o) { o->count = initial_count; o->max = max_count; h = o->handle; }
    pthread_mutex_unlock(&g_lock);
    return h;
}

uint32_t wg_sync_create_thread_obj(uint32_t tid) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = alloc_obj_locked(WGO_THREAD);
    uint32_t h = 0;
    if (o) { o->owner_tid = tid; o->exited = false; h = o->handle; }
    pthread_mutex_unlock(&g_lock);
    return h;
}

// ── Signalling ───────────────────────────────────────────────────────────────

bool wg_sync_set_event(uint32_t h) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    bool ok = false;
    if (o && o->type == WGO_EVENT) { o->signalled = true; ok = true; pthread_cond_broadcast(&g_cond); }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

bool wg_sync_reset_event(uint32_t h) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    bool ok = false;
    if (o && o->type == WGO_EVENT) { o->signalled = false; ok = true; }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

bool wg_sync_pulse_event(uint32_t h) {
    // Release waiters momentarily, then reset. With the broadcast-and-recheck
    // model, set+broadcast+reset under the lock wakes everyone currently waiting.
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    bool ok = false;
    if (o && o->type == WGO_EVENT) { o->signalled = true; pthread_cond_broadcast(&g_cond); o->signalled = false; ok = true; }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

bool wg_sync_release_mutex(uint32_t h, uint32_t owner_tid) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    bool ok = false;
    if (o && o->type == WGO_MUTEX && o->owner_tid == owner_tid && o->recursion > 0) {
        if (--o->recursion == 0) { o->owner_tid = 0; pthread_cond_broadcast(&g_cond); }
        ok = true;
    }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

bool wg_sync_release_semaphore(uint32_t h, long count, long *prev_count) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    bool ok = false;
    if (o && o->type == WGO_SEM) {
        if (prev_count) *prev_count = o->count;
        o->count += count;
        if (o->max > 0 && o->count > o->max) o->count = o->max;
        pthread_cond_broadcast(&g_cond);
        ok = true;
    }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

void wg_sync_thread_exit(uint32_t h, uint32_t exit_code) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    if (o && o->type == WGO_THREAD && !o->exited) {
        o->exited = true; o->exit_code = exit_code; pthread_cond_broadcast(&g_cond);
    }
    pthread_mutex_unlock(&g_lock);
}

// ── Waiting ──────────────────────────────────────────────────────────────────

// Caller holds g_lock. Is the object satisfied for caller_tid?
static bool satisfied_locked(const WGSyncObj *o, uint32_t caller_tid) {
    switch (o->type) {
        case WGO_EVENT:  return o->signalled;
        case WGO_MUTEX:  return o->owner_tid == 0 || o->owner_tid == caller_tid;
        case WGO_SEM:    return o->count > 0;
        case WGO_THREAD: return o->exited;
        default:         return false;
    }
}

// Caller holds g_lock. Consume/acquire a satisfied object.
static void acquire_locked(WGSyncObj *o, uint32_t caller_tid) {
    switch (o->type) {
        case WGO_EVENT:  if (!o->manual) o->signalled = false; break;   // auto-reset
        case WGO_MUTEX:  o->owner_tid = caller_tid; o->recursion++;     break;
        case WGO_SEM:    o->count--;                                    break;
        case WGO_THREAD: /* no consume */                              break;
        default: break;
    }
}

static void deadline_from_ms(struct timespec *ts, uint32_t timeout_ms) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec  += timeout_ms / 1000u;
    ts->tv_nsec += (long)(timeout_ms % 1000u) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec += 1; ts->tv_nsec -= 1000000000L; }
}

uint32_t wg_sync_wait_single(uint32_t h, uint32_t timeout_ms, uint32_t caller_tid) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    if (!o) { pthread_mutex_unlock(&g_lock); return WG_WAIT_FAILED; }

    struct timespec ts;
    bool have_deadline = (timeout_ms != WG_SYNC_INFINITE && timeout_ms != 0);
    if (have_deadline) deadline_from_ms(&ts, timeout_ms);

    uint32_t rv;
    for (;;) {
        if (satisfied_locked(o, caller_tid)) { acquire_locked(o, caller_tid); rv = WG_WAIT_OBJECT_0; break; }
        if (timeout_ms == 0) { rv = WG_WAIT_TIMEOUT; break; }
        if (timeout_ms == WG_SYNC_INFINITE) {
            pthread_cond_wait(&g_cond, &g_lock);
        } else {
            int rc = pthread_cond_timedwait(&g_cond, &g_lock, &ts);
            if (rc == ETIMEDOUT) {
                if (satisfied_locked(o, caller_tid)) { acquire_locked(o, caller_tid); rv = WG_WAIT_OBJECT_0; }
                else rv = WG_WAIT_TIMEOUT;
                break;
            }
        }
        // find again in case the slot was closed/reused while we waited
        o = find_locked(h);
        if (!o) { rv = WG_WAIT_FAILED; break; }
    }
    pthread_mutex_unlock(&g_lock);
    return rv;
}

uint32_t wg_sync_wait_multiple(const uint32_t *handles, int count, bool wait_all,
                               uint32_t timeout_ms, uint32_t caller_tid) {
    if (count <= 0 || count > 64 || !handles) return WG_WAIT_FAILED;
    pthread_mutex_lock(&g_lock);

    struct timespec ts;
    bool have_deadline = (timeout_ms != WG_SYNC_INFINITE && timeout_ms != 0);
    if (have_deadline) deadline_from_ms(&ts, timeout_ms);

    uint32_t rv;
    for (;;) {
        // Resolve objects; a missing handle fails the whole wait.
        WGSyncObj *objs[64];
        bool all_ok = true;
        for (int i = 0; i < count; i++) {
            objs[i] = find_locked(handles[i]);
            if (!objs[i]) { all_ok = false; break; }
        }
        if (!all_ok) { rv = WG_WAIT_FAILED; break; }

        if (wait_all) {
            bool every = true;
            for (int i = 0; i < count; i++) if (!satisfied_locked(objs[i], caller_tid)) { every = false; break; }
            if (every) { for (int i = 0; i < count; i++) acquire_locked(objs[i], caller_tid); rv = WG_WAIT_OBJECT_0; break; }
        } else {
            int hit = -1;
            for (int i = 0; i < count; i++) if (satisfied_locked(objs[i], caller_tid)) { hit = i; break; }
            if (hit >= 0) { acquire_locked(objs[hit], caller_tid); rv = WG_WAIT_OBJECT_0 + (uint32_t)hit; break; }
        }

        if (timeout_ms == 0) { rv = WG_WAIT_TIMEOUT; break; }
        if (timeout_ms == WG_SYNC_INFINITE) {
            pthread_cond_wait(&g_cond, &g_lock);
        } else {
            int rc = pthread_cond_timedwait(&g_cond, &g_lock, &ts);
            if (rc == ETIMEDOUT) { rv = WG_WAIT_TIMEOUT; break; }
        }
    }
    pthread_mutex_unlock(&g_lock);
    return rv;
}

// ── Introspection / lifecycle ────────────────────────────────────────────────

bool wg_sync_is_known(uint32_t h) {
    pthread_mutex_lock(&g_lock);
    bool ok = find_locked(h) != NULL;
    pthread_mutex_unlock(&g_lock);
    return ok;
}

uint32_t wg_sync_thread_exit_code(uint32_t h) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    uint32_t code = (o && o->type == WGO_THREAD) ? o->exit_code : 0;
    pthread_mutex_unlock(&g_lock);
    return code;
}

bool wg_sync_close(uint32_t h) {
    pthread_mutex_lock(&g_lock);
    WGSyncObj *o = find_locked(h);
    bool ok = false;
    if (o) { o->type = WGO_FREE; o->handle = 0; pthread_cond_broadcast(&g_cond); ok = true; }
    pthread_mutex_unlock(&g_lock);
    return ok;
}
