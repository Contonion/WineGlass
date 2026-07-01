# Real-Threads Rearchitecture (Steam reactor reliability)

## Why
Every Steam reliability failure (manifest "fails early", `WaitForSingleObject(0x207)`
deadlock, "Illegal termination of worker thread") traces to **one** thing: we
emulate Steam's preemptive worker threads on a single **cooperative** scheduler
(`wg_threading.c`). Steam's async reactor assumes real, concurrently-scheduled
threads coordinating via events/CVs; our approximation breaks a new way each run.

Fix: stop emulating threads. Map each guest `CreateThread`/`_beginthreadex` to a
**real pthread** running its own blink `Machine` over the **shared** `System`
(guest memory). iOS schedules them preemptively, so Steam's event/CV coordination
"just works." We become a pure Win32 translation layer, not a thread scheduler.

## Feasibility — CONFIRMED
- blink's `System` already has full SMP support: `machines` list, `machines_lock`,
  `exec_lock`, `pagelocks_lock`, `mmap_lock`, `sig_lock`; `g_machine` is
  `_Thread_local`. `NewMachine(System*, parent Machine*)` is the thread primitive.
- It was only switched off by `#define DISABLE_THREADS` in blink `config.h.ios`
  (stubs pthread types/locks to no-ops; only 4 files reference it). We don't use
  blink's `clone()` (Windows PEs don't), so enabling threads mainly makes the
  System locks real.

## Phases
- [x] **P1 — Enable blink threads (de-risk).** Comment out `DISABLE_THREADS` in
      `~/Developer/blink/config.h.ios`, rebuild `blink_macos.a`. Verified: harness
      compiles, single-Machine cooperative path still works (Steam loads, manifest
      downloads, no crash). *iOS: blink.a must be rebuilt the same way (see below).*
- [x] **P2a — g_machine routing (bridge).** DONE (0db5914). All per-thread
      accessors route through `cur_m()` = `g_machine` (fallback `vm->m`); seed
      `g_machine=vm->m` at create. No-op single-threaded (manifest 3/3, no
      regression). The halt/abort longjmp mechanism is already `_Thread_local`.
- [x] **P2b — per-thread Machine primitives (bridge).** DONE (2c1bc05).
      `wg_blink_new_thread_machine` (NewMachine over shared System + restore decode
      mode), `wg_blink_adopt_machine` (set g_machine + m->thread on the worker),
      `wg_blink_free_thread_machine`. Additive, compiles, no caller yet.
- [ ] **P2c — engine worker-pthread entry + wiring (INTERLOCKED with P4).**
      A `wg_worker_thread_entry` in wg_engine.c: adopt Machine, seed
      regs/esp/param/retaddr=0/fs_base, run its own `wg_blink_run` loop, call
      `handle_blink_thunk` on HLT, on rip==0 exit → signal joiners + free Machine.
      Wire CreateThread/_beginthreadex to spawn it. **Gate behind `s_use_real_threads`
      (default OFF)** so the cooperative path stays default until proven.
      *Cannot run standalone:* `handle_blink_thunk`'s `wg_sched_yield` calls
      (WFSO/Sleep/select/CV) assume cooperative scheduling — with real threads they
      must block the real pthread. So P2c ships together with P4.
- [ ] **P3 — Thread-safe Win32 layer.** `handle_blink_thunk` + all shared tables
      (files, sockets `wg_winsock`, handle tables, GlobalAlloc/guest heap bump
      allocator, event/CV tables) get locks. Guest heap allocator especially
      (currently a lockless bump pointer).
- [ ] **P4 — Real synchronization (ships with P2c).** New `wg_sync` module: a
      handle-keyed table of pthread-backed Win32 objects — EVENT (mutex+cond+manual/
      signalled), MUTEX (recursive owner+count), SEMAPHORE (count+cond), THREAD
      (exited+exitcode+cond for join). Real ops: WFSO/WFMO = lock+cond_wait (or
      cond_timedwait for finite timeout); SetEvent = set+broadcast(manual)/
      signal(auto); Sleep = real usleep; EnterCriticalSection = recursive pthread
      mutex; CVs = real pthread_cond. In `s_use_real_threads` mode the WFSO/Sleep/
      select/CV thunk handlers call these instead of `wg_sched_yield`. Plus a global
      thunk mutex around `handle_blink_thunk` so the (large) shared Win32 state +
      wg_engine `s_*` statics stay safe while guest CODE runs concurrently (blink's
      own System locks cover shared memory).
- [ ] **P5 — Retire `wg_threading.c`** (cooperative scheduler) and the
      device-gated crutches: `s_backstop_enabled`, `s_real_timeouts`, the
      select-timeout, the CV emulation, the Sleep-spin watchdog.
- [ ] **P6 — iOS bring-up.** Rebuild iOS `blink.a` without `DISABLE_THREADS`;
      resolve pthread/JIT entitlement + `_Thread_local` on iOS; on-device test.

## Build note (both platforms)
blink must be rebuilt **without** `DISABLE_THREADS`:
- macOS harness: `Tests/build_mac.sh` (delete `/tmp/wineglass_mac/blink_macos.a` to
  force a rebuild after editing `config.h.ios`).
- iOS: rebuild `Vendor/blink/lib/blink.a` from the same `config.h.ios`.

## ✅ P2c/P4 UPDATE (bring-up milestone): real threads RUN
The blink-threading blocker below is **RESOLVED** by option (A): keep blink built
with `DISABLE_THREADS` (fast, no lock deadlock, no init hang) and track the
current thread's Machine in the bridge's OWN real TLS via `__thread wg_tls_m`
(blink's macro only rewrites `_Thread_local`, not `__thread`; blink's interpreter
hot path uses the passed `m`, not `g_machine` — verified memory.c has 0 reads).
Commit 6328f9a. Now: a real worker pthread spawns + runs its own Machine, the
MAIN thread is NOT clobbered (no crash, no fault), and the cooperative shipping
path is unregressed (202k lines, 5 handshakes).

**MILESTONE (76f0607): real threads run Steam's reactor to the manifest download.**
Three fixes cleared the startup coordination stall:
1. **Worker thunk dispatch** — the worker loop only handled WG_BLINK_ERROR, but a
   HLT thunk returns WG_BLINK_HALT, so every Win32 call from a worker spun forever
   on its HLT at 0xC000xx. Now handles BOTH (like the main tick). THE core fix.
2. **GetMessageW real-threads branch** — main is a real pthread (driven by
   wg_engine_tick); don't cooperative-yield/PAUSE (froze it). Deliver msg/WM_TIMER,
   return, brief sleep.
3. **Skip armed HLT diag traps** (0x6BB882 etc.) in real-threads mode — only the
   main tick handles them; a worker hitting one took an unhandled halt. Functional
   TLS config-string/cert/manifest patch still runs (s_tls_setup_done once-guard).
Result: no crash/deadlock/fault; Steam spawns its full 4-thread pool, reaches
"Downloading manifest" -> connect -> send request -> finished -> retry.
**Manifest not yet CONFIRMED downloaded** under real threads: rapid testing hit
Fastly CDN 429/403 rate-limiting (needs cooldown, or verify on device). The retry
loop + "http error 0" is the same pre-existing GET-queue race as cooperative.

**Done earlier:** CVs + SRW locks wired to wg_sync (4a31ffb); tid logging fixed;
wg_sync CV type added. Corrected earlier misread: the pool worker does NOT exit
early — "exited code=0" was just the time-limit shutdown breaking its loop.

**Current stall (real target):** Steam's startup coordination cycle under real
threads. Sequence: main reaches set_cipher_list, spawns pool worker 0x53CEE0
(handle 0x90028), then CloseHandles it (normal) and sits in the GetMessageW pump
cycling WM_TIMER (0x113); the worker blocks waiting for work. tier0 logs
threadtools.cpp:3972 "Probably deadlock or failure". Neither advances to
"Downloading manifest". Hypothesis: a main<->worker cycle that the cooperative
scheduler happened to break by interleaving, but real preemptive threads
genuinely deadlock — main waits for a message the worker should post; worker
waits for work main should queue. NEXT: trace what 0x53CEE0 blocks on (its
WFSO/CV handle) and who is supposed to signal it; check the thread-message queue
(PostThreadMessageW/GetMessageW) delivery between real threads; check GetMessageW
real-threads behaviour (should block on a real event, not cooperative-yield).
**Remaining P2c also:** worker abort-recovery + first-run warm-up parity
(defensive); then manifest/packages end-to-end + reliability measurement.

## ⚠ (RESOLVED — see above) BLOCKER (found during P2c bring-up): blink threading model vs our manual stepping
P2c/P4 are fully coded + gated behind `s_use_real_threads` (default OFF). First
real-threads run got a real worker pthread spawned + running, then crashed — and
bring-up exposed a blink-internals wall. Three blink configs, none clean:

1. **`DISABLE_THREADS` (original / current, shipping):** `thread.h` `#define`s
   `_Thread_local` to *nothing* → `g_machine` is a **shared global**. Cooperative
   works, but a worker's `adopt_machine` clobbers the main thread's Machine →
   main's RIP goes wild → SIGSEGV in int3 padding (observed at 0x53648b). So real
   threads are impossible here.
2. **Threads fully ON (`HAVE_THREADS`, config.h.ios DISABLE_THREADS off):**
   `_Thread_local` real (good) BUT the SMP `LOCK()`s (pagelocks per memory access,
   exec_lock) are real and **DEADLOCK our manual per-instruction
   LoadInstruction/ExecuteInstruction stepping** — Steam hangs at ~CRT init
   (VirtualAlloc 0xFFEEFFEE / WakeAllConditionVariable), never progresses. blink's
   locks assume blink's own Actor/run loop manages them; we bypass it.
3. **Hybrid (edit thread.h: keep `_Thread_local` real but `LOCK`=no-op):** blink
   **hangs at init**, right after "VM created", before executing sections. Cause
   not yet diagnosed (possibly a g_machine def/decl mismatch across TUs, or blink
   touching g_machine before TLS is ready). Reverted.

**Core need:** per-thread current-Machine WITHOUT blink's SMP lock deadlock.
**Next-session options (in promise order):**
- **(A) Own TLS in the bridge (most promising).** Keep `DISABLE_THREADS`
  (fast, no deadlock). In `wg_blink_impl.c` use OUR OWN `static _Thread_local
  struct Machine *wg_tls_machine` for `cur_m()`/`AdoptMachine` instead of blink's
  `g_machine`. *Precondition to verify first:* does blink's interpreter path
  (ExecuteInstruction, memory ops, fault handling) read the global `g_machine`
  internally, or only the `m` we pass? If only `m`, (A) works cleanly. If it
  reads g_machine, workers would hit the wrong Machine → (A) fails. Grep blink
  for `g_machine` uses in the hot path to decide.
- **(B) Diagnose the config-3 init hang** (lldb: where it stalls after VM create
  with `_Thread_local` real + locks off). If fixable, gives per-thread g_machine
  + no deadlock.
- **(C) Make blink's SMP locks compatible** with manual stepping (understand the
  pagelock lifecycle; release between steps). Deepest.

Build note: `build_mac.sh` now always syncs `config.h` from `config.h.ios` and
force-rebuilds blink on change (a stale config.h silently kept threads off,
masking all of this during P1's "verified" step — P1 never actually had threads).

## Risks / open questions
- blink SMP correctness in **interpreter** mode on iOS (no JIT) — untested at scale.
- `_Thread_local` availability/behavior on iOS.
- Thoroughness of locking the Win32 layer — lots of shared mutable state.
- Keep the current native package fetch (it stays; orthogonal win).
