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
- [ ] **P2 — Machine-per-thread bridge.** `wg_blink_impl.c`: keep System + main
      Machine; add `WGBlinkVM_SpawnThread(entry, arg, stack)` → `NewMachine(s, main)`
      + real pthread that sets `g_machine`, seeds regs/rip/stack/TEB, runs the blink
      loop, and calls back into `handle_blink_thunk` on HLT. Per-Machine reg/mem
      accessors (operate on the calling thread's Machine, not `vm->m`).
- [ ] **P3 — Thread-safe Win32 layer.** `handle_blink_thunk` + all shared tables
      (files, sockets `wg_winsock`, handle tables, GlobalAlloc/guest heap bump
      allocator, event/CV tables) get locks. Guest heap allocator especially
      (currently a lockless bump pointer).
- [ ] **P4 — Real synchronization.** Back Win32 events/CVs/WFSO/CriticalSection
      with real pthread mutex+cond. `WaitForSingleObject` blocks the real thread on
      a real cond; `SetEvent` signals it. This is where the deadlocks vanish.
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

## Risks / open questions
- blink SMP correctness in **interpreter** mode on iOS (no JIT) — untested at scale.
- `_Thread_local` availability/behavior on iOS.
- Thoroughness of locking the Win32 layer — lots of shared mutable state.
- Keep the current native package fetch (it stays; orthogonal win).
