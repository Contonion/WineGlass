# WineGlass Threading Redesign — the path to a rendered Visage frame

## The one blocker (proven this session)
Visage boots to **14M thunk-calls** (into UE4's main tick loop) then deadlocks in
UE4's **parallel config-parse coordination** (driver `0x14AA9F4`, factory
`0x9199d0`). Root cause, confirmed by instruction-level tracing:

> Our GIL (`s_thunk_lock`) serializes guest execution but **hands off only at
> thunk boundaries** — specifically when a thread does a blocking Win32 call
> (`WaitForSingleObject`/`Sleep`/CV wait) and calls `wg_thunk_block_begin()`.
> UE4's config-parse driver yields there **mid-way through building a config
> object**; another guest thread then runs and observes/writes the half-built
> object → the driver's dispatch-decision branch reads corrupt state → it skips
> `SetEvent(work)` → the worker parks forever → deadlock. The stall point varies
> per run (2.25M–14M) because it's a timing race.

### What is already proven NOT to fix it (don't repeat)
- `WaitOnAddress`/`WakeByAddress` real impl + worker-timeout cap — **help** (2.5M→14M) but don't fix the final deadlock.
- SetEvent-yields-GIL, all deadlock-kick variants, `WG_IPT` small AND huge, `-onethread`, long patience, and a **fair (FIFO) GIL** — all reach the same deadlock. Fairness is not enough; it's a *logic-level* corruption, not starvation or ordering.

## The fix: cooperative-but-Windows-faithful scheduling
The GIL model is fine (blink isn't thread-safe, so one guest thread at a time is
required). The bug is *where* it yields. Two viable designs, in order of effort:

### Option A — "atomic critical regions" (smaller, targeted)
Prevent a yield from splitting an operation that another thread reads racily.
1. Add a per-Machine `no_yield_depth` counter. While >0, `wg_thunk_block_begin`
   must NOT release the GIL (defer the block) — the thread runs to the end of the
   region first.
2. Raise it around the config-object build. Since we can't edit guest code, gate
   it on the guest RIP range of the factory/driver (`0x9199d0`..factory-end and
   the `0x14AA` build sites) via a check in `wg_blink` step or a HLT-trap at
   entry/exit — set `no_yield_depth++` on entry, `--` on the matching return.
3. Problem to solve: the region contains a *genuine* `WaitForSingleObject` for a
   helper thread. Deferring that block would deadlock. So A only works if the
   racy window is the part BEFORE that wait. Verify with the sync-trace
   (`WG_SYNCTRACE`) whether the corruption is pre- or post-wait. If pre-wait,
   defer yields only until the wait; this is the minimal fix.

### Option B — directed handoff (larger, general, the real fix)
Make the GIL hand off to the *specific* thread a waiter depends on, so parallel
config workers can't interleave into the build.
1. Replace the pthread-mutex GIL with the **fair ticket GIL already implemented**
   (`WG_FAIR_GIL`, `wg_engine.c`) as the base — it's correct, just not sufficient alone.
2. Track a **wait→signaler edge**: when a thread `WaitForSingleObject(h)`, record
   `waiter=tid` on object `h`. When any thread `SetEvent(h)`/`ResumeThread(t)`,
   that thread is the "producer" for the waiter. (The sync-op ring `WG_SYNCTRACE`
   already captures exactly these edges — promote it from diagnostic to live state.)
3. On `wg_thunk_block_begin`, instead of releasing to the FIFO queue, **grant the
   next ticket to the producer thread** if one is known (directed handoff), else
   fall back to FIFO. This reproduces Windows' "SetEvent switches to the waiter"
   and prevents unrelated workers from running mid-build.
4. Recursion + block/restore already handled by the fair-lock skeleton.

### Option C — accept the interp is single-writer during config-parse
UE4's parallel config-parse is an optimization. If we make **`CreateThread` for
config-parse helper threads run synchronously (inline to completion on the
creating thread)** — detected by proc-address range, NOT the persistent task-pool
workers (entry `0x9EA6B0`, which loop forever and must stay async) — there is no
parallel writer, so no corruption. Risk: a helper that itself waits on the main
would deadlock; verify helpers are self-contained (memory says `0x9ffc70` is a
one-shot — likely safe). This is the highest-odds *pragmatic* path to a first
frame, even if slower.

## Recommended sequence
1. **Option C first** (highest odds, least invasive): gate inline execution of
   config-parse helper threads behind `WG_SYNC_CONFIG_THREADS`; run the interp
   patience test — if config-parse completes single-threaded, the main loop's
   time+condition gate satisfies and it proceeds toward first Present.
2. If C's helpers aren't self-contained, do **Option A** (defer yields in the
   build region up to the genuine wait).
3. If neither, **Option B** (directed handoff) is the general, correct fix.

## Diagnostics already in the tree (all env-gated OFF by default)
`WG_SYNCTRACE` (sync-op ring), `WG_DEADLOCK_DUMP`/`_KICK`/`_KICKALL`/`_KICKMANUAL`
(watchdog + live-wait dump + breakers), `WG_SETEVENT_YIELD`, `WG_FAIR_GIL`,
`WG_WAITCAP`/`_INF`, `WG_HB` (thunk heartbeat), and blink `WG_JITTRACE`/`WG_JITREGS`
(now thread-tagged with `m=`). These produced the surgical diagnosis and remain
for whoever implements the above.
