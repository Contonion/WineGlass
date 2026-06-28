// run_exe.c — Headless macOS harness: load a Windows .exe through the WineGlass
// engine and tick it to completion, printing all logs to stdout. Lets us run &
// diagnose (e.g. Steam) on the Mac directly, with no device round-trip.
//
// Usage: run_exe <path-to.exe> [max_seconds]

#include "wg_log.h"
#include "wg_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.exe> [max_seconds]\n", argv[0]);
        return 2;
    }
    const char *exe = argv[1];
    double max_seconds = (argc >= 3) ? atof(argv[2]) : 30.0;

    wg_log_init();
    WG_LOGI("RUN", "=== WineGlass headless runner ===");
    WG_LOGI("RUN", "exe=%s max_seconds=%.1f", exe, max_seconds);

    WGEngine *engine = wg_engine_create();
    if (!engine || !wg_engine_init(engine)) { WG_LOGE("RUN", "engine init failed"); return 1; }
    if (!wg_engine_load_pe(engine, exe))     { WG_LOGE("RUN", "PE load failed");    return 1; }
    if (!wg_engine_run(engine))              { WG_LOGE("RUN", "engine start failed"); return 1; }

    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    unsigned long long ticks = 0;
    for (;;) {
        wg_engine_tick(engine);
        ticks++;
        WGEngineState st = wg_engine_get_state(engine);
        if (st != WG_ENGINE_RUNNING && st != WG_ENGINE_PAUSED) {
            WG_LOGI("RUN", "engine stopped: state=%d after %llu ticks", st, ticks);
            break;
        }
        if ((ticks & 0x3FF) == 0) {
            struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
            double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
            if (el > max_seconds) { WG_LOGW("RUN", "time limit %.1fs hit (%llu ticks)", max_seconds, ticks); break; }
        }
    }
    WG_LOGI("RUN", "done");
    wg_engine_destroy(engine);
    return 0;
}
