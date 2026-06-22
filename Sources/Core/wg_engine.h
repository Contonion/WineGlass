#ifndef WG_ENGINE_H
#define WG_ENGINE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct WGEngine WGEngine;

WGEngine *wg_engine_create(void);
void      wg_engine_destroy(WGEngine *engine);

bool wg_engine_init(WGEngine *engine);
bool wg_engine_load_pe(WGEngine *engine, const char *path);
bool wg_engine_load_pe_memory(WGEngine *engine, const uint8_t *data, size_t size);
bool wg_engine_run(WGEngine *engine);
void wg_engine_tick(WGEngine *engine);
void wg_engine_stop(WGEngine *engine);

typedef enum {
    WG_ENGINE_IDLE,
    WG_ENGINE_LOADED,
    WG_ENGINE_RUNNING,
    WG_ENGINE_PAUSED,    // paused on DialogBoxParamW — waiting for user
    WG_ENGINE_STOPPED,
    WG_ENGINE_ERROR
} WGEngineState;

// Resume from PAUSED state (e.g., after dialog dismissed)
void wg_engine_resume(WGEngine *engine);

// Modal-dialog input. wg_engine_dialog_active() is true while a wizard dialog
// is up and waiting; wg_engine_dialog_command() delivers a button click
// (1=Next/Install, 2=Cancel, 3=Back) so the wizard advances.
bool wg_engine_dialog_active(WGEngine *engine);
void wg_engine_dialog_command(WGEngine *engine, uint32_t ctrl_id);

WGEngineState wg_engine_get_state(const WGEngine *engine);
WGEngineState wg_engine_run_sync(WGEngine *engine, int max_ticks);

#endif
