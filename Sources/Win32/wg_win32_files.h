#ifndef WG_WIN32_FILES_H
#define WG_WIN32_FILES_H

#include <stdint.h>
#include <stdbool.h>

#define WG_MAX_FILE_HANDLES 64
#define WG_FILE_HANDLE_BASE 0x100

// Set the real filesystem path for the loaded .exe
void wg_files_set_exe_path(const char *path);

// The Windows-style path to the loaded exe (e.g. "C:\Program Files\Steam\steam.exe").
const char *wg_files_exe_win_path(void);

// The bottle's C: drive (a persistent prefix dir, like a Wine/CrossOver bottle).
// All guest C:\ paths map under here. Returns the real drive_c path (or "").
const char *wg_files_drive_c(void);

// Remove stale NSIS plug-in temp dirs (ns*.tmp) from the bottle's Temp so each
// run gets a fresh plug-ins directory.
void wg_files_reset_temp(void);

// Recursively create all parent directories of a real (already-mapped) path.
void wg_files_ensure_parents(const char *real_path);

// Map a Windows-style path to a real iOS filesystem path
const char *wg_files_map_path(uint32_t guest_path_addr, void *blink,
                               char *buf, int bufsize);

// File handle management
uint32_t wg_files_create(const char *real_path, uint32_t access, uint32_t creation);
bool     wg_files_read(uint32_t handle, void *buf, uint32_t bytes, uint32_t *bytes_read);
bool     wg_files_write(uint32_t handle, const void *buf, uint32_t bytes, uint32_t *bytes_written);
uint32_t wg_files_get_size(uint32_t handle);
uint32_t wg_files_set_pointer(uint32_t handle, int32_t distance, uint32_t method);
bool     wg_files_close(uint32_t handle);

void wg_files_prepopulate_nsis_data(const char *exe_path, const char *tmp_path);

// Create a null handle that silently discards writes
uint32_t wg_files_create_null(void);

#endif
