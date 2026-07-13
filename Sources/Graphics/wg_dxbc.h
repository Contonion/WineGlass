// wg_dxbc.h — translate Direct3D shader bytecode (DXBC, Shader Model 4/5) to
// Metal Shading Language (MSL).
//
// DXBC is the container D3D10/11 shaders compile to (via fxc). It holds a chunk
// table; the SHDR/SHEX chunk is the SM4/5 token stream, and ISGN/OSGN describe
// the input/output signatures. This module parses that and emits equivalent MSL
// so a game's own compiled shaders can run on Metal.
//
// Coverage is incremental: the container/signatures and a core instruction set
// first, expanding as real shaders demand.
#ifndef WG_DXBC_H
#define WG_DXBC_H

#include <stdint.h>
#include <stdbool.h>

// Translate a DXBC blob to MSL source. Returns a malloc'd, NUL-terminated MSL
// string (caller frees) or NULL on failure.
//  *out_stage  <- 'v' (vertex) or 'f' (fragment/pixel)
//  entry point is always "wg_vs_main" (vertex) or "wg_ps_main" (fragment).
char *wg_dxbc_to_msl(const void *dxbc, uint32_t size, char *out_stage);

// True if `data` looks like a DXBC container ("DXBC" magic).
bool wg_dxbc_is_dxbc(const void *data, uint32_t size);

#endif
