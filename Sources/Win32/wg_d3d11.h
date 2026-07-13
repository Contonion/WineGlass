// wg_d3d11.h — D3D11/DXGI -> Metal translation layer for WineGlass.
//
// The guest game calls COM-based Direct3D 11 / DXGI APIs: it gets back interface
// pointers (objects whose first field is a vtable pointer) and invokes methods
// through the vtable. We emulate this by building guest-side COM objects whose
// vtable entries are HLT thunks in a dedicated range; when the guest calls a
// method, the engine traps the thunk, maps it to (interface, method), and
// dispatches here. Native handlers drive a Metal backend (WGMetalBackend on
// device; a null backend in the headless harness).
//
// This is the scaffolding + device/factory bring-up. Resource/draw translation
// grows incrementally on top of it.
#ifndef WG_D3D11_H
#define WG_D3D11_H

#include <stdint.h>
#include <stdbool.h>

// Guest region holding all COM method thunks (HLT-filled). Above the Win32 thunk
// range (0xDEAD0000+0x20000). 0x10000 bytes / 8 = 8192 method slots.
#define WG_COM_THUNK_BASE  0xDEC00000u
#define WG_COM_THUNK_SIZE  0x10000u

struct WGEngine;   // opaque to callers

// Called once from wg_engine_init: reset object/thunk state.
void wg_d3d11_init(void);

// Map the COM thunk region + build interface vtables into guest memory. Called
// per PE load (fresh blink VM) before execution starts. `blink` is the VM.
void wg_d3d11_setup(struct WGEngine *engine);

// True if `addr` is a COM method thunk we own.
bool wg_d3d11_is_thunk(uint64_t addr);

// Dispatch a COM vtable call. `args` are the already-read integer args (x64:
// args[0]=RCX=this, args[1]=RDX, args[2]=R8, args[3]=R9, args[4..]=stack). Sets
// *ret to the method's return value (HRESULT / ULONG / pointer). Returns true if
// handled (always true for a thunk we own).
bool wg_d3d11_dispatch(struct WGEngine *engine, uint64_t thunk_addr,
                       uint32_t *args, uint64_t *ret);

// Win32 entry points (called from the engine's DLL dispatch). Each returns the
// HRESULT to put in the guest's RAX and writes out-params into guest memory.
uint32_t wg_d3d11_CreateDXGIFactory(struct WGEngine *engine, uint32_t *args, bool factory1);
uint32_t wg_d3d11_D3D11CreateDevice(struct WGEngine *engine, uint32_t *args, bool with_swapchain);

#endif
