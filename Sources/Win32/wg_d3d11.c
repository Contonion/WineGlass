// wg_d3d11.c — D3D11/DXGI COM emulation dispatched onto a Metal backend.
// See wg_d3d11.h for the architecture overview.
#include "wg_d3d11.h"
#include "wg_gpu_backend.h"
#include "wg_engine.h"
#include "wg_blink_bridge.h"
#include "wg_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "D3D11"

// ---- HRESULTs ----
#define S_OK_          0x00000000u
#define E_NOINTERFACE  0x80004002u
#define E_FAIL         0x80004005u
#define E_INVALIDARG   0x80070057u
#define DXGI_ERROR_NOT_FOUND 0x887A0002u

// ---- Interfaces we model. Order-sensitive vtables are built from method counts;
//      handlers switch on (iface, method index). ----
enum {
    IF_DXGIFACTORY = 0,   // IDXGIFactory1
    IF_DXGIADAPTER,       // IDXGIAdapter1
    IF_DXGIOUTPUT,        // IDXGIOutput
    IF_DXGISWAPCHAIN,     // IDXGISwapChain
    IF_D3D11DEVICE,       // ID3D11Device
    IF_D3D11CONTEXT,      // ID3D11DeviceContext
    IF_D3D11CHILD,        // generic ID3D11DeviceChild-derived (buffers/textures/views/shaders/states)
    IF_DXGIDEVICE,        // IDXGIDevice (via ID3D11Device QueryInterface); RHI walks dev->adapter->factory
    IF_COUNT
};

// Number of vtable entries per interface (must match the real header layout for
// the interfaces whose non-IUnknown methods the game actually calls by index).
static const int kMethodCount[IF_COUNT] = {
    [IF_DXGIFACTORY]   = 14,   // IUnknown(3)+IDXGIObject(4)+IDXGIFactory(5)+IDXGIFactory1(2)
    [IF_DXGIADAPTER]   = 11,   // +IDXGIAdapter(3)+IDXGIAdapter1(1)
    [IF_DXGIOUTPUT]    = 19,   // +IDXGIOutput(12)
    [IF_DXGISWAPCHAIN] = 18,   // +IDXGIDeviceSubObject(1)+IDXGISwapChain(10)
    [IF_D3D11DEVICE]   = 43,   // IUnknown(3)+40
    [IF_D3D11CONTEXT]  = 108,  // IUnknown(3)+ID3D11DeviceChild(4)+101
    [IF_D3D11CHILD]    = 16,   // IUnknown(3)+GetDevice+3 private + slack
    [IF_DXGIDEVICE]    = 12,   // IUnknown(3)+IDXGIObject(4)+IDXGIDevice(5: GetAdapter..GetGPUThreadPriority)
};

// ---- Native object table ----
typedef struct {
    bool     in_use;
    int      iface;
    uint32_t guest;      // guest object address
    uint32_t refcount;
    void    *backend;    // WGGpuDevice / WGGpuSwapchain / WGGpuResource / WGGpuView
    bool     owns_backend; // free `backend` on final Release? Only unique resource
                           // wrappers own theirs; QI aliases / GetParent share the
                           // device backend, so freeing on Release double-frees.
    uint32_t aux;        // interface-specific scratch (adapter index, etc.)
    uint8_t  desc_len;   // bytes of `desc` GetDesc should echo (0 = none)
    uint32_t desc[11];   // cached D3D11_BUFFER_DESC (24B) or D3D11_TEXTURE2D_DESC (44B)
    uint32_t map_scratch; // guest scratch buffer backing ID3D11DeviceContext::Map
    uint32_t map_size;    // size of map_scratch
    uint32_t parent;      // for a VIEW (SRV/RTV/DSV/UAV): the source ID3D11Resource
                          // COM handle, returned by ID3D11View::GetResource (method 7).
                          // 0 for a resource/state/shader (method 7 = GetType there).
} WGComObj;

#define WG_MAX_COM 4096
static WGComObj s_objs[WG_MAX_COM];
static int      s_obj_count;

static uint32_t s_vtable[IF_COUNT];       // guest addr of each interface's vtable
static bool     s_setup_done;
static int      s_thunk_slot_iface[WG_COM_THUNK_SIZE / 8]; // slot -> iface
static int      s_thunk_slot_method[WG_COM_THUNK_SIZE / 8];// slot -> method index
static int      s_next_slot;

static void *B(struct WGEngine *e) { return wg_engine_blink(e); }

void wg_d3d11_init(void) {
    memset(s_objs, 0, sizeof(s_objs));
    s_obj_count = 0;
    memset(s_vtable, 0, sizeof(s_vtable));
    s_setup_done = false;
    s_next_slot = 0;
}

// Build all interface vtables into guest memory: HLT-fill the thunk region, then
// for each interface allocate a vtable array whose entry i is the thunk address
// for that (iface, method). Recorded so dispatch can reverse the mapping.
void wg_d3d11_setup(struct WGEngine *engine) {
    if (s_setup_done) return;
    void *bl = B(engine);
    if (!bl) return;

    // Only byte 0 of each 8-byte slot is the HLT trap; fill the padding bytes
    // with a distinct marker so a stray guest read of a thunk address as data is
    // identifiable (was all-0xF4, indistinguishable from other HLT regions).
    uint8_t *page = calloc(1, WG_COM_THUNK_SIZE);
    if (!page) return;
    memset(page, 0xCC, WG_COM_THUNK_SIZE);                       // int3 padding marker
    for (uint32_t i = 0; i < WG_COM_THUNK_SIZE; i += 8) page[i] = 0xF4;  // HLT at slot start
    wg_blink_load_code(bl, WG_COM_THUNK_BASE, page, WG_COM_THUNK_SIZE, 0);
    free(page);

    for (int iface = 0; iface < IF_COUNT; iface++) {
        // PAD every vtable well past the modelled 11.0/DXGI-1.1 method count. If
        // the game QIs a newer interface (ID3D11Device1..5, ..Context1..4,
        // IDXGISwapChain1..4, ..Factory2..7) and calls a higher-indexed method,
        // an unpadded read runs past the array into adjacent heap = garbage
        // (0xFFFFFFFF) which the guest CALLs -> wild crash. Padded slots are real
        // thunks; dispatch returns S_OK for methods beyond kMethodCount.
        int n = kMethodCount[iface];
        if (n < 256) n = 256;
        uint32_t vt = wg_engine_guest_alloc(engine, (uint32_t)n * 8);
        s_vtable[iface] = vt;
        for (int m = 0; m < n; m++) {
            int slot = s_next_slot++;
            if (slot >= (int)(WG_COM_THUNK_SIZE / 8)) { WG_LOGE(TAG, "COM thunk overflow"); break; }
            s_thunk_slot_iface[slot]  = iface;
            s_thunk_slot_method[slot] = m;
            uint64_t thunk = WG_COM_THUNK_BASE + (uint64_t)slot * 8;
            wg_blink_write_mem(bl, vt + (uint32_t)m * 8, &thunk, 8);
        }
    }
    s_setup_done = true;
    WG_LOGI(TAG, "D3D11/DXGI COM vtables built (%d ifaces, %d thunks); GPU backend: %s",
            IF_COUNT, s_next_slot, wg_gpu_available() ? wg_gpu_device_name(NULL) : "headless-stub");
}

bool wg_d3d11_is_thunk(uint64_t addr) {
    return addr >= WG_COM_THUNK_BASE && addr < WG_COM_THUNK_BASE + WG_COM_THUNK_SIZE;
}

// Allocate a guest COM object of `iface`, backed by `backend`. Writes the vtable
// pointer + native id into guest memory. Returns the guest object address.
static uint32_t com_new(struct WGEngine *engine, int iface, void *backend, uint32_t aux) {
    if (s_obj_count >= WG_MAX_COM) return 0;
    uint32_t guest = wg_engine_guest_alloc(engine, 0x40);
    if (!guest) return 0;
    int id = s_obj_count++;
    s_objs[id] = (WGComObj){ .in_use = true, .iface = iface, .guest = guest,
                             .refcount = 1, .backend = backend, .aux = aux };
    void *bl = B(engine);
    uint64_t vt = s_vtable[iface];
    wg_blink_write_mem(bl, guest + 0x00, &vt, 8);          // vtable ptr
    wg_blink_write_mem(bl, guest + 0x08, &id, 4);          // native id
    uint32_t ifv = (uint32_t)iface;
    wg_blink_write_mem(bl, guest + 0x0C, &ifv, 4);
    return guest;
}

// Find the native object for a guest `this` pointer (native id stored at +8).
static WGComObj *com_from_this(struct WGEngine *engine, uint32_t self) {
    if (!self) return NULL;
    int id = 0;
    wg_blink_read_mem(B(engine), self + 0x08, &id, 4);
    if (id < 0 || id >= s_obj_count || !s_objs[id].in_use) return NULL;
    return &s_objs[id];
}

// Write a guest 64-bit pointer out-param (COM out-params are 8 bytes on x64).
static void put_ptr(struct WGEngine *engine, uint32_t at, uint32_t val) {
    if (!at) return;
    uint64_t v = val;
    wg_blink_write_mem(B(engine), at, &v, 8);
}

// ---- IUnknown (methods 0,1,2 of every interface) ----
// Returns true if handled here.
static bool handle_iunknown(struct WGEngine *engine, WGComObj *o, int method,
                            uint32_t *args, uint64_t *ret) {
    switch (method) {
        case 0: { // QueryInterface(this, riid, ppvObject)
            uint32_t d1 = 0;
            if (args[1]) wg_blink_read_mem(B(engine), args[1], &d1, 4);  // GUID Data1
            // The D3D11 device exposes IDXGIDevice (any version) so the RHI can
            // walk device->GetAdapter->GetParent(factory)->EnumOutputs for display
            // setup. Returning the same (ID3D11Device-typed) object here made the
            // RHI call IDXGIDevice::GetAdapter into the wrong handler -> null ->
            // infinite device-lost spin. Hand back a properly-typed IDXGIDevice.
            if (o->iface == IF_D3D11DEVICE &&
                (d1 == 0x54EC77FAu || d1 == 0x77DB970Fu || d1 == 0x05008617u ||
                 d1 == 0x6007896Cu || d1 == 0x95B4F95Fu)) {
                put_ptr(engine, args[2], com_new(engine, IF_DXGIDEVICE, o->backend, 0));
                *ret = S_OK_;
                return true;
            }
            // Permissive default: hand back the same object for any other QI —
            // most are for the same or a vtable-compatible base.
            o->refcount++;
            put_ptr(engine, args[2], o->guest);
            *ret = S_OK_;
            return true;
        }
        case 1: // AddRef
            *ret = ++o->refcount;
            return true;
        case 2: // Release
            if (o->refcount) o->refcount--;
            *ret = o->refcount;
            if (o->refcount == 0 && o->backend && o->owns_backend) { wg_gpu_release(o->backend); o->backend = NULL; }
            return true;
    }
    return false;
}

// ---- DXGI adapter descriptor (DXGI_ADAPTER_DESC1, 0xB0 bytes) ----
static void write_adapter_desc(struct WGEngine *engine, uint32_t at, bool desc1) {
    if (!at) return;
    uint8_t d[0xB0]; memset(d, 0, sizeof(d));
    // Description[128] wchar_t at +0. MUST look like a real discrete GPU: UE4's D3D11
    // RHI classifies the adapter by VendorId — the old 0x1414 is MICROSOFT's Basic
    // Render Driver (WARP software rasterizer) ID, so UE4 treated us as a software
    // adapter and dropped to the ES2 feature level → the game then tried to load ES2
    // global shaders that aren't cooked in this SM5 PC build → LowLevelFatalError
    // "Missing global shader ..._ES2_0" and the boot never renders. Report NVIDIA +
    // an RTX device id + an NVIDIA GPU name so device-profile matching picks a desktop
    // SM5 profile and the cooked SM5 shaders are used.
    const char *name = "NVIDIA GeForce RTX 3070";
    for (int i = 0; name[i] && i < 100; i++) { uint16_t w = (uint8_t)name[i]; memcpy(d + i*2, &w, 2); }
    uint32_t v;
    v = 0x10DE; memcpy(d + 0x80, &v, 4);   // VendorId = NVIDIA (real discrete GPU, not WARP)
    v = 0x2484; memcpy(d + 0x84, &v, 4);   // DeviceId = RTX 3070
    // DedicatedVideoMemory (SIZE_T at +0x90): report ~1GB.
    uint64_t vram = 0x40000000ULL; memcpy(d + 0x90, &vram, 8);
    uint64_t shared = 0x40000000ULL; memcpy(d + 0xA0, &shared, 8);
    wg_blink_write_mem(B(engine), at, d, desc1 ? 0xB0 : 0xA8);
}

// ---- DXGI factory / adapter / output ----
static void handle_dxgi(struct WGEngine *engine, WGComObj *o, int method,
                        uint32_t *args, uint64_t *ret) {
    *ret = S_OK_;
    if (o->iface == IF_DXGIFACTORY) {
        switch (method) {
            case 7:  // EnumAdapters(this, index, ppAdapter)
            case 12: // EnumAdapters1(this, index, ppAdapter)
                if (args[1] == 0) {
                    uint32_t a = com_new(engine, IF_DXGIADAPTER, o->backend, 0);
                    put_ptr(engine, args[2], a);
                    *ret = S_OK_;
                } else { put_ptr(engine, args[2], 0); *ret = DXGI_ERROR_NOT_FOUND; }
                return;
            case 10: // CreateSwapChain(this, pDevice, pDesc, ppSwapChain)
                { int w = 1280, h = 720;
                  // DXGI_SWAP_CHAIN_DESC.BufferDesc.Width/Height at +0/+4
                  if (args[2]) { wg_blink_read_mem(B(engine), args[2]+0, &w, 4);
                                 wg_blink_read_mem(B(engine), args[2]+4, &h, 4); }
                  if (w <= 0) w = 1280; if (h <= 0) h = 720;
                  WGGpuSwapchain sc = wg_gpu_create_swapchain(o->backend, w, h);
                  uint32_t so = com_new(engine, IF_DXGISWAPCHAIN, sc, 0);
                  put_ptr(engine, args[3], so);
                  WG_LOGI(TAG, "CreateSwapChain %dx%d -> 0x%X", w, h, so);
                  *ret = S_OK_; }
                return;
            case 8: case 9: *ret = S_OK_; return;  // Make/GetWindowAssociation
            case 13: *ret = S_OK_; return;         // IsCurrent
        }
        *ret = S_OK_;
        return;
    }
    if (o->iface == IF_DXGIDEVICE) {
        switch (method) {
            case 6: // IDXGIObject::GetParent(this, riid, ppParent) -> the adapter
                put_ptr(engine, args[2], com_new(engine, IF_DXGIADAPTER, o->backend, 0));
                *ret = S_OK_; return;
            case 7: // IDXGIDevice::GetAdapter(this, pAdapter) -> IDXGIAdapter
                put_ptr(engine, args[1], com_new(engine, IF_DXGIADAPTER, o->backend, 0));
                *ret = S_OK_; return;
        }
        *ret = S_OK_;
        return;
    }
    if (o->iface == IF_DXGIADAPTER) {
        switch (method) {
            case 6: // IDXGIObject::GetParent(this, riid, ppParent) -> the factory
                put_ptr(engine, args[2], com_new(engine, IF_DXGIFACTORY, o->backend, 0));
                *ret = S_OK_; return;
            case 7: // EnumOutputs(this, index, ppOutput)
                if (args[1] == 0) { uint32_t out = com_new(engine, IF_DXGIOUTPUT, o->backend, 0);
                                    put_ptr(engine, args[2], out); *ret = S_OK_; }
                else { put_ptr(engine, args[2], 0); *ret = DXGI_ERROR_NOT_FOUND; }
                return;
            case 8:  write_adapter_desc(engine, args[1], false); *ret = S_OK_; return; // GetDesc
            case 10: write_adapter_desc(engine, args[1], true);  *ret = S_OK_; return; // GetDesc1
            case 9:  *ret = S_OK_; return; // CheckInterfaceSupport
        }
        *ret = S_OK_;
        return;
    }
    if (o->iface == IF_DXGIOUTPUT) {
        // GetDesc / GetDisplayModeList / FindClosestMatchingMode — return success
        // with zeroed/echoed output. Enough for the game to pick a mode.
        *ret = S_OK_;
        return;
    }
    if (o->iface == IF_DXGISWAPCHAIN) {
        switch (method) {
            case 8:  // Present(this, SyncInterval, Flags)
                { static unsigned s_np = 0;
                  if (s_np < 8) WG_LOGW(TAG, "*** GAME Present #%u (first frame reached!)", ++s_np); }
                wg_gpu_present(o->backend); *ret = S_OK_; return;
            case 9:  // GetBuffer(this, Buffer, riid, ppSurface) -> backbuffer texture
                { WGGpuResource bb = wg_gpu_swapchain_backbuffer(o->backend);
                  uint32_t t = com_new(engine, IF_D3D11CHILD, bb, 0);
                  put_ptr(engine, args[3], t); *ret = S_OK_; }
                return;
            case 13: // ResizeBuffers(this, Count, W, H, Format, Flags)
                wg_gpu_resize(o->backend, (int)args[2], (int)args[3]); *ret = S_OK_; return;
            case 10: case 11: *ret = S_OK_; return; // Set/GetFullscreenState
        }
        *ret = S_OK_;
        return;
    }
    *ret = S_OK_;
}

// ---- ID3D11Device ----
static void handle_device(struct WGEngine *engine, WGComObj *o, int method,
                          uint32_t *args, uint64_t *ret) {
    *ret = S_OK_;
    switch (method) {
        case 3:  // CreateBuffer(this, pDesc, pInitialData, ppBuffer)
            { uint32_t size = 0, bind = 0;
              if (args[1]) { wg_blink_read_mem(B(engine), args[1]+0, &size, 4);
                             wg_blink_read_mem(B(engine), args[1]+8, &bind, 4); }
              // Upload pInitialData->pSysMem so vertex/index/constant buffers hold
              // the guest's data (was NULL -> empty buffers -> nothing to draw).
              void *initial = NULL; uint8_t *tmp = NULL;
              if (args[2] && size && size <= 0x4000000) {
                  uint32_t sysmem = 0;
                  wg_blink_read_mem(B(engine), args[2], &sysmem, 4);  // D3D11_SUBRESOURCE_DATA.pSysMem
                  if (sysmem && (tmp = malloc(size))) {
                      wg_blink_read_mem(B(engine), sysmem, tmp, size); initial = tmp;
                  }
              }
              WGGpuResource b = wg_gpu_create_buffer(o->backend, size, initial, bind);
              free(tmp);
              uint32_t g = com_new(engine, IF_D3D11CHILD, b, 0);
              // Stash the full D3D11_BUFFER_DESC so ID3D11Buffer::GetDesc can echo
              // it back — the RHI divides ByteWidth/StructureByteStride when making
              // a structured-buffer SRV and a zeroed desc is a divide-by-zero.
              WGComObj *bo = com_from_this(engine, g);
              if (bo) { bo->owns_backend = true;   // unique buffer wrapper
                        if (args[1]) { wg_blink_read_mem(B(engine), args[1], bo->desc, 24);
                                       bo->desc_len = 24; } }
              put_ptr(engine, args[3], g); }
            return;
        case 5:  // CreateTexture2D(this, pDesc, pInitialData, ppTexture2D)
            { uint32_t w = 0, h = 0, fmt = 0, bind = 0;
              if (args[1]) { wg_blink_read_mem(B(engine), args[1]+0, &w, 4);
                             wg_blink_read_mem(B(engine), args[1]+4, &h, 4);
                             wg_blink_read_mem(B(engine), args[1]+0x10, &fmt, 4);   // DXGI_FORMAT
                             wg_blink_read_mem(B(engine), args[1]+0x20, &bind, 4); } // BindFlags
              // Upload pInitialData->pSysMem (row by row, honoring SysMemPitch)
              // so textures actually contain the guest's pixels.
              void *initial = NULL; uint8_t *tmp = NULL;
              uint32_t sz = (uint32_t)w * (uint32_t)h * 4;
              if (args[2] && w && h && sz <= 0x8000000 && (tmp = malloc(sz))) {
                  uint32_t sysmem = 0, srcpitch = 0;
                  wg_blink_read_mem(B(engine), args[2],   &sysmem,   4);  // pSysMem
                  wg_blink_read_mem(B(engine), args[2]+8, &srcpitch, 4);  // SysMemPitch
                  uint32_t dstpitch = (uint32_t)w * 4;
                  if (!srcpitch) srcpitch = dstpitch;
                  if (sysmem) { for (uint32_t row = 0; row < (uint32_t)h; row++)
                                    wg_blink_read_mem(B(engine), sysmem + row*srcpitch,
                                                      tmp + row*dstpitch, dstpitch);
                                initial = tmp; }
                  else { free(tmp); tmp = NULL; }
              }
              WGGpuResource t = wg_gpu_create_texture2d(o->backend, (int)w, (int)h, fmt, initial, bind);
              free(tmp);
              uint32_t g = com_new(engine, IF_D3D11CHILD, t, 0);
              // Cache the D3D11_TEXTURE2D_DESC (44B) for ID3D11Texture2D::GetDesc.
              // Without it, the game reads a garbage MipLevels and the RHI's
              // per-mip texture-size loop runs billions of iterations (hang).
              WGComObj *to = com_from_this(engine, g);
              if (to) to->owns_backend = true;   // unique texture wrapper
              if (to && args[1]) { wg_blink_read_mem(B(engine), args[1], to->desc, 44);
                                   if (to->desc[2] == 0) {  // MipLevels 0 => full chain; report real count
                                       uint32_t mx = w > h ? w : h, m = 1;
                                       while (mx > 1) { mx >>= 1; m++; }
                                       to->desc[2] = m;
                                   }
                                   to->desc_len = 44; }
              put_ptr(engine, args[3], g); }
            return;
        case 9:  // CreateRenderTargetView(this, pResource, pDesc, ppRTView)
            { WGComObj *res = com_from_this(engine, args[1]);
              WGGpuView v = wg_gpu_create_rtv(o->backend, res ? res->backend : NULL);
              uint32_t g = com_new(engine, IF_D3D11CHILD, v, 0);
              WGComObj *vo = com_from_this(engine, g);
              if (vo) { vo->owns_backend = true; vo->parent = args[1]; } // unique RTV wrapper
              put_ptr(engine, args[3], g); }
            return;
        // Object-creating methods we don't back yet: hand out a valid opaque
        // child object so the game can hold/pass it without dereferencing null.
        // CRITICAL: the ppOut arg index differs per method (views=3, shaders=4,
        // states=2, InputLayout=5, ...). A wrong index leaves the real ppOut
        // UNFILLED, so the game reads a stale thunk address off its stack as the
        // object, dereferences it, and later frees the garbage -> heap corruption.
        case 7:  // CreateShaderResourceView(this, pResource, pDesc, ppSRView)
            { WGComObj *res = com_from_this(engine, args[1]);
              // Share the source resource's backend so binding the SRV gives the
              // sampler the texture. Shared => don't own (resource wrapper owns it).
              uint32_t g = com_new(engine, IF_D3D11CHILD, res ? res->backend : NULL, 0);
              WGComObj *vo = com_from_this(engine, g);
              if (vo) vo->parent = args[1];   // SRV remembers its source resource
              put_ptr(engine, args[3], g); }
            return;
        case 20: // CreateBlendState(this, pBlendStateDesc, ppBlendState)
            { uint32_t g = com_new(engine, IF_D3D11CHILD, NULL, 0);
              WGComObj *bo = com_from_this(engine, g);
              // Cache RenderTarget[0].BlendEnable (D3D11_BLEND_DESC +8) so
              // OMSetBlendState knows whether to enable alpha blending.
              if (bo && args[1]) { uint32_t be = 0; wg_blink_read_mem(B(engine), args[1]+8, &be, 4); bo->aux = be; }
              put_ptr(engine, args[2], g); }
            return;
        case 10: // CreateDepthStencilView(this, pResource, pDesc, ppDepthStencilView)
            { WGComObj *res = com_from_this(engine, args[1]);
              WGGpuView v = wg_gpu_create_rtv(o->backend, res ? res->backend : NULL); // wraps the texture
              uint32_t g = com_new(engine, IF_D3D11CHILD, v, 0);
              WGComObj *vo = com_from_this(engine, g);
              if (vo) { vo->owns_backend = true; vo->parent = args[1]; }
              put_ptr(engine, args[3], g); }
            return;
        case 22: // CreateDepthStencilState(this, pDepthStencilDesc, ppDepthStencilState)
            { uint32_t g = com_new(engine, IF_D3D11CHILD, NULL, 0);
              WGComObj *so = com_from_this(engine, g);
              if (so && args[1]) {   // D3D11_DEPTH_STENCIL_DESC: DepthEnable/WriteMask/Func at 0/4/8
                  uint32_t de = 0, dwm = 0, df = 2;
                  wg_blink_read_mem(B(engine), args[1]+0, &de, 4);
                  wg_blink_read_mem(B(engine), args[1]+4, &dwm, 4);
                  wg_blink_read_mem(B(engine), args[1]+8, &df, 4);
                  so->aux = (de?1:0) | ((dwm?1:0)<<1) | ((df & 0xF)<<4);
              }
              put_ptr(engine, args[2], g); }
            return;
        case 11: // CreateInputLayout(this, pElems, NumElems, pShaderBC, BCLen, ppInputLayout)
            { int n = (int)args[2]; if (n > 16) n = 16; if (n < 0) n = 0;
              WGVtxAttr attrs[16]; memset(attrs, 0, sizeof attrs);
              for (int i = 0; i < n; i++) {
                  uint32_t e = args[1] + (uint32_t)i * 32;   // D3D11_INPUT_ELEMENT_DESC = 32 bytes
                  wg_blink_read_mem(B(engine), e + 12, &attrs[i].dxgi_format, 4); // Format
                  wg_blink_read_mem(B(engine), e + 20, &attrs[i].offset, 4);      // AlignedByteOffset
              }
              WGGpuInputLayout il = wg_gpu_create_input_layout(o->backend, attrs, n);
              put_ptr(engine, args[5], com_new(engine, IF_D3D11CHILD, il, 0)); }
            return;
        case 12: // CreateVertexShader(this, pBytecode, BytecodeLength, pClassLinkage, ppVertexShader)
        case 15: // CreatePixelShader(this, pBytecode, BytecodeLength, pClassLinkage, ppPixelShader)
            { WGGpuShader sh = NULL;
              uint32_t bc = args[1], len = args[2];
              if (bc && len && len <= 0x100000) {
                  void *tmp = malloc(len);
                  if (tmp) { wg_blink_read_mem(B(engine), bc, tmp, len);
                             sh = wg_gpu_create_shader(o->backend, tmp, len); free(tmp); }
              }
              put_ptr(engine, args[4], com_new(engine, IF_D3D11CHILD, sh, 0)); }
            return;
        case 4: case 6: case 8: case 13:
        case 14: case 16: case 17: case 18: case 19: case 21:
        case 23: case 24: case 25: case 26: case 27:
            { // ID3D11Device create-method ppOut arg index (0 = this)
              static const signed char kOut[] = {
                  [4]=3,[6]=3,[7]=3,[8]=3,[10]=3,     // tex1D/3D, SRV, UAV, DSV
                  [11]=5,                              // CreateInputLayout
                  [12]=4,[13]=4,[15]=4,[16]=4,[17]=4,[18]=4, // VS,GS,PS,HS,DS,CS
                  [14]=9,                              // GS with stream output
                  [19]=1,                              // CreateClassLinkage
                  [20]=2,[21]=2,[22]=2,[23]=2,         // Blend/DepthStencil/Rasterizer/Sampler
                  [24]=2,[25]=2,[26]=2,                // Query/Predicate/Counter
                  [27]=7,                              // CreateDeviceContextState
              };
              int outidx = (method < (int)(sizeof kOut) && kOut[method]) ? kOut[method] : 3;
              put_ptr(engine, args[outidx], com_new(engine, IF_D3D11CHILD, NULL, 0));
              *ret = S_OK_; }
            return;
        case 29: // CheckFormatSupport(this, Format, pFormatSupport)
            // Report a broadly-usable format (Texture2D|SHADER_SAMPLE|RENDER_TARGET|
            // BLENDABLE|DISPLAY|CPU_LOCKABLE|MIP) so the game doesn't reject formats
            // and then compute degenerate sizes from a garbage (unfilled) mask.
            if (args[2]) { uint32_t s = 0x0020|0x0200|0x4000|0x8000|0x0080|0x40000|0x1000;
                           wg_blink_write_mem(B(engine), args[2], &s, 4); }
            *ret = S_OK_; return;
        case 30: // CheckMultisampleQualityLevels(this, Format, SampleCount, pNumQualityLevels)
            if (args[3]) { uint32_t q = 1; wg_blink_write_mem(B(engine), args[3], &q, 4); }
            *ret = S_OK_; return;
        case 33: // CheckFeatureSupport(this, Feature, pFeatureSupportData, DataSize)
            // Zero the output struct (deterministic "no optional features") instead
            // of leaving the game's buffer uninitialized.
            if (args[2] && args[3] && args[3] <= 256) {
                uint8_t z[256] = {0};
                wg_blink_write_mem(B(engine), args[2], z, args[3]);
            }
            *ret = S_OK_; return;
        case 37: *ret = 0xB100; return;  // GetFeatureLevel -> D3D_FEATURE_LEVEL_11_0
        case 39: *ret = S_OK_; return;   // GetDeviceRemovedReason -> S_OK (not removed)
        case 40: // GetImmediateContext(this, ppImmediateContext)
            { if (o->aux == 0) {
                  uint32_t ctx = com_new(engine, IF_D3D11CONTEXT, o->backend, 0);
                  o->aux = ctx;   // cache the singleton immediate context
              }
              put_ptr(engine, args[1], o->aux); }
            return;
    }
    *ret = S_OK_;
}

// ---- ID3D11DeviceContext ----
static void handle_context(struct WGEngine *engine, WGComObj *o, int method,
                           uint32_t *args, uint64_t *ret) {
    *ret = S_OK_;
    switch (method) {
        case 50: // ClearRenderTargetView(this, pRTV, ColorRGBA[4])
            { WGComObj *rtv = com_from_this(engine, args[1]);
              float c[4] = {0,0,0,1};
              if (args[2]) wg_blink_read_mem(B(engine), args[2], c, 16);
              wg_gpu_clear_rtv(o->backend, rtv ? rtv->backend : NULL, c[0], c[1], c[2], c[3]); }
            return;
        case 14: { // Map(this, pResource, Sub, MapType, Flags, pMappedResource)
            // Hand back a real, writable scratch buffer as pData. Leaving the
            // D3D11_MAPPED_SUBRESOURCE unfilled made the game write through a
            // garbage pointer (heap corruption -> FMemory::Realloc fatal).
            WGComObj *res = com_from_this(engine, args[1]);
            uint32_t sz = 0x10000;
            if (res && res->desc_len >= 24) {           // buffer ByteWidth / texture Width*Height*4
                uint32_t w = res->desc[0];
                sz = (res->desc_len >= 44) ? (w * (res->desc[1] ? res->desc[1] : 1) * 4) : w;
            }
            if (sz == 0 || sz > 0x4000000) sz = 0x10000;
            if (res && (res->map_scratch == 0 || res->map_size < sz)) {
                res->map_scratch = wg_engine_guest_alloc(engine, sz);
                res->map_size = sz;
            }
            uint32_t data = res ? res->map_scratch : wg_engine_guest_alloc(engine, sz);
            if (args[5]) {
                uint64_t p = data; wg_blink_write_mem(B(engine), args[5], &p, 8);      // pData
                uint32_t rp = (res && res->desc_len >= 44) ? res->desc[0]*4 : sz;      // RowPitch
                wg_blink_write_mem(B(engine), args[5]+8,  &rp, 4);
                wg_blink_write_mem(B(engine), args[5]+12, &sz, 4);                     // DepthPitch
            }
            *ret = S_OK_; return;
        }
        case 15: { // Unmap(this, pResource, Subresource) -> flush scratch to backend buffer
            WGComObj *res = com_from_this(engine, args[1]);
            if (res && res->backend && res->map_scratch) {
                uint32_t sz = (res->desc_len >= 24) ? res->desc[0] : res->map_size; // ByteWidth
                if (sz == 0 || sz > res->map_size) sz = res->map_size;
                if (sz > 0 && sz <= 0x400000) {
                    uint8_t *tmp = malloc(sz);
                    if (tmp) { wg_blink_read_mem(B(engine), res->map_scratch, tmp, sz);
                               wg_gpu_update_buffer(res->backend, tmp, sz); free(tmp); }
                }
            }
            *ret = S_OK_; return;
        }
        case 9: { // PSSetShader(this, pPixelShader, ppClassInstances, NumClassInstances)
            WGComObj *sh = com_from_this(engine, args[1]);
            wg_gpu_set_ps(o->backend, sh ? sh->backend : NULL);
            return;
        }
        case 11: { // VSSetShader(this, pVertexShader, ppClassInstances, NumClassInstances)
            WGComObj *sh = com_from_this(engine, args[1]);
            wg_gpu_set_vs(o->backend, sh ? sh->backend : NULL);
            return;
        }
        case 17: { // IASetInputLayout(this, pInputLayout)
            WGComObj *il = com_from_this(engine, args[1]);
            wg_gpu_set_input_layout(o->backend, il ? il->backend : NULL);
            return;
        }
        case 16: { // PSSetConstantBuffers(this, StartSlot, NumBuffers, ppConstantBuffers)
            uint32_t cb_guest = 0;
            if (args[2] && args[3]) wg_blink_read_mem(B(engine), args[3], &cb_guest, 4);
            WGComObj *cb = com_from_this(engine, cb_guest);
            wg_gpu_set_ps_cbuffer(o->backend, cb ? cb->backend : NULL);
            return;
        }
        case 7: { // VSSetConstantBuffers(this, StartSlot, NumBuffers, ppConstantBuffers)
            uint32_t cb_guest = 0;
            if (args[2] && args[3]) wg_blink_read_mem(B(engine), args[3], &cb_guest, 4); // slot-0 CB
            WGComObj *cb = com_from_this(engine, cb_guest);
            wg_gpu_set_vs_cbuffer(o->backend, cb ? cb->backend : NULL);
            return;
        }
        case 8: { // PSSetShaderResources(this, StartSlot, NumViews, ppShaderResourceViews)
            uint32_t srv_guest = 0;
            if (args[2] && args[3]) wg_blink_read_mem(B(engine), args[3], &srv_guest, 4); // slot-0 SRV
            WGComObj *srv = com_from_this(engine, srv_guest);
            wg_gpu_set_texture(o->backend, srv ? srv->backend : NULL);
            return;
        }
        case 12: // DrawIndexed(this, IndexCount, StartIndexLocation, BaseVertexLocation)
            { static unsigned s_nd = 0; if (s_nd < 4) WG_LOGW(TAG, "*** GAME DrawIndexed #%u (rendering geometry!)", ++s_nd); }
            wg_gpu_draw_indexed(o->backend, args[1], args[2], (int)args[3]);
            return;
        case 13: // Draw(this, VertexCount, StartVertexLocation)
            { static unsigned s_nd2 = 0; if (s_nd2 < 4) WG_LOGW(TAG, "*** GAME Draw #%u (rendering geometry!)", ++s_nd2); }
            wg_gpu_draw(o->backend, args[1], args[2]);
            return;
        case 19: { // IASetIndexBuffer(this, pIndexBuffer, Format, Offset)
            WGComObj *ib = com_from_this(engine, args[1]);   // passed by value (not an array)
            wg_gpu_ia_set_ibuf(o->backend, ib ? ib->backend : NULL, (int)args[2], args[3]);
            return;
        }
        case 35: { // OMSetBlendState(this, pBlendState, BlendFactor[4], SampleMask)
            WGComObj *bs = com_from_this(engine, args[1]);
            wg_gpu_set_blend(o->backend, bs ? (bs->aux != 0) : 0);  // NULL => default opaque
            return;
        }
        case 18: { // IASetVertexBuffers(this, StartSlot, Num, ppVBs, pStrides, pOffsets)
            uint32_t vbuf_guest = 0, stride = 0, offset = 0;
            if (args[3]) wg_blink_read_mem(B(engine), args[3], &vbuf_guest, 4);  // slot-0 buffer ptr
            if (args[4]) wg_blink_read_mem(B(engine), args[4], &stride, 4);
            if (args[5]) wg_blink_read_mem(B(engine), args[5], &offset, 4);
            WGComObj *vb = com_from_this(engine, vbuf_guest);
            wg_gpu_ia_set_vbuf(o->backend, vb ? vb->backend : NULL, stride, offset);
            return;
        }
        case 24: // IASetPrimitiveTopology(this, Topology)
            wg_gpu_ia_set_topology(o->backend, (int)args[1]);
            return;
        case 33: { // OMSetRenderTargets(this, NumViews, ppRTVs, pDepthStencilView)
            uint32_t rtv_guest = 0;
            if (args[1] && args[2]) wg_blink_read_mem(B(engine), args[2], &rtv_guest, 4); // slot-0 RTV
            WGComObj *rtv = com_from_this(engine, rtv_guest);
            wg_gpu_om_set_rtv(o->backend, rtv ? rtv->backend : NULL);
            WGComObj *dsv = com_from_this(engine, args[3]); // pDepthStencilView (by value)
            wg_gpu_om_set_dsv(o->backend, dsv ? dsv->backend : NULL);
            return;
        }
        case 36: { // OMSetDepthStencilState(this, pDepthStencilState, StencilRef)
            WGComObj *st = com_from_this(engine, args[1]);
            if (st) wg_gpu_set_depth_state(o->backend, st->aux & 1, (st->aux>>1) & 1, (st->aux>>4) & 0xF);
            else    wg_gpu_set_depth_state(o->backend, 1, 1, 2);  // NULL => default: enable, write, LESS
            return;
        }
        case 53: { // ClearDepthStencilView(this, pDSV, ClearFlags, Depth, Stencil)
            WGComObj *dsv = com_from_this(engine, args[1]);
            // Depth is a float in XMM3 (not captured in GPR args); games clear to 1.0 (far).
            wg_gpu_clear_dsv(o->backend, dsv ? dsv->backend : NULL, 1.0f);
            return;
        }
        case 44: // RSSetViewports(this, NumViewports, pViewports)
            if (args[1] && args[2]) {
                float vp[6] = {0};
                wg_blink_read_mem(B(engine), args[2], vp, 24); // D3D11_VIEWPORT (6 floats)
                wg_gpu_rs_set_viewport(o->backend, vp[0], vp[1], vp[2], vp[3]);
            }
            return;
        default:
            // The vast majority of context calls are state-setting/draw with void
            // return; safely ignored until the pipeline is implemented.
            *ret = S_OK_;
            return;
    }
}

bool wg_d3d11_dispatch(struct WGEngine *engine, uint64_t thunk_addr,
                       uint32_t *args, uint64_t *ret) {
    int slot = (int)((thunk_addr - WG_COM_THUNK_BASE) / 8);
    if (slot < 0 || slot >= s_next_slot) { *ret = E_FAIL; return true; }
    int iface  = s_thunk_slot_iface[slot];
    int method = s_thunk_slot_method[slot];
    WGComObj *o = com_from_this(engine, args[0]);
    if (!o) { *ret = E_FAIL; return true; }

    if (getenv("WG_COMLOG"))
        WG_LOGI(TAG, "COM if=%d m=%d this=0x%X a1=0x%X a2=0x%X a3=0x%X",
                iface, method, args[0], args[1], args[2], args[3]);

    if (method <= 2 && handle_iunknown(engine, o, method, args, ret)) return true;

    // Padded/unknown high method (a newer interface version we don't model). x64
    // COM is caller-cleaned, so just return success (RAX=0/S_OK) — never crash.
    if (method >= kMethodCount[iface]) { *ret = S_OK_; return true; }

    switch (iface) {
        case IF_DXGIFACTORY: case IF_DXGIADAPTER: case IF_DXGIOUTPUT: case IF_DXGISWAPCHAIN:
        case IF_DXGIDEVICE:
            handle_dxgi(engine, o, method, args, ret); return true;
        case IF_D3D11DEVICE:  handle_device(engine, o, method, args, ret); return true;
        case IF_D3D11CONTEXT: handle_context(engine, o, method, args, ret); return true;
        case IF_D3D11CHILD:
            if (method == 3) { put_ptr(engine, args[1], 0); } // GetDevice (TODO: real device)
            // Method 7 is polymorphic: for a VIEW it's ID3D11View::GetResource
            // (ppResource out-param) — was UNFILLED, so the game got NULL and
            // dereferenced it (Visage's worker: view->GetResource(&r); r->GetDesc()
            // -> the deterministic -1/NULL crash). For a resource it's
            // ID3D11Resource::GetType (pResourceDimension out-param).
            else if (method == 7 && o->parent && args[1]) {   // view: GetResource
                put_ptr(engine, args[1], o->parent);          // hand back source resource
                WGComObj *p = com_from_this(engine, o->parent);
                if (p) p->refcount++;                         // GetResource AddRefs
            } else if (method == 7 && args[1]) {              // resource: GetType
                uint32_t dim = (o->desc_len >= 44) ? 3 /*TEXTURE2D*/ :
                               (o->desc_len >= 24) ? 1 /*BUFFER*/ : 0 /*UNKNOWN*/;
                wg_blink_write_mem(B(engine), args[1], &dim, 4);
            }
            // GetDesc (method 10): echo the stored D3D11_BUFFER_DESC / TEXTURE2D_DESC
            // so the RHI reads real ByteWidth/StructureByteStride/MipLevels. A
            // zeroed/garbage desc either divide-by-zeroes (structured-buffer SRV)
            // or loops billions of times on a bogus MipLevels (texture size calc).
            else if (method == 10 && o->desc_len && args[1])
                wg_blink_write_mem(B(engine), args[1], o->desc, o->desc_len);
            *ret = S_OK_; return true;
    }
    *ret = S_OK_;
    return true;
}

// ---- Win32 entry points ----
uint32_t wg_d3d11_CreateDXGIFactory(struct WGEngine *engine, uint32_t *args, bool factory1) {
    wg_d3d11_setup(engine);
    // CreateDXGIFactory(riid, ppFactory) / CreateDXGIFactory1(riid, ppFactory)
    WGGpuDevice dev = wg_gpu_available() ? wg_gpu_create_device() : (WGGpuDevice)0x1;
    uint32_t f = com_new(engine, IF_DXGIFACTORY, dev, 0);
    put_ptr(engine, args[1], f);
    { static int once = 0; if (!once) { once = 1;
        fprintf(stderr, "[MILESTONE] CreateDXGIFactory%s — RHI adapter enumeration reached\n",
                factory1 ? "1" : ""); fflush(stderr); } }
    WG_LOGI(TAG, "CreateDXGIFactory%s -> 0x%X", factory1 ? "1" : "", f);
    return S_OK_;
}

uint32_t wg_d3d11_D3D11CreateDevice(struct WGEngine *engine, uint32_t *args, bool with_swapchain) {
    wg_d3d11_setup(engine);
    // Unconditional progress milestone: reaching RHI/device creation means the
    // guest finished the multi-minute module+config load and is bringing up the
    // renderer. Always visible (INFO logs are filtered to WRN in long runs).
    { static int once = 0; if (!once) { once = 1;
        fprintf(stderr, "[MILESTONE] D3D11CreateDevice%s — RHI up, renderer init reached\n",
                with_swapchain ? "AndSwapChain" : ""); fflush(stderr); } }
    // D3D11CreateDevice(pAdapter, DriverType, Software, Flags, pFeatureLevels,
    //   FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext)
    // D3D11CreateDeviceAndSwapChain(pAdapter, DriverType, Software, Flags,
    //   pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc, ppSwapChain,
    //   ppDevice, pFeatureLevel, ppImmediateContext)
    WGGpuDevice dev = wg_gpu_available() ? wg_gpu_create_device() : (WGGpuDevice)0x1;
    if (!dev) return E_FAIL;

    uint32_t dev_out, ctx_out, fl_out, sc_out = 0, scdesc = 0;
    if (with_swapchain) {
        scdesc  = args[7];
        sc_out  = args[8];
        dev_out = args[9];
        fl_out  = args[10];
        ctx_out = args[11];
    } else {
        dev_out = args[7];
        fl_out  = args[8];
        ctx_out = args[9];
    }

    uint32_t d = com_new(engine, IF_D3D11DEVICE, dev, 0);
    put_ptr(engine, dev_out, d);

    // Log the game's requested feature levels (pFeatureLevels array) so we can see
    // if/why it lands on ES2. args[4]=pFeatureLevels, args[5]=FeatureLevels count.
    {
        uint32_t pfl = args[4], nfl = args[5];
        char buf[128] = {0}; int bi = 0;
        if (pfl && nfl && nfl <= 16) {
            for (uint32_t i = 0; i < nfl; i++) { uint32_t lvl = 0;
                wg_blink_read_mem(B(engine), pfl + i*4, &lvl, 4);
                bi += snprintf(buf+bi, sizeof(buf)-bi, "0x%X ", lvl); }
        }
        WG_LOGW(TAG, "D3D11CreateDevice: requested FLs=[%s] count=%u fl_out=0x%X -> writing 0xB000",
                buf, nfl, fl_out);
    }
    if (fl_out) { uint32_t fl = 0xB000; wg_blink_write_mem(B(engine), fl_out, &fl, 4); } // 11_0

    if (ctx_out) {
        WGComObj *dobj = com_from_this(engine, d);
        uint32_t ctx = com_new(engine, IF_D3D11CONTEXT, dev, 0);
        if (dobj) dobj->aux = ctx;   // same object as GetImmediateContext returns
        put_ptr(engine, ctx_out, ctx);
    }

    if (with_swapchain && sc_out) {
        int w = 1280, h = 720;
        if (scdesc) { wg_blink_read_mem(B(engine), scdesc+0, &w, 4);
                      wg_blink_read_mem(B(engine), scdesc+4, &h, 4); }
        if (w <= 0) w = 1280; if (h <= 0) h = 720;
        WGGpuSwapchain sc = wg_gpu_create_swapchain(dev, w, h);
        put_ptr(engine, sc_out, com_new(engine, IF_DXGISWAPCHAIN, sc, 0));
    }
    WG_LOGI(TAG, "D3D11CreateDevice%s -> device 0x%X (FL 11_0), GPU=%s",
            with_swapchain ? "AndSwapChain" : "", d,
            wg_gpu_available() ? "Metal" : "headless-stub");
    return S_OK_;
}

// ---- Weak headless GPU backend (overridden by WGMetalBackend.m on device) ----
// Lets the macOS harness link and exercise the whole COM/device path without a
// real Metal surface: device creation "succeeds", resources are fake non-null
// handles, present/clear are no-ops.
__attribute__((weak)) bool wg_gpu_available(void) { return false; }
__attribute__((weak)) WGGpuDevice wg_gpu_create_device(void) { return (WGGpuDevice)0x6D74; }
__attribute__((weak)) void wg_gpu_destroy_device(WGGpuDevice d) { (void)d; }
__attribute__((weak)) const char *wg_gpu_device_name(WGGpuDevice d) { (void)d; return "headless-stub"; }
__attribute__((weak)) WGGpuSwapchain wg_gpu_create_swapchain(WGGpuDevice d, int w, int h) { (void)d;(void)w;(void)h; return (WGGpuSwapchain)0x5343; }
__attribute__((weak)) WGGpuResource wg_gpu_swapchain_backbuffer(WGGpuSwapchain s) { (void)s; return (WGGpuResource)0x4242; }
__attribute__((weak)) void wg_gpu_present(WGGpuSwapchain s) { (void)s; }
__attribute__((weak)) void wg_gpu_play_movie(const char *dir) { (void)dir; }
__attribute__((weak)) void wg_gpu_resize(WGGpuSwapchain s, int w, int h) { (void)s;(void)w;(void)h; }
__attribute__((weak)) WGGpuResource wg_gpu_create_buffer(WGGpuDevice d, uint32_t sz, const void *i, uint32_t bf) { (void)d;(void)sz;(void)i;(void)bf; return (WGGpuResource)0x4255; }
__attribute__((weak)) WGGpuResource wg_gpu_create_texture2d(WGGpuDevice d, int w, int h, uint32_t f, const void *i, uint32_t bf) { (void)d;(void)w;(void)h;(void)f;(void)i;(void)bf; return (WGGpuResource)0x5458; }
__attribute__((weak)) WGGpuView wg_gpu_create_rtv(WGGpuDevice d, WGGpuResource r) { (void)d;(void)r; return (WGGpuView)0x5254; }
__attribute__((weak)) void wg_gpu_release(void *h) { (void)h; }
__attribute__((weak)) void wg_gpu_clear_rtv(WGGpuDevice d, WGGpuView v, float r, float g, float b, float a) { (void)d;(void)v;(void)r;(void)g;(void)b;(void)a; }
__attribute__((weak)) void wg_gpu_om_set_rtv(WGGpuDevice d, WGGpuView v) { (void)d;(void)v; }
__attribute__((weak)) void wg_gpu_ia_set_vbuf(WGGpuDevice d, WGGpuResource b, uint32_t s, uint32_t o) { (void)d;(void)b;(void)s;(void)o; }
__attribute__((weak)) void wg_gpu_ia_set_topology(WGGpuDevice d, int t) { (void)d;(void)t; }
__attribute__((weak)) void wg_gpu_rs_set_viewport(WGGpuDevice d, float x, float y, float w, float h) { (void)d;(void)x;(void)y;(void)w;(void)h; }
__attribute__((weak)) void wg_gpu_draw(WGGpuDevice d, uint32_t vc, uint32_t sv) { (void)d;(void)vc;(void)sv; }
__attribute__((weak)) void wg_gpu_set_texture(WGGpuDevice d, WGGpuResource t) { (void)d;(void)t; }
__attribute__((weak)) void wg_gpu_set_vs_cbuffer(WGGpuDevice d, WGGpuResource c) { (void)d;(void)c; }
__attribute__((weak)) void wg_gpu_update_buffer(WGGpuResource b, const void *data, uint32_t sz) { (void)b;(void)data;(void)sz; }
__attribute__((weak)) void wg_gpu_ia_set_ibuf(WGGpuDevice d, WGGpuResource b, int f, uint32_t o) { (void)d;(void)b;(void)f;(void)o; }
__attribute__((weak)) void wg_gpu_draw_indexed(WGGpuDevice d, uint32_t ic, uint32_t si, int bv) { (void)d;(void)ic;(void)si;(void)bv; }
__attribute__((weak)) void wg_gpu_set_blend(WGGpuDevice d, int e) { (void)d;(void)e; }
__attribute__((weak)) void wg_gpu_om_set_dsv(WGGpuDevice d, WGGpuView v) { (void)d;(void)v; }
__attribute__((weak)) void wg_gpu_set_depth_state(WGGpuDevice d, int e, int w, int f) { (void)d;(void)e;(void)w;(void)f; }
__attribute__((weak)) void wg_gpu_clear_dsv(WGGpuDevice d, WGGpuView v, float z) { (void)d;(void)v;(void)z; }
__attribute__((weak)) WGGpuShader wg_gpu_create_shader(WGGpuDevice d, const void *b, uint32_t s) { (void)d;(void)b;(void)s; return 0; }
__attribute__((weak)) void wg_gpu_set_vs(WGGpuDevice d, WGGpuShader v) { (void)d;(void)v; }
__attribute__((weak)) void wg_gpu_set_ps(WGGpuDevice d, WGGpuShader p) { (void)d;(void)p; }
__attribute__((weak)) WGGpuInputLayout wg_gpu_create_input_layout(WGGpuDevice d, const WGVtxAttr *a, int n) { (void)d;(void)a;(void)n; return 0; }
__attribute__((weak)) void wg_gpu_set_input_layout(WGGpuDevice d, WGGpuInputLayout il) { (void)d;(void)il; }
__attribute__((weak)) void wg_gpu_set_ps_cbuffer(WGGpuDevice d, WGGpuResource c) { (void)d;(void)c; }
