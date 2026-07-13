// wg_gpu_backend.h — the native GPU surface the D3D11->Metal layer drives.
//
// Implemented by WGMetalBackend.m (Metal, iOS + macOS). The macOS harness links
// weak fallbacks (in wg_d3d11.c) so the COM/device path can be exercised headless
// without a real surface. Kept as plain C so wg_d3d11.c (C) can call it.
#ifndef WG_GPU_BACKEND_H
#define WG_GPU_BACKEND_H

#include <stdint.h>
#include <stdbool.h>

// Opaque native handles (MTLDevice, CAMetalLayer swapchain, MTLBuffer, MTLTexture,
// pipeline, etc.). The D3D layer stores these inside its COM objects.
typedef void *WGGpuDevice;
typedef void *WGGpuSwapchain;
typedef void *WGGpuResource;   // buffer or texture
typedef void *WGGpuView;       // render-target / shader-resource view
typedef void *WGGpuShader;     // a translated shader (MTLFunction)
typedef void *WGGpuInputLayout; // a vertex descriptor (from a D3D input layout)

// Returns true if a real GPU backend is linked (device); false = headless stub.
bool         wg_gpu_available(void);

WGGpuDevice  wg_gpu_create_device(void);
void         wg_gpu_destroy_device(WGGpuDevice dev);
const char  *wg_gpu_device_name(WGGpuDevice dev);

// Create a swapchain presenting to the app's Metal layer. width/height in px.
WGGpuSwapchain wg_gpu_create_swapchain(WGGpuDevice dev, int width, int height);
WGGpuResource  wg_gpu_swapchain_backbuffer(WGGpuSwapchain sc);
void           wg_gpu_present(WGGpuSwapchain sc);
void           wg_gpu_resize(WGGpuSwapchain sc, int width, int height);

// Resources. `fmt` is a DXGI_FORMAT value; the backend maps to MTLPixelFormat.
WGGpuResource wg_gpu_create_buffer(WGGpuDevice dev, uint32_t size,
                                   const void *initial, uint32_t bind_flags);
WGGpuResource wg_gpu_create_texture2d(WGGpuDevice dev, int w, int h, uint32_t fmt,
                                      const void *initial, uint32_t bind_flags);
WGGpuView     wg_gpu_create_rtv(WGGpuDevice dev, WGGpuResource res);
void          wg_gpu_release(void *handle);

// Frame ops (grow as the pipeline fills in).
void wg_gpu_clear_rtv(WGGpuDevice dev, WGGpuView rtv,
                      float r, float g, float b, float a);

// ---- Draw path ----
// The D3D11 immediate context is stateful; these record the bound state (per
// device, one immediate context for now) and wg_gpu_draw encodes a Metal render
// pass that preserves the prior clear (loadAction=Load) and issues the draw.
// The milestone uses a fixed position+color pipeline (vertex format: float2
// position + float4 color, tightly packed); real DXBC->MSL comes later.
void wg_gpu_om_set_rtv(WGGpuDevice dev, WGGpuView rtv);
void wg_gpu_ia_set_vbuf(WGGpuDevice dev, WGGpuResource vbuf,
                        uint32_t stride, uint32_t offset);
void wg_gpu_ia_set_topology(WGGpuDevice dev, int d3d_topology);
void wg_gpu_rs_set_viewport(WGGpuDevice dev, float x, float y, float w, float h);
// Bind a texture (from a shader-resource view) to fragment slot 0; NULL unbinds.
// When a texture is bound, wg_gpu_draw uses the textured pipeline (vertex format
// float2 position + float2 uv) instead of the position+color one.
void wg_gpu_set_texture(WGGpuDevice dev, WGGpuResource tex);
// Bind a constant buffer (float4x4 MVP) to the vertex shader at slot 0; NULL =>
// identity. Both vertex pipelines transform position by this matrix.
void wg_gpu_set_vs_cbuffer(WGGpuDevice dev, WGGpuResource cbuf);
// Copy `size` bytes into a buffer's backing store (constant/vertex buffer update
// via Map/Unmap or UpdateSubresource).
void wg_gpu_update_buffer(WGGpuResource buf, const void *data, uint32_t size);
void wg_gpu_draw(WGGpuDevice dev, uint32_t vertex_count, uint32_t start_vertex);
// Indexed drawing. dxgi_format: 57=R16_UINT, 42=R32_UINT.
void wg_gpu_ia_set_ibuf(WGGpuDevice dev, WGGpuResource ibuf, int dxgi_format, uint32_t offset);
void wg_gpu_draw_indexed(WGGpuDevice dev, uint32_t index_count, uint32_t start_index,
                         int base_vertex);
// Enable/disable standard src-alpha over-blending for subsequent draws.
void wg_gpu_set_blend(WGGpuDevice dev, int enable);

// Depth buffer. Bind a depth-stencil view as the render pass's depth attachment
// (NULL => no depth). set_depth_state uses D3D11_COMPARISON_FUNC (1..8).
void wg_gpu_om_set_dsv(WGGpuDevice dev, WGGpuView dsv);
void wg_gpu_set_depth_state(WGGpuDevice dev, int depth_enable, int depth_write, int d3d_func);
void wg_gpu_clear_dsv(WGGpuDevice dev, WGGpuView dsv, float depth);

// ---- Programmable shaders (DXBC->MSL translated) ----
// Translate a DXBC blob and create a shader (MTLFunction). NULL on failure.
WGGpuShader wg_gpu_create_shader(WGGpuDevice dev, const void *dxbc, uint32_t size);
void wg_gpu_set_vs(WGGpuDevice dev, WGGpuShader vs);   // NULL => fixed-function path
void wg_gpu_set_ps(WGGpuDevice dev, WGGpuShader ps);
// Input layout -> vertex descriptor. `attrs[i]` describes input register i:
// {dxgi_format, byte offset into the vertex}. Assumes one vertex buffer (slot 0).
typedef struct { uint32_t dxgi_format; uint32_t offset; } WGVtxAttr;
WGGpuInputLayout wg_gpu_create_input_layout(WGGpuDevice dev, const WGVtxAttr *attrs, int n);
void wg_gpu_set_input_layout(WGGpuDevice dev, WGGpuInputLayout il);
void wg_gpu_set_ps_cbuffer(WGGpuDevice dev, WGGpuResource cbuf);   // PSSetConstantBuffers slot 0

// Native startup-movie playback: decode the game's .mp4 logos and present them to
// the window (guest Media Foundation is unimplemented). `dir` = host Content/Movies.
void wg_gpu_play_movie(const char *dir);

#endif
