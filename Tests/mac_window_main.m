// mac_window_main.m — Windowed macOS harness. Same engine as the headless
// run_exe.c, but presents to a real NSWindow/CAMetalLayer so you can SEE what
// the guest renders (D3D11 -> Metal via WGMetalBackend.m). Apple Silicon runs
// the same blink interpreter as iOS, so behaviour/speed match the device, with
// no build-install-launch round-trip.
//
// Usage: wineglass_window <file.exe> [max_seconds]
//
// The window stays open after the guest stops so you can inspect the last frame.

#import <Cocoa/Cocoa.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include "wg_log.h"
#include "wg_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

extern void wg_gpu_set_present_layer(void *layer);
extern void wg_gpu_set_render_loop_active(int active);
extern void wg_gpu_render_frame(void);   // presents one viewer frame (main thread)

// Paint one frame directly (dark "loading" slate) so the window isn't blank
// white while the guest boots, and to prove the Metal present path works end to
// end (NSWindow -> CAMetalLayer -> drawable) before the guest ever renders.
static void present_solid_frame(CAMetalLayer *layer, id<MTLCommandQueue> q,
                                double r, double g, double b) {
    @autoreleasepool {
        id<CAMetalDrawable> d = [layer nextDrawable];
        if (!d) return;
        MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
        rp.colorAttachments[0].texture = d.texture;
        rp.colorAttachments[0].loadAction = MTLLoadActionClear;
        rp.colorAttachments[0].storeAction = MTLStoreActionStore;
        rp.colorAttachments[0].clearColor = MTLClearColorMake(r, g, b, 1.0);
        id<MTLCommandBuffer> cb = [q commandBuffer];
        id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rp];
        [enc endEncoding];
        [cb presentDrawable:d];
        [cb commit];
    }
}

static const char *g_exe;
static double g_max_seconds = 1e12;   // windowed: effectively run until it stops

// The guest engine runs on its OWN thread (like the iOS scene delegate), leaving
// the AppKit main thread free for the window/event loop; wg_gpu_present pulls the
// next drawable from the registered layer on this thread.
static void *engine_thread(void *arg) {
    (void)arg;
    WGEngine *engine = wg_engine_create();
    if (!engine || !wg_engine_init(engine)) { WG_LOGE("RUN", "engine init failed"); return NULL; }

    char chain[1024];
    const char *exe_to_run = g_exe;
    for (int chained = 0; ; chained++) {
        if (!wg_engine_load_pe(engine, exe_to_run)) { WG_LOGE("RUN", "PE load failed"); break; }
        if (!wg_engine_run(engine))                 { WG_LOGE("RUN", "engine start failed"); break; }

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
                if (el > g_max_seconds) { WG_LOGW("RUN", "time limit %.1fs hit (%llu ticks)", g_max_seconds, ticks); break; }
            }
        }
        const char *next = wg_engine_take_pending_exec(engine);
        if (!next || !next[0] || chained >= 3) break;
        strncpy(chain, next, sizeof(chain) - 1);
        chain[sizeof(chain) - 1] = 0;
        WG_LOGI("RUN", "chain-loading: %s", chain);
        exe_to_run = chain;
    }
    WG_LOGI("RUN", "done (window stays open — close it to quit)");
    wg_engine_destroy(engine);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "usage: %s <file.exe> [max_seconds]\n", argv[0]); return 2; }
    g_exe = argv[1];
    if (argc >= 3) g_max_seconds = atof(argv[2]);

    wg_log_init();
    if (getenv("WG_LOG_LEVEL")) {   // W=warn E=error I=info (default: debug) — quiets CRT-call spam
        char l = getenv("WG_LOG_LEVEL")[0];
        wg_log_set_level(l=='W'?WG_LOG_WARN : l=='E'?WG_LOG_ERROR : l=='I'?WG_LOG_INFO : WG_LOG_DEBUG);
    }
    WG_LOGI("RUN", "=== WineGlass windowed runner (macOS) ===");
    WG_LOGI("RUN", "exe=%s", g_exe);

    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        NSRect frame = NSMakeRect(0, 0, 1280, 720);
        NSWindow *win = [[NSWindow alloc]
            initWithContentRect:frame
                      styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                 NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable)
                        backing:NSBackingStoreBuffered
                          defer:NO];
        [win setTitle:@"WineGlass — macOS"];

        // Layer-hosting view: set .layer BEFORE wantsLayer so AppKit doesn't
        // replace our CAMetalLayer with its own.
        NSView *view = [[NSView alloc] initWithFrame:frame];
        CAMetalLayer *metalLayer = [CAMetalLayer layer];
        metalLayer.frame = view.bounds;
        metalLayer.contentsScale = win.backingScaleFactor;
        metalLayer.pixelFormat = MTLPixelFormatBGRA8Unorm;
        view.layer = metalLayer;
        view.wantsLayer = YES;
        [win setContentView:view];
        [win center];
        [win makeKeyAndOrderFront:nil];

        wg_gpu_set_present_layer((__bridge void *)metalLayer);

        // The layer needs a device before -nextDrawable works. The guest's
        // swapchain will re-set this (and drawableSize) when it creates one.
        id<MTLDevice> mtldev = MTLCreateSystemDefaultDevice();
        metalLayer.device = mtldev;
        metalLayer.drawableSize = CGSizeMake(frame.size.width * win.backingScaleFactor,
                                             frame.size.height * win.backingScaleFactor);
        (void)present_solid_frame;   // superseded by the render loop below

        // The main thread OWNS presentation from here on: a ~60fps timer presents
        // the guest's swapchain backbuffer every frame (or a dark slate before any
        // swapchain exists). This is why the window shows something even while the
        // guest is still grinding through boot and hasn't called Present yet.
        wg_gpu_set_render_loop_active(1);
        NSTimer *renderTimer = [NSTimer timerWithTimeInterval:1.0 / 60.0 repeats:YES
                                                        block:^(NSTimer *t) { (void)t; wg_gpu_render_frame(); }];
        [[NSRunLoop mainRunLoop] addTimer:renderTimer forMode:NSRunLoopCommonModes];
        WG_LOGI("RUN", "render loop active (60fps) — window presents guest frames continuously");

        pthread_t t;
        pthread_create(&t, NULL, engine_thread, NULL);

        [NSApp activateIgnoringOtherApps:YES];
        [NSApp run];   // AppKit event loop; window close terminates the app
    }
    return 0;
}
