#import "WGSceneDelegate.h"
#import <Metal/Metal.h>
#import <GameController/GameController.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include "wg_log.h"
#include "wg_engine.h"
#include "wg_selftest.h"
#import "WGCompositor.h"
#include "wg_win32_windows.h"
#include <unistd.h>

@implementation WGSceneDelegate {
    CADisplayLink *_displayLink;
    id<MTLDevice> _device;
    id<MTLCommandQueue> _commandQueue;
    WGEngine *_engine;
    UIButton *_loadButton;
    WGCompositor *_compositor;
    NSThread *_engineThread;          // runs the emulator at full speed
    volatile BOOL _engineThreadRunning;
}

- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions {
    UIWindowScene *windowScene = (UIWindowScene *)scene;

    wg_log_init();

    self.window = [[UIWindow alloc] initWithWindowScene:windowScene];

    [self createMetalView];
    [self createMetalResources];
    [self createConsole];
    [self createLoadButton];
    [self installTapHandler];
    [self.window makeKeyAndVisible];

    UIApplication.sharedApplication.idleTimerDisabled = YES;

    [self startRenderLoop];
    [self observeLifecycle];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self runSelfTestsSync];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self createEngine];
        });
    });
}

- (void)createMetalView {
    CGRect bounds = self.window.bounds;
    self.metalView = [[WGMetalView alloc] initWithFrame:bounds];
    self.metalView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;

    WGViewController *vc = [[WGViewController alloc] init];
    vc.view = self.metalView;
    self.window.rootViewController = vc;

    WG_LOGI("App", "Window created: %.0fx%.0f", bounds.size.width, bounds.size.height);
}

- (void)createMetalResources {
    _device = self.metalView.metalLayer.device;
    if (!_device) {
        WG_LOGE("App", "No Metal device available");
        return;
    }
    _commandQueue = [_device newCommandQueue];
    _compositor = [[WGCompositor alloc] initWithDevice:_device];
    WG_LOGI("App", "Metal device: %s", _device.name.UTF8String);

    int gpuFamily = 0;
    if ([_device supportsFamily:MTLGPUFamilyApple9]) gpuFamily = 9;
    else if ([_device supportsFamily:MTLGPUFamilyApple8]) gpuFamily = 8;
    else if ([_device supportsFamily:MTLGPUFamilyApple7]) gpuFamily = 7;
    else if ([_device supportsFamily:MTLGPUFamilyApple6]) gpuFamily = 6;
    else if ([_device supportsFamily:MTLGPUFamilyApple5]) gpuFamily = 5;
    WG_LOGI("App", "GPU family: Apple %d", gpuFamily);
}

- (void)createConsole {
    // On-screen log overlay disabled: logs still go to stderr (visible in the
    // Xcode/device console on the computer), and skipping the per-line
    // main-queue dispatch keeps the UI thread free for rendering.
    WG_LOGI("App", "WineGlass Translation Engine for iOS (logs -> console)");
}

- (void)createLoadButton {
    _loadButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _loadButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_loadButton setTitle:@"  Load .exe  " forState:UIControlStateNormal];
    _loadButton.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    [_loadButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    _loadButton.backgroundColor = [UIColor colorWithRed:0.2 green:0.5 blue:1.0 alpha:0.9];
    _loadButton.layer.cornerRadius = 10;
    _loadButton.enabled = NO; // enabled after engine init
    [_loadButton addTarget:self action:@selector(openFilePicker) forControlEvents:UIControlEventTouchUpInside];
    [self.metalView addSubview:_loadButton];

    [NSLayoutConstraint activateConstraints:@[
        [_loadButton.topAnchor constraintEqualToAnchor:self.metalView.safeAreaLayoutGuide.topAnchor constant:12],
        [_loadButton.centerXAnchor constraintEqualToAnchor:self.metalView.centerXAnchor],
        [_loadButton.heightAnchor constraintEqualToConstant:44],
    ]];
}

// Tap the rendered wizard window: map the touch into the compositor's virtual
// space, hit-test the dialog's buttons, and deliver the click to NSIS.
- (void)installTapHandler {
    UITapGestureRecognizer *tap =
        [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleTap:)];
    [self.metalView addGestureRecognizer:tap];
}

- (void)handleTap:(UITapGestureRecognizer *)g {
    if (!_engine || !wg_engine_dialog_active(_engine)) return;

    CGPoint p = [g locationInView:self.metalView];
    CGSize ds = self.metalView.metalLayer.drawableSize;   // pixels
    CGSize bs = self.metalView.bounds.size;               // points
    if (bs.width <= 0 || bs.height <= 0) return;

    // points -> drawable pixels, then invert the compositor's fit-into-800x600.
    float spx = p.x * (ds.width  / bs.width);
    float spy = p.y * (ds.height / bs.height);
    float sw = ds.width, sh = ds.height;
    float scale = fminf(sw / 800.0f, sh / 600.0f);
    float offX = (sw - 800.0f * scale) / 2.0f;
    float offY = (sh - 600.0f * scale) / 2.0f;
    int vx = (int)((spx - offX) / scale);
    int vy = (int)((spy - offY) / scale);

    uint32_t id = wg_engine_hit_test(_engine, vx, vy);
    if (id) {
        WG_LOGI("App", "tap (%d,%d) -> wizard button id %u", vx, vy, id);
        wg_engine_dialog_command(_engine, id);
    }
}

- (void)resumeEngine {
    if (_engine) wg_engine_resume(_engine);
}

- (void)openFilePicker {
    UTType *exeType = [UTType typeWithFilenameExtension:@"exe"];
    NSArray *types = exeType ? @[exeType, UTTypeData] : @[UTTypeData];

    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:types];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;

    [self.window.rootViewController presentViewController:picker animated:YES completion:nil];
    WG_LOGI("App", "File picker opened — select a .exe");
}

#pragma mark - UIDocumentPickerDelegate

- (void)documentPicker:(UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;

    // Need to access the security-scoped resource
    BOOL accessing = [url startAccessingSecurityScopedResource];

    NSString *filename = url.lastPathComponent;
    WG_LOGI("App", "Selected: %s", filename.UTF8String);

    // Copy to Documents so we can access it freely
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *destPath = [docs stringByAppendingPathComponent:filename];
    NSFileManager *fm = [NSFileManager defaultManager];

    [fm removeItemAtPath:destPath error:nil];
    NSError *error = nil;
    if ([fm copyItemAtURL:url toURL:[NSURL fileURLWithPath:destPath] error:&error]) {
        WG_LOGI("App", "Copied to: %s", destPath.UTF8String);
        [self loadAndRunPE:destPath];
    } else {
        WG_LOGE("App", "Copy failed: %s", error.localizedDescription.UTF8String);
    }

    if (accessing) {
        [url stopAccessingSecurityScopedResource];
    }
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    WG_LOGI("App", "File picker cancelled");
}

#pragma mark - PE Loading

- (void)loadAndRunPE:(NSString *)path {
    if (!_engine) {
        WG_LOGE("App", "Engine not ready");
        return;
    }

    WG_LOGI("App", "Loading PE: %s", path.lastPathComponent.UTF8String);

    // Wipe stale NSIS temp leftovers (ns*.tmp files and dirs) so installers
    // always get fresh plug-in directories — a stale dir makes NSIS bail with
    // "Can't initialize plug-ins directory".
    {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docs = paths.firstObject;
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *f in [fm contentsOfDirectoryAtPath:docs error:nil]) {
            if (([f hasPrefix:@"ns"] && [f.pathExtension.lowercaseString isEqualToString:@"tmp"]) ||
                [f.pathExtension.lowercaseString isEqualToString:@"tmp"]) {
                [fm removeItemAtPath:[docs stringByAppendingPathComponent:f] error:nil];
            }
        }
        WG_LOGI("App", "Cleaned stale temp files");
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        bool ok = wg_engine_load_pe(self->_engine, path.UTF8String);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (ok) {
                WG_LOGI("App", "PE loaded successfully — starting execution");
                wg_engine_run(self->_engine);
                [self startEngineThread];
            } else {
                WG_LOGE("App", "Failed to load PE");
            }
        });
    });
}

// Run the emulator on a dedicated high-priority thread at full speed, decoupled
// from the 60 Hz render loop (previously the engine only ticked once per frame).
- (void)startEngineThread {
    // Signal any prior engine loop to exit AND wait for it to actually finish
    // before starting a new one. Without the wait, the old thread never observes
    // the stop flag (it gets reset to YES on the next line) and keeps ticking the
    // same blink VM as the new thread — a data race on the guest heap that
    // corrupts libsystem_malloc (EXC_BREAKPOINT) and double-runs the program.
    _engineThreadRunning = NO;
    NSThread *prior = _engineThread;
    if (prior && prior != [NSThread currentThread]) {
        // Bounded wait so a wedged tick can't freeze the UI indefinitely.
        for (int i = 0; i < 2000 && !prior.isFinished; i++)
            usleep(1000); // up to ~2s
        if (!prior.isFinished)
            WG_LOGW("App", "Prior engine thread did not stop in time — proceeding");
    }
    _engineThreadRunning = YES;
    _engineThread = [[NSThread alloc] initWithTarget:self
                                            selector:@selector(engineLoop)
                                              object:nil];
    _engineThread.stackSize = 4 * 1024 * 1024; // 4MB — handle_blink_thunk is large
    _engineThread.qualityOfService = NSQualityOfServiceUserInteractive;
    _engineThread.name = @"WineGlass-Engine";
    [_engineThread start];
}

- (void)engineLoop {
    while (_engineThreadRunning) {
        WGEngineState s = wg_engine_get_state(_engine);
        if (s == WG_ENGINE_RUNNING) {
            wg_engine_tick(_engine);          // tight loop — full core
        } else if (s == WG_ENGINE_PAUSED) {
            wg_engine_tick(_engine);          // let worker threads run
            usleep(8000);                     // then idle briefly
        } else {
            break;                            // STOPPED / ERROR / IDLE
        }
    }
    // The installer exited — if it asked to launch the Steam bootstrapper
    // (steam.exe), chain-load and run it (the "fancier" Steam UI).
    const char *next = wg_engine_take_pending_exec(_engine);
    if (next && next[0] && _engineThreadRunning) {
        NSString *p = [NSString stringWithUTF8String:next];
        WG_LOGI("App", "Chain-loading bootstrapper: %s", next);
        dispatch_async(dispatch_get_main_queue(), ^{ [self loadAndRunPE:p]; });
    }
}

- (void)tryLoadBundledPE {
    // Prefer a real .exe dropped in Documents (e.g. SteamSetup.exe). Fall back
    // to the bundled GDI demo. (Diagnostic probes are still in the bundle and
    // loadable via the file picker if needed.)
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docs = paths.firstObject;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *files = [fm contentsOfDirectoryAtPath:docs error:nil];

    for (NSString *file in files) {
        if ([file.pathExtension.lowercaseString isEqualToString:@"exe"]) {
            NSString *path = [docs stringByAppendingPathComponent:file];
            WG_LOGI("App", "Found PE in Documents: %s", file.UTF8String);
            [self loadAndRunPE:path];
            return;
        }
    }

    NSString *testPath = [[NSBundle mainBundle] pathForResource:@"WGTest" ofType:@"exe"];
    if (testPath) {
        WG_LOGI("App", "No Documents .exe — loading bundled GDI demo: WGTest.exe");
        [self loadAndRunPE:testPath];
        return;
    }
    WG_LOGI("App", "Tap 'Load .exe' to select a Windows executable");
}

#pragma mark - Engine & Tests

- (void)runSelfTestsSync {
    WG_LOGI("App", "Running full self-tests (including blink x86-64 execution)...");
    bool ok = wg_selftest_run();
    dispatch_async(dispatch_get_main_queue(), ^{
        if (ok) {
            WG_LOGI("App", "All self-tests passed — x86-64 executing on iPhone");
        } else {
            WG_LOGW("App", "Some tests failed (blink may need fallback)");
        }
    });
}

- (void)createEngine {
    WG_LOGI("App", "Creating translation engine...");
    _engine = wg_engine_create();
    if (_engine) {
        if (wg_engine_init(_engine)) {
            WG_LOGI("App", "Translation engine ready");
            _loadButton.enabled = YES;
            [self tryLoadBundledPE];
        } else {
            WG_LOGW("App", "Engine init incomplete");
        }
    } else {
        WG_LOGE("App", "Failed to create translation engine");
    }
}

#pragma mark - Render Loop

- (void)startRenderLoop {
    _displayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(renderFrame:)];
    _displayLink.preferredFrameRateRange = CAFrameRateRangeMake(30, 120, 60);
    [_displayLink addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSDefaultRunLoopMode];
    WG_LOGI("App", "Render loop started");
}

- (void)renderFrame:(CADisplayLink *)link {
    @autoreleasepool {
        if (!_commandQueue) return;

        id<CAMetalDrawable> drawable = [self.metalView.metalLayer nextDrawable];
        if (!drawable) return;

        // The engine runs on its own thread; the render loop only composites.
        // Wizard input is via tapping the rendered buttons (see handleTap:).

        // If there are visible Win32 windows, render them via compositor
        if (wg_wm_visible_count() > 0) {
            CGSize size = self.metalView.metalLayer.drawableSize;
            [_compositor renderWindowsToDrawable:drawable
                                   commandQueue:_commandQueue
                                     screenSize:size];
        } else {
            // Default dark background
            MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor new];
            pass.colorAttachments[0].texture = drawable.texture;
            pass.colorAttachments[0].loadAction = MTLLoadActionClear;
            pass.colorAttachments[0].storeAction = MTLStoreActionStore;
            pass.colorAttachments[0].clearColor = MTLClearColorMake(0.05, 0.05, 0.1, 1.0);

            id<MTLCommandBuffer> cmd = [_commandQueue commandBuffer];
            id<MTLRenderCommandEncoder> enc = [cmd renderCommandEncoderWithDescriptor:pass];
            [enc endEncoding];
            [cmd presentDrawable:drawable];
            [cmd commit];
        }
    }
}

- (void)observeLifecycle {
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil queue:nil
                usingBlock:^(NSNotification *n) { self->_displayLink.paused = YES; }];
    [nc addObserverForName:UIApplicationWillEnterForegroundNotification object:nil queue:nil
                usingBlock:^(NSNotification *n) { self->_displayLink.paused = NO; }];
}

- (void)sceneDidDisconnect:(UIScene *)scene {
    _engineThreadRunning = NO;        // stop the engine thread
    [NSThread sleepForTimeInterval:0.02];
    if (_engine) {
        wg_engine_destroy(_engine);
        _engine = NULL;
    }
    [_displayLink invalidate];
    _displayLink = nil;
}

@end
