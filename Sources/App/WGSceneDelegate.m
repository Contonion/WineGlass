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
    UIButton *_nextButton;            // wizard Next/Install
    UIButton *_cancelButton;          // wizard Cancel
}

- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions {
    UIWindowScene *windowScene = (UIWindowScene *)scene;

    wg_log_init();

    self.window = [[UIWindow alloc] initWithWindowScene:windowScene];

    [self createMetalView];
    [self createMetalResources];
    [self createConsole];
    [self createLoadButton];
    [self createWizardButtons];
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

- (void)createWizardButtons {
    _nextButton = [self makeWizardButton:@"Next ›"
                                   color:[UIColor colorWithRed:0.2 green:0.7 blue:0.3 alpha:0.95]
                                  action:@selector(wizardNext)];
    _cancelButton = [self makeWizardButton:@"Cancel"
                                     color:[UIColor colorWithRed:0.5 green:0.5 blue:0.55 alpha:0.95]
                                    action:@selector(wizardCancel)];
    [NSLayoutConstraint activateConstraints:@[
        [_nextButton.bottomAnchor constraintEqualToAnchor:self.metalView.safeAreaLayoutGuide.bottomAnchor constant:-16],
        [_nextButton.trailingAnchor constraintEqualToAnchor:self.metalView.trailingAnchor constant:-16],
        [_nextButton.heightAnchor constraintEqualToConstant:48],
        [_nextButton.widthAnchor constraintEqualToConstant:120],
        [_cancelButton.bottomAnchor constraintEqualToAnchor:_nextButton.bottomAnchor],
        [_cancelButton.trailingAnchor constraintEqualToAnchor:_nextButton.leadingAnchor constant:-12],
        [_cancelButton.heightAnchor constraintEqualToConstant:48],
        [_cancelButton.widthAnchor constraintEqualToConstant:120],
    ]];
    _nextButton.hidden = YES;
    _cancelButton.hidden = YES;
}

- (UIButton *)makeWizardButton:(NSString *)title color:(UIColor *)color action:(SEL)action {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b setTitle:title forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    b.backgroundColor = color;
    b.layer.cornerRadius = 10;
    [b addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    [self.metalView addSubview:b];
    return b;
}

- (void)wizardNext {
    if (_engine) wg_engine_dialog_command(_engine, 1);   // IDOK / Next / Install
}

- (void)wizardCancel {
    if (_engine) wg_engine_dialog_command(_engine, 2);   // IDCANCEL
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
    _engineThreadRunning = NO;            // signal any prior loop to exit
    _engineThreadRunning = YES;
    _engineThread = [[NSThread alloc] initWithTarget:self
                                            selector:@selector(engineLoop)
                                              object:nil];
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
            usleep(8000);                     // idle while a modal dialog waits
        } else {
            break;                            // STOPPED / ERROR / IDLE
        }
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

        // The engine runs on its own thread now; the render loop only
        // composites and toggles the wizard buttons when a modal dialog waits.
        BOOL wizard = (_engine &&
                       wg_engine_get_state(_engine) == WG_ENGINE_PAUSED &&
                       wg_engine_dialog_active(_engine));
        if (_nextButton.hidden != !wizard) {
            _nextButton.hidden = !wizard;
            _cancelButton.hidden = !wizard;
        }

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
