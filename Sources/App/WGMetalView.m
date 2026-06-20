#import "WGMetalView.h"

@implementation WGMetalView

+ (Class)layerClass {
    return [CAMetalLayer class];
}

- (CAMetalLayer *)metalLayer {
    return (CAMetalLayer *)self.layer;
}

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.backgroundColor = UIColor.blackColor;
        CAMetalLayer *layer = self.metalLayer;
        layer.device = MTLCreateSystemDefaultDevice();
        layer.pixelFormat = MTLPixelFormatBGRA8Unorm;
        layer.framebufferOnly = YES;
        layer.opaque = YES;
        layer.contentsGravity = kCAGravityResizeAspect;
        layer.backgroundColor = CGColorGetConstantColor(kCGColorBlack);
    }
    return self;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    CGFloat scale = self.window.screen.nativeScale;
    self.metalLayer.drawableSize = CGSizeMake(
        self.bounds.size.width * scale,
        self.bounds.size.height * scale
    );
}

@end

@implementation WGViewController

- (BOOL)prefersStatusBarHidden {
    return YES;
}

- (BOOL)prefersHomeIndicatorAutoHidden {
    return YES;
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations {
    return UIInterfaceOrientationMaskLandscape;
}

@end
