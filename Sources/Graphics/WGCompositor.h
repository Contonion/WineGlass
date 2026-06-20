#import <UIKit/UIKit.h>
#import <Metal/Metal.h>

@interface WGCompositor : NSObject

- (instancetype)initWithDevice:(id<MTLDevice>)device;
- (void)renderWindowsToDrawable:(id<CAMetalDrawable>)drawable
                   commandQueue:(id<MTLCommandQueue>)queue
                     screenSize:(CGSize)size;

@end
