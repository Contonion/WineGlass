#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import "WGMetalView.h"
#import "WGConsoleOverlay.h"

@interface WGSceneDelegate : UIResponder <UIWindowSceneDelegate, UIDocumentPickerDelegate>

@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) WGMetalView *metalView;
@property (nonatomic, strong) WGConsoleOverlay *console;

@end
