#import <UIKit/UIKit.h>
#include "wg_log.h"

@interface WGConsoleOverlay : UIView

- (void)appendLog:(NSString *)message level:(WGLogLevel)level;
- (void)clear;
@property (nonatomic, assign) BOOL visible;

@end
