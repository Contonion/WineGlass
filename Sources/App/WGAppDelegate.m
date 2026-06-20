#import "WGAppDelegate.h"
#import "WGSceneDelegate.h"

@implementation WGAppDelegate

- (UISceneConfiguration *)application:(UIApplication *)application
    configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession
                                  options:(UISceneConnectionOptions *)options {
    UISceneConfiguration *config = [[UISceneConfiguration alloc]
        initWithName:@"Default"
        sessionRole:connectingSceneSession.role];
    config.delegateClass = [WGSceneDelegate class];
    return config;
}

@end
