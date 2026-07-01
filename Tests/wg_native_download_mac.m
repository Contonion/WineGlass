// wg_native_download_mac.m — macOS-harness-only native download so the Mac
// runner exercises the SAME native-fetch path as the iOS device (on iOS the
// strong def lives in WGSceneDelegate.m; this file is NOT under Sources/ so the
// iOS xcodegen project never sees it -> no duplicate symbol). Compiled only by
// Tests/build_mac.sh. Same NSURLSession implementation.
#import <Foundation/Foundation.h>
#include "wg_native_download.h"

int wg_native_download(const char *url, const char *dest_path) {
    if (!url || !dest_path || !url[0] || !dest_path[0]) return 0;
    @autoreleasepool {
        NSURL *u = [NSURL URLWithString:[NSString stringWithUTF8String:url]];
        if (!u) return 0;
        NSString *dest = [NSString stringWithUTF8String:dest_path];
        __block int ok = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest  = 60.0;
        cfg.timeoutIntervalForResource = 300.0;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
        NSURLSessionDownloadTask *task =
            [session downloadTaskWithURL:u
                       completionHandler:^(NSURL *loc, NSURLResponse *resp, NSError *err) {
                long code = [resp isKindOfClass:[NSHTTPURLResponse class]]
                                ? (long)[(NSHTTPURLResponse *)resp statusCode] : 0;
                if (loc && !err && code == 200) {
                    NSFileManager *fm = [NSFileManager defaultManager];
                    [fm createDirectoryAtPath:[dest stringByDeletingLastPathComponent]
                  withIntermediateDirectories:YES attributes:nil error:nil];
                    [fm removeItemAtPath:dest error:nil];
                    NSError *mv = nil;
                    if ([fm moveItemAtURL:loc toURL:[NSURL fileURLWithPath:dest] error:&mv]) ok = 1;
                }
                dispatch_semaphore_signal(sem);
            }];
        [task resume];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        [session finishTasksAndInvalidate];
        return ok;
    }
}
