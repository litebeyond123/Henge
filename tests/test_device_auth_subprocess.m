#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import "../ios/Henge/Native/HengeAuthSubprocess.h"
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned checks;
static atomic_bool interruptNextWait = false;
static atomic_uint interruptions = 0;

static void require(BOOL value, const char *message) {
    if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
    checks++;
}
pid_t HengeAuthTestWaitPID(pid_t pid, int *status, int options) {
    if (atomic_exchange(&interruptNextWait, false)) {
        atomic_fetch_add(&interruptions, 1); errno = EINTR; return -1;
    }
    return waitpid(pid, status, options);
}

static NSDictionary *run(NSString *path, NSInteger operation, NSData *input, NSUInteger timeout,
                         NSString *expected, NSData **secretResult) {
    HengeAuthSetTestSignerPath(path);
    dispatch_semaphore_t ready = dispatch_semaphore_create(0);
    __block NSDictionary *diag = nil;
    __block NSData *result = nil;
    __block BOOL wasMain = YES;
    double start = NSProcessInfo.processInfo.systemUptime;
    HengeAuthRunSignerChild(operation, input, timeout, ^(NSData *value, NSData *diagnostics) {
        wasMain = NSThread.isMainThread;
        result = [value copy];
        diag = [NSJSONSerialization JSONObjectWithData:diagnostics options:0 error:NULL];
        dispatch_semaphore_signal(ready);
    });
    require(dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC)) == 0, "bounded child completion");
    require(!wasMain, "child completion is off main thread");
    require([diag[@"outcome"] isEqual:expected], "expected child outcome");
    require([diag[@"isolatedSigner"] isEqual:@YES], "child scope recorded");
    require(NSProcessInfo.processInfo.systemUptime - start < 3.5, "deadline and reap remain bounded");
    if (secretResult) *secretResult = result;
    else require(!result.length, "failure does not contain a secret result");
    NSString *pidText = [NSString stringWithContentsOfFile:[path stringByAppendingString:@".pid"]
        encoding:NSUTF8StringEncoding error:NULL];
    if (pidText) {
        pid_t pid = (pid_t)pidText.intValue;
        errno = 0;
        require(pid > 1 && kill(pid, 0) == -1 && errno == ESRCH, "child is no longer running or a zombie");
    }
    return diag;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        require(argc == 4, "fixture and real-main paths provided");
        NSString *fixture = @(argv[1]), *realMain = @(argv[2]), *directory = @(argv[3]);
        NSData *input = [@"SYNTHETIC-SECRET-INPUT" dataUsingEncoding:NSUTF8StringEncoding];
        NSFileManager *fm = NSFileManager.defaultManager;
        NSArray *modes = @[@"success", @"native-error", @"early-exit", @"signal-exit", @"oversize-frame",
            @"zero-frame", @"truncated-frame", @"not-plist", @"wrong-protocol", @"bad-diagnostics",
            @"oversize-result", @"hang-before-read", @"reply-then-hang", @"eintr"];
        for (NSString *mode in modes) {
            NSString *path = [directory stringByAppendingPathComponent:mode];
            require([fm createSymbolicLinkAtPath:path withDestinationPath:fixture error:NULL], "create isolated fixture path");
            NSString *expected = @"child_transport_failed";
            if ([mode isEqual:@"success"] || [mode isEqual:@"eintr"]) expected = @"success";
            else if ([mode isEqual:@"native-error"]) expected = @"native_error";
            else if ([@[@"not-plist", @"wrong-protocol", @"bad-diagnostics", @"oversize-result"] containsObject:mode]) expected = @"child_invalid_response";
            else if ([@[@"hang-before-read", @"reply-then-hang"] containsObject:mode]) expected = @"child_timed_out";
            if ([mode isEqual:@"eintr"]) atomic_store(&interruptNextWait, true);
            NSData *response = nil;
            NSUInteger budget = [expected isEqual:@"child_timed_out"] ? 400 : 1800;
            NSDictionary *diag = run(path, 2, input, budget, expected, [expected isEqual:@"success"] ? &response : NULL);
            if ([expected isEqual:@"success"]) require(response.length > 0, "complete successful result returned");
            if ([mode isEqual:@"early-exit"]) require([diag[@"childExitCode"] isEqual:@7], "actual child exit code retained");
            if ([mode isEqual:@"signal-exit"]) require([diag[@"childSignal"] isEqual:@(SIGTERM)], "actual child signal retained");
        }
        require(atomic_load(&interruptions) == 1, "injected waitpid EINTR was exercised");
        run([directory stringByAppendingPathComponent:@"missing-helper"], 2, input, 400, @"child_spawn_failed", NULL);
        run(fixture, 1, input, 400, @"child_invalid_request", NULL);
        run(fixture, 2, [NSMutableData dataWithLength:32769], 400, @"child_invalid_request", NULL);
        NSData *response = nil;
        run(realMain, 2, input, 1500, @"success", &response);
        NSDictionary *decoded = [NSPropertyListSerialization propertyListWithData:response options:NSPropertyListImmutable format:NULL error:NULL];
        require([decoded[@"signature"] isEqual:input], "real signer-main roundtrip preserves input bytes");
        run(realMain, 0, [NSData data], 1500, @"probe_complete", &response);
        decoded = [NSPropertyListSerialization propertyListWithData:response options:NSPropertyListImmutable format:NULL error:NULL];
        require([decoded[@"supported"] isEqual:@NO], "real signer-main preserves unsupported probe");
        printf("PASS: subprocess + real signer-main synthetic tests checks=%u; no Apple services called\n", checks);
    }
    return 0;
}
