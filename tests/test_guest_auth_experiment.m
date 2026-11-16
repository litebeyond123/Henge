#import "../tools/guest-auth-experiment.h"
#import <AppKit/AppKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// This is our own signed fixture, not an OpenAI application. Its original
// methods deliberately cannot produce the mock host's synthetic result.
static NSUInteger originalTokens, originalSingles, originalMultiples;
@interface DCDevice : NSObject
+ (instancetype)currentDevice;
- (BOOL)isSupported;
- (void)generateTokenWithCompletionHandler:(void (^)(NSData *, NSError *))completion;
@end
@implementation DCDevice
+ (instancetype)currentDevice { static DCDevice *value; if (!value) value = [DCDevice new]; return value; }
- (BOOL)isSupported { return NO; }
- (void)generateTokenWithCompletionHandler:(void (^)(NSData *, NSError *))completion {
    originalTokens++;
    if (completion) completion(nil, [NSError errorWithDomain:@"FixtureOriginal" code:701 userInfo:nil]);
}
@end
@interface DCBAASigner : NSObject
+ (instancetype)sharedSigner;
- (void)signatureForData:(NSData *)data completion:(void (^)(id, id, NSError *))completion;
- (void)signaturesForData:(NSDictionary *)data completion:(void (^)(id, id, NSError *))completion;
@end
@implementation DCBAASigner
+ (instancetype)sharedSigner { static DCBAASigner *value; if (!value) value = [DCBAASigner new]; return value; }
- (void)signatureForData:(NSData *)data completion:(void (^)(id, id, NSError *))completion {
    (void)data; originalSingles++;
    if (completion) completion(@"ORIGINAL_SINGLE", @{@"original": @YES}, nil);
}
- (void)signaturesForData:(NSDictionary *)data completion:(void (^)(id, id, NSError *))completion {
    (void)data; originalMultiples++;
    if (completion) completion(@{@"original": @"ORIGINAL_MULTIPLE"}, @{@"original": @YES}, nil);
}
@end

static unsigned checks, failures;
static void check(BOOL ok, const char *message) {
    checks++; if (!ok) failures++;
    fprintf(stdout, "%s %s\n", ok ? "PASS" : "FAIL", message); fflush(stdout);
}
static NSString *const session = @"11111111-1111-4111-8111-111111111111";
static NSString *const launch = @"22222222-2222-4222-8222-222222222222";
static NSString *const request = @"33333333-3333-4333-8333-333333333333";
static NSData *json(id object) { return [NSJSONSerialization dataWithJSONObject:object options:0 error:NULL]; }
static NSData *windowMarker(BOOL visible, pid_t pid) {
    // C's unary ! has type int; @(!visible) becomes JSON 0/1 rather than true/false.
    return json(@{@"window_closed": visible ? @NO : @YES, @"pid": @(pid)});
}
static NSMutableDictionary *envelope(NSString *operation, NSDictionary *result) {
    NSData *bytes = [NSPropertyListSerialization dataWithPropertyList:result format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    return [@{@"protocol": @1, @"session": session, @"launch_id": launch, @"request_id": request,
              @"operation": operation, @"status": @"ok", @"resultBase64": [bytes base64EncodedStringWithOptions:0],
              @"diagnostics": @{@"status": @"success", @"errorDomain": @"", @"errorCode": @0}} mutableCopy];
}
static int unitTests(void) {
    NSMutableDictionary *state = [@{@"protocol": @1, @"enabled": @YES, @"session": session,
                                     @"launch_id": launch, @"mode": @"public_token"} mutableCopy];
    check(HengeAuthValidateState(json(state)) != nil, "current launch state accepted");
    state[@"protocol"] = @YES;
    check(HengeAuthValidateState(json(state)) == nil, "boolean protocol rejected");
    state[@"protocol"] = @1; state[@"mode"] = @"future";
    check(HengeAuthValidateState(json(state)) == nil, "unknown mode rejected");
    check(HengeAuthValidateState(json(@{@"protocol": @1, @"enabled": @NO})) != nil, "disabled state needs no reusable launch identity");
    NSData *token = [@"SYNTHETIC_TOKEN_DO_NOT_LOG" dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *wire = envelope(@"dc_token", @{@"token": token});
    NSError *error = nil;
    check([HengeAuthDecodeResponse(json(wire), 200, session, launch, request, @"dc_token", &error)[@"token"] isEqual:token],
          "binary property-list token returned intact");
    for (NSString *key in @[@"session", @"launch_id", @"request_id", @"operation"]) {
        id previous = wire[key]; wire[key] = @"wrong";
        check(HengeAuthDecodeResponse(json(wire), 200, session, launch, request, @"dc_token", &error) == nil,
              "response identity mismatch rejected");
        wire[key] = previous;
    }
    check(HengeAuthDecodeResponse(json(envelope(@"dc_token", @{@"token": [NSData data]})), 200,
                                  session, launch, request, @"dc_token", &error) == nil && error,
          "empty token is an error, never nil/nil success");
    wire[@"status"] = @"error";
    wire[@"diagnostics"] = @{@"errorDomain": @"com.apple.devicecheck.error", @"errorCode": @1};
    check(!HengeAuthDecodeResponse(json(wire), 200, session, launch, request, @"dc_token", &error) &&
          [error.domain isEqual:@"com.apple.devicecheck.error"] && error.code == 1, "native error domain and code preserved");
    wire[@"diagnostics"] = @{@"errorDomain": @"Fixture.Native.Error", @"errorCode": @(-123)};
    check(!HengeAuthDecodeResponse(json(wire), 200, session, launch, request, @"dc_token", &error) &&
          [error.domain isEqual:@"Fixture.Native.Error"] && error.code == -123, "bounded unknown native domain preserved for caller");
    wire[@"diagnostics"] = @{@"errorDomain": @"description with private content", @"errorCode": @1};
    check(!HengeAuthDecodeResponse(json(wire), 200, session, launch, request, @"dc_token", &error) &&
          [error.domain isEqual:HengeAuthBridgeErrorDomain], "arbitrary descriptive error domain rejected");
    check(!HengeAuthDecodeResponse(json(@{@"protocol": @1, @"error": @"disabled"}), 403, session, launch, request, @"dc_token", &error) &&
          [error.domain isEqual:HengeAuthBridgeErrorDomain] && error.code == 403, "host revocation without result envelope remains a bridge error");
    check(HengeAuthValidPayload(token, NO), "single BAA data accepted");
    check(!HengeAuthValidPayload(@"not data", NO), "single BAA wrong class rejected");
    check(HengeAuthValidPayload(@{@"request": token, @"nonce": token}, YES), "dictionary BAA preserves NSData values");
    check(!HengeAuthValidPayload(@{@"request": @"not data"}, YES), "dictionary BAA string value rejected");
    NSMutableDictionary *many = [NSMutableDictionary dictionary];
    for (NSUInteger i = 0; i < 32; i++) many[[NSString stringWithFormat:@"k%lu", (unsigned long)i]] = [NSData dataWithBytes:"x" length:1];
    check(HengeAuthValidPayload(many, YES), "32 dictionary entries accepted");
    many[@"extra"] = token;
    check(!HengeAuthValidPayload(many, YES), "33 dictionary entries rejected");
    check(!HengeAuthValidPayload(@{@"oversize": [NSMutableData dataWithLength:4097]}, YES), "per-entry BAA data bound enforced");
    void (^two)(id, id) = ^(id a, id b) { (void)a; (void)b; };
    void (^three)(id, id, id) = ^(id a, id b, id c) { (void)a; (void)b; (void)c; };
    check(HengeAuthCallbackABI(two, 2) && !HengeAuthCallbackABI(two, 3), "two-object callback ABI is exact");
    check(HengeAuthCallbackABI(three, 3) && !HengeAuthCallbackABI(three, 2), "three-object callback ABI is exact");
    void (^typedTwo)(NSData *, NSError *) = ^(NSData *data, NSError *error) { (void)data; (void)error; };
    void (^typedThree)(NSData *, NSDictionary *, NSError *) = ^(NSData *signature, NSDictionary *attestation, NSError *error) {
        (void)signature; (void)attestation; (void)error;
    };
    void (^pointer)(void *, id) = ^(void *value, id other) { (void)value; (void)other; };
    void (^scalar)(NSInteger, id) = ^(NSInteger value, id other) { (void)value; (void)other; };
    void (^nestedBlock)(void (^)(void), id) = ^(void (^value)(void), id other) { (void)value; (void)other; };
    check(HengeAuthCallbackABI(typedTwo, 2), "NSData/NSError callback accepts typed object encodings");
    check(HengeAuthCallbackABI(typedThree, 3), "typed signature/attestation/error callback accepts object encodings");
    check(!HengeAuthCallbackABI(pointer, 2), "raw pointer is not accepted as a callback object");
    check(!HengeAuthCallbackABI(scalar, 2), "scalar is not accepted as a callback object");
    check(!HengeAuthCallbackABI(nestedBlock, 2), "nested block is not accepted as an ordinary callback object");
    check(HengeAuthMethodABI(DCBAASigner.class, @selector(signatureForData:completion:), "v", 2, YES),
          "fixture private method has expected object/block ABI");
    NSString *flagsKey = (__bridge NSString *)kSecCodeInfoFlags, *entitlementsKey = (__bridge NSString *)kSecCodeInfoEntitlementsDict;
    NSDictionary *allowed = @{@"com.apple.security.cs.allow-dyld-environment-variables": @YES,
                              @"com.apple.security.cs.disable-library-validation": @YES};
    check(HengeAuthSignaturePolicy(@{flagsKey: @(kSecCodeSignatureRuntime), entitlementsKey: allowed}),
          "hardened runtime permits declared third-party dynamic library loading");
    check(!HengeAuthSignaturePolicy(@{flagsKey: @(kSecCodeSignatureRuntime), entitlementsKey:
          @{@"com.apple.security.cs.disable-library-validation": @YES}}), "missing DYLD entitlement blocks launch");
    check(!HengeAuthSignaturePolicy(@{flagsKey: @(kSecCodeSignatureRuntime), entitlementsKey:
          @{@"com.apple.security.cs.allow-dyld-environment-variables": @YES}}), "missing library-validation exception blocks launch");
    check(!HengeAuthSignaturePolicy(@{flagsKey: @(kSecCodeSignatureLibraryValidation)}), "explicit library validation blocks foreign adapter");
    for (unsigned mask = 0; mask < 16; mask++) {
        BOOL runtime = (mask & 1) != 0, libraryFlag = (mask & 2) != 0;
        BOOL dyld = (mask & 4) != 0, exception = (mask & 8) != 0;
        uint32_t flags = (runtime ? kSecCodeSignatureRuntime : 0) | (libraryFlag ? kSecCodeSignatureLibraryValidation : 0);
        NSDictionary *info = @{flagsKey: @(flags), entitlementsKey:
            @{@"com.apple.security.cs.allow-dyld-environment-variables": @(dyld),
              @"com.apple.security.cs.disable-library-validation": @(exception)}};
        NSDictionary *facts = HengeAuthSignaturePolicySnapshot(info);
        NSDictionary *decoded = [NSJSONSerialization JSONObjectWithData:json(facts) options:0 error:NULL];
        BOOL booleanTypes = YES;
        for (NSString *key in @[@"flags_known", @"hardened_runtime", @"library_validation_flag",
                               @"dyld_environment_allowed", @"library_validation_exception", @"policy_allows_adapter"]) {
            id value = decoded[key];
            if (!value || CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID()) booleanTypes = NO;
        }
        BOOL allows = runtime ? (dyld && exception) : (!libraryFlag || exception);
        check(booleanTypes && [facts[@"flags_known"] boolValue] && [facts[@"hardened_runtime"] boolValue] == runtime &&
              [facts[@"library_validation_flag"] boolValue] == libraryFlag &&
              [facts[@"dyld_environment_allowed"] boolValue] == dyld &&
              [facts[@"library_validation_exception"] boolValue] == exception &&
              [facts[@"policy_allows_adapter"] boolValue] == allows,
              "fixed policy facts retain flag/entitlement distinctions and original permission rule");
    }
    for (id flags in @[NSNull.null, @"runtime"]) {
        NSDictionary *facts = HengeAuthSignaturePolicySnapshot(@{flagsKey: flags, entitlementsKey: allowed});
        check(![facts[@"flags_known"] boolValue] && facts[@"hardened_runtime"] == nil &&
              facts[@"library_validation_flag"] == nil && ![facts[@"policy_allows_adapter"] boolValue],
              "unknown flags never become runtime/library-validation off");
    }
    NSDictionary *missingFlags = HengeAuthSignaturePolicySnapshot(@{});
    check(![missingFlags[@"flags_known"] boolValue] && missingFlags[@"hardened_runtime"] == nil,
          "absent flags remain unknown");
    for (NSNumber *visible in @[@NO, @YES]) {
        NSDictionary *marker = [NSJSONSerialization JSONObjectWithData:windowMarker(visible.boolValue, getpid()) options:0 error:NULL];
        id closed = marker[@"window_closed"];
        check(closed && CFGetTypeID((__bridge CFTypeRef)closed) == CFBooleanGetTypeID() &&
              [closed boolValue] == !visible.boolValue && [marker[@"pid"] intValue] == getpid(),
              "window marker serializes the real visibility inverse as JSON boolean with its exact PID");
    }
    fprintf(stdout, "guest auth unit checks=%u failures=%u\n", checks, failures); fflush(stdout);
    return failures ? 1 : 0;
}
static BOOL waitFor(dispatch_semaphore_t done) {
    return dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC)) == 0;
}
static int injectedFixture(void) {
    NSDictionary *info = NSBundle.mainBundle.infoDictionary;
    NSString *scenario = info[@"HengeFixtureScenario"], *resultPath = info[@"HengeFixtureResultPath"];
    BOOL ok = scenario.length && resultPath.length;
    // The original target's stdout and stderr must never become bridge logs.
    fprintf(stdout, "SYNTHETIC_CHAT_TEXT_DO_NOT_LOG\n");
    fprintf(stderr, "SYNTHETIC_COOKIE_DO_NOT_LOG\n");
    const char *keys[] = {"DYLD_INSERT_LIBRARIES", "HENGE_AUTH_SESSION", "HENGE_AUTH_LAUNCH_ID",
                         "HENGE_AUTH_MODE", "HENGE_AUTH_TARGET", NULL};
    for (NSUInteger i = 0; keys[i]; i++) if (getenv(keys[i])) ok = NO;
    // Spawn a real child after injection. It must not inherit DYLD or experiment
    // credentials, regardless of how Electron later starts its subprocesses.
    NSTask *child = [NSTask new];
    child.executableURL = [NSURL fileURLWithPath:@"/usr/bin/env"];
    NSPipe *pipe = [NSPipe pipe];
    child.standardOutput = pipe; child.standardError = NSFileHandle.fileHandleWithNullDevice;
    NSError *launchError = nil;
    if (![child launchAndReturnError:&launchError]) ok = NO;
    else {
        NSData *data = [pipe.fileHandleForReading readDataToEndOfFile];
        [child waitUntilExit];
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (child.terminationStatus || [text containsString:@"DYLD_INSERT_LIBRARIES="] || [text containsString:@"HENGE_AUTH_"]) ok = NO;
    }
    DCDevice *device = DCDevice.currentDevice;
    double started = HengeAuthMonotonic();
    BOOL support = device.isSupported;
    if (HengeAuthMonotonic() - started > 0.1) ok = NO;
    if ([scenario isEqual:@"unsupported"] || [scenario hasPrefix:@"baa"]) ok &= !support;
    else ok &= support;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSData *token;
    __block NSError *error;
    if ([scenario hasPrefix:@"baa"]) {
        __block id signature, attestation;
        NSData *payload = [@"SYNTHETIC_CHALLENGE_DO_NOT_LOG" dataUsingEncoding:NSUTF8StringEncoding];
        [DCBAASigner.sharedSigner signatureForData:payload completion:^(id s, id a, NSError *e) {
            signature = s; attestation = a; error = e; dispatch_semaphore_signal(done);
        }];
        ok &= waitFor(done) && !error && [signature isKindOfClass:NSData.class] &&
              [signature isEqual:[@"SYNTHETIC_SIGNATURE_DO_NOT_LOG" dataUsingEncoding:NSUTF8StringEncoding]] &&
              [attestation isKindOfClass:NSDictionary.class] && [attestation[@"kind"] isEqual:@"fixture"] && originalSingles == 0;
        signature = attestation = nil; error = nil;
        id dictionary = [scenario isEqual:@"baa_bad_input"] ? @{@"request": @"wrong type"} : @{@"request": payload, @"nonce": payload};
        [DCBAASigner.sharedSigner signaturesForData:dictionary completion:^(id s, id a, NSError *e) {
            signature = s; attestation = a; error = e; dispatch_semaphore_signal(done);
        }];
        ok &= waitFor(done);
        if ([scenario isEqual:@"baa_bad_input"]) ok &= originalMultiples == 1 && [signature[@"original"] isEqual:@"ORIGINAL_MULTIPLE"];
        else ok &= !error && originalMultiples == 0 && [signature isKindOfClass:NSDictionary.class] &&
                   [signature[@"request"] isKindOfClass:NSData.class] && [attestation isKindOfClass:NSArray.class];
        [device generateTokenWithCompletionHandler:^(NSData *t, NSError *e) { token = t; error = e; dispatch_semaphore_signal(done); }];
        ok &= waitFor(done) && !token && [error.domain isEqual:@"FixtureOriginal"] && originalTokens == 1;
    } else {
        [device generateTokenWithCompletionHandler:^(NSData *t, NSError *e) { token = t; error = e; dispatch_semaphore_signal(done); }];
        ok &= waitFor(done) && originalTokens == 0;
        if ([scenario isEqual:@"public_success"]) {
            ok &= !error && [token isEqual:[@"SYNTHETIC_TOKEN_DO_NOT_LOG" dataUsingEncoding:NSUTF8StringEncoding]];
            __block id signature;
            [DCBAASigner.sharedSigner signatureForData:[NSData dataWithBytes:"x" length:1] completion:^(id s, id a, NSError *e) {
                signature = s; (void)a; (void)e;
            }];
            ok &= originalSingles == 1 && [signature isEqual:@"ORIGINAL_SINGLE"];
        } else if ([scenario isEqual:@"unsupported"]) {
            ok &= !token && [error.domain isEqual:@"com.apple.devicecheck.error"] && error.code == 1;
        } else if ([scenario isEqual:@"token_error"]) {
            ok &= !token && [error.domain isEqual:@"Fixture.Native.Error"] && error.code == -123;
        } else if ([scenario isEqual:@"session_revoked"]) {
            ok &= !token && [error.domain isEqual:HengeAuthBridgeErrorDomain] && error.code == 1002;
        } else {
            ok &= !token && [error.domain isEqual:HengeAuthBridgeErrorDomain] && error.code == 1005;
        }
    }
    NSDictionary *result = @{@"passed": @(ok), @"scenario": scenario ?: @"missing",
                              @"original_token_calls": @(originalTokens),
                              @"original_single_calls": @(originalSingles), @"original_multiple_calls": @(originalMultiples)};
    NSData *data = json(result);
    if (![data writeToFile:resultPath options:NSDataWritingAtomic error:NULL]) return 2;
    // Let the last asynchronous fixed event reach the synthetic host.
    usleep(250000);
    return ok ? 0 : 1;
}
static int closedWindowFixture(NSString *marker) {
    // Only our owned fixture uses this entry point. Close a real AppKit window,
    // keep the main process running, and exit cooperatively when the test asks.
    NSApplication *application = NSApplication.sharedApplication;
    [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [application finishLaunching];
    NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 120, 80)
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable backing:NSBackingStoreBuffered defer:NO];
    window.releasedWhenClosed = NO;
    window.animationBehavior = NSWindowAnimationBehaviorNone;
    [window orderFront:nil];
    [window close];
    double closeDeadline = HengeAuthMonotonic() + 1;
    while (window.visible && HengeAuthMonotonic() < closeDeadline)
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    // If AppKit did not close the window in time, retain false so the strict
    // parent assertion fails with observable state rather than claiming closure.
    NSData *data = windowMarker(window.visible, getpid());
    if (![data writeToFile:marker options:NSDataWritingAtomic error:NULL]) return 2;
    NSString *stop = [marker stringByAppendingString:@".stop"];
    double deadline = HengeAuthMonotonic() + 60;
    while (HengeAuthMonotonic() < deadline) {
        if ([NSFileManager.defaultManager fileExistsAtPath:stop]) return 0;
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    }
    return 3;
}
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 2 && !strcmp(argv[1], "--unit")) return unitTests();
        if (argc == 3 && !strcmp(argv[1], "--hold-closed-window"))
            return closedWindowFixture([NSString stringWithUTF8String:argv[2]]);
        return injectedFixture();
    }
}
