#import "guest-auth-experiment.h"
#import <objc/runtime.h>
#include <dlfcn.h>
#include <crt_externs.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// This library is loaded only by the explicit experimental launcher. It never
// writes the target bundle, patches system services, changes sysctl values, or
// substitutes an invented token. Every successful callback contains material
// returned by the current, explicitly enabled host session.
static NSString *sessionID, *launchID, *experimentMode;
static NSObject *stateLock;
static BOOL hostSupported, active;
static double stateAt, probeAt;
static dispatch_source_t stateTimer;
static dispatch_queue_t stateQueue;
static atomic_bool requestInFlight;
static IMP originalGenerate, originalSingle, originalMultiple;

static void event(NSString *request, NSString *stage, NSError *error, double started, NSUInteger inBytes, NSUInteger outBytes) {
    HengeAuthEvent(sessionID, launchID, request, stage, error,
                   started ? HengeAuthMonotonic() - started : 0, inBytes, outBytes);
}
static BOOL stateMatches(NSDictionary *state) {
    return [state[@"enabled"] boolValue] && [state[@"session"] isEqual:sessionID] &&
           [state[@"launch_id"] isEqual:launchID] && [state[@"mode"] isEqual:experimentMode];
}
static BOOL cachedActive(void) {
    @synchronized (stateLock) { return active && HengeAuthMonotonic() - stateAt <= 5; }
}
static void refreshState(void) {
    @autoreleasepool {
        NSError *error = nil;
        NSDictionary *state = HengeAuthReadState(&error);
        double now = HengeAuthMonotonic();
        if (!stateMatches(state)) {
            BOOL wasActive;
            @synchronized (stateLock) { wasActive = active; active = NO; hostSupported = NO; }
            if (wasActive) event(NSUUID.UUID.UUIDString, @"session_inactive", error ?: HengeAuthError(1002), 0, 0, 0);
            // A transient transport failure may recover. An explicit different,
            // disabled or expired session permanently ends this launch's timer.
            if (state && stateTimer) { dispatch_source_cancel(stateTimer); stateTimer = nil; }
            return;
        }
        BOOL needsProbe;
        @synchronized (stateLock) { active = YES; stateAt = now; needsProbe = !probeAt || now - probeAt >= 20; }
        if (!needsProbe || atomic_load(&requestInFlight)) return;
        NSString *request = NSUUID.UUID.UUIDString;
        double started = HengeAuthMonotonic();
        event(request, @"probe_requested", nil, 0, 0, 0);
        NSDictionary *probe = HengeAuthRequest(sessionID, launchID, @"probe", nil, request, 3, &error);
        @synchronized (stateLock) {
            if (probe) { hostSupported = [probe[@"supported"] boolValue]; probeAt = HengeAuthMonotonic(); }
            else if (!probeAt || HengeAuthMonotonic() - probeAt > 25) hostSupported = NO;
        }
        event(request, @"probe_result", error ?: (probe && ![probe[@"supported"] boolValue] ? HengeAuthError(1006) : nil),
              started, 0, 0);
    }
}
static BOOL supported(id self, SEL selector) {
    // A property getter must not block Electron's main thread on networking.
    // The value is a recent, real host probe, conditional on this exact active
    // launch. No fixed true value or fabricated support result is used.
    @synchronized (stateLock) {
        return active && hostSupported && HengeAuthMonotonic() - stateAt <= 5 &&
               HengeAuthMonotonic() - probeAt <= 25;
    }
}
static void generate(id self, SEL selector, id completion) {
    if (!HengeAuthCallbackABI(completion, 2)) {
        event(NSUUID.UUID.UUIDString, @"request_declined", HengeAuthError(1017), 0, 0, 0);
        ((void (*)(id, SEL, id))originalGenerate)(self, selector, completion);
        return;
    }
    void (^reply)(NSData *, NSError *) = [completion copy];
    NSString *request = NSUUID.UUID.UUIDString;
    if (atomic_exchange(&requestInFlight, true)) {
        event(request, @"request_declined", HengeAuthError(429), 0, 0, 0);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ reply(nil, HengeAuthError(429)); });
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            double started = HengeAuthMonotonic();
            event(request, @"token_requested", nil, 0, 0, 0);
            NSError *error = nil;
            NSDictionary *state = HengeAuthReadState(&error);
            NSDictionary *result = stateMatches(state)
                ? HengeAuthRequest(sessionID, launchID, @"dc_token", nil, request, 17, &error) : nil;
            if (!result && !error) error = HengeAuthError(1002);
            NSData *token = result[@"token"];
            if (!token.length && !error) error = HengeAuthError(1005);
            event(request, @"token_result", error, started, 0, token.length);
            atomic_store(&requestInFlight, false);
            reply(error ? nil : token, error);
        }
    });
}
static id immutablePayload(id payload, BOOL multiple) {
    if (!HengeAuthValidPayload(payload, multiple)) return nil;
    if (!multiple) return [payload copy];
    NSMutableDictionary *copy = [NSMutableDictionary dictionary];
    for (NSString *key in payload) copy[[key copy]] = [payload[key] copy];
    return [copy copy];
}
static NSUInteger payloadSize(id payload, BOOL multiple) {
    if (!multiple) return [payload length];
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:payload format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    return data.length;
}
static void signPayload(id self, SEL selector, id payload, id completion, BOOL multiple) {
    IMP original = multiple ? originalMultiple : originalSingle;
    NSString *request = NSUUID.UUID.UUIDString;
    NSString *requested = multiple ? @"baa_dictionary_requested" : @"baa_data_requested";
    NSString *finished = multiple ? @"baa_dictionary_result" : @"baa_data_result";
    NSString *operation = multiple ? @"baa_dictionary" : @"baa_data";
    event(request, requested, nil, 0, 0, 0);
    // Both methods are observed in public_token mode, but that mode does not
    // authorize host BAA signing. Preserve their original behavior.
    id frozen = immutablePayload(payload, multiple);
    if (![experimentMode isEqual:@"baa"] || !frozen || !HengeAuthCallbackABI(completion, 3)) {
        NSInteger code = ![experimentMode isEqual:@"baa"] ? 403 : frozen ? 1017 : 1004;
        event(request, @"request_declined", HengeAuthError(code), 0, 0, 0);
        ((void (*)(id, SEL, id, id))original)(self, selector, payload, completion);
        return;
    }
    void (^reply)(id, id, NSError *) = [completion copy];
    if (atomic_exchange(&requestInFlight, true)) {
        event(request, @"request_declined", HengeAuthError(429), 0, 0, 0);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ reply(nil, nil, HengeAuthError(429)); });
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            double started = HengeAuthMonotonic();
            NSError *error = nil;
            NSDictionary *state = HengeAuthReadState(&error);
            NSDictionary *result = stateMatches(state) ? HengeAuthRequest(sessionID, launchID, operation, frozen, request, 17, &error) : nil;
            if (!result && !error) error = HengeAuthError(1002);
            id signature = result[multiple ? @"signatures" : @"signature"], attestation = result[@"attestation"];
            if ((!signature || !attestation) && !error) error = HengeAuthError(1005);
            NSData *encoded = result ? [NSPropertyListSerialization dataWithPropertyList:result
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL] : nil;
            event(request, finished, error, started, payloadSize(frozen, multiple), encoded.length);
            atomic_store(&requestInFlight, false);
            reply(error ? nil : signature, error ? nil : attestation, error);
        }
    });
}
static void single(id self, SEL selector, id data, id completion) { signPayload(self, selector, data, completion, NO); }
static void multiple(id self, SEL selector, id dictionary, id completion) { signPayload(self, selector, dictionary, completion, YES); }
static BOOL supportABI(Class cls) {
    return HengeAuthMethodABI(cls, @selector(isSupported), "B", 0, NO) ||
           HengeAuthMethodABI(cls, @selector(isSupported), "c", 0, NO);
}
static NSString *environmentString(const char *key) {
    const char *value = getenv(key);
    return value && strlen(value) < PATH_MAX ? [NSString stringWithUTF8String:value] : nil;
}
__attribute__((constructor)) static void initializeAdapter(void) {
    @autoreleasepool {
        HengeAuthCaptureTestConfiguration();
        NSString *target = environmentString("HENGE_AUTH_TARGET");
        sessionID = [environmentString("HENGE_AUTH_SESSION") copy];
        launchID = [environmentString("HENGE_AUTH_LAUNCH_ID") copy];
        experimentMode = [environmentString("HENGE_AUTH_MODE") copy];
        // Do this before any target code can create Electron subprocesses.
        NSMutableArray<NSString *> *keys = [NSMutableArray array];
        for (char **entry = *_NSGetEnviron(); entry && *entry; entry++) {
            const char *equal = strchr(*entry, '=');
            if (!equal) continue;
            NSString *key = [[NSString alloc] initWithBytes:*entry length:(NSUInteger)(equal - *entry) encoding:NSUTF8StringEncoding];
            if ([key hasPrefix:@"DYLD_"] || [key hasPrefix:@"HENGE_AUTH_"]) [keys addObject:key];
        }
        for (NSString *key in keys) unsetenv(key.UTF8String);
        if (![[NSUUID alloc] initWithUUIDString:sessionID] || ![[NSUUID alloc] initWithUUIDString:launchID] ||
            ![@[@"public_token", @"baa"] containsObject:experimentMode ?: @""] || !target) return;
        NSError *error = nil;
        NSString *request = NSUUID.UUID.UUIDString;
        if (!HengeAuthCurrentProcessMatches(target, &error)) {
            event(request, @"adapter_target_rejected", error ?: HengeAuthError(1012), 0, 0, 0);
            return;
        }
        stateLock = [NSObject new];
        stateQueue = dispatch_queue_create("org.henge.auth.experiment.state", DISPATCH_QUEUE_SERIAL);
        event(request, @"adapter_loaded", nil, 0, 0, 0);
#ifndef HENGE_AUTH_TESTING
        // These are process-local loads only. Missing private APIs are reported
        // rather than replaced by a guessed ABI or an external system injection.
        dlopen("/System/Library/Frameworks/DeviceCheck.framework/DeviceCheck", RTLD_LAZY | RTLD_LOCAL);
        dlopen("/System/Library/PrivateFrameworks/DeviceCheckInternal.framework/DeviceCheckInternal", RTLD_LAZY | RTLD_LOCAL);
#endif
        Class device = NSClassFromString(@"DCDevice"), signer = NSClassFromString(@"DCBAASigner");
        SEL tokenSelector = NSSelectorFromString(@"generateTokenWithCompletionHandler:");
        SEL singleSelector = NSSelectorFromString(@"signatureForData:completion:");
        SEL multipleSelector = NSSelectorFromString(@"signaturesForData:completion:");
        BOOL tokenABI = HengeAuthMethodABI(device, tokenSelector, "v", 1, YES);
        BOOL singleABI = HengeAuthMethodABI(signer, singleSelector, "v", 2, YES);
        BOOL multipleABI = HengeAuthMethodABI(signer, multipleSelector, "v", 2, YES);
        if (([experimentMode isEqual:@"public_token"] && (!supportABI(device) || !tokenABI)) ||
            ([experimentMode isEqual:@"baa"] && (!singleABI || !multipleABI))) {
            event(request, @"adapter_abi_mismatch", HengeAuthError(1017), 0, 0, 0);
            return;
        }
        refreshState(); // A bounded real probe warms the getter before app main.
        if (!cachedActive()) {
            event(request, @"session_inactive", HengeAuthError(1002), 0, 0, 0);
            return;
        }
        if ([experimentMode isEqual:@"public_token"]) {
            (void)method_setImplementation(class_getInstanceMethod(device, @selector(isSupported)), (IMP)supported);
            originalGenerate = method_setImplementation(class_getInstanceMethod(device, tokenSelector), (IMP)generate);
        }
        if (singleABI) originalSingle = method_setImplementation(class_getInstanceMethod(signer, singleSelector), (IMP)single);
        if (multipleABI) originalMultiple = method_setImplementation(class_getInstanceMethod(signer, multipleSelector), (IMP)multiple);
        stateTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, stateQueue);
        dispatch_source_set_timer(stateTimer, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), 2 * NSEC_PER_SEC, NSEC_PER_SEC / 4);
        dispatch_source_set_event_handler(stateTimer, ^{ refreshState(); });
        dispatch_resume(stateTimer);
        event(request, @"adapter_ready", cachedActive() ? nil : HengeAuthError(1002), 0, 0, 0);
    }
}
