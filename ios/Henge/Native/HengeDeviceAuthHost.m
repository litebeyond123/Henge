#import "HengeDeviceAuthHost.h"
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dispatch/dispatch.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#if !__has_feature(objc_arc)
#error HengeDeviceAuthHost requires Objective-C ARC
#endif

/* Inspected deb: DCBAASigner method v32@0:8@16@?24 and a completion with
 * three pointer arguments (signature(s), attestation, error). Method encodings
 * only describe @?, not a private API's block internals. We additionally check
 * OUR compiler-emitted block signature. This guards known ABI shapes, not an
 * undocumented Apple change to the expected callback arity. Isolate BAA calls.
 */
static const char *HDADeviceFramework = "/System/Library/Frameworks/DeviceCheck.framework/DeviceCheck";
static const char *HDAInternalFramework = "/System/Library/PrivateFrameworks/DeviceCheckInternal.framework/DeviceCheckInternal";
static atomic_bool HDAPublicPending = false;
static atomic_bool HDABAAPending = false;

static double HDANow(void) {
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}

static dispatch_queue_t HDAWorkQueue(void) {
    return dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
}

static NSString *HDAOperationName(uint32_t operation) {
    switch (operation) {
        case HENGE_DEVICE_AUTH_PROBE: return @"probe";
        case HENGE_DEVICE_AUTH_DC_TOKEN: return @"dc_token";
        case HENGE_DEVICE_AUTH_BAA_DATA: return @"baa_data";
        case HENGE_DEVICE_AUTH_BAA_DICTIONARY: return @"baa_dictionary";
        default: return @"invalid";
    }
}

static const char *HDAUnqualified(const char *type) {
    if (!type) return "";
    while (*type && strchr("rnNoORV", *type)) type++;
    return type;
}

static BOOL HDAObjectType(const char *type) {
    type = HDAUnqualified(type);
    return type[0] == '@' && type[1] != '?';
}

static BOOL HDAMethodEncoding(const char *encoding, BOOL publicToken) {
    if (!encoding) return NO;
    @try {
        NSMethodSignature *s = [NSMethodSignature signatureWithObjCTypes:encoding];
        NSUInteger count = publicToken ? 3 : 4;
        return s && s.numberOfArguments == count &&
            strcmp(HDAUnqualified(s.methodReturnType), "v") == 0 &&
            HDAObjectType([s getArgumentTypeAtIndex:0]) &&
            strcmp(HDAUnqualified([s getArgumentTypeAtIndex:1]), ":") == 0 &&
            (publicToken || HDAObjectType([s getArgumentTypeAtIndex:2])) &&
            strcmp(HDAUnqualified([s getArgumentTypeAtIndex:count - 1]), "@?") == 0;
    } @catch (__unused NSException *exception) { return NO; }
}

static BOOL HDAGetterEncoding(Method method, BOOL boolean) {
    if (!method) return NO;
    NSMethodSignature *s = [NSMethodSignature signatureWithObjCTypes:method_getTypeEncoding(method)];
    if (!s || s.numberOfArguments != 2 ||
        !HDAObjectType([s getArgumentTypeAtIndex:0]) ||
        strcmp(HDAUnqualified([s getArgumentTypeAtIndex:1]), ":") != 0) return NO;
    const char *ret = HDAUnqualified(s.methodReturnType);
    return boolean ? (strcmp(ret, "B") == 0 || strcmp(ret, "c") == 0) : HDAObjectType(ret);
}

static BOOL HDABlockEncoding(const char *encoding, NSUInteger arguments) {
    if (!encoding) return NO;
    @try {
        NSMethodSignature *s = [NSMethodSignature signatureWithObjCTypes:encoding];
        if (!s || s.numberOfArguments != arguments + 1 ||
            strcmp(HDAUnqualified(s.methodReturnType), "v") != 0 ||
            strcmp(HDAUnqualified([s getArgumentTypeAtIndex:0]), "@?") != 0) return NO;
        for (NSUInteger i = 1; i <= arguments; i++) {
            const char *type = HDAUnqualified([s getArgumentTypeAtIndex:i]);
            if (!HDAObjectType(type) && strcmp(type, "^v") != 0) return NO;
        }
        return YES;
    } @catch (__unused NSException *exception) { return NO; }
}

/* Clang Blocks ABI; inspect only blocks created in this translation unit. */
static BOOL HDACallbackABI(id block, NSUInteger arguments) {
    struct Literal { void *isa; int flags; int reserved; void *invoke; const void *descriptor; };
    const struct Literal *literal = (__bridge const void *)block;
    if (!literal || !(literal->flags & (1 << 30)) || !literal->descriptor) return NO;
    const uint8_t *cursor = literal->descriptor;
    cursor += 2 * sizeof(unsigned long); /* reserved, size */
    if (literal->flags & (1 << 25)) cursor += 2 * sizeof(void *); /* copy, dispose */
    const char *signature = NULL;
    memcpy(&signature, cursor, sizeof(signature));
    return HDABlockEncoding(signature, arguments);
}

static BOOL HDALoadDevice(void) {
    static void *handle;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ handle = dlopen(HDADeviceFramework, RTLD_LAZY | RTLD_LOCAL); });
    return handle != NULL; /* Never unload classes while callbacks can be pending. */
}

static BOOL HDALoadInternal(void) {
    static void *handle;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ handle = dlopen(HDAInternalFramework, RTLD_LAZY | RTLD_LOCAL); });
    return handle != NULL;
}

static NSDictionary *HDAEntitlementPresence(void) {
    typedef CFTypeRef (*CreateTask)(CFAllocatorRef);
    typedef CFTypeRef (*CopyValue)(CFTypeRef, CFStringRef, CFErrorRef *);
    static CreateTask create;
    static CopyValue copy;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY | RTLD_LOCAL);
        create = security ? (CreateTask)dlsym(security, "SecTaskCreateFromSelf") : NULL;
        copy = security ? (CopyValue)dlsym(security, "SecTaskCopyValueForEntitlement") : NULL;
    });
    NSArray *keys = @[@"com.apple.mobileactivationd.device-identifiers", @"com.apple.mobileactivationd.spi",
        @"com.apple.security.attestation.access", @"keychain-access-groups",
        @"com.apple.private.security.no-sandbox", @"platform-application"];
    NSMutableDictionary *presence = [NSMutableDictionary dictionary];
    CFTypeRef task = create && copy ? create(kCFAllocatorDefault) : NULL;
    for (NSString *key in keys) {
        CFTypeRef value = task ? copy(task, (__bridge CFStringRef)key, NULL) : NULL;
        presence[key] = @(value != NULL); /* Presence only; no value or group names. */
        if (value) CFRelease(value);
    }
    BOOL readable = task != NULL;
    if (task) CFRelease(task);
    return @{@"entitlement_query_available": @(readable), @"entitlement_presence": presence};
}

static BOOL HDABoundedPlist(id value, NSUInteger depth, NSUInteger *nodes, NSUInteger *bytes) {
    if (!value || depth > 8 || ++*nodes > 1024) return NO;
    if ([value isKindOfClass:NSData.class]) *bytes += [(NSData *)value length];
    else if ([value isKindOfClass:NSString.class]) *bytes += [(NSString *)value lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    else if ([value isKindOfClass:NSNumber.class] || [value isKindOfClass:NSDate.class]) *bytes += 16;
    else if ([value isKindOfClass:NSArray.class]) {
        if ([(NSArray *)value count] > 256) return NO;
        for (id item in value) if (!HDABoundedPlist(item, depth + 1, nodes, bytes)) return NO;
    } else if ([value isKindOfClass:NSDictionary.class]) {
        if ([(NSDictionary *)value count] > 256) return NO;
        for (id key in value) {
            if (![key isKindOfClass:NSString.class] ||
                !HDABoundedPlist(key, depth + 1, nodes, bytes) ||
                !HDABoundedPlist(value[key], depth + 1, nodes, bytes)) return NO;
        }
    } else return NO;
    return *bytes <= HENGE_DEVICE_AUTH_MAX_RESULT_BYTES;
}

static NSData *HDAPlist(id value) {
    NSUInteger nodes = 0, bytes = 0;
    if (!HDABoundedPlist(value, 0, &nodes, &bytes)) return nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:value
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    return data.length && data.length <= HENGE_DEVICE_AUTH_MAX_RESULT_BYTES ? data : nil;
}

static BOOL HDANonemptyOpaqueValue(id value) {
    if ([value isKindOfClass:NSData.class] || [value isKindOfClass:NSString.class]) return [value length] > 0;
    if ([value isKindOfClass:NSArray.class] || [value isKindOfClass:NSDictionary.class]) return [value count] > 0;
    return NO;
}

/* Error domains are protocol labels, not arbitrary NSError descriptions. Unknown
 * domains are classified without copying caller-defined strings into diagnostics. */
static NSString *HDASafeErrorDomain(NSError *error) {
    static NSSet *known;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ known = [NSSet setWithArray:@[NSCocoaErrorDomain, NSPOSIXErrorDomain,
        NSOSStatusErrorDomain, NSMachErrorDomain, NSURLErrorDomain, @"com.apple.devicecheck.error",
        @"IDSBAASignerErrorDomain", @"DCErrorDomain", @"DeviceCheckErrorDomain",
        @"com.apple.DeviceCheck.error", @"com.apple.DeviceIdentity", @"com.apple.DeviceIdentity.ErrorDomain",
        @"com.apple.MobileActivation.ErrorDomain", @"com.apple.mobileactivation.ErrorDomain"]]; });
    return [known containsObject:error.domain] ? error.domain : @"other_domain";
}

@interface HDARequest : NSObject {
    NSLock *_lock;
    BOOL _finished;
    dispatch_source_t _timer;
    NSMutableDictionary *_diagnostics;
    double _started;
    HengeDeviceAuthHostCompletion _completion;
    void *_context;
}
- (instancetype)initWithOperation:(uint32_t)operation length:(size_t)length timeout:(uint32_t)timeout
                      completion:(HengeDeviceAuthHostCompletion)completion context:(void *)context;
- (void)armTimeout:(uint32_t)timeout;
- (BOOL)isFinished;
- (void)fields:(NSDictionary *)fields;
- (void)finish:(NSString *)status result:(NSDictionary *)result error:(NSError *)error;
@end

@implementation HDARequest
- (instancetype)initWithOperation:(uint32_t)operation length:(size_t)length timeout:(uint32_t)timeout
                      completion:(HengeDeviceAuthHostCompletion)completion context:(void *)context {
    if ((self = [super init])) {
        _lock = [NSLock new]; _started = HDANow(); _completion = completion; _context = context;
        _diagnostics = [@{@"operation": HDAOperationName(operation), @"inputBytes": @(length),
            @"timeoutMs": @(timeout), @"methodABIChecked": @NO, @"callbackABIChecked": @NO,
            @"signatureBytes": @0, @"attestationBytes": @0, @"serverAcceptanceVerified": @NO} mutableCopy];
    }
    return self;
}
- (void)armTimeout:(uint32_t)timeout {
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, HDAWorkQueue());
    _timer = timer;
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout * NSEC_PER_MSEC),
        DISPATCH_TIME_FOREVER, NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{ [self finish:@"timed_out" result:nil error:nil]; });
    dispatch_resume(timer);
}
- (BOOL)isFinished { [_lock lock]; BOOL done = _finished; [_lock unlock]; return done; }
- (void)fields:(NSDictionary *)fields {
    [_lock lock]; if (!_finished) [_diagnostics addEntriesFromDictionary:fields]; [_lock unlock];
}
- (void)finish:(NSString *)status result:(NSDictionary *)result error:(NSError *)error {
    [_lock lock];
    if (_finished) { [_lock unlock]; return; }
    _finished = YES;
    dispatch_source_t timer = _timer; _timer = nil;
    NSMutableDictionary *diagnostics = [_diagnostics mutableCopy];
    HengeDeviceAuthHostCompletion completion = _completion;
    void *context = _context;
    [_lock unlock];
    if (timer) dispatch_source_cancel(timer);
    NSData *encoded = nil;
    @try {
        if (!result && ([status isEqualToString:@"success"] || [status isEqualToString:@"probe_complete"]))
            status = @"invalid_response";
        if (result) {
            encoded = HDAPlist(result);
            if (!encoded) status = @"unsupported_result_type";
        }
        if (error) {
            diagnostics[@"errorDomain"] = HDASafeErrorDomain(error);
            diagnostics[@"errorCode"] = @(error.code);
        }
    } @catch (__unused NSException *exception) {
        encoded = nil; status = @"objc_exception";
    }
    if (![status isEqualToString:@"success"] && ![status isEqualToString:@"probe_complete"]) encoded = nil;
    diagnostics[@"status"] = status; diagnostics[@"outcome"] = status;
    diagnostics[@"latencyMs"] = @((uint64_t)MAX(0, (HDANow() - _started) * 1000));
    diagnostics[@"resultBytes"] = @(encoded.length);
    if (!diagnostics[@"errorDomain"]) diagnostics[@"errorDomain"] = @"";
    if (!diagnostics[@"errorCode"]) diagnostics[@"errorCode"] = @0;
    NSData *json = [NSJSONSerialization dataWithJSONObject:diagnostics options:0 error:NULL];
    if (!json) json = [@"{\"status\":\"diagnostic_encoding_failed\",\"outcome\":\"diagnostic_encoding_failed\"}" dataUsingEncoding:NSUTF8StringEncoding];
    dispatch_async(HDAWorkQueue(), ^{
        @autoreleasepool {
            completion(context, encoded.bytes, encoded.length, json.bytes, json.length);
        }
    });
}
@end

/* A timeout does not cancel Apple APIs. Keep its family busy until the actual
 * callback/exception, and release only once even if a faulty backend calls twice. */
@interface HDALease : NSObject { atomic_bool *_gate; atomic_bool _released; }
- (instancetype)initWithGate:(atomic_bool *)gate;
- (void)releaseGate;
@end
@implementation HDALease
- (instancetype)initWithGate:(atomic_bool *)gate {
    if ((self = [super init])) { _gate = gate; atomic_init(&_released, false); }
    return self;
}
- (void)releaseGate {
    if (!atomic_exchange(&_released, true)) atomic_store(_gate, false);
}
@end

static id HDADecodeInput(uint32_t operation, NSData *bytes) {
    if (operation == HENGE_DEVICE_AUTH_PROBE || operation == HENGE_DEVICE_AUTH_DC_TOKEN)
        return bytes.length ? nil : [NSData data];
    if (!bytes.length || bytes.length > HENGE_DEVICE_AUTH_MAX_INPUT_BYTES) return nil;
    if (operation == HENGE_DEVICE_AUTH_BAA_DATA) return bytes;
    if (operation != HENGE_DEVICE_AUTH_BAA_DICTIONARY) return nil;
    if (bytes.length < 8 || memcmp(bytes.bytes, "bplist00", 8) != 0) return nil;
    NSPropertyListFormat format = NSPropertyListBinaryFormat_v1_0;
    id value = [NSPropertyListSerialization propertyListWithData:bytes options:NSPropertyListImmutable
        format:&format error:NULL];
    if (![value isKindOfClass:NSDictionary.class] || [value count] == 0 || [value count] > 32) return nil;
    for (id key in value) {
        id data = value[key];
        if (![key isKindOfClass:NSString.class] || [key length] == 0 || [key length] > 128 ||
            ![data isKindOfClass:NSData.class] || [data length] == 0 || [data length] > 4096) return nil;
    }
    return value;
}

static BOOL HDADCDevice(id *device, BOOL *supported, HDARequest *request) {
    BOOL loaded = HDALoadDevice();
    Class cls = NSClassFromString(@"DCDevice");
    SEL current = sel_registerName("currentDevice"), support = sel_registerName("isSupported");
    Method getter = cls ? class_getClassMethod(cls, current) : NULL;
    Method check = cls ? class_getInstanceMethod(cls, support) : NULL;
    [request fields:@{@"dc_framework_available": @(loaded), @"dc_class_available": @(cls != Nil)}];
    if (!loaded || !cls || !HDAGetterEncoding(getter, NO) || !HDAGetterEncoding(check, YES)) return NO;
    id currentDevice = ((id (*)(id, SEL))objc_msgSend)((id)cls, current);
    if (!currentDevice) return NO;
    *supported = ((BOOL (*)(id, SEL))objc_msgSend)(currentDevice, support);
    *device = currentDevice;
    [request fields:@{@"dc_supported": @(*supported), @"dc_support_checked": @YES}];
    return YES;
}

static NSDictionary *HDAProbe(HDARequest *request) {
    id device = nil; BOOL supported = NO;
    BOOL checked = HDADCDevice(&device, &supported, request);
    Class dc = NSClassFromString(@"DCDevice");
    Method tokenMethod = dc ? class_getInstanceMethod(dc, sel_registerName("generateTokenWithCompletionHandler:")) : NULL;
    BOOL internal = HDALoadInternal(); Class baa = NSClassFromString(@"DCBAASigner");
    Method single = baa ? class_getInstanceMethod(baa, sel_registerName("signatureForData:completion:")) : NULL;
    Method multiple = baa ? class_getInstanceMethod(baa, sel_registerName("signaturesForData:completion:")) : NULL;
    Method shared = baa ? class_getClassMethod(baa, sel_registerName("sharedSigner")) : NULL;
    BOOL sharedOK = HDAGetterEncoding(shared, NO);
    NSMutableDictionary *result = [@{@"supported": @(supported), @"dc_supported": @(supported),
        @"dc_support_checked": @(checked), @"dc_framework_available": @(HDALoadDevice()),
        @"dc_class_available": @(dc != Nil),
        @"dc_method_available": @(tokenMethod && HDAMethodEncoding(method_getTypeEncoding(tokenMethod), YES)),
        @"baa_framework_available": @(internal), @"baa_class_available": @(baa != Nil),
        @"baa_single_available": @(sharedOK && single && HDAMethodEncoding(method_getTypeEncoding(single), NO)),
        @"baa_multiple_available": @(sharedOK && multiple && HDAMethodEncoding(method_getTypeEncoding(multiple), NO))} mutableCopy];
    [result addEntriesFromDictionary:HDAEntitlementPresence()];
    return result;
}

static void HDAAccept(uint32_t operation, id first, id attestation, NSError *error, HDARequest *request) {
    if ([request isFinished]) return;
    @try {
        if (error) {
            if (![error isKindOfClass:NSError.class]) [request finish:@"invalid_response" result:nil error:nil];
            else [request finish:@"native_error" result:nil error:error];
            return;
        }
        if (operation == HENGE_DEVICE_AUTH_DC_TOKEN) {
            if (![first isKindOfClass:NSData.class] || ![first length]) {
                [request finish:@"invalid_response" result:nil error:nil]; return;
            }
            [request finish:@"success" result:@{@"token": first} error:nil]; return;
        }
        BOOL validFirst = operation == HENGE_DEVICE_AUTH_BAA_DICTIONARY
            ? [first isKindOfClass:NSDictionary.class]
            : ([first isKindOfClass:NSData.class] || [first isKindOfClass:NSString.class] ||
               [first isKindOfClass:NSArray.class] || [first isKindOfClass:NSDictionary.class]);
        if (!validFirst || !HDANonemptyOpaqueValue(first) || !HDANonemptyOpaqueValue(attestation)) {
            [request finish:@"invalid_response" result:nil error:nil]; return;
        }
        NSData *firstPlist = HDAPlist(first), *attestationPlist = HDAPlist(attestation);
        if (!firstPlist || !attestationPlist) { [request finish:@"unsupported_result_type" result:nil error:nil]; return; }
        [request fields:@{@"signatureBytes": @([first isKindOfClass:NSData.class] ? [first length] : firstPlist.length),
            @"attestationBytes": @([attestation isKindOfClass:NSData.class] ? [attestation length] : attestationPlist.length)}];
        NSString *key = operation == HENGE_DEVICE_AUTH_BAA_DICTIONARY ? @"signatures" : @"signature";
        [request finish:@"success" result:@{key: first, @"attestation": attestation} error:nil];
    } @catch (__unused NSException *exception) { [request finish:@"objc_exception" result:nil error:nil]; }
}

static void HDAPerformNative(uint32_t operation, id input, HDARequest *request, HDALease *lease) {
    if (operation == HENGE_DEVICE_AUTH_PROBE) {
        NSDictionary *result = HDAProbe(request);
        [lease releaseGate]; [request finish:@"probe_complete" result:result error:nil]; return;
    }
    if (operation == HENGE_DEVICE_AUTH_DC_TOKEN) {
        id device = nil; BOOL supported = NO;
        if (!HDADCDevice(&device, &supported, request)) {
            [lease releaseGate]; [request finish:@"api_unavailable" result:nil error:nil]; return;
        }
        if (!supported) { [lease releaseGate]; [request finish:@"unsupported" result:nil error:nil]; return; }
        SEL selector = sel_registerName("generateTokenWithCompletionHandler:");
        Method method = class_getInstanceMethod([device class], selector);
        if (!method || !HDAMethodEncoding(method_getTypeEncoding(method), YES)) {
            [lease releaseGate]; [request finish:@"method_abi_mismatch" result:nil error:nil]; return;
        }
        void (^callback)(id, NSError *) = ^(id token, NSError *error) {
            [lease releaseGate]; HDAAccept(operation, token, nil, error, request);
        };
        if (!HDACallbackABI(callback, 2)) {
            [lease releaseGate]; [request finish:@"callback_abi_mismatch" result:nil error:nil]; return;
        }
        [request fields:@{@"methodABIChecked": @YES, @"callbackABIChecked": @YES}];
        ((void (*)(id, SEL, id))objc_msgSend)(device, selector, callback);
        return;
    }
    BOOL loaded = HDALoadInternal(); Class cls = NSClassFromString(@"DCBAASigner");
    [request fields:@{@"baa_framework_available": @(loaded), @"baa_class_available": @(cls != Nil)}];
    SEL shared = sel_registerName("sharedSigner");
    Method getter = cls ? class_getClassMethod(cls, shared) : NULL;
    if (!loaded || !cls || !HDAGetterEncoding(getter, NO)) {
        [lease releaseGate]; [request finish:@"api_unavailable" result:nil error:nil]; return;
    }
    id signer = ((id (*)(id, SEL))objc_msgSend)((id)cls, shared);
    SEL selector = sel_registerName(operation == HENGE_DEVICE_AUTH_BAA_DICTIONARY
        ? "signaturesForData:completion:" : "signatureForData:completion:");
    Method method = signer ? class_getInstanceMethod([signer class], selector) : NULL;
    if (!method || !HDAMethodEncoding(method_getTypeEncoding(method), NO)) {
        [lease releaseGate]; [request finish:@"method_abi_mismatch" result:nil error:nil]; return;
    }
    void (^callback)(id, id, NSError *) = ^(id first, id attestation, NSError *error) {
        [lease releaseGate]; HDAAccept(operation, first, attestation, error, request);
    };
    if (!HDACallbackABI(callback, 3)) {
        [lease releaseGate]; [request finish:@"callback_abi_mismatch" result:nil error:nil]; return;
    }
    [request fields:@{@"methodABIChecked": @YES, @"callbackABIChecked": @YES}];
    ((void (*)(id, SEL, id, id))objc_msgSend)(signer, selector, input, callback);
}

static void HDAStart(uint32_t operation, const void *input, size_t length, uint32_t timeout,
    id testBackend, HengeDeviceAuthHostCompletion completion, void *context) {
    if (!completion) return;
    timeout = timeout ? MIN(MAX(timeout, 100u), HENGE_DEVICE_AUTH_MAX_TIMEOUT_MS) : HENGE_DEVICE_AUTH_DEFAULT_TIMEOUT_MS;
    HDARequest *request = [[HDARequest alloc] initWithOperation:operation length:length timeout:timeout
        completion:completion context:context];
    [request armTimeout:timeout];
    if (operation > HENGE_DEVICE_AUTH_BAA_DICTIONARY || length > HENGE_DEVICE_AUTH_MAX_INPUT_BYTES || (length && !input)) {
        [request finish:@"invalid_request" result:nil error:nil]; return;
    }
    NSData *copied = nil;
    @try { copied = length ? [NSData dataWithBytes:input length:length] : [NSData data]; }
    @catch (__unused NSException *exception) { [request finish:@"objc_exception" result:nil error:nil]; return; }
    dispatch_async(HDAWorkQueue(), ^{
        @autoreleasepool {
            if ([request isFinished]) return;
            HDALease *lease = nil;
            @try {
                id decoded = HDADecodeInput(operation, copied);
                if (!decoded) { [request finish:@"invalid_request" result:nil error:nil]; return; }
                atomic_bool *gate = operation <= HENGE_DEVICE_AUTH_DC_TOKEN ? &HDAPublicPending : &HDABAAPending;
                HDALease *candidate = [[HDALease alloc] initWithGate:gate];
                if (!candidate) { [request finish:@"allocation_failed" result:nil error:nil]; return; }
                if (atomic_exchange(gate, true)) { [request finish:@"busy" result:nil error:nil]; return; }
                lease = candidate;
                if ([request isFinished]) { [lease releaseGate]; return; }
#if defined(HENGE_DEVICE_AUTH_HOST_TESTING)
                if (testBackend) {
                    id<HengeDeviceAuthHostTestBackend> backend = testBackend;
                    if (operation == HENGE_DEVICE_AUTH_PROBE) {
                        NSDictionary *result = [backend probe];
                        [lease releaseGate]; [request finish:@"probe_complete" result:result error:nil];
                    } else {
                        [backend performOperation:operation input:decoded completion:^(id first, id attestation, NSError *error) {
                            [lease releaseGate]; HDAAccept(operation, first, attestation, error, request);
                        }];
                    }
                    return;
                }
#else
                (void)testBackend;
#endif
                HDAPerformNative(operation, decoded, request, lease);
            } @catch (__unused NSException *exception) {
                [lease releaseGate]; [request finish:@"objc_exception" result:nil error:nil];
            }
        }
    });
}

void henge_device_auth_host_request(uint32_t operation, const void *input, size_t input_length,
    uint32_t timeout_ms, HengeDeviceAuthHostCompletion completion, void *context) {
    HDAStart(operation, input, input_length, timeout_ms, nil, completion, context);
}

#if defined(HENGE_DEVICE_AUTH_HOST_TESTING)
void HengeDeviceAuthHostRequestForTesting(uint32_t operation, const void *input, size_t input_length,
    uint32_t timeout_ms, id<HengeDeviceAuthHostTestBackend> backend,
    HengeDeviceAuthHostCompletion completion, void *context) {
    HDAStart(operation, input, input_length, timeout_ms, backend, completion, context);
}
BOOL HengeDeviceAuthHostMethodEncodingForTesting(const char *encoding, BOOL publicToken) {
    return HDAMethodEncoding(encoding, publicToken);
}
BOOL HengeDeviceAuthHostBlockEncodingForTesting(const char *encoding, NSUInteger arguments) {
    return HDABlockEncoding(encoding, arguments);
}
BOOL HengeDeviceAuthHostCompiledBlocksForTesting(void) {
    void (^token)(id, NSError *) = ^(__unused id data, __unused NSError *error) {};
    void (^baa)(id, id, NSError *) = ^(__unused id value, __unused id attestation, __unused NSError *error) {};
    return HDACallbackABI(token, 2) && HDACallbackABI(baa, 3);
}
#endif
