#import "guest-auth-experiment.h"
#import <AppKit/AppKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

NSString *const HengeAuthBridgeErrorDomain = @"HengeAuthBridge";
const NSUInteger HengeAuthResponseLimit = 96 * 1024;
static const NSUInteger inputLimit = 32 * 1024, resultLimit = 64 * 1024, ringLimit = 64 * 1024;
static const NSUInteger stateLimit = 32 * 1024;
static NSString *const statePath = @"/.henge/v1/auth/state";
static NSString *const requestPath = @"/.henge/v1/auth/request";
static NSString *const eventPath = @"/.henge/v1/auth/event";

enum {
    InvalidState = 1001, SessionInactive, SessionMismatch, InvalidPayload, InvalidResponse,
    HostUnsupported, SignaturePolicy = 1010, SignatureInvalid, TargetIdentity, TargetMissing,
    AlreadyRunning, LaunchFailed, AdapterNotLoaded, ABIInvalid, LaunchTimeout
};

NSError *HengeAuthError(NSInteger code) {
    return [NSError errorWithDomain:HengeAuthBridgeErrorDomain code:code userInfo:nil];
}
double HengeAuthMonotonic(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec + now.tv_nsec / 1e9;
}
static BOOL uuid(id value) {
    return [value isKindOfClass:NSString.class] && [value length] == 36 &&
           [[NSUUID alloc] initWithUUIDString:value] != nil;
}
static BOOL boolean(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID();
}
static BOOL integer(id value, long long low, long long high) {
    if (![value isKindOfClass:NSNumber.class] || boolean(value)) return NO;
    double n = [value doubleValue];
    return isfinite(n) && floor(n) == n && n >= low && n <= high;
}
static BOOL domain(id value) {
    if (![value isKindOfClass:NSString.class] || ![value length] || [value length] > 128) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"];
    return [value rangeOfCharacterFromSet:allowed.invertedSet].location == NSNotFound;
}
static NSDictionary *jsonDictionary(NSData *data, NSUInteger limit) {
    if (!data.length || data.length > limit) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}
NSDictionary *HengeAuthValidateState(NSData *data) {
    NSDictionary *raw = jsonDictionary(data, stateLimit);
    if (!raw || !integer(raw[@"protocol"], 1, 1) || !boolean(raw[@"enabled"])) return nil;
    if (![raw[@"enabled"] boolValue]) return @{@"enabled": @NO};
    if (!uuid(raw[@"session"]) || !uuid(raw[@"launch_id"]) ||
        ![@[@"public_token", @"baa"] containsObject:raw[@"mode"] ?: @""]) return nil;
    return @{@"enabled": @YES, @"session": raw[@"session"], @"launch_id": raw[@"launch_id"], @"mode": raw[@"mode"]};
}

#ifdef HENGE_AUTH_TESTING
static NSString *testAddress, *testLogDirectory, *testFixturePath;
static int testPort;
#endif
void HengeAuthCaptureTestConfiguration(void) {
#ifdef HENGE_AUTH_TESTING
    // Only fixture builds contain these overrides. Production always connects to
    // the guest-only Henge address and accepts only the OpenAI application.
    const char *port = getenv("HENGE_AUTH_TEST_PORT");
    if (port && strlen(port) <= 5) {
        char *end = NULL;
        long value = strtol(port, &end, 10);
        if (end && !*end && value > 0 && value <= 65535) { testAddress = @"127.0.0.1"; testPort = (int)value; }
    }
    const char *logs = getenv("HENGE_AUTH_TEST_LOG_DIRECTORY"), *fixture = getenv("HENGE_AUTH_TEST_APP");
    if (logs && strlen(logs) < PATH_MAX) testLogDirectory = [NSString stringWithUTF8String:logs];
    if (fixture && strlen(fixture) < PATH_MAX) testFixturePath = [[NSString stringWithUTF8String:fixture] stringByResolvingSymlinksInPath];
#endif
}
static int ready(int fd, short events, double deadline) {
    for (;;) {
        double left = deadline - HengeAuthMonotonic();
        if (left <= 0) { errno = ETIMEDOUT; return -1; }
        struct pollfd p = {.fd = fd, .events = events};
        int n = poll(&p, 1, (int)ceil(fmin(left, 20) * 1000));
        if (n < 0 && errno == EINTR) continue;
        if (!n) errno = ETIMEDOUT;
        return n > 0 ? 0 : -1;
    }
}
static BOOL writeAll(int fd, const void *bytes, size_t count, double deadline) {
    const char *p = bytes;
    while (count) {
        if (ready(fd, POLLOUT, deadline)) return NO;
        ssize_t n = send(fd, p, count, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return NO;
        p += n; count -= (size_t)n;
    }
    return YES;
}
NSData *HengeAuthHTTP(NSString *method, NSString *path, NSData *body, NSString *session,
                    NSUInteger limit, double seconds, int *status, NSError **error) {
    if (status) *status = 0;
    if (error) *error = nil;
    if (![@[statePath, requestPath, eventPath] containsObject:path ?: @""] ||
        ![@[@"GET", @"POST"] containsObject:method ?: @""] || (session && !uuid(session)) ||
        body.length > 128 * 1024 || limit > HengeAuthResponseLimit || seconds <= 0 || seconds > 20) {
        if (error) *error = HengeAuthError(InvalidPayload);
        return nil;
    }
    NSString *address = @"10.0.2.4";
    int port = 80;
#ifdef HENGE_AUTH_TESTING
    if (testAddress) { address = testAddress; port = testPort; }
#endif
    double deadline = HengeAuthMonotonic() + seconds;
    int fd = socket(AF_INET, SOCK_STREAM, 0), saved = 0;
    if (fd < 0) { saved = errno; goto failed; }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    int noSignal = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, sizeof noSignal);
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) { saved = errno; goto failed; }
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, address.UTF8String, &addr.sin_addr) != 1) { saved = EINVAL; goto failed; }
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr)) {
        if (errno != EINPROGRESS || ready(fd, POLLOUT, deadline)) { saved = errno; goto failed; }
        socklen_t size = sizeof saved;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &saved, &size) || saved) { if (!saved) saved = errno; goto failed; }
    }
    @autoreleasepool {
        NSString *sessionHeader = session ? [NSString stringWithFormat:@"X-Henge-Session: %@\r\n", session] : @"";
        NSString *headers = [NSString stringWithFormat:
            @"%@ %@ HTTP/1.1\r\nHost: %@\r\nContent-Type: application/json\r\nContent-Length: %lu\r\n%@Connection: close\r\n\r\n",
            method, path, address, (unsigned long)body.length, sessionHeader];
        NSData *head = [headers dataUsingEncoding:NSUTF8StringEncoding];
        if (!writeAll(fd, head.bytes, head.length, deadline) ||
            (body.length && !writeAll(fd, body.bytes, body.length, deadline))) { saved = errno ?: EIO; goto failed; }
        NSMutableData *all = [NSMutableData data];
        char block[8192];
        for (;;) {
            if (ready(fd, POLLIN, deadline)) { saved = errno; goto failed; }
            ssize_t n = recv(fd, block, sizeof block, 0);
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            if (n < 0) { saved = errno; goto failed; }
            if (!n) break;
            if (all.length + (NSUInteger)n > limit + 16384) { saved = EMSGSIZE; goto failed; }
            [all appendBytes:block length:(NSUInteger)n];
        }
        close(fd); fd = -1;
        NSData *separator = [NSData dataWithBytes:"\r\n\r\n" length:4];
        NSRange split = [all rangeOfData:separator options:0 range:NSMakeRange(0, all.length)];
        if (split.location == NSNotFound || split.location > 16384 || all.length - NSMaxRange(split) > limit) {
            if (error) *error = HengeAuthError(InvalidResponse);
            return nil;
        }
        NSString *headText = [[NSString alloc] initWithData:[all subdataWithRange:NSMakeRange(0, split.location)]
                                                  encoding:NSUTF8StringEncoding];
        int code = 0;
        if (!headText || sscanf(headText.UTF8String, "HTTP/1.%*d %d", &code) != 1 || code < 100 || code > 599) {
            if (error) *error = HengeAuthError(InvalidResponse);
            return nil;
        }
        if (status) *status = code;
        return [all subdataWithRange:NSMakeRange(NSMaxRange(split), all.length - NSMaxRange(split))];
    }
failed:
    if (fd >= 0) close(fd);
    if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:saved ?: EIO userInfo:nil];
    return nil;
}
NSDictionary *HengeAuthReadState(NSError **error) {
    int status = 0;
    NSData *data = HengeAuthHTTP(@"GET", statePath, nil, nil, stateLimit, 2, &status, error);
    if (!data) return nil;
    NSDictionary *state = status == 200 ? HengeAuthValidateState(data) : nil;
    if (!state && error) *error = HengeAuthError(InvalidState);
    return state;
}

static BOOL plistObject(id value, NSUInteger depth, NSUInteger *nodes) {
    if (!value || depth > 8 || ++*nodes > 1024) return NO;
    if ([value isKindOfClass:NSData.class]) return [value length] <= resultLimit;
    if ([value isKindOfClass:NSString.class]) return [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] <= resultLimit;
    if ([value isKindOfClass:NSNumber.class]) return isfinite([value doubleValue]);
    if ([value isKindOfClass:NSDate.class]) return YES;
    if ([value isKindOfClass:NSArray.class]) {
        if ([value count] > 256) return NO;
        for (id child in value) if (!plistObject(child, depth + 1, nodes)) return NO;
        return YES;
    }
    if ([value isKindOfClass:NSDictionary.class]) {
        if ([value count] > 256) return NO;
        for (id key in value) if (![key isKindOfClass:NSString.class] || [key length] > 256 ||
                                  !plistObject(value[key], depth + 1, nodes)) return NO;
        return YES;
    }
    return NO;
}
BOOL HengeAuthValidPayload(id payload, BOOL multiple) {
    if (!multiple) return [payload isKindOfClass:NSData.class] && [payload length] > 0 && [payload length] <= inputLimit;
    if (![payload isKindOfClass:NSDictionary.class] || ![payload count] || [payload count] > 32) return NO;
    NSUInteger total = 0;
    for (id key in payload) {
        id value = payload[key];
        if (![key isKindOfClass:NSString.class] || ![key length] || [key length] > 128 ||
            ![value isKindOfClass:NSData.class] || ![value length] || [value length] > 4096) return NO;
        total += [value length] + [key lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        if (total > inputLimit) return NO;
    }
    return YES;
}
static BOOL nonempty(id value) {
    if ([value respondsToSelector:@selector(length)]) return [value length] > 0;
    if ([value respondsToSelector:@selector(count)]) return [value count] > 0;
    return value != nil;
}
NSDictionary *HengeAuthDecodeResponse(NSData *data, int httpStatus, NSString *session,
                                     NSString *launchID, NSString *requestID, NSString *operation,
                                     NSError **error) {
    if (error) *error = nil;
    NSDictionary *raw = jsonDictionary(data, HengeAuthResponseLimit);
    if (!raw || !integer(raw[@"protocol"], 1, 1) ||
        ![raw[@"session"] isEqual:session] || ![raw[@"launch_id"] isEqual:launchID] ||
        ![raw[@"request_id"] isEqual:requestID] || ![raw[@"operation"] isEqual:operation] ||
        ![@[@"ok", @"error"] containsObject:raw[@"status"] ?: @""]) {
        if (error) *error = HengeAuthError(httpStatus >= 400 ? httpStatus : InvalidResponse);
        return nil;
    }
    if (![raw[@"status"] isEqual:@"ok"] || httpStatus != 200) {
        NSDictionary *d = [raw[@"diagnostics"] isKindOfClass:NSDictionary.class] ? raw[@"diagnostics"] : nil;
        if (domain(d[@"errorDomain"]) && integer(d[@"errorCode"], -9007199254740991LL, 9007199254740991LL)) {
            if (error) *error = [NSError errorWithDomain:d[@"errorDomain"] code:[d[@"errorCode"] longLongValue] userInfo:nil];
        } else if (error) *error = HengeAuthError(httpStatus == 200 ? InvalidResponse : httpStatus);
        return nil;
    }
    NSString *encoded = [raw[@"resultBase64"] isKindOfClass:NSString.class] ? raw[@"resultBase64"] : nil;
    NSData *bytes = encoded.length <= 90 * 1024 ? [[NSData alloc] initWithBase64EncodedString:encoded ?: @"" options:0] : nil;
    NSPropertyListFormat format = 0;
    id result = bytes.length && bytes.length <= resultLimit
        ? [NSPropertyListSerialization propertyListWithData:bytes options:NSPropertyListImmutable format:&format error:NULL] : nil;
    NSUInteger nodes = 0;
    BOOL valid = format == NSPropertyListBinaryFormat_v1_0 && [result isKindOfClass:NSDictionary.class] &&
                 plistObject(result, 0, &nodes);
    if (valid && [operation isEqual:@"probe"]) {
        for (NSString *key in @[@"supported", @"dc_supported", @"dc_support_checked", @"dc_framework_available",
                               @"dc_class_available", @"dc_method_available", @"baa_framework_available",
                               @"baa_class_available", @"baa_single_available", @"baa_multiple_available"])
            if (!boolean(result[key])) { valid = NO; break; }
        if (valid && ([result[@"supported"] boolValue] != [result[@"dc_supported"] boolValue] ||
                      ([result[@"supported"] boolValue] && ![result[@"dc_support_checked"] boolValue]))) valid = NO;
    } else if (valid && [operation isEqual:@"dc_token"]) {
        valid = [result[@"token"] isKindOfClass:NSData.class] && [result[@"token"] length] > 0;
    } else if (valid && ([operation isEqual:@"baa_data"] || [operation isEqual:@"baa_dictionary"])) {
        NSString *key = [operation isEqual:@"baa_data"] ? @"signature" : @"signatures";
        valid = nonempty(result[key]) && nonempty(result[@"attestation"]);
        if ([operation isEqual:@"baa_dictionary"] && ![result[key] isKindOfClass:NSDictionary.class]) valid = NO;
    } else valid = NO;
    if (!valid) { if (error) *error = HengeAuthError(InvalidResponse); return nil; }
    return result;
}
NSDictionary *HengeAuthRequest(NSString *session, NSString *launchID, NSString *operation,
                             id payload, NSString *requestID, double seconds, NSError **error) {
    if (error) *error = nil;
    BOOL single = [operation isEqual:@"baa_data"], multiple = [operation isEqual:@"baa_dictionary"];
    if (!uuid(session) || !uuid(launchID) || !uuid(requestID) ||
        ![@[@"probe", @"dc_token", @"baa_data", @"baa_dictionary"] containsObject:operation ?: @""] ||
        ((single || multiple) ? !HengeAuthValidPayload(payload, multiple) : payload != nil)) {
        if (error) *error = HengeAuthError(InvalidPayload); return nil;
    }
    NSMutableDictionary *request = [@{@"protocol": @1, @"request_id": requestID, @"launch_id": launchID,
                                      @"operation": operation} mutableCopy];
    if (payload) {
        NSData *bytes = single ? payload : [NSPropertyListSerialization dataWithPropertyList:payload
            format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
        if (!bytes.length || bytes.length > inputLimit) { if (error) *error = HengeAuthError(InvalidPayload); return nil; }
        request[@"payloadBase64"] = [bytes base64EncodedStringWithOptions:0];
    }
    NSData *body = [NSJSONSerialization dataWithJSONObject:request options:0 error:NULL];
    int status = 0;
    NSData *data = HengeAuthHTTP(@"POST", requestPath, body, session, HengeAuthResponseLimit, seconds, &status, error);
    if (!data) return nil;
    return HengeAuthDecodeResponse(data, status, session, launchID, requestID, operation, error);
}

static BOOL objectABI(const char *type) {
    if (!type) return NO;
    if (!strcmp(type, "@")) return YES;
    // A typed block preserves class/protocol annotations (for example
    // @"NSData"), whereas id is encoded as @. Both have the same object ABI.
    // @? remains a distinct block parameter; pointers and scalars are rejected.
    size_t length = strlen(type);
    return length >= 3 && length <= 512 && type[0] == '@' && type[1] == '"' && type[length - 1] == '"';
}
BOOL HengeAuthMethodABI(Class cls, SEL selector, const char *returnType, NSUInteger objects, BOOL finalBlock) {
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    if (!method || !method_getTypeEncoding(method)) return NO;
    @try {
        NSMethodSignature *s = [NSMethodSignature signatureWithObjCTypes:method_getTypeEncoding(method)];
        if (!s || strcmp(s.methodReturnType, returnType) || s.numberOfArguments != objects + 2) return NO;
        for (NSUInteger i = 2; i < s.numberOfArguments; i++) {
            const char *type = [s getArgumentTypeAtIndex:i];
            if (finalBlock && i + 1 == s.numberOfArguments) { if (strcmp(type, "@?")) return NO; }
            else if (!objectABI(type)) return NO;
        }
        return YES;
    } @catch (__unused NSException *exception) { return NO; }
}
BOOL HengeAuthCallbackABI(id callback, NSUInteger objects) {
    // Apple's Blocks ABI: inspect only an actual compiler block's signature.
    // A missing/changed signature causes the private hook to decline to its
    // original implementation; no guessed callback cast is invoked.
    if (!callback) return NO;
    NSString *name = NSStringFromClass(object_getClass(callback));
    if (![name containsString:@"Block"]) return NO;
    struct BlockPrefix { void *isa; int flags; int reserved; void *invoke; void *descriptor; };
    struct BlockPrefix *block = (__bridge void *)callback;
    if (!(block->flags & (1 << 30)) || !block->descriptor) return NO;
    const char *cursor = block->descriptor;
    cursor += 2 * sizeof(unsigned long);
    if (block->flags & (1 << 25)) cursor += 2 * sizeof(void *);
    const char *signature = *(const char **)cursor;
    if (!signature) return NO;
    @try {
        NSMethodSignature *s = [NSMethodSignature signatureWithObjCTypes:signature];
        if (!s || strcmp(s.methodReturnType, "v") || s.numberOfArguments != objects + 1 ||
            strcmp([s getArgumentTypeAtIndex:0], "@?")) return NO;
        for (NSUInteger i = 1; i < s.numberOfArguments; i++) if (!objectABI([s getArgumentTypeAtIndex:i])) return NO;
        return YES;
    } @catch (__unused NSException *exception) { return NO; }
}

static BOOL entitlement(NSDictionary *info, NSString *key) {
    NSDictionary *e = [info[(__bridge NSString *)kSecCodeInfoEntitlementsDict] isKindOfClass:NSDictionary.class]
        ? info[(__bridge NSString *)kSecCodeInfoEntitlementsDict] : nil;
    return boolean(e[key]) && [e[key] boolValue];
}
BOOL HengeAuthSignaturePolicy(NSDictionary *info) {
    NSNumber *flags = info[(__bridge NSString *)kSecCodeInfoFlags];
    if (![flags isKindOfClass:NSNumber.class]) return NO;
    uint32_t bits = flags.unsignedIntValue;
    if (bits & kSecCodeSignatureRuntime) {
        // Our independently signed library cannot satisfy OpenAI's Team ID.
        return entitlement(info, @"com.apple.security.cs.allow-dyld-environment-variables") &&
               entitlement(info, @"com.apple.security.cs.disable-library-validation");
    }
    return !(bits & kSecCodeSignatureLibraryValidation) ||
           entitlement(info, @"com.apple.security.cs.disable-library-validation");
}
NSDictionary *HengeAuthSignaturePolicySnapshot(NSDictionary *info) {
    id flags = info[(__bridge NSString *)kSecCodeInfoFlags];
    BOOL known = [flags isKindOfClass:NSNumber.class];
    NSMutableDictionary *facts = [@{@"flags_known": @(known),
        @"dyld_environment_allowed": @(entitlement(info, @"com.apple.security.cs.allow-dyld-environment-variables")),
        @"library_validation_exception": @(entitlement(info, @"com.apple.security.cs.disable-library-validation")),
        @"policy_allows_adapter": @(HengeAuthSignaturePolicy(info))} mutableCopy];
    if (known) {
        uint32_t bits = [flags unsignedIntValue];
        facts[@"hardened_runtime"] = @((bits & kSecCodeSignatureRuntime) != 0);
        facts[@"library_validation_flag"] = @((bits & kSecCodeSignatureLibraryValidation) != 0);
    }
    return facts;
}
static BOOL expectedBundle(NSString *bundlePath) {
    NSString *canonical = bundlePath.stringByResolvingSymlinksInPath;
#ifdef HENGE_AUTH_TESTING
    if (testFixturePath) return [canonical isEqual:testFixturePath];
#endif
    return [canonical isEqual:@"/Applications/ChatGPT.app"] ||
        [canonical isEqual:[[NSHomeDirectory() stringByAppendingPathComponent:@"Applications/ChatGPT.app"] stringByResolvingSymlinksInPath]];
}
static NSString *expectedIdentifier(void) {
#ifdef HENGE_AUTH_TESTING
    if (testFixturePath) return @"org.henge.auth.fixture";
#endif
    return @"com.openai.codex";
}
static NSString *expectedExecutable(void) {
#ifdef HENGE_AUTH_TESTING
    if (testFixturePath) return @"HengeAuthFixture";
#endif
    return @"ChatGPT";
}
static BOOL signingIdentity(NSDictionary *info) {
    if (![info[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:expectedIdentifier()]) return NO;
#ifdef HENGE_AUTH_TESTING
    if (testFixturePath) return YES;
#endif
    return [info[(__bridge NSString *)kSecCodeInfoTeamIdentifier] isEqual:@"2DC432GLL2"];
}
static NSDictionary *targetIdentityInformation(NSString *bundlePath, NSError **error) {
    if (error) *error = nil;
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
    NSString *executable = [bundle objectForInfoDictionaryKey:@"CFBundleExecutable"];
    if (!expectedBundle(bundlePath) || ![bundle.bundleIdentifier isEqual:expectedIdentifier()] ||
        ![executable isEqual:expectedExecutable()] || !bundle.executablePath) {
        if (error) *error = HengeAuthError(TargetIdentity); return nil;
    }
    NSString *expected = [[bundlePath stringByAppendingPathComponent:
        [@"Contents/MacOS" stringByAppendingPathComponent:expectedExecutable()]] stringByResolvingSymlinksInPath];
    if (![bundle.executablePath.stringByResolvingSymlinksInPath isEqual:expected]) {
        if (error) *error = HengeAuthError(TargetIdentity); return nil;
    }
    struct stat st;
    if (lstat(expected.fileSystemRepresentation, &st) || !S_ISREG(st.st_mode) || (st.st_mode & (S_ISUID | S_ISGID))) {
        if (error) *error = HengeAuthError(TargetIdentity); return nil;
    }
    SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:bundlePath],
                                                 kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL);
    if (status == errSecSuccess) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
    NSDictionary *info = CFBridgingRelease(information);
    if (code) CFRelease(code);
    if (status != errSecSuccess || !info) {
        if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil]; return nil;
    }
    if (!signingIdentity(info)) { if (error) *error = HengeAuthError(TargetIdentity); return nil; }
    return info;
}
BOOL HengeAuthTargetIdentity(NSString *bundlePath, BOOL checkPolicy, NSError **error) {
    NSDictionary *info = targetIdentityInformation(bundlePath, error);
    if (!info) return NO;
    if (checkPolicy && !HengeAuthSignaturePolicy(info)) { if (error) *error = HengeAuthError(SignaturePolicy); return NO; }
    return YES;
}
NSDictionary *HengeAuthTargetPreflight(NSString *bundlePath, NSError **error) {
    NSDictionary *info = targetIdentityInformation(bundlePath, error);
    if (!info) return nil;
    NSMutableDictionary *facts = [HengeAuthSignaturePolicySnapshot(info) mutableCopy];
    NSString *canonicalBundle = bundlePath.stringByResolvingSymlinksInPath;
    NSString *canonicalExecutable = [NSBundle bundleWithPath:canonicalBundle].executablePath.stringByResolvingSymlinksInPath;
    BOOL running = NO;
    for (NSRunningApplication *app in [NSRunningApplication runningApplicationsWithBundleIdentifier:expectedIdentifier()]) {
        // A closed window does not imply process exit. Match the validated
        // main executable and bundle, never an Electron child or another copy.
        if (!app.terminated && [app.bundleIdentifier isEqual:expectedIdentifier()] &&
            [app.bundleURL.path.stringByResolvingSymlinksInPath isEqual:canonicalBundle] &&
            [app.executableURL.path.stringByResolvingSymlinksInPath isEqual:canonicalExecutable]) {
            running = YES;
            break;
        }
    }
    facts[@"main_process_running"] = @(running);
    return facts;
}
BOOL HengeAuthCurrentProcessMatches(NSString *bundlePath, NSError **error) {
    if (error) *error = nil;
    char path[PATH_MAX]; uint32_t length = sizeof path;
    if (!expectedBundle(bundlePath) || _NSGetExecutablePath(path, &length) ||
        ![[[NSString stringWithUTF8String:path] stringByResolvingSymlinksInPath]
            isEqual:[[bundlePath stringByAppendingPathComponent:
                [@"Contents/MacOS" stringByAppendingPathComponent:expectedExecutable()]] stringByResolvingSymlinksInPath]]) {
        if (error) *error = HengeAuthError(TargetIdentity); return NO;
    }
    SecCodeRef selfCode = NULL;
    CFDictionaryRef information = NULL;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &selfCode);
    if (status == errSecSuccess) status = SecCodeCopySigningInformation((SecStaticCodeRef)selfCode, kSecCSSigningInformation, &information);
    NSDictionary *info = CFBridgingRelease(information);
    if (selfCode) CFRelease(selfCode);
    if (status != errSecSuccess || !signingIdentity(info)) {
        if (error) *error = HengeAuthError(TargetIdentity); return NO;
    }
    return YES;
}

NSString *HengeAuthEventPath(void) {
    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Logs/Henge"];
#ifdef HENGE_AUTH_TESTING
    if (testLogDirectory) directory = testLogDirectory;
#endif
    return [directory stringByAppendingPathComponent:@"AuthExperiment.events.jsonl"];
}
static NSArray *safeEvents(NSData *data) {
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text) return @[];
    NSMutableArray *events = [NSMutableArray array];
    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if (!line.length || [line lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 2048) continue;
        NSDictionary *event = jsonDictionary([line dataUsingEncoding:NSUTF8StringEncoding], 2048);
        if (event && uuid(event[@"launch_id"]) && uuid(event[@"request_id"]) &&
            [event[@"stage"] isKindOfClass:NSString.class]) [events addObject:event];
    }
    return events;
}
BOOL HengeAuthEventWasRecorded(NSString *launchID, NSString *stage) {
    int fd = open(HengeAuthEventPath().fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return NO;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > ringLimit ||
        st.st_uid != geteuid() || flock(fd, LOCK_SH | LOCK_NB)) { close(fd); return NO; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    ssize_t count = read(fd, data.mutableBytes, data.length);
    flock(fd, LOCK_UN); close(fd);
    if (count != (ssize_t)data.length) return NO;
    for (NSDictionary *event in safeEvents(data))
        if ([event[@"launch_id"] isEqual:launchID] && [event[@"stage"] isEqual:stage]) return YES;
    return NO;
}
static dispatch_group_t eventDeliveryGroup(void) {
    static dispatch_group_t group;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ group = dispatch_group_create(); });
    return group;
}
void HengeAuthFlushEvents(void) {
    (void)dispatch_group_wait(eventDeliveryGroup(), dispatch_time(DISPATCH_TIME_NOW, 2500 * NSEC_PER_MSEC));
}
static void appendEvent(NSData *line) {
    NSString *path = HengeAuthEventPath(), *directory = path.stringByDeletingLastPathComponent;
    [NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:YES
        attributes:@{NSFilePosixPermissions: @0700} error:NULL];
    struct stat directoryStat;
    if (lstat(directory.fileSystemRepresentation, &directoryStat) || !S_ISDIR(directoryStat.st_mode) ||
        directoryStat.st_uid != geteuid()) return;
    int fd = open(path.fileSystemRepresentation, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        flock(fd, LOCK_EX | LOCK_NB)) { close(fd); return; }
    if (st.st_size < 0 || st.st_size > ringLimit || (NSUInteger)st.st_size + line.length > ringLimit) {
        // This file contains fixed events only. Retain a bounded complete-line
        // suffix; never read or copy stdout/stderr from the target application.
        off_t start = st.st_size > (off_t)(ringLimit / 2) ? st.st_size - (off_t)(ringLimit / 2) : 0;
        lseek(fd, start, SEEK_SET);
        char old[32768];
        ssize_t count = read(fd, old, sizeof old);
        NSUInteger offset = 0;
        if (start && count > 0) { while (offset < (NSUInteger)count && old[offset++] != '\n') {} }
        ftruncate(fd, 0); lseek(fd, 0, SEEK_SET);
        if (count > 0 && offset < (NSUInteger)count) (void)write(fd, old + offset, (NSUInteger)count - offset);
    }
    lseek(fd, 0, SEEK_END);
    (void)write(fd, line.bytes, line.length);
    flock(fd, LOCK_UN); close(fd);
}
void HengeAuthEvent(NSString *session, NSString *launchID, NSString *requestID, NSString *stage,
                   NSError *error, double elapsedSeconds, NSUInteger inputBytes, NSUInteger resultBytes) {
    if (!uuid(session) || !uuid(launchID) || !uuid(requestID)) return;
    NSArray *stages = @[@"launch_requested", @"target_not_found", @"target_identity_mismatch", @"target_signature_invalid",
        @"target_process_running", @"target_process_not_running", @"policy_flags_unavailable",
        @"policy_runtime_on", @"policy_runtime_off", @"policy_library_flag_on", @"policy_library_flag_off",
        @"policy_dyld_env_allowed", @"policy_dyld_env_not_allowed", @"policy_library_exception_on", @"policy_library_exception_off",
        @"signature_policy_blocked", @"already_running", @"launch_started", @"launch_failed", @"launch_timeout",
        @"adapter_loaded", @"adapter_not_loaded", @"adapter_target_rejected", @"adapter_abi_mismatch", @"adapter_ready",
        @"probe_requested", @"probe_result", @"token_requested", @"token_result", @"baa_data_requested", @"baa_data_result",
        @"baa_dictionary_requested", @"baa_dictionary_result", @"request_declined", @"transport_failed", @"response_invalid", @"session_inactive"];
    if (![stages containsObject:stage]) return;
    NSArray *domains = @[@"HengeAuthBridge", @"HengeDeviceAuthHost", @"NSURLErrorDomain", @"NSPOSIXErrorDomain",
        @"NSOSStatusErrorDomain", @"DCErrorDomain", @"DeviceCheckErrorDomain", @"NSCocoaErrorDomain",
        @"com.apple.devicecheck.error", @"com.apple.MobileActivation.ErrorDomain", @"IDSBAASignerErrorDomain"];
    NSString *safeDomain = error ? ([domains containsObject:error.domain] ? error.domain : @"other") : @"";
    NSDictionary *event = @{@"protocol": @1, @"launch_id": launchID, @"request_id": requestID, @"stage": stage,
        @"errorDomain": safeDomain, @"errorCode": @(error ? MAX((NSInteger)INT32_MIN, MIN((NSInteger)INT32_MAX, error.code)) : 0),
        @"elapsedMs": @((NSUInteger)(fmin(fmax(isfinite(elapsedSeconds) ? elapsedSeconds : 0, 0), 300) * 1000)),
        @"inputBytes": @(MIN(inputBytes, 128 * 1024)), @"resultBytes": @(MIN(resultBytes, HengeAuthResponseLimit))};
    NSData *data = [NSJSONSerialization dataWithJSONObject:event options:NSJSONWritingSortedKeys error:NULL];
    if (!data.length || data.length > 2048) return;
    NSMutableData *line = [data mutableCopy]; [line appendBytes:"\n" length:1];
    appendEvent(line);
    // Event delivery is best effort, never recursively logs transport failures,
    // and never delays a native completion. Only the bounded safe JSON is queued.
    dispatch_group_async(eventDeliveryGroup(), dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            int status = 0;
            (void)HengeAuthHTTP(@"POST", eventPath, data, session, 4096, 2, &status, NULL);
        }
    });
}

static NSString *findTarget(void) {
#ifdef HENGE_AUTH_TESTING
    if (testFixturePath) return testFixturePath;
#endif
    for (NSString *path in @[@"/Applications/ChatGPT.app", [NSHomeDirectory() stringByAppendingPathComponent:@"Applications/ChatGPT.app"]])
        if ([NSFileManager.defaultManager fileExistsAtPath:path]) return path.stringByResolvingSymlinksInPath;
    return nil;
}
static NSString *resource(NSString *name) {
    NSString *path = [NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:name];
    if ([NSFileManager.defaultManager fileExistsAtPath:path]) return path;
    // A command-line launcher's adapter is beside it inside the helper bundle.
    path = [[[NSProcessInfo.processInfo.arguments firstObject] stringByDeletingLastPathComponent] stringByAppendingPathComponent:name];
    return [NSFileManager.defaultManager fileExistsAtPath:path] ? path.stringByResolvingSymlinksInPath : nil;
}
static NSMutableDictionary *launchEnvironment(void) {
    NSMutableDictionary *environment = [NSProcessInfo.processInfo.environment mutableCopy];
    for (NSString *key in [environment.allKeys copy])
        if ([key hasPrefix:@"DYLD_"] || [key hasPrefix:@"HENGE_AUTH_"]) [environment removeObjectForKey:key];
#ifdef HENGE_AUTH_TESTING
    // Fixture configuration is deliberately absent from production builds.
    for (NSString *key in @[@"HENGE_AUTH_TEST_PORT", @"HENGE_AUTH_TEST_LOG_DIRECTORY", @"HENGE_AUTH_TEST_APP", @"HENGE_AUTH_TEST_SCENARIO"])
        if (NSProcessInfo.processInfo.environment[key]) environment[key] = NSProcessInfo.processInfo.environment[key];
#endif
    return environment;
}
int HengeGuestAuthExperimentRun(NSArray<NSString *> *arguments) {
    HengeAuthCaptureTestConfiguration();
    if (arguments.count != 6 || ![arguments[0] isEqual:@"--session"] || ![arguments[2] isEqual:@"--launch-id"] ||
        ![arguments[4] isEqual:@"--mode"] || !uuid(arguments[1]) || !uuid(arguments[3]) ||
        ![@[@"public_token", @"baa"] containsObject:arguments[5]]) return 64;
    NSString *session = arguments[1], *launchID = arguments[3], *mode = arguments[5], *requestID = NSUUID.UUID.UUIDString;
    double started = HengeAuthMonotonic();
    void (^event)(NSString *, NSError *) = ^(NSString *stage, NSError *error) {
        HengeAuthEvent(session, launchID, requestID, stage, error, HengeAuthMonotonic() - started, 0, 0);
        fprintf(stdout, "henge-auth stage=%s errorCode=%ld\n", stage.UTF8String, (long)(error ? error.code : 0));
        fflush(stdout);
    };
    event(@"launch_requested", nil);
    NSError *error = nil;
    NSDictionary *state = HengeAuthReadState(&error);
    if (![state[@"enabled"] boolValue] || ![state[@"session"] isEqual:session] ||
        ![state[@"launch_id"] isEqual:launchID] || ![state[@"mode"] isEqual:mode]) {
        event(@"session_inactive", error ?: HengeAuthError(SessionInactive)); return 1;
    }
    NSString *target = findTarget();
    if (!target) { event(@"target_not_found", HengeAuthError(TargetMissing)); return 1; }
    NSDictionary *preflight = HengeAuthTargetPreflight(target, &error);
    if (!preflight) {
        NSString *stage = [error.domain isEqual:HengeAuthBridgeErrorDomain] && error.code == TargetIdentity
            ? @"target_identity_mismatch" : @"target_signature_invalid";
        event(stage, error); return 1;
    }
    event([preflight[@"main_process_running"] boolValue] ? @"target_process_running" : @"target_process_not_running", nil);
    if ([preflight[@"flags_known"] boolValue]) {
        event([preflight[@"hardened_runtime"] boolValue] ? @"policy_runtime_on" : @"policy_runtime_off", nil);
        event([preflight[@"library_validation_flag"] boolValue] ? @"policy_library_flag_on" : @"policy_library_flag_off", nil);
    } else event(@"policy_flags_unavailable", nil);
    event([preflight[@"dyld_environment_allowed"] boolValue] ? @"policy_dyld_env_allowed" : @"policy_dyld_env_not_allowed", nil);
    event([preflight[@"library_validation_exception"] boolValue] ? @"policy_library_exception_on" : @"policy_library_exception_off", nil);
    if (![preflight[@"policy_allows_adapter"] boolValue]) {
        event(@"signature_policy_blocked", HengeAuthError(SignaturePolicy)); return 1;
    }
    if ([preflight[@"main_process_running"] boolValue]) {
        event(@"already_running", HengeAuthError(AlreadyRunning)); return 1;
    }
    NSString *adapter = resource(@"henge-auth-adapter.dylib");
    if (!adapter || [adapter containsString:@":"]) { event(@"launch_failed", HengeAuthError(LaunchFailed)); return 1; }
    // Check that the independently signed adapter is intact as well. The target
    // remains untouched, including Info.plist, resources and its code signature.
    SecStaticCodeRef adapterCode = NULL;
    OSStatus adapterStatus = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:adapter],
                                                        kSecCSDefaultFlags, &adapterCode);
    if (adapterStatus == errSecSuccess) adapterStatus = SecStaticCodeCheckValidity(adapterCode, kSecCSStrictValidate, NULL);
    if (adapterCode) CFRelease(adapterCode);
    if (adapterStatus != errSecSuccess) { event(@"launch_failed", [NSError errorWithDomain:NSOSStatusErrorDomain code:adapterStatus userInfo:nil]); return 1; }
    state = HengeAuthReadState(&error);
    if (![state[@"enabled"] boolValue] || ![state[@"session"] isEqual:session] ||
        ![state[@"launch_id"] isEqual:launchID] || ![state[@"mode"] isEqual:mode]) {
        event(@"session_inactive", error ?: HengeAuthError(SessionInactive)); return 1;
    }
    if (HengeAuthMonotonic() - started > 35) { event(@"launch_timeout", HengeAuthError(LaunchTimeout)); return 1; }
    NSMutableDictionary *environment = launchEnvironment();
    environment[@"DYLD_INSERT_LIBRARIES"] = adapter;
    environment[@"HENGE_AUTH_SESSION"] = session;
    environment[@"HENGE_AUTH_LAUNCH_ID"] = launchID;
    environment[@"HENGE_AUTH_MODE"] = mode;
    environment[@"HENGE_AUTH_TARGET"] = target;
    NSTask *task = [NSTask new];
    task.executableURL = [NSURL fileURLWithPath:[NSBundle bundleWithPath:target].executablePath];
    task.environment = environment;
    task.arguments = @[];
    task.standardInput = NSFileHandle.fileHandleWithNullDevice;
    task.standardOutput = NSFileHandle.fileHandleWithNullDevice;
    task.standardError = NSFileHandle.fileHandleWithNullDevice;
    if (![task launchAndReturnError:&error]) { event(@"launch_failed", error ?: HengeAuthError(LaunchFailed)); return 1; }
    event(@"launch_started", nil);
    double deadline = MIN(started + 40, HengeAuthMonotonic() + 30);
    while (HengeAuthMonotonic() < deadline) {
        if (HengeAuthEventWasRecorded(launchID, @"adapter_ready")) return 0;
        if (HengeAuthEventWasRecorded(launchID, @"adapter_target_rejected") ||
            HengeAuthEventWasRecorded(launchID, @"adapter_abi_mismatch") ||
            HengeAuthEventWasRecorded(launchID, @"session_inactive")) return 1;
        if (!task.running) break;
        usleep(100000);
    }
    event(@"adapter_not_loaded", HengeAuthError(AdapterNotLoaded));
    // Failure never force-quits the target. The user can close it normally.
    return 1;
}
void HengeGuestAuthExperimentPoll(HengeGuestAuthTransport transport) {
    static atomic_bool polling;
    static NSString *lastLaunch, *lastSession;
    if (!transport || atomic_exchange(&polling, true)) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            @try {
                int status = 0;
                NSData *data = transport(@"GET", statePath, nil, nil, stateLimit, &status);
                NSDictionary *state = status == 200 ? HengeAuthValidateState(data) : nil;
                if (![state[@"enabled"] boolValue] || [lastLaunch isEqual:state[@"launch_id"]]) return;
                lastLaunch = [state[@"launch_id"] copy]; // One attempt for each explicit host launch.
                lastSession = [state[@"session"] copy];
                NSString *path = resource(@"henge-auth-launcher");
                NSString *requestID = NSUUID.UUID.UUIDString;
                double started = HengeAuthMonotonic();
                if (!path) {
                    HengeAuthEvent(state[@"session"], lastLaunch, requestID, @"launch_failed", HengeAuthError(LaunchFailed), 0, 0, 0);
                    return;
                }
                NSTask *task = [NSTask new];
                task.executableURL = [NSURL fileURLWithPath:path];
                task.arguments = @[@"--session", state[@"session"], @"--launch-id", lastLaunch, @"--mode", state[@"mode"]];
                task.environment = launchEnvironment();
                task.standardInput = NSFileHandle.fileHandleWithNullDevice;
                task.standardOutput = NSFileHandle.fileHandleWithNullDevice;
                task.standardError = NSFileHandle.fileHandleWithNullDevice;
                NSError *error = nil;
                if (![task launchAndReturnError:&error]) {
                    HengeAuthEvent(state[@"session"], lastLaunch, requestID, @"launch_failed", error, HengeAuthMonotonic() - started, 0, 0);
                    return;
                }
                while (task.running && HengeAuthMonotonic() - started < 45) usleep(100000);
                if (task.running) {
                    [task terminate]; // Only our launcher; never the ChatGPT process.
                    HengeAuthEvent(state[@"session"], lastLaunch, requestID, @"launch_timeout", HengeAuthError(LaunchTimeout),
                                   HengeAuthMonotonic() - started, 0, 0);
                }
            } @catch (__unused NSException *exception) {
                // A concrete launch/probe failure is visible, but arbitrary
                // exception text and target output are never retained.
                if (lastLaunch && lastSession)
                    HengeAuthEvent(lastSession, lastLaunch, NSUUID.UUID.UUIDString, @"launch_failed",
                                   HengeAuthError(LaunchFailed), 0, 0, 0);
            } @finally { atomic_store(&polling, false); }
        }
    });
}
