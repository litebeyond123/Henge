#import <Foundation/Foundation.h>
#import "../ios/Henge/Native/HengeDeviceAuthHost.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdatomic.h>
#include <unistd.h>

// A one-request process. No arguments, input or result are written to a log.
// stdin/stdout carry length-prefixed binary plists only. The parent owns the
// process deadline and can terminate this isolated private-framework caller.
static BOOL exactIO(int fd, void *buffer, size_t length, BOOL writing) {
    uint8_t *p = buffer;
    while (length) {
        ssize_t n = writing ? write(fd, p, length) : read(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        p += n; length -= (size_t)n;
    }
    return YES;
}

@interface HengeSignerReply : NSObject {
@public atomic_bool finished;
}
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic, strong) NSData *data;
@end
@implementation HengeSignerReply
- (instancetype)init { if ((self = [super init])) { atomic_init(&finished, false); _lock = [NSLock new]; } return self; }
@end

static void completed(void *context, const uint8_t *result, size_t resultLength,
                      const char *diagnostics, size_t diagnosticsLength) {
    HengeSignerReply *reply = (__bridge_transfer HengeSignerReply *)context;
    NSMutableDictionary *wrapper = [@{@"protocol": @1,
        @"diagnostics": [NSData dataWithBytes:diagnostics length:diagnosticsLength]} mutableCopy];
    if (result && resultLength) wrapper[@"result"] = [NSData dataWithBytes:result length:resultLength];
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:wrapper
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    [reply.lock lock]; reply.data = data; [reply.lock unlock];
    atomic_store_explicit(&reply->finished, true, memory_order_release);
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2 || strcmp(argv[1], "--request-stdin")) return 2;
        uint32_t rawLength = 0;
        if (!exactIO(STDIN_FILENO, &rawLength, sizeof rawLength, NO)) return 3;
        NSUInteger length = ntohl(rawLength);
        if (!length || length > 70 * 1024) return 4;
        NSMutableData *data = [NSMutableData dataWithLength:length];
        if (!exactIO(STDIN_FILENO, data.mutableBytes, length, NO)) return 5;
        id request = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
        if (![request isKindOfClass:NSDictionary.class] || [request count] != 4 ||
            ![request[@"protocol"] isEqual:@1] || ![request[@"operation"] isKindOfClass:NSNumber.class] ||
            ![request[@"timeoutMs"] isKindOfClass:NSNumber.class] || ![request[@"input"] isKindOfClass:NSData.class]) return 6;
        NSUInteger operation = [request[@"operation"] unsignedIntegerValue];
        NSUInteger timeout = [request[@"timeoutMs"] unsignedIntegerValue];
        NSData *input = request[@"input"];
        if ((operation != HENGE_DEVICE_AUTH_PROBE && operation != HENGE_DEVICE_AUTH_BAA_DATA &&
             operation != HENGE_DEVICE_AUTH_BAA_DICTIONARY) || timeout < 250 || timeout > 10000 ||
            input.length > HENGE_DEVICE_AUTH_MAX_INPUT_BYTES) return 7;
        HengeSignerReply *reply = [HengeSignerReply new];
        henge_device_auth_host_request((uint32_t)operation, input.bytes, input.length, (uint32_t)timeout,
            completed, (__bridge_retained void *)reply);
        double deadline = NSProcessInfo.processInfo.systemUptime + (timeout + 200) / 1000.0;
        while (!atomic_load_explicit(&reply->finished, memory_order_acquire) && NSProcessInfo.processInfo.systemUptime < deadline) {
            // Some private implementations may deliver through the main run loop.
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.02, true);
        }
        if (!atomic_load_explicit(&reply->finished, memory_order_acquire)) return 8;
        [reply.lock lock]; NSData *response = reply.data; [reply.lock unlock];
        if (!response || response.length > 160 * 1024) return 9;
        uint32_t responseLength = htonl((uint32_t)response.length);
        return exactIO(STDOUT_FILENO, &responseLength, sizeof responseLength, YES) &&
            exactIO(STDOUT_FILENO, (void *)response.bytes, response.length, YES) ? 0 : 10;
    }
}
