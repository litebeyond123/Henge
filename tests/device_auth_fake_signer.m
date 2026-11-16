/* Malformed/slow child fixture. No DeviceCheck imports or production backend. */
#import <Foundation/Foundation.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static BOOL exact(int fd, void *buffer, size_t length, BOOL writing) {
    uint8_t *p = buffer;
    while (length) {
        ssize_t n = writing ? write(fd, p, length) : read(fd, p, length);
        if (n <= 0) return NO;
        p += n; length -= (size_t)n;
    }
    return YES;
}
static NSData *plist(id value) {
    return [NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2 || strcmp(argv[1], "--request-stdin")) return 90;
        NSString *path = @(argv[0]);
        NSString *mode = path.lastPathComponent;
        [[NSString stringWithFormat:@"%d", getpid()] writeToFile:[path stringByAppendingString:@".pid"]
            atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        if ([mode isEqual:@"early-exit"]) return 7;
        if ([mode isEqual:@"hang-before-read"]) { for (;;) pause(); }
        uint32_t count = 0;
        if (!exact(STDIN_FILENO, &count, sizeof count, NO)) return 91;
        NSUInteger length = ntohl(count);
        if (!length || length > 70 * 1024) return 92;
        NSMutableData *input = [NSMutableData dataWithLength:length];
        if (!exact(STDIN_FILENO, input.mutableBytes, length, NO)) return 93;
        id request = [NSPropertyListSerialization propertyListWithData:input options:NSPropertyListImmutable format:NULL error:NULL];
        if (![request isKindOfClass:NSDictionary.class]) return 94;
        if ([mode isEqual:@"signal-exit"]) { kill(getpid(), SIGTERM); return 95; }
        if ([mode isEqual:@"oversize-frame"] || [mode isEqual:@"zero-frame"]) {
            count = htonl([mode isEqual:@"zero-frame"] ? 0 : UINT32_MAX);
            exact(STDOUT_FILENO, &count, sizeof count, YES); return 0;
        }
        if ([mode isEqual:@"truncated-frame"]) {
            count = htonl(100); exact(STDOUT_FILENO, &count, sizeof count, YES);
            char byte = 'x'; exact(STDOUT_FILENO, &byte, 1, YES); return 0;
        }
        NSData *secret = [@"SYNTHETIC-SECRET-CHILD" dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *result = [request[@"operation"] integerValue] == 0
            ? @{@"supported": @NO, @"dc_supported": @NO, @"dc_support_checked": @YES}
            : @{@"signature": secret, @"attestation": @{@"chain": @[secret]}};
        NSDictionary *diag = @{@"status": @"success", @"outcome": @"success", @"operation": @"baa_data",
            @"errorDomain": @"", @"errorCode": @0, @"serverAcceptanceVerified": @NO};
        if ([mode isEqual:@"native-error"]) diag = @{@"status": @"native_error", @"outcome": @"native_error",
            @"errorDomain": @"IDSBAASignerErrorDomain", @"errorCode": @17};
        NSMutableDictionary *wrapper = [@{@"protocol": @1,
            @"diagnostics": [NSJSONSerialization dataWithJSONObject:diag options:0 error:NULL]} mutableCopy];
        if (![mode isEqual:@"native-error"]) wrapper[@"result"] = plist(result);
        if ([mode isEqual:@"wrong-protocol"]) wrapper[@"protocol"] = @2;
        if ([mode isEqual:@"bad-diagnostics"]) wrapper[@"diagnostics"] = [@"[]" dataUsingEncoding:NSUTF8StringEncoding];
        if ([mode isEqual:@"oversize-result"]) wrapper[@"result"] = [NSMutableData dataWithLength:65537];
        NSData *response = [mode isEqual:@"not-plist"] ? [@"not a plist" dataUsingEncoding:NSUTF8StringEncoding] : plist(wrapper);
        /* stderr must never be inherited by the VM's native log. */
        static const char marker[] = "SYNTHETIC-SECRET-STDERR\n";
        write(STDERR_FILENO, marker, sizeof(marker) - 1);
        count = htonl((uint32_t)response.length);
        exact(STDOUT_FILENO, &count, sizeof count, YES);
        exact(STDOUT_FILENO, (void *)response.bytes, response.length, YES);
        if ([mode isEqual:@"reply-then-hang"]) { for (;;) pause(); }
        if ([mode isEqual:@"eintr"]) usleep(80000);
        return 0;
    }
}
