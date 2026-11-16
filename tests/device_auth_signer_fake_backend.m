/* Linked ONLY into the synthetic build of the real signer main. */
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import "../ios/Henge/Native/HengeDeviceAuthHost.h"

void henge_device_auth_host_request(uint32_t operation, const void *input, size_t length,
    uint32_t timeoutMs, HengeDeviceAuthHostCompletion completion, void *context) {
    (void)timeoutMs;
    NSData *copied = [NSData dataWithBytes:input length:length];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            NSDictionary *value = operation == HENGE_DEVICE_AUTH_PROBE
                ? @{@"supported": @NO, @"dc_supported": @NO, @"dc_support_checked": @YES}
                : @{@"signature": copied, @"attestation": [@"synthetic-attestation" dataUsingEncoding:NSUTF8StringEncoding]};
            NSData *result = [NSPropertyListSerialization dataWithPropertyList:value
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            NSString *status = operation == HENGE_DEVICE_AUTH_PROBE ? @"probe_complete" : @"success";
            NSData *diag = [NSJSONSerialization dataWithJSONObject:@{@"status": status, @"outcome": status,
                @"errorDomain": @"", @"errorCode": @0, @"serverAcceptanceVerified": @NO} options:0 error:NULL];
            completion(context, result.bytes, result.length, diag.bytes, diag.length);
        }
    });
}
