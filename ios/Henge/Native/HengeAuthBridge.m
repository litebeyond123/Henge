#import "HengeAuthBridge.h"
#import "HengeAuthSubprocess.h"
#import "HengeDeviceAuthHost.h"
#include "device_auth.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

@interface HengeAuthWork : NSObject {
@public HvDeviceAuthJob job;
}
@property(nonatomic, copy) NSString *scope;
@end
@implementation HengeAuthWork
@end

static NSLock *receiptLock;
static NSMutableArray<NSDictionary *> *receipts;
static void prepareReceipts(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ receiptLock = [NSLock new]; receipts = [NSMutableArray new]; });
}

static BOOL isBool(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID();
}

// Rebuild summaries from enumerated keys and values. The result plist is never
// passed here: it is used only for the correlated HTTP response below.
static NSDictionary *canonicalDiagnostics(NSData *data, HengeAuthWork *work) {
    NSDictionary *raw = data.length <= 8192 ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
    if (![raw isKindOfClass:NSDictionary.class]) raw = @{};
    NSArray *outcomes = @[@"success", @"probe_complete", @"native_error", @"unsupported", @"api_unavailable",
        @"method_abi_mismatch", @"callback_abi_mismatch", @"objc_exception", @"invalid_request", @"busy",
        @"timed_out", @"invalid_response", @"unsupported_result_type", @"diagnostic_encoding_failed",
        @"child_invalid_request", @"child_not_bundled", @"child_pipe_failed", @"child_spawn_failed",
        @"child_timed_out", @"child_transport_failed", @"child_invalid_response", @"session_cancelled"];
    NSString *outcome = [outcomes containsObject:raw[@"outcome"]] ? raw[@"outcome"] : @"invalid_response";
    NSMutableDictionary *safe = [@{@"status": outcome, @"outcome": outcome,
        @"operation": @(hv_device_auth_operation_name(work->job.operation)), @"scope": work.scope ?: @"unknown",
        @"serverAcceptanceVerified": @NO} mutableCopy];
    NSArray *domains = @[@"", @"NSCocoaErrorDomain", @"NSPOSIXErrorDomain", @"NSOSStatusErrorDomain", @"NSMachErrorDomain",
        @"NSURLErrorDomain", @"com.apple.devicecheck.error", @"com.apple.DeviceCheck.error", @"com.apple.DeviceIdentity",
        @"com.apple.DeviceIdentity.ErrorDomain", @"com.apple.MobileActivation.ErrorDomain", @"com.apple.mobileactivation.ErrorDomain",
        @"DCErrorDomain", @"DeviceCheckErrorDomain", @"IDSBAASignerErrorDomain", @"HengeDeviceAuthHost", @"other_domain"];
    safe[@"errorDomain"] = [domains containsObject:raw[@"errorDomain"]] ? raw[@"errorDomain"] : @"other_domain";
    for (NSString *key in @[@"errorCode", @"latencyMs", @"timeoutMs", @"inputBytes", @"resultBytes",
                            @"signatureBytes", @"attestationBytes", @"childExitCode", @"childSignal"]) {
        id value = raw[key];
        if (![value isKindOfClass:NSNumber.class] || isBool(value)) continue;
        double v = [value doubleValue];
        if (!isfinite(v) || trunc(v) != v || v < -2147483648.0 || v > 2147483647.0) continue;
        if (![key isEqual:@"errorCode"] && ![key isEqual:@"childExitCode"] && v < 0) continue;
        safe[key] = @((int64_t)v);
    }
    if (!safe[@"errorCode"]) safe[@"errorCode"] = @0;
    for (NSString *key in @[@"methodABIChecked", @"callbackABIChecked", @"isolatedSigner",
                            @"dc_framework_available", @"dc_class_available", @"dc_method_available", @"dc_supported",
                            @"dc_support_checked", @"baa_framework_available", @"baa_class_available",
                            @"baa_single_available", @"baa_multiple_available", @"entitlement_query_available"]) {
        if (isBool(raw[key])) safe[key] = raw[key];
    }
    return safe;
}

static void retainReceipt(NSDictionary *diagnostics, HengeAuthWork *work, NSDictionary *probe) {
    prepareReceipts();
    NSMutableDictionary *safe = [diagnostics mutableCopy];
    safe[@"request_id"] = @(work->job.request_id);
    safe[@"launch_id"] = @(work->job.launch_id);
    safe[@"observed_utc"] = [[NSISO8601DateFormatter new] stringFromDate:[NSDate date]];
    // The probe contains only fixed booleans. Never merge token/signature plists.
    if (work->job.operation == HV_DEVICE_AUTH_PROBE && [probe isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *capabilities = [NSMutableDictionary new];
        for (NSString *key in @[@"supported", @"dc_supported", @"dc_support_checked", @"dc_framework_available",
                                @"dc_class_available", @"dc_method_available", @"baa_framework_available",
                                @"baa_class_available", @"baa_single_available", @"baa_multiple_available",
                                @"entitlement_query_available"]) {
            if (isBool(probe[key])) capabilities[key] = probe[key];
        }
        NSDictionary *presence = probe[@"entitlement_presence"];
        NSMutableDictionary *entitlements = [NSMutableDictionary new];
        if ([presence isKindOfClass:NSDictionary.class]) {
            for (NSString *key in @[@"com.apple.mobileactivationd.device-identifiers", @"com.apple.mobileactivationd.spi",
                                    @"com.apple.security.attestation.access", @"keychain-access-groups",
                                    @"com.apple.private.security.no-sandbox", @"platform-application"]) {
                if (isBool(presence[key])) entitlements[key] = presence[key];
            }
        }
        capabilities[@"entitlement_presence"] = entitlements;
        safe[@"capabilities"] = capabilities;
    }
    [receiptLock lock];
    [receipts addObject:safe];
    if (receipts.count > 16) [receipts removeObjectAtIndex:0];
    [receiptLock unlock];
    fprintf(stderr, "hengevm: device-auth-backend request=%s operation=%s scope=%s outcome=%s domain=%s code=%lld elapsed_ms=%llu input_bytes=%llu result_bytes=%llu\n",
        work->job.request_id, hv_device_auth_operation_name(work->job.operation), work.scope.UTF8String,
        [safe[@"outcome"] UTF8String], [safe[@"errorDomain"] UTF8String], [safe[@"errorCode"] longLongValue],
        [safe[@"latencyMs"] unsignedLongLongValue], [safe[@"inputBytes"] unsignedLongLongValue], [safe[@"resultBytes"] unsignedLongLongValue]);
}

static BOOL nonemptyResult(id value) {
    if ([value isKindOfClass:NSData.class] || [value isKindOfClass:NSString.class]) return [value length] > 0;
    if ([value isKindOfClass:NSArray.class] || [value isKindOfClass:NSDictionary.class]) return [value count] > 0;
    return [value isKindOfClass:NSNumber.class];
}

static NSDictionary *validResult(NSData *data, HvDeviceAuthOperation operation) {
    if (data.length < 8 || data.length > HENGE_DEVICE_AUTH_MAX_RESULT_BYTES || memcmp(data.bytes, "bplist00", 8)) return nil;
    id object = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
    if (![object isKindOfClass:NSDictionary.class]) return nil;
    if (operation == HV_DEVICE_AUTH_PROBE) return isBool(object[@"supported"]) ? object : nil;
    if (operation == HV_DEVICE_AUTH_DC_TOKEN)
        return [object[@"token"] isKindOfClass:NSData.class] && [object[@"token"] length] ? object : nil;
    NSString *key = operation == HV_DEVICE_AUTH_BAA_DICTIONARY ? @"signatures" : @"signature";
    if (operation == HV_DEVICE_AUTH_BAA_DICTIONARY && ![object[key] isKindOfClass:NSDictionary.class]) return nil;
    return nonemptyResult(object[key]) && nonemptyResult(object[@"attestation"]) ? object : nil;
}

static void finishWork(HengeAuthWork *work, NSData *result, NSData *rawDiagnostics) {
    NSMutableDictionary *diagnostics = [canonicalDiagnostics(rawDiagnostics, work) mutableCopy];
    NSString *outcome = diagnostics[@"outcome"];
    BOOL declaredSuccess = [outcome isEqual:@"success"] ||
        (work->job.operation == HV_DEVICE_AUTH_PROBE && [outcome isEqual:@"probe_complete"]);
    NSDictionary *decoded = declaredSuccess ? validResult(result, work->job.operation) : nil;
    BOOL ok = declaredSuccess && decoded != nil;
    if (declaredSuccess && !ok) {
        diagnostics[@"outcome"] = diagnostics[@"status"] = @"invalid_response";
        diagnostics[@"resultBytes"] = @0;
    }
    // This is a currentness check, not an acknowledgement by the client or server.
    BOOL current = hv_device_auth_job_is_current(work->job.ticket, work->job.session, work->job.launch_id, work->job.request_id);
    diagnostics[@"deliveryCurrent"] = @(current);
    diagnostics[@"responseDiscarded"] = @(!current);
    retainReceipt(diagnostics, work, work->job.operation == HV_DEVICE_AUTH_PROBE ? decoded : nil);
    NSMutableDictionary *body = [@{@"protocol": @1, @"session": @(work->job.session),
        @"launch_id": @(work->job.launch_id), @"request_id": @(work->job.request_id),
        @"operation": @(hv_device_auth_operation_name(work->job.operation)),
        @"status": ok ? @"ok" : @"error", @"diagnostics": diagnostics} mutableCopy];
    if (ok) body[@"resultBase64"] = [result base64EncodedStringWithOptions:0];
    NSData *response = [NSJSONSerialization dataWithJSONObject:body options:0 error:NULL];
    if (!response || response.length > HV_DEVICE_AUTH_RESPONSE_MAX) {
        hv_device_auth_complete(work->job.ticket, work->job.session, work->job.launch_id, work->job.request_id,
            503, HV_DEVICE_AUTH_BACKEND_FAILED, NULL, 0);
    } else {
        // HTTP 200 with status=error preserves an actual native NSError without
        // confusing it with a local HTTP transport or session rejection.
        hv_device_auth_complete(work->job.ticket, work->job.session, work->job.launch_id, work->job.request_id,
            200, HV_DEVICE_AUTH_OK, response.bytes, response.length);
    }
}

static void coreCompleted(void *context, const uint8_t *result, size_t resultLength,
                          const char *diagnostics, size_t diagnosticsLength) {
    HengeAuthWork *work = (__bridge_transfer HengeAuthWork *)context;
    @autoreleasepool {
        finishWork(work, result && resultLength ? [NSData dataWithBytes:result length:resultLength] : nil,
            [NSData dataWithBytes:diagnostics length:diagnosticsLength]);
    }
}

static void failWork(HengeAuthWork *work, NSString *outcome) {
    finishWork(work, nil, [NSJSONSerialization dataWithJSONObject:@{@"status": outcome, @"outcome": outcome,
        @"errorDomain": @"", @"errorCode": @0, @"inputBytes": @(work->job.body_length)} options:0 error:NULL]);
}

static void consume(void) {
    @autoreleasepool {
        HengeAuthWork *work = [HengeAuthWork new];
        HvDeviceAuthJob claimed = {0};
        if (!hv_device_auth_take(&claimed)) return;
        work->job = claimed;
        NSData *json = [NSData dataWithBytes:claimed.body length:claimed.body_length];
        work->job.body = NULL;
        // Keep only correlation metadata after the backend input has been copied.
        hv_device_auth_job_dispose(&claimed);
        NSDictionary *raw = [NSJSONSerialization JSONObjectWithData:json options:0 error:NULL];
        work.scope = work->job.mode == HV_DEVICE_AUTH_MODE_BAA ? @"isolated_baa_signer" : @"henge_app_public_api";
        if (![raw isKindOfClass:NSDictionary.class] || ![raw[@"protocol"] isEqual:@1] ||
            ![raw[@"launch_id"] isEqual:@(work->job.launch_id)] || ![raw[@"request_id"] isEqual:@(work->job.request_id)] ||
            ![raw[@"operation"] isEqual:@(hv_device_auth_operation_name(work->job.operation))]) {
            failWork(work, @"invalid_request"); return;
        }
        NSData *input = [NSData data];
        if (work->job.operation == HV_DEVICE_AUTH_BAA_DATA || work->job.operation == HV_DEVICE_AUTH_BAA_DICTIONARY) {
            if (![raw[@"payloadBase64"] isKindOfClass:NSString.class]) { failWork(work, @"invalid_request"); return; }
            input = [[NSData alloc] initWithBase64EncodedString:raw[@"payloadBase64"] options:0];
            if (!input.length || input.length > HENGE_DEVICE_AUTH_MAX_INPUT_BYTES) { failWork(work, @"invalid_request"); return; }
        } else if (raw[@"payloadBase64"] != nil) { failWork(work, @"invalid_request"); return; }
        if (!hv_device_auth_job_is_current(work->job.ticket, work->job.session, work->job.launch_id, work->job.request_id)) {
            failWork(work, @"session_cancelled"); return;
        }
        uint32_t timeout = MIN(work->job.remaining_ms > 500 ? work->job.remaining_ms - 500 : 100, 8000u);
        if (work->job.mode == HV_DEVICE_AUTH_MODE_BAA) {
            HengeAuthRunSignerChild(work->job.operation, input, timeout, ^(NSData *result, NSData *diagnostics) {
                finishWork(work, result, diagnostics);
            });
        } else {
            henge_device_auth_host_request(work->job.operation, input.bytes, input.length, timeout,
                coreCompleted, (__bridge_retained void *)work);
        }
    }
}

static void wakeup(void *context) {
    (void)context;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ consume(); });
}

void HengeAuthInstallBridge(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ prepareReceipts(); hv_device_auth_set_wakeup(wakeup, NULL); });
}

char *HengeAuthBridgeDiagnosticsJSON(void) {
    @autoreleasepool {
        prepareReceipts();
        [receiptLock lock]; NSArray *copy = [receipts copy]; [receiptLock unlock];
        NSData *json = [NSJSONSerialization dataWithJSONObject:@{@"protocol": @1, @"receipts": copy,
            @"privacy": @"fixed_fields_only", @"serverAcceptanceVerified": @NO} options:0 error:NULL];
        if (!json) return NULL;
        char *text = malloc(json.length + 1);
        if (text) { memcpy(text, json.bytes, json.length); text[json.length] = 0; }
        return text;
    }
}
