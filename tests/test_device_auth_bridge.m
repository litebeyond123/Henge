/* Exercise the production Objective-C bridge with a fake C queue and fake
 * backends. No real DeviceCheck, private framework, or child is invoked. */
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import "../ios/Henge/Native/HengeAuthBridge.h"
#import "../ios/Henge/Native/HengeAuthSubprocess.h"
#import "../ios/Henge/Native/HengeDeviceAuthHost.h"
#include "device_auth.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static atomic_uint checks = 0;
static HvDeviceAuthWakeup wake;
static void *wakeContext;
static HvDeviceAuthJob pending;
static NSLock *queueLock;
static dispatch_semaphore_t completed;
static dispatch_semaphore_t backendHeld;
static atomic_bool current = true;
static atomic_bool claimed = false;
static NSData *backendResult, *backendDiagnostics, *delivered;
static HengeDeviceAuthHostCompletion heldCallback;
static void *heldContext;
static BOOL holdReply;
static NSUInteger publicCalls, childCalls;
static const char *sessionID = "11111111-1111-1111-1111-111111111111";
static const char *launchID = "22222222-2222-2222-2222-222222222222";
static NSString *secretText = @"SYNTHETIC-SECRET-DO-NOT-LOG";

static void require(BOOL value, const char *message) {
    if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
    atomic_fetch_add(&checks, 1);
}
const char *hv_device_auth_operation_name(HvDeviceAuthOperation operation) {
    static const char *names[] = {"probe", "dc_token", "baa_data", "baa_dictionary"};
    return (unsigned)operation <= 3 ? names[operation] : "invalid";
}
int hv_device_auth_set_wakeup(HvDeviceAuthWakeup callback, void *context) {
    wake = callback; wakeContext = context; return 1;
}
int hv_device_auth_take(HvDeviceAuthJob *job) {
    [queueLock lock];
    BOOL exists = pending.ticket != 0;
    if (exists) { *job = pending; memset(&pending, 0, sizeof pending); atomic_store(&claimed, true); }
    [queueLock unlock];
    return exists;
}
void hv_device_auth_job_dispose(HvDeviceAuthJob *job) {
    if (job->body) { memset(job->body, 0, job->body_length); free(job->body); }
    memset(job, 0, sizeof(*job));
}
int hv_device_auth_job_is_current(uint64_t ticket, const char *session, const char *launch, const char *request) {
    return ticket > 0 && !strcmp(session, sessionID) && !strcmp(launch, launchID) && strlen(request) == 36 && atomic_load(&current);
}
int hv_device_auth_complete(uint64_t ticket, const char *session, const char *launch, const char *request,
    int httpStatus, HvDeviceAuthError error, const void *body, size_t length) {
    require(ticket > 0 && !strcmp(session, sessionID) && !strcmp(launch, launchID) && strlen(request) == 36,
            "callback preserves full request correlation");
    require(httpStatus == 200 && error == HV_DEVICE_AUTH_OK, "native outcome uses HTTP envelope");
    if (atomic_load(&current)) delivered = [NSData dataWithBytes:body length:length];
    else delivered = nil; /* Same no-copy behavior as the real revoked C slot. */
    dispatch_semaphore_signal(completed);
    return 1;
}

void henge_device_auth_host_request(uint32_t operation, const void *input, size_t length, uint32_t timeout,
    HengeDeviceAuthHostCompletion completion, void *context) {
    (void)input;
    require(!NSThread.isMainThread && operation <= HENGE_DEVICE_AUTH_DC_TOKEN && length == 0,
            "public API stays on background host path with empty input");
    require(timeout > 0 && timeout <= 8000, "backend budget is bounded");
    publicCalls++;
    if (holdReply) { heldCallback = completion; heldContext = context; dispatch_semaphore_signal(backendHeld); return; }
    completion(context, backendResult.bytes, backendResult.length, backendDiagnostics.bytes, backendDiagnostics.length);
}
void HengeAuthRunSignerChild(NSInteger operation, NSData *input, NSUInteger timeout, HengeAuthChildCompletion completion) {
    require(!NSThread.isMainThread && operation != HENGE_DEVICE_AUTH_DC_TOKEN && timeout <= 8000,
            "BAA path uses isolated child with bounded budget");
    require(operation == HENGE_DEVICE_AUTH_PROBE || input.length > 0, "BAA payload reaches child");
    childCalls++;
    completion(backendResult, backendDiagnostics);
}

static NSData *json(id value) { return [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL]; }
static NSData *plist(id value) { return [NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL]; }
static NSDictionary *lastReceipt(void) {
    char *text = HengeAuthBridgeDiagnosticsJSON();
    require(text != NULL, "bridge diagnostic snapshot exists");
    NSString *string = @(text); free(text);
    require(![string containsString:secretText] && ![string containsString:@"resultBase64"], "persisted summaries exclude secrets");
    NSDictionary *value = [NSJSONSerialization JSONObjectWithData:[string dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL];
    return [value[@"receipts"] lastObject];
}
static NSDictionary *await(void) {
    require(dispatch_semaphore_wait(completed, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0, "bridge completes bounded request");
    return delivered ? [NSJSONSerialization JSONObjectWithData:delivered options:0 error:NULL] : nil;
}
static void submit(HvDeviceAuthMode mode, HvDeviceAuthOperation operation, NSDictionary *overrides) {
    static uint64_t sequence;
    sequence++;
    NSString *request = [NSString stringWithFormat:@"33333333-3333-3333-3333-%012llu", (unsigned long long)sequence];
    NSMutableDictionary *body = [@{@"protocol": @1, @"launch_id": @(launchID), @"request_id": request,
        @"operation": @(hv_device_auth_operation_name(operation))} mutableCopy];
    if (operation >= HV_DEVICE_AUTH_BAA_DATA) body[@"payloadBase64"] =
        [[secretText dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
    [body addEntriesFromDictionary:overrides ?: @{}];
    NSData *data = json(body);
    [queueLock lock];
    memset(&pending, 0, sizeof pending);
    pending.ticket = sequence; pending.mode = mode; pending.operation = operation; pending.remaining_ms = 9000;
    strlcpy(pending.session, sessionID, sizeof pending.session);
    strlcpy(pending.launch_id, launchID, sizeof pending.launch_id);
    strlcpy(pending.request_id, request.UTF8String, sizeof pending.request_id);
    pending.body = malloc(data.length); memcpy(pending.body, data.bytes, data.length); pending.body_length = data.length;
    delivered = nil; atomic_store(&claimed, false);
    [queueLock unlock];
    wake(wakeContext);
}

int main(void) {
    @autoreleasepool {
        queueLock = [NSLock new]; completed = dispatch_semaphore_create(0); backendHeld = dispatch_semaphore_create(0);
        HengeAuthInstallBridge(); require(wake != NULL, "bridge registers background worker");
        NSData *secret = [secretText dataUsingEncoding:NSUTF8StringEncoding];
        backendResult = plist(@{@"token": secret});
        backendDiagnostics = json(@{@"outcome": @"success", @"status": @"success", @"errorDomain": secretText,
            @"errorCode": @1, @"latencyMs": @12, @"inputBytes": @0, @"resultBytes": @(backendResult.length),
            @"privatePayload": secretText, @"serverAcceptanceVerified": @YES, @"scope": secretText,
            @"dc_supported": @1, @"methodABIChecked": @YES});
        submit(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, HV_DEVICE_AUTH_DC_TOKEN, nil);
        NSDictionary *response = await();
        require([response[@"status"] isEqual:@"ok"] && [response[@"session"] isEqual:@(sessionID)] &&
            [response[@"launch_id"] isEqual:@(launchID)], "successful response remains correlated");
        NSData *decoded = [[NSData alloc] initWithBase64EncodedString:response[@"resultBase64"] options:0];
        require([decoded isEqual:backendResult], "secret result is only forwarded intact to requester");
        NSDictionary *receipt = lastReceipt();
        require([receipt[@"errorDomain"] isEqual:@"other_domain"] && [receipt[@"scope"] isEqual:@"henge_app_public_api"], "domain and scope are canonical");
        require([receipt[@"serverAcceptanceVerified"] isEqual:@NO] && !receipt[@"dc_supported"], "booleans are typed and backend cannot claim server acceptance");
        require([receipt[@"deliveryCurrent"] isEqual:@YES] && [receipt[@"responseDiscarded"] isEqual:@NO], "currentness snapshot is explicit");

        backendResult = [@"garbage-with-success" dataUsingEncoding:NSUTF8StringEncoding];
        submit(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, HV_DEVICE_AUTH_DC_TOKEN, nil);
        response = await();
        require([response[@"status"] isEqual:@"error"] && !response[@"resultBase64"] &&
            [response[@"diagnostics"][@"outcome"] isEqual:@"invalid_response"], "malformed binary plist cannot be called success");

        backendResult = plist(@{@"token": @"wrong-type"});
        submit(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, HV_DEVICE_AUTH_DC_TOKEN, nil);
        response = await(); require([response[@"status"] isEqual:@"error"], "token must remain NSData");

        backendResult = plist(@{@"supported": @NO, @"dc_supported": @NO, @"dc_support_checked": @YES,
            @"dc_class_available": @YES, @"privateValue": secretText,
            @"entitlement_presence": @{@"com.apple.security.attestation.access": @YES, @"privateValue": secretText}});
        backendDiagnostics = json(@{@"outcome": @"probe_complete", @"errorDomain": @"", @"errorCode": @0});
        submit(HV_DEVICE_AUTH_MODE_BAA, HV_DEVICE_AUTH_PROBE, nil);
        response = await(); receipt = lastReceipt();
        require([response[@"status"] isEqual:@"ok"] && [receipt[@"scope"] isEqual:@"isolated_baa_signer"], "BAA probe uses child context");
        require([receipt[@"capabilities"][@"supported"] isEqual:@NO] && !receipt[@"capabilities"][@"privateValue"], "probe false and fixed schema retained");
        require([receipt[@"capabilities"][@"entitlement_presence"] count] == 1, "only named entitlement presence retained");

        backendResult = plist(@{@"signature": secret, @"attestation": @{@"chain": @[secret]}});
        backendDiagnostics = json(@{@"outcome": @"success", @"errorDomain": @"", @"errorCode": @0});
        submit(HV_DEVICE_AUTH_MODE_BAA, HV_DEVICE_AUTH_BAA_DATA, nil);
        response = await(); require([response[@"status"] isEqual:@"ok"], "opaque valid BAA result passes intact");

        NSUInteger before = publicCalls;
        submit(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, HV_DEVICE_AUTH_DC_TOKEN, @{@"launch_id": @"wrong-launch"});
        response = await(); require([response[@"status"] isEqual:@"error"] && publicCalls == before, "identity mismatch never reaches backend");

        backendResult = plist(@{@"token": secret}); holdReply = YES;
        submit(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, HV_DEVICE_AUTH_DC_TOKEN, nil);
        require(dispatch_semaphore_wait(backendHeld, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0,
                "backend reached held callback before deadline");
        require(heldCallback != NULL && atomic_load(&claimed), "backend callback held for lifecycle test");
        atomic_store(&current, false);
        heldCallback(heldContext, backendResult.bytes, backendResult.length, backendDiagnostics.bytes, backendDiagnostics.length);
        heldCallback = NULL; heldContext = NULL; holdReply = NO;
        require(await() == nil, "revoked C slot receives no copied secret response");
        receipt = lastReceipt();
        require([receipt[@"outcome"] isEqual:@"success"] && [receipt[@"deliveryCurrent"] isEqual:@NO] &&
            [receipt[@"responseDiscarded"] isEqual:@YES], "late generation success is labelled discarded");
        require(publicCalls > 0 && childCalls == 2, "both host paths exercised without Apple calls");
        printf("PASS: bridge synthetic tests checks=%u; no Apple services called\n", atomic_load(&checks));
    }
    return 0;
}
