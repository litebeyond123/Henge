/* Synthetic Foundation test. This binary NEVER calls Apple's DeviceCheck or
 * private signer: all requests use the test-only injected backend. */
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import "../ios/Henge/Native/HengeDeviceAuthHost.h"
#include <stdlib.h>
#include <stdatomic.h>

static atomic_uint checks = 0;
static void require(BOOL value, const char *message) {
    if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
    atomic_fetch_add(&checks, 1);
}

typedef void (^Reply)(id, id, NSError *);
typedef void (^Handler)(uint32_t, id, Reply);

@interface FakeBackend : NSObject <HengeDeviceAuthHostTestBackend>
@property(copy) Handler handler;
@property(copy) NSDictionary *probeValue;
@end
@implementation FakeBackend
- (NSDictionary *)probe { return self.probeValue; }
- (void)performOperation:(uint32_t)operation input:(id)input completion:(Reply)completion {
    self.handler(operation, input, completion);
}
@end

@interface Receipt : NSObject
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic, strong) dispatch_semaphore_t ready;
@property(nonatomic, strong) NSData *result;
@property(nonatomic, strong) NSData *json;
@property(nonatomic) NSUInteger count;
@property(nonatomic) BOOL wasMainThread;
@end
@implementation Receipt
- (instancetype)init {
    if ((self = [super init])) { _lock = [NSLock new]; _ready = dispatch_semaphore_create(0); }
    return self;
}
@end

/* Keep contexts alive through all deliberately late/duplicate callbacks. */
static NSMutableArray<Receipt *> *receipts;
static void receive(void *context, const uint8_t *result, size_t resultLength,
                    const char *json, size_t jsonLength) {
    Receipt *receipt = (__bridge Receipt *)context;
    [receipt.lock lock];
    receipt.count++;
    receipt.wasMainThread = NSThread.isMainThread;
    receipt.result = [NSData dataWithBytes:result length:resultLength];
    receipt.json = [NSData dataWithBytes:json length:jsonLength];
    [receipt.lock unlock];
    dispatch_semaphore_signal(receipt.ready);
}

static Receipt *start(uint32_t op, NSData *input, uint32_t timeout, FakeBackend *backend) {
    Receipt *receipt = [Receipt new]; [receipts addObject:receipt];
    HengeDeviceAuthHostRequestForTesting(op, input.bytes, input.length, timeout, backend, receive, (__bridge void *)receipt);
    return receipt;
}

static void waitFor(dispatch_semaphore_t semaphore) {
    require(dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0,
            "bounded asynchronous completion");
}

static NSDictionary *await(Receipt *receipt, NSString *status) {
    waitFor(receipt.ready);
    [receipt.lock lock];
    NSDictionary *diagnostics = [NSJSONSerialization JSONObjectWithData:receipt.json options:0 error:NULL];
    BOOL main = receipt.wasMainThread;
    NSUInteger count = receipt.count;
    [receipt.lock unlock];
    require([diagnostics[@"status"] isEqual:status], "expected fixed status");
    require([diagnostics[@"outcome"] isEqual:status], "outcome agrees with status");
    require(!main && count == 1, "one callback off main thread");
    require([diagnostics[@"serverAcceptanceVerified"] isEqual:@NO], "never claims server acceptance");
    return diagnostics;
}

static NSData *plist(id object) {
    return [NSPropertyListSerialization dataWithPropertyList:object format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
}
static NSDictionary *result(Receipt *receipt) {
    return [NSPropertyListSerialization propertyListWithData:receipt.result options:NSPropertyListImmutable format:NULL error:NULL];
}
static FakeBackend *backend(Handler handler) { FakeBackend *b = [FakeBackend new]; b.handler = handler; return b; }
static NSData *bytes(NSString *value) { return [value dataUsingEncoding:NSUTF8StringEncoding]; }

int main(void) {
    @autoreleasepool {
        receipts = [NSMutableArray array];
        require(HengeDeviceAuthHostMethodEncodingForTesting("v32@0:8@16@?24", NO), "deb BAA method ABI");
        require(HengeDeviceAuthHostMethodEncodingForTesting("v24@0:8@?16", YES), "public token method ABI");
        require(!HengeDeviceAuthHostMethodEncodingForTesting("v32@0:8q16@?24", NO), "reject integer payload ABI");
        require(!HengeDeviceAuthHostMethodEncodingForTesting("@32@0:8@16@?24", NO), "reject return ABI mismatch");
        require(!HengeDeviceAuthHostMethodEncodingForTesting("v24@0:8@16", YES), "require block argument");
        require(HengeDeviceAuthHostBlockEncodingForTesting("v32@?0^v8^v16^v24", 3), "deb callback pointer ABI");
        require(!HengeDeviceAuthHostBlockEncodingForTesting("v24@?0@8@16", 3), "reject callback arity mismatch");
        require(HengeDeviceAuthHostCompiledBlocksForTesting(), "compiler-emitted block descriptors match ABI");

        NSData *secret = bytes(@"SYNTHETIC-SECRET-DO-NOT-LOG");
        FakeBackend *token = backend(^(uint32_t operation, id input, Reply reply) {
            require(operation == HENGE_DEVICE_AUTH_DC_TOKEN && [input length] == 0, "token operation has no caller-selected device data");
            reply(secret, nil, nil);
        });
        Receipt *ok = start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, token);
        NSDictionary *diag = await(ok, @"success");
        require([result(ok)[@"token"] isEqual:secret], "complete token bytes reach caller");
        require([diag[@"resultBytes"] unsignedIntegerValue] == ok.result.length, "reported result size is exact");
        NSString *safe = [[NSString alloc] initWithData:ok.json encoding:NSUTF8StringEncoding];
        require(![safe containsString:@"SYNTHETIC-SECRET"], "diagnostics contain no token");

        FakeBackend *probe = [FakeBackend new];
        probe.probeValue = @{@"supported": @NO, @"dc_supported": @NO, @"dc_support_checked": @YES};
        Receipt *probeReceipt = start(HENGE_DEVICE_AUTH_PROBE, nil, 1000, probe);
        await(probeReceipt, @"probe_complete");
        require([result(probeReceipt)[@"supported"] isEqual:@NO], "false support remains false");

        NSDictionary *challenge = @{@"challenge": secret};
        NSDictionary *opaqueAttestation = @{@"chain": @[secret, @"opaque-label"], @"version": @1};
        FakeBackend *multiple = backend(^(uint32_t operation, id input, Reply reply) {
            require(operation == HENGE_DEVICE_AUTH_BAA_DICTIONARY && [input isEqual:challenge], "dictionary input preserved");
            reply(@{@"challenge": secret}, opaqueAttestation, nil);
        });
        Receipt *multi = start(HENGE_DEVICE_AUTH_BAA_DICTIONARY, plist(challenge), 1000, multiple);
        await(multi, @"success");
        require([result(multi)[@"signatures"] isEqual:challenge] &&
                [result(multi)[@"attestation"] isEqual:opaqueAttestation], "opaque plist signature and attestation preserved");

        FakeBackend *unused = backend(^(__unused uint32_t operation, __unused id input, __unused Reply reply) {
            require(NO, "invalid input must not reach signer");
        });
        await(start(99, nil, 1000, unused), @"invalid_request");
        await(start(HENGE_DEVICE_AUTH_PROBE, secret, 1000, unused), @"invalid_request");
        await(start(HENGE_DEVICE_AUTH_BAA_DATA, nil, 1000, unused), @"invalid_request");
        await(start(HENGE_DEVICE_AUTH_BAA_DICTIONARY, plist(@{@"challenge": @"wrong-type"}), 1000, unused), @"invalid_request");
        await(start(HENGE_DEVICE_AUTH_BAA_DICTIONARY, bytes(@"<?xml version=\"1.0\"?><plist/>"), 1000, unused), @"invalid_request");
        await(start(HENGE_DEVICE_AUTH_BAA_DATA, [NSMutableData dataWithLength:HENGE_DEVICE_AUTH_MAX_INPUT_BYTES + 1], 1000, unused), @"invalid_request");

        FakeBackend *error = backend(^(__unused uint32_t operation, __unused id input, Reply reply) {
            reply(nil, nil, [NSError errorWithDomain:@"com.apple.devicecheck.error" code:1
                userInfo:@{NSLocalizedDescriptionKey: @"SYNTHETIC-SECRET-DO-NOT-LOG"}]);
        });
        Receipt *failure = start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, error);
        NSDictionary *failureDiag = await(failure, @"native_error");
        require([failureDiag[@"errorDomain"] isEqual:@"com.apple.devicecheck.error"] &&
                [failureDiag[@"errorCode"] isEqual:@1] && failure.result.length == 0, "native error domain/code, no secret result");
        require(![[[NSString alloc] initWithData:failure.json encoding:NSUTF8StringEncoding] containsString:@"SYNTHETIC-SECRET"],
                "NSError descriptions are never exported");
        FakeBackend *unknownDomain = backend(^(__unused uint32_t operation, __unused id input, Reply reply) {
            reply(nil, nil, [NSError errorWithDomain:@"SYNTHETIC-SECRET" code:9 userInfo:nil]);
        });
        require([await(start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, unknownDomain), @"native_error")[@"errorDomain"]
            isEqual:@"other_domain"], "unknown error domain cannot smuggle secret text");

        FakeBackend *wrong = backend(^(__unused uint32_t operation, __unused id input, Reply reply) { reply(@"not-data", nil, nil); });
        await(start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, wrong), @"invalid_response");
        FakeBackend *missing = backend(^(__unused uint32_t operation, __unused id input, Reply reply) { reply(secret, nil, nil); });
        await(start(HENGE_DEVICE_AUTH_BAA_DATA, secret, 1000, missing), @"invalid_response");
        FakeBackend *nonPlist = backend(^(__unused uint32_t operation, __unused id input, Reply reply) {
            reply(secret, @{@"unsupported": [NSSet setWithObject:secret]}, nil);
        });
        await(start(HENGE_DEVICE_AUTH_BAA_DATA, secret, 1000, nonPlist), @"unsupported_result_type");
        FakeBackend *huge = backend(^(__unused uint32_t operation, __unused id input, Reply reply) {
            reply([NSMutableData dataWithLength:HENGE_DEVICE_AUTH_MAX_RESULT_BYTES + 1], nil, nil);
        });
        await(start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, huge), @"unsupported_result_type");
        FakeBackend *exception = backend(^(__unused uint32_t operation, __unused id input, __unused Reply reply) {
            @throw [NSException exceptionWithName:@"PrivateException" reason:@"SYNTHETIC-SECRET" userInfo:nil];
        });
        await(start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, exception), @"objc_exception");

        /* Deadline finishes once, but does not pretend it cancelled the native
         * operation. Its late callback releases the lease without a second reply. */
        __block Reply delayed = nil;
        dispatch_semaphore_t invoked = dispatch_semaphore_create(0);
        FakeBackend *slow = backend(^(__unused uint32_t operation, __unused id input, Reply reply) {
            delayed = [reply copy]; dispatch_semaphore_signal(invoked);
        });
        Receipt *timeout = start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 100, slow);
        waitFor(invoked); await(timeout, @"timed_out");
        await(start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, token), @"busy");
        delayed(secret, nil, nil); delayed = nil;
        [timeout.lock lock]; require(timeout.count == 1, "late callback does not complete again"); [timeout.lock unlock];
        await(start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, token), @"success");

        /* A duplicate reply for an old request must not clear a NEW request's
         * native-operation gate. */
        __block Reply firstReply = nil, secondReply = nil;
        dispatch_semaphore_t firstStarted = dispatch_semaphore_create(0), secondStarted = dispatch_semaphore_create(0);
        FakeBackend *first = backend(^(__unused uint32_t operation, __unused id input, Reply reply) {
            firstReply = [reply copy]; dispatch_semaphore_signal(firstStarted);
        });
        FakeBackend *second = backend(^(__unused uint32_t operation, __unused id input, Reply reply) {
            secondReply = [reply copy]; dispatch_semaphore_signal(secondStarted);
        });
        Receipt *firstReceipt = start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, first);
        waitFor(firstStarted); firstReply(secret, nil, nil); await(firstReceipt, @"success");
        Receipt *secondReceipt = start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, second);
        waitFor(secondStarted); firstReply(secret, nil, nil);
        await(start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, token), @"busy");
        secondReply(secret, nil, nil); await(secondReceipt, @"success");
        firstReply = nil; secondReply = nil;

        dispatch_group_t race = dispatch_group_create();
        FakeBackend *racing = backend(^(__unused uint32_t operation, __unused id input, Reply reply) {
            for (int i = 0; i < 16; i++) dispatch_group_async(race, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                reply(secret, nil, nil);
            });
        });
        Receipt *raced = start(HENGE_DEVICE_AUTH_DC_TOKEN, nil, 1000, racing);
        await(raced, @"success");
        require(dispatch_group_wait(race, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0, "all duplicate callbacks returned");
        [raced.lock lock]; require(raced.count == 1, "concurrent completions remain one-shot"); [raced.lock unlock];
        puts("PASS: synthetic DeviceAuth host tests; no Apple token/signature generated");
        printf("checks=%u\n", atomic_load(&checks));
    }
    return 0;
}
