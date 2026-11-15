#import "../tools/guest-chat-diagnostics.h"
#include <assert.h>
#include <stdio.h>

static NSData *json(id value) { return [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL]; }

int main(void) {
    @autoreleasepool {
        NSISO8601DateFormatter *format = [NSISO8601DateFormatter new];
        NSDate *now = [format dateFromString:@"2026-11-15T14:00:00Z"];
        NSMutableDictionary *request = [@{@"schema_version": @1, @"task": @"chat_error_summary",
            @"vm_session_id": @"D378AA81-830C-4F98-B9B4-0AE0A0D28E32", @"request_id": @"2B7DD5D2-728C-434D-BE3C-731665C86CAB",
            @"created_utc": @"2026-11-15T14:00:00Z", @"expires_utc": @"2026-11-15T14:01:00Z"} mutableCopy];
        assert(HengeChatDiagnosticsValidateRequest(json(request), now, YES));
        assert(!HengeChatDiagnosticsValidateRequest(json(request), [now dateByAddingTimeInterval:61], YES));
        assert(HengeChatDiagnosticsValidateRequest(json(request), [now dateByAddingTimeInterval:61], NO));
        request[@"task"] = @"run_command";
        assert(!HengeChatDiagnosticsValidateRequest(json(request), now, YES));
        request[@"task"] = @"chat_error_summary";
        request[@"expires_utc"] = @"2026-11-15T15:00:00Z";
        assert(!HengeChatDiagnosticsValidateRequest(json(request), now, YES));
        request[@"expires_utc"] = @"2026-11-15T14:01:00Z";
        request[@"request_id"] = @"not-a-uuid\r\nInjected: secret";
        assert(!HengeChatDiagnosticsValidateRequest(json(request), now, YES));

        NSString *secret = @"PRIVATE_CONVERSATION_COOKIE_TOKEN_EMAIL_MUST_NOT_LEAVE";
        NSArray *events = @[
            @{@"eventMessage": [@"devicecheck_unsupported_device " stringByAppendingString:secret], @"timestamp": @"2026-11-15 13:59:00.000000+0000"},
            @{@"eventMessage": @"DeviceCheck token generation is unavailable"},
            @{@"eventMessage": [@"NSURLErrorDomain Code=-1001 https://example.invalid/?token=" stringByAppendingString:secret]},
            @{@"eventMessage": @"HTTP status 401"}, @{@"eventMessage": @"statusCode=429"},
            @{@"eventMessage": @"HTTP/2 503"}, @{@"eventMessage": @"statusCode=40123"},
            @{@"eventMessage": secret, @"subsystem": secret, @"processImagePath": secret},
            @{@"eventMessage": @"normal successful DeviceCheck request"},
            @{@"eventMessage": @"DeviceCheck is not supported.", @"process": @"devicecheckd", @"messageType": @"Debug"},
            @{@"eventMessage": @"[DeviceCheck] isSupported=false", @"processImagePath": @"/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"},
            @{@"eventMessage": @[@"not a message"]}
        ];
        NSDictionary *summary = HengeChatDiagnosticsClassifyLog(json(events));
        assert([summary[@"log_status"] isEqual:@"complete"]);
        assert([summary[@"classification"] isEqual:@"devicecheck_unavailable_observed"]);
        assert([summary[@"matched_event_count"] isEqual:@8]);
        assert([summary[@"error_devicecheck_unsupported_count"] isEqual:@3]);
        assert([summary[@"chatgpt_matched_event_count"] isEqual:@1]);
        assert([summary[@"system_devicecheck_matched_event_count"] isEqual:@1]);
        assert([summary[@"unknown_source_matched_event_count"] isEqual:@6]);
        assert([summary[@"error_devicecheck_token_unavailable_count"] isEqual:@1]);
        assert([summary[@"error_network_timeout_count"] isEqual:@1]);
        assert([summary[@"error_http_401_count"] isEqual:@1]);
        assert([summary[@"error_http_429_count"] isEqual:@1]);
        assert([summary[@"error_http_5xx_count"] isEqual:@1]);
        NSString *serialized = [[NSString alloc] initWithData:json(summary) encoding:NSUTF8StringEncoding];
        assert(![serialized containsString:secret] && ![serialized containsString:@"example.invalid"]);
        assert(!summary[@"eventMessage"] && !summary[@"processImagePath"]);
        assert([HengeChatDiagnosticsClassifyLog([@"[truncated" dataUsingEncoding:NSUTF8StringEncoding])[@"log_status"] isEqual:@"unavailable"]);
        assert([HengeChatDiagnosticsClassifyLog([NSMutableData dataWithLength:2 * 1024 * 1024 + 1])[@"log_status"] isEqual:@"unavailable"]);
        assert([HengeChatDiagnosticsClassifyLog(json(@[]))[@"classification"] isEqual:@"no_known_error_observed"]);

        NSString *status;
        NSData *output = HengeChatDiagnosticsTestCommand(@"/usr/bin/printf", @[@"safe-output"], 2, 100, &status);
        assert([status isEqual:@"complete"] && [[[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] isEqual:@"safe-output"]);
        output = HengeChatDiagnosticsTestCommand(@"/usr/bin/true", @[], 2, 100, &status);
        assert(output && output.length == 0 && [status isEqual:@"complete"]);
        double start = NSProcessInfo.processInfo.systemUptime;
        output = HengeChatDiagnosticsTestCommand(@"/bin/sleep", @[@"5"], 0.1, 100, &status);
        assert(!output && [status isEqual:@"timed_out"] && NSProcessInfo.processInfo.systemUptime - start < 2);
        output = HengeChatDiagnosticsTestCommand(@"/usr/bin/yes", @[@"bounded"], 2, 100, &status);
        assert(!output && [status isEqual:@"output_limit"]);
        puts("PASS: guest request bounds, error allowlist, privacy, child-output cap and deadline");
    }
    return 0;
}
