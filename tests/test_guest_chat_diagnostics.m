#import "../tools/guest-chat-diagnostics.h"
#include <assert.h>
#include <math.h>
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
        request[@"collect"] = @NO;
        assert(HengeChatDiagnosticsValidateRequest(json(request), now, NO));
        // At host now+120 these timestamps are expired, but a guest clock 90 seconds behind sees them
        // as fresh. An explicit false still permits only the heartbeat, never collect/log show.
        assert(!HengeChatDiagnosticsValidateRequest(json(request), [now dateByAddingTimeInterval:30], YES));
        request[@"collect"] = @YES;
        assert(HengeChatDiagnosticsValidateRequest(json(request), [now dateByAddingTimeInterval:30], YES));
        for (id invalid in @[@0, @1, @"false", NSNull.null]) {
            request[@"collect"] = invalid;
            assert(!HengeChatDiagnosticsValidateRequest(json(request), now, NO));
        }
        [request removeObjectForKey:@"collect"]; // Legacy hosts omit this field and retain existing behavior.
        assert([HengeChatDiagnosticsValidateRequest(json(request), now, YES)[@"collection_mode"] isEqual:@"automatic"]);
        request[@"collection_mode"] = @"manual";
        assert([HengeChatDiagnosticsValidateRequest(json(request), now, YES)[@"collection_mode"] isEqual:@"manual"]);
        request[@"collect"] = @NO;
        assert(!HengeChatDiagnosticsValidateRequest(json(request), now, YES)); // A mode never upgrades heartbeat permission.
        [request removeObjectForKey:@"collect"];
        for (id invalid in @[@YES, @1, @"live_stream", @"MANUAL", NSNull.null]) {
            request[@"collection_mode"] = invalid;
            assert(!HengeChatDiagnosticsValidateRequest(json(request), now, NO));
        }
        [request removeObjectForKey:@"collection_mode"];
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
        // The production prefilter must include the same DCDevice form the classifier recognizes,
        // and the executable discovered in the installed app's Info.plist.
        NSString *predicateText = HengeChatDiagnosticsLogPredicate(@"CodexFixture", @"com.openai.codex.fixture");
        NSPredicate *predicate = [NSPredicate predicateWithFormat:predicateText];
        NSDictionary *event = @{@"process": @"CodexFixture", @"subsystem": @"com.openai.codex.fixture",
            @"eventMessage": [@"[DCDevice] supported=false " stringByAppendingString:secret],
            @"timestamp": @"2026-11-15 22:00:00.000000+0800"};
        assert([predicate evaluateWithObject:event]);
        assert((![predicate evaluateWithObject:@{@"process": @"UnrelatedFixture", @"subsystem": @"com.example.unrelated",
                                                @"eventMessage": @"[DCDevice] supported=false"}]));
        NSString *line = [[NSString alloc] initWithData:json(event) encoding:NSUTF8StringEncoding];
        NSString *ndjson = [line stringByAppendingString:@"\n{\"finished\":true}\n"];
        NSDictionary *parsed = HengeChatDiagnosticsTestLogCommand(@"/usr/bin/printf", @[@"%s", ndjson], 2,
                                                                 @"CodexFixture", @"com.openai.codex.fixture");
        assert([parsed[@"log_counts_status"] isEqual:@"complete"]);
        assert([parsed[@"log_command_status"] isEqual:@"complete"] && [parsed[@"log_command_started"] boolValue]);
        assert([parsed[@"log_command_exit_code"] isEqual:@0]);
        assert([parsed[@"log_event_count"] isEqual:@1] && [parsed[@"chatgpt_matched_event_count"] isEqual:@1]);
        assert([parsed[@"error_devicecheck_unsupported_count"] isEqual:@1]);
        assert([parsed[@"first_match_utc"] isEqual:@"2026-11-15T14:00:00Z"]);
        assert(![[[NSString alloc] initWithData:json(parsed) encoding:NSUTF8StringEncoding] containsString:secret]);

        // The same production runner sees a complete event before its child stalls. Preserve that
        // evidence as a lower bound instead of discarding all output and manufacturing a zero.
        NSString *delayed = [NSString stringWithFormat:@"printf '%%s\\n' '%@'; exec /bin/sleep 5", line];
        parsed = HengeChatDiagnosticsTestLogCommand(@"/bin/sh", @[@"-c", delayed], 0.75,
                                                    @"CodexFixture", @"com.openai.codex.fixture");
        assert([parsed[@"log_command_status"] isEqual:@"timed_out"] && [parsed[@"log_command_started"] boolValue]);
        assert([parsed[@"log_counts_status"] isEqual:@"partial"] && [parsed[@"log_status"] isEqual:@"timed_out"]);
        assert([parsed[@"classification"] isEqual:@"devicecheck_unavailable_observed"]);
        assert([parsed[@"error_devicecheck_unsupported_count"] isEqual:@1]);

        parsed = HengeChatDiagnosticsTestLogCommand(@"/usr/bin/printf", @[@"%s", @"{\"eventMessage\":\"devicecheck_unsupported_device"], 2,
                                                    @"ChatGPT", nil);
        assert([parsed[@"log_counts_status"] isEqual:@"unavailable"]);
        assert([parsed[@"classification"] isEqual:@"logs_unavailable"]);
        assert([parsed[@"log_event_count"] isEqual:@0]); // An unterminated JSON fragment is not an event.
        NSString *oversized = [@"{\"eventMessage\":\"devicecheck_unsupported_device " stringByPaddingToLength:70000 withString:@"x" startingAtIndex:0];
        parsed = HengeChatDiagnosticsTestLogCommand(@"/usr/bin/printf", @[@"%s", oversized], 2, @"ChatGPT", nil);
        assert([parsed[@"log_command_status"] isEqual:@"output_limit"]);
        assert([parsed[@"log_counts_status"] isEqual:@"unavailable"] && [parsed[@"log_event_count"] isEqual:@0]);

        NSString *nonzero = [NSString stringWithFormat:@"printf '%%s\\n' '%@'; exit 7", line];
        parsed = HengeChatDiagnosticsTestLogCommand(@"/bin/sh", @[@"-c", nonzero], 2, @"CodexFixture", nil);
        assert([parsed[@"log_command_status"] isEqual:@"exit_nonzero"] && [parsed[@"log_command_exit_code"] isEqual:@7]);
        assert([parsed[@"log_counts_status"] isEqual:@"partial"] && [parsed[@"matched_event_count"] isEqual:@1]);
        parsed = HengeChatDiagnosticsTestLogCommand(@"/usr/bin/true", @[], 0, @"ChatGPT", nil);
        assert([parsed[@"log_command_status"] isEqual:@"not_run_budget"] && ![parsed[@"log_command_started"] boolValue]);
        assert([parsed[@"log_counts_status"] isEqual:@"unavailable"]);
        parsed = HengeChatDiagnosticsTestLogCommand(@"/henge-synthetic-missing-command", @[], 2, @"ChatGPT", nil);
        assert([parsed[@"log_command_status"] isEqual:@"launch_failed"] && ![parsed[@"log_command_started"] boolValue]);
        parsed = HengeChatDiagnosticsTestLogCommand(@"/usr/bin/printf", @[@"%s", @"{\"finished\":true}\n"], 2, @"ChatGPT", nil);
        assert([parsed[@"log_counts_status"] isEqual:@"complete"] && [parsed[@"log_event_count"] isEqual:@0]);
        assert([parsed[@"classification"] isEqual:@"no_known_error_observed"]);

        NSDictionary *manualPlan = HengeChatDiagnosticsTestBudgetPlan(@"manual", 60);
        NSDictionary *automaticPlan = HengeChatDiagnosticsTestBudgetPlan(@"automatic", 60);
        assert([manualPlan[@"collection_budget_ms"] isEqual:@35000] && [manualPlan[@"log_command_budget_ms"] isEqual:@30000]);
        assert([automaticPlan[@"collection_budget_ms"] isEqual:@10000] && [automaticPlan[@"log_command_budget_ms"] isEqual:@8000]);
        assert([manualPlan[@"signature_display_budget_ms"] isEqual:@3000] && [manualPlan[@"signature_verify_budget_ms"] isEqual:@0]);
        assert([HengeChatDiagnosticsTestBudgetPlan(@"manual", 20)[@"collection_effective_budget_ms"] isEqual:@18000]);
        assert([HengeChatDiagnosticsTestBudgetPlan(@"manual", 2)[@"collection_effective_budget_ms"] isEqual:@0]);
        assert([HengeChatDiagnosticsTestBudgetPlan(@"manual", NAN)[@"collection_effective_budget_ms"] isEqual:@0]);
        assert(!HengeChatDiagnosticsTestBudgetPlan(@"arbitrary", 60));
        // Exercise the actual profile + production child runner. This complete event only
        // becomes available after the old eight-second budget, and must now be retained.
        NSString *slowEvidence = [NSString stringWithFormat:@"/bin/sleep 9; printf '%%s\\n' '%@'; printf '%%s\\n' '{\"finished\":true}'", line];
        parsed = HengeChatDiagnosticsTestPlannedLogCommand(@"manual", 60, @"/bin/sh", @[@"-c", slowEvidence],
                                                          @"CodexFixture", @"com.openai.codex.fixture");
        assert([parsed[@"log_command_status"] isEqual:@"complete"] && [parsed[@"log_counts_status"] isEqual:@"complete"]);
        assert([parsed[@"collection_elapsed_ms"] unsignedIntegerValue] >= 8500);
        assert([parsed[@"log_event_count"] isEqual:@1] && [parsed[@"error_devicecheck_unsupported_count"] isEqual:@1]);
        assert([parsed[@"log_command_effective_budget_ms"] unsignedIntegerValue] > 8000 &&
               [parsed[@"log_command_effective_budget_ms"] unsignedIntegerValue] <= 30000);
        assert(![[[NSString alloc] initWithData:json(parsed) encoding:NSUTF8StringEncoding] containsString:secret]);
        parsed = HengeChatDiagnosticsTestPlannedLogCommand(@"manual", 2.75, @"/bin/sh", @[@"-c", delayed], @"CodexFixture", nil);
        assert([parsed[@"log_command_status"] isEqual:@"timed_out"] && [parsed[@"log_counts_status"] isEqual:@"partial"]);
        assert([parsed[@"error_devicecheck_unsupported_count"] isEqual:@1]);
        assert([parsed[@"collection_effective_budget_ms"] isEqual:@750]);
        assert([parsed[@"log_command_effective_budget_ms"] unsignedIntegerValue] <= 750);
        parsed = HengeChatDiagnosticsTestPlannedLogCommand(@"manual", 2.25, @"/bin/sleep", @[@"5"], @"ChatGPT", nil);
        assert([parsed[@"log_counts_status"] isEqual:@"unavailable"] && [parsed[@"classification"] isEqual:@"logs_unavailable"]);
        parsed = HengeChatDiagnosticsTestPlannedLogCommand(@"manual", 2, @"/usr/bin/true", @[], @"ChatGPT", nil);
        assert([parsed[@"log_command_status"] isEqual:@"not_run_budget"] && ![parsed[@"log_command_started"] boolValue]);

        NSFileManager *files = NSFileManager.defaultManager;
        NSString *folder = [NSTemporaryDirectory() stringByAppendingPathComponent:[@"henge-electron-metadata-" stringByAppendingString:NSUUID.UUID.UUIDString]];
        NSString *app = [folder stringByAppendingPathComponent:@"Fixture.app"];
        NSString *framework = [app stringByAppendingPathComponent:@"Contents/Frameworks/Electron Framework.framework"];
        NSString *resources = [framework stringByAppendingPathComponent:@"Versions/A/Resources"];
        assert([files createDirectoryAtPath:resources withIntermediateDirectories:YES attributes:nil error:NULL]);
        assert([HengeChatDiagnosticsTestElectronMetadata(nil)[@"electron_framework_metadata_status"] isEqual:@"not_found"]);
        assert([HengeChatDiagnosticsTestElectronMetadata(app)[@"electron_framework_metadata_status"] isEqual:@"not_found"]);
        NSString *plistPath = [resources stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *plist = @{@"CFBundleShortVersionString": @"42.0.0-beta.2", @"ArbitrarySecret": secret};
        NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
        assert([plistData writeToFile:plistPath atomically:YES]);
        NSDictionary *electron = HengeChatDiagnosticsTestElectronMetadata(app);
        assert([electron[@"electron_framework_metadata_status"] isEqual:@"complete"] && [electron[@"electron_framework_version"] isEqual:@"42.0.0-beta.2"]);
        assert(electron.count == 2 && ![[[NSString alloc] initWithData:json(electron) encoding:NSUTF8StringEncoding] containsString:secret]);
        NSString *resourceLink = [framework stringByAppendingPathComponent:@"Resources"];
        assert([files createSymbolicLinkAtPath:resourceLink withDestinationPath:@"Versions/A/Resources" error:NULL]);
        assert([HengeChatDiagnosticsTestElectronMetadata(app)[@"electron_framework_version"] isEqual:@"42.0.0-beta.2"]);
        for (id invalid in @[secret, @"42.0.0?token=secret", @"42.0", @YES]) {
            plistData = [NSPropertyListSerialization dataWithPropertyList:@{@"CFBundleShortVersionString": invalid}
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            assert([plistData writeToFile:plistPath atomically:YES]);
            electron = HengeChatDiagnosticsTestElectronMetadata(app);
            assert([electron[@"electron_framework_metadata_status"] isEqual:@"invalid"] && !electron[@"electron_framework_version"]);
        }
        assert([[NSMutableData dataWithLength:65537] writeToFile:plistPath atomically:YES]);
        assert([HengeChatDiagnosticsTestElectronMetadata(app)[@"electron_framework_metadata_status"] isEqual:@"unavailable"]);
        assert([files removeItemAtPath:resourceLink error:NULL]);
        assert([files createSymbolicLinkAtPath:resourceLink withDestinationPath:folder error:NULL]);
        assert([plistData writeToFile:[folder stringByAppendingPathComponent:@"Info.plist"] atomically:YES]);
        assert([HengeChatDiagnosticsTestElectronMetadata(app)[@"electron_framework_metadata_status"] isEqual:@"unavailable"]);
        assert([files removeItemAtPath:folder error:NULL]);
        puts("PASS: manual 35s/30s budget retains delayed synthetic evidence; TTL clamps, partial results and fixed Electron metadata");
        puts("PASS: guest request bounds, fixed error categories, NDJSON partial evidence, privacy, child-output cap and independent deadline");
    }
    return 0;
}
