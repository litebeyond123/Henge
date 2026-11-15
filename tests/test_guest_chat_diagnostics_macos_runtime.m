/* Actual macOS log-command integration gate. Compile against the production collector:
   env -u SDKROOT -u IPHONEOS_DEPLOYMENT_TARGET xcrun --sdk macosx clang \
     -fobjc-arc -Wall -Wextra -O2 -mmacosx-version-min=12.0 \
     -DHENGE_CHAT_DIAGNOSTICS_TEST -framework Foundation \
     tests/test_guest_chat_diagnostics_macos_runtime.m tools/guest-chat-diagnostics.m \
     -o /tmp/henge-test-guest-chat-macos-runtime
   /tmp/henge-test-guest-chat-macos-runtime
*/
//
// No sudo, log configuration changes, real ChatGPT process, or existing application data.
// The predicate admits only this process's one synthetic message, in a random category.
// Raw log dictionaries stay in bounded memory and are never printed or written to disk.
// ERROR is intentional: --info/--debug cannot recover messages that were never persisted.
// This tests real log output/command/classification, not DeviceCheck or VM performance.

#import "../tools/guest-chat-diagnostics.h"
#import <os/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#if !defined(__APPLE__) || !defined(HENGE_CHAT_DIAGNOSTICS_TEST)
#error This integration gate requires macOS and HENGE_CHAT_DIAGNOSTICS_TEST.
#endif

static void require(BOOL condition, const char *reason) {
    if (!condition) {
        // Callers supply only fixed reason codes, never log text, paths or exceptions.
        fprintf(stderr, "guest_chat_macos_runtime: FAIL (%s)\n", reason);
        exit(1);
    }
}

static double monotonicSeconds(void) {
    struct timespec now;
    require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic_clock_failed");
    return now.tv_sec + now.tv_nsec / 1e9;
}

// Validate actual `log show` dictionaries independently of the production parser.
// A footer is not a log event and must not contribute to the classifier's counts.
static NSUInteger validateNDJSON(NSData *data, NSString *subsystem, NSString *category,
                                 NSString *message, NSString *executable) {
    require(data.length > 0 && data.length <= 128 * 1024, "raw_output_size_invalid");
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    require(text != nil, "raw_output_not_utf8");
    NSUInteger events = 0, footers = 0;
    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if ([line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length == 0) continue;
        require(footers == 0, "record_after_finished_footer");
        require(line.length <= 65536, "ndjson_line_too_large");
        id value = [NSJSONSerialization JSONObjectWithData:[line dataUsingEncoding:NSUTF8StringEncoding]
                                                  options:0 error:NULL];
        require([value isKindOfClass:NSDictionary.class], "ndjson_line_not_dictionary");
        NSDictionary *event = value;
        if (event[@"finished"] != nil && event[@"eventMessage"] == nil) {
            require([event[@"finished"] isKindOfClass:NSNumber.class] && [event[@"finished"] boolValue],
                    "finished_footer_invalid");
            if (event[@"count"] != nil) {
                require([event[@"count"] isKindOfClass:NSNumber.class] &&
                        [event[@"count"] unsignedIntegerValue] == events, "footer_count_mismatch");
            }
            footers++;
            continue;
        }
        require([event[@"eventMessage"] isEqual:message], "unexpected_event_message");
        require([event[@"subsystem"] isEqual:subsystem], "unexpected_event_subsystem");
        require([event[@"category"] isEqual:category], "unexpected_event_category");
        require([event[@"processID"] isKindOfClass:NSNumber.class] &&
                [event[@"processID"] intValue] == getpid(), "unexpected_event_pid");
        NSString *path = [event[@"processImagePath"] isKindOfClass:NSString.class] ? event[@"processImagePath"] : nil;
        NSString *process = [event[@"process"] isKindOfClass:NSString.class] ? event[@"process"] : nil;
        require([[path lastPathComponent] isEqual:executable] || [process isEqual:executable],
                "unexpected_event_process");
        require([event[@"timestamp"] isKindOfClass:NSString.class] && [event[@"timestamp"] length] > 0,
                "event_timestamp_missing");
        require([event[@"messageType"] isKindOfClass:NSString.class] &&
                [event[@"messageType"] caseInsensitiveCompare:@"Error"] == NSOrderedSame,
                "event_not_error_level");
        events++;
        require(events <= 1, "synthetic_event_duplicated");
    }
    require(footers == 1, "finished_footer_missing");
    return events;
}

static void checkNumber(NSDictionary *summary, NSString *key, NSUInteger expected, const char *reason) {
    id value = summary[key];
    require([value isKindOfClass:NSNumber.class] && [value unsignedIntegerValue] == expected, reason);
}

static int runGate(void) {
    double started = monotonicSeconds();
    NSString *subsystem = @"org.henge.tests.collector";
    NSString *category = NSUUID.UUID.UUIDString;
    NSString *executable = [NSProcessInfo.processInfo.arguments.firstObject lastPathComponent];
    require(executable.length > 0 && executable.length <= 64, "test_executable_name_invalid");
    NSString *message = [NSString stringWithFormat:
        @"HENGE_SYNTHETIC DeviceCheck is not supported. run=%@", category];
    os_log_t logger = os_log_create(subsystem.UTF8String, category.UTF8String);
    require(logger != nil, "synthetic_logger_unavailable");

    // Use the production prefilter, further restricted so no unrelated CI log can be returned.
    NSString *production = HengeChatDiagnosticsLogPredicate(executable, subsystem);
    NSString *onlyThisEvent = [NSPredicate predicateWithFormat:
        @"processID == %d AND subsystem == %@ AND category == %@ AND eventMessage == %@",
        getpid(), subsystem, category, message].predicateFormat;
    NSString *predicate = [NSString stringWithFormat:@"(%@) AND (%@)", production, onlyThisEvent];
    NSArray<NSString *> *arguments = @[@"show", @"--last", @"1m", @"--style", @"ndjson",
                                      @"--info", @"--debug", @"--predicate", predicate];

    // Explicitly public contains only a constant test string and a newly generated UUID.
    os_log_error(logger, "HENGE_SYNTHETIC DeviceCheck is not supported. run=%{public}s", category.UTF8String);

    NSUInteger attempts = 0, rawEvents = 0, rawBytes = 0;
    // logd persistence is asynchronous. Retry only a successful, valid, zero-event snapshot.
    // A command failure, timeout or malformed record is immediately fatal, never retried away.
    for (NSUInteger attempt = 0; attempt < 5; attempt++) {
        [NSThread sleepForTimeInterval:0.5];
        attempts++;
        NSString *status = nil;
        NSData *raw = HengeChatDiagnosticsTestCommand(@"/usr/bin/log", arguments, 5.0, 128 * 1024, &status);
        require([status isEqual:@"complete"], "real_log_command_not_complete");
        rawEvents = validateNDJSON(raw, subsystem, category, message, executable);
        rawBytes = raw.length;
        if (rawEvents == 1) break;
    }
    require(rawEvents == 1, "synthetic_event_not_persisted");

    // Re-read the exact same event through the production bounded runner + NDJSON accumulator.
    // No mock process or reserialized fixture intervenes in this path.
    NSDictionary *summary = HengeChatDiagnosticsTestLogCommand(@"/usr/bin/log", arguments, 5.0,
                                                              executable, subsystem);
    require([summary[@"log_command_status"] isEqual:@"complete"], "production_log_command_not_complete");
    checkNumber(summary, @"log_command_started", 1, "production_log_command_not_started");
    checkNumber(summary, @"log_command_exit_code", 0, "production_log_command_exit_nonzero");
    require(summary[@"log_command_termination_signal"] == nil, "production_log_command_signaled");
    require([summary[@"log_status"] isEqual:@"complete"] && [summary[@"log_counts_status"] isEqual:@"complete"],
            "production_ndjson_parse_not_complete");
    require([summary[@"classification"] isEqual:@"devicecheck_unavailable_observed"],
            "production_classification_mismatch");
    checkNumber(summary, @"log_event_count", 1, "production_event_count_mismatch");
    checkNumber(summary, @"matched_event_count", 1, "production_matched_count_mismatch");
    checkNumber(summary, @"error_devicecheck_unsupported_count", 1, "production_unsupported_count_mismatch");
    checkNumber(summary, @"chatgpt_matched_event_count", 1, "production_configured_source_count_mismatch");
    checkNumber(summary, @"system_devicecheck_matched_event_count", 0, "production_system_source_count_mismatch");
    checkNumber(summary, @"unknown_source_matched_event_count", 0, "production_unknown_source_count_mismatch");
    require([summary[@"first_match_utc"] isKindOfClass:NSString.class] &&
            [summary[@"last_match_utc"] isKindOfClass:NSString.class], "production_event_time_unparsed");
    NSData *safeJSON = [NSJSONSerialization dataWithJSONObject:summary options:0 error:NULL];
    NSString *safeText = [[NSString alloc] initWithData:safeJSON encoding:NSUTF8StringEncoding];
    require(safeText != nil && [safeText rangeOfString:category].location == NSNotFound &&
            [safeText rangeOfString:@"HENGE_SYNTHETIC"].location == NSNotFound &&
            [safeText rangeOfString:subsystem].location == NSNotFound,
            "production_summary_retained_raw_event_data");

    NSOperatingSystemVersion version = NSProcessInfo.processInfo.operatingSystemVersion;
    // Deliberate allowlist: no paths, message text, UUID, PID, environment, or raw dictionaries.
    printf("{\"gate\":\"guest_chat_macos_command\",\"status\":\"passed\","
           "\"macos\":\"%ld.%ld.%ld\",\"synthetic_only\":true,\"privilege_required\":false,"
           "\"persisted_error_events\":1,\"ndjson_footer_seen\":true,\"event_classified\":true,"
           "\"attempts\":%lu,\"filtered_output_bytes\":%lu,\"production_command_elapsed_ms\":%lu,"
           "\"total_elapsed_ms\":%lu,\"debug_persistence_tested\":false}\n",
           (long)version.majorVersion, (long)version.minorVersion, (long)version.patchVersion,
           (unsigned long)attempts, (unsigned long)rawBytes,
           (unsigned long)[summary[@"log_command_elapsed_ms"] unsignedIntegerValue],
           (unsigned long)((monotonicSeconds() - started) * 1000));
    return 0;
}

int main(void) {
    @autoreleasepool {
        @try { return runGate(); }
        @catch (__unused NSException *exception) {
            // An exception's reason may contain system paths or output. Keep it out of CI artifacts.
            fprintf(stderr, "guest_chat_macos_runtime: FAIL (unexpected_foundation_exception)\n");
            return 1;
        }
    }
}
