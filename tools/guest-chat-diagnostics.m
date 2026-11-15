#import "guest-chat-diagnostics.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const requestPath = @"/Henge-Chat-Diagnostics/request.json";
static NSString *const reportPath = @"/Henge-Chat-Diagnostics/report.json";
static NSString *const readyPath = @"/Henge-Chat-Diagnostics/agent-status.json";
static atomic_bool busy = false;
static NSString *handledRequest;
static NSString *readySession;
static double lastReady;
static NSData *pendingReport;

static double mono(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec + now.tv_nsec / 1e9;
}

static NSString *utc(NSDate *date) {
    NSISO8601DateFormatter *format = [NSISO8601DateFormatter new];
    return [format stringFromDate:date];
}

static NSDate *dateValue(id value) {
    if (![value isKindOfClass:NSString.class] || [value length] > 40) return nil;
    NSISO8601DateFormatter *format = [NSISO8601DateFormatter new];
    NSDate *date = [format dateFromString:value];
    if (!date) {
        format.formatOptions = NSISO8601DateFormatWithInternetDateTime | NSISO8601DateFormatWithFractionalSeconds;
        date = [format dateFromString:value];
    }
    return date;
}

static BOOL matches(id value, NSString *pattern, NSUInteger limit) {
    if (![value isKindOfClass:NSString.class] || ![value length] || [value length] > limit) return NO;
    NSRange range = [value rangeOfString:pattern options:NSRegularExpressionSearch];
    return range.location == 0 && range.length == [value length];
}

static BOOL uuid(id value) {
    return [value isKindOfClass:NSString.class] && [value length] == 36 &&
           [[NSUUID alloc] initWithUUIDString:value] != nil;
}

NSDictionary *HengeChatDiagnosticsValidateRequest(NSData *data, NSDate *now, BOOL requireFresh) {
    if (!data || data.length > 4096) return nil;
    id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![json isKindOfClass:NSDictionary.class] || ![json[@"schema_version"] isEqual:@1] ||
        ![json[@"task"] isEqual:@"chat_error_summary"] ||
        !uuid(json[@"vm_session_id"]) || !uuid(json[@"request_id"])) return nil;
    NSDate *created = dateValue(json[@"created_utc"]), *expires = dateValue(json[@"expires_utc"]);
    NSTimeInterval duration = [expires timeIntervalSinceDate:created ?: now];
    if (!created || !expires || duration < 1 || duration > 90) return nil;
    if (requireFresh && ([created timeIntervalSinceDate:now] > 30 || [expires timeIntervalSinceDate:now] <= 0)) return nil;
    // Return a new allowlisted dictionary; the caller never evaluates request strings as code/paths.
    return @{@"schema_version": @1, @"task": @"chat_error_summary",
             @"vm_session_id": [json[@"vm_session_id"] uppercaseString],
             @"request_id": [json[@"request_id"] uppercaseString],
             @"created_utc": utc(created), @"expires_utc": utc(expires)};
}

static NSArray<NSString *> *countKeys(void) {
    return @[@"error_devicecheck_unsupported_count", @"error_devicecheck_token_unavailable_count",
             @"error_devicecheck_other_count", @"error_network_timeout_count", @"error_network_offline_count",
             @"error_network_connection_lost_count", @"error_network_tls_count", @"error_http_401_count",
             @"error_http_403_count", @"error_http_429_count", @"error_http_5xx_count", @"error_request_failed_count"];
}

static BOOL contains(NSString *text, NSString *needle) {
    return [text rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound;
}

static BOOL regex(NSString *text, NSString *pattern) {
    return [text rangeOfString:pattern options:NSRegularExpressionSearch | NSCaseInsensitiveSearch].location != NSNotFound;
}

static NSDate *logDate(id value) {
    NSDate *date = dateValue(value);
    if (date || ![value isKindOfClass:NSString.class] || [value length] > 40) return date;
    NSDateFormatter *format = [NSDateFormatter new];
    format.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    format.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSSSSSZ";
    return [format dateFromString:value];
}

NSDictionary *HengeChatDiagnosticsClassifyLog(NSData *data) {
    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:
        @{@"log_status": @"unavailable", @"log_event_count": @0, @"matched_event_count": @0,
          @"classification": @"logs_unavailable", @"source_scope": @"mixed_chatgpt_device_services",
          @"chatgpt_matched_event_count": @0, @"system_devicecheck_matched_event_count": @0,
          @"unknown_source_matched_event_count": @0}];
    for (NSString *key in countKeys()) result[key] = @0;
    if (!data || data.length > 2 * 1024 * 1024) return result;
    id events = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![events isKindOfClass:NSArray.class] || [events count] > 50000) return result;
    result[@"log_status"] = @"complete";
    result[@"log_event_count"] = @([events count]);
    NSUInteger total = 0;
    NSDate *first = nil, *last = nil;
    for (id event in events) {
        if (![event isKindOfClass:NSDictionary.class]) continue;
        NSString *message = event[@"eventMessage"];
        if (![message isKindOfClass:NSString.class] || message.length > 65536) continue;
        NSMutableSet<NSString *> *hits = [NSMutableSet set];
        if (contains(message, @"devicecheck_unsupported_device") || contains(message, @"DeviceCheck is not supported") ||
            ((contains(message, @"DeviceCheck") || contains(message, @"DCDevice")) &&
             regex(message, @"\\b(?:isSupported|supported)\\s*[:=]\\s*(?:false|0)\\b")))
            [hits addObject:@"error_devicecheck_unsupported_count"];
        if (contains(message, @"DeviceCheck token generation is unavailable")) [hits addObject:@"error_devicecheck_token_unavailable_count"];
        if ((contains(message, @"DeviceCheck") || contains(message, @"DCErrorDomain")) &&
            (contains(message, @"error") || contains(message, @"fail") || contains(message, @"unavailable") || contains(message, @"unsupported")) && hits.count == 0)
            [hits addObject:@"error_devicecheck_other_count"];
        BOOL urlError = contains(message, @"NSURLErrorDomain");
        if (urlError && regex(message, @"(?<![0-9])-1001(?![0-9])")) [hits addObject:@"error_network_timeout_count"];
        if (urlError && regex(message, @"(?<![0-9])-1009(?![0-9])")) [hits addObject:@"error_network_offline_count"];
        if (urlError && regex(message, @"(?<![0-9])-1005(?![0-9])")) [hits addObject:@"error_network_connection_lost_count"];
        if (urlError && regex(message, @"(?<![0-9])-120[0-6](?![0-9])")) [hits addObject:@"error_network_tls_count"];
        for (NSString *code in @[@"401", @"403", @"429"]) {
            NSString *pattern = [NSString stringWithFormat:@"(?:http(?:/[12](?:\\.[01])?)?[ :]+|status(?:code| code|_code)?[\\\" :==]+)%@(?![0-9])", code];
            if (regex(message, pattern)) [hits addObject:[NSString stringWithFormat:@"error_http_%@_count", code]];
        }
        if (regex(message, @"(?:http(?:/[12](?:\\.[01])?)?[ :]+|status(?:code| code|_code)?[\\\" :==]+)5[0-9]{2}(?![0-9])"))
            [hits addObject:@"error_http_5xx_count"];
        if (contains(message, @"request failed") || contains(message, @"request_failed") ||
            contains(message, @"failed to create conversation")) [hits addObject:@"error_request_failed_count"];
        if (!hits.count) continue;
        total++;
        for (NSString *key in hits) result[key] = @([result[key] unsignedIntegerValue] + 1);
        NSString *process = [event[@"process"] isKindOfClass:NSString.class] ? event[@"process"] : nil;
        if (!process && [event[@"processImagePath"] isKindOfClass:NSString.class]) process = [event[@"processImagePath"] lastPathComponent];
        NSString *subsystem = [event[@"subsystem"] isKindOfClass:NSString.class] ? event[@"subsystem"] : @"";
        NSString *scopeKey = [process isEqual:@"ChatGPT"] ? @"chatgpt_matched_event_count" :
            (([process isEqual:@"devicecheckd"] || [process isEqual:@"mobileactivationd"] || contains(subsystem, @"DeviceCheck"))
             ? @"system_devicecheck_matched_event_count" : @"unknown_source_matched_event_count");
        result[scopeKey] = @([result[scopeKey] unsignedIntegerValue] + 1);
        NSDate *date = logDate(event[@"timestamp"]);
        if (date && (!first || [date compare:first] == NSOrderedAscending)) first = date;
        if (date && (!last || [date compare:last] == NSOrderedDescending)) last = date;
    }
    result[@"matched_event_count"] = @(total);
    if (first) result[@"first_match_utc"] = utc(first);
    if (last) result[@"last_match_utc"] = utc(last);
    if ([result[@"error_devicecheck_unsupported_count"] unsignedIntegerValue] ||
        [result[@"error_devicecheck_token_unavailable_count"] unsignedIntegerValue]) result[@"classification"] = @"devicecheck_unavailable_observed";
    else if ([result[@"error_devicecheck_other_count"] unsignedIntegerValue]) result[@"classification"] = @"devicecheck_error_observed";
    else if ([result[@"error_network_timeout_count"] unsignedIntegerValue] || [result[@"error_network_offline_count"] unsignedIntegerValue] ||
             [result[@"error_network_connection_lost_count"] unsignedIntegerValue] || [result[@"error_network_tls_count"] unsignedIntegerValue]) result[@"classification"] = @"network_error_observed";
    else if ([result[@"error_http_401_count"] unsignedIntegerValue] || [result[@"error_http_403_count"] unsignedIntegerValue] ||
             [result[@"error_http_429_count"] unsignedIntegerValue] || [result[@"error_http_5xx_count"] unsignedIntegerValue]) result[@"classification"] = @"http_error_observed";
    else if (total) result[@"classification"] = @"request_error_observed";
    else result[@"classification"] = @"no_known_error_observed";
    // No raw eventMessage, subsystem, path, process arguments, private payload or log records leave this parser.
    return result;
}

// Output is bounded while being read. Nothing from a child process is written to disk or the helper log.
static NSData *run(NSString *path, NSArray<NSString *> *arguments, double deadline, NSUInteger limit,
                   BOOL captureError, NSString **status) {
    *status = @"unavailable";
    if (mono() >= deadline) { *status = @"timed_out"; return nil; }
    NSTask *task = [NSTask new];
    NSPipe *pipe = [NSPipe pipe];
    task.executableURL = [NSURL fileURLWithPath:path];
    task.arguments = arguments;
    task.standardInput = NSFileHandle.fileHandleWithNullDevice;
    task.standardOutput = pipe;
    task.standardError = captureError ? pipe : NSFileHandle.fileHandleWithNullDevice;
    if (![task launchAndReturnError:NULL]) return nil;
    [pipe.fileHandleForWriting closeFile];
    int fd = pipe.fileHandleForReading.fileDescriptor;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    NSMutableData *data = [NSMutableData data];
    BOOL eof = NO, exceeded = NO, timedOut = NO;
    while (!eof) {
        if (mono() >= deadline) { timedOut = YES; break; }
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int ready = poll(&p, 1, 50);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        if (!ready) {
            if (!task.running) { // Drain a child's final buffered output, then observe EOF.
                p.revents = POLLIN;
            } else continue;
        }
        char bytes[8192];
        ssize_t n = read(fd, bytes, sizeof bytes);
        if (n > 0) {
            if (data.length + (NSUInteger)n > limit) { exceeded = YES; break; }
            [data appendBytes:bytes length:(NSUInteger)n];
        } else if (!n) eof = YES;
        else if (errno != EAGAIN && errno != EINTR) break;
    }
    while (eof && !exceeded && !timedOut && task.running && mono() < deadline) usleep(5000);
    if (task.running) {
        timedOut = !exceeded;
        kill(task.processIdentifier, SIGKILL);
        // Do not wait without a deadline even after a kill request.
        double reapDeadline = mono() + 0.25;
        while (task.running && mono() < reapDeadline) usleep(5000);
    }
    [pipe.fileHandleForReading closeFile];
    if (exceeded) { *status = @"output_limit"; return nil; }
    if (timedOut) { *status = @"timed_out"; return nil; }
    if (!eof || task.running || task.terminationStatus != 0) return nil;
    *status = @"complete";
    return data;
}

#ifdef HENGE_CHAT_DIAGNOSTICS_TEST
NSData *HengeChatDiagnosticsTestCommand(NSString *path, NSArray<NSString *> *arguments,
                                      double seconds, NSUInteger limit, NSString **status) {
    return run(path, arguments, mono() + seconds, limit, NO, status);
}
#endif

static NSData *readSmallFile(NSString *path, NSUInteger limit) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 0 || (uint64_t)info.st_size > limit) { close(fd); return nil; }
    NSMutableData *data = [NSMutableData data];
    char bytes[4096];
    for (;;) {
        ssize_t count = read(fd, bytes, MIN(sizeof bytes, limit + 1 - data.length));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(fd); return nil; }
        if (!count) break;
        [data appendBytes:bytes length:(NSUInteger)count];
        if (data.length > limit) { close(fd); return nil; }
    }
    close(fd);
    return data;
}

static NSString *commandText(NSString *path, NSArray *arguments, double deadline, BOOL captureError) {
    NSString *status;
    NSData *data = run(path, arguments, MIN(deadline, mono() + 1.0), 16384, captureError, &status);
    NSString *text = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
    return [text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
}

static void safeField(NSMutableDictionary *report, NSString *key, id value, NSString *pattern, NSUInteger limit) {
    if (matches(value, pattern, limit)) report[key] = value;
}

static NSDictionary *collect(NSDictionary *request) {
    double started = mono(), deadline = started + 10.0;
    NSMutableDictionary *report = [NSMutableDictionary dictionaryWithDictionary:
        @{@"schema_version": @1, @"collector_version": @1,
          @"vm_session_id": request[@"vm_session_id"], @"request_id": request[@"request_id"],
          @"request_created_utc": request[@"created_utc"], @"request_expires_utc": request[@"expires_utc"],
          @"log_window_seconds": @900, @"privacy_mode": @"error_categories_only", @"client_found": @NO,
          @"client_signature_kind": @"unavailable", @"client_signature_check": @"not_found"}];
    safeField(report, @"os_version", commandText(@"/usr/bin/sw_vers", @[@"-productVersion"], deadline, NO), @"[0-9]{1,3}(\\.[0-9]{1,6}){0,5}", 40);
    safeField(report, @"os_build", commandText(@"/usr/bin/sw_vers", @[@"-buildVersion"], deadline, NO), @"[0-9]{1,3}[A-Z][0-9]{1,8}[a-z]?", 20);
    safeField(report, @"hardware_model", commandText(@"/usr/sbin/sysctl", @[@"-n", @"hw.model"], deadline, NO), @"[A-Za-z]{1,32}[0-9]{1,3},[0-9]{1,3}", 40);
    NSString *arch = commandText(@"/usr/bin/uname", @[@"-m"], deadline, NO);
    report[@"architecture"] = [@[@"arm64", @"arm64e", @"x86_64"] containsObject:arch ?: @""] ? arch : @"unknown";
    // Only these two named app bundles are read. Never enumerate the user's home or application data.
    NSArray *apps = @[@"/Applications/ChatGPT.app", [NSHomeDirectory() stringByAppendingPathComponent:@"Applications/ChatGPT.app"]];
    for (NSString *app in apps) {
        NSData *data = readSmallFile([app stringByAppendingPathComponent:@"Contents/Info.plist"], 256 * 1024);
        id plist = data ? [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL] : nil;
        if (![plist isKindOfClass:NSDictionary.class]) continue;
        report[@"client_found"] = @YES;
        safeField(report, @"client_bundle_id", plist[@"CFBundleIdentifier"], @"[A-Za-z][A-Za-z0-9-]{0,40}(\\.[A-Za-z0-9-]{1,40}){1,5}", 128);
        safeField(report, @"client_version", plist[@"CFBundleShortVersionString"], @"[0-9]{1,12}(\\.[0-9]{1,12}){0,5}([a-z][0-9]{0,4})?", 64);
        safeField(report, @"client_build", plist[@"CFBundleVersion"], @"[0-9]{1,12}(\\.[0-9]{1,12}){0,5}([a-z][0-9]{0,4})?", 64);
        NSString *signature = commandText(@"/usr/bin/codesign", @[@"-d", @"--verbose=2", app], deadline, YES);
        if (signature) {
            report[@"client_signature_kind"] = contains(signature, @"Signature=adhoc") ? @"adhoc" : @"signed";
            for (NSString *line in [signature componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
                if ([line hasPrefix:@"TeamIdentifier="]) safeField(report, @"client_team_identifier", [line substringFromIndex:15], @"[A-Z0-9]{10}", 10);
            }
        }
        NSString *check;
        NSData *verified = run(@"/usr/bin/codesign", @[@"--verify", @"--strict", app], MIN(deadline, mono() + 1.5), 4096, NO, &check);
        report[@"client_signature_check"] = verified ? @"valid_main_bundle" : ([check isEqual:@"timed_out"] ? @"timed_out" : @"not_verified");
        break;
    }
    NSString *predicate = @"(process == 'ChatGPT' OR process == 'devicecheckd' OR process == 'mobileactivationd' OR subsystem CONTAINS[c] 'DeviceCheck') AND (eventMessage CONTAINS[c] 'devicecheck' OR eventMessage CONTAINS[c] 'DCErrorDomain' OR eventMessage CONTAINS[c] 'NSURLErrorDomain' OR eventMessage CONTAINS[c] 'request failed' OR eventMessage CONTAINS[c] 'request_failed' OR eventMessage CONTAINS[c] 'failed to create conversation' OR eventMessage CONTAINS[c] 'HTTP' OR eventMessage CONTAINS[c] 'statusCode' OR eventMessage CONTAINS[c] 'status code')";
    NSString *logStatus;
    NSData *log = run(@"/usr/bin/log", @[@"show", @"--last", @"15m", @"--style", @"json", @"--info", @"--debug", @"--predicate", predicate], deadline, 2 * 1024 * 1024, NO, &logStatus);
    [report addEntriesFromDictionary:HengeChatDiagnosticsClassifyLog(log)];
    if (![logStatus isEqual:@"complete"]) report[@"log_status"] = logStatus;
    report[@"collection_status"] = [report[@"log_status"] isEqual:@"complete"] ? @"complete" : @"partial";
    report[@"collected_utc"] = utc(NSDate.date);
    report[@"collection_elapsed_ms"] = @((NSUInteger)((mono() - started) * 1000));
    return report;
}

static BOOL sameRequest(NSDictionary *a, NSDictionary *b) {
    return a && b && [a[@"request_id"] isEqual:b[@"request_id"]] && [a[@"vm_session_id"] isEqual:b[@"vm_session_id"]];
}

static int pollOnce(HengeChatTransport transport) {
    int status = 0;
    NSData *bytes = transport(@"GET", requestPath, nil, 4096, &status);
    NSDictionary *request = status == 200 ? HengeChatDiagnosticsValidateRequest(bytes, NSDate.date, NO) : nil;
    if (!request) return 1;
    if (![readySession isEqual:request[@"vm_session_id"]] || mono() - lastReady >= 15.0) {
        NSData *ready = [NSJSONSerialization dataWithJSONObject:
            @{@"schema_version": @1, @"collector_version": @1, @"vm_session_id": request[@"vm_session_id"], @"seen_utc": utc(NSDate.date)} options:0 error:NULL];
        transport(@"PUT", readyPath, ready, 1024, &status);
        if (status == 200 || status == 201 || status == 204) { readySession = request[@"vm_session_id"]; lastReady = mono(); }
    }
    if (!HengeChatDiagnosticsValidateRequest(bytes, NSDate.date, YES)) return 0; // Enabled, waiting for a fresh host request.
    NSString *key = [NSString stringWithFormat:@"%@/%@", request[@"vm_session_id"], request[@"request_id"]];
    if (![handledRequest isEqual:key]) {
        NSDictionary *report = collect(request);
        pendingReport = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:NULL];
        if (pendingReport.length > 16384) pendingReport = nil;
        handledRequest = key;
    }
    if (!pendingReport) return 0;
    // A VM restart or a newer request invalidates results before upload as well as at the host importer.
    NSData *current = transport(@"GET", requestPath, nil, 4096, &status);
    NSDictionary *newRequest = status == 200 ? HengeChatDiagnosticsValidateRequest(current, NSDate.date, YES) : nil;
    if (!sameRequest(request, newRequest)) { pendingReport = nil; return 1; }
    transport(@"PUT", reportPath, pendingReport, 1024, &status);
    if (status == 200 || status == 201 || status == 204) { pendingReport = nil; return 0; }
    return 1;
}

void HengeChatDiagnosticsPoll(HengeChatTransport transport) {
    if (atomic_exchange(&busy, true)) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool { pollOnce(transport); }
        atomic_store(&busy, false);
    });
}

int HengeChatDiagnosticsRun(HengeChatTransport transport) {
    if (atomic_exchange(&busy, true)) return 0;
    int status = pollOnce(transport);
    atomic_store(&busy, false);
    puts(status == 0 ? "Chat diagnostics is enabled. Use Collect Chat diagnostics in Henge; the Mac summary is included automatically."
                     : "Keep Henge and this Mac running, then use Collect Chat diagnostics in Henge. No diagnostic text was printed here.");
    return status;
}
