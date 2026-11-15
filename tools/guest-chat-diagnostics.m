#import "guest-chat-diagnostics.h"
#import <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
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
    // New hosts explicitly distinguish a heartbeat request from permission to collect. An expired
    // timestamp alone is insufficient when the guest clock lags. Old hosts retain their prior behavior.
    id collectValue = json[@"collect"];
    if (collectValue && (![collectValue isKindOfClass:NSNumber.class] ||
        CFGetTypeID((__bridge CFTypeRef)collectValue) != CFBooleanGetTypeID())) return nil;
    BOOL shouldCollect = collectValue ? [collectValue boolValue] : YES;
    NSDate *created = dateValue(json[@"created_utc"]), *expires = dateValue(json[@"expires_utc"]);
    NSTimeInterval duration = [expires timeIntervalSinceDate:created ?: now];
    if (!created || !expires || duration < 1 || duration > 90) return nil;
    if (requireFresh && (!shouldCollect || [created timeIntervalSinceDate:now] > 30 || [expires timeIntervalSinceDate:now] <= 0)) return nil;
    // Return a new allowlisted dictionary; the caller never evaluates request strings as code/paths.
    return @{@"schema_version": @1, @"task": @"chat_error_summary",
             @"vm_session_id": [json[@"vm_session_id"] uppercaseString],
             @"request_id": [json[@"request_id"] uppercaseString],
             @"created_utc": utc(created), @"expires_utc": utc(expires), @"collect": @(shouldCollect)};
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

static NSDictionary *classifyEvents(NSArray *events, NSString *executable, NSString *bundleID) {
    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:
        @{@"log_status": @"unavailable", @"log_event_count": @0, @"matched_event_count": @0,
          @"classification": @"logs_unavailable", @"source_scope": @"mixed_chatgpt_device_services",
          @"chatgpt_matched_event_count": @0, @"system_devicecheck_matched_event_count": @0,
          @"unknown_source_matched_event_count": @0}];
    for (NSString *key in countKeys()) result[key] = @0;
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
        BOOL fromClient = [process isEqual:@"ChatGPT"] || (executable.length && [process isEqual:executable]) ||
                          (bundleID.length && [subsystem hasPrefix:bundleID]);
        NSString *scopeKey = fromClient ? @"chatgpt_matched_event_count" :
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

NSDictionary *HengeChatDiagnosticsClassifyLog(NSData *data) {
    id events = data && data.length <= 2 * 1024 * 1024
        ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
    return classifyEvents(events, @"ChatGPT", nil);
}

NSString *HengeChatDiagnosticsLogPredicate(NSString *executable, NSString *bundleID) {
    if (!matches(executable, @"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", 64)) executable = @"ChatGPT";
    if (!matches(bundleID, @"[A-Za-z][A-Za-z0-9-]{0,40}(\\.[A-Za-z0-9-]{1,40}){1,5}", 128)) bundleID = @"com.openai.chat";
    // Use the installed app's executable/subsystem as well as the legacy process name. The classifier
    // accepts DCDevice messages too, so the prefilter must not silently discard that same category.
    return [NSPredicate predicateWithFormat:
        @"(process == %@ OR process == 'ChatGPT' OR subsystem BEGINSWITH %@ OR process == 'devicecheckd' OR process == 'mobileactivationd' OR subsystem CONTAINS[c] 'DeviceCheck') AND (eventMessage CONTAINS[c] 'devicecheck' OR eventMessage CONTAINS[c] 'DCDevice' OR eventMessage CONTAINS[c] 'DCErrorDomain' OR eventMessage CONTAINS[c] 'NSURLErrorDomain' OR eventMessage CONTAINS[c] 'request failed' OR eventMessage CONTAINS[c] 'request_failed' OR eventMessage CONTAINS[c] 'failed to create conversation' OR eventMessage CONTAINS[c] 'HTTP' OR eventMessage CONTAINS[c] 'statusCode' OR eventMessage CONTAINS[c] 'status code')",
        executable, bundleID].predicateFormat;
}

// Only fixed counters/timestamps survive each line. No complete raw log or event array is retained.
@interface HengeLogLines : NSObject
@property(nonatomic, strong) NSMutableData *pending;
@property(nonatomic, strong) NSMutableDictionary *summary;
@property(nonatomic, copy) NSString *executable;
@property(nonatomic, copy) NSString *bundleID;
@property(nonatomic) NSUInteger invalidLines;
@property(nonatomic) BOOL limitReached;
@property(nonatomic) BOOL budgetReached;
@property(nonatomic) double processingDeadline;
- (instancetype)initWithExecutable:(NSString *)executable bundleID:(NSString *)bundleID;
- (BOOL)append:(NSData *)chunk;
- (NSDictionary *)finish:(BOOL)complete;
@end

@implementation HengeLogLines
- (instancetype)initWithExecutable:(NSString *)executable bundleID:(NSString *)bundleID {
    if ((self = [super init])) {
        _pending = [NSMutableData data];
        _summary = [classifyEvents(nil, nil, nil) mutableCopy];
        _executable = [executable copy]; _bundleID = [bundleID copy];
        _processingDeadline = INFINITY;
    }
    return self;
}
- (void)line:(NSData *)line {
    if (!line.length) return;
    @autoreleasepool {
        id event = [NSJSONSerialization JSONObjectWithData:line options:0 error:NULL];
        if (![event isKindOfClass:NSDictionary.class]) { self.invalidLines++; return; }
        if (event[@"finished"] && !event[@"eventMessage"]) return; // log's NDJSON end-of-events record.
        if (![event[@"eventMessage"] isKindOfClass:NSString.class]) { self.invalidLines++; return; }
        if ([self.summary[@"log_event_count"] unsignedIntegerValue] >= 50000) { self.limitReached = YES; return; }
        NSDictionary *one = classifyEvents(@[event], self.executable, self.bundleID);
        NSMutableArray *keys = [countKeys() mutableCopy];
        [keys addObjectsFromArray:@[@"log_event_count", @"matched_event_count", @"chatgpt_matched_event_count",
                                   @"system_devicecheck_matched_event_count", @"unknown_source_matched_event_count"]];
        for (NSString *key in keys) self.summary[key] = @([self.summary[key] unsignedIntegerValue] + [one[key] unsignedIntegerValue]);
        for (NSString *key in @[@"first_match_utc", @"last_match_utc"]) {
            NSDate *next = dateValue(one[key]), *old = dateValue(self.summary[key]);
            if (next && (!old || ([next compare:old] == ([key isEqual:@"first_match_utc"] ? NSOrderedAscending : NSOrderedDescending))))
                self.summary[key] = one[key];
        }
        // Reuse the production classifier's category priority when merging lines.
        NSArray *priority = @[@"devicecheck_unavailable_observed", @"devicecheck_error_observed", @"network_error_observed",
                              @"http_error_observed", @"request_error_observed", @"no_known_error_observed", @"logs_unavailable"];
        if ([priority indexOfObject:one[@"classification"]] < [priority indexOfObject:self.summary[@"classification"]])
            self.summary[@"classification"] = one[@"classification"];
    }
}
- (BOOL)append:(NSData *)chunk {
    // The runner supplies at most 8192 bytes. Keep one unfinished line, never the full command output.
    if (self.limitReached || chunk.length > 8192) { self.limitReached = YES; return NO; }
    [self.pending appendData:chunk];
    for (;;) {
        NSRange newline = [self.pending rangeOfData:[NSData dataWithBytes:"\n" length:1]
                                           options:0 range:NSMakeRange(0, self.pending.length)];
        if (newline.location == NSNotFound) break;
        if (mono() >= self.processingDeadline) { self.budgetReached = YES; return NO; }
        if (newline.location > 65536) { self.limitReached = YES; return NO; }
        [self line:[self.pending subdataWithRange:NSMakeRange(0, newline.location)]];
        if (self.limitReached) return NO;
        [self.pending replaceBytesInRange:NSMakeRange(0, NSMaxRange(newline)) withBytes:NULL length:0];
    }
    if (self.pending.length > 65536) { self.limitReached = YES; return NO; }
    return YES;
}
- (NSDictionary *)finish:(BOOL)complete {
    // An interrupted final line is never classified as an event fragment.
    if (complete && !self.limitReached && self.pending.length) {
        if (mono() >= self.processingDeadline) self.budgetReached = YES;
        else [self line:self.pending];
    }
    BOOL full = complete && !self.limitReached && !self.budgetReached && self.invalidLines == 0;
    NSUInteger events = [self.summary[@"log_event_count"] unsignedIntegerValue];
    self.summary[@"log_counts_status"] = full ? @"complete" : (events ? @"partial" : @"unavailable");
    self.summary[@"log_status"] = full ? @"complete" : @"unavailable";
    if (![self.summary[@"matched_event_count"] unsignedIntegerValue])
        self.summary[@"classification"] = full ? @"no_known_error_observed" : @"logs_unavailable";
    [self.pending setLength:0];
    return [self.summary copy];
}
@end

@interface HengeCommandResult : NSObject
@property(nonatomic, copy) NSString *status;
@property(nonatomic) BOOL started;
@property(nonatomic) NSUInteger elapsedMilliseconds;
@property(nonatomic, strong) NSNumber *exitCode;
@property(nonatomic, strong) NSNumber *terminationSignal;
@property(nonatomic, strong) NSData *data;
@end
@implementation HengeCommandResult
@end

typedef BOOL (^HengeOutputConsumer)(NSData *chunk);

// All deadlines include bounded cleanup. The log consumer sees each complete line before timeout;
// codesign callers still receive output only when their own command completes successfully.
static HengeCommandResult *runCommand(NSString *path, NSArray<NSString *> *arguments, double deadline,
                                     NSUInteger limit, BOOL captureError, HengeOutputConsumer consumer) {
    double startedAt = mono();
    HengeCommandResult *result = [HengeCommandResult new];
    result.status = @"not_run_budget";
    if (startedAt >= deadline) return result;
    double readDeadline = MAX(startedAt, deadline - 0.10); // Reserve cleanup inside this command's budget.
    NSTask *task = [NSTask new];
    NSPipe *pipe = [NSPipe pipe];
    task.executableURL = [NSURL fileURLWithPath:path]; task.arguments = arguments;
    task.standardInput = NSFileHandle.fileHandleWithNullDevice;
    task.standardOutput = pipe;
    task.standardError = captureError ? pipe : NSFileHandle.fileHandleWithNullDevice;
    if (![task launchAndReturnError:NULL]) {
        result.status = @"launch_failed"; result.elapsedMilliseconds = (NSUInteger)((mono() - startedAt) * 1000); return result;
    }
    result.started = YES;
    [pipe.fileHandleForWriting closeFile];
    int fd = pipe.fileHandleForReading.fileDescriptor;
    int flags = fcntl(fd, F_GETFL, 0);
    result.status = flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? @"complete" : @"read_failed";
    NSMutableData *data = consumer ? nil : [NSMutableData data];
    NSUInteger bytesRead = 0;
    BOOL eof = NO;
    while ([result.status isEqual:@"complete"] && !eof) {
        if (mono() >= readDeadline) { result.status = @"timed_out"; break; }
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int ready = poll(&p, 1, 20);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { result.status = @"read_failed"; break; }
        if (!ready && task.running) continue;
        char bytes[8192];
        ssize_t n = read(fd, bytes, sizeof bytes);
        if (n > 0) {
            if (bytesRead + (NSUInteger)n > limit) { result.status = @"output_limit"; break; }
            bytesRead += (NSUInteger)n;
            @autoreleasepool {
                if (consumer) {
                    if (!consumer([NSData dataWithBytes:bytes length:(NSUInteger)n])) result.status = @"output_limit";
                } else [data appendBytes:bytes length:(NSUInteger)n];
            }
        } else if (!n) eof = YES;
        else if (errno != EAGAIN && errno != EINTR) { result.status = @"read_failed"; break; }
    }
    while (eof && [result.status isEqual:@"complete"] && task.running && mono() < readDeadline) usleep(5000);
    if (task.running) {
        if ([result.status isEqual:@"complete"]) result.status = @"timed_out";
        kill(task.processIdentifier, SIGKILL);
        while (task.running && mono() < deadline) usleep(5000);
    }
    [pipe.fileHandleForReading closeFile];
    if (!task.running) {
        if (task.terminationReason == NSTaskTerminationReasonUncaughtSignal) result.terminationSignal = @(task.terminationStatus);
        else result.exitCode = @(task.terminationStatus);
        if (task.terminationStatus != 0 && [result.status isEqual:@"complete"]) result.status = @"exit_nonzero";
    }
    if (eof && [result.status isEqual:@"complete"]) result.data = data;
    result.elapsedMilliseconds = (NSUInteger)((mono() - startedAt) * 1000);
    return result;
}

static void commandFields(NSMutableDictionary *report, NSString *prefix, HengeCommandResult *command) {
    report[[prefix stringByAppendingString:@"_status"]] = command.status;
    report[[prefix stringByAppendingString:@"_elapsed_ms"]] = @(command.elapsedMilliseconds);
    if ([prefix isEqual:@"log_command"]) {
        report[@"log_command_started"] = @(command.started);
        if (command.exitCode) report[@"log_command_exit_code"] = command.exitCode;
        if (command.terminationSignal) report[@"log_command_termination_signal"] = command.terminationSignal;
    }
}

static NSDictionary *logResult(HengeLogLines *lines, HengeCommandResult *command) {
    if (lines.budgetReached) command.status = @"timed_out";
    NSMutableDictionary *result = [[lines finish:[command.status isEqual:@"complete"]] mutableCopy];
    commandFields(result, @"log_command", command);
    if ([@[@"timed_out", @"output_limit", @"not_run_budget"] containsObject:command.status]) result[@"log_status"] = command.status;
    return result;
}

#ifdef HENGE_CHAT_DIAGNOSTICS_TEST
NSData *HengeChatDiagnosticsTestCommand(NSString *path, NSArray<NSString *> *arguments,
                                      double seconds, NSUInteger limit, NSString **status) {
    HengeCommandResult *command = runCommand(path, arguments, mono() + seconds, limit, NO, nil);
    *status = command.status;
    return command.data;
}
NSDictionary *HengeChatDiagnosticsTestLogCommand(NSString *path, NSArray<NSString *> *arguments, double seconds,
                                               NSString *executable, NSString *bundleID) {
    HengeLogLines *lines = [[HengeLogLines alloc] initWithExecutable:executable bundleID:bundleID];
    double deadline = mono() + seconds;
    lines.processingDeadline = deadline - 0.10;
    HengeCommandResult *command = runCommand(path, arguments, deadline, 2 * 1024 * 1024, NO,
                                           ^BOOL(NSData *chunk) { return [lines append:chunk]; });
    return logResult(lines, command);
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

static void safeField(NSMutableDictionary *report, NSString *key, id value, NSString *pattern, NSUInteger limit) {
    if (matches(value, pattern, limit)) report[key] = value;
}

static NSString *sysctlText(const char *name) {
    char text[128] = {0};
    size_t length = sizeof text;
    if (sysctlbyname(name, text, &length, NULL, 0) || !length || length > sizeof text) return nil;
    text[sizeof text - 1] = 0;
    return [[NSString alloc] initWithBytes:text length:strnlen(text, sizeof text) encoding:NSUTF8StringEncoding];
}

static NSDictionary *collect(NSDictionary *request) {
    double started = mono(), deadline = started + 10.0;
    NSMutableDictionary *report = [NSMutableDictionary dictionaryWithDictionary:
        @{@"schema_version": @1, @"collector_version": @1,
          @"vm_session_id": request[@"vm_session_id"], @"request_id": request[@"request_id"],
          @"request_created_utc": request[@"created_utc"], @"request_expires_utc": request[@"expires_utc"],
          @"log_window_seconds": @900, @"privacy_mode": @"error_categories_only", @"client_found": @NO,
          @"client_signature_kind": @"unavailable", @"client_signature_check": @"not_found"}];
    // Fixed metadata queries use in-process APIs. Starting four external utilities could consume
    // the evidence budget before log show launches on a slowly emulated Mac.
    NSOperatingSystemVersion version = NSProcessInfo.processInfo.operatingSystemVersion;
    report[@"os_version"] = [NSString stringWithFormat:@"%ld.%ld.%ld", (long)version.majorVersion,
                            (long)version.minorVersion, (long)version.patchVersion];
    safeField(report, @"os_build", sysctlText("kern.osversion"), @"[0-9]{1,3}[A-Z][0-9]{1,8}[a-z]?", 20);
    safeField(report, @"hardware_model", sysctlText("hw.model"), @"[A-Za-z]{1,32}[0-9]{1,3},[0-9]{1,3}", 40);
    struct utsname system;
    NSString *arch = uname(&system) == 0 ? [NSString stringWithUTF8String:system.machine] : nil;
    report[@"architecture"] = [@[@"arm64", @"arm64e", @"x86_64"] containsObject:arch ?: @""] ? arch : @"unknown";
    NSString *clientApp = nil;
    NSArray *apps = @[@"/Applications/ChatGPT.app", [NSHomeDirectory() stringByAppendingPathComponent:@"Applications/ChatGPT.app"]];
    for (NSString *app in apps) {
        NSData *data = readSmallFile([app stringByAppendingPathComponent:@"Contents/Info.plist"], 256 * 1024);
        id plist = data ? [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL] : nil;
        if (![plist isKindOfClass:NSDictionary.class]) continue;
        clientApp = app;
        report[@"client_found"] = @YES;
        safeField(report, @"client_bundle_id", plist[@"CFBundleIdentifier"], @"[A-Za-z][A-Za-z0-9-]{0,40}(\\.[A-Za-z0-9-]{1,40}){1,5}", 128);
        safeField(report, @"client_executable", plist[@"CFBundleExecutable"], @"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", 64);
        safeField(report, @"client_version", plist[@"CFBundleShortVersionString"], @"[0-9]{1,12}(\\.[0-9]{1,12}){0,5}([a-z][0-9]{0,4})?", 64);
        safeField(report, @"client_build", plist[@"CFBundleVersion"], @"[0-9]{1,12}(\\.[0-9]{1,12}){0,5}([a-z][0-9]{0,4})?", 64);
        break;
    }
    report[@"metadata_status"] = report[@"os_build"] && report[@"hardware_model"] && ![report[@"architecture"] isEqual:@"unknown"] ? @"complete" : @"partial";
    report[@"metadata_elapsed_ms"] = @((NSUInteger)((mono() - started) * 1000));

    // The first subprocess is the evidence query. Preserve the 15-minute window and all log levels;
    // NDJSON lets a timeout retain complete observed events without retaining incomplete fragments.
    NSString *executable = report[@"client_executable"] ?: @"ChatGPT", *bundleID = report[@"client_bundle_id"];
    NSString *predicate = HengeChatDiagnosticsLogPredicate(executable, bundleID);
    HengeLogLines *lines = [[HengeLogLines alloc] initWithExecutable:executable bundleID:bundleID];
    lines.processingDeadline = MIN(deadline, started + 8.0) - 0.10;
    HengeCommandResult *log = runCommand(@"/usr/bin/log",
        @[@"show", @"--last", @"15m", @"--style", @"ndjson", @"--info", @"--debug", @"--predicate", predicate],
        MIN(deadline, started + 8.0), 2 * 1024 * 1024, NO, ^BOOL(NSData *chunk) { return [lines append:chunk]; });
    [report addEntriesFromDictionary:logResult(lines, log)];

    // Signature metadata is supplementary, never a prerequisite for getting Chat error evidence.
    // Each step has its own small budget, inside the unchanged overall ten-second deadline.
    HengeCommandResult *display = [HengeCommandResult new], *verify = [HengeCommandResult new];
    display.status = verify.status = @"not_found";
    if (clientApp) {
        display = runCommand(@"/usr/bin/codesign", @[@"-d", @"--verbose=2", clientApp], MIN(deadline, mono() + 0.75), 16384, YES, nil);
        NSString *signature = display.data ? [[NSString alloc] initWithData:display.data encoding:NSUTF8StringEncoding] : nil;
        if (signature) {
            report[@"client_signature_kind"] = contains(signature, @"Signature=adhoc") ? @"adhoc" : @"signed";
            for (NSString *line in [signature componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
                if ([line hasPrefix:@"TeamIdentifier="]) safeField(report, @"client_team_identifier", [line substringFromIndex:15], @"[A-Z0-9]{10}", 10);
            }
        }
        verify = runCommand(@"/usr/bin/codesign", @[@"--verify", @"--strict", clientApp], MIN(deadline, mono() + 0.75), 4096, NO, nil);
        report[@"client_signature_check"] = verify.data ? @"valid_main_bundle" : ([verify.status isEqual:@"timed_out"] ? @"timed_out" : @"not_verified");
    }
    commandFields(report, @"signature_display", display);
    commandFields(report, @"signature_verify", verify);
    report[@"collection_status"] = [report[@"log_counts_status"] isEqual:@"complete"] ? @"complete" : @"partial";
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
    if (![request[@"collect"] boolValue]) { pendingReport = nil; return 0; } // Explicit heartbeat-only request, regardless of clock skew.
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
