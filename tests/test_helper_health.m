#import <Foundation/Foundation.h>
#import "../tools/helper-health.h"
#include <stdlib.h>
#include <unistd.h>

static int checks;
#define CHECK(...) do { checks++; if (!(__VA_ARGS__)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #__VA_ARGS__); exit(1); } } while (0)
static NSString *const Session = @"11111111-2222-3333-4444-555555555555";
static NSMutableDictionary *snapshot(void) {
    return [@{@"protocol": @1, @"session": Session, @"helper_protocol": @4, @"helper_pid": @321,
              @"agent_seen_s": @0, @"probe_seen_s": @-1, @"startup_stage": @"clipboard_starting",
              @"install_stage": @"launch_requested", @"install_error": @"none"} mutableCopy];
}
static NSData *json(id value) { return [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL]; }
static NSMutableArray *calls;
static NSData *response;
static BOOL rejectPing;
static NSData *transport(NSString *method, NSString *path, NSString *session, int *status) {
    [calls addObject:@{@"method": method, @"path": path, @"session": session ?: @""}];
    *status = 200;
    if ([path isEqual:@"/.henge/helper/health"]) return response;
    if (rejectPing) { *status = 409; return json(@{@"error": @"session_changed"}); }
    return json(@{@"ok": @YES});
}

int main(void) {
    @autoreleasepool {
        NSDictionary *health = HengeHelperValidateHealth(json(snapshot()));
        CHECK(health != nil);
        CHECK(HengeHelperHealthMatchesPID(health, 321));
        CHECK(!HengeHelperHealthMatchesPID(health, 123));
        CHECK(!HengeHelperHealthMatchesPID(nil, 321));
        CHECK(!HengeHelperHealthMatchesPID(health, 0));
        CHECK(health[@"install_stage"] == nil); // whitelist, no unrelated/raw values returned
        for (NSString *stage in @[@"network_ready", @"clipboard_starting", @"ready", @"clipboard_unavailable"]) {
            NSMutableDictionary *value = snapshot(); value[@"startup_stage"] = stage;
            CHECK(HengeHelperHealthMatchesPID(HengeHelperValidateHealth(json(value)), 321));
        }
        for (NSNumber *age in @[@-1, @30, @1000]) {
            NSMutableDictionary *value = snapshot(); value[@"agent_seen_s"] = age;
            CHECK(!HengeHelperHealthMatchesPID(HengeHelperValidateHealth(json(value)), 321));
        }
        for (NSString *key in @[@"protocol", @"helper_pid", @"agent_seen_s", @"probe_seen_s", @"helper_protocol"]) {
            for (id invalid in @[@YES, @"1", @1.5, NSNull.null, @-2]) {
                NSMutableDictionary *value = snapshot(); value[key] = invalid;
                CHECK(HengeHelperValidateHealth(json(value)) == nil);
            }
        }
        for (NSString *session in @[@"", @"bad", @"11111111-2222-3333-4444-555555555555\r\nX-Bad: yes"]) {
            NSMutableDictionary *value = snapshot(); value[@"session"] = session;
            CHECK(HengeHelperValidateHealth(json(value)) == nil);
        }
        CHECK(HengeHelperValidateHealth([NSMutableData dataWithLength:4097]) == nil);
        CHECK(HengeHelperValidateHealth(json(@[])) == nil);
        CHECK(HengeHelperValidateHealth([@"not JSON" dataUsingEncoding:NSUTF8StringEncoding]) == nil);
        calls = [NSMutableArray new];
        response = json(snapshot());
        CHECK(HengeHelperPing(transport, @"network_ready", YES));
        CHECK(calls.count == 2);
        CHECK([calls[0][@"session"] isEqual:@""]);
        CHECK([calls[1][@"session"] isEqual:Session]);
        CHECK([calls[1][@"path"] containsString:@"kind=probe&protocol=4"]);
        CHECK([calls[1][@"path"] containsString:[NSString stringWithFormat:@"pid=%d", getpid()]]);
        [calls removeAllObjects];
        CHECK(HengeHelperPing(transport, @"ready", NO));
        CHECK([calls[1][@"path"] containsString:@"kind=agent&protocol=4"]);
        rejectPing = YES;
        CHECK(!HengeHelperPing(transport, @"ready", NO));
        rejectPing = NO;
        [calls removeAllObjects];
        CHECK(!HengeHelperPing(transport, @"raw-message", NO));
        CHECK(calls.count == 0);
        response = json(@{@"protocol": @1});
        CHECK(!HengeHelperPing(transport, @"ready", NO));
        CHECK(calls.count == 1);
        response = json(snapshot());
        CHECK(HengeHelperCheckPID(transport, 321));
        CHECK(!HengeHelperCheckPID(transport, 999));
        // A running app may confirm itself after the installer has stopped
        // waiting for an OS permission prompt. A probe or someone else's PID
        // must never create that confirmation.
        [calls removeAllObjects];
        CHECK(!HengeHelperConfirm(transport));
        CHECK(calls.count == 1);
        NSMutableDictionary *own = snapshot();
        own[@"helper_pid"] = @(getpid());
        response = json(own);
        [calls removeAllObjects];
        CHECK(HengeHelperConfirm(transport));
        CHECK(calls.count == 2);
        CHECK([calls[1][@"method"] isEqual:@"POST"]);
        CHECK([calls[1][@"session"] isEqual:Session]);
        CHECK([calls[1][@"path"] containsString:@"stage=confirmed&error=none&code=0&pid="]);
        rejectPing = YES;
        CHECK(!HengeHelperConfirm(transport));
        rejectPing = NO;
        own[@"agent_seen_s"] = @30;
        response = json(own);
        [calls removeAllObjects];
        CHECK(!HengeHelperConfirm(transport));
        CHECK(calls.count == 1);
        printf("Helper health: %d assertions passed.\n", checks);
    }
    return 0;
}
