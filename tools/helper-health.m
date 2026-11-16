#import "helper-health.h"
#import <CoreFoundation/CoreFoundation.h>
#include <limits.h>
#include <math.h>
#include <unistd.h>

static BOOL integer(id value, long long minimum, long long maximum) {
    if (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) return NO;
    double n = [value doubleValue];
    return isfinite(n) && floor(n) == n && n >= minimum && n <= maximum;
}

NSDictionary *HengeHelperValidateHealth(NSData *data) {
    if (!data || data.length > 4096) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![value isKindOfClass:NSDictionary.class]) return nil;
    NSDictionary *health = value;
    NSString *session = health[@"session"];
    id helperVersion = health[@"helper_version"] ?: @0;
    id authProtocol = health[@"auth_experiment_protocol"] ?: @0;
    if (!integer(health[@"protocol"], 1, 1) || ![session isKindOfClass:NSString.class] || session.length != 36 ||
        ![[NSUUID alloc] initWithUUIDString:session] || !integer(health[@"helper_protocol"], 0, 4) ||
        ![@[@0, @4] containsObject:health[@"helper_protocol"]] || !integer(health[@"helper_pid"], 0, INT_MAX) ||
        !integer(health[@"agent_seen_s"], -1, INT_MAX) || !integer(health[@"probe_seen_s"], -1, INT_MAX) ||
        !integer(helperVersion, 0, 65535) || !integer(authProtocol, 0, 65535)) return nil;
    NSArray *stages = @[@"unseen", @"network_ready", @"clipboard_starting", @"ready", @"clipboard_unavailable"];
    if (![stages containsObject:health[@"startup_stage"]]) return nil;
    // Return only the fields this module uses, never arbitrary server text.
    return @{@"session": session, @"helper_protocol": health[@"helper_protocol"], @"helper_pid": health[@"helper_pid"],
             @"helper_version": helperVersion, @"auth_experiment_protocol": authProtocol,
             @"agent_seen_s": health[@"agent_seen_s"], @"probe_seen_s": health[@"probe_seen_s"], @"startup_stage": health[@"startup_stage"]};
}

BOOL HengeHelperHealthMatchesPID(NSDictionary *health, int pid) {
    return health && pid > 0 && [health[@"helper_protocol"] intValue] == 4 &&
        [health[@"helper_pid"] intValue] == pid && [health[@"agent_seen_s"] longLongValue] >= 0 &&
        [health[@"agent_seen_s"] longLongValue] < 30 && ![health[@"startup_stage"] isEqual:@"unseen"];
}

BOOL HengeHelperPing(HengeHelperTransport transport, NSString *stage, BOOL probe) {
    if (![@[@"network_ready", @"clipboard_starting", @"ready", @"clipboard_unavailable"] containsObject:stage]) return NO;
    int status = 0;
    NSData *data = transport(@"GET", @"/.henge/helper/health", nil, &status);
    NSDictionary *health = status == 200 ? HengeHelperValidateHealth(data) : nil;
    if (!health) return NO;
    NSString *path = [NSString stringWithFormat:@"/.henge/helper/ping?kind=%@&protocol=%d&pid=%d&stage=%@&helper_version=%d&auth_experiment_protocol=%d",
        probe ? @"probe" : @"agent", HENGE_HELPER_HEALTH_PROTOCOL, getpid(), stage,
        HENGE_HELPER_VERSION, HENGE_HELPER_AUTH_EXPERIMENT_PROTOCOL];
    data = transport(@"GET", path, health[@"session"], &status);
    if (!data || status != 200 || data.length > 4096) return NO;
    id ack = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [ack isKindOfClass:NSDictionary.class] && [ack[@"ok"] isKindOfClass:NSNumber.class] &&
        CFGetTypeID((__bridge CFTypeRef)ack[@"ok"]) == CFBooleanGetTypeID() && [ack[@"ok"] boolValue];
}

BOOL HengeHelperCheckPID(HengeHelperTransport transport, int pid) {
    int status = 0;
    NSData *data = transport(@"GET", @"/.henge/helper/health", nil, &status);
    return status == 200 && HengeHelperHealthMatchesPID(HengeHelperValidateHealth(data), pid);
}

BOOL HengeHelperConfirm(HengeHelperTransport transport) {
    int status = 0;
    NSData *data = transport(@"GET", @"/.henge/helper/health", nil, &status);
    NSDictionary *health = status == 200 ? HengeHelperValidateHealth(data) : nil;
    if (!HengeHelperHealthMatchesPID(health, getpid())) return NO;
    NSString *path = [NSString stringWithFormat:@"/.henge/helper/install-status?stage=confirmed&error=none&code=0&pid=%d", getpid()];
    data = transport(@"POST", path, health[@"session"], &status);
    if (!data || status != 200 || data.length > 4096) return NO;
    id ack = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [ack isKindOfClass:NSDictionary.class] && [ack[@"ok"] isKindOfClass:NSNumber.class] &&
        CFGetTypeID((__bridge CFTypeRef)ack[@"ok"]) == CFBooleanGetTypeID() && [ack[@"ok"] boolValue];
}
