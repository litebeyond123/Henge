#import "../tools/guest-auth-experiment.h"
#include <stdlib.h>

// Only the test runner builds/signs this library and places it beside its own
// launcher. There is no production switch for a fabricated readiness event.
__attribute__((constructor)) static void fixtureAdapter(void) {
    @autoreleasepool {
        HengeAuthCaptureTestConfiguration();
        NSString *scenario = NSBundle.mainBundle.infoDictionary[@"HengeFixtureScenario"];
        if ([scenario isEqual:@"early_exit"]) return; // Deliberately no handshake.
        const char *session = getenv("HENGE_AUTH_SESSION"), *launch = getenv("HENGE_AUTH_LAUNCH_ID");
        if (!session || !launch) return;
        NSString *sessionID = [NSString stringWithUTF8String:session], *launchID = [NSString stringWithUTF8String:launch];
        NSString *requestID = NSUUID.UUID.UUIDString;
        HengeAuthEvent(sessionID, launchID, requestID, @"adapter_loaded", nil, 0, 0, 0);
        if ([scenario isEqual:@"error_ready"])
            HengeAuthEvent(sessionID, launchID, requestID, @"adapter_ready", HengeAuthError(1002), 0, 0, 0);
        HengeAuthFlushEvents();
    }
}
