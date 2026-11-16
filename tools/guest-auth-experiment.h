#import <Foundation/Foundation.h>

// Experimental, per-launch bridge. The helper only polls for an explicit host
// launch request; no account credentials or DeviceCheck material are logged.
typedef NSData *(*HengeGuestAuthTransport)(NSString *method, NSString *path, NSData *body,
                                         NSString *session, NSUInteger limit, int *status);
void HengeGuestAuthExperimentPoll(HengeGuestAuthTransport transport);
int HengeGuestAuthExperimentRun(NSArray<NSString *> *arguments);

extern NSString *const HengeAuthBridgeErrorDomain;
extern const NSUInteger HengeAuthResponseLimit;

// Shared production validation/transport, also used by the injected adapter and
// the synthetic macOS fixture. Result material is returned only in memory.
NSDictionary *HengeAuthValidateState(NSData *data);
NSData *HengeAuthHTTP(NSString *method, NSString *path, NSData *body,
                    NSString *session, NSUInteger limit, double seconds, int *status, NSError **error);
NSDictionary *HengeAuthReadState(NSError **error);
NSDictionary *HengeAuthRequest(NSString *session, NSString *launchID, NSString *operation,
                             id payload, NSString *requestID, double seconds, NSError **error);
NSDictionary *HengeAuthDecodeResponse(NSData *data, int httpStatus, NSString *session,
                                     NSString *launchID, NSString *requestID, NSString *operation,
                                     NSError **error);
BOOL HengeAuthValidPayload(id payload, BOOL multiple);
BOOL HengeAuthCallbackABI(id callback, NSUInteger objectArguments);
BOOL HengeAuthMethodABI(Class cls, SEL selector, const char *returnType, NSUInteger objectArguments,
                       BOOL finalArgumentIsBlock);
BOOL HengeAuthSignaturePolicy(NSDictionary *information);
BOOL HengeAuthTargetIdentity(NSString *bundlePath, BOOL checkPolicy, NSError **error);
BOOL HengeAuthCurrentProcessMatches(NSString *bundlePath, NSError **error);
void HengeAuthEvent(NSString *session, NSString *launchID, NSString *requestID, NSString *stage,
                   NSError *error, double elapsedSeconds, NSUInteger inputBytes, NSUInteger resultBytes);
// Only the short-lived launcher drains before exiting. Native adapter callbacks
// never wait for diagnostic delivery; the drain is bounded to 2.5 seconds.
void HengeAuthFlushEvents(void);
NSString *HengeAuthEventPath(void);
BOOL HengeAuthEventWasRecorded(NSString *launchID, NSString *stage);
NSError *HengeAuthError(NSInteger code);
double HengeAuthMonotonic(void);
void HengeAuthCaptureTestConfiguration(void);
