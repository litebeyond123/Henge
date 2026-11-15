#import <Foundation/Foundation.h>

// The only task accepted by this module is the fixed, read-only Chat diagnostic below.
// Transport is the existing guest-only HTTP connection; it must bound response bytes and time.
typedef NSData *(*HengeChatTransport)(NSString *method, NSString *path, NSData *body,
                                    NSUInteger responseLimit, int *status);
void HengeChatDiagnosticsPoll(HengeChatTransport transport);
int HengeChatDiagnosticsRun(HengeChatTransport transport);

// Pure production parsers, also exercised by the native macOS regression tests.
NSDictionary *HengeChatDiagnosticsValidateRequest(NSData *data, NSDate *now, BOOL requireFresh);
NSDictionary *HengeChatDiagnosticsClassifyLog(NSData *data);
NSString *HengeChatDiagnosticsLogPredicate(NSString *executable, NSString *bundleID);
#ifdef HENGE_CHAT_DIAGNOSTICS_TEST
NSData *HengeChatDiagnosticsTestCommand(NSString *path, NSArray<NSString *> *arguments,
                                      double seconds, NSUInteger limit, NSString **status);
NSDictionary *HengeChatDiagnosticsTestLogCommand(NSString *path, NSArray<NSString *> *arguments, double seconds,
                                               NSString *executable, NSString *bundleID);
#endif
