#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
// Only the BAA experiment uses the separately signed child. Public DCDevice
// stays in Henge's application process so it keeps that application's identity.
typedef void (^HengeAuthChildCompletion)(NSData * _Nullable resultPlist, NSData *diagnosticsJSON);
void HengeAuthRunSignerChild(NSInteger operation, NSData *input, NSUInteger timeoutMs,
                            HengeAuthChildCompletion completion);
#if defined(HENGE_AUTH_SUBPROCESS_TEST)
void HengeAuthSetTestSignerPath(NSString *path);
#endif
NS_ASSUME_NONNULL_END
