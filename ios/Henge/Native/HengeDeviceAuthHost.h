#ifndef HENGE_DEVICE_AUTH_HOST_H
#define HENGE_DEVICE_AUTH_HOST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum HengeDeviceAuthHostOperation {
    HENGE_DEVICE_AUTH_PROBE = 0,
    HENGE_DEVICE_AUTH_DC_TOKEN = 1,
    HENGE_DEVICE_AUTH_BAA_DATA = 2,
    HENGE_DEVICE_AUTH_BAA_DICTIONARY = 3,
};

#define HENGE_DEVICE_AUTH_MAX_INPUT_BYTES (32u * 1024u)
#define HENGE_DEVICE_AUTH_MAX_RESULT_BYTES (64u * 1024u)
#define HENGE_DEVICE_AUTH_DEFAULT_TIMEOUT_MS 15000u
#define HENGE_DEVICE_AUTH_MAX_TIMEOUT_MS 45000u

/* All buffers are borrowed and valid only during this callback; copy before returning.
 * Called asynchronously, off the main thread, exactly once for a non-NULL callback.
 * result is a BINARY PROPERTY LIST, never JSON:
 *   probe: {supported, dc_supported, dc_support_checked, dc_framework_available,
 *           dc_class_available, dc_method_available, baa_framework_available,
 *           baa_class_available, baa_single_available, baa_multiple_available,
 *           entitlement_presence, entitlement_query_available}
 *   dc_token: {token: NSData}
 *   baa_data: {signature: original plist object, attestation: original plist object}
 *   baa_dictionary: {signatures: NSDictionary, attestation: original plist object}
 * Both BAA result objects must be present, as in the inspected deb's signer.
 * The opaque BAA values are preserved, with bounded plist types/depth/size.
 * Failure has no result bytes. diagnostics is a separate, secret-free UTF-8 JSON
 * object: status/outcome (identical), operation, errorDomain/errorCode, latencyMs,
 * timeoutMs, inputBytes/resultBytes, signatureBytes/attestationBytes,
 * methodABIChecked/callbackABIChecked, serverAcceptanceVerified=false, and fixed
 * boolean capability fields when observed. Never log or persist result bytes.
 */
typedef void (*HengeDeviceAuthHostCompletion)(void *context,
    const uint8_t *result, size_t result_length,
    const char *diagnostics, size_t diagnostics_length);

/* probe/dc_token require empty input. baa_data takes raw bytes. baa_dictionary
 * takes a binary plist containing 1..32 NSString -> NSData pairs, keys <=128
 * UTF-16 units, each data value 1..4096 bytes. Input is copied before returning.
 * timeout_ms=0 selects the default; other values are bounded to 100..45000 ms.
 * Timeout stops waiting, not Apple's operation. Late callbacks cannot complete
 * twice. One native operation per family may remain pending until its actual
 * callback: further calls return busy, avoiding unbounded un-cancellable work.
 *
 * Keep probe/dc_token in the Henge app's signing context. The experimental BAA
 * operations are intended for a separately entitled, isolated signer process;
 * this file neither changes entitlements nor asserts server acceptance.
 */
void henge_device_auth_host_request(uint32_t operation,
    const void *input, size_t input_length, uint32_t timeout_ms,
    HengeDeviceAuthHostCompletion completion, void *context);

#ifdef __cplusplus
}
#endif

#if defined(__OBJC__) && defined(HENGE_DEVICE_AUTH_HOST_TESTING)
#import <Foundation/Foundation.h>

/* Only compiled into the synthetic test binary. No test calls Apple services. */
@protocol HengeDeviceAuthHostTestBackend <NSObject>
- (NSDictionary *)probe;
- (void)performOperation:(uint32_t)operation input:(id)input
              completion:(void (^)(id first, id attestation, NSError *error))completion;
@end

void HengeDeviceAuthHostRequestForTesting(uint32_t operation,
    const void *input, size_t input_length, uint32_t timeout_ms,
    id<HengeDeviceAuthHostTestBackend> backend,
    HengeDeviceAuthHostCompletion completion, void *context);
BOOL HengeDeviceAuthHostMethodEncodingForTesting(const char *encoding, BOOL publicToken);
BOOL HengeDeviceAuthHostBlockEncodingForTesting(const char *encoding, NSUInteger arguments);
BOOL HengeDeviceAuthHostCompiledBlocksForTesting(void);
#endif

#endif
