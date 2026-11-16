#ifndef HENGE_AUTH_BRIDGE_H
#define HENGE_AUTH_BRIDGE_H
#ifdef __cplusplus
extern "C" {
#endif
// Install once before a VM session. This only registers a worker; it neither
// enables the experiment nor calls Apple's token/signature APIs.
void HengeAuthInstallBridge(void);
// Caller owns this fixed-schema JSON string. It never contains result material.
char *HengeAuthBridgeDiagnosticsJSON(void);
#ifdef __cplusplus
}
#endif
#endif
