#import <AppKit/AppKit.h>

// The guest helper is an actual macOS application. CLI probes deliberately do
// not start it or register a login item; only the normal application does that.
int HengeHelperAppPID(void);
int HengeHelperQuitApp(void);
const char *HengeHelperLoginStatus(void);
int HengeHelperUnregisterLogin(void);
int HengeHelperPrintStartupStatus(void);
void HengeHelperAppHealth(BOOL connected, int networkError);
void HengeHelperRunApplication(BOOL installing, BOOL smokeTest, dispatch_block_t start);
