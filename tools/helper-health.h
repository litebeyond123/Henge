#import <Foundation/Foundation.h>
#include "helper-version.h"

// A separate, bounded connection channel. It never reads or initializes the clipboard.
typedef NSData *(*HengeHelperTransport)(NSString *method, NSString *path, NSString *session, int *status);
NSDictionary *HengeHelperValidateHealth(NSData *data);
BOOL HengeHelperHealthMatchesPID(NSDictionary *health, int pid);
BOOL HengeHelperPing(HengeHelperTransport transport, NSString *stage, BOOL probe);
BOOL HengeHelperCheckPID(HengeHelperTransport transport, int pid);
BOOL HengeHelperConfirm(HengeHelperTransport transport);
