#import "helper-app.h"
#import <Network/Network.h>
#import <ServiceManagement/ServiceManagement.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const helperBundleID = @"com.henge.guesthelper";

static NSRunningApplication *runningHelper(void) {
    NSURL *own = NSBundle.mainBundle.bundleURL.URLByResolvingSymlinksInPath;
    if (![NSBundle.mainBundle.bundleIdentifier isEqual:helperBundleID]) return nil;
    for (NSRunningApplication *app in [NSRunningApplication runningApplicationsWithBundleIdentifier:helperBundleID]) {
        if (app.processIdentifier != getpid() && !app.terminated &&
            [app.bundleURL.URLByResolvingSymlinksInPath isEqual:own]) return app;
    }
    return nil;
}

int HengeHelperAppPID(void) {
    NSRunningApplication *app = runningHelper();
    if (!app || app.processIdentifier <= 0) return 1;
    printf("%d\n", app.processIdentifier);
    return 0;
}

int HengeHelperQuitApp(void) {
    NSRunningApplication *app = runningHelper();
    if (!app) return 0;
    if (![app terminate]) return 1;
    // Never kill arbitrary PIDs and never block an installer indefinitely.
    for (int i = 0; i < 50; i++) {
        if (app.terminated) return 0;
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    return app.terminated ? 0 : 1;
}

const char *HengeHelperLoginStatus(void) {
    if (![NSBundle.mainBundle.bundleIdentifier isEqual:helperBundleID]) return "unavailable";
    if (@available(macOS 13.0, *)) {
        switch (SMAppService.mainAppService.status) {
            case SMAppServiceStatusEnabled: return "enabled";
            case SMAppServiceStatusRequiresApproval: return "requires_approval";
            case SMAppServiceStatusNotRegistered: return "not_registered";
            case SMAppServiceStatusNotFound: return "unavailable";
        }
    }
    return "unavailable";
}

int HengeHelperUnregisterLogin(void) {
    if (![NSBundle.mainBundle.bundleIdentifier isEqual:helperBundleID]) return 2;
    if (@available(macOS 13.0, *)) {
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block BOOL removed = NO;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            SMAppService *service = SMAppService.mainAppService;
            removed = service.status == SMAppServiceStatusNotRegistered || [service unregisterAndReturnError:NULL];
            dispatch_semaphore_signal(done);
        });
        if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) return 1;
        return removed ? 0 : 1;
    }
    return 2;
}

static NSURL *statusURL(void) {
    return [[NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES]
            URLByAppendingPathComponent:@"Library/Logs/Henge/helper-status.json"];
}

int HengeHelperPrintStartupStatus(void) {
    // Re-serialize a fixed schema; never echo an arbitrary file into diagnostics.
    NSData *data = [NSData dataWithContentsOfURL:statusURL() options:0 error:NULL];
    id decoded = data.length <= 4096 ? [NSJSONSerialization JSONObjectWithData:data ?: NSData.data options:0 error:NULL] : nil;
    NSDictionary *value = [decoded isKindOfClass:NSDictionary.class] ? decoded : nil;
    NSArray *networks = @[@"waiting", @"connected", @"local_network_denied", @"connection_failed"];
    NSArray *logins = @[@"enabled", @"requires_approval", @"not_registered", @"unavailable", @"registration_failed", @"test_disabled"];
    NSRunningApplication *app = runningHelper();
    BOOL valid = value && [value[@"pid"] isKindOfClass:NSNumber.class] &&
        [value[@"pid"] intValue] == app.processIdentifier && app.processIdentifier > 0 &&
        [networks containsObject:value[@"network"]] && [logins containsObject:value[@"login"]] &&
        [value[@"network_errno"] isKindOfClass:NSNumber.class] &&
        [value[@"network_errno"] intValue] >= 0 && [value[@"network_errno"] intValue] <= 4095;
    NSDictionary *out = valid ? @{@"pid": @(app.processIdentifier), @"startup": @"running",
        @"network": value[@"network"], @"login": value[@"login"], @"network_errno": value[@"network_errno"]} :
        @{@"pid": @(app ? app.processIdentifier : 0), @"startup": app ? @"starting" : @"not_running"};
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingSortedKeys error:NULL];
    fwrite(encoded.bytes, 1, encoded.length, stdout);
    fputc('\n', stdout);
    return 0;
}

@interface HengeHelperApplication : NSObject <NSApplicationDelegate>
@property BOOL installing;
@property BOOL smokeTest;
@property BOOL connected;
@property BOOL localDenied;
@property int networkError;
@property(copy) NSString *login;
@property(copy) dispatch_block_t start;
@property(strong) NSWindow *window;
@property(strong) NSTextField *message;
@property(strong) NSTextField *detail;
@property(strong) NSTextField *loginMessage;
@property(strong) NSStatusItem *statusItem;
@property(strong) NSMenuItem *statusMenu;
@property(strong) nw_connection_t permissionConnection;
@end

static HengeHelperApplication *helperApplication;

@implementation HengeHelperApplication
- (void)writeStatus {
    if (self.smokeTest) return;
    NSString *network = self.connected ? @"connected" : self.localDenied ? @"local_network_denied" :
        self.networkError ? @"connection_failed" : @"waiting";
    NSDictionary *value = @{@"pid": @(getpid()), @"startup": @"running", @"network": network,
        @"login": self.login ?: @"unavailable", @"network_errno": @(MAX(0, MIN(4095, self.networkError)))};
    NSURL *url = statusURL();
    [NSFileManager.defaultManager createDirectoryAtURL:url.URLByDeletingLastPathComponent withIntermediateDirectories:YES
        attributes:@{NSFilePosixPermissions: @0700} error:NULL];
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:NULL];
    if ([data writeToURL:url options:NSDataWritingAtomic error:NULL]) chmod(url.fileSystemRepresentation, 0600);
}

- (void)refresh {
    NSString *title = self.connected ? @"Connected to Henge" : self.localDenied ? @"Allow Local Network access" : @"Waiting for Henge";
    self.message.stringValue = title;
    self.statusMenu.title = title;
    self.detail.stringValue = self.connected ?
        @"The helper has connected. You can close this window; it will keep running in the menu bar." : self.localDenied ?
        @"In System Settings > Privacy & Security > Local Network, allow Henge Helper. It will reconnect automatically." :
        @"Keep Henge open on your iPad. If macOS asks whether Henge Helper can find devices on the local network, choose Allow. This window stays open while you respond.";
    if ([self.login isEqual:@"enabled"]) self.loginMessage.stringValue = @"Starts automatically when you log in to this Mac.";
    else if ([self.login isEqual:@"requires_approval"]) self.loginMessage.stringValue = @"Login startup is waiting for approval in System Settings > General > Login Items.";
    else if (self.smokeTest) self.loginMessage.stringValue = @"Runtime test: login startup, clipboard and shared-folder access are disabled.";
    else self.loginMessage.stringValue = @"Login startup is not enabled. Use Enable Login Startup below to try again.";
    [self writeStatus];
}

- (void)showWindow:(id)sender {
    (void)sender;
    [NSApp activateIgnoringOtherApps:YES];
    [self.window makeKeyAndOrderFront:nil];
}
- (void)openNetworkSettings:(id)sender {
    (void)sender;
    [NSWorkspace.sharedWorkspace openURL:[NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork"]];
}
- (void)openLoginSettings:(id)sender {
    (void)sender;
    if (@available(macOS 13.0, *)) [SMAppService openSystemSettingsLoginItems];
}
- (void)enableLogin:(id)sender {
    (void)sender;
    if (self.smokeTest) return;
    if (@available(macOS 13.0, *)) {
        NSError *error = nil;
        SMAppService *service = SMAppService.mainAppService;
        if (service.status == SMAppServiceStatusNotRegistered && ![service registerAndReturnError:&error])
            self.login = @"registration_failed";
        else self.login = [NSString stringWithUTF8String:HengeHelperLoginStatus()];
    } else self.login = @"unavailable";
    [self refresh];
    if ([self.login isEqual:@"requires_approval"]) [self openLoginSettings:nil];
}
- (void)quit:(id)sender { (void)sender; [NSApp terminate:nil]; }

- (NSTextField *)text:(NSString *)value frame:(NSRect)frame size:(CGFloat)size {
    NSTextField *label = [NSTextField wrappingLabelWithString:value];
    label.frame = frame;
    label.font = [NSFont systemFontOfSize:size];
    [self.window.contentView addSubview:label];
    return label;
}
- (void)button:(NSString *)title action:(SEL)action frame:(NSRect)frame {
    NSButton *button = [NSButton buttonWithTitle:title target:self action:action];
    button.frame = frame;
    [self.window.contentView addSubview:button];
}
- (void)makeUI {
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 580, 290)
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable backing:NSBackingStoreBuffered defer:NO];
    self.window.title = @"Henge Helper";
    self.window.releasedWhenClosed = NO;
    [self.window center];
    self.message = [self text:@"Starting Henge Helper" frame:NSMakeRect(24, 232, 532, 32) size:20];
    self.detail = [self text:@"" frame:NSMakeRect(24, 144, 532, 82) size:13];
    self.loginMessage = [self text:@"" frame:NSMakeRect(24, 86, 532, 52) size:12];
    [self button:@"Local Network Settings" action:@selector(openNetworkSettings:) frame:NSMakeRect(16, 42, 184, 32)];
    [self button:@"Enable Login Startup" action:@selector(enableLogin:) frame:NSMakeRect(200, 42, 176, 32)];
    [self button:@"Login Items Settings" action:@selector(openLoginSettings:) frame:NSMakeRect(380, 42, 184, 32)];
    [self text:@"Helper connectivity does not provide DeviceCheck support for ChatGPT." frame:NSMakeRect(24, 10, 532, 24) size:11];
    self.statusItem = [NSStatusBar.systemStatusBar statusItemWithLength:NSVariableStatusItemLength];
    self.statusItem.button.title = @"Henge";
    NSMenu *menu = [NSMenu new];
    self.statusMenu = [menu addItemWithTitle:@"Starting" action:NULL keyEquivalent:@""];
    [menu addItem:NSMenuItem.separatorItem];
    for (NSArray *entry in @[@[@"Show Connection", NSStringFromSelector(@selector(showWindow:))],
        @[@"Local Network Settings", NSStringFromSelector(@selector(openNetworkSettings:))],
        @[@"Login Items Settings", NSStringFromSelector(@selector(openLoginSettings:))],
        @[@"Quit Henge Helper", NSStringFromSelector(@selector(quit:))]]) {
        NSMenuItem *item = [menu addItemWithTitle:entry[0] action:NSSelectorFromString(entry[1]) keyEquivalent:@""];
        item.target = self;
    }
    self.statusItem.menu = menu;
}

- (void)monitorLocalNetwork {
    // Use the system's explicit denied-path reason. A BSD errno alone is not
    // enough to call a failure a privacy denial. This connection carries no data.
    nw_endpoint_t endpoint = nw_endpoint_create_host("10.0.2.4", "80");
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    self.permissionConnection = nw_connection_create(endpoint, parameters);
    nw_connection_set_queue(self.permissionConnection, dispatch_get_main_queue());
    __weak HengeHelperApplication *weak = self;
    nw_connection_set_state_changed_handler(self.permissionConnection, ^(nw_connection_state_t state, nw_error_t error) {
        (void)error;
        HengeHelperApplication *strong = weak;
        if (!strong || !strong.permissionConnection) return;
        if (state == nw_connection_state_waiting) {
            nw_path_t path = nw_connection_copy_current_path(strong.permissionConnection);
            strong.localDenied = path && nw_path_get_unsatisfied_reason(path) == nw_path_unsatisfied_reason_local_network_denied;
            [strong refresh];
        } else if (state == nw_connection_state_ready) {
            strong.localDenied = NO;
            nw_connection_cancel(strong.permissionConnection);
            [strong refresh];
        }
    });
    nw_connection_start(self.permissionConnection);
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    self.login = self.smokeTest ? @"test_disabled" : [NSString stringWithUTF8String:HengeHelperLoginStatus()];
    [self makeUI];
    [self refresh];
    if (self.installing) [self showWindow:nil];
    [self monitorLocalNetwork];
    self.start();
    if (self.installing) [self enableLogin:nil];
}
- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)visible {
    (void)sender; (void)visible; [self showWindow:nil]; return NO;
}
- (void)applicationDidBecomeActive:(NSNotification *)notification {
    (void)notification;
    if (!self.smokeTest && ![self.login isEqual:@"registration_failed"])
        self.login = [NSString stringWithUTF8String:HengeHelperLoginStatus()];
    [self refresh];
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender { (void)sender; return NO; }
- (void)applicationWillTerminate:(NSNotification *)notification {
    (void)notification;
    if (self.permissionConnection) nw_connection_cancel(self.permissionConnection);
}
@end

void HengeHelperAppHealth(BOOL connected, int networkError) {
    dispatch_async(dispatch_get_main_queue(), ^{
        HengeHelperApplication *app = helperApplication;
        if (!app) return;
        BOOL changed = app.connected != connected || app.networkError != networkError;
        app.connected = connected;
        app.networkError = networkError;
        if (connected) app.localDenied = NO;
        if (changed) [app refresh];
    });
}

void HengeHelperRunApplication(BOOL installing, BOOL smokeTest, dispatch_block_t start) {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    helperApplication = [HengeHelperApplication new];
    helperApplication.installing = installing;
    helperApplication.smokeTest = smokeTest;
    helperApplication.start = start;
    NSApp.delegate = helperApplication;
    [NSApp run];
}
