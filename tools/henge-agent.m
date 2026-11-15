// Runs inside macOS on a Henge virtual Mac, as a LaunchAgent. It keeps the clipboard in step with the device,
// and keeps the shared folder mounted. It talks to host/share.c at 10.0.2.4, which only exists inside Henge.
#import <AppKit/AppKit.h>
#import "guest-chat-diagnostics.h"
#import "helper-health.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define HOST "10.0.2.4"

static int send_all(int fd, const void *p, size_t n) {
    const char *c = p;
    while (n) {
        ssize_t w = send(fd, c, n, 0);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        c += w, n -= (size_t)w;
    }
    return 0;
}

static double monotonicSeconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec + now.tv_nsec / 1e9;
}

// One request on its own connection. Clipboard long polls have 40 s; the small host-service requests have
// 5 s and a 16 KB response limit. A nonblocking connect cannot hang the CLI when the host is unavailable.
static NSData *requestWithSession(NSString *method, NSString *path, NSData *body, NSString *session,
                                  int seconds, NSUInteger responseLimit, int *status, unsigned long *seq) {
    *status = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return nil;
    struct timeval timeout = {.tv_sec = seconds};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(80)};
    inet_pton(AF_INET, HOST, &addr.sin_addr);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) { close(fd); return nil; }
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        struct pollfd wait = {.fd = fd, .events = POLLOUT};
        int error = 0;
        socklen_t size = sizeof error;
        if (errno != EINPROGRESS || poll(&wait, 1, seconds < 5 ? seconds * 1000 : 5000) <= 0 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error) {
            close(fd);
            return nil;
        }
    }
    if (fcntl(fd, F_SETFL, flags) != 0) {
        close(fd);
        return nil;
    }
    NSString *extra = session ? [NSString stringWithFormat:@"X-Henge-Session: %@\r\nContent-Type: application/json\r\n", session] : @"";
    NSString *head = [NSString stringWithFormat:@"%@ %@ HTTP/1.1\r\nHost: " HOST "\r\nContent-Length: %lu\r\n%@Connection: close\r\n\r\n", method, path,
                                                (unsigned long)body.length, extra];
    const char *text = head.UTF8String;
    if (send_all(fd, text, strlen(text)) != 0 || (body.length && send_all(fd, body.bytes, body.length) != 0)) {
        close(fd);
        return nil;
    }
    NSMutableData *all = [NSMutableData data];
    char piece[16384];
    double deadline = monotonicSeconds() + seconds;
    for (;;) {
        double left = deadline - monotonicSeconds();
        if (left <= 0) { close(fd); return nil; }
        struct pollfd wait = {.fd = fd, .events = POLLIN};
        int ready = poll(&wait, 1, (int)ceil(left * 1000));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) { close(fd); return nil; }
        ssize_t got = recv(fd, piece, sizeof piece, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { close(fd); return nil; }
        if (!got) break;
        if (all.length + (NSUInteger)got > responseLimit + 32768) { close(fd); return nil; }
        [all appendBytes:piece length:(NSUInteger)got];
    }
    close(fd);
    NSRange end = [all rangeOfData:[NSData dataWithBytes:"\r\n\r\n" length:4] options:0 range:NSMakeRange(0, all.length)];
    if (end.location == NSNotFound) return nil;
    NSString *headers = [[NSString alloc] initWithData:[all subdataWithRange:NSMakeRange(0, end.location)] encoding:NSUTF8StringEncoding];
    if (!headers || sscanf(headers.UTF8String, "HTTP/1.1 %d", status) != 1) return nil;
    NSRange found = [headers rangeOfString:@"X-Henge-Seq: "];
    if (found.location != NSNotFound && seq) *seq = strtoul(headers.UTF8String + NSMaxRange(found), NULL, 10);
    NSUInteger start = NSMaxRange(end);
    if (all.length - start > responseLimit) return nil;
    return [all subdataWithRange:NSMakeRange(start, all.length - start)];
}

static NSData *request(NSString *method, NSString *path, NSData *body, int *status, unsigned long *seq) {
    return requestWithSession(method, path, body, nil, 40, 16 * 1024 * 1024, status, seq);
}

static NSData *chatTransport(NSString *method, NSString *path, NSData *body, NSUInteger limit, int *status) {
    return requestWithSession(method, path, body, nil, 4, limit, status, NULL);
}

// Health is separate from clipboard long polls and diagnostic collection. A probe never marks a daemon alive.
static NSData *helperTransport(NSString *method, NSString *path, NSString *session, int *status) {
    return requestWithSession(method, path, nil, session, 2, 4096, status, NULL);
}

static atomic_int helperStartupStage;
static NSString *helperStage(void) {
    switch (atomic_load(&helperStartupStage)) {
        case 1: return @"clipboard_starting";
        case 2: return @"ready";
        case 3: return @"clipboard_unavailable";
        default: return @"network_ready";
    }
}

static void startHelperHealth(void) {
    // Report before the first AppKit/NSPasteboard call. Later heartbeats run even if AppKit is blocked.
    HengeHelperPing(helperTransport, @"network_ready", NO);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        double nextHealth = monotonicSeconds() + 10;
        for (;;) {
            @autoreleasepool {
                // Polling/receipts must not depend on NSPasteboard or the main run loop becoming ready.
                // The collector itself serializes bounded work and skips expired startup requests.
                HengeChatDiagnosticsPoll(chatTransport);
                if (monotonicSeconds() >= nextHealth) {
                    HengeHelperPing(helperTransport, helperStage(), NO);
                    nextHealth = monotonicSeconds() + 10;
                }
            }
            sleep(2);
        }
    });
}

static int printHostResponse(NSData *data, int status) {
    if (!data) {
        fprintf(stderr, "Henge host services did not answer in time. Keep Henge in the foreground with this Mac running.\n");
        return 1;
    }
    FILE *out = status == 200 ? stdout : stderr;
    fwrite(data.bytes, 1, data.length, out);
    if (!data.length || ((const char *)data.bytes)[data.length - 1] != '\n') fputc('\n', out);
    return status == 200 ? 0 : 1;
}

static void hostUsage(void) {
    fprintf(stderr, "Usage: henge-agent [--host-capabilities | --host-state | --host-brightness 0..1]\n"
                    "Without arguments, keeps the shared folder and clipboard connected.\n"
                    "Brightness control must be enabled in Henge > running Mac > Details > iPad services.\n");
}

static int hostCommand(int argc, const char *argv[]) {
    int status = 0;
    if (argc == 2 && (!strcmp(argv[1], "--host-state") || !strcmp(argv[1], "--host-capabilities"))) {
        NSString *path = !strcmp(argv[1], "--host-state") ? @"/.henge/v1/state" : @"/.henge/v1/capabilities";
        NSData *data = requestWithSession(@"GET", path, nil, nil, 5, 16384, &status, NULL);
        return printHostResponse(data, status);
    }
    if (argc != 3 || strcmp(argv[1], "--host-brightness")) { hostUsage(); return 2; }
    char *end;
    errno = 0;
    double value = strtod(argv[2], &end);
    if (errno || end == argv[2] || *end || !isfinite(value) || value < 0 || value > 1) { hostUsage(); return 2; }
    NSData *data = requestWithSession(@"GET", @"/.henge/v1/state", nil, nil, 5, 16384, &status, NULL);
    if (!data || status != 200) return printHostResponse(data, status);
    id state = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![state isKindOfClass:NSDictionary.class] || ![state[@"protocol"] isEqual:@1] ||
        ![state[@"session"] isKindOfClass:NSString.class]) {
        fprintf(stderr, "Henge returned an incompatible host-service response. Update Henge and this helper together.\n");
        return 1;
    }
    NSString *session = state[@"session"];
    // UUID validation also prevents a response from injecting request headers.
    if (![[NSUUID alloc] initWithUUIDString:session] || session.length != 36) {
        fprintf(stderr, "There is no active Henge session. Start this Mac in Henge first.\n");
        return 1;
    }
    NSData *body = [NSJSONSerialization dataWithJSONObject:@{@"value": @(value)} options:0 error:NULL];
    data = requestWithSession(@"POST", @"/.henge/v1/brightness", body, session, 5, 16384, &status, NULL);
    return printHostResponse(data, status);
}

static NSInteger lastChange;

// The device's clipboard, as it changes. The server holds each request until there is something new.
static void followDevice(void) {
    unsigned long seq = 0;
    for (BOOL first = YES;; first = NO) {
        if (atomic_load(&helperStartupStage) != 2) return;
        @autoreleasepool {
            int status = 0;
            unsigned long now = seq;
            NSData *body = request(@"GET", [NSString stringWithFormat:@"/.henge/clipboard?since=%lu", first ? ULONG_MAX >> 1 : seq], nil, &status, &now);
            if (!body) {
                sleep(5);
                continue;
            }
            BOOL news = !first && status == 200 && now != seq;
            seq = now; // what the device had before this helper started isn't news
            if (!news) continue;
            NSString *text = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            if (!text) continue;
            dispatch_async(dispatch_get_main_queue(), ^{
                if (atomic_load(&helperStartupStage) != 2) return;
                @try {
                    NSPasteboard *board = NSPasteboard.generalPasteboard;
                    [board clearContents];
                    [board setString:text forType:NSPasteboardTypeString];
                    lastChange = board.changeCount;
                } @catch (NSException *exception) {
                    (void)exception;
                    atomic_store(&helperStartupStage, 3);
                }
            });
        }
    }
}

// The Mac's clipboard goes to the device, unless the app that copied it marked it as secret.
static void checkClipboard(void) {
    NSPasteboard *board = NSPasteboard.generalPasteboard;
    if (board.changeCount == lastChange) return;
    lastChange = board.changeCount;
    if ([board.types containsObject:@"org.nspasteboard.ConcealedType"]) return;
    NSString *text = [board stringForType:NSPasteboardTypeString];
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    if (!data.length) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        int status = 0;
        request(@"PUT", @"/.henge/clipboard", data, &status, NULL);
    });
}

static NSString *mountPoint(void) { return [NSHomeDirectory() stringByAppendingPathComponent:@"Henge"]; }

// The shared folder, at ~/Henge. mount_webdav needs an empty folder it owns, and is a no-op failure if it is mounted.
static void keepMounted(void) {
    NSString *point = mountPoint();
    [NSFileManager.defaultManager createDirectoryAtPath:point withIntermediateDirectories:YES attributes:nil error:NULL];
    struct stat folder, parent;
    if (stat(point.fileSystemRepresentation, &folder) != 0 || stat(NSHomeDirectory().fileSystemRepresentation, &parent) != 0) return;
    if (folder.st_dev != parent.st_dev) return; // already something else's volume: mounted
    NSTask *task = [NSTask new];
    task.executableURL = [NSURL fileURLWithPath:@"/sbin/mount_webdav"];
    task.arguments = @[ @"-S", @"-v", @"Henge", @"http://" HOST "/", point ];
    task.standardOutput = NSFileHandle.fileHandleWithNullDevice;
    task.standardError = NSFileHandle.fileHandleWithNullDevice;
    [task launchAndReturnError:NULL];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 2 && !strcmp(argv[1], "--version")) { puts("henge-agent 4"); return 0; }
        if (argc == 2 && !strcmp(argv[1], "--connection-check")) {
            BOOL connected = HengeHelperPing(helperTransport, @"network_ready", YES);
            if (!connected) fputs("Henge helper connection probe failed. Keep Henge open with this Mac running.\n", stderr);
            return connected ? 0 : 1;
        }
        if (argc == 3 && !strcmp(argv[1], "--health-check")) {
            char *end = NULL;
            errno = 0;
            long pid = strtol(argv[2], &end, 10);
            if (errno || !argv[2][0] || *end || pid <= 0 || pid > INT_MAX) return 2;
            return HengeHelperCheckPID(helperTransport, (int)pid) ? 0 : 1;
        }
        if (argc == 2 && !strcmp(argv[1], "--chat-diagnostics")) return HengeChatDiagnosticsRun(chatTransport);
        if (argc > 1) return hostCommand(argc, argv);
        startHelperHealth();
        atomic_store(&helperStartupStage, 1);
        HengeHelperPing(helperTransport, @"clipboard_starting", NO);
        @try {
            lastChange = NSPasteboard.generalPasteboard.changeCount;
            atomic_store(&helperStartupStage, 2);
        } @catch (NSException *exception) {
            (void)exception;
            atomic_store(&helperStartupStage, 3);
        }
        if (atomic_load(&helperStartupStage) == 2)
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ followDevice(); });
        keepMounted();
        [NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(NSTimer *timer) {
            (void)timer;
            if (atomic_load(&helperStartupStage) != 2) return;
            @try { checkClipboard(); }
            @catch (NSException *exception) { (void)exception; atomic_store(&helperStartupStage, 3); }
        }];
        [NSTimer scheduledTimerWithTimeInterval:30 repeats:YES block:^(NSTimer *timer) { (void)timer; keepMounted(); }];
        [NSRunLoop.mainRunLoop run];
    }
    return 0;
}
