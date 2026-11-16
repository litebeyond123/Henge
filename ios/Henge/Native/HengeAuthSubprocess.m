#import "HengeAuthSubprocess.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const NSUInteger HengeAuthChildInputLimit = 70 * 1024;
static const NSUInteger HengeAuthChildOutputLimit = 160 * 1024;

static int64_t childClockMs(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static NSData *childFailure(NSString *outcome, int code, int status, int64_t start, NSUInteger bytes) {
    NSDictionary *value = @{ @"status": outcome, @"outcome": outcome,
        @"operation": @"isolated_signer", @"errorDomain": @"NSPOSIXErrorDomain", @"errorCode": @(code),
        @"latencyMs": @(MAX((int64_t)0, childClockMs() - start)), @"inputBytes": @(bytes),
        @"resultBytes": @0, @"signatureBytes": @0, @"attestationBytes": @0,
        @"methodABIChecked": @NO, @"callbackABIChecked": @NO,
        @"childExitCode": @(status >= 0 && WIFEXITED(status) ? WEXITSTATUS(status) : -1),
        @"childSignal": @(status >= 0 && WIFSIGNALED(status) ? WTERMSIG(status) : 0), @"isolatedSigner": @YES };
    return [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
}

static BOOL transfer(int fd, void *buffer, size_t length, BOOL writing, int64_t deadline) {
    uint8_t *cursor = buffer;
    while (length) {
        int64_t remaining = deadline - childClockMs();
        if (remaining <= 0) { errno = ETIMEDOUT; return NO; }
        struct pollfd wait = { .fd = fd, .events = writing ? POLLOUT : POLLIN };
        int ready = poll(&wait, 1, (int)MIN(remaining, (int64_t)250));
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return NO;
        if (!ready) continue;
        ssize_t n = writing ? write(fd, cursor, length) : read(fd, cursor, length);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) { if (!n) errno = EPIPE; return NO; }
        cursor += n;
        length -= (size_t)n;
    }
    return YES;
}

#if defined(HENGE_AUTH_SUBPROCESS_TEST)
static NSString *testSignerPath;
void HengeAuthSetTestSignerPath(NSString *path) { testSignerPath = [path copy]; }
#endif

void HengeAuthRunSignerChild(NSInteger operation, NSData *input, NSUInteger timeoutMs,
                            HengeAuthChildCompletion completion) {
    NSData *ownedInput = [input copy];
    HengeAuthChildCompletion done = [completion copy];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            int64_t started = childClockMs();
            NSUInteger boundedTimeout = MIN(MAX(timeoutMs, (NSUInteger)250), (NSUInteger)10000);
            int64_t deadline = started + boundedTimeout;
            NSString *path = [[NSBundle mainBundle] pathForResource:@"henge-auth-signer" ofType:nil inDirectory:@"Helpers"];
#if defined(HENGE_AUTH_SUBPROCESS_TEST)
            if (testSignerPath) path = testSignerPath;
#endif
            if ((operation != 2 && operation != 3 && operation != 0) || ownedInput.length > 32 * 1024 || !path) {
                done(nil, childFailure(path ? @"child_invalid_request" : @"child_not_bundled", path ? EINVAL : ENOENT, -1, started, ownedInput.length));
                return;
            }
            NSData *request = [NSPropertyListSerialization dataWithPropertyList:@{ @"protocol": @1,
                @"operation": @(operation), @"input": ownedInput, @"timeoutMs": @(boundedTimeout) }
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            if (!request || request.length > HengeAuthChildInputLimit) {
                done(nil, childFailure(@"child_invalid_request", EINVAL, -1, started, ownedInput.length)); return;
            }
            int incoming[2] = {-1, -1}, outgoing[2] = {-1, -1};
            if (pipe(incoming) || pipe(outgoing)) {
                int saved = errno;
                for (int i=0;i<2;i++) { if (incoming[i]>=0) close(incoming[i]); if (outgoing[i]>=0) close(outgoing[i]); }
                done(nil, childFailure(@"child_pipe_failed", saved, -1, started, ownedInput.length)); return;
            }
            int setup = 0;
            for (int i=0;i<2;i++) {
                if (fcntl(incoming[i], F_SETFD, FD_CLOEXEC) < 0 && !setup) setup = errno;
                if (fcntl(outgoing[i], F_SETFD, FD_CLOEXEC) < 0 && !setup) setup = errno;
            }
            // Prevent a child crash or early exit from delivering SIGPIPE to the VM process.
            if (fcntl(incoming[1], F_SETNOSIGPIPE, 1) < 0 && !setup) setup = errno;
            if (fcntl(incoming[1], F_SETFL, O_NONBLOCK) < 0 && !setup) setup = errno;
            if (fcntl(outgoing[0], F_SETFL, O_NONBLOCK) < 0 && !setup) setup = errno;
            posix_spawn_file_actions_t actions;
            posix_spawnattr_t attributes;
            BOOL hasActions = NO, hasAttributes = NO;
            if (!setup) { setup = posix_spawn_file_actions_init(&actions); hasActions = setup == 0; }
            if (!setup) setup = posix_spawn_file_actions_adddup2(&actions, incoming[0], STDIN_FILENO);
            if (!setup) setup = posix_spawn_file_actions_adddup2(&actions, outgoing[1], STDOUT_FILENO);
            // Private frameworks can emit arbitrary descriptions. Never include those in Henge logs.
            if (!setup) setup = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
            if (!setup) setup = posix_spawn_file_actions_addclose(&actions, incoming[1]);
            if (!setup) setup = posix_spawn_file_actions_addclose(&actions, outgoing[0]);
            if (!setup) { setup = posix_spawnattr_init(&attributes); hasAttributes = setup == 0; }
            if (!setup) setup = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT);
            char *const arguments[] = {(char *)path.fileSystemRepresentation, "--request-stdin", NULL};
            NSString *home = [@"HOME=" stringByAppendingString:NSHomeDirectory()];
            NSString *temporary = [@"TMPDIR=" stringByAppendingString:NSTemporaryDirectory()];
            char *const environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", (char *)home.UTF8String, (char *)temporary.UTF8String, NULL};
            pid_t pid = 0;
            int spawned = setup ?: posix_spawn(&pid, path.fileSystemRepresentation, &actions, &attributes, arguments, environment);
            if (hasAttributes) posix_spawnattr_destroy(&attributes);
            if (hasActions) posix_spawn_file_actions_destroy(&actions);
            close(incoming[0]); close(outgoing[1]);
            if (spawned) {
                close(incoming[1]); close(outgoing[0]);
                done(nil, childFailure(@"child_spawn_failed", spawned, -1, started, ownedInput.length)); return;
            }
            uint32_t requestLength = htonl((uint32_t)request.length), responseLength = 0;
            BOOL ok = transfer(incoming[1], &requestLength, sizeof requestLength, YES, deadline) &&
                transfer(incoming[1], (void *)request.bytes, request.length, YES, deadline);
            close(incoming[1]);
            if (ok) ok = transfer(outgoing[0], &responseLength, sizeof responseLength, NO, deadline);
            NSUInteger length = ntohl(responseLength);
            if (ok && (length == 0 || length > HengeAuthChildOutputLimit)) { ok = NO; errno = EOVERFLOW; }
            NSMutableData *response = ok ? [NSMutableData dataWithLength:length] : nil;
            if (ok) ok = transfer(outgoing[0], response.mutableBytes, length, NO, deadline);
            int saved = ok ? 0 : errno;
            close(outgoing[0]);
            int childStatus = -1;
            pid_t waited = 0;
            for (;;) {
                waited = waitpid(pid, &childStatus, WNOHANG);
                if (waited < 0 && errno == EINTR) continue;
                if (waited != 0 || childClockMs() >= deadline) break;
                struct timespec pause = {.tv_nsec = 10 * 1000 * 1000}; nanosleep(&pause, NULL);
            }
            if (waited == 0 || (waited < 0 && errno != ECHILD)) {
                int waitError = waited == 0 ? ETIMEDOUT : errno;
                kill(pid, SIGKILL);
                do { waited = waitpid(pid, &childStatus, 0); } while (waited < 0 && errno == EINTR);
                if (waited < 0) childStatus = -1;
                ok = NO; saved = waitError;
            } else if (waited < 0 || !WIFEXITED(childStatus) || WEXITSTATUS(childStatus) != 0) {
                if (waited < 0) childStatus = -1;
                ok = NO; if (!saved) saved = ECHILD;
            }
            if (!ok) {
                done(nil, childFailure(saved == ETIMEDOUT ? @"child_timed_out" : @"child_transport_failed", saved, childStatus, started, ownedInput.length)); return;
            }
            id wrapper = [NSPropertyListSerialization propertyListWithData:response options:NSPropertyListImmutable format:NULL error:NULL];
            NSData *result = [wrapper isKindOfClass:NSDictionary.class] && [wrapper[@"result"] isKindOfClass:NSData.class] ? wrapper[@"result"] : nil;
            NSData *diagnostics = [wrapper isKindOfClass:NSDictionary.class] && [wrapper[@"diagnostics"] isKindOfClass:NSData.class] ? wrapper[@"diagnostics"] : nil;
            id raw = diagnostics.length <= 8192 ? [NSJSONSerialization JSONObjectWithData:diagnostics ?: [NSData data] options:0 error:NULL] : nil;
            if (![wrapper isKindOfClass:NSDictionary.class] || ![wrapper[@"protocol"] isEqual:@1] ||
                result.length > 65536 || ![raw isKindOfClass:NSDictionary.class]) {
                done(nil, childFailure(@"child_invalid_response", EPROTO, childStatus, started, ownedInput.length)); return;
            }
            NSMutableDictionary *augmented = [raw mutableCopy];
            augmented[@"isolatedSigner"] = @YES;
            augmented[@"childExitCode"] = @0;
            augmented[@"childSignal"] = @0;
            done(result, [NSJSONSerialization dataWithJSONObject:augmented options:0 error:NULL]);
        }
    });
}
