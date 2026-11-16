#include "guest-auth-process.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned checks;
static void require(int value, const char *label) {
    checks++;
    if (!value) { fprintf(stderr, "FAIL: %s\n", label); exit(1); }
}
static void stateIs(HengeAuthProcessState actual, HengeAuthProcessState expected, const char *label) {
    checks++;
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s state=%d expected=%d\n", label, actual, expected);
        exit(1);
    }
}

static void comparisonTests(void) {
    HengeAuthProcessIdentity expected = {
        .pid = 123, .uid = 501, .real_uid = 501,
        .start_seconds = 100, .start_microseconds = 42,
        .executable_path = "/Applications/OwnedFixture.app/Contents/MacOS/OwnedFixture"
    };
    HengeAuthProcessSample sample = {
        .kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT, .identity = expected, .process_status = 2
    };
    HengeAuthProcessObservation observation;
#define COMPARE(want, label) stateIs(HengeAuthProcessCompare(&expected, &sample, &observation), want, label)
    COMPARE(HENGE_AUTH_PROCESS_ALIVE, "same kernel identity alive");
    require(observation.identity_available && observation.observed_pid == expected.pid, "fixed identity observation");
    sample.kind = HENGE_AUTH_PROCESS_SAMPLE_ABSENT;
    COMPARE(HENGE_AUTH_PROCESS_EXITED, "kernel absence means original exited");
    require(!observation.identity_available, "absence does not fabricate identity");
    sample.kind = HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE; sample.error_number = EACCES;
    COMPARE(HENGE_AUTH_PROCESS_UNAVAILABLE, "access failure is not exit");
    require(observation.error_number == EACCES, "errno preserved separately");
    sample.error_number = 0;
    COMPARE(HENGE_AUTH_PROCESS_UNAVAILABLE, "unspecified failure remains unknown");
    require(observation.error_number == EIO, "unknown failure has fixed fallback");
    sample.kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT;
    sample.identity.start_seconds++;
    COMPARE(HENGE_AUTH_PROCESS_REPLACED, "same PID different birth second");
    sample.identity = expected; sample.identity.start_microseconds++;
    COMPARE(HENGE_AUTH_PROCESS_REPLACED, "same PID different birth microsecond");
    sample.identity = expected; sample.identity.pid++;
    COMPARE(HENGE_AUTH_PROCESS_REPLACED, "different PID");
    sample.identity = expected; sample.identity.uid++;
    COMPARE(HENGE_AUTH_PROCESS_REPLACED, "effective UID changed");
    sample.identity = expected; sample.identity.real_uid++;
    COMPARE(HENGE_AUTH_PROCESS_REPLACED, "real UID changed");
    sample.identity = expected; strcpy(sample.identity.executable_path, "/different/executable");
    COMPARE(HENGE_AUTH_PROCESS_REPLACED, "same lifetime different executable");
    sample.identity = expected; sample.kind = HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ;
    COMPARE(HENGE_AUTH_PROCESS_REPLACED, "identity changed while reading");
    sample.kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT; sample.zombie = 1;
    sample.identity.executable_path[0] = '\0';
    COMPARE(HENGE_AUTH_PROCESS_EXITED, "original zombie needs no live path");
    require(observation.zombie, "zombie observation preserved");
    sample.identity.start_microseconds++;
    COMPARE(HENGE_AUTH_PROCESS_REPLACED, "replacement zombie never original instance");
    sample.identity = expected; sample.zombie = 0; sample.identity.executable_path[0] = '\0';
    COMPARE(HENGE_AUTH_PROCESS_UNAVAILABLE, "missing path is not exit");
    sample.identity = expected; memset(sample.identity.executable_path, 'x', sizeof(sample.identity.executable_path));
    sample.identity.executable_path[0] = '/';
    COMPARE(HENGE_AUTH_PROCESS_UNAVAILABLE, "unterminated path rejected");
    sample.identity = expected; sample.identity.start_microseconds = 1000000;
    COMPARE(HENGE_AUTH_PROCESS_UNAVAILABLE, "invalid kernel birth time rejected");
    sample.identity = expected; sample.identity.start_seconds = 0;
    COMPARE(HENGE_AUTH_PROCESS_UNAVAILABLE, "missing kernel birth time rejected");
    sample.identity = expected; sample.kind = 0;
    COMPARE(HENGE_AUTH_PROCESS_UNAVAILABLE, "invalid sample kind rejected");
    sample.kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT; expected.pid = 0;
    COMPARE(HENGE_AUTH_PROCESS_UNAVAILABLE, "invalid expected identity rejected");
    stateIs(HengeAuthProcessCompare(NULL, &sample, &observation), HENGE_AUTH_PROCESS_UNAVAILABLE, "null expected rejected");
#undef COMPARE
    printf("PASS: %u pure process-identity checks\n", checks);
}

static void canonicalPathTests(void) {
    char directory[] = "/tmp/henge-path-tests.XXXXXX";
    require(mkdtemp(directory) != NULL, "owned path directory");
    char file[4096], alias[4096], missing[4096], notDirectory[4096];
    require(snprintf(file, sizeof(file), "%s/file", directory) < (int)sizeof(file), "owned file path bounded");
    require(snprintf(alias, sizeof(alias), "%s/alias", directory) < (int)sizeof(alias), "owned alias path bounded");
    require(snprintf(missing, sizeof(missing), "%s/missing", directory) < (int)sizeof(missing), "missing path bounded");
    require(snprintf(notDirectory, sizeof(notDirectory), "%s/child", file) < (int)sizeof(notDirectory), "non-directory path bounded");
    int fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    require(fd >= 0 && close(fd) == 0, "owned canonical target created");
    require(symlink(file, alias) == 0, "owned alias created");
    char direct[HENGE_AUTH_PROCESS_PATH_CAPACITY], resolved[HENGE_AUTH_PROCESS_PATH_CAPACITY];
    require(HengeAuthProcessCanonicalizePath(file, direct) == 0, "canonicalize existing absolute target");
    require(HengeAuthProcessCanonicalizePath(alias, resolved) == 0, "canonicalize existing absolute alias");
    require(!strcmp(direct, resolved), "same target aliases have one canonical identity");
    strcpy(resolved, alias);
    require(HengeAuthProcessCanonicalizePath(resolved, resolved) == 0 && !strcmp(direct, resolved), "in-place canonicalization is safe");
    require(HengeAuthProcessCanonicalizePath(missing, resolved) == ENOENT && !resolved[0], "missing target fails with empty output and ENOENT");
    require(HengeAuthProcessCanonicalizePath(notDirectory, resolved) == ENOTDIR && !resolved[0], "non-directory fails with real errno");
    require(HengeAuthProcessCanonicalizePath("relative/path", resolved) == EINVAL && !resolved[0], "relative path rejected");
    require(HengeAuthProcessCanonicalizePath(NULL, resolved) == EINVAL && !resolved[0], "null input rejected");
    require(HengeAuthProcessCanonicalizePath(file, NULL) == EINVAL, "null output rejected");
    require(unlink(file) == 0, "remove owned target");
    require(HengeAuthProcessCanonicalizePath(alias, resolved) == ENOENT && !resolved[0], "dangling alias never supplies trusted path");
    require(unlink(alias) == 0 && rmdir(directory) == 0, "owned path test cleanup");
    printf("PASS: %u comparison and POSIX path checks\n", checks);
}

#if defined(__APPLE__)
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>

extern char **environ;
extern int HengeTestFoundationResolvedPath(const char *path, char *output, size_t capacity);
typedef struct { pid_t pid; int input; int output; int reaped; } OwnedChild;
static OwnedChild children[2] = {{.input = -1, .output = -1}, {.input = -1, .output = -1}};
static double now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}
static void pauseBriefly(void) { struct timespec ts = {0, 20000000}; nanosleep(&ts, NULL); }
static void cleanup(void) {
    for (size_t i = 0; i < 2; i++) {
        OwnedChild *child = &children[i];
        if (child->input >= 0) { close(child->input); child->input = -1; }
        if (child->output >= 0) { close(child->output); child->output = -1; }
        if (child->pid <= 0 || child->reaped) continue;
        int status = 0; pid_t result = waitpid(child->pid, &status, WNOHANG);
        if (result == 0) {
            /* This is our own still-unreaped test child; never an API result
             * or an application discovered by the process census. */
            kill(child->pid, SIGKILL);
            double deadline = now() + 3;
            while ((result = waitpid(child->pid, &status, WNOHANG)) == 0 && now() < deadline) pauseBriefly();
        }
        child->reaped = result == child->pid || (result < 0 && errno == ECHILD);
        if (!child->reaped) fprintf(stderr, "FAIL: owned test child cleanup incomplete\n");
    }
}
static void spawnOwned(OwnedChild *child, const char *executable) {
    int input[2], output[2];
    require(pipe(input) == 0 && pipe(output) == 0, "owned child pipes");
    posix_spawn_file_actions_t actions;
    require(posix_spawn_file_actions_init(&actions) == 0, "spawn actions init");
    require(posix_spawn_file_actions_adddup2(&actions, input[0], STDIN_FILENO) == 0, "spawn input");
    require(posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO) == 0, "spawn output");
    require(posix_spawn_file_actions_addclose(&actions, input[1]) == 0, "spawn closes parent input");
    require(posix_spawn_file_actions_addclose(&actions, output[0]) == 0, "spawn closes parent output");
    require(posix_spawn_file_actions_addclose(&actions, input[0]) == 0, "spawn closes duplicated input");
    require(posix_spawn_file_actions_addclose(&actions, output[1]) == 0, "spawn closes duplicated output");
    char *args[] = {(char *)executable, "--owned-child", NULL};
    int result = posix_spawn(&child->pid, executable, &actions, NULL, args, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(input[0]); close(output[1]);
    child->input = input[1]; child->output = output[0];
    require(result == 0 && child->pid > 0, "owned child spawned");
    struct pollfd fd = {.fd = child->output, .events = POLLIN};
    require(poll(&fd, 1, 5000) == 1 && (fd.revents & POLLIN), "owned child readiness bounded");
    char ready = 0;
    require(read(child->output, &ready, 1) == 1 && ready == 'R', "owned child ready");
}
static int hasPID(const HengeAuthProcessIdentity *identities, size_t count, pid_t pid) {
    for (size_t i = 0; i < count; i++) if (identities[i].pid == pid) return 1;
    return 0;
}
static void kernelTests(const char *executable, const char *unrelated, const char *renamed) {
    require(atexit(cleanup) == 0, "owned cleanup registered");
    char *canonical = realpath(executable, NULL);
    char *unrelatedCanonical = realpath(unrelated, NULL);
    require(canonical && unrelatedCanonical && strcmp(canonical, unrelatedCanonical), "owned fixture paths distinct");
    spawnOwned(&children[0], canonical);
    HengeAuthProcessIdentity original, rejected, identities[8];
    HengeAuthProcessObservation observation;
    stateIs(HengeAuthProcessCapture(children[0].pid, canonical, geteuid(), &original, &observation), HENGE_AUTH_PROCESS_ALIVE, "capture real owned process");
    require(original.pid == children[0].pid && original.start_seconds > 0 && original.start_microseconds < 1000000, "kernel birth captured");
    require(original.uid == geteuid() && original.real_uid == getuid(), "kernel ownership captured");
    stateIs(HengeAuthProcessCheck(&original, &observation), HENGE_AUTH_PROCESS_ALIVE, "owned identity remains live");
    /* The runner deliberately builds in /var/tmp. Both names must identify the
     * same owned process, not merely return equal strings in a mock. */
    require(!strncmp(executable, "/var/tmp/", 9) && !strncmp(canonical, "/private/var/tmp/", 17), "owned fixture exercises var and private-var aliases");
    HengeAuthProcessIdentity aliased;
    stateIs(HengeAuthProcessCapture(children[0].pid, executable, geteuid(), &aliased, &observation), HENGE_AUTH_PROCESS_ALIVE, "capture owned process through var alias");
    require(!strcmp(aliased.executable_path, original.executable_path) &&
        aliased.start_seconds == original.start_seconds && aliased.start_microseconds == original.start_microseconds,
        "alias preserves canonical executable and kernel lifetime");
    char foundationPath[HENGE_AUTH_PROCESS_PATH_CAPACITY];
    require(HengeTestFoundationResolvedPath(executable, foundationPath, sizeof(foundationPath)) == 0, "read actual Foundation path standardization");
    stateIs(HengeAuthProcessCapture(children[0].pid, foundationPath, geteuid(), &aliased, &observation), HENGE_AUTH_PROCESS_ALIVE, "Foundation path resolves to same owned process");
    stateIs(HengeAuthProcessCapture(children[0].pid, unrelatedCanonical, geteuid(), &rejected, &observation), HENGE_AUTH_PROCESS_REPLACED, "real executable path mismatch");
    require(rejected.pid == 0, "mismatch never fills trusted identity");
    stateIs(HengeAuthProcessCapture(children[0].pid, canonical, geteuid() + 1, &rejected, &observation), HENGE_AUTH_PROCESS_UNAVAILABLE, "other UID request fails closed");
    size_t count = 0;
    stateIs(HengeAuthProcessListMatching(canonical, geteuid(), identities, 8, &count, &observation), HENGE_AUTH_PROCESS_ALIVE, "fresh kernel census");
    require(hasPID(identities, count, getpid()) && hasPID(identities, count, children[0].pid), "census includes parent and owned child");
    stateIs(HengeAuthProcessListMatching(executable, geteuid(), identities, 8, &count, &observation), HENGE_AUTH_PROCESS_ALIVE, "census accepts var alias");
    require(hasPID(identities, count, children[0].pid), "alias census retains exact owned target");
    stateIs(HengeAuthProcessListMatching(foundationPath, geteuid(), identities, 8, &count, &observation), HENGE_AUTH_PROCESS_ALIVE, "census accepts actual Foundation path");
    require(hasPID(identities, count, children[0].pid), "Foundation census retains exact owned target");
    stateIs(HengeAuthProcessListMatching(canonical, geteuid(), identities, 1, &count, &observation), HENGE_AUTH_PROCESS_UNAVAILABLE, "truncated matching capacity is unknown");
    require(count == 0 && observation.error_number == EOVERFLOW, "truncation cannot report absence");
    stateIs(HengeAuthProcessListMatching(unrelatedCanonical, geteuid(), identities, 8, &count, &observation), HENGE_AUTH_PROCESS_EXITED, "complete census of unused fixture absent");
    require(count == 0, "unused fixture has no live instances");
    spawnOwned(&children[1], unrelatedCanonical);
    require(rename(unrelated, renamed) == 0, "rename unrelated live executable");
    stateIs(HengeAuthProcessListMatching(canonical, geteuid(), identities, 8, &count, &observation), HENGE_AUTH_PROCESS_ALIVE, "unrelated renamed executable does not block census");
    require(hasPID(identities, count, children[0].pid), "target preserved with renamed unrelated instance");
    require(unlink(renamed) == 0, "unlink unrelated live executable");
    char kernelPath[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int pathLength = proc_pidpath(children[1].pid, kernelPath, sizeof(kernelPath));
    HengeAuthProcessState deletedState = HengeAuthProcessListMatching(canonical, geteuid(), identities, 8, &count, &observation);
    if (pathLength > 0 && strcmp(kernelPath, canonical)) {
        stateIs(deletedState, HENGE_AUTH_PROCESS_ALIVE, "known unrelated deleted path does not block census");
        require(hasPID(identities, count, children[0].pid), "target preserved with known deleted path");
    } else {
        /* Some kernels do not disclose a path for an unlinked text vnode.
         * That cannot safely be dismissed as unrelated using its name. */
        stateIs(deletedState, HENGE_AUTH_PROCESS_UNAVAILABLE, "unavailable deleted path cannot prove absence");
        require(count == 0, "unknown scan does not leak partial matches");
        printf("INFO: kernel withholds unlinked executable path; census correctly unknown\n");
    }
    close(children[1].input); children[1].input = -1;
    int status = 0; pid_t waited = 0; double deadline = now() + 5;
    while ((waited = waitpid(children[1].pid, &status, WNOHANG)) == 0 && now() < deadline) pauseBriefly();
    require(waited == children[1].pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "unrelated owned child reaped");
    children[1].reaped = 1;
    require(write(children[0].input, "Q", 1) == 1, "request owned cooperative exit");
    deadline = now() + 5;
    HengeAuthProcessState state;
    do { state = HengeAuthProcessCheck(&original, &observation); if (state == HENGE_AUTH_PROCESS_ALIVE) pauseBriefly(); }
    while (state == HENGE_AUTH_PROCESS_ALIVE && now() < deadline);
    stateIs(state, HENGE_AUTH_PROCESS_EXITED, "owned zombie or kernel absence confirms exit");
    waited = waitpid(children[0].pid, &status, 0);
    require(waited == children[0].pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "original owned child reaped");
    children[0].reaped = 1;
    stateIs(HengeAuthProcessCheck(&original, &observation), HENGE_AUTH_PROCESS_EXITED, "reaped original remains exited");
    stateIs(HengeAuthProcessListMatching(canonical, geteuid(), identities, 8, &count, &observation), HENGE_AUTH_PROCESS_ALIVE, "fresh post-exit census");
    require(hasPID(identities, count, getpid()) && !hasPID(identities, count, original.pid), "post-exit census excludes original child");
    free(canonical); free(unrelatedCanonical);
    printf("PASS: %u total process-identity checks including real macOS owned processes\n", checks);
}
#endif

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--owned-child")) {
        if (write(STDOUT_FILENO, "R", 1) != 1) return 90;
        char input;
        for (;;) {
            ssize_t length = read(STDIN_FILENO, &input, 1);
            if (!length || (length == 1 && input == 'Q')) return 0;
            if (length < 0 && errno != EINTR) return 91;
        }
    }
    comparisonTests();
    canonicalPathTests();
#if defined(__APPLE__)
    require(argc == 3, "owned fixture path arguments");
    kernelTests(argv[0], argv[1], argv[2]);
#else
    (void)argc; (void)argv;
    HengeAuthProcessIdentity identity;
    HengeAuthProcessObservation observation;
    size_t count = 999;
    stateIs(HengeAuthProcessCapture(getpid(), "/unavailable", geteuid(), &identity, &observation), HENGE_AUTH_PROCESS_UNAVAILABLE, "non-Darwin capture fails closed");
    require(observation.error_number == ENOTSUP, "non-Darwin unsupported explicit");
    stateIs(HengeAuthProcessCheck(&identity, &observation), HENGE_AUTH_PROCESS_UNAVAILABLE, "non-Darwin check fails closed");
    stateIs(HengeAuthProcessListMatching("/unavailable", geteuid(), &identity, 1, &count, &observation), HENGE_AUTH_PROCESS_UNAVAILABLE, "non-Darwin census fails closed");
    require(count == 0, "non-Darwin census does not report fake process");
    printf("PASS: %u portable checks; SKIP: real macOS kernel evidence unavailable\n", checks);
#endif
    return 0;
}
