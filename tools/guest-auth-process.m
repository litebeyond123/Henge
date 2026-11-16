#include "guest-auth-process.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#endif

static int validPath(const char *path) {
    return path && path[0] == '/' &&
        strnlen(path, HENGE_AUTH_PROCESS_PATH_CAPACITY) < HENGE_AUTH_PROCESS_PATH_CAPACITY;
}

int HengeAuthProcessCanonicalizePath(const char *absolutePath,
    char output[HENGE_AUTH_PROCESS_PATH_CAPACITY]) {
    if (!output) return EINVAL;
    if (!validPath(absolutePath)) { output[0] = '\0'; return EINVAL; }
    errno = 0;
    char *canonical = realpath(absolutePath, NULL);
    if (!canonical) { int error = errno ?: EIO; output[0] = '\0'; return error; }
    size_t length = strlen(canonical);
    if (length >= HENGE_AUTH_PROCESS_PATH_CAPACITY) {
        free(canonical); output[0] = '\0'; return ENAMETOOLONG;
    }
    memcpy(output, canonical, length + 1);
    free(canonical);
    return 0;
}

static int validNumbers(const HengeAuthProcessIdentity *identity) {
    return identity && identity->pid > 0 && identity->start_seconds > 0 &&
        identity->start_microseconds < 1000000;
}

static HengeAuthProcessState observed(HengeAuthProcessState state,
    const HengeAuthProcessSample *sample, int error, HengeAuthProcessObservation *out) {
    if (out) {
        memset(out, 0, sizeof(*out));
        out->state = state;
        out->error_number = error;
        if (sample) {
            out->source = sample->source;
            out->path_only_esrch = !!sample->path_only_esrch;
            out->retry_count = sample->retry_count;
            out->sample_elapsed_ms = sample->sample_elapsed_ms;
        }
        if (sample && sample->kind != HENGE_AUTH_PROCESS_SAMPLE_ABSENT && validNumbers(&sample->identity)) {
            out->identity_available = 1;
            out->observed_pid = sample->identity.pid;
            out->observed_uid = sample->identity.uid;
            out->observed_real_uid = sample->identity.real_uid;
            out->observed_start_seconds = sample->identity.start_seconds;
            out->observed_start_microseconds = sample->identity.start_microseconds;
            out->observed_status = sample->process_status;
            out->zombie = !!sample->zombie;
        }
    }
    return state;
}

static int sameLifetime(const HengeAuthProcessIdentity *a, const HengeAuthProcessIdentity *b) {
    return a->pid == b->pid && a->uid == b->uid && a->real_uid == b->real_uid &&
        a->start_seconds == b->start_seconds && a->start_microseconds == b->start_microseconds;
}

static HengeAuthProcessState observedAt(HengeAuthProcessState state, int error,
    HengeAuthProcessSource source, HengeAuthProcessObservation *out) {
    HengeAuthProcessState result = observed(state, NULL, error, out);
    if (out) out->source = source;
    return result;
}

static HengeAuthProcessState compared(HengeAuthProcessState state,
    const HengeAuthProcessIdentity *expected, const HengeAuthProcessSample *sample,
    int error, HengeAuthProcessObservation *out) {
    HengeAuthProcessState result = observed(state, sample, error, out);
    if (out && out->identity_available && sample && validNumbers(expected) && validNumbers(&sample->identity))
        out->same_lifetime = sameLifetime(expected, &sample->identity);
    return result;
}

int HengeAuthProcessCanWaitForExit(const HengeAuthProcessIdentity *identity,
    const HengeAuthProcessObservation *observation) {
    if (!validNumbers(identity) || !validPath(identity->executable_path) || !observation) return 0;
    return observation->state == HENGE_AUTH_PROCESS_UNAVAILABLE &&
        observation->error_number == ESRCH && observation->source == HENGE_AUTH_PROCESS_SOURCE_PIDPATH &&
        observation->identity_available && observation->same_lifetime && observation->path_only_esrch &&
        !observation->zombie && observation->observed_pid == identity->pid &&
        observation->observed_uid == identity->uid && observation->observed_real_uid == identity->real_uid &&
        observation->observed_start_seconds == identity->start_seconds &&
        observation->observed_start_microseconds == identity->start_microseconds;
}

HengeAuthProcessState HengeAuthProcessCompare(const HengeAuthProcessIdentity *expected,
    const HengeAuthProcessSample *sample, HengeAuthProcessObservation *observation) {
    if (!validNumbers(expected) || !validPath(expected->executable_path) || !sample)
        return observedAt(HENGE_AUTH_PROCESS_UNAVAILABLE, EINVAL, HENGE_AUTH_PROCESS_SOURCE_ARGUMENTS, observation);
    if (sample->kind == HENGE_AUTH_PROCESS_SAMPLE_ABSENT)
        return compared(HENGE_AUTH_PROCESS_EXITED, expected, sample, 0, observation);
    if (sample->kind == HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE)
        return compared(HENGE_AUTH_PROCESS_UNAVAILABLE, expected, sample, sample->error_number ?: EIO, observation);
    if (sample->kind != HENGE_AUTH_PROCESS_SAMPLE_PRESENT &&
        sample->kind != HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ)
        return compared(HENGE_AUTH_PROCESS_UNAVAILABLE, expected, sample, EINVAL, observation);
    if (!validNumbers(&sample->identity))
        return compared(HENGE_AUTH_PROCESS_UNAVAILABLE, expected, sample, EIO, observation);
    if (sample->kind == HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ ||
        !sameLifetime(expected, &sample->identity))
        return compared(HENGE_AUTH_PROCESS_REPLACED, expected, sample, 0, observation);
    if (sample->zombie)
        return compared(HENGE_AUTH_PROCESS_EXITED, expected, sample, 0, observation);
    if (!validPath(sample->identity.executable_path))
        return compared(HENGE_AUTH_PROCESS_UNAVAILABLE, expected, sample, EIO, observation);
    if (strcmp(expected->executable_path, sample->identity.executable_path))
        return compared(HENGE_AUTH_PROCESS_REPLACED, expected, sample, 0, observation);
    return compared(HENGE_AUTH_PROCESS_ALIVE, expected, sample, 0, observation);
}

#if defined(__APPLE__) || defined(HENGE_AUTH_PROCESS_RESAMPLE_TESTING)
static double monotonic(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time)) return -1;
    return (double)time.tv_sec + time.tv_nsec / 1e9;
}

static int pathExitRace(const HengeAuthProcessSample *sample) {
    /* readSampleOnce has already mapped BSD ESRCH to ABSENT. This retained
     * ESRCH has a complete, unchanged live BSD identity but no executable path.
     * It is still unknown, never evidence of exit by itself. */
    return sample->kind == HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE &&
        sample->error_number == ESRCH && validNumbers(&sample->identity) &&
        sample->source == HENGE_AUTH_PROCESS_SOURCE_PIDPATH && sample->path_only_esrch &&
        !sample->zombie && !sample->identity.executable_path[0];
}

typedef void (*SampleReader)(void *context, HengeAuthProcessSample *sample);
static void readSettledSample(SampleReader reader, void *context,
    const HengeAuthProcessIdentity *expected, HengeAuthProcessSample *sample) {
    double started = monotonic();
    unsigned retries = 0;
    reader(context, sample);
    if (expected && validNumbers(&sample->identity) && !sameLifetime(expected, &sample->identity)) {
        sample->kind = HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ;
        sample->source = HENGE_AUTH_PROCESS_SOURCE_IDENTITY_CHANGE;
        sample->path_only_esrch = 0;
        goto finished; // Never hide a replacement already seen on Check's first read.
    }
    if (!pathExitRace(sample) || started < 0) goto finished;
    HengeAuthProcessIdentity first = sample->identity;
    const double deadline = started + 0.250;
    /* XNU clears p_textvp before setting SZOMB. Let that narrow transition
     * settle, while retaining the first lifetime across every observation.
     * Only a later BSD absence/zombie can establish exit. Persistent ESRCH,
     * access failures, and other unreadable state remain UNAVAILABLE. */
    for (unsigned attempt = 0; attempt < 25; attempt++) {
        double now = monotonic();
        if (now < 0 || now >= deadline) goto finished;
        struct timespec delay = {0, 10000000};
        if (nanosleep(&delay, NULL) && errno != EINTR) goto finished;
        HengeAuthProcessSample next;
        reader(context, &next);
        retries++;
        if (validNumbers(&next.identity) && !sameLifetime(&first, &next.identity)) {
            next.kind = HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ;
            next.source = HENGE_AUTH_PROCESS_SOURCE_IDENTITY_CHANGE;
            next.path_only_esrch = 0;
        }
        *sample = next;
        if (!pathExitRace(sample)) goto finished;
    }
finished:
    sample->retry_count = retries;
    double elapsed = monotonic() - started;
    sample->sample_elapsed_ms = started >= 0 && elapsed >= 0 ? (unsigned)(elapsed < 300 ? elapsed * 1000 : 300000) : 0;
}
#endif

#if defined(__APPLE__)
/* PROC_PIDTBSDINFO is a kernel snapshot. Reading it on both sides of the path
 * read detects a PID replacement or credential change during that read. It is
 * not an atomic process handle and does not prevent a later exec/exit. */
static int readBSD(pid_t pid, struct proc_bsdinfo *info) {
    memset(info, 0, sizeof(*info));
    errno = 0;
    // A nonzero argument also permits the kernel to return a zombie's BSD info.
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, info, (int)sizeof(*info));
    if (size != (int)sizeof(*info)) return size == 0 && errno == ESRCH ? ESRCH : errno ?: EIO;
    if (info->pbi_pid != (uint32_t)pid || !info->pbi_start_tvsec || info->pbi_start_tvusec >= 1000000)
        return EIO;
    if (info->pbi_status < SIDL || info->pbi_status > SZOMB) return EIO;
    return 0;
}

static void copyBSD(const struct proc_bsdinfo *info, HengeAuthProcessSample *sample) {
    sample->identity.pid = (pid_t)info->pbi_pid;
    sample->identity.uid = info->pbi_uid;
    sample->identity.real_uid = info->pbi_ruid;
    sample->identity.start_seconds = info->pbi_start_tvsec;
    sample->identity.start_microseconds = info->pbi_start_tvusec;
    sample->process_status = info->pbi_status;
    sample->zombie = info->pbi_status == SZOMB;
}

static void readSampleOnce(pid_t pid, uid_t expectedUID, const char *candidatePath,
    HengeAuthProcessSample *sample) {
    memset(sample, 0, sizeof(*sample));
    sample->kind = HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE;
    sample->source = HENGE_AUTH_PROCESS_SOURCE_BSD_BEFORE;
    struct proc_bsdinfo before, after;
    int error = readBSD(pid, &before);
    if (error) {
        sample->kind = error == ESRCH ? HENGE_AUTH_PROCESS_SAMPLE_ABSENT : HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE;
        sample->error_number = error;
        return;
    }
    copyBSD(&before, sample);
    if (sample->zombie || before.pbi_uid != expectedUID || before.pbi_ruid != expectedUID) {
        sample->kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT;
        return; // Never inspect another user's executable path.
    }
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    errno = 0;
    int length = proc_pidpath(pid, path, (uint32_t)sizeof(path));
    int pathError = errno;
    int pathValid = length > 0 && (size_t)length < sizeof(path) &&
        path[0] == '/' && strnlen(path, sizeof(path)) == (size_t)length;
    char canonical[HENGE_AUTH_PROCESS_PATH_CAPACITY] = {0};
    if (pathValid) {
        /* proc_pidpath gets the path from the executable text vnode, not argv
         * or a process name. Normalize both sides before comparing, including
         * aliases such as /var and /private/var. If an unrelated temporary file
         * no longer exists, a known different vnode path still excludes it.
         * If the kernel cannot return any path, absence remains unproven. */
        pathError = HengeAuthProcessCanonicalizePath(path, canonical);
        if (pathError && candidatePath && strcmp(path, candidatePath)) {
            memcpy(sample->identity.executable_path, path, (size_t)length + 1);
        }
    }
    error = readBSD(pid, &after);
    sample->source = HENGE_AUTH_PROCESS_SOURCE_BSD_AFTER;
    if (error) {
        sample->kind = error == ESRCH ? HENGE_AUTH_PROCESS_SAMPLE_ABSENT : HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE;
        sample->error_number = error;
        return;
    }
    HengeAuthProcessIdentity original = sample->identity;
    copyBSD(&after, sample);
    if (!sameLifetime(&original, &sample->identity)) {
        sample->kind = HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ;
        sample->source = HENGE_AUTH_PROCESS_SOURCE_IDENTITY_CHANGE;
        return;
    }
    if (sample->zombie) { sample->kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT; return; }
    if (!pathValid) {
        sample->error_number = pathError ?: EIO;
        sample->source = HENGE_AUTH_PROCESS_SOURCE_PIDPATH;
        sample->path_only_esrch = sample->error_number == ESRCH;
        return; // A path failure alone does not prove that the process exited.
    }
    if (pathError && candidatePath && strcmp(path, candidatePath)) {
        sample->kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT;
        return;
    }
    if (pathError) {
        sample->error_number = pathError;
        sample->source = HENGE_AUTH_PROCESS_SOURCE_PATH_REALPATH;
        return;
    }
    memcpy(sample->identity.executable_path, canonical, strlen(canonical) + 1);
    sample->kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT;
}

typedef struct { pid_t pid; uid_t uid; const char *candidate_path; } SampleRequest;
static void readRequestedSample(void *context, HengeAuthProcessSample *sample) {
    const SampleRequest *request = context;
    readSampleOnce(request->pid, request->uid, request->candidate_path, sample);
}
static void readSample(pid_t pid, uid_t expectedUID, const char *candidatePath,
    const HengeAuthProcessIdentity *expected, HengeAuthProcessSample *sample) {
    SampleRequest request = {pid, expectedUID, candidatePath};
    readSettledSample(readRequestedSample, &request, expected, sample);
}

static int canonicalExpected(const char *path, uid_t uid,
    char canonical[HENGE_AUTH_PROCESS_PATH_CAPACITY]) {
    if (uid != geteuid() || getuid() != geteuid()) return EINVAL;
    return HengeAuthProcessCanonicalizePath(path, canonical);
}

HengeAuthProcessState HengeAuthProcessCapture(pid_t pid, const char *expectedExecutablePath,
    uid_t expectedUID, HengeAuthProcessIdentity *outIdentity, HengeAuthProcessObservation *observation) {
    if (outIdentity) memset(outIdentity, 0, sizeof(*outIdentity));
    char expectedCanonicalExe[HENGE_AUTH_PROCESS_PATH_CAPACITY] = {0};
    int error = pid > 0 && outIdentity ? canonicalExpected(expectedExecutablePath, expectedUID, expectedCanonicalExe) : EINVAL;
    if (error) return observedAt(HENGE_AUTH_PROCESS_UNAVAILABLE, error,
        pid > 0 && outIdentity ? HENGE_AUTH_PROCESS_SOURCE_EXPECTED_REALPATH : HENGE_AUTH_PROCESS_SOURCE_ARGUMENTS, observation);
    HengeAuthProcessSample sample;
    readSample(pid, expectedUID, NULL, NULL, &sample);
    if (sample.kind == HENGE_AUTH_PROCESS_SAMPLE_ABSENT)
        return observed(HENGE_AUTH_PROCESS_EXITED, &sample, 0, observation);
    if (sample.kind == HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE)
        return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, &sample, sample.error_number ?: EIO, observation);
    if (sample.kind == HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ ||
        sample.identity.pid != pid || sample.identity.uid != expectedUID || sample.identity.real_uid != expectedUID)
        return observed(HENGE_AUTH_PROCESS_REPLACED, &sample, 0, observation);
    if (sample.zombie) return observed(HENGE_AUTH_PROCESS_EXITED, &sample, 0, observation);
    if (!validPath(sample.identity.executable_path))
        return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, &sample, EIO, observation);
    if (strcmp(expectedCanonicalExe, sample.identity.executable_path))
        return observed(HENGE_AUTH_PROCESS_REPLACED, &sample, 0, observation);
    *outIdentity = sample.identity;
    return observed(HENGE_AUTH_PROCESS_ALIVE, &sample, 0, observation);
}

HengeAuthProcessState HengeAuthProcessCheck(const HengeAuthProcessIdentity *identity,
    HengeAuthProcessObservation *observation) {
    if (!validNumbers(identity) || !validPath(identity->executable_path) ||
        identity->uid != geteuid() || identity->real_uid != geteuid() || getuid() != geteuid())
        return observedAt(HENGE_AUTH_PROCESS_UNAVAILABLE, EINVAL, HENGE_AUTH_PROCESS_SOURCE_ARGUMENTS, observation);
    HengeAuthProcessSample sample;
    readSample(identity->pid, identity->uid, NULL, identity, &sample);
    return HengeAuthProcessCompare(identity, &sample, observation);
}

HengeAuthProcessState HengeAuthProcessListMatching(const char *expectedExecutablePath,
    uid_t expectedUID, HengeAuthProcessIdentity *outIdentities, size_t capacity,
    size_t *count, HengeAuthProcessObservation *observation) {
    if (count) *count = 0;
    char expectedCanonicalExe[HENGE_AUTH_PROCESS_PATH_CAPACITY] = {0};
    int error = outIdentities && count && capacity && capacity <= 64
        ? canonicalExpected(expectedExecutablePath, expectedUID, expectedCanonicalExe) : EINVAL;
    if (error) return observedAt(HENGE_AUTH_PROCESS_UNAVAILABLE, error,
        outIdentities && count && capacity && capacity <= 64
            ? HENGE_AUTH_PROCESS_SOURCE_EXPECTED_REALPATH : HENGE_AUTH_PROCESS_SOURCE_ARGUMENTS, observation);
    memset(outIdentities, 0, capacity * sizeof(*outIdentities));
    enum { MaxPIDs = 8192, MinimumPIDs = 128, CensusAttempts = 3 };
    double start = monotonic();
    if (start < 0) return observedAt(HENGE_AUTH_PROCESS_UNAVAILABLE, EIO, HENGE_AUTH_PROCESS_SOURCE_CENSUS_DEADLINE, observation);
    const double deadline = start + 5;
    size_t matches = 0;
    pid_t *pids = NULL;
    HengeAuthProcessSample last = {0};
    for (unsigned attempt = 0; attempt < CensusAttempts; attempt++) {
        memset(&last, 0, sizeof(last));
        last.source = HENGE_AUTH_PROCESS_SOURCE_CENSUS_SIZE;
        errno = 0;
        int needed = proc_listpids(PROC_UID_ONLY, (uint32_t)expectedUID, NULL, 0);
        if (needed <= 0 || needed % (int)sizeof(pid_t)) { error = errno ?: EIO; goto failed; }
        size_t pidCapacity = (size_t)needed / sizeof(pid_t) + 64u * (attempt + 1);
        if (pidCapacity < MinimumPIDs) pidCapacity = MinimumPIDs;
        if (pidCapacity > MaxPIDs) { last.source = HENGE_AUTH_PROCESS_SOURCE_CENSUS_CAPACITY; error = EOVERFLOW; goto failed; }
        free(pids);
        pids = calloc(pidCapacity, sizeof(*pids));
        if (!pids) { error = ENOMEM; goto failed; }
        errno = 0;
        last.source = HENGE_AUTH_PROCESS_SOURCE_CENSUS_READ;
        int bytes = proc_listpids(PROC_UID_ONLY, (uint32_t)expectedUID, pids, (int)(pidCapacity * sizeof(*pids)));
        if (bytes <= 0 || bytes % (int)sizeof(pid_t)) { error = errno ?: EIO; goto failed; }
        if ((size_t)bytes >= pidCapacity * sizeof(*pids)) {
            if (monotonic() >= deadline) { last.source = HENGE_AUTH_PROCESS_SOURCE_CENSUS_DEADLINE; error = ETIMEDOUT; goto failed; }
            continue; // A full buffer may be truncated, never a complete absence.
        }
        for (size_t i = 0; i < (size_t)bytes / sizeof(*pids); i++) {
            if (monotonic() >= deadline) { last.source = HENGE_AUTH_PROCESS_SOURCE_CENSUS_DEADLINE; error = ETIMEDOUT; goto failed; }
            if (pids[i] <= 0) continue;
            readSample(pids[i], expectedUID, expectedCanonicalExe, NULL, &last);
            if (last.kind == HENGE_AUTH_PROCESS_SAMPLE_ABSENT) continue;
            if (last.kind != HENGE_AUTH_PROCESS_SAMPLE_PRESENT) { error = last.error_number ?: EAGAIN; goto failed; }
            if (last.identity.uid != expectedUID || last.identity.real_uid != expectedUID) continue;
            if (last.zombie) continue;
            if (!validPath(last.identity.executable_path)) { error = EIO; goto failed; }
            if (strcmp(last.identity.executable_path, expectedCanonicalExe)) continue;
            int duplicate = 0;
            for (size_t j = 0; j < matches; j++) if (sameLifetime(&outIdentities[j], &last.identity)) duplicate = 1;
            if (duplicate) continue;
            if (matches >= capacity) { last.source = HENGE_AUTH_PROCESS_SOURCE_CENSUS_CAPACITY; error = EOVERFLOW; goto failed; }
            outIdentities[matches++] = last.identity;
        }
        free(pids);
        *count = matches;
        return observedAt(matches ? HENGE_AUTH_PROCESS_ALIVE : HENGE_AUTH_PROCESS_EXITED, 0,
            HENGE_AUTH_PROCESS_SOURCE_CENSUS_READ, observation);
    }
    last.source = HENGE_AUTH_PROCESS_SOURCE_CENSUS_CAPACITY;
    error = EOVERFLOW;
failed:
    free(pids);
    memset(outIdentities, 0, capacity * sizeof(*outIdentities));
    return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, &last, error, observation);
}
#else
/* Linux executes only the pure comparison tests. It must not emulate Darwin
 * process evidence or permit a caller to act on an unverified process. */
HengeAuthProcessState HengeAuthProcessCapture(pid_t pid, const char *path, uid_t uid,
    HengeAuthProcessIdentity *identity, HengeAuthProcessObservation *observation) {
    (void)pid; (void)path; (void)uid;
    if (identity) memset(identity, 0, sizeof(*identity));
    return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, NULL, ENOTSUP, observation);
}
HengeAuthProcessState HengeAuthProcessCheck(const HengeAuthProcessIdentity *identity,
    HengeAuthProcessObservation *observation) {
    (void)identity;
    return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, NULL, ENOTSUP, observation);
}
HengeAuthProcessState HengeAuthProcessListMatching(const char *path, uid_t uid,
    HengeAuthProcessIdentity *identities, size_t capacity, size_t *count,
    HengeAuthProcessObservation *observation) {
    (void)path; (void)uid; (void)identities; (void)capacity;
    if (count) *count = 0;
    return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, NULL, ENOTSUP, observation);
}
#endif
