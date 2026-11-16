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
        if (sample && validNumbers(&sample->identity)) {
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

HengeAuthProcessState HengeAuthProcessCompare(const HengeAuthProcessIdentity *expected,
    const HengeAuthProcessSample *sample, HengeAuthProcessObservation *observation) {
    if (!validNumbers(expected) || !validPath(expected->executable_path) || !sample)
        return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, NULL, EINVAL, observation);
    if (sample->kind == HENGE_AUTH_PROCESS_SAMPLE_ABSENT)
        return observed(HENGE_AUTH_PROCESS_EXITED, NULL, 0, observation);
    if (sample->kind == HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE)
        return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, sample, sample->error_number ?: EIO, observation);
    if (sample->kind != HENGE_AUTH_PROCESS_SAMPLE_PRESENT &&
        sample->kind != HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ)
        return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, sample, EINVAL, observation);
    if (!validNumbers(&sample->identity))
        return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, sample, EIO, observation);
    if (sample->kind == HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ ||
        !sameLifetime(expected, &sample->identity))
        return observed(HENGE_AUTH_PROCESS_REPLACED, sample, 0, observation);
    if (sample->zombie)
        return observed(HENGE_AUTH_PROCESS_EXITED, sample, 0, observation);
    if (!validPath(sample->identity.executable_path))
        return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, sample, EIO, observation);
    if (strcmp(expected->executable_path, sample->identity.executable_path))
        return observed(HENGE_AUTH_PROCESS_REPLACED, sample, 0, observation);
    return observed(HENGE_AUTH_PROCESS_ALIVE, sample, 0, observation);
}

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

static void readSample(pid_t pid, uid_t expectedUID, const char *candidatePath,
    HengeAuthProcessSample *sample) {
    memset(sample, 0, sizeof(*sample));
    sample->kind = HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE;
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
    char *canonical = NULL;
    if (pathValid) {
        /* proc_pidpath gets the path from the executable text vnode, not argv
         * or a process name. A known different path in a census is enough to
         * exclude that instance: do not require an unrelated temporary file
         * still to exist. Only a candidate is canonicalized and retained.
         * If the kernel cannot return any path, absence remains unproven. */
        if (candidatePath && strcmp(path, candidatePath)) {
            memcpy(sample->identity.executable_path, path, (size_t)length + 1);
        } else {
            errno = 0;
            canonical = realpath(path, NULL);
            pathError = errno;
        }
    }
    error = readBSD(pid, &after);
    if (error) {
        free(canonical);
        sample->kind = error == ESRCH ? HENGE_AUTH_PROCESS_SAMPLE_ABSENT : HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE;
        sample->error_number = error;
        return;
    }
    HengeAuthProcessIdentity original = sample->identity;
    copyBSD(&after, sample);
    if (!sameLifetime(&original, &sample->identity)) {
        free(canonical);
        sample->kind = HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ;
        return;
    }
    if (sample->zombie) { free(canonical); sample->kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT; return; }
    if (!pathValid) {
        sample->error_number = pathError ?: EIO;
        return; // A path failure alone does not prove that the process exited.
    }
    if (candidatePath && strcmp(path, candidatePath)) {
        sample->kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT;
        return;
    }
    if (!canonical) { sample->error_number = pathError ?: EIO; return; }
    size_t canonicalLength = strlen(canonical);
    if (canonicalLength >= sizeof(sample->identity.executable_path)) {
        free(canonical); sample->error_number = ENAMETOOLONG; return;
    }
    memcpy(sample->identity.executable_path, canonical, canonicalLength + 1);
    free(canonical);
    sample->kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT;
}

static int canonicalExpected(const char *path, uid_t uid) {
    if (!validPath(path) || uid != geteuid() || getuid() != geteuid()) return EINVAL;
    char *canonical = realpath(path, NULL);
    if (!canonical) return errno ?: EIO;
    int error = strcmp(canonical, path) ? EINVAL : 0;
    free(canonical);
    return error;
}

HengeAuthProcessState HengeAuthProcessCapture(pid_t pid, const char *expectedCanonicalExe,
    uid_t expectedUID, HengeAuthProcessIdentity *outIdentity, HengeAuthProcessObservation *observation) {
    if (outIdentity) memset(outIdentity, 0, sizeof(*outIdentity));
    int error = pid > 0 && outIdentity ? canonicalExpected(expectedCanonicalExe, expectedUID) : EINVAL;
    if (error) return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, NULL, error, observation);
    HengeAuthProcessSample sample;
    readSample(pid, expectedUID, NULL, &sample);
    if (sample.kind == HENGE_AUTH_PROCESS_SAMPLE_ABSENT)
        return observed(HENGE_AUTH_PROCESS_EXITED, NULL, 0, observation);
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
        return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, NULL, EINVAL, observation);
    HengeAuthProcessSample sample;
    readSample(identity->pid, identity->uid, NULL, &sample);
    return HengeAuthProcessCompare(identity, &sample, observation);
}

static double monotonic(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time)) return -1;
    return (double)time.tv_sec + time.tv_nsec / 1e9;
}

HengeAuthProcessState HengeAuthProcessListMatching(const char *expectedCanonicalExe,
    uid_t expectedUID, HengeAuthProcessIdentity *outIdentities, size_t capacity,
    size_t *count, HengeAuthProcessObservation *observation) {
    if (count) *count = 0;
    int error = outIdentities && count && capacity && capacity <= 64 ? canonicalExpected(expectedCanonicalExe, expectedUID) : EINVAL;
    if (error) return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, NULL, error, observation);
    memset(outIdentities, 0, capacity * sizeof(*outIdentities));
    enum { MaxPIDs = 8192, MinimumPIDs = 128, CensusAttempts = 3 };
    double start = monotonic();
    if (start < 0) return observed(HENGE_AUTH_PROCESS_UNAVAILABLE, NULL, EIO, observation);
    const double deadline = start + 5;
    size_t matches = 0;
    pid_t *pids = NULL;
    HengeAuthProcessSample last = {0};
    for (unsigned attempt = 0; attempt < CensusAttempts; attempt++) {
        errno = 0;
        int needed = proc_listpids(PROC_UID_ONLY, (uint32_t)expectedUID, NULL, 0);
        if (needed <= 0 || needed % (int)sizeof(pid_t)) { error = errno ?: EIO; goto failed; }
        size_t pidCapacity = (size_t)needed / sizeof(pid_t) + 64u * (attempt + 1);
        if (pidCapacity < MinimumPIDs) pidCapacity = MinimumPIDs;
        if (pidCapacity > MaxPIDs) { error = EOVERFLOW; goto failed; }
        free(pids);
        pids = calloc(pidCapacity, sizeof(*pids));
        if (!pids) { error = ENOMEM; goto failed; }
        errno = 0;
        int bytes = proc_listpids(PROC_UID_ONLY, (uint32_t)expectedUID, pids, (int)(pidCapacity * sizeof(*pids)));
        if (bytes <= 0 || bytes % (int)sizeof(pid_t)) { error = errno ?: EIO; goto failed; }
        if ((size_t)bytes >= pidCapacity * sizeof(*pids)) {
            if (monotonic() >= deadline) { error = ETIMEDOUT; goto failed; }
            continue; // A full buffer may be truncated, never a complete absence.
        }
        for (size_t i = 0; i < (size_t)bytes / sizeof(*pids); i++) {
            if (monotonic() >= deadline) { error = ETIMEDOUT; goto failed; }
            if (pids[i] <= 0) continue;
            readSample(pids[i], expectedUID, expectedCanonicalExe, &last);
            if (last.kind == HENGE_AUTH_PROCESS_SAMPLE_ABSENT) continue;
            if (last.kind != HENGE_AUTH_PROCESS_SAMPLE_PRESENT) { error = last.error_number ?: EAGAIN; goto failed; }
            if (last.identity.uid != expectedUID || last.identity.real_uid != expectedUID) continue;
            if (last.zombie) continue;
            if (!validPath(last.identity.executable_path)) { error = EIO; goto failed; }
            if (strcmp(last.identity.executable_path, expectedCanonicalExe)) continue;
            int duplicate = 0;
            for (size_t j = 0; j < matches; j++) if (sameLifetime(&outIdentities[j], &last.identity)) duplicate = 1;
            if (duplicate) continue;
            if (matches >= capacity) { error = EOVERFLOW; goto failed; }
            outIdentities[matches++] = last.identity;
        }
        free(pids);
        *count = matches;
        return observed(matches ? HENGE_AUTH_PROCESS_ALIVE : HENGE_AUTH_PROCESS_EXITED, NULL, 0, observation);
    }
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
