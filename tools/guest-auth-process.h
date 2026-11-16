#ifndef HENGE_GUEST_AUTH_PROCESS_H
#define HENGE_GUEST_AUTH_PROCESS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HENGE_AUTH_PROCESS_PATH_CAPACITY 4096u

typedef enum {
    HENGE_AUTH_PROCESS_ALIVE = 1,
    HENGE_AUTH_PROCESS_EXITED,
    HENGE_AUTH_PROCESS_REPLACED,
    HENGE_AUTH_PROCESS_UNAVAILABLE
} HengeAuthProcessState;

/* Fixed diagnostic labels, not syscall errno values. No path is serialized. */
typedef enum {
    HENGE_AUTH_PROCESS_SOURCE_NONE = 0,
    HENGE_AUTH_PROCESS_SOURCE_ARGUMENTS,
    HENGE_AUTH_PROCESS_SOURCE_EXPECTED_REALPATH,
    HENGE_AUTH_PROCESS_SOURCE_BSD_BEFORE,
    HENGE_AUTH_PROCESS_SOURCE_PIDPATH,
    HENGE_AUTH_PROCESS_SOURCE_PATH_REALPATH,
    HENGE_AUTH_PROCESS_SOURCE_BSD_AFTER,
    HENGE_AUTH_PROCESS_SOURCE_CENSUS_SIZE,
    HENGE_AUTH_PROCESS_SOURCE_CENSUS_READ,
    HENGE_AUTH_PROCESS_SOURCE_CENSUS_CAPACITY,
    HENGE_AUTH_PROCESS_SOURCE_CENSUS_DEADLINE,
    HENGE_AUTH_PROCESS_SOURCE_IDENTITY_CHANGE,
    HENGE_AUTH_PROCESS_SOURCE_APPKIT_LOOKUP
} HengeAuthProcessSource;

/* This path is used only for comparison. Never serialize it to diagnostics. */
typedef struct {
    pid_t pid;
    uid_t uid, real_uid;
    uint64_t start_seconds, start_microseconds;
    char executable_path[HENGE_AUTH_PROCESS_PATH_CAPACITY];
} HengeAuthProcessIdentity;

/* Fixed numeric observations only; errno is not an app/Apple error code. */
typedef struct {
    HengeAuthProcessState state;
    int error_number;
    pid_t observed_pid;
    uid_t observed_uid, observed_real_uid;
    uint64_t observed_start_seconds, observed_start_microseconds;
    uint32_t observed_status;
    int identity_available, zombie;
    HengeAuthProcessSource source;
    int same_lifetime, path_only_esrch;
    unsigned retry_count, sample_elapsed_ms;
} HengeAuthProcessObservation;

/* One path representation for the kernel reader and AppKit callers. Returns 0
 * and an absolute POSIX realpath on success, or errno with an empty output.
 * The caller supplies HENGE_AUTH_PROCESS_PATH_CAPACITY bytes. No path is logged.
 * This resolves filesystem aliases; it does not validate an app's identity. */
int HengeAuthProcessCanonicalizePath(const char *absolutePath,
    char output[HENGE_AUTH_PROCESS_PATH_CAPACITY]);

/* The caller first validates the original app's complete signature and exact
 * executable path. Absolute aliases are canonicalized before exact comparison;
 * only ALIVE fills outIdentity, always with its canonical executable path.
 * Unknown never means absent. */
HengeAuthProcessState HengeAuthProcessCapture(pid_t pid, const char *expectedExecutablePath,
    uid_t expectedUID, HengeAuthProcessIdentity *outIdentity, HengeAuthProcessObservation *observation);
HengeAuthProcessState HengeAuthProcessCheck(const HengeAuthProcessIdentity *identity,
    HengeAuthProcessObservation *observation);
/* Only this exact unknown observation may be waited on AFTER one requested
 * operation. It never means exited, never authorizes a signal, and never
 * changes the caller's existing deadline. Other unknowns fail closed. */
int HengeAuthProcessCanWaitForExit(const HengeAuthProcessIdentity *identity,
    const HengeAuthProcessObservation *observation);

/* A bounded kernel census of the current UID, not an AppKit cache. ALIVE means
 * count > 0; EXITED means a complete scan found no matching live instance.
 * UNAVAILABLE (including truncation) must never authorize a new launch.
 * Results are a snapshot, not a process handle: recheck immediately before
 * requesting termination of the original NSRunningApplication. This module
 * never sends a signal and never chooses a replacement instance to terminate. */
HengeAuthProcessState HengeAuthProcessListMatching(const char *expectedExecutablePath,
    uid_t expectedUID, HengeAuthProcessIdentity *outIdentities, size_t capacity,
    size_t *count, HengeAuthProcessObservation *observation);

/* Deterministic comparison seam. No test hooks or PID/path overrides are
 * compiled into the kernel reader. A sample may represent an absent process,
 * an unavailable read, a zombie, or a complete live identity. */
typedef enum {
    HENGE_AUTH_PROCESS_SAMPLE_PRESENT = 1,
    HENGE_AUTH_PROCESS_SAMPLE_ABSENT,
    HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE,
    HENGE_AUTH_PROCESS_SAMPLE_CHANGED_DURING_READ
} HengeAuthProcessSampleKind;
typedef struct {
    HengeAuthProcessSampleKind kind;
    HengeAuthProcessIdentity identity;
    uint32_t process_status;
    int zombie, error_number;
    HengeAuthProcessSource source;
    int path_only_esrch;
    unsigned retry_count, sample_elapsed_ms;
} HengeAuthProcessSample;
HengeAuthProcessState HengeAuthProcessCompare(const HengeAuthProcessIdentity *expected,
    const HengeAuthProcessSample *sample, HengeAuthProcessObservation *observation);

#ifdef __cplusplus
}
#endif
#endif
