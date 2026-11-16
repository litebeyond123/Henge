#ifndef HENGE_GUEST_AUTH_EXIT_WAIT_H
#define HENGE_GUEST_AUTH_EXIT_WAIT_H

#include "guest-auth-process.h"
#include <string.h>

/* Private launcher flow, shared verbatim with deterministic tests. These
 * callbacks are supplied by Run, never selected by an environment variable or
 * a wire request. The kernel reader has no override. */
typedef enum {
    HENGE_AUTH_PHASE_NONE = 0, HENGE_AUTH_PHASE_PREFLIGHT,
    HENGE_AUTH_PHASE_BEFORE_ACTION, HENGE_AUTH_PHASE_AFTER_ACTION,
    HENGE_AUTH_PHASE_WAIT, HENGE_AUTH_PHASE_POST_EXIT_SIGNATURE,
    HENGE_AUTH_PHASE_POST_EXIT_CENSUS
} HengeAuthProcessPhase;
typedef enum {
    HENGE_AUTH_QUIT_INTENT, HENGE_AUTH_QUIT_RETURNED, HENGE_AUTH_EXIT_PENDING
} HengeAuthQuitNotice;
typedef enum {
    HENGE_AUTH_QUIT_EXITED, HENGE_AUTH_QUIT_REFUSED, HENGE_AUTH_QUIT_DEADLINE,
    HENGE_AUTH_QUIT_UNKNOWN, HENGE_AUTH_QUIT_CHANGED, HENGE_AUTH_QUIT_CANCELLED
} HengeAuthQuitOutcome;
typedef struct {
    HengeAuthProcessObservation observation;
    HengeAuthProcessState state;
    HengeAuthProcessPhase phase;
    double phase_started;
    int operation_invoked, operation_result;
} HengeAuthQuitProgress;
typedef struct {
    double (*now)(void *);
    HengeAuthProcessState (*check)(void *, HengeAuthProcessObservation *);
    int (*authorize)(void *, double remaining);
    int (*invoke)(void *);
    void (*pump)(void *, double seconds);
    void (*notify)(void *, HengeAuthQuitNotice, const HengeAuthQuitProgress *);
} HengeAuthQuitCallbacks;

static HengeAuthQuitOutcome HengeAuthQuitOriginalAndWait(
    const HengeAuthProcessIdentity *identity, double deadline, void *context,
    const HengeAuthQuitCallbacks *callbacks, HengeAuthQuitProgress *progress) {
    progress->operation_invoked = 0;
    progress->operation_result = -1;
    progress->phase = HENGE_AUTH_PHASE_BEFORE_ACTION;
    progress->phase_started = callbacks->now(context);
    if (progress->state == HENGE_AUTH_PROCESS_ALIVE) {
        double remaining = deadline - callbacks->now(context);
        if (remaining <= 0) return HENGE_AUTH_QUIT_DEADLINE;
        if (!callbacks->authorize(context, remaining)) return HENGE_AUTH_QUIT_CANCELLED;
        progress->state = callbacks->check(context, &progress->observation);
        if (progress->state == HENGE_AUTH_PROCESS_ALIVE) {
            callbacks->notify(context, HENGE_AUTH_QUIT_INTENT, progress);
            // The intent journal can do I/O. Check the original lifetime again
            // after it, immediately before this flow's only OS operation.
            progress->state = callbacks->check(context, &progress->observation);
            if (progress->state == HENGE_AUTH_PROCESS_ALIVE) {
                if (callbacks->now(context) >= deadline) return HENGE_AUTH_QUIT_DEADLINE;
                progress->operation_invoked = 1;
                progress->phase = HENGE_AUTH_PHASE_AFTER_ACTION;
                progress->phase_started = callbacks->now(context);
                progress->operation_result = !!callbacks->invoke(context);
                progress->state = callbacks->check(context, &progress->observation);
                callbacks->notify(context, HENGE_AUTH_QUIT_RETURNED, progress);
                if (!progress->operation_result && progress->state == HENGE_AUTH_PROCESS_ALIVE)
                    return HENGE_AUTH_QUIT_REFUSED;
            }
        }
    }
    double nextAuthorizationCheck = 0;
    int pendingNotified = 0;
    while (progress->state == HENGE_AUTH_PROCESS_ALIVE ||
        (progress->operation_invoked && HengeAuthProcessCanWaitForExit(identity, &progress->observation))) {
        double now = callbacks->now(context);
        if (now >= deadline) break;
        if (progress->phase != HENGE_AUTH_PHASE_WAIT) {
            progress->phase = HENGE_AUTH_PHASE_WAIT;
            progress->phase_started = now;
        }
        if (progress->state == HENGE_AUTH_PROCESS_UNAVAILABLE && !pendingNotified) {
            pendingNotified = 1;
            callbacks->notify(context, HENGE_AUTH_EXIT_PENDING, progress);
        }
        now = callbacks->now(context);
        if (now >= deadline) break;
        if (now >= nextAuthorizationCheck) {
            if (!callbacks->authorize(context, deadline - now)) return HENGE_AUTH_QUIT_CANCELLED;
            nextAuthorizationCheck = callbacks->now(context) + 0.5;
        }
        double remaining = deadline - callbacks->now(context);
        if (remaining <= 0) break;
        callbacks->pump(context, remaining < 0.05 ? remaining : 0.05);
        progress->state = callbacks->check(context, &progress->observation);
    }
    if (progress->state == HENGE_AUTH_PROCESS_EXITED) return HENGE_AUTH_QUIT_EXITED;
    if (progress->state == HENGE_AUTH_PROCESS_REPLACED) return HENGE_AUTH_QUIT_CHANGED;
    if (progress->state == HENGE_AUTH_PROCESS_UNAVAILABLE) return HENGE_AUTH_QUIT_UNKNOWN;
    return HENGE_AUTH_QUIT_DEADLINE;
}
#endif
