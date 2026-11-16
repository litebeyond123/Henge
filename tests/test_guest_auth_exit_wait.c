/* Deterministic tests of the exact private flow called by the real launcher.
 * No process is signalled and no production kernel-reader override is added. */
#include "guest-auth-exit-wait.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned assertions;
static void require(int value, const char *label) {
    assertions++;
    if (!value) { fprintf(stderr, "FAIL: %s\n", label); exit(1); }
}
typedef struct {
    HengeAuthProcessIdentity identity;
    double time, transient_until, revoke_at;
    int force, sent, after_kind, after_errno, pre_unknown_check;
    unsigned checks, before_checks, invocations, normal_calls, force_calls, authorizations;
    unsigned intent, returned, pending, notice_errors;
} Fixture;
static double fixtureNow(void *context) { return ((Fixture *)context)->time; }
static HengeAuthProcessState fixtureCheck(void *context, HengeAuthProcessObservation *observation) {
    Fixture *fixture = context;
    fixture->checks++;
    fixture->time += 0.002;
    HengeAuthProcessSample sample = {.kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT,
        .identity = fixture->identity, .process_status = 2, .source = HENGE_AUTH_PROCESS_SOURCE_BSD_AFTER};
    int transient = 0;
    if (!fixture->invocations) {
        fixture->before_checks++;
        transient = fixture->pre_unknown_check && fixture->before_checks >= (unsigned)fixture->pre_unknown_check;
    } else if (fixture->time < fixture->transient_until) transient = 1;
    else switch (fixture->after_kind) {
        case 1: sample.kind = HENGE_AUTH_PROCESS_SAMPLE_ABSENT; sample.source = HENGE_AUTH_PROCESS_SOURCE_BSD_BEFORE; break;
        case 2: sample.zombie = 1; sample.process_status = 5; sample.identity.executable_path[0] = 0; break;
        case 3: sample.identity.start_microseconds++; sample.source = HENGE_AUTH_PROCESS_SOURCE_IDENTITY_CHANGE; break;
        case 4: transient = 1; break;
        default: break;
    }
    if (transient) {
        sample.kind = HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE;
        sample.identity.executable_path[0] = 0;
        sample.error_number = fixture->after_errno ?: ESRCH;
        sample.source = HENGE_AUTH_PROCESS_SOURCE_PIDPATH;
        sample.path_only_esrch = sample.error_number == ESRCH;
        sample.retry_count = sample.path_only_esrch ? 25 : 0;
        sample.sample_elapsed_ms = sample.path_only_esrch ? 250 : 2;
    }
    return HengeAuthProcessCompare(&fixture->identity, &sample, observation);
}
static int fixtureAuthorize(void *context, double remaining) {
    Fixture *fixture = context;
    fixture->authorizations++;
    require(remaining > 0 && remaining <= 30, "authorization keeps the existing remaining budget");
    return fixture->revoke_at < 0 || fixture->time < fixture->revoke_at;
}
static int fixtureInvoke(void *context) {
    Fixture *fixture = context;
    fixture->invocations++;
    if (fixture->force) fixture->force_calls++; else fixture->normal_calls++;
    return fixture->sent;
}
static void fixturePump(void *context, double seconds) {
    Fixture *fixture = context;
    if (!(seconds > 0 && seconds <= 0.05)) fixture->notice_errors++;
    fixture->time += seconds;
}
static void fixtureNotice(void *context, HengeAuthQuitNotice notice, const HengeAuthQuitProgress *progress) {
    Fixture *fixture = context;
    if (notice == HENGE_AUTH_QUIT_INTENT) {
        fixture->intent++;
        if (progress->operation_invoked || progress->operation_result != -1) fixture->notice_errors++;
    } else if (notice == HENGE_AUTH_QUIT_RETURNED) {
        fixture->returned++;
        if (!progress->operation_invoked || progress->operation_result != fixture->sent) fixture->notice_errors++;
    } else {
        fixture->pending++;
        if (!progress->operation_invoked || !HengeAuthProcessCanWaitForExit(&fixture->identity, &progress->observation))
            fixture->notice_errors++;
    }
}
static const HengeAuthQuitCallbacks callbacks = {
    fixtureNow, fixtureCheck, fixtureAuthorize, fixtureInvoke, fixturePump, fixtureNotice
};
static Fixture makeFixture(void) {
    return (Fixture){.identity = {.pid = 123, .uid = 501, .real_uid = 501,
        .start_seconds = 100, .start_microseconds = 42,
        .executable_path = "/Applications/OwnedFixture.app/Contents/MacOS/OwnedFixture"},
        .transient_until = 0.8, .revoke_at = -1, .sent = 1, .after_kind = 1};
}
static HengeAuthQuitOutcome run(Fixture *fixture, double deadline, HengeAuthQuitProgress *progress) {
    HengeAuthProcessSample alive = {.kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT,
        .identity = fixture->identity, .process_status = 2, .source = HENGE_AUTH_PROCESS_SOURCE_BSD_AFTER};
    memset(progress, 0, sizeof(*progress));
    progress->state = HengeAuthProcessCompare(&fixture->identity, &alive, &progress->observation);
    HengeAuthQuitOutcome result = HengeAuthQuitOriginalAndWait(&fixture->identity, deadline, fixture, &callbacks, progress);
    require(fixture->invocations <= 1 && !fixture->notice_errors, "one OS operation and truthful fixed intent/return/pending notices");
    require(fixture->force ? fixture->normal_calls == 0 : fixture->force_calls == 0,
        "normal never escalates and force never invokes a different operation");
    return result;
}
int main(void) {
    Fixture fixture = makeFixture(); HengeAuthQuitProgress progress;
    require(run(&fixture, 30, &progress) == HENGE_AUTH_QUIT_EXITED && fixture.time >= 0.8 && fixture.time < 1 &&
        fixture.invocations == 1 && fixture.pending == 1 && fixture.returned == 1 &&
        progress.observation.source == HENGE_AUTH_PROCESS_SOURCE_BSD_BEFORE,
        "normal path-only ESRCH lasting over 250ms waits for positive BSD absence");
    fixture = makeFixture(); fixture.force = 1; fixture.after_kind = 2;
    require(run(&fixture, 10, &progress) == HENGE_AUTH_QUIT_EXITED && fixture.time >= 0.8 &&
        fixture.invocations == 1 && fixture.pending == 1 && progress.observation.zombie,
        "force path-only ESRCH waits for the original zombie without a second kill");
    for (int force = 0; force <= 1; force++) {
        fixture = makeFixture(); fixture.force = force; fixture.after_kind = 4;
        double deadline = force ? 10 : 30;
        require(run(&fixture, deadline, &progress) == HENGE_AUTH_QUIT_UNKNOWN &&
            progress.state == HENGE_AUTH_PROCESS_UNAVAILABLE && progress.observation.error_number == ESRCH &&
            fixture.time >= deadline && fixture.time < deadline + 0.01 && fixture.invocations == 1 && fixture.pending == 1,
            "persistent path-only ESRCH remains unknown at the unchanged 10/30s deadline");
    }
    fixture = makeFixture(); fixture.after_errno = EACCES;
    require(run(&fixture, 30, &progress) == HENGE_AUTH_QUIT_UNKNOWN && fixture.time < 0.02 && fixture.pending == 0 &&
        fixture.invocations == 1 && progress.observation.error_number == EACCES,
        "an unrelated access failure stops immediately after the single operation");
    fixture = makeFixture(); fixture.after_kind = 3;
    require(run(&fixture, 30, &progress) == HENGE_AUTH_QUIT_CHANGED && fixture.time >= 0.8 && fixture.time < 1 &&
        fixture.invocations == 1 && !progress.observation.same_lifetime,
        "new PID lifetime stops waiting and cannot be signalled");
    fixture = makeFixture(); fixture.revoke_at = 0.4; fixture.transient_until = 2;
    require(run(&fixture, 30, &progress) == HENGE_AUTH_QUIT_CANCELLED && fixture.time < 0.7 && fixture.invocations == 1,
        "authorization revocation stops a transient wait without another operation");
    fixture = makeFixture(); fixture.revoke_at = 0;
    require(run(&fixture, 30, &progress) == HENGE_AUTH_QUIT_CANCELLED && fixture.invocations == 0,
        "authorization must remain current before the operation");
    fixture = makeFixture(); fixture.pre_unknown_check = 2;
    require(run(&fixture, 30, &progress) == HENGE_AUTH_QUIT_UNKNOWN && fixture.intent == 1 &&
        fixture.invocations == 0 && fixture.returned == 0 && fixture.pending == 0 &&
        !progress.operation_invoked && progress.operation_result == -1,
        "pre-operation requested marker plus ESRCH does not become dispatched or eligible for waiting");
    fixture = makeFixture(); fixture.sent = 0; fixture.transient_until = 0; fixture.after_kind = 0;
    require(run(&fixture, 30, &progress) == HENGE_AUTH_QUIT_REFUSED && fixture.invocations == 1 &&
        fixture.time < 0.02 && progress.operation_invoked && !progress.operation_result,
        "AppKit false with verified live process is a refusal without retry");
    fixture = makeFixture(); fixture.sent = 0;
    require(run(&fixture, 30, &progress) == HENGE_AUTH_QUIT_EXITED && fixture.time >= 0.8 && fixture.invocations == 1,
        "AppKit false alone cannot hide a later positively confirmed original exit");
    fixture = makeFixture(); fixture.transient_until = 0; fixture.after_kind = 0;
    require(run(&fixture, 10, &progress) == HENGE_AUTH_QUIT_DEADLINE && progress.state == HENGE_AUTH_PROCESS_ALIVE &&
        fixture.time >= 10 && fixture.invocations == 1 && fixture.pending == 0,
        "verified still-live process times out without spawning or escalation");
    printf("PASS: 12 production quit-flow scenarios, %u assertions\n", assertions);
    return 0;
}
