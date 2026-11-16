/* Include the production implementation only in this separate test binary so
 * its private sampling loop can consume deterministic observations. There is
 * no new public production interface, global override, or fake kernel reader. */
#define HENGE_AUTH_PROCESS_RESAMPLE_TESTING 1
#include "../tools/guest-auth-process.m"
#include <stdio.h>

static unsigned checks;
static void require(int value, const char *label) {
    checks++;
    if (!value) { fprintf(stderr, "FAIL: %s\n", label); exit(1); }
}
typedef struct {
    HengeAuthProcessSample samples[3];
    size_t count, reads;
} Sequence;
static void nextSample(void *context, HengeAuthProcessSample *sample) {
    Sequence *sequence = context;
    size_t index = sequence->reads < sequence->count ? sequence->reads : sequence->count - 1;
    *sample = sequence->samples[index];
    sequence->reads++;
}
static HengeAuthProcessState settle(Sequence *sequence, const HengeAuthProcessIdentity *identity,
    HengeAuthProcessObservation *observation) {
    HengeAuthProcessSample sample;
    readSettledSample(nextSample, sequence, identity, &sample);
    return HengeAuthProcessCompare(identity, &sample, observation);
}
int main(void) {
    HengeAuthProcessIdentity original = {
        .pid = 123, .uid = 501, .real_uid = 501,
        .start_seconds = 100, .start_microseconds = 42,
        .executable_path = "/Applications/OwnedFixture.app/Contents/MacOS/OwnedFixture"
    };
    HengeAuthProcessSample transient = {
        .kind = HENGE_AUTH_PROCESS_SAMPLE_UNAVAILABLE, .identity = original,
        .error_number = ESRCH, .process_status = 2,
        .source = HENGE_AUTH_PROCESS_SOURCE_PIDPATH, .path_only_esrch = 1
    };
    transient.identity.executable_path[0] = '\0';
    HengeAuthProcessSample alive = {.kind = HENGE_AUTH_PROCESS_SAMPLE_PRESENT, .identity = original, .process_status = 2};
    HengeAuthProcessSample absent = {.kind = HENGE_AUTH_PROCESS_SAMPLE_ABSENT, .error_number = ESRCH};
    HengeAuthProcessSample zombie = alive;
    zombie.zombie = 1; zombie.process_status = 5; zombie.identity.executable_path[0] = '\0';
    HengeAuthProcessObservation observation;
    require(HengeAuthProcessCompare(&original, &transient, &observation) == HENGE_AUTH_PROCESS_UNAVAILABLE,
        "path-only ESRCH alone remains unknown");
    require(HengeAuthProcessCanWaitForExit(&original, &observation),
        "only complete same-lifetime pidpath ESRCH is eligible for post-action waiting");
    Sequence sequence = {.samples = {transient, absent}, .count = 2};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_EXITED && sequence.reads == 2,
        "later confirmed BSD absence resolves path race");
    sequence = (Sequence){.samples = {transient, zombie}, .count = 2};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_EXITED && sequence.reads == 2 && observation.zombie,
        "later original zombie resolves path race");
    sequence = (Sequence){.samples = {transient, alive}, .count = 2};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_ALIVE && sequence.reads == 2,
        "recovering live path does not invent an exit");
    sequence = (Sequence){.samples = {transient}, .count = 1};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_UNAVAILABLE && observation.error_number == ESRCH,
        "persistent path ESRCH remains unknown");
    require(sequence.reads > 1 && sequence.reads <= 26, "persistent retry count bounded");
    require(observation.source == HENGE_AUTH_PROCESS_SOURCE_PIDPATH &&
        observation.retry_count == sequence.reads - 1 && observation.sample_elapsed_ms >= 100 &&
        HengeAuthProcessCanWaitForExit(&original, &observation), "retained unknown has precise source and retry evidence");
    HengeAuthProcessSample denied = transient; denied.error_number = EACCES;
    sequence = (Sequence){.samples = {denied, absent}, .count = 2};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_UNAVAILABLE && sequence.reads == 1 && observation.error_number == EACCES,
        "access denied is not retried into false absence");
    require(!HengeAuthProcessCanWaitForExit(&original, &observation), "access denied cannot enter extended exit wait");
    HengeAuthProcessSample wrongSource = transient; wrongSource.source = HENGE_AUTH_PROCESS_SOURCE_PATH_REALPATH;
    sequence = (Sequence){.samples = {wrongSource, absent}, .count = 2};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_UNAVAILABLE && sequence.reads == 1 &&
        !HengeAuthProcessCanWaitForExit(&original, &observation), "realpath ESRCH is not mistaken for executable-vnode exit race");
    HengeAuthProcessSample noIdentity = transient; noIdentity.identity.start_seconds = 0;
    sequence = (Sequence){.samples = {noIdentity, absent}, .count = 2};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_UNAVAILABLE && sequence.reads == 1,
        "ESRCH without a verified lifetime remains unknown");
    HengeAuthProcessSample replaced = transient; replaced.identity.start_microseconds++;
    sequence = (Sequence){.samples = {replaced, absent}, .count = 2};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_REPLACED && sequence.reads == 1,
        "replacement on first read cannot be hidden by its later exit");
    require(observation.source == HENGE_AUTH_PROCESS_SOURCE_IDENTITY_CHANGE && !observation.same_lifetime &&
        !HengeAuthProcessCanWaitForExit(&original, &observation), "replacement clears exit-race eligibility");
    sequence = (Sequence){.samples = {transient, replaced, absent}, .count = 3};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_REPLACED && sequence.reads == 2,
        "PID reuse cannot be retried away into exit");
    replaced = transient; replaced.identity.uid++;
    sequence = (Sequence){.samples = {transient, replaced, absent}, .count = 3};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_REPLACED && sequence.reads == 2,
        "credential change stops resampling");
    replaced = alive; strcpy(replaced.identity.executable_path, "/different/executable");
    sequence = (Sequence){.samples = {transient, replaced, absent}, .count = 3};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_REPLACED && sequence.reads == 2,
        "different executable stops at replacement");
    sequence = (Sequence){.samples = {transient, denied, absent}, .count = 3};
    require(settle(&sequence, &original, &observation) == HENGE_AUTH_PROCESS_UNAVAILABLE && sequence.reads == 2 && observation.error_number == EACCES,
        "new unknown error remains failure");
    printf("PASS: %u deterministic process-exit resampling checks\n", checks);
    return 0;
}
