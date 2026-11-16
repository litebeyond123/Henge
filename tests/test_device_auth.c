#define _POSIX_C_SOURCE 200809L
#include "../host/device_auth.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* This exercises the production transport/state machine. There are no Apple frameworks, device
   identifiers, genuine challenges or tokens in this test. Only the asynchronous backend is synthetic. */
static const char SESSION[] = "01234567-89AB-CDEF-0123-456789ABCDEF";
static const char SESSION_TWO[] = "11234567-89AB-CDEF-0123-456789ABCDEF";
static const char LAUNCH[] = "22234567-89AB-CDEF-0123-456789ABCDEF";
static const char LAUNCH_TWO[] = "33234567-89AB-CDEF-0123-456789ABCDEF";
static const char REQUEST[] = "44234567-89AB-CDEF-0123-456789ABCDEF";
static const char REQUEST_TWO[] = "55234567-89AB-CDEF-0123-456789ABCDEF";
static const char INPUT[] = "{\"protocol\":1,\"operation\":\"probe\",\"synthetic\":\"SYNTHETIC_INPUT_MATERIAL\"}";
static const char RESULT[] = "{\"protocol\":1,\"status\":\"ok\",\"synthetic\":\"SYNTHETIC_SECRET_MATERIAL\"}";
static const char ERROR_RESULT[] = "{\"protocol\":1,\"status\":\"error\",\"diagnostics\":{\"errorCode\":4}}";
static atomic_uint assertion_count, wakes, enable_calls;

#define CHECK(test) do { \
    atomic_fetch_add(&assertion_count, 1); \
    if (!(test)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #test); abort(); } \
} while (0)
#define RUN(test) do { test(); printf("PASS %s\n", #test); } while (0)

/* Count the externally exercised calls so the runner can require one native
   log record per call, including validation failures before authorization. */
static HvDeviceAuthError observed_enable(HvDeviceAuthMode mode, const char *launch) {
    atomic_fetch_add(&enable_calls, 1);
    return hv_device_auth_enable(mode, launch);
}
#define hv_device_auth_enable(mode, launch) observed_enable((mode), (launch))

static void sleep_ms(unsigned milliseconds) {
    struct timespec duration = { milliseconds / 1000, (long)(milliseconds % 1000) * 1000000L };
    while (nanosleep(&duration, &duration) != 0) {}
}

static HvDeviceAuthRequest request(void) {
    return (HvDeviceAuthRequest){
        .method = "POST", .content_type = "application/json", .session = SESSION,
        .launch_id = LAUNCH, .request_id = REQUEST, .operation = HV_DEVICE_AUTH_PROBE,
        .body = INPUT, .body_length = sizeof(INPUT) - 1, .timeout_ms = 1000
    };
}

static void idle_wakeup(void *context) {
    CHECK(context == &wakes);
    atomic_fetch_add(&wakes, 1);
}

static void success_wakeup(void *context) {
    CHECK(context == &wakes);
    atomic_fetch_add(&wakes, 1);
    HvDeviceAuthJob job;
    CHECK(hv_device_auth_take(&job));
    CHECK(job.body_length == sizeof(INPUT) - 1);
    CHECK(!memcmp(job.body, INPUT, job.body_length));
    CHECK(job.remaining_ms > 0 && job.remaining_ms <= 1000);
    CHECK(hv_device_auth_job_is_current(job.ticket, job.session, job.launch_id, job.request_id));
    CHECK(hv_device_auth_complete(job.ticket, job.session, job.launch_id, job.request_id,
                                 200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    hv_device_auth_job_dispose(&job);
    CHECK(!job.body && !job.body_length && !job.ticket);
}

static void setup(HvDeviceAuthWakeup wakeup) {
    hv_device_auth_end();
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(!state.busy);
    CHECK(hv_device_auth_set_wakeup(wakeup, &wakes));
    atomic_store(&wakes, 0);
    hv_device_auth_begin(SESSION);
    hv_device_auth_publish(1, 1);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH) == HV_DEVICE_AUTH_OK);
}

static void expect_rejected(HvDeviceAuthRequest *input, HvDeviceAuthError expected) {
    HvDeviceAuthResponse response;
    unsigned before = atomic_load(&wakes);
    CHECK(hv_device_auth_submit(input, &response) == expected);
    CHECK(response.error == expected);
    CHECK(response.http_status == hv_device_auth_http_status(expected));
    CHECK(!response.body && !response.body_length);
    CHECK(atomic_load(&wakes) == before);
    hv_device_auth_response_dispose(&response);
}

typedef struct {
    HvDeviceAuthRequest input;
    HvDeviceAuthResponse output;
    HvDeviceAuthError result;
    pthread_t thread;
} Submission;

static void *submit_thread(void *context) {
    Submission *submission = context;
    submission->result = hv_device_auth_submit(&submission->input, &submission->output);
    return NULL;
}

static void start_submission(Submission *submission, unsigned timeout_ms) {
    memset(submission, 0, sizeof(*submission));
    submission->input = request();
    submission->input.timeout_ms = timeout_ms;
    unsigned before = atomic_load(&wakes);
    CHECK(pthread_create(&submission->thread, NULL, submit_thread, submission) == 0);
    unsigned attempts = 0;
    while (atomic_load(&wakes) == before && attempts++ < 1000) sleep_ms(1);
    CHECK(atomic_load(&wakes) == before + 1);
}

static void join_submission(Submission *submission, HvDeviceAuthError expected) {
    CHECK(pthread_join(submission->thread, NULL) == 0);
    CHECK(submission->result == expected);
    CHECK(submission->output.error == expected);
    if (expected != HV_DEVICE_AUTH_OK) CHECK(!submission->output.body);
}

static int finish(const HvDeviceAuthJob *job, int status, HvDeviceAuthError error,
                  const void *body, size_t length) {
    return hv_device_auth_complete(job->ticket, job->session, job->launch_id, job->request_id,
                                   status, error, body, length);
}

static void metadata_and_default_denial(void) {
    setup(idle_wakeup);
    HvDeviceAuthRequest input = request();
    input.method = "GET"; expect_rejected(&input, HV_DEVICE_AUTH_METHOD_NOT_ALLOWED);
    input = request(); input.invalid_headers = 1; expect_rejected(&input, HV_DEVICE_AUTH_INVALID_HEADERS);
    input = request(); input.has_origin = 1; expect_rejected(&input, HV_DEVICE_AUTH_ORIGIN_FORBIDDEN);
    input = request(); input.content_type = "text/plain"; expect_rejected(&input, HV_DEVICE_AUTH_JSON_REQUIRED);
    input = request(); input.content_type = "application/json; charset=latin1"; expect_rejected(&input, HV_DEVICE_AUTH_JSON_REQUIRED);
    input = request(); input.content_type = "application/json; charset=utf-8; extra=x"; expect_rejected(&input, HV_DEVICE_AUTH_JSON_REQUIRED);
    input = request(); input.session = NULL; expect_rejected(&input, HV_DEVICE_AUTH_SESSION_REQUIRED);
    input = request(); input.session = SESSION_TWO; expect_rejected(&input, HV_DEVICE_AUTH_SESSION_CHANGED);
    input = request(); input.launch_id = "not-a-uuid"; expect_rejected(&input, HV_DEVICE_AUTH_LAUNCH_REQUIRED);
    input = request(); input.launch_id = LAUNCH_TWO; expect_rejected(&input, HV_DEVICE_AUTH_LAUNCH_CHANGED);
    input = request(); input.request_id = "44234567-89AB-CDEF-0123-456789ABCDEG"; expect_rejected(&input, HV_DEVICE_AUTH_REQUEST_ID_REQUIRED);
    input = request(); input.body_length = HV_DEVICE_AUTH_BODY_MAX + 1; expect_rejected(&input, HV_DEVICE_AUTH_BODY_TOO_LARGE);
    input = request(); input.body = NULL; expect_rejected(&input, HV_DEVICE_AUTH_INVALID_REQUEST);
    input = request(); input.timeout_ms = HV_DEVICE_AUTH_TIMEOUT_MAX_MS + 1; expect_rejected(&input, HV_DEVICE_AUTH_INVALID_REQUEST);
    input = request(); input.operation = (HvDeviceAuthOperation)99; expect_rejected(&input, HV_DEVICE_AUTH_INVALID_REQUEST);
    input = request(); input.operation = HV_DEVICE_AUTH_BAA_DATA; expect_rejected(&input, HV_DEVICE_AUTH_MODE_FORBIDDEN);
    hv_device_auth_disable();
    input = request(); expect_rejected(&input, HV_DEVICE_AUTH_NOT_ENABLED);
    hv_device_auth_begin(SESSION_TWO);
    hv_device_auth_publish(1, 1);
    input.session = SESSION_TWO;
    expect_rejected(&input, HV_DEVICE_AUTH_NOT_ENABLED);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, "invalid") == HV_DEVICE_AUTH_LAUNCH_REQUIRED);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_NONE, LAUNCH) == HV_DEVICE_AUTH_INVALID_REQUEST);
    hv_device_auth_end();
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH) == HV_DEVICE_AUTH_HOST_INACTIVE);
}

static void enable_diagnostics_preserve_authorization(void) {
    hv_device_auth_end();
    CHECK(hv_device_auth_set_wakeup(NULL, NULL));
    hv_device_auth_begin(SESSION);
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(state.enable_attempts == 0 && state.enable_successes == 0 && state.enable_failures == 0);
    CHECK(!state.backend_registered && !state.last_enable_backend_registered);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, NULL) == HV_DEVICE_AUTH_LAUNCH_REQUIRED);
    CHECK(hv_device_auth_enable((HvDeviceAuthMode)99, LAUNCH) == HV_DEVICE_AUTH_INVALID_REQUEST);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_BAA, LAUNCH) == HV_DEVICE_AUTH_HOST_INACTIVE);
    hv_device_auth_snapshot(&state);
    CHECK(state.enable_attempts == 3 && state.enable_successes == 0 && state.enable_failures == 3);
    CHECK(state.last_enable_error == HV_DEVICE_AUTH_HOST_INACTIVE && state.last_enable_mode == HV_DEVICE_AUTH_MODE_BAA);
    CHECK(!state.enabled && !state.launch_id[0] && state.mode == HV_DEVICE_AUTH_MODE_NONE && state.event_count == 0);

    hv_device_auth_publish(1, 1);
    /* Registration is observable, but this patch deliberately preserves the
       existing enable behavior: missing backend is rejected later by submit. */
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH) == HV_DEVICE_AUTH_OK);
    hv_device_auth_snapshot(&state);
    CHECK(state.enable_attempts == 4 && state.enable_successes == 1 && state.enable_failures == 3);
    CHECK(!state.backend_registered && !state.last_enable_backend_registered);
    CHECK(state.enabled && !strcmp(state.launch_id, LAUNCH) && state.mode == HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN);
    CHECK(state.event_count == 1 && state.events[0].stage == HV_DEVICE_AUTH_STAGE_HOST_BRIDGE_ENABLED);
    HvDeviceAuthRequest input = request();
    expect_rejected(&input, HV_DEVICE_AUTH_BACKEND_UNAVAILABLE);

    CHECK(hv_device_auth_set_wakeup(idle_wakeup, &wakes));
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH) == HV_DEVICE_AUTH_OK);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_BAA, LAUNCH_TWO) == HV_DEVICE_AUTH_MODE_CONFLICT);
    CHECK(hv_device_auth_enable((HvDeviceAuthMode)99, "SYNTHETIC_INPUT_MATERIAL") == HV_DEVICE_AUTH_LAUNCH_REQUIRED);
    hv_device_auth_snapshot(&state);
    CHECK(state.enable_attempts == 7 && state.enable_successes == 2 && state.enable_failures == 5);
    CHECK(state.last_enable_error == HV_DEVICE_AUTH_LAUNCH_REQUIRED && state.last_enable_mode == HV_DEVICE_AUTH_MODE_NONE);
    CHECK(state.backend_registered && state.last_enable_backend_registered);
    CHECK(state.enabled && !strcmp(state.launch_id, LAUNCH) && state.mode == HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN);
    CHECK(state.event_count == 1); /* Attempts do not replace the existing stage. */

    hv_device_auth_disable();
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH) == HV_DEVICE_AUTH_LAUNCH_REUSED);
    hv_device_auth_snapshot(&state);
    CHECK(!state.enabled && !strcmp(state.launch_id, LAUNCH) && state.mode == HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN);
    CHECK(state.enable_attempts == 8 && state.enable_successes == 2 && state.enable_failures == 6);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_BAA, LAUNCH_TWO) == HV_DEVICE_AUTH_OK);
    hv_device_auth_end();
    hv_device_auth_snapshot(&state);
    CHECK(state.enable_attempts == 9 && state.enable_successes == 3 && state.enable_failures == 6);
    CHECK(state.enable_attempts == state.enable_successes + state.enable_failures);
    hv_device_auth_begin(SESSION_TWO);
    hv_device_auth_snapshot(&state);
    CHECK(state.enable_attempts == 0 && state.enable_successes == 0 && state.enable_failures == 0);
    CHECK(state.last_enable_error == HV_DEVICE_AUTH_OK && state.last_enable_mode == HV_DEVICE_AUTH_MODE_NONE);
    CHECK(state.backend_registered && !state.last_enable_backend_registered);
    CHECK(!state.enabled && !state.launch_id[0] && state.event_count == 0);
}

static void immediate_completion_and_copy_ownership(void) {
    setup(success_wakeup);
    HvDeviceAuthRequest input = request();
    input.content_type = " Application/JSON ; CHARSET = UTF-8\t";
    input.session = "01234567-89ab-cdef-0123-456789abcdef";
    HvDeviceAuthResponse response;
    CHECK(hv_device_auth_submit(&input, &response) == HV_DEVICE_AUTH_OK);
    CHECK(response.http_status == 200);
    CHECK(response.body_length == sizeof(RESULT) - 1 && !memcmp(response.body, RESULT, response.body_length));
    CHECK(!strcmp(response.session, SESSION) && !strcmp(response.launch_id, LAUNCH) && !strcmp(response.request_id, REQUEST));
    CHECK(hv_device_auth_response_revalidate(&response) == HV_DEVICE_AUTH_OK);
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(state.enabled && state.active && !state.busy);
    CHECK(state.accepted_requests == 1 && state.completed_requests == 1);
    CHECK(state.event_count == 4);
    CHECK(state.events[3].stage == HV_DEVICE_AUTH_STAGE_HOST_REQUEST_COMPLETED);
    CHECK(!strcmp(state.events[3].launch_id, LAUNCH));
    CHECK(state.events[3].input_bytes == sizeof(INPUT) - 1 && state.events[3].result_bytes == sizeof(RESULT) - 1);
    hv_device_auth_response_dispose(&response);
    CHECK(!response.body && !response.body_length && !response.session[0]);
}

static void queued_timeout_never_reaches_backend(void) {
    setup(idle_wakeup);
    Submission submission;
    start_submission(&submission, 30);
    join_submission(&submission, HV_DEVICE_AUTH_TIMED_OUT);
    HvDeviceAuthJob job;
    CHECK(!hv_device_auth_take(&job));
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(!state.busy && state.completed_requests == 0);
    hv_device_auth_response_dispose(&submission.output);
}

static void single_flight_survives_waiter_timeout(void) {
    setup(idle_wakeup);
    Submission submission;
    start_submission(&submission, 80);
    HvDeviceAuthJob job;
    CHECK(hv_device_auth_take(&job));
    HvDeviceAuthRequest second = request();
    second.request_id = REQUEST_TWO;
    expect_rejected(&second, HV_DEVICE_AUTH_BUSY);
    CHECK(!hv_device_auth_set_wakeup(success_wakeup, &wakes));
    join_submission(&submission, HV_DEVICE_AUTH_TIMED_OUT);
    CHECK(!hv_device_auth_job_is_current(job.ticket, job.session, job.launch_id, job.request_id));
    expect_rejected(&second, HV_DEVICE_AUTH_BUSY);
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(state.busy);
    CHECK(finish(&job, 200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    hv_device_auth_snapshot(&state);
    CHECK(!state.busy && state.completed_requests == 0);
    CHECK(!finish(&job, 200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    hv_device_auth_job_dispose(&job);
    hv_device_auth_response_dispose(&submission.output);
}

static void all_completion_ids_must_match(void) {
    setup(idle_wakeup);
    Submission submission;
    start_submission(&submission, 1000);
    HvDeviceAuthJob job;
    CHECK(hv_device_auth_take(&job));
    CHECK(!hv_device_auth_complete(job.ticket + 1, job.session, job.launch_id, job.request_id,
                                  200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    CHECK(!hv_device_auth_complete(job.ticket, SESSION_TWO, job.launch_id, job.request_id,
                                  200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    CHECK(!hv_device_auth_complete(job.ticket, job.session, LAUNCH_TWO, job.request_id,
                                  200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    CHECK(!hv_device_auth_complete(job.ticket, job.session, job.launch_id, REQUEST_TWO,
                                  200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    CHECK(hv_device_auth_job_is_current(job.ticket, job.session, job.launch_id, job.request_id));
    unsigned char temporary[sizeof(RESULT)];
    memcpy(temporary, RESULT, sizeof(RESULT));
    CHECK(finish(&job, 200, HV_DEVICE_AUTH_OK, temporary, sizeof(RESULT) - 1));
    memset(temporary, 'X', sizeof(temporary));
    join_submission(&submission, HV_DEVICE_AUTH_OK);
    CHECK(!memcmp(submission.output.body, RESULT, sizeof(RESULT) - 1));
    hv_device_auth_response_dispose(&submission.output);
    hv_device_auth_job_dispose(&job);
}

static void cancellation_and_new_session_do_not_deliver_old_results(void) {
    setup(idle_wakeup);
    Submission old;
    start_submission(&old, 1000);
    HvDeviceAuthJob job;
    CHECK(hv_device_auth_take(&job));
    hv_device_auth_begin(SESSION_TWO);
    hv_device_auth_publish(1, 1);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH_TWO) == HV_DEVICE_AUTH_OK);
    join_submission(&old, HV_DEVICE_AUTH_SESSION_CHANGED);
    CHECK(!hv_device_auth_job_is_current(job.ticket, job.session, job.launch_id, job.request_id));
    HvDeviceAuthRequest second = request();
    second.session = SESSION_TWO; second.launch_id = LAUNCH_TWO;
    expect_rejected(&second, HV_DEVICE_AUTH_BUSY);
    CHECK(finish(&job, 200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(state.enabled && !state.busy && state.completed_requests == 0);
    CHECK(state.event_count == 1 && state.events[0].stage == HV_DEVICE_AUTH_STAGE_HOST_BRIDGE_ENABLED);
    CHECK(!strcmp(state.events[0].launch_id, LAUNCH_TWO));
    hv_device_auth_job_dispose(&job);
    hv_device_auth_response_dispose(&old.output);
}

static void background_cancels_claimed_work_and_does_not_resume_authorization(void) {
    setup(idle_wakeup);
    Submission submission;
    start_submission(&submission, 1000);
    HvDeviceAuthJob job;
    CHECK(hv_device_auth_take(&job));
    hv_device_auth_publish(1, 0);
    join_submission(&submission, HV_DEVICE_AUTH_HOST_INACTIVE);
    CHECK(!hv_device_auth_job_is_current(job.ticket, job.session, job.launch_id, job.request_id));
    CHECK(finish(&job, 200, HV_DEVICE_AUTH_OK, RESULT, sizeof(RESULT) - 1));
    hv_device_auth_publish(1, 1);
    HvDeviceAuthRequest input = request();
    expect_rejected(&input, HV_DEVICE_AUTH_NOT_ENABLED);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH) == HV_DEVICE_AUTH_LAUNCH_REUSED);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH_TWO) == HV_DEVICE_AUTH_OK);
    hv_device_auth_response_dispose(&submission.output);
    hv_device_auth_job_dispose(&job);
}

static void queued_disable_and_end_cancel_without_take(void) {
    setup(idle_wakeup);
    Submission submission;
    start_submission(&submission, 1000);
    hv_device_auth_disable();
    join_submission(&submission, HV_DEVICE_AUTH_CANCELLED);
    HvDeviceAuthJob job;
    CHECK(!hv_device_auth_take(&job));
    hv_device_auth_response_dispose(&submission.output);
    setup(idle_wakeup);
    start_submission(&submission, 1000);
    hv_device_auth_end();
    join_submission(&submission, HV_DEVICE_AUTH_SESSION_CHANGED);
    CHECK(!hv_device_auth_take(&job));
    hv_device_auth_response_dispose(&submission.output);
}

static void mode_cannot_change_and_launch_cannot_be_reused(void) {
    setup(success_wakeup);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH) == HV_DEVICE_AUTH_OK);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_BAA, LAUNCH) == HV_DEVICE_AUTH_MODE_CONFLICT);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_BAA, LAUNCH_TWO) == HV_DEVICE_AUTH_MODE_CONFLICT);
    hv_device_auth_disable();
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_BAA, LAUNCH) == HV_DEVICE_AUTH_LAUNCH_REUSED);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_BAA, LAUNCH_TWO) == HV_DEVICE_AUTH_OK);
    HvDeviceAuthRequest input = request();
    input.launch_id = LAUNCH_TWO;
    input.operation = HV_DEVICE_AUTH_DC_TOKEN;
    expect_rejected(&input, HV_DEVICE_AUTH_MODE_FORBIDDEN);
    input.operation = HV_DEVICE_AUTH_BAA_DICTIONARY;
    HvDeviceAuthResponse response;
    CHECK(hv_device_auth_submit(&input, &response) == HV_DEVICE_AUTH_OK);
    hv_device_auth_response_dispose(&response);
}

static void response_revalidation_discards_after_revoke(void) {
    setup(success_wakeup);
    HvDeviceAuthRequest input = request();
    HvDeviceAuthResponse response;
    CHECK(hv_device_auth_submit(&input, &response) == HV_DEVICE_AUTH_OK);
    hv_device_auth_disable();
    CHECK(hv_device_auth_response_revalidate(&response) == HV_DEVICE_AUTH_NOT_ENABLED);
    CHECK(!response.body && !response.body_length && response.http_status == 409);
    hv_device_auth_response_dispose(&response);

    setup(success_wakeup);
    CHECK(hv_device_auth_submit(&input, &response) == HV_DEVICE_AUTH_OK);
    hv_device_auth_disable();
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH_TWO) == HV_DEVICE_AUTH_OK);
    CHECK(hv_device_auth_response_revalidate(&response) == HV_DEVICE_AUTH_LAUNCH_CHANGED);
    CHECK(!response.body && !response.body_length);
    hv_device_auth_response_dispose(&response);
}

static void bounded_backend_output_and_error_payload(void) {
    setup(idle_wakeup);
    Submission submission;
    start_submission(&submission, 1000);
    HvDeviceAuthJob job;
    CHECK(hv_device_auth_take(&job));
    CHECK(finish(&job, 200, HV_DEVICE_AUTH_OK, RESULT, HV_DEVICE_AUTH_RESPONSE_MAX + 1));
    join_submission(&submission, HV_DEVICE_AUTH_RESPONSE_TOO_LARGE);
    CHECK(submission.output.http_status == 502);
    hv_device_auth_response_dispose(&submission.output);
    hv_device_auth_job_dispose(&job);

    start_submission(&submission, 1000);
    CHECK(hv_device_auth_take(&job));
    CHECK(finish(&job, 200, HV_DEVICE_AUTH_OK, NULL, 0));
    join_submission(&submission, HV_DEVICE_AUTH_BACKEND_FAILED);
    hv_device_auth_response_dispose(&submission.output);
    hv_device_auth_job_dispose(&job);

    start_submission(&submission, 1000);
    CHECK(hv_device_auth_take(&job));
    CHECK(finish(&job, 200, HV_DEVICE_AUTH_BACKEND_FAILED, ERROR_RESULT, sizeof(ERROR_RESULT) - 1));
    CHECK(pthread_join(submission.thread, NULL) == 0);
    CHECK(submission.result == HV_DEVICE_AUTH_BACKEND_FAILED);
    CHECK(submission.output.http_status == 200 && submission.output.body_length == sizeof(ERROR_RESULT) - 1);
    CHECK(hv_device_auth_response_revalidate(&submission.output) == HV_DEVICE_AUTH_OK);
    hv_device_auth_response_dispose(&submission.output);
    hv_device_auth_job_dispose(&job);
}

static void rate_limit_is_enforced_before_backend(void) {
    setup(success_wakeup);
    HvDeviceAuthRequest input = request();
    for (int i = 0; i < 4; i++) {
        HvDeviceAuthResponse response;
        CHECK(hv_device_auth_submit(&input, &response) == HV_DEVICE_AUTH_OK);
        hv_device_auth_response_dispose(&response);
    }
    HvDeviceAuthResponse response;
    CHECK(hv_device_auth_submit(&input, &response) == HV_DEVICE_AUTH_RATE_LIMITED);
    CHECK(response.http_status == 429 && response.retry_after_ms > 0 && response.retry_after_ms <= 2000);
    CHECK(atomic_load(&wakes) == 4);
    hv_device_auth_response_dispose(&response);
    setup(NULL);
    expect_rejected(&input, HV_DEVICE_AUTH_BACKEND_UNAVAILABLE);
}

static void fixed_event_fields_and_bounded_history(void) {
    setup(idle_wakeup);
    HvDeviceAuthEvent event = {0};
    memcpy(event.request_id, REQUEST, sizeof(REQUEST));
    memcpy(event.launch_id, LAUNCH_TWO, sizeof(LAUNCH_TWO));
    event.stage = HV_DEVICE_AUTH_STAGE_PROBE_RESULT;
    event.error_domain = HV_DEVICE_AUTH_DOMAIN_APPLE_DEVICECHECK;
    event.error_code = -4;
    event.elapsed_ms = 10;
    event.sequence = UINT64_MAX;
    event.from_guest = 0;
    for (unsigned i = 0; i < 40; i++) CHECK(hv_device_auth_record_event(SESSION, LAUNCH, &event) == HV_DEVICE_AUTH_OK);
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(state.event_count == HV_DEVICE_AUTH_EVENT_COUNT);
    CHECK(state.events[0].sequence < state.events[31].sequence && state.events[31].sequence != UINT64_MAX);
    CHECK(state.events[31].from_guest && !strcmp(state.events[31].launch_id, LAUNCH));
    CHECK(state.events[31].error_code == -4 && state.events[31].error_domain == HV_DEVICE_AUTH_DOMAIN_APPLE_DEVICECHECK);
    event.stage = HV_DEVICE_AUTH_STAGE_HOST_REQUEST_COMPLETED;
    CHECK(hv_device_auth_record_event(SESSION, LAUNCH, &event) == HV_DEVICE_AUTH_INVALID_REQUEST);
    event.stage = HV_DEVICE_AUTH_STAGE_TOKEN_RESULT;
    event.error_domain = (HvDeviceAuthDomain)99;
    CHECK(hv_device_auth_record_event(SESSION, LAUNCH, &event) == HV_DEVICE_AUTH_INVALID_REQUEST);
    event.error_domain = HV_DEVICE_AUTH_DOMAIN_BRIDGE;
    CHECK(hv_device_auth_record_event(SESSION_TWO, LAUNCH, &event) == HV_DEVICE_AUTH_SESSION_CHANGED);
    CHECK(hv_device_auth_record_event(SESSION, LAUNCH_TWO, &event) == HV_DEVICE_AUTH_LAUNCH_CHANGED);
    event.result_bytes = HV_DEVICE_AUTH_RESPONSE_MAX + 1;
    CHECK(hv_device_auth_record_event(SESSION, LAUNCH, &event) == HV_DEVICE_AUTH_INVALID_REQUEST);
    for (int i = HV_DEVICE_AUTH_STAGE_LAUNCH_REQUESTED; i <= HV_DEVICE_AUTH_STAGE_SESSION_INACTIVE; i++)
        CHECK(hv_device_auth_stage_from_name(hv_device_auth_stage_name((HvDeviceAuthStage)i)) == (HvDeviceAuthStage)i);
    CHECK(hv_device_auth_stage_from_name("host_request_completed") == HV_DEVICE_AUTH_STAGE_NONE);
    CHECK(hv_device_auth_stage_from_name("unexpected raw message") == HV_DEVICE_AUTH_STAGE_NONE);
    for (int i = HV_DEVICE_AUTH_DOMAIN_NONE; i <= HV_DEVICE_AUTH_DOMAIN_OTHER; i++)
        CHECK(hv_device_auth_domain_from_name(hv_device_auth_domain_name((HvDeviceAuthDomain)i)) == (HvDeviceAuthDomain)i);
    CHECK(hv_device_auth_domain_from_name("unknown.private.domain") == HV_DEVICE_AUTH_DOMAIN_OTHER);
}

static void stale_host_state_is_not_revived_by_a_late_publication(void) {
    setup(idle_wakeup);
    sleep_ms(HV_DEVICE_AUTH_STATE_MAX_AGE_MS + 30);
    /* No polling runs during the gap: publish itself must notice expiration before updating it. */
    hv_device_auth_publish(1, 1);
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(state.active && state.fresh && !state.enabled);
    HvDeviceAuthRequest input = request();
    expect_rejected(&input, HV_DEVICE_AUTH_NOT_ENABLED);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH) == HV_DEVICE_AUTH_LAUNCH_REUSED);
    CHECK(hv_device_auth_enable(HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN, LAUNCH_TWO) == HV_DEVICE_AUTH_OK);
}

static void fixed_guest_preflight_observations(void) {
    static const struct { const char *name; HvDeviceAuthStage stage; } observations[] = {
        {"target_process_running", HV_DEVICE_AUTH_STAGE_TARGET_PROCESS_RUNNING},
        {"target_process_not_running", HV_DEVICE_AUTH_STAGE_TARGET_PROCESS_NOT_RUNNING},
        {"policy_flags_unavailable", HV_DEVICE_AUTH_STAGE_POLICY_FLAGS_UNAVAILABLE},
        {"policy_runtime_on", HV_DEVICE_AUTH_STAGE_POLICY_RUNTIME_ON},
        {"policy_runtime_off", HV_DEVICE_AUTH_STAGE_POLICY_RUNTIME_OFF},
        {"policy_library_flag_on", HV_DEVICE_AUTH_STAGE_POLICY_LIBRARY_FLAG_ON},
        {"policy_library_flag_off", HV_DEVICE_AUTH_STAGE_POLICY_LIBRARY_FLAG_OFF},
        {"policy_dyld_env_allowed", HV_DEVICE_AUTH_STAGE_POLICY_DYLD_ENV_ALLOWED},
        {"policy_dyld_env_not_allowed", HV_DEVICE_AUTH_STAGE_POLICY_DYLD_ENV_NOT_ALLOWED},
        {"policy_library_exception_on", HV_DEVICE_AUTH_STAGE_POLICY_LIBRARY_EXCEPTION_ON},
        {"policy_library_exception_off", HV_DEVICE_AUTH_STAGE_POLICY_LIBRARY_EXCEPTION_OFF},
    };
    setup(idle_wakeup);
    HvDeviceAuthEvent event = {0};
    memcpy(event.request_id, REQUEST, sizeof(REQUEST));
    for (size_t i = 0; i < sizeof observations / sizeof observations[0]; i++) {
        event.stage = observations[i].stage;
        CHECK(hv_device_auth_stage_from_name(observations[i].name) == event.stage);
        CHECK(!strcmp(hv_device_auth_stage_name(event.stage), observations[i].name));
        CHECK(hv_device_auth_record_event(SESSION, LAUNCH, &event) == HV_DEVICE_AUTH_OK);
    }
    for (int stage = HV_DEVICE_AUTH_STAGE_HOST_REQUEST_QUEUED; stage <= HV_DEVICE_AUTH_STAGE_HOST_BRIDGE_DISABLED; stage++) {
        event.stage = (HvDeviceAuthStage)stage;
        CHECK(hv_device_auth_stage_from_name(hv_device_auth_stage_name(event.stage)) == HV_DEVICE_AUTH_STAGE_NONE);
        CHECK(hv_device_auth_record_event(SESSION, LAUNCH, &event) == HV_DEVICE_AUTH_INVALID_REQUEST);
    }
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    CHECK(state.event_count == 1 + sizeof observations / sizeof observations[0]);
    for (size_t i = 1; i < state.event_count; i++) {
        CHECK(state.events[i].from_guest && state.events[i].stage == observations[i - 1].stage);
        CHECK(!strcmp(state.events[i].request_id, REQUEST) && !strcmp(state.events[i].launch_id, LAUNCH));
        CHECK(state.events[i].error_domain == HV_DEVICE_AUTH_DOMAIN_NONE && state.events[i].error_code == 0);
        CHECK(state.events[i].input_bytes == 0 && state.events[i].result_bytes == 0 && state.events[i].elapsed_ms == 0);
    }
    CHECK(state.enabled && state.mode == HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN && !strcmp(state.launch_id, LAUNCH));
    CHECK(state.accepted_requests == 0 && state.completed_requests == 0 && atomic_load(&wakes) == 0);
}

int main(void) {
    RUN(metadata_and_default_denial);
    RUN(enable_diagnostics_preserve_authorization);
    RUN(immediate_completion_and_copy_ownership);
    RUN(queued_timeout_never_reaches_backend);
    RUN(single_flight_survives_waiter_timeout);
    RUN(all_completion_ids_must_match);
    RUN(cancellation_and_new_session_do_not_deliver_old_results);
    RUN(background_cancels_claimed_work_and_does_not_resume_authorization);
    RUN(queued_disable_and_end_cancel_without_take);
    RUN(mode_cannot_change_and_launch_cannot_be_reused);
    RUN(response_revalidation_discards_after_revoke);
    RUN(bounded_backend_output_and_error_payload);
    RUN(rate_limit_is_enforced_before_backend);
    RUN(fixed_event_fields_and_bounded_history);
    RUN(fixed_guest_preflight_observations);
    RUN(stale_host_state_is_not_revived_by_a_late_publication);
    hv_device_auth_end();
    CHECK(hv_device_auth_set_wakeup(NULL, NULL));
    printf("PASS device-auth production C: %u assertions; synthetic backend only\n", atomic_load(&assertion_count));
    printf("enable_calls_exercised=%u\n", atomic_load(&enable_calls));
    return 0;
}
