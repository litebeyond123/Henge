#ifndef HENGE_DEVICE_AUTH_H
#define HENGE_DEVICE_AUTH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HV_DEVICE_AUTH_UUID_SIZE 37
#define HV_DEVICE_AUTH_BODY_MAX (128u * 1024u)
#define HV_DEVICE_AUTH_RESPONSE_MAX (96u * 1024u)
#define HV_DEVICE_AUTH_TIMEOUT_MAX_MS 15000u
#define HV_DEVICE_AUTH_TIMEOUT_DEFAULT_MS 12000u
#define HV_DEVICE_AUTH_STATE_MAX_AGE_MS 5000u
#define HV_DEVICE_AUTH_EVENT_COUNT 32u
#define HV_DEVICE_AUTH_STARTUP_EVENT_COUNT 48u
#define HV_DEVICE_AUTH_STATE_RESPONSE_MAX (64u * 1024u)

typedef enum {
    HV_DEVICE_AUTH_MODE_NONE = 0,
    /* Public mode probes/calls DCDevice in the main app; BAA mode probes/calls the isolated
       private signer. A dc_token request is deliberately forbidden in BAA mode. */
    HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN = 1,
    HV_DEVICE_AUTH_MODE_BAA = 2
} HvDeviceAuthMode;

typedef enum {
    HV_DEVICE_AUTH_ACTION_INVALID = -1,
    HV_DEVICE_AUTH_ACTION_NORMAL_QUIT = 0,
    HV_DEVICE_AUTH_ACTION_FORCE_QUIT = 1
} HvDeviceAuthAction;

typedef enum {
    HV_DEVICE_AUTH_PROBE = 0,
    HV_DEVICE_AUTH_DC_TOKEN = 1,
    HV_DEVICE_AUTH_BAA_DATA = 2,
    HV_DEVICE_AUTH_BAA_DICTIONARY = 3
} HvDeviceAuthOperation;

typedef enum {
    HV_DEVICE_AUTH_OK = 0,
    HV_DEVICE_AUTH_INVALID_REQUEST,
    HV_DEVICE_AUTH_METHOD_NOT_ALLOWED,
    HV_DEVICE_AUTH_INVALID_HEADERS,
    HV_DEVICE_AUTH_ORIGIN_FORBIDDEN,
    HV_DEVICE_AUTH_JSON_REQUIRED,
    HV_DEVICE_AUTH_BODY_TOO_LARGE,
    HV_DEVICE_AUTH_SESSION_REQUIRED,
    HV_DEVICE_AUTH_SESSION_CHANGED,
    HV_DEVICE_AUTH_LAUNCH_REQUIRED,
    HV_DEVICE_AUTH_LAUNCH_CHANGED,
    HV_DEVICE_AUTH_REQUEST_ID_REQUIRED,
    HV_DEVICE_AUTH_HOST_INACTIVE,
    HV_DEVICE_AUTH_NOT_ENABLED,
    HV_DEVICE_AUTH_MODE_FORBIDDEN,
    HV_DEVICE_AUTH_MODE_CONFLICT,
    HV_DEVICE_AUTH_LAUNCH_REUSED,
    HV_DEVICE_AUTH_LAUNCH_LIMIT,
    HV_DEVICE_AUTH_BUSY,
    HV_DEVICE_AUTH_RATE_LIMITED,
    HV_DEVICE_AUTH_TIMED_OUT,
    HV_DEVICE_AUTH_BACKEND_UNAVAILABLE,
    HV_DEVICE_AUTH_BACKEND_FAILED,
    HV_DEVICE_AUTH_RESPONSE_TOO_LARGE,
    HV_DEVICE_AUTH_NO_MEMORY,
    HV_DEVICE_AUTH_CANCELLED,
    HV_DEVICE_AUTH_INTERNAL_ERROR,
    HV_DEVICE_AUTH_ACTION_CONFLICT
} HvDeviceAuthError;

typedef enum {
    HV_DEVICE_AUTH_DOMAIN_NONE = 0,
    HV_DEVICE_AUTH_DOMAIN_BRIDGE,
    HV_DEVICE_AUTH_DOMAIN_URL,
    HV_DEVICE_AUTH_DOMAIN_POSIX,
    HV_DEVICE_AUTH_DOMAIN_OSSTATUS,
    HV_DEVICE_AUTH_DOMAIN_DC,
    HV_DEVICE_AUTH_DOMAIN_DEVICECHECK,
    HV_DEVICE_AUTH_DOMAIN_APPLE_DEVICECHECK,
    HV_DEVICE_AUTH_DOMAIN_MOBILE_ACTIVATION,
    HV_DEVICE_AUTH_DOMAIN_IDS_BAA,
    HV_DEVICE_AUTH_DOMAIN_COCOA,
    HV_DEVICE_AUTH_DOMAIN_HOST,
    HV_DEVICE_AUTH_DOMAIN_OTHER
} HvDeviceAuthDomain;

typedef enum {
    HV_DEVICE_AUTH_STAGE_NONE = 0,
    HV_DEVICE_AUTH_STAGE_LAUNCH_REQUESTED,
    HV_DEVICE_AUTH_STAGE_TARGET_NOT_FOUND,
    HV_DEVICE_AUTH_STAGE_TARGET_IDENTITY_MISMATCH,
    HV_DEVICE_AUTH_STAGE_TARGET_SIGNATURE_INVALID,
    HV_DEVICE_AUTH_STAGE_SIGNATURE_POLICY_BLOCKED,
    HV_DEVICE_AUTH_STAGE_ALREADY_RUNNING,
    HV_DEVICE_AUTH_STAGE_LAUNCH_STARTED,
    HV_DEVICE_AUTH_STAGE_LAUNCH_FAILED,
    HV_DEVICE_AUTH_STAGE_LAUNCH_TIMEOUT,
    HV_DEVICE_AUTH_STAGE_ADAPTER_LOADED,
    HV_DEVICE_AUTH_STAGE_ADAPTER_NOT_LOADED,
    HV_DEVICE_AUTH_STAGE_ADAPTER_TARGET_REJECTED,
    HV_DEVICE_AUTH_STAGE_ADAPTER_ABI_MISMATCH,
    HV_DEVICE_AUTH_STAGE_ADAPTER_READY,
    HV_DEVICE_AUTH_STAGE_PROBE_REQUESTED,
    HV_DEVICE_AUTH_STAGE_PROBE_RESULT,
    HV_DEVICE_AUTH_STAGE_TOKEN_REQUESTED,
    HV_DEVICE_AUTH_STAGE_TOKEN_RESULT,
    HV_DEVICE_AUTH_STAGE_BAA_DATA_REQUESTED,
    HV_DEVICE_AUTH_STAGE_BAA_DATA_RESULT,
    HV_DEVICE_AUTH_STAGE_BAA_DICTIONARY_REQUESTED,
    HV_DEVICE_AUTH_STAGE_BAA_DICTIONARY_RESULT,
    HV_DEVICE_AUTH_STAGE_REQUEST_DECLINED,
    HV_DEVICE_AUTH_STAGE_TRANSPORT_FAILED,
    HV_DEVICE_AUTH_STAGE_RESPONSE_INVALID,
    /* Guest observations after target identity validation. These are facts at
       preflight time, not proof of adapter loading or server acceptance. */
    HV_DEVICE_AUTH_STAGE_TARGET_PROCESS_RUNNING,
    HV_DEVICE_AUTH_STAGE_TARGET_PROCESS_NOT_RUNNING,
    HV_DEVICE_AUTH_STAGE_POLICY_FLAGS_UNAVAILABLE,
    HV_DEVICE_AUTH_STAGE_POLICY_RUNTIME_ON,
    HV_DEVICE_AUTH_STAGE_POLICY_RUNTIME_OFF,
    HV_DEVICE_AUTH_STAGE_POLICY_LIBRARY_FLAG_ON,
    HV_DEVICE_AUTH_STAGE_POLICY_LIBRARY_FLAG_OFF,
    HV_DEVICE_AUTH_STAGE_POLICY_DYLD_ENV_ALLOWED,
    HV_DEVICE_AUTH_STAGE_POLICY_DYLD_ENV_NOT_ALLOWED,
    HV_DEVICE_AUTH_STAGE_POLICY_LIBRARY_EXCEPTION_ON,
    HV_DEVICE_AUTH_STAGE_POLICY_LIBRARY_EXCEPTION_OFF,
    /* Signed flags predict a launch outcome; the OS still decides whether to
       load the unmodified original app and independently signed adapter. */
    HV_DEVICE_AUTH_STAGE_POLICY_PREDICTS_RESTRICTION,
    HV_DEVICE_AUTH_STAGE_POLICY_PREDICTS_PERMISSION,
    HV_DEVICE_AUTH_STAGE_QUIT_REQUESTED,
    HV_DEVICE_AUTH_STAGE_QUIT_COMPLETED,
    HV_DEVICE_AUTH_STAGE_QUIT_REFUSED,
    HV_DEVICE_AUTH_STAGE_QUIT_TIMEOUT,
    HV_DEVICE_AUTH_STAGE_TARGET_EXITED_BEFORE_ADAPTER,
    HV_DEVICE_AUTH_STAGE_ADAPTER_INITIALIZATION_FAILED,
    HV_DEVICE_AUTH_STAGE_FORCE_QUIT_REQUESTED,
    HV_DEVICE_AUTH_STAGE_FORCE_QUIT_COMPLETED,
    HV_DEVICE_AUTH_STAGE_FORCE_QUIT_REFUSED,
    HV_DEVICE_AUTH_STAGE_FORCE_QUIT_TIMEOUT,
    HV_DEVICE_AUTH_STAGE_PROCESS_IDENTITY_UNAVAILABLE,
    HV_DEVICE_AUTH_STAGE_TARGET_PROCESS_CHANGED,
    HV_DEVICE_AUTH_STAGE_TARGET_REAPPEARED,
    HV_DEVICE_AUTH_STAGE_QUIT_OPERATION_RETURNED,
    HV_DEVICE_AUTH_STAGE_PROCESS_EXIT_PENDING,
    HV_DEVICE_AUTH_STAGE_POST_EXIT_SIGNATURE_STARTED,
    HV_DEVICE_AUTH_STAGE_POST_EXIT_SIGNATURE_COMPLETED,
    HV_DEVICE_AUTH_STAGE_POST_EXIT_CENSUS_STARTED,
    HV_DEVICE_AUTH_STAGE_POST_EXIT_CENSUS_COMPLETED,
    HV_DEVICE_AUTH_STAGE_SESSION_INACTIVE,
    /* Host-only stages cannot be submitted by the guest event route. */
    HV_DEVICE_AUTH_STAGE_HOST_REQUEST_QUEUED,
    HV_DEVICE_AUTH_STAGE_HOST_REQUEST_STARTED,
    HV_DEVICE_AUTH_STAGE_HOST_REQUEST_COMPLETED,
    HV_DEVICE_AUTH_STAGE_HOST_REQUEST_FAILED,
    HV_DEVICE_AUTH_STAGE_HOST_REQUEST_CANCELLED,
    HV_DEVICE_AUTH_STAGE_HOST_BRIDGE_ENABLED,
    HV_DEVICE_AUTH_STAGE_HOST_BRIDGE_DISABLED
} HvDeviceAuthStage;

/* Capability 4: fixed process evidence, stored once per current launch rather
   than copied into every ring/cache entry. These fields never authorize work. */
typedef struct {
    int present;
    uint32_t phase, source, state, flags, status, retries, sample_ms;
    int operation_invoked, operation_result;
    uint32_t phase_elapsed_ms;
} HvDeviceAuthProcessObservation;

typedef struct {
    uint64_t sequence;           /* Filled by the service, never accepted from the guest. */
    uint64_t age_ms;             /* Filled when taking a snapshot. */
    int from_guest;              /* Filled by the service. */
    char launch_id[HV_DEVICE_AUTH_UUID_SIZE]; /* Filled by the service. */
    char request_id[HV_DEVICE_AUTH_UUID_SIZE];
    HvDeviceAuthStage stage;
    HvDeviceAuthDomain error_domain;
    int64_t error_code;
    uint32_t elapsed_ms;
    uint32_t input_bytes;
    uint32_t result_bytes;
    int32_t target_pid, observed_pid; /* 0 means not observed; fixed process metadata only. */
    HvDeviceAuthProcessObservation process;
} HvDeviceAuthEvent;

typedef struct {
    char session[HV_DEVICE_AUTH_UUID_SIZE];
    char launch_id[HV_DEVICE_AUTH_UUID_SIZE];
    HvDeviceAuthMode mode;
    HvDeviceAuthAction launch_action;
    int enabled, running, foreground, fresh, active, busy;
    int64_t state_age_ms;        /* -1 before the first publication. */
    uint64_t accepted_requests, completed_requests, refused_requests;
    /* Enable-call diagnostics for the current begin epoch. Success includes an
       idempotent OK; none of these fields grants or changes authorization.
       last_enable_* is meaningful only when enable_attempts is nonzero.
       A mode other than PUBLIC_TOKEN/BAA is stored as NONE and rendered invalid. */
    uint64_t enable_attempts, enable_successes, enable_failures;
    HvDeviceAuthError last_enable_error;
    HvDeviceAuthMode last_enable_mode;
    HvDeviceAuthAction last_enable_action;
    int backend_registered, last_enable_backend_registered;
    size_t event_count;
    HvDeviceAuthEvent events[HV_DEVICE_AUTH_EVENT_COUNT]; /* Oldest first. */
    /* Current launch only, newest observation per fixed startup stage, sorted
       by service sequence. Request/probe traffic cannot evict these facts. */
    size_t startup_event_count;
    HvDeviceAuthEvent startup_events[HV_DEVICE_AUTH_STARTUP_EVENT_COUNT];
    HvDeviceAuthEvent process_observation; /* process.present=0 means no evidence yet. */
} HvDeviceAuthState;

typedef struct {
    const char *method;
    const char *content_type;
    int invalid_headers, has_origin;
    const char *session;
    const char *launch_id;
    const char *request_id;
    HvDeviceAuthOperation operation;
    const void *body;           /* Already validated flat JSON; copied before submission. */
    size_t body_length;
    uint32_t timeout_ms;        /* 0 selects the default; otherwise 1..maximum. */
} HvDeviceAuthRequest;

typedef struct {
    uint64_t ticket;            /* Nonrepeating within this process; not a bearer credential. */
    char session[HV_DEVICE_AUTH_UUID_SIZE];
    char launch_id[HV_DEVICE_AUTH_UUID_SIZE];
    char request_id[HV_DEVICE_AUTH_UUID_SIZE];
    HvDeviceAuthMode mode;
    HvDeviceAuthOperation operation;
    unsigned char *body;        /* take transfers ownership; dispose after making the backend copy. */
    size_t body_length;
    uint32_t remaining_ms;
} HvDeviceAuthJob;

typedef struct {
    int http_status;
    HvDeviceAuthError error;
    uint32_t retry_after_ms;
    char session[HV_DEVICE_AUTH_UUID_SIZE];
    char launch_id[HV_DEVICE_AUTH_UUID_SIZE];
    char request_id[HV_DEVICE_AUTH_UUID_SIZE];
    unsigned char *body;        /* Opaque response JSON, only for this request's HTTP connection. */
    size_t body_length;
} HvDeviceAuthResponse;

/* wakeup must only schedule a background consumer; it must return promptly and may call take.
   Context must live until process exit. Configure only while no job is outstanding. No Apple API
   is called by this C module. A backend must complete exactly once, including its own deadline. */
typedef void (*HvDeviceAuthWakeup)(void *context);
int hv_device_auth_set_wakeup(HvDeviceAuthWakeup wakeup, void *context);

/* begin uses the existing hv_share_host_begin UUID. A new session starts disabled. */
void hv_device_auth_begin(const char *session);
void hv_device_auth_end(void);
void hv_device_auth_publish(int running, int foreground);
/* Legacy callers authorize only a normal quit. A new active launch binds both
   mode and action; neither may be changed under its UUID. Revocation never
   upgrades a normal attempt or resumes a previous forced attempt. */
HvDeviceAuthError hv_device_auth_enable(HvDeviceAuthMode mode, const char *launch_id);
HvDeviceAuthError hv_device_auth_enable_with_action(HvDeviceAuthMode mode, HvDeviceAuthAction action,
                                                   const char *launch_id);
void hv_device_auth_disable(void);
void hv_device_auth_snapshot(HvDeviceAuthState *out);

/* HTTP worker only: this can wait up to request.timeout_ms. Never call on the UI thread.
   share.c must reject duplicate headers, CORS/Origin and transfer encoding, enforce Content-Length
   before reading, and validate the JSON operation and both request/launch UUIDs before this call.
   This service independently checks the supplied metadata and state, but does not parse JSON. */
HvDeviceAuthError hv_device_auth_submit(const HvDeviceAuthRequest *request, HvDeviceAuthResponse *out);

/* Utility queue only. take claims a still-valid queued job atomically. A job that expired in the
   queue is never returned. A claimed Apple operation cannot generally be cancelled; on revocation
   its results are dropped and it retains the single-flight slot until complete arrives. */
int hv_device_auth_take(HvDeviceAuthJob *out);
int hv_device_auth_job_is_current(uint64_t ticket, const char *session, const char *launch_id,
                                  const char *request_id);
/* 1 means a matching completion was consumed, including a revoked result that was discarded.
   It does not mean secret material was delivered. 0 means the IDs did not identify a live job. */
int hv_device_auth_complete(uint64_t ticket, const char *session, const char *launch_id,
                            const char *request_id, int http_status, HvDeviceAuthError error,
                            const void *body, size_t body_length);
void hv_device_auth_job_dispose(HvDeviceAuthJob *job);
void hv_device_auth_response_dispose(HvDeviceAuthResponse *response);
/* Recheck immediately before writing the HTTP response; revocation clears secret bytes.
   OK means authorization is still current (or no body exists), independent of backend error. */
HvDeviceAuthError hv_device_auth_response_revalidate(HvDeviceAuthResponse *response);

/* Metadata only. Guest events require an enabled, active, matching session and launch and a valid
   request UUID. Guest stage/domain strings are mapped with the allowlist helpers below. */
HvDeviceAuthError hv_device_auth_record_event(const char *session, const char *launch_id,
                                             const HvDeviceAuthEvent *event);

const char *hv_device_auth_error_name(HvDeviceAuthError error);
int hv_device_auth_http_status(HvDeviceAuthError error);
const char *hv_device_auth_mode_name(HvDeviceAuthMode mode);
const char *hv_device_auth_action_name(HvDeviceAuthAction action);
const char *hv_device_auth_operation_name(HvDeviceAuthOperation operation);
const char *hv_device_auth_stage_name(HvDeviceAuthStage stage);
HvDeviceAuthStage hv_device_auth_stage_from_name(const char *name); /* Guest stages only. */
const char *hv_device_auth_domain_name(HvDeviceAuthDomain domain);
HvDeviceAuthDomain hv_device_auth_domain_from_name(const char *name); /* Unknown -> other. */

#ifdef __cplusplus
}
#endif
#endif
