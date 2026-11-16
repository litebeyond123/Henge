#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#else
#define _POSIX_C_SOURCE 200809L
#endif
#include "device_auth.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* The transport has one bounded slot, not an unbounded pool of pending Apple calls. A dispatched
   operation owns that slot until the backend completes, even after the HTTP caller has gone away. */
enum { SLOT_EMPTY, SLOT_QUEUED, SLOT_RUNNING, SLOT_DONE };
#define LAUNCH_HISTORY_MAX 256u
#define REQUEST_BURST 4u
#define REQUEST_REFILL_MS 2000u

typedef struct {
    int phase, waiter, cancelled;
    uint64_t ticket, started_ms, deadline_ms;
    char session[HV_DEVICE_AUTH_UUID_SIZE];
    char launch_id[HV_DEVICE_AUTH_UUID_SIZE];
    char request_id[HV_DEVICE_AUTH_UUID_SIZE];
    HvDeviceAuthMode mode;
    HvDeviceAuthOperation operation;
    unsigned char *input, *output;
    size_t input_length, output_length;
    uint32_t original_input_length;
    HvDeviceAuthError error;
    int http_status;
} Slot;

static struct {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int init_error;
    char session[HV_DEVICE_AUTH_UUID_SIZE], launch_id[HV_DEVICE_AUTH_UUID_SIZE];
    HvDeviceAuthMode mode;
    int enabled, running, foreground, published;
    uint64_t published_ms, next_ticket, next_sequence;
    uint64_t accepted, completed, refused;
    char used_launches[LAUNCH_HISTORY_MAX][HV_DEVICE_AUTH_UUID_SIZE];
    size_t launch_count;
    unsigned tokens;
    uint64_t refill_ms;
    HvDeviceAuthEvent events[HV_DEVICE_AUTH_EVENT_COUNT];
    uint64_t event_times[HV_DEVICE_AUTH_EVENT_COUNT];
    size_t event_next, event_count;
    HvDeviceAuthWakeup wakeup;
    void *wakeup_context;
    Slot slot;
} service = { .mutex = PTHREAD_MUTEX_INITIALIZER };
static pthread_once_t once = PTHREAD_ONCE_INIT;

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void initialize(void) {
    pthread_condattr_t attributes;
    int error = pthread_condattr_init(&attributes);
    if (error) { service.init_error = error; return; }
#if !defined(__APPLE__)
    error = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
#endif
    if (!error) error = pthread_cond_init(&service.changed, &attributes);
    pthread_condattr_destroy(&attributes);
    service.init_error = error;
}

static void lock_service(void) {
    pthread_once(&once, initialize);
    pthread_mutex_lock(&service.mutex);
}

static void notify_locked(void) {
    if (!service.init_error) pthread_cond_broadcast(&service.changed);
}

static void clear_bytes(void *bytes, size_t length) {
    volatile unsigned char *p = bytes;
    while (length--) *p++ = 0;
}

static void clear_free(unsigned char **bytes, size_t *length) {
    if (*bytes) { clear_bytes(*bytes, *length); free(*bytes); }
    *bytes = NULL;
    *length = 0;
}

static int uuid_copy(char output[HV_DEVICE_AUTH_UUID_SIZE], const char *input) {
    if (!input || strnlen(input, HV_DEVICE_AUTH_UUID_SIZE) != 36) return 0;
    for (size_t i = 0; i < 36; i++) {
        unsigned char c = (unsigned char)input[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return 0;
        } else if (c >= 'a' && c <= 'f') {
            c = (unsigned char)(c - ('a' - 'A'));
        } else if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
        output[i] = (char)c;
    }
    output[36] = 0;
    return 1;
}

static int json_content_type(const char *value) {
    if (!value || strnlen(value, 80) >= 80) return 0;
    const char *p = value;
    while (*p == ' ' || *p == '\t') p++;
    const char *mime = "application/json";
    size_t length = strlen(mime);
    if (strncasecmp(p, mime, length) != 0) return 0;
    p += length;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return 1;
    if (*p++ != ';') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (strncasecmp(p, "charset", 7) != 0) return 0;
    p += 7;
    while (*p == ' ' || *p == '\t') p++;
    if (*p++ != '=') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (strncasecmp(p, "utf-8", 5) != 0) return 0;
    p += 5;
    while (*p == ' ' || *p == '\t') p++;
    return !*p;
}

static int fresh_locked(uint64_t now) {
    return service.published && now >= service.published_ms &&
        now - service.published_ms <= HV_DEVICE_AUTH_STATE_MAX_AGE_MS;
}

static int active_locked(uint64_t now) {
    return service.session[0] && service.running && service.foreground && fresh_locked(now);
}

static void event_locked(const HvDeviceAuthEvent *input, int from_guest, uint64_t now) {
    size_t index = service.event_next;
    HvDeviceAuthEvent *event = &service.events[index];
    *event = *input;
    event->sequence = ++service.next_sequence;
    event->age_ms = 0;
    event->from_guest = from_guest;
    memcpy(event->launch_id, service.launch_id, sizeof(event->launch_id));
    service.event_times[index] = now;
    service.event_next = (index + 1) % HV_DEVICE_AUTH_EVENT_COUNT;
    if (service.event_count < HV_DEVICE_AUTH_EVENT_COUNT) service.event_count++;
}

static int slot_context_current_locked(void) {
    return strcmp(service.slot.session, service.session) == 0 &&
        strcmp(service.slot.launch_id, service.launch_id) == 0;
}

static void host_event_locked(HvDeviceAuthStage stage, HvDeviceAuthError error,
                              uint64_t now, int use_slot, uint32_t result_bytes) {
    if (use_slot && !slot_context_current_locked()) return;
    HvDeviceAuthEvent event = {0};
    event.stage = stage;
    event.error_domain = error == HV_DEVICE_AUTH_OK ? HV_DEVICE_AUTH_DOMAIN_NONE : HV_DEVICE_AUTH_DOMAIN_BRIDGE;
    event.error_code = error;
    if (use_slot) {
        memcpy(event.request_id, service.slot.request_id, sizeof(event.request_id));
        uint64_t elapsed = now >= service.slot.started_ms ? now - service.slot.started_ms : 0;
        event.elapsed_ms = elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed;
        event.input_bytes = service.slot.original_input_length;
        event.result_bytes = result_bytes;
    }
    event_locked(&event, 0, now);
    /* No UUID, HTTP body, token, challenge, signature, NSError description, or userInfo. */
    fprintf(stderr, "[device-auth] stage=%s error=%s input_bytes=%u result_bytes=%u\n",
            hv_device_auth_stage_name(stage), hv_device_auth_error_name(error),
            event.input_bytes, event.result_bytes);
    fflush(stderr);
}

static void reset_slot_locked(void) {
    clear_free(&service.slot.input, &service.slot.input_length);
    clear_free(&service.slot.output, &service.slot.output_length);
    memset(&service.slot, 0, sizeof(service.slot));
}

static void cancel_locked(HvDeviceAuthError error, uint64_t now) {
    Slot *slot = &service.slot;
    if (slot->phase == SLOT_EMPTY || slot->cancelled) return;
    slot->cancelled = 1;
    slot->error = error;
    slot->http_status = hv_device_auth_http_status(error);
    clear_free(&slot->input, &slot->input_length);
    clear_free(&slot->output, &slot->output_length);
    host_event_locked(HV_DEVICE_AUTH_STAGE_HOST_REQUEST_CANCELLED, error, now, 1, 0);
    if (slot->phase != SLOT_RUNNING) {
        slot->phase = SLOT_DONE;
        if (!slot->waiter) reset_slot_locked();
    }
    notify_locked();
}

static void revoke_locked(HvDeviceAuthError error, uint64_t now) {
    if (service.enabled) {
        service.enabled = 0;
        host_event_locked(HV_DEVICE_AUTH_STAGE_HOST_BRIDGE_DISABLED, error, now, 0, 0);
    }
    cancel_locked(error, now);
}

static void refresh_locked(uint64_t now) {
    if (service.enabled && !active_locked(now)) revoke_locked(HV_DEVICE_AUTH_HOST_INACTIVE, now);
    if ((service.slot.phase == SLOT_QUEUED || service.slot.phase == SLOT_RUNNING) &&
        !service.slot.cancelled && now >= service.slot.deadline_ms)
        cancel_locked(HV_DEVICE_AUTH_TIMED_OUT, now);
}

static HvDeviceAuthError authorize_locked(const char *session, const char *launch, uint64_t now) {
    if (!service.session[0] || strcmp(session, service.session)) return HV_DEVICE_AUTH_SESSION_CHANGED;
    if (!active_locked(now)) return HV_DEVICE_AUTH_HOST_INACTIVE;
    if (!service.enabled) return HV_DEVICE_AUTH_NOT_ENABLED;
    if (strcmp(launch, service.launch_id)) return HV_DEVICE_AUTH_LAUNCH_CHANGED;
    return HV_DEVICE_AUTH_OK;
}

static int wait_until_locked(uint64_t deadline) {
#if defined(__APPLE__)
    uint64_t now = now_ms();
    if (deadline <= now) return ETIMEDOUT;
    uint64_t remaining = deadline - now;
    struct timespec duration = { (time_t)(remaining / 1000u), (long)((remaining % 1000u) * 1000000u) };
    return pthread_cond_timedwait_relative_np(&service.changed, &service.mutex, &duration);
#else
    struct timespec absolute = { (time_t)(deadline / 1000u), (long)((deadline % 1000u) * 1000000u) };
    return pthread_cond_timedwait(&service.changed, &service.mutex, &absolute);
#endif
}

int hv_device_auth_set_wakeup(HvDeviceAuthWakeup wakeup, void *context) {
    lock_service();
    int accepted = !service.init_error && service.slot.phase == SLOT_EMPTY;
    if (accepted) { service.wakeup = wakeup; service.wakeup_context = context; }
    pthread_mutex_unlock(&service.mutex);
    return accepted;
}

void hv_device_auth_begin(const char *session) {
    char normalized[HV_DEVICE_AUTH_UUID_SIZE] = {0};
    int valid = uuid_copy(normalized, session);
    lock_service();
    uint64_t now = now_ms();
    revoke_locked(HV_DEVICE_AUTH_SESSION_CHANGED, now);
    memcpy(service.session, normalized, sizeof(service.session));
    if (!valid) service.session[0] = 0;
    memset(service.launch_id, 0, sizeof(service.launch_id));
    service.mode = HV_DEVICE_AUTH_MODE_NONE;
    service.running = service.foreground = service.published = 0;
    service.published_ms = 0;
    service.accepted = service.completed = service.refused = 0;
    memset(service.used_launches, 0, sizeof(service.used_launches));
    service.launch_count = 0;
    service.tokens = REQUEST_BURST;
    service.refill_ms = now;
    memset(service.events, 0, sizeof(service.events));
    memset(service.event_times, 0, sizeof(service.event_times));
    service.event_next = service.event_count = 0;
    notify_locked();
    pthread_mutex_unlock(&service.mutex);
}

void hv_device_auth_end(void) {
    lock_service();
    revoke_locked(HV_DEVICE_AUTH_SESSION_CHANGED, now_ms());
    service.session[0] = service.launch_id[0] = 0;
    service.mode = HV_DEVICE_AUTH_MODE_NONE;
    service.running = service.foreground = service.published = 0;
    notify_locked();
    pthread_mutex_unlock(&service.mutex);
}

void hv_device_auth_publish(int running, int foreground) {
    lock_service();
    uint64_t now = now_ms();
    /* A late publication must not revive an authorization whose previous snapshot expired. */
    refresh_locked(now);
    service.running = !!running;
    service.foreground = !!foreground;
    service.published = 1;
    service.published_ms = now;
    if (!active_locked(now)) revoke_locked(HV_DEVICE_AUTH_HOST_INACTIVE, now);
    notify_locked();
    pthread_mutex_unlock(&service.mutex);
}

HvDeviceAuthError hv_device_auth_enable(HvDeviceAuthMode mode, const char *launch_id) {
    char launch[HV_DEVICE_AUTH_UUID_SIZE];
    if (!uuid_copy(launch, launch_id)) return HV_DEVICE_AUTH_LAUNCH_REQUIRED;
    if (mode != HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN && mode != HV_DEVICE_AUTH_MODE_BAA)
        return HV_DEVICE_AUTH_INVALID_REQUEST;
    lock_service();
    uint64_t now = now_ms();
    refresh_locked(now);
    HvDeviceAuthError error = HV_DEVICE_AUTH_OK;
    if (service.init_error) error = HV_DEVICE_AUTH_INTERNAL_ERROR;
    else if (!active_locked(now)) error = HV_DEVICE_AUTH_HOST_INACTIVE;
    else if (service.enabled) {
        if (mode != service.mode || strcmp(launch, service.launch_id)) error = HV_DEVICE_AUTH_MODE_CONFLICT;
    } else {
        for (size_t i = 0; i < service.launch_count; i++) {
            if (!strcmp(launch, service.used_launches[i])) { error = HV_DEVICE_AUTH_LAUNCH_REUSED; break; }
        }
        if (error == HV_DEVICE_AUTH_OK && service.launch_count >= LAUNCH_HISTORY_MAX)
            error = HV_DEVICE_AUTH_LAUNCH_LIMIT;
        if (error == HV_DEVICE_AUTH_OK) {
            memcpy(service.used_launches[service.launch_count++], launch, sizeof(launch));
            memcpy(service.launch_id, launch, sizeof(launch));
            service.mode = mode;
            service.enabled = 1;
            host_event_locked(HV_DEVICE_AUTH_STAGE_HOST_BRIDGE_ENABLED, HV_DEVICE_AUTH_OK, now, 0, 0);
        }
    }
    pthread_mutex_unlock(&service.mutex);
    return error;
}

void hv_device_auth_disable(void) {
    lock_service();
    revoke_locked(HV_DEVICE_AUTH_CANCELLED, now_ms());
    pthread_mutex_unlock(&service.mutex);
}

void hv_device_auth_snapshot(HvDeviceAuthState *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    lock_service();
    uint64_t now = now_ms();
    refresh_locked(now);
    memcpy(out->session, service.session, sizeof(out->session));
    memcpy(out->launch_id, service.launch_id, sizeof(out->launch_id));
    out->mode = service.mode;
    out->enabled = service.enabled;
    out->running = service.running;
    out->foreground = service.foreground;
    out->fresh = fresh_locked(now);
    out->active = active_locked(now);
    out->busy = service.slot.phase != SLOT_EMPTY;
    out->state_age_ms = service.published && now >= service.published_ms ? (int64_t)(now - service.published_ms) : -1;
    out->accepted_requests = service.accepted;
    out->completed_requests = service.completed;
    out->refused_requests = service.refused;
    out->event_count = service.event_count;
    size_t start = (service.event_next + HV_DEVICE_AUTH_EVENT_COUNT - service.event_count) % HV_DEVICE_AUTH_EVENT_COUNT;
    for (size_t i = 0; i < service.event_count; i++) {
        size_t index = (start + i) % HV_DEVICE_AUTH_EVENT_COUNT;
        out->events[i] = service.events[index];
        out->events[i].age_ms = now >= service.event_times[index] ? now - service.event_times[index] : 0;
    }
    pthread_mutex_unlock(&service.mutex);
}

static HvDeviceAuthError reject_response(HvDeviceAuthResponse *out, HvDeviceAuthError error) {
    out->error = error;
    out->http_status = hv_device_auth_http_status(error);
    return error;
}

HvDeviceAuthError hv_device_auth_submit(const HvDeviceAuthRequest *request, HvDeviceAuthResponse *out) {
    if (!out) return HV_DEVICE_AUTH_INVALID_REQUEST;
    memset(out, 0, sizeof(*out));
    if (!request) return reject_response(out, HV_DEVICE_AUTH_INVALID_REQUEST);
    if (!request->method || strcmp(request->method, "POST")) return reject_response(out, HV_DEVICE_AUTH_METHOD_NOT_ALLOWED);
    if (request->invalid_headers) return reject_response(out, HV_DEVICE_AUTH_INVALID_HEADERS);
    if (request->has_origin) return reject_response(out, HV_DEVICE_AUTH_ORIGIN_FORBIDDEN);
    if (!json_content_type(request->content_type)) return reject_response(out, HV_DEVICE_AUTH_JSON_REQUIRED);
    if (request->body_length > HV_DEVICE_AUTH_BODY_MAX) return reject_response(out, HV_DEVICE_AUTH_BODY_TOO_LARGE);
    if (!request->body || !request->body_length || request->timeout_ms > HV_DEVICE_AUTH_TIMEOUT_MAX_MS ||
        request->operation < HV_DEVICE_AUTH_PROBE || request->operation > HV_DEVICE_AUTH_BAA_DICTIONARY)
        return reject_response(out, HV_DEVICE_AUTH_INVALID_REQUEST);
    if (!uuid_copy(out->session, request->session)) return reject_response(out, HV_DEVICE_AUTH_SESSION_REQUIRED);
    if (!uuid_copy(out->launch_id, request->launch_id)) return reject_response(out, HV_DEVICE_AUTH_LAUNCH_REQUIRED);
    if (!uuid_copy(out->request_id, request->request_id)) return reject_response(out, HV_DEVICE_AUTH_REQUEST_ID_REQUIRED);

    lock_service();
    uint64_t now = now_ms();
    refresh_locked(now);
    HvDeviceAuthError error = authorize_locked(out->session, out->launch_id, now);
    if (service.init_error) error = HV_DEVICE_AUTH_INTERNAL_ERROR;
    if (error == HV_DEVICE_AUTH_OK && request->operation >= HV_DEVICE_AUTH_BAA_DATA && service.mode != HV_DEVICE_AUTH_MODE_BAA)
        error = HV_DEVICE_AUTH_MODE_FORBIDDEN;
    if (error == HV_DEVICE_AUTH_OK && request->operation == HV_DEVICE_AUTH_DC_TOKEN && service.mode == HV_DEVICE_AUTH_MODE_BAA)
        error = HV_DEVICE_AUTH_MODE_FORBIDDEN;
    if (error == HV_DEVICE_AUTH_OK && service.slot.phase != SLOT_EMPTY) error = HV_DEVICE_AUTH_BUSY;
    if (error == HV_DEVICE_AUTH_OK && !service.wakeup) error = HV_DEVICE_AUTH_BACKEND_UNAVAILABLE;
    if (now >= service.refill_ms) {
        uint64_t refill = (now - service.refill_ms) / REQUEST_REFILL_MS;
        if (refill) {
            service.tokens = refill >= REQUEST_BURST - service.tokens ? REQUEST_BURST : service.tokens + (unsigned)refill;
            service.refill_ms += refill * REQUEST_REFILL_MS;
        }
    }
    if (error == HV_DEVICE_AUTH_OK && !service.tokens) {
        error = HV_DEVICE_AUTH_RATE_LIMITED;
        out->retry_after_ms = (uint32_t)(REQUEST_REFILL_MS - (now - service.refill_ms));
    }
    if (error == HV_DEVICE_AUTH_OK && service.next_ticket == UINT64_MAX) error = HV_DEVICE_AUTH_INTERNAL_ERROR;
    if (error != HV_DEVICE_AUTH_OK) {
        service.refused++;
        pthread_mutex_unlock(&service.mutex);
        return reject_response(out, error);
    }
    unsigned char *copy = malloc(request->body_length);
    if (!copy) {
        service.refused++;
        pthread_mutex_unlock(&service.mutex);
        return reject_response(out, HV_DEVICE_AUTH_NO_MEMORY);
    }
    memcpy(copy, request->body, request->body_length);
    Slot *slot = &service.slot;
    slot->phase = SLOT_QUEUED;
    slot->waiter = 1;
    slot->ticket = ++service.next_ticket;
    slot->started_ms = now;
    uint32_t timeout = request->timeout_ms ? request->timeout_ms : HV_DEVICE_AUTH_TIMEOUT_DEFAULT_MS;
    slot->deadline_ms = now + timeout;
    memcpy(slot->session, out->session, sizeof(slot->session));
    memcpy(slot->launch_id, out->launch_id, sizeof(slot->launch_id));
    memcpy(slot->request_id, out->request_id, sizeof(slot->request_id));
    slot->mode = service.mode;
    slot->operation = request->operation;
    slot->input = copy;
    slot->input_length = request->body_length;
    slot->original_input_length = (uint32_t)request->body_length;
    service.tokens--;
    service.accepted++;
    host_event_locked(HV_DEVICE_AUTH_STAGE_HOST_REQUEST_QUEUED, HV_DEVICE_AUTH_OK, now, 1, 0);
    uint64_t ticket = slot->ticket;
    HvDeviceAuthWakeup wakeup = service.wakeup;
    void *context = service.wakeup_context;
    pthread_mutex_unlock(&service.mutex);
    wakeup(context);
    pthread_mutex_lock(&service.mutex);

    for (;;) {
        now = now_ms();
        refresh_locked(now);
        if (slot->ticket != ticket || slot->phase == SLOT_EMPTY) {
            error = HV_DEVICE_AUTH_INTERNAL_ERROR;
            break;
        }
        if (slot->phase == SLOT_DONE || slot->cancelled) {
            error = slot->error;
            out->http_status = slot->http_status;
            out->error = error;
            out->body = slot->output;
            out->body_length = slot->output_length;
            slot->output = NULL;
            slot->output_length = 0;
            slot->waiter = 0;
            if (slot->phase == SLOT_DONE) reset_slot_locked();
            break;
        }
        uint64_t deadline = slot->deadline_ms;
        uint64_t stale_at = service.published_ms + HV_DEVICE_AUTH_STATE_MAX_AGE_MS + 1u;
        if (service.published && stale_at < deadline) deadline = stale_at;
        int wait_error = wait_until_locked(deadline);
        if (wait_error && wait_error != ETIMEDOUT && wait_error != EINTR)
            cancel_locked(HV_DEVICE_AUTH_INTERNAL_ERROR, now_ms());
    }
    pthread_mutex_unlock(&service.mutex);
    if (!out->http_status) reject_response(out, error);
    return error;
}

int hv_device_auth_take(HvDeviceAuthJob *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    lock_service();
    uint64_t now = now_ms();
    refresh_locked(now);
    Slot *slot = &service.slot;
    int found = slot->phase == SLOT_QUEUED && !slot->cancelled;
    if (found) {
        HvDeviceAuthError error = authorize_locked(slot->session, slot->launch_id, now);
        if (error != HV_DEVICE_AUTH_OK) { cancel_locked(error, now); found = 0; }
    }
    if (found) {
        out->ticket = slot->ticket;
        memcpy(out->session, slot->session, sizeof(out->session));
        memcpy(out->launch_id, slot->launch_id, sizeof(out->launch_id));
        memcpy(out->request_id, slot->request_id, sizeof(out->request_id));
        out->mode = slot->mode;
        out->operation = slot->operation;
        out->body = slot->input;
        out->body_length = slot->input_length;
        out->remaining_ms = (uint32_t)(slot->deadline_ms - now);
        slot->input = NULL;
        slot->input_length = 0;
        slot->phase = SLOT_RUNNING;
        host_event_locked(HV_DEVICE_AUTH_STAGE_HOST_REQUEST_STARTED, HV_DEVICE_AUTH_OK, now, 1, 0);
    }
    pthread_mutex_unlock(&service.mutex);
    return found;
}

static int matches_slot_locked(uint64_t ticket, const char *session, const char *launch_id,
                                const char *request_id) {
    char normalized_session[HV_DEVICE_AUTH_UUID_SIZE], launch[HV_DEVICE_AUTH_UUID_SIZE], request[HV_DEVICE_AUTH_UUID_SIZE];
    return service.slot.phase == SLOT_RUNNING && ticket && service.slot.ticket == ticket &&
        uuid_copy(normalized_session, session) && uuid_copy(launch, launch_id) && uuid_copy(request, request_id) &&
        !strcmp(normalized_session, service.slot.session) && !strcmp(launch, service.slot.launch_id) &&
        !strcmp(request, service.slot.request_id);
}

int hv_device_auth_job_is_current(uint64_t ticket, const char *session, const char *launch_id,
                                  const char *request_id) {
    lock_service();
    uint64_t now = now_ms();
    refresh_locked(now);
    int current = matches_slot_locked(ticket, session, launch_id, request_id) && !service.slot.cancelled &&
        authorize_locked(service.slot.session, service.slot.launch_id, now) == HV_DEVICE_AUTH_OK;
    pthread_mutex_unlock(&service.mutex);
    return current;
}

int hv_device_auth_complete(uint64_t ticket, const char *session, const char *launch_id,
                            const char *request_id, int http_status, HvDeviceAuthError error,
                            const void *body, size_t body_length) {
    lock_service();
    uint64_t now = now_ms();
    refresh_locked(now);
    if (!matches_slot_locked(ticket, session, launch_id, request_id)) {
        pthread_mutex_unlock(&service.mutex);
        return 0;
    }
    Slot *slot = &service.slot;
    HvDeviceAuthError authority = authorize_locked(slot->session, slot->launch_id, now);
    if (authority != HV_DEVICE_AUTH_OK) cancel_locked(authority, now);
    if (slot->cancelled || !slot->waiter) {
        slot->phase = SLOT_DONE;
        if (!slot->waiter) reset_slot_locked();
        notify_locked();
        pthread_mutex_unlock(&service.mutex);
        return 1;
    }
    if (error < HV_DEVICE_AUTH_OK || error > HV_DEVICE_AUTH_INTERNAL_ERROR ||
        http_status < 200 || http_status > 599 ||
        (error == HV_DEVICE_AUTH_OK && (http_status != 200 || !body_length))) {
        error = HV_DEVICE_AUTH_BACKEND_FAILED;
        body_length = 0;
    }
    if (body_length > HV_DEVICE_AUTH_RESPONSE_MAX) {
        error = HV_DEVICE_AUTH_RESPONSE_TOO_LARGE;
        body_length = 0;
    }
    if (body_length && !body) { error = HV_DEVICE_AUTH_BACKEND_FAILED; body_length = 0; }
    if (body_length) {
        slot->output = malloc(body_length);
        if (!slot->output) { error = HV_DEVICE_AUTH_NO_MEMORY; body_length = 0; }
        else memcpy(slot->output, body, body_length);
    }
    slot->output_length = body_length;
    slot->error = error;
    slot->http_status = body_length ? http_status : hv_device_auth_http_status(error);
    slot->phase = SLOT_DONE;
    service.completed++;
    host_event_locked(error == HV_DEVICE_AUTH_OK ? HV_DEVICE_AUTH_STAGE_HOST_REQUEST_COMPLETED :
                      HV_DEVICE_AUTH_STAGE_HOST_REQUEST_FAILED, error, now, 1, (uint32_t)body_length);
    notify_locked();
    pthread_mutex_unlock(&service.mutex);
    return 1;
}

void hv_device_auth_job_dispose(HvDeviceAuthJob *job) {
    if (!job) return;
    clear_free(&job->body, &job->body_length);
    memset(job, 0, sizeof(*job));
}

void hv_device_auth_response_dispose(HvDeviceAuthResponse *response) {
    if (!response) return;
    clear_free(&response->body, &response->body_length);
    memset(response, 0, sizeof(*response));
}

HvDeviceAuthError hv_device_auth_response_revalidate(HvDeviceAuthResponse *response) {
    if (!response) return HV_DEVICE_AUTH_INVALID_REQUEST;
    if (!response->body) return HV_DEVICE_AUTH_OK;
    lock_service();
    uint64_t now = now_ms();
    refresh_locked(now);
    HvDeviceAuthError error = authorize_locked(response->session, response->launch_id, now);
    if (error != HV_DEVICE_AUTH_OK) {
        clear_free(&response->body, &response->body_length);
        reject_response(response, error);
    }
    pthread_mutex_unlock(&service.mutex);
    return error;
}

HvDeviceAuthError hv_device_auth_record_event(const char *session, const char *launch_id,
                                             const HvDeviceAuthEvent *event) {
    char normalized_session[HV_DEVICE_AUTH_UUID_SIZE], launch[HV_DEVICE_AUTH_UUID_SIZE];
    HvDeviceAuthEvent copy = {0};
    if (!uuid_copy(normalized_session, session)) return HV_DEVICE_AUTH_SESSION_REQUIRED;
    if (!uuid_copy(launch, launch_id)) return HV_DEVICE_AUTH_LAUNCH_REQUIRED;
    if (!event || !uuid_copy(copy.request_id, event->request_id)) return HV_DEVICE_AUTH_REQUEST_ID_REQUIRED;
    if (event->stage < HV_DEVICE_AUTH_STAGE_LAUNCH_REQUESTED || event->stage > HV_DEVICE_AUTH_STAGE_SESSION_INACTIVE ||
        event->error_domain < HV_DEVICE_AUTH_DOMAIN_NONE || event->error_domain > HV_DEVICE_AUTH_DOMAIN_OTHER ||
        event->elapsed_ms > 300000u || event->input_bytes > HV_DEVICE_AUTH_BODY_MAX || event->result_bytes > HV_DEVICE_AUTH_RESPONSE_MAX)
        return HV_DEVICE_AUTH_INVALID_REQUEST;
    copy.stage = event->stage;
    copy.error_domain = event->error_domain;
    copy.error_code = event->error_code;
    copy.elapsed_ms = event->elapsed_ms;
    copy.input_bytes = event->input_bytes;
    copy.result_bytes = event->result_bytes;
    lock_service();
    uint64_t now = now_ms();
    refresh_locked(now);
    HvDeviceAuthError error = authorize_locked(normalized_session, launch, now);
    if (error == HV_DEVICE_AUTH_OK) event_locked(&copy, 1, now);
    pthread_mutex_unlock(&service.mutex);
    return error;
}

static const char *const error_names[] = {
    "ok", "invalid_request", "method_not_allowed", "invalid_headers", "origin_forbidden", "json_required",
    "body_too_large", "session_required", "session_changed", "launch_required", "launch_changed",
    "request_id_required", "host_inactive", "not_enabled", "mode_forbidden", "mode_conflict", "launch_reused",
    "launch_limit", "busy", "rate_limited", "timed_out", "backend_unavailable", "backend_failed",
    "response_too_large", "no_memory", "cancelled", "internal_error"
};

const char *hv_device_auth_error_name(HvDeviceAuthError error) {
    return error >= HV_DEVICE_AUTH_OK && error <= HV_DEVICE_AUTH_INTERNAL_ERROR ? error_names[error] : "internal_error";
}

int hv_device_auth_http_status(HvDeviceAuthError error) {
    switch (error) {
    case HV_DEVICE_AUTH_OK: return 200;
    case HV_DEVICE_AUTH_METHOD_NOT_ALLOWED: return 405;
    case HV_DEVICE_AUTH_JSON_REQUIRED: return 415;
    case HV_DEVICE_AUTH_BODY_TOO_LARGE: return 413;
    case HV_DEVICE_AUTH_ORIGIN_FORBIDDEN:
    case HV_DEVICE_AUTH_MODE_FORBIDDEN: return 403;
    case HV_DEVICE_AUTH_SESSION_REQUIRED:
    case HV_DEVICE_AUTH_SESSION_CHANGED:
    case HV_DEVICE_AUTH_LAUNCH_REQUIRED:
    case HV_DEVICE_AUTH_LAUNCH_CHANGED: return 409;
    case HV_DEVICE_AUTH_HOST_INACTIVE:
    case HV_DEVICE_AUTH_NOT_ENABLED:
    case HV_DEVICE_AUTH_MODE_CONFLICT:
    case HV_DEVICE_AUTH_LAUNCH_REUSED:
    case HV_DEVICE_AUTH_CANCELLED: return 409;
    case HV_DEVICE_AUTH_BUSY:
    case HV_DEVICE_AUTH_RATE_LIMITED:
    case HV_DEVICE_AUTH_LAUNCH_LIMIT: return 429;
    case HV_DEVICE_AUTH_TIMED_OUT: return 504;
    case HV_DEVICE_AUTH_BACKEND_UNAVAILABLE: return 503;
    case HV_DEVICE_AUTH_BACKEND_FAILED:
    case HV_DEVICE_AUTH_RESPONSE_TOO_LARGE: return 502;
    case HV_DEVICE_AUTH_NO_MEMORY:
    case HV_DEVICE_AUTH_INTERNAL_ERROR: return 500;
    default: return 400;
    }
}

const char *hv_device_auth_mode_name(HvDeviceAuthMode mode) {
    return mode == HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN ? "public_token" : mode == HV_DEVICE_AUTH_MODE_BAA ? "baa" : "none";
}

const char *hv_device_auth_operation_name(HvDeviceAuthOperation operation) {
    static const char *const names[] = { "probe", "dc_token", "baa_data", "baa_dictionary" };
    return operation >= HV_DEVICE_AUTH_PROBE && operation <= HV_DEVICE_AUTH_BAA_DICTIONARY ? names[operation] : "invalid";
}

static const char *const stage_names[] = {
    "none", "launch_requested", "target_not_found", "target_identity_mismatch", "target_signature_invalid",
    "signature_policy_blocked", "already_running", "launch_started", "launch_failed", "launch_timeout",
    "adapter_loaded", "adapter_not_loaded", "adapter_target_rejected", "adapter_abi_mismatch", "adapter_ready",
    "probe_requested", "probe_result", "token_requested", "token_result", "baa_data_requested", "baa_data_result",
    "baa_dictionary_requested", "baa_dictionary_result", "request_declined", "transport_failed", "response_invalid",
    "session_inactive", "host_request_queued", "host_request_started", "host_request_completed", "host_request_failed",
    "host_request_cancelled", "host_bridge_enabled", "host_bridge_disabled"
};

const char *hv_device_auth_stage_name(HvDeviceAuthStage stage) {
    return stage >= HV_DEVICE_AUTH_STAGE_NONE && stage <= HV_DEVICE_AUTH_STAGE_HOST_BRIDGE_DISABLED ? stage_names[stage] : "none";
}

HvDeviceAuthStage hv_device_auth_stage_from_name(const char *name) {
    if (name) for (int i = HV_DEVICE_AUTH_STAGE_LAUNCH_REQUESTED; i <= HV_DEVICE_AUTH_STAGE_SESSION_INACTIVE; i++)
        if (!strcmp(name, stage_names[i])) return (HvDeviceAuthStage)i;
    return HV_DEVICE_AUTH_STAGE_NONE;
}

static const char *const domain_names[] = {
    "", "HengeAuthBridge", "NSURLErrorDomain", "NSPOSIXErrorDomain", "NSOSStatusErrorDomain", "DCErrorDomain",
    "DeviceCheckErrorDomain", "com.apple.devicecheck.error", "com.apple.MobileActivation.ErrorDomain",
    "IDSBAASignerErrorDomain", "NSCocoaErrorDomain", "HengeDeviceAuthHost", "other"
};

const char *hv_device_auth_domain_name(HvDeviceAuthDomain domain) {
    return domain >= HV_DEVICE_AUTH_DOMAIN_NONE && domain <= HV_DEVICE_AUTH_DOMAIN_OTHER ? domain_names[domain] : "other";
}

HvDeviceAuthDomain hv_device_auth_domain_from_name(const char *name) {
    if (!name || !*name) return HV_DEVICE_AUTH_DOMAIN_NONE;
    for (int i = HV_DEVICE_AUTH_DOMAIN_NONE; i <= HV_DEVICE_AUTH_DOMAIN_OTHER; i++)
        if (!strcmp(name, domain_names[i])) return (HvDeviceAuthDomain)i;
    return HV_DEVICE_AUTH_DOMAIN_OTHER;
}
