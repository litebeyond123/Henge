/* Reuse the real share.c connection/listener and the existing socketpair courier, without changing
   the host-services fixture. -I<repository> selects the source tree under review. */
#define main henge_host_services_fixture_main
#include "tests/host_services_driver.c"
#undef main
#include <stdatomic.h>

static atomic_uint auth_wakes;
static unsigned auth_takes;
static HvDeviceAuthJob auth_job;

static void auth_wakeup(void *context) {
    (void)context;
    atomic_fetch_add(&auth_wakes, 1);
}

static int finish_synthetic(int error) {
    if (!auth_job.ticket) return 0;
    char body[1200];
    int length = snprintf(body, sizeof(body),
        "{\"protocol\":1,\"session\":\"%s\",\"launch_id\":\"%s\",\"request_id\":\"%s\","
        "\"status\":\"%s\",%s\"diagnostics\":{\"errorDomain\":\"%s\",\"errorCode\":%d}}",
        auth_job.session, auth_job.launch_id, auth_job.request_id, error ? "error" : "ok",
        error ? "" : "\"resultBase64\":\"U1lOVEhFVElDX01BVEVSSUFM\",",
        error ? "com.apple.devicecheck.error" : "", error ? 4 : 0);
    if (length < 0 || (size_t)length >= sizeof(body)) return 0;
    /* This mirrors the wrapper's HTTP200/status=error contract; no Apple API is linked or called. */
    int result = hv_device_auth_complete(auth_job.ticket, auth_job.session, auth_job.launch_id,
        auth_job.request_id, 200, HV_DEVICE_AUTH_OK, body, (size_t)length);
    memset(body, 0, sizeof(body));
    hv_device_auth_job_dispose(&auth_job);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    signal(SIGPIPE, SIG_IGN);
    if (!hv_device_auth_set_wakeup(auth_wakeup, NULL)) return 2;
    if (!strncmp(argv[2], "fd:", 3)) {
        if (!realpath(argv[1], root)) return 1;
        pthread_t thread;
        if (pthread_create(&thread, NULL, courier, (void *)(intptr_t)atoi(argv[2] + 3))) return 1;
        pthread_detach(thread);
    } else if (hv_share_start(argv[1], argv[2], NULL)) return 1;
    puts("ready"); fflush(stdout);
    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (!strncmp(line, "begin ", 6)) hv_share_host_begin(line + 6);
        else if (!strcmp(line, "end")) hv_share_host_end();
        else if (!strncmp(line, "publish ", 8)) {
            int running, foreground;
            if (sscanf(line + 8, "%d %d", &running, &foreground) != 2) return 2;
            hv_share_host_publish(running, foreground, 0, 0.5, 0.25);
        } else if (!strncmp(line, "enable-action ", 14)) {
            char mode[32], action[32], launch[37], extra;
            if (sscanf(line + 14, "%31s %31s %36s %c", mode, action, launch, &extra) != 3) return 2;
            HvDeviceAuthMode value = !strcmp(mode, "public_token") ? HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN :
                !strcmp(mode, "baa") ? HV_DEVICE_AUTH_MODE_BAA : HV_DEVICE_AUTH_MODE_NONE;
            HvDeviceAuthAction operation = !strcmp(action, "normal_quit") ? HV_DEVICE_AUTH_ACTION_NORMAL_QUIT :
                !strcmp(action, "force_quit") ? HV_DEVICE_AUTH_ACTION_FORCE_QUIT : HV_DEVICE_AUTH_ACTION_INVALID;
            printf("enabled %s\n", hv_device_auth_error_name(hv_device_auth_enable_with_action(value, operation, launch)));
            fflush(stdout); continue;
        } else if (!strncmp(line, "enable ", 7)) {
            char mode[32], launch[37], extra;
            if (sscanf(line + 7, "%31s %36s %c", mode, launch, &extra) != 2) return 2;
            HvDeviceAuthMode value = !strcmp(mode, "public_token") ? HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN :
                !strcmp(mode, "baa") ? HV_DEVICE_AUTH_MODE_BAA : HV_DEVICE_AUTH_MODE_NONE;
            printf("enabled %s\n", hv_device_auth_error_name(hv_device_auth_enable(value, launch)));
            fflush(stdout); continue;
        } else if (!strcmp(line, "disable")) hv_device_auth_disable();
        else if (!strcmp(line, "take")) {
            HvDeviceAuthJob job = {0};
            int taken = !auth_job.ticket && hv_device_auth_take(&job);
            if (taken) { auth_job = job; auth_takes++; }
            printf("taken %d\n", taken); fflush(stdout); continue;
        } else if (!strcmp(line, "complete") || !strcmp(line, "complete-error")) {
            printf("completed %d\n", finish_synthetic(!strcmp(line, "complete-error")));
            fflush(stdout); continue;
        } else if (!strcmp(line, "stats")) {
            printf("wakes %u takes %u\n", atomic_load(&auth_wakes), auth_takes);
            fflush(stdout); continue;
        } else if (!strcmp(line, "quit")) {
            hv_share_host_end();
            if (auth_job.ticket) finish_synthetic(1);
            break;
        } else return 2;
        puts("ok"); fflush(stdout);
    }
    return 0;
}
