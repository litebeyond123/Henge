/* A fake UI thread around the real share.c server, controlled by the Python integration test. */
/* Including the implementation lets the socketpair transport enter the same connection handler without
   opening a listener. HENGE_TEST_LISTENER=1 in the Python runner exercises the normal listener as well. */
#include "../host/share.c"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int calls;
static double applied;
static double apply(double value) { calls++; applied = value; return value; }
static double refuse(double value) { (void)value; calls++; return -1; }

static void *courier(void *opaque) {
    int fd = (int)(intptr_t)opaque;
    for (;;) {
        char byte, ancillary[CMSG_SPACE(sizeof(int))];
        struct iovec io = {.iov_base = &byte, .iov_len = 1};
        struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = ancillary, .msg_controllen = sizeof ancillary};
        if (recvmsg(fd, &message, 0) <= 0) break;
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) continue;
        int client;
        memcpy(&client, CMSG_DATA(header), sizeof client);
        Conn *c = calloc(1, sizeof *c);
        c->fd = client;
        pthread_t thread;
        if (pthread_create(&thread, NULL, connection, c)) { close(client); free(c); }
        else pthread_detach(thread);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    signal(SIGPIPE, SIG_IGN);
    if (!strncmp(argv[2], "fd:", 3)) {
        if (!realpath(argv[1], root)) return 1;
        pthread_t thread;
        if (pthread_create(&thread, NULL, courier, (void *)(intptr_t)atoi(argv[2] + 3))) return 1;
        pthread_detach(thread);
    } else if (hv_share_start(argv[1], argv[2], NULL)) return 1;
    puts("ready");
    fflush(stdout);
    char line[512];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (!strncmp(line, "begin ", 6)) hv_share_host_begin(line + 6);
        else if (!strcmp(line, "end")) hv_share_host_end();
        else if (!strncmp(line, "agent-path ", 11)) snprintf(agent_path, sizeof agent_path, "%s", line + 11);
        else if (!strncmp(line, "publish ", 8)) {
            int running, foreground, allowed;
            double brightness, volume;
            if (sscanf(line + 8, "%d %d %d %lf %lf", &running, &foreground, &allowed, &brightness, &volume) != 5) return 2;
            hv_share_host_publish(running, foreground, allowed, brightness, volume);
        } else if (!strcmp(line, "apply") || !strcmp(line, "refuse")) {
            int result = hv_share_host_process_brightness(!strcmp(line, "apply") ? apply : refuse);
            printf("applied %d calls %d value %.9f\n", result, calls, applied);
            fflush(stdout);
            continue;
        } else if (!strcmp(line, "calls")) {
            printf("calls %d\n", calls);
            fflush(stdout);
            continue;
        } else if (!strncmp(line, "clipboard ", 10)) hv_share_set_clipboard(line + 10);
        else if (!strcmp(line, "take-clipboard")) {
            char *text = hv_share_take_clipboard();
            printf("clipboard %s\n", text ? text : "");
            free(text);
            fflush(stdout);
            continue;
        } else if (!strcmp(line, "quit")) break;
        else return 2;
        puts("ok");
        fflush(stdout);
    }
    return 0;
}
