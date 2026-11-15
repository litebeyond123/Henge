/* Real production listener/routes for the macOS launchd/LaunchServices smoke gate.
   This fixture exposes only a temporary test folder; the TCP proxy blocks clipboard and mount traffic. */
#include "../host/share.c"
#include <signal.h>

int main(int argc, char **argv) {
    if (argc != 4 || !host_uuid(argv[3])) return 2;
    signal(SIGPIPE, SIG_IGN);
    if (hv_share_start(argv[1], argv[2], NULL)) return 1;
    hv_share_host_begin(argv[3]);
    hv_share_host_publish(1, 1, 0, 0.5, 0.25);
    puts("ready");
    fflush(stdout);
    char command[32];
    while (fgets(command, sizeof command, stdin)) {
        if (!strcmp(command, "quit\n")) break;
    }
    hv_share_host_end();
    return 0;
}
