#ifndef HENGE_DEVICE_AUTH_SUBPROCESS_HOOKS_H
#define HENGE_DEVICE_AUTH_SUBPROCESS_HOOKS_H
#include <sys/types.h>
/* Only the production subprocess translation unit gets the waitpid macro.
 * This lets the fixture deterministically exercise EINTR without timing races. */
pid_t HengeAuthTestWaitPID(pid_t pid, int *status, int options);
#endif
