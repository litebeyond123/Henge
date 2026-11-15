#include <errno.h>
#define REMOVEFILE_RECURSIVE 1
static inline int removefile(const char *a, void *state, int flags) {
    (void)a; (void)state; (void)flags;
    errno = ENOTSUP;
    return -1;
}
