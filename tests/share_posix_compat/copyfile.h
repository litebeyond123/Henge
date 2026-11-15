#include <errno.h>
#define COPYFILE_ALL 1
#define COPYFILE_RECURSIVE 2
static inline int copyfile(const char *a, const char *b, void *state, int flags) {
    (void)a; (void)b; (void)state; (void)flags;
    errno = ENOTSUP;
    return -1;
}
