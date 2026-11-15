/* Linux-only compile shims for the HTTP integration test. The tested socket, parsing, queue and file
   PUT/GET paths are the production implementation. Apple-only recursive COPY/DELETE are not tested. */
#include <sys/vfs.h>
#define st_mtimespec st_mtim
#define st_birthtimespec st_ctim
#define SO_NOSIGPIPE (-1)
