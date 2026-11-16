#import <Foundation/Foundation.h>
#include <errno.h>
#include <string.h>

/* Exercise the exact Foundation operation formerly used by the guest caller.
 * It is test-only, and never prints the fixture's path. */
int HengeTestFoundationResolvedPath(const char *path, char *output, size_t capacity) {
    if (!path || !output || !capacity) return EINVAL;
    output[0] = '\0';
    @autoreleasepool {
        NSString *source = [NSString stringWithUTF8String:path];
        const char *resolved = source.stringByResolvingSymlinksInPath.fileSystemRepresentation;
        if (!resolved) return EINVAL;
        size_t length = strlen(resolved);
        if (length >= capacity) return ENAMETOOLONG;
        memcpy(output, resolved, length + 1);
    }
    return 0;
}
