#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Darwin ]; then
    printf '#include "ios/Henge/Native/HengeDeviceAuthHost.h"\nint main(void) { return HENGE_DEVICE_AUTH_PROBE; }\n' |
        cc -x c -std=c11 -Wall -Wextra -Werror -fsyntax-only -I. -
    echo 'SKIP: C interface checked; Objective-C synthetic tests require macOS Foundation.'
    exit 77
fi
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/henge-device-auth-host.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
xcrun clang -std=c11 -fobjc-arc -fblocks -Wall -Wextra -Werror \
    -DHENGE_DEVICE_AUTH_HOST_TESTING=1 -mmacosx-version-min=13.0 \
    ios/Henge/Native/HengeDeviceAuthHost.m tests/test_device_auth_host.m \
    -framework Foundation -o "$test_dir/test-device-auth-host"
"$test_dir/test-device-auth-host"
