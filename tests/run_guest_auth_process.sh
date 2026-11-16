#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(uname -s)" = Darwin ]; then
    # /var is a filesystem alias of /private/var on macOS. Exercise that exact
    # caller/kernel boundary with our own executable, independently of TMPDIR.
    build=$(mktemp -d /var/tmp/henge-process-tests.XXXXXX)
else
    build=$(mktemp -d "${TMPDIR:-/tmp}/henge-process-tests.XXXXXX")
fi
trap 'rm -rf "$build"' EXIT HUP INT TERM

if [ "$(uname -s)" = Darwin ]; then
    xcrun --sdk macosx clang -std=gnu11 -Wall -Wextra -Werror -O1 \
        -mmacosx-version-min=13.0 -I"$repo/tools" \
        "$repo/tools/guest-auth-process.m" "$repo/tests/test_guest_auth_process.c" \
        "$repo/tests/guest_auth_process_foundation.m" \
        -framework Foundation -lproc -o "$build/process-tests"
    cp "$build/process-tests" "$build/unrelated-owned-fixture"
    "$build/process-tests" "$build/unrelated-owned-fixture" "$build/unrelated-renamed-fixture"
else
    "${CC:-cc}" -x c -std=gnu11 -Wall -Wextra -Werror -O1 -I"$repo/tools" \
        "$repo/tools/guest-auth-process.m" "$repo/tests/test_guest_auth_process.c" \
        -o "$build/process-tests"
    "$build/process-tests"
    exit 77
fi
