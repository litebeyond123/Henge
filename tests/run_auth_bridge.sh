#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Darwin ]; then
    echo 'SKIP: subprocess/bridge native tests require macOS Foundation; no Apple services are called by these tests.'
    exit 77
fi
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/henge-auth-bridge.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
native_flags='-std=c11 -fobjc-arc -fblocks -Wall -Wextra -Werror -mmacosx-version-min=13.0'
xcrun clang $native_flags tests/device_auth_fake_signer.m -framework Foundation -o "$test_dir/fake-signer"
# Compile the ACTUAL child main against a synthetic implementation, never the
# real DCDevice/DCBAASigner backend, so its framing and run-loop path are tested.
xcrun clang $native_flags tools/henge-auth-signer-main.m tests/device_auth_signer_fake_backend.m \
    -framework Foundation -o "$test_dir/synthetic-signer-main"
xcrun clang $native_flags -DHENGE_AUTH_SUBPROCESS_TEST=1 -Dwaitpid=HengeAuthTestWaitPID \
    -include tests/device_auth_subprocess_hooks.h -c ios/Henge/Native/HengeAuthSubprocess.m -o "$test_dir/subprocess.o"
xcrun clang $native_flags -DHENGE_AUTH_SUBPROCESS_TEST=1 tests/test_device_auth_subprocess.m \
    "$test_dir/subprocess.o" -framework Foundation -o "$test_dir/test-subprocess"
xcrun clang $native_flags -Ihost ios/Henge/Native/HengeAuthBridge.m tests/test_device_auth_bridge.m \
    -framework Foundation -o "$test_dir/test-bridge"
if ! "$test_dir/test-subprocess" "$test_dir/fake-signer" "$test_dir/synthetic-signer-main" "$test_dir" >"$test_dir/subprocess.log" 2>&1; then
    cat "$test_dir/subprocess.log"; exit 1
fi
if ! "$test_dir/test-bridge" >"$test_dir/bridge.log" 2>&1; then
    cat "$test_dir/bridge.log"; exit 1
fi
if grep -q 'SYNTHETIC-SECRET' "$test_dir/subprocess.log" "$test_dir/bridge.log"; then
    echo 'FAIL: a synthetic secret escaped into process logs'; exit 1
fi
cat "$test_dir/subprocess.log" "$test_dir/bridge.log"
