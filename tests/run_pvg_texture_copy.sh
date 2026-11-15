#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
test_build_dir=$(mktemp -d "${TMPDIR:-/tmp}/henge-texture-copy.XXXXXX")
trap 'rm -rf "$test_build_dir"' EXIT

env -u SDKROOT -u IPHONEOS_DEPLOYMENT_TARGET cc -std=c11 -Wall -Wextra -Werror -O2 \
    tests/test_pvg_texture_copy.c -o "$test_build_dir/layout"
"$test_build_dir/layout"

if [[ $(uname -s) != Darwin ]]; then
    echo 'SKIP: native Metal compilation and pixels require macOS/Xcode; portable checks passed'
    exit 77
fi

# Always compile the actual helper-based native test before checking for a GPU.
env -u SDKROOT -u IPHONEOS_DEPLOYMENT_TARGET xcrun --sdk macosx clang \
    -fobjc-arc -mmacosx-version-min=12.0 -Wall -Wextra -Werror -O2 \
    tests/test_pvg_texture_copy.m -framework Foundation -framework Metal -o "$test_build_dir/metal"
MTL_DEBUG_LAYER=1 "$test_build_dir/metal"
