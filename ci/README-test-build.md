# Henge 0.4 test packages

The test release is version **0.4.0**, build **4003**. This build setup starts
from the successful `2ed42fcf61f2f71eae15b57b8b4d8014fef9ab0f` workflow and
keeps its `xcode-27` runner and dependency build procedure. It does not contain
a prebuilt 0.4 app. A successful macOS build is required to produce one.

## Build on an authorized GitHub repository

Commit the complete test source, including the version change, host-services
tests and diagnostics tests, on a branch in a repository you control. Use
**Actions → Build Henge 0.4 test packages → Run workflow**, and select that
branch. The existing workflow file must also be present on the default branch
for GitHub to offer manual dispatch.

The workflow checks out the selected commit SHA, builds and validates a
TrollStore **Henge.tipa** first, and uploads it with a JSON manifest and SHA-256
checksum. Select `include_ipa` only if an additional sideloading IPA is needed.
On `litebeyond123/Henge`, a successful push build of
`work/0.4-ipados17-test` also publishes the validated package as the
`v0.4.0-test3` prerelease. The publication job checks the package digest,
version, build and full source commit against this run's manifest before
uploading it. That separate job alone has repository write permission.
Other repositories and branches only receive build artifacts. The workflow
does not open a PR or overwrite an existing release tag.

Husk is pinned to `29abb512d81bf8cc08babcbe7f7007cb557208ef`, recovered from
the successful base build's checkout log. The workflow records both source
commits and the Xcode/SDK versions, and includes Husk's commit in the cache key.

The build runs the package-validator regression tests, host-services tests,
small-surface layout/Metal tests, Foundation-only Swift diagnostics tests, and
the Swift/Objective-C guest Chat summary protocol tests before compiling the
app. A missing compatible Metal device is reported
as a native pixel-test skip, not a pass. Logs are
uploaded even when a subsequent build or validation step fails. The log
artifact includes source/toolchain provenance and separate Xcode logs for TIPA
and IPA packaging.

## Local checks

The package validator uses only Python 3's standard library and runs on Linux
or macOS. Its tests use small structural fixtures that cannot be installed:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ci/tests -v
zsh -n ios/scripts/package_ipa.sh
bash tests/run_pvg_texture_copy.sh
```

The texture test script runs portable layout checks and, on macOS, compiles and
runs the native Metal pixel checks when a compatible GPU is available. Exit 77
means that the native GPU test could not run. Test 2's texture compatibility
notes remain in `docs/0.4-test2-zh-CN.md`; Test 3's automatic Chat diagnostics,
sharing changes and runtime limitations are in `docs/release-test3.md`.

Validate an actual downloaded build against the full source commit used by its
workflow. The default expected version/build are 0.4.0/4003:

```sh
python3 ci/validate-package.py /path/to/Henge.tipa \
  --expected-commit FULL_40_CHARACTER_GIT_COMMIT \
  --manifest /path/to/Henge.tipa.manifest.json \
  --sha256-file /path/to/Henge.tipa.sha256
```

The validator checks the ZIP, required resources, build/version/commit stamps,
the main executable's arm64 architecture and iOS minimum of at most 17.0, and
embedded code signatures. For a TIPA it rejects the banned TrollStore
entitlements in both XML and DER entitlement slots, including nested Mach-O
executables. The newer, guarded JIT helper may target a newer iOS; the iOS 17
check applies to the main executable and its app Info.plist.

This portable validator inspects signature structure. The macOS packager also
runs `codesign --verify --deep --strict` to verify the signed bundle itself.
Neither check establishes that the app runs correctly on a physical iPad.

## Local macOS packaging

Prepare the dependencies using the main README and use Xcode 27 or later.
Commit all source changes first so the package's commit stamp describes the
actual source. Then run:

```sh
zsh ios/scripts/package_ipa.sh --trollstore
```

`HENGE_PACKAGE_OUTPUT_DIR` can redirect the output from `~/Desktop`, and
`HENGE_BUILD_LOG_DIR` can collect separate Xcode logs. The packager removes the
previous output package and reports before attempting a new build, verifies
the staged archive, and publishes the new package only after every check
passes. A failed build cannot leave an older package at the advertised path.
