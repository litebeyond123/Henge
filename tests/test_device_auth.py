#!/usr/bin/env python3
"""Compile/run the real C queue with synthetic callbacks; never call Apple identity APIs."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="henge-device-auth-test-") as temporary:
        executable = Path(temporary) / "device-auth-tests"
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
            str(ROOT / "host/device_auth.c"), str(ROOT / "tests/test_device_auth.c"),
            "-o", str(executable),
        ]
        # An optional sanitizer switch changes instrumentation, never authentication behavior.
        if os.environ.get("HENGE_TEST_SANITIZE") == "1":
            command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g"]
        subprocess.run(command, cwd=ROOT, check=True, timeout=60)
        result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True, timeout=30)
        if any(marker in result.stdout + result.stderr for marker in (
            b"SYNTHETIC_INPUT_MATERIAL", b"SYNTHETIC_SECRET_MATERIAL",
        )):
            print("FAIL device-auth transport logged synthetic secret material", file=sys.stderr)
            return 1
        sys.stdout.write(result.stdout.decode("utf-8", "replace"))
        if result.returncode:
            sys.stderr.write(result.stderr.decode("utf-8", "replace"))
            return 1
        print("PASS native log contains no synthetic challenge/result material")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
