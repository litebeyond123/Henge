#!/usr/bin/env python3
"""Compile/run the real C queue with synthetic callbacks; never call Apple identity APIs."""
import os
from pathlib import Path
import re
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
        exercised = re.search(rb"^enable_calls_exercised=(\d+)$", result.stdout, re.MULTILINE)
        records = [line for line in result.stderr.splitlines() if line.startswith(b"[device-auth] action=enable ")]
        record_pattern = re.compile(
            rb"\[device-auth\] action=enable attempt=(\d+) successes=(\d+) failures=(\d+) "
            rb"mode=(public_token|baa|invalid) result=(ok|launch_required|invalid_request|internal_error|host_inactive|mode_conflict|action_conflict|launch_reused|launch_limit) "
            rb"backend_registered=[01] enabled=[01] running=([01]) foreground=([01]) fresh=([01]) active=([01]) state_age_ms=(-1|\d+) launch_action=(?:normal_quit|force_quit|invalid)"
        )
        if exercised is None or len(records) != int(exercised[1]):
            print("FAIL an enable call did not produce exactly one fixed diagnostic record", file=sys.stderr)
            return 1
        for record in records:
            match = record_pattern.fullmatch(record)
            if match is None or int(match[1]) != int(match[2]) + int(match[3]):
                print("FAIL an enable diagnostic record contains unexpected fields or inconsistent counters", file=sys.stderr)
                return 1
            if match[9] == b"1" and any(match[index] != b"1" for index in (6, 7, 8)):
                print("FAIL enable active state contradicts its contemporaneous runtime flags", file=sys.stderr)
                return 1
        print(f"PASS every enable call has one fixed diagnostic record ({len(records)} calls)")
        accepted = re.search(rb"^accepted_guest_events_exercised=(\d+)$", result.stdout, re.MULTILINE)
        guest_records = [line for line in result.stderr.splitlines() if line.startswith(b"[device-auth-guest] ")]
        guest_pattern = re.compile(
            rb"\[device-auth-guest\] launch=[0-9A-Fa-f-]{36} request=[0-9A-Fa-f-]{36} stage=[a-z_]+ "
            rb"domain=[A-Za-z.]* code=-?\d+ elapsed_ms=\d+ target_pid=\d+ observed_pid=\d+"
            rb"(?: process_phase=\d+ process_source=\d+ process_state=\d+ process_flags=\d+ process_status=\d+ "
            rb"process_retries=\d+ process_sample_ms=\d+ operation_invoked=[01] operation_result=-?[01] phase_elapsed_ms=\d+)?"
        )
        if accepted is None or len(guest_records) != int(accepted[1]) or any(not guest_pattern.fullmatch(r) for r in guest_records):
            print("FAIL accepted guest stages must each produce one fixed persistent journal record", file=sys.stderr)
            return 1
        if not any(b"process_phase=4 process_source=4" in r for r in guest_records):
            print("FAIL process observation was not preserved in the native journal", file=sys.stderr)
            return 1
        print(f"PASS every accepted guest stage has one persistent fixed diagnostic record ({len(guest_records)} events)")
        print("PASS native log contains no synthetic challenge/result material")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
