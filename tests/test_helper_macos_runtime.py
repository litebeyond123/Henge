#!/usr/bin/env python3
"""Actual macOS helper startup + production C HTTP roundtrip, with no stub launchctl or helper.

Legacy mode launches the unchanged executable as a real Aqua LaunchAgent. App mode uses LaunchServices
and requires the helper's explicit --smoke-test marker; clipboard/mount/login registration are not tested.
A temporary loopback alias reproduces the transport address, NOT macOS LAN privacy permission behavior.
"""
import argparse
import ctypes
import datetime
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import select
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = "10.0.2.4"


class GateError(Exception):
    pass


def command(args, *, check=True, timeout=15):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise GateError(f"command_failed:{Path(str(args[0])).name}:exit_{result.returncode}")
    return result


def first_line(process, seconds):
    if not select.select([process.stdout], [], [], seconds)[0]:
        raise GateError("child_readiness_timeout")
    value = process.stdout.readline()
    if not value:
        raise GateError(f"child_exited_before_ready:{process.poll()}")
    return value.strip()


def http(method, path, session=None):
    connection = http.client.HTTPConnection(ADDRESS, 80, timeout=5)
    try:
        headers = {"Connection": "close", "Content-Length": "0"}
        if session:
            headers["X-Henge-Session"] = session
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read(65537)
        if len(body) > 65536 or response.status != 200:
            raise GateError(f"runtime_http_status:{response.status}")
        return json.loads(body)
    finally:
        connection.close()


def process_path(pid):
    library = ctypes.CDLL("/usr/lib/libproc.dylib")
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    if library.proc_pidpath(pid, buffer, len(buffer)) <= 0:
        return None
    return Path(os.fsdecode(buffer.value)).resolve()


def matching_pids(executable):
    # Read only PID numbers for this CI user; verify each executable path before retaining/signalling it.
    listing = command(["/bin/ps", "-u", str(os.getuid()), "-o", "pid="], check=False).stdout
    return {int(value) for value in listing.split() if value.isdecimal() and process_path(int(value)) == executable}


def interrupted(signum, _frame):
    raise GateError(f"interrupted:{signum}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("legacy", "app"), required=True)
    parser.add_argument("--helper", type=Path, required=True, help="Unmodified helper executable, or its app bundle")
    parser.add_argument("--expected-version", default=None)
    parser.add_argument("--process-type", choices=("Background", "Interactive", "Standard"), default="Background")
    parser.add_argument("--timeout", type=int, default=75)
    parser.add_argument("--stable-seconds", type=int, default=12)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise GateError("macOS_required")
    if not 20 <= args.timeout <= 180 or not 10 <= args.stable_seconds <= 30:
        raise GateError("invalid_runtime_budget")
    if os.geteuid() == 0:
        raise GateError("non_root_gui_user_required")
    app = args.helper.resolve() if args.mode == "app" else None
    if app:
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        executable_name = info.get("CFBundleExecutable")
        if not isinstance(executable_name, str) or Path(executable_name).name != executable_name:
            raise GateError("invalid_app_executable")
        helper = (app / "Contents/MacOS" / executable_name).resolve()
    else:
        helper = args.helper.resolve()
    if args.mode == "app" and matching_pids(helper):
        raise GateError("test_app_already_running")
    expected_version = args.expected_version or ("henge-agent 4" if args.mode == "legacy" else "henge-agent 5")
    command(["/usr/bin/codesign", "--verify", "--strict", app or helper])
    if command([helper, "--version"]).stdout.strip() != expected_version:
        raise GateError("helper_version_mismatch")
    domain = f"gui/{os.getuid()}"
    if command(["/bin/launchctl", "print", domain], check=False).returncode:
        raise GateError("gui_domain_unavailable_required_gate")
    command(["/usr/bin/sudo", "-n", "/usr/bin/true"])
    if re.search(r"(?m)^\s*inet\s+10\.0\.2\.4(?:\s|$)", command(["/sbin/ifconfig", "-a"]).stdout):
        raise GateError("test_address_already_in_use")
    # The unchanged legacy executable may create ~/Henge before the proxy rejects its mount request.
    # Never remove an existing folder or unmount anything the gate did not create.
    mount_point = Path.home() / "Henge"
    if args.mode == "legacy" and mount_point.exists():
        raise GateError("legacy_mount_point_already_exists")
    directory = Path(tempfile.mkdtemp(prefix="henge-runtime-", dir="/tmp"))
    session = str(uuid.uuid4()).upper()
    label = "com.henge.runtime." + uuid.uuid4().hex
    target = f"{domain}/{label}"
    driver = proxy = None
    proxy_pid = app_pid = None
    alias_created = job_created = False
    summary = {"mode": args.mode, "helper_version": expected_version, "health_wire_protocol": 4,
               "status": "failed", "launchd_runtime": args.mode == "legacy", "launchservices_runtime": args.mode == "app",
               "lan_privacy_authorization_tested": False, "clipboard_tested": False,
               "shared_mount_tested": False, "login_registration_tested": False,
               "smoke_test_marker_verified": False, "cleanup_complete": False}
    failure = None
    launched_app_pids = set()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        shared = directory / "Shared"
        inputs = shared / "Henge-Chat-Diagnostics"
        inputs.mkdir(parents=True)
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        date = lambda value: value.isoformat().replace("+00:00", "Z")
        request = {"schema_version": 1, "task": "chat_error_summary", "vm_session_id": session,
                   "request_id": str(uuid.uuid4()).upper(), "created_utc": date(now - datetime.timedelta(days=1)),
                   "expires_utc": date(now - datetime.timedelta(days=1) + datetime.timedelta(seconds=60)), "collect": False}
        (inputs / "request.json").write_text(json.dumps(request))
        executable = directory / "server"
        command(["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                 ROOT / "tests/helper_runtime_driver.c", "-o", executable], timeout=60)
        unix_socket = directory / "s.sock"
        driver = subprocess.Popen([str(executable), str(shared), str(unix_socket), session],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if first_line(driver, 10) != "ready":
            raise GateError("production_server_not_ready")
        command(["/usr/bin/sudo", "-n", "/sbin/ifconfig", "lo0", "alias", ADDRESS, "netmask", "255.255.255.255"])
        alias_created = True
        proxy = subprocess.Popen(["/usr/bin/sudo", "-n", sys.executable, str(ROOT / "tests/helper_runtime_proxy.py"),
                                  "--socket", str(unix_socket), "--stop", str(directory / "stop"), "--stats", str(directory / "proxy-stats.json")],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        proxy_ready = json.loads(first_line(proxy, 10))
        if not proxy_ready.get("ready") or not isinstance(proxy_ready.get("pid"), int):
            raise GateError(f"test_port_unavailable:{proxy_ready.get('errno')}")
        proxy_pid = proxy_ready["pid"]
        health = http("GET", "/.henge/helper/health")
        if health.get("session") != session or health.get("agent_seen_s") != -1:
            raise GateError("production_health_initial_state_wrong")
        http("POST", "/.henge/helper/install-status?stage=launch_requested&error=none&code=0&pid=0", session)
        stdout_path, stderr_path = directory / "helper.stdout", directory / "helper.stderr"
        if args.mode == "legacy":
            plist = {"Label": label, "ProgramArguments": [str(helper)], "RunAtLoad": True, "KeepAlive": True,
                     "LimitLoadToSessionType": "Aqua", "ProcessType": args.process_type,
                     "StandardOutPath": str(stdout_path), "StandardErrorPath": str(stderr_path)}
            plist_path = directory / f"{label}.plist"
            plist_path.write_bytes(plistlib.dumps(plist))
            command(["/bin/launchctl", "bootstrap", domain, plist_path])
            job_created = True
        else:
            command(["/usr/bin/open", "-n", "-a", app, "--stdout", stdout_path, "--stderr", stderr_path,
                     "--args", "--smoke-test"])
        started = time.monotonic()
        stable_start = None
        previous_pid = None
        collector_seen = False
        while time.monotonic() - started < args.timeout:
            health = http("GET", "/.henge/helper/health")
            pid = health.get("helper_pid")
            actual_pid = None
            if args.mode == "app":
                launched_app_pids.update(matching_pids(helper))
                marker = stdout_path.exists() and b"HENGE_HELPER_SMOKE_TEST=1" in stdout_path.read_bytes()[:8192].splitlines()
                summary["smoke_test_marker_verified"] = marker
            if args.mode == "legacy":
                description = command(["/bin/launchctl", "print", target], check=False).stdout
                # Exercise the production 4005 installer's exact awk expression on real launchctl output.
                parsed = subprocess.run(["/usr/bin/awk", "/^[[:space:]]*pid = [0-9]+/ { print $3; exit }"],
                                        input=description, capture_output=True, text=True, check=True).stdout.strip()
                if parsed.isdecimal():
                    actual_pid = int(parsed)
                summary["last_launchd_pid"] = actual_pid
                state = re.search(r"(?m)^\s*state = ([a-z ]+)\s*$", description)
                summary["last_launchd_state"] = state.group(1).strip() if state and state.group(1).strip() in {"running", "waiting", "not running", "spawn scheduled", "exited"} else "unknown"
                exit_code = re.search(r"(?m)^\s*last exit code = (-?[0-9]+)", description)
                if exit_code:
                    summary["last_launchd_exit_code"] = int(exit_code.group(1))
            elif isinstance(pid, int) and pid > 0 and process_path(pid) == helper:
                actual_pid = app_pid = pid
            connected = (health.get("session") == session and health.get("helper_protocol") == 4 and
                         isinstance(pid, int) and pid > 0 and pid == actual_pid and
                         isinstance(health.get("agent_seen_s"), int) and 0 <= health["agent_seen_s"] < 30 and
                         process_path(pid) == helper)
            ready = inputs / "agent-status.json"
            if ready.exists() and ready.stat().st_size <= 4096:
                try:
                    heartbeat = json.loads(ready.read_text())
                    collector_seen = (heartbeat.get("vm_session_id") == session and heartbeat.get("collector_version") == 1)
                except (ValueError, OSError):
                    collector_seen = False
            if connected:
                if pid != previous_pid:
                    stable_start, previous_pid = time.monotonic(), pid
                if (collector_seen and stable_start is not None and time.monotonic() - stable_start >= args.stable_seconds and
                    (args.mode == "legacy" or marker)):
                    if command([helper, "--health-check", str(pid)], check=False).returncode:
                        raise GateError("real_helper_pid_health_check_failed")
                    http("POST", f"/.henge/helper/install-status?stage=confirmed&error=none&code=0&pid={pid}", session)
                    if http("GET", "/.henge/helper/health").get("install_stage") != "confirmed":
                        raise GateError("production_install_confirmation_failed")
                    summary.update(status="passed", actual_pid=pid, executable_identity_verified=True,
                                   collector_heartbeat_verified=True, install_receipt_verified=True,
                                   startup_stage=health.get("startup_stage"), observed_seconds=round(time.monotonic() - started, 2),
                                   stable_seconds=round(time.monotonic() - stable_start, 2), agent_seen_s=health["agent_seen_s"])
                    break
            else:
                stable_start = previous_pid = None
            time.sleep(1)
        else:
            summary.update(last_helper_pid=health.get("helper_pid"), last_agent_seen_s=health.get("agent_seen_s"),
                           last_startup_stage=health.get("startup_stage"), collector_heartbeat_verified=collector_seen)
            raise GateError("real_runtime_health_deadline_exceeded")
    except BaseException as error:
        failure = f"{type(error).__name__}:{error}" if isinstance(error, GateError) else type(error).__name__
        summary["failure"] = failure
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        cleanup_errors = []
        if job_created:
            if command(["/bin/launchctl", "bootout", target], check=False).returncode:
                cleanup_errors.append("launchagent_bootout_failed")
        if args.mode == "app":
            # This also finds a just-launched app that never reached the health server. The preflight
            # rejected an already-running copy, and every PID is path-checked again before a signal.
            launched_app_pids.update(matching_pids(helper))
            for pid in launched_app_pids:
                if process_path(pid) == helper:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
            stop_deadline = time.monotonic() + 5
            while time.monotonic() < stop_deadline and any(process_path(pid) == helper for pid in launched_app_pids):
                time.sleep(0.1)
            for pid in launched_app_pids:
                if process_path(pid) == helper:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    cleanup_errors.append("test_app_required_force_stop")
        (directory / "stop").touch()
        if proxy:
            try:
                proxy.wait(timeout=7)
            except subprocess.TimeoutExpired:
                if proxy_pid:
                    command(["/usr/bin/sudo", "-n", "/bin/kill", "-TERM", str(proxy_pid)], check=False)
                try:
                    proxy.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cleanup_errors.append("proxy_stop_failed")
        stats = directory / "proxy-stats.json"
        if stats.exists():
            summary["proxy"] = json.loads(stats.read_text())
            if summary["proxy"].get("report_requests_blocked"):
                cleanup_errors.append("unexpected_collection_attempt")
        if driver:
            try:
                driver.stdin.write("quit\n")
                driver.stdin.flush()
                driver.wait(timeout=5)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                driver.kill()
                driver.wait(timeout=5)
            for pipe in (driver.stdin, driver.stdout, driver.stderr):
                pipe.close()
        if alias_created:
            if command(["/usr/bin/sudo", "-n", "/sbin/ifconfig", "lo0", "-alias", ADDRESS], check=False).returncode:
                cleanup_errors.append("test_address_cleanup_failed")
        if args.mode == "legacy" and mount_point.exists():
            try:
                mount_point.rmdir()  # Never recursive; the proxy cannot provide a working WebDAV mount.
            except OSError:
                cleanup_errors.append("legacy_mount_point_not_empty")
        summary["cleanup_complete"] = not cleanup_errors
        if cleanup_errors:
            summary["status"] = "failed"
            summary["cleanup_errors"] = cleanup_errors
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(json.dumps(summary, sort_keys=True), flush=True)
        shutil.rmtree(directory)
    return 0 if summary["status"] == "passed" and summary["cleanup_complete"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as error:
        print(json.dumps({"status": "failed", "failure": str(error), "cleanup_complete": True}), flush=True)
        raise SystemExit(1)
