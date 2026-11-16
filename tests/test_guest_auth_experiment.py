#!/usr/bin/env python3
"""Real macOS DYLD fixture + production protocol tests; never runs ChatGPT.

The localhost service is deliberately synthetic. PASS proves adapter routing,
not Apple issuance, OpenAI acceptance, or compatibility with the user's binary.
"""
from __future__ import annotations

import base64
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
MARKERS = (b"SYNTHETIC_TOKEN_DO_NOT_LOG", b"SYNTHETIC_SIGNATURE_DO_NOT_LOG",
           b"SYNTHETIC_CHALLENGE_DO_NOT_LOG", b"SYNTHETIC_CHAT_TEXT_DO_NOT_LOG",
           b"SYNTHETIC_COOKIE_DO_NOT_LOG")


def command(arguments: list[str], *, env: dict[str, str], timeout: int = 90, expected: int | None = 0):
    result = subprocess.run(arguments, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if expected is not None and result.returncode != expected:
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        sys.stdout.flush()
        sys.stderr.flush()
        raise AssertionError(f"command failed ({result.returncode}): {arguments[0]}")
    return result


class Service(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: str):
        self.scenario = scenario
        self.session = str(uuid.uuid4()).upper()
        self.launch_id = str(uuid.uuid4()).upper()
        self.mode = "baa" if scenario.startswith("baa") else "public_token"
        self.operations: Counter[str] = Counter()
        self.events: list[dict] = []
        self.failures: list[str] = []
        self.revoked = False
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def send_json(self, value, code=200):
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_GET(self):
        service = self.server
        if self.path != "/.henge/v1/auth/state":
            return self.send_json({"protocol": 1, "error": "not_found"}, 404)
        self.send_json({"protocol": 1, "enabled": not service.revoked, "session": service.session,
                        "launch_id": service.launch_id, "mode": service.mode})

    def do_POST(self):
        service = self.server
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 128 * 1024:
                raise ValueError("body_bound")
            body = json.loads(self.rfile.read(length))
            if self.headers.get("X-Henge-Session") != service.session or self.headers.get("Origin"):
                raise ValueError("session_header")
            if body.get("protocol") != 1 or body.get("launch_id") != service.launch_id:
                raise ValueError("launch_identity")
            uuid.UUID(body["request_id"])
            if self.path == "/.henge/v1/auth/event":
                expected = {"protocol", "launch_id", "request_id", "stage", "errorDomain", "errorCode",
                            "elapsedMs", "inputBytes", "resultBytes"}
                if set(body) != expected:
                    raise ValueError("event_schema")
                service.events.append(body)
                if service.scenario == "quit_cancelled" and body["stage"] == "quit_requested":
                    service.revoked = True
                return self.send_json({"protocol": 1, "status": "ok"})
            if self.path != "/.henge/v1/auth/request":
                raise ValueError("path")
            operation = body["operation"]
            allowed = {"probe", "dc_token"} if service.mode == "public_token" else {"probe", "baa_data", "baa_dictionary"}
            if operation not in allowed:
                return self.send_json({"protocol": 1, "error": "mode_forbidden"}, 403)
            service.operations[operation] += 1
            reply = {"protocol": 1, "session": service.session, "launch_id": service.launch_id,
                     "request_id": body["request_id"], "operation": operation, "status": "ok",
                     "diagnostics": {"status": "success", "outcome": "success", "errorDomain": "", "errorCode": 0}}
            if operation == "probe":
                support = service.scenario != "unsupported"
                result = {"supported": support, "dc_supported": support, "dc_support_checked": True,
                          "dc_framework_available": True, "dc_class_available": True, "dc_method_available": True,
                          "baa_framework_available": True, "baa_class_available": True,
                          "baa_single_available": True, "baa_multiple_available": True,
                          "entitlement_presence": {}}
                reply["diagnostics"]["status"] = reply["diagnostics"]["outcome"] = "probe_complete"
                if service.scenario == "session_revoked":
                    service.revoked = True
            elif operation == "dc_token":
                if service.scenario in {"unsupported", "token_error"}:
                    reply["status"] = "error"
                    reply["diagnostics"] = {
                        "status": "native_error", "outcome": "native_error",
                        "errorDomain": "com.apple.devicecheck.error" if service.scenario == "unsupported" else "Fixture.Native.Error",
                        "errorCode": 1 if service.scenario == "unsupported" else -123}
                    return self.send_json(reply)
                result = {"token": b"" if service.scenario == "empty_token" else MARKERS[0]}
                if service.scenario == "mismatched_response":
                    reply["launch_id"] = str(uuid.uuid4())
            elif operation == "baa_data":
                if base64.b64decode(body["payloadBase64"], validate=True) != MARKERS[2]:
                    raise ValueError("single_payload_changed")
                result = {"signature": MARKERS[1], "attestation": {"kind": "fixture", "opaque": b"\x01\x02"}}
            elif operation == "baa_dictionary":
                payload = plistlib.loads(base64.b64decode(body["payloadBase64"], validate=True))
                if payload != {"request": MARKERS[2], "nonce": MARKERS[2]}:
                    raise ValueError("dictionary_payload_changed")
                result = {"signatures": {"request": MARKERS[1], "nonce": b"\x03\x04"},
                          "attestation": [{"kind": "fixture"}, b"\x01\x02"]}
            else:
                raise ValueError("operation")
            reply["resultBase64"] = base64.b64encode(plistlib.dumps(result, fmt=plistlib.FMT_BINARY)).decode()
            self.send_json(reply)
        except Exception as exc:
            # Only an exception category is exposed; never echo a request body.
            service.failures.append(type(exc).__name__)
            self.send_json({"protocol": 1, "error": "fixture_request_invalid"}, 400)


def main() -> int:
    if sys.platform != "darwin":
        print("SKIP guest authentication native tests: macOS Foundation/Security/dyld required", flush=True)
        return 77
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("DYLD_", "HENGE_AUTH_")) or key in {"SDKROOT", "IPHONEOS_DEPLOYMENT_TARGET", "MACOSX_DEPLOYMENT_TARGET"}:
            env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="henge-auth-test-") as temporary:
        folder = Path(temporary)
        common = str(ROOT / "tools/guest-auth-experiment.m")
        flags = ["xcrun", "--sdk", "macosx", "clang", "-fobjc-arc", "-fblocks", "-O1",
                 "-mmacosx-version-min=13.0", "-Werror=implicit-function-declaration", "-Werror=return-type",
                 "-framework", "Foundation", "-framework", "AppKit", "-framework", "Security"]
        # Compile production binaries too. No mock endpoint or target identity
        # can be selected in either of these production builds.
        production_launcher = folder / "production-launcher"
        production_adapter = folder / "production-adapter.dylib"
        command(flags + [common, str(ROOT / "tools/henge-auth-launcher.m"), "-o", str(production_launcher)], env=env)
        command(flags + ["-dynamiclib", common, str(ROOT / "tools/henge-auth-adapter.m"), "-o", str(production_adapter)], env=env)
        for binary in (production_launcher, production_adapter):
            if b"HENGE_AUTH_TEST_PORT" in binary.read_bytes() or b"org.henge.auth.fixture" in binary.read_bytes():
                raise AssertionError("fixture override present in production binary")
        print("PASS production launcher and adapter compile without fixture overrides", flush=True)
        launcher = folder / "henge-auth-launcher"
        adapter = folder / "henge-auth-adapter.dylib"
        fixture_binary = folder / "HengeAuthFixture"
        outcome_adapter = folder / "fixture-outcome-adapter.dylib"
        test_flags = flags + ["-DHENGE_AUTH_TESTING=1"]
        command(test_flags + [common, str(ROOT / "tools/henge-auth-launcher.m"), "-o", str(launcher)], env=env)
        command(test_flags + ["-dynamiclib", common, str(ROOT / "tools/henge-auth-adapter.m"), "-o", str(adapter)], env=env)
        command(test_flags + [common, str(ROOT / "tests/test_guest_auth_experiment.m"), "-o", str(fixture_binary)], env=env)
        command(test_flags + ["-dynamiclib", common, str(ROOT / "tests/guest_auth_fixture_adapter.m"),
                              "-o", str(outcome_adapter)], env=env)
        for binary in (launcher, adapter, fixture_binary, outcome_adapter):
            command(["codesign", "--force", "--sign", "-", str(binary)], env=env)
        unit = command([str(fixture_binary), "--unit"], env=env)
        sys.stdout.buffer.write(unit.stdout)
        sys.stdout.flush()
        routed = {"public_success", "unsupported", "token_error", "empty_token", "mismatched_response",
                  "session_revoked", "baa_success", "baa_bad_input", "closed_window_restart"}
        held = {"closed_window_restart", "quit_refused", "quit_cancelled"}
        outcomes = {"hardened_policy_observation", "early_exit", "error_ready", "loaded_then_exit"}
        scenarios = ["public_success", "unsupported", "token_error", "empty_token", "mismatched_response",
                     "session_revoked", "baa_success", "baa_bad_input", "identity_mismatch",
                     "hardened_policy_observation", "closed_window_restart", "quit_refused", "quit_cancelled",
                     "early_exit", "error_ready", "loaded_then_exit"]
        for scenario in scenarios:
            case = folder / scenario
            application = case / "Fixture.app"
            macos = application / "Contents/MacOS"
            macos.mkdir(parents=True)
            shutil.copy2(fixture_binary, macos / "HengeAuthFixture")
            result_path = case / "fixture-result.json"
            info = {"CFBundleIdentifier": "org.henge.auth.fixture" if scenario != "identity_mismatch" else "org.henge.auth.wrong",
                    "CFBundleExecutable": "HengeAuthFixture", "CFBundleName": "HengeAuthFixture",
                    "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "LSUIElement": True,
                    "HengeFixtureScenario": scenario, "HengeFixtureResultPath": str(result_path)}
            (application / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
            entitlements = {"com.apple.security.cs.disable-library-validation": True}
            if scenario != "hardened_policy_observation":
                entitlements["com.apple.security.cs.allow-dyld-environment-variables"] = True
            entitlements_path = case / "fixture-entitlements.plist"
            entitlements_path.write_bytes(plistlib.dumps(entitlements))
            command(["codesign", "--force", "--sign", "-", "--options", "runtime", "--entitlements", str(entitlements_path),
                     str(application)], env=env)
            case_launcher = launcher
            if scenario in {"early_exit", "error_ready", "loaded_then_exit"}:
                # A separate, self-owned signed adapter induces a real bad/missing
                # handshake. Production binaries have no behavior override for it.
                runner = case / "runner"
                runner.mkdir()
                case_launcher = runner / "henge-auth-launcher"
                shutil.copy2(launcher, case_launcher)
                shutil.copy2(outcome_adapter, runner / "henge-auth-adapter.dylib")
            service = Service(scenario)
            thread = threading.Thread(target=service.serve_forever, daemon=True)
            thread.start()
            holder = None
            holder_pid = None
            window_marker = case / "window-closed.json"
            try:
                child_env = dict(env, HENGE_AUTH_TEST_PORT=str(service.server_port),
                                 HENGE_AUTH_TEST_APP=str(application), HENGE_AUTH_TEST_LOG_DIRECTORY=str(case / "logs"))
                before = {str(path.relative_to(application)): hashlib.sha256(path.read_bytes()).digest()
                          for path in application.rglob("*") if path.is_file()}
                if scenario in held:
                    option = "--hold-closed-window" if scenario == "closed_window_restart" else "--refuse-quit-closed-window"
                    holder = subprocess.Popen([str(macos / "HengeAuthFixture"), option, str(window_marker)],
                                              env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    holder_pid = holder.pid
                    deadline = time.monotonic() + 10
                    while not window_marker.exists() and holder.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.05)
                    if not window_marker.exists() or holder.poll() is not None:
                        raise AssertionError("owned window fixture did not remain alive after closing its window")
                    closed = json.loads(window_marker.read_text())
                    pid_matches = type(closed.get("pid")) is int and closed["pid"] == holder.pid
                    if closed.get("window_closed") is not True or not pid_matches:
                        print("fixture window state " + json.dumps({
                            "window_closed": closed.get("window_closed") is True,
                            "window_closed_is_boolean": type(closed.get("window_closed")) is bool,
                            "pid_matches": pid_matches, "holder_running": holder.poll() is None,
                        }, sort_keys=True), flush=True)
                        raise AssertionError("owned fixture did not confirm its closed window and exact main PID")
                invocation = [str(case_launcher), "--session", service.session, "--launch-id", service.launch_id,
                              "--mode", service.mode]
                # The real OS, not the static predictor, decides whether this
                # self-owned ad-hoc signed app loads the adapter. Verify either
                # result against its actual fixed handshake/backend evidence.
                expected = None if scenario == "hardened_policy_observation" else (0 if scenario in routed else 1)
                run = command(invocation, env=child_env, timeout=50, expected=expected)
                if scenario == "hardened_policy_observation" and run.returncode not in {0, 1}:
                    raise AssertionError(f"hardened fixture launcher failed unexpectedly ({run.returncode})")
                if (scenario in routed or scenario in outcomes - {"hardened_policy_observation"} or
                        scenario == "hardened_policy_observation" and run.returncode == 0):
                    deadline = time.monotonic() + 12
                    while not result_path.exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    if not result_path.exists():
                        raise AssertionError(f"{scenario}: fixture did not finish")
                    result = json.loads(result_path.read_text())
                    if result.get("passed") is not True:
                        safe_keys = {"stage", "errorDomain", "errorCode", "elapsedMs", "inputBytes", "resultBytes"}
                        events_path = case / "logs/AuthExperiment.events.jsonl"
                        if events_path.exists():
                            for line in events_path.read_bytes().splitlines()[-32:]:
                                value = json.loads(line)
                                print("fixture event " + json.dumps({key: value[key] for key in safe_keys if key in value},
                                                                  sort_keys=True), flush=True)
                        print("fixture backend operations " + json.dumps(dict(service.operations), sort_keys=True), flush=True)
                        raise AssertionError(f"{scenario}: fixture assertions failed: {result}")
                    if scenario == "closed_window_restart":
                        if type(result.get("pid")) is not int or result["pid"] == holder_pid:
                            raise AssertionError("closed-window target was reused rather than cold-started")
                        if holder.wait(timeout=3) != 0:
                            raise AssertionError("normal quit did not finish cleanly before cold launch")
                elif scenario not in outcomes and result_path.exists():
                    raise AssertionError("a refused/revoked/identity-mismatched launch executed the target")
                events_file = case / "logs/AuthExperiment.events.jsonl"
                local_events = events_file.read_bytes()
                if len(local_events) > 64 * 1024:
                    raise AssertionError("event ring exceeds its bound")
                events = [json.loads(line) for line in local_events.splitlines()]
                stages = {event["stage"] for event in events}
                server_stages = {event["stage"] for event in service.events}
                if scenario == "identity_mismatch":
                    if any(stage.startswith(("target_process_", "policy_")) for stage in stages):
                        raise AssertionError("unverified target was reported as a validated process/policy observation")
                    if "target_identity_mismatch" not in stages or "target_identity_mismatch" not in server_stages:
                        raise AssertionError("identity rejection did not reach both fixed event paths")
                else:
                    observations = {"target_process_running" if scenario in held else "target_process_not_running",
                                    "policy_runtime_on", "policy_library_exception_on",
                                    "policy_dyld_env_not_allowed" if scenario == "hardened_policy_observation" else "policy_dyld_env_allowed",
                                    "policy_predicts_restriction" if scenario == "hardened_policy_observation" else "policy_predicts_permission"}
                    if not observations <= stages or not observations <= server_stages:
                        raise AssertionError(f"{scenario}: verified preflight facts were not delivered to host")
                    if len(stages & {"policy_library_flag_on", "policy_library_flag_off"}) != 1 or "policy_flags_unavailable" in stages:
                        raise AssertionError("known signature flags were not distinguished from unavailable flags")
                    for event in events:
                        if event["stage"].startswith(("target_process_", "policy_")) and any(event[key] for key in ("errorCode", "inputBytes", "resultBytes")):
                            raise AssertionError("preflight facts must not overload error/byte fields")
                if "signature_policy_blocked" in stages:
                    raise AssertionError("static policy prediction still prevented an actual OS launch")
                if scenario in routed:
                    if not {"adapter_loaded", "adapter_ready", "launch_started"} <= stages or not service.operations["probe"]:
                        raise AssertionError(f"{scenario}: adapter did not actually load and call the backend")
                    ready = [event for event in events if event["stage"] == "adapter_ready"]
                    if not ready or any(type(event["errorCode"]) is not int or event["errorCode"] != 0 or event["errorDomain"] != "" for event in ready):
                        raise AssertionError("success was reported without an explicit zero-error handshake")
                    if scenario == "closed_window_restart" and not {"quit_requested", "quit_completed"} <= stages:
                        raise AssertionError("closed-window process was not normally quit before the cold launch")
                elif scenario in outcomes:
                    if "launch_started" not in stages:
                        raise AssertionError(f"{scenario}: did not perform one actual OS launch")
                    if scenario == "hardened_policy_observation":
                        ready = [event for event in events if event["stage"] == "adapter_ready"]
                        if run.returncode == 0:
                            if ("adapter_loaded" not in stages or not ready or not service.operations["probe"] or
                                    any(type(event["errorCode"]) is not int or event["errorCode"] != 0 or event["errorDomain"] != "" for event in ready)):
                                raise AssertionError("allowed hardened launch lacked actual successful readiness/probe evidence")
                            if set(service.operations) != {"probe"}:
                                raise AssertionError("policy-observation fixture unexpectedly generated authentication material")
                        elif ("adapter_loaded" in stages or ready or service.operations or
                              not stages & {"target_exited_before_adapter", "adapter_not_loaded"}):
                            raise AssertionError("hardened launch failure lacked a consistent no-handshake outcome")
                        print("hardened OS observation " + json.dumps({
                            "static_prediction": "restriction", "launcher_exit": run.returncode,
                            "adapter_loaded": "adapter_loaded" in stages, "adapter_ready": bool(ready),
                            "probe_calls": service.operations["probe"],
                        }, sort_keys=True), flush=True)
                    elif service.operations:
                        raise AssertionError(f"{scenario}: failed-handshake fixture unexpectedly called a backend")
                    elif scenario == "early_exit":
                        if "target_exited_before_adapter" not in stages or "adapter_loaded" in stages:
                            raise AssertionError("intentional target exit was not distinct from adapter initialization")
                    else:
                        if not {"adapter_loaded", "adapter_initialization_failed"} <= stages or "target_exited_before_adapter" in stages:
                            raise AssertionError("loaded adapter without successful readiness was misclassified")
                        if scenario == "error_ready":
                            errors = [event for event in events if event["stage"] == "adapter_ready"]
                            if not errors or errors[-1]["errorCode"] != 1002:
                                raise AssertionError("owned error-handshake fixture was not exercised")
                else:
                    if "launch_started" in stages or "adapter_loaded" in stages or service.operations:
                        raise AssertionError(f"{scenario}: failure still launched or called authentication")
                    if scenario in {"quit_refused", "quit_cancelled"}:
                        if "quit_requested" not in stages or holder.poll() is not None:
                            raise AssertionError("normal quit refusal/cancellation did not preserve the running fixture")
                        required = {"quit_refused", "quit_timeout"} if scenario == "quit_refused" else {"session_inactive"}
                        if not required & stages or not required & server_stages or "quit_completed" in stages:
                            raise AssertionError("quit refusal/cancellation was not acknowledged without relaunch")
                if service.mode == "public_token" and (service.operations["baa_data"] or service.operations["baa_dictionary"]):
                    raise AssertionError("public mode crossed into host BAA signing")
                if service.mode == "baa" and service.operations["dc_token"]:
                    raise AssertionError("BAA mode crossed into host public token generation")
                if scenario == "baa_bad_input" and service.operations["baa_dictionary"]:
                    raise AssertionError("unsupported dictionary reached backend")
                if scenario == "session_revoked" and service.operations["dc_token"]:
                    raise AssertionError("revoked launch issued a new token request")
                for marker in MARKERS:
                    if marker in local_events + run.stdout + run.stderr or base64.b64encode(marker) in local_events:
                        raise AssertionError("synthetic secret or target output leaked to experiment logs")
                if service.failures:
                    raise AssertionError(f"fixture transport rejected request: {service.failures}")
                if scenario == "public_success":
                    # Separate launcher processes model helper restart. Reusing
                    # the current UUID must not append stages or reexecute target.
                    time.sleep(0.3)
                    previous_events = events_file.read_bytes()
                    previous_result = result_path.read_bytes()
                    previous_operations = dict(service.operations)
                    for _ in range(2):
                        command(invocation, env=child_env, timeout=10)
                    if (events_file.read_bytes() != previous_events or result_path.read_bytes() != previous_result or
                            dict(service.operations) != previous_operations):
                        raise AssertionError("replayed launch UUID performed another action or overwrote its outcome")
                    # A malformed persisted record is an actual failure, never
                    # treated as an empty first-run state that permits a quit.
                    (case / "logs/AuthExperiment.launch-claim").write_bytes(b"partial")
                    service.launch_id = str(uuid.uuid4()).upper()
                    command([str(launcher), "--session", service.session, "--launch-id", service.launch_id,
                             "--mode", service.mode], env=child_env, timeout=10, expected=1)
                    later = {event["stage"] for event in service.events if event["launch_id"] == service.launch_id}
                    if later != {"launch_failed"} or dict(service.operations) != previous_operations:
                        raise AssertionError("damaged claim storage was silently reset or triggered authentication")
                if holder and holder.poll() is None:
                    Path(str(window_marker) + ".stop").write_bytes(b"")
                    if holder.wait(timeout=5) != 0:
                        raise AssertionError("owned refusal fixture did not exit cooperatively during test cleanup")
                holder = None
                after = {str(path.relative_to(application)): hashlib.sha256(path.read_bytes()).digest()
                         for path in application.rglob("*") if path.is_file()}
                if before != after:
                    raise AssertionError("launcher or adapter changed the signed target bundle")
                print(f"PASS real DYLD fixture {scenario}; fixed logs only", flush=True)
            finally:
                if holder and holder.poll() is None:
                    Path(str(window_marker) + ".stop").write_bytes(b"")
                    try:
                        holder.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        holder.terminate()  # Cleanup only the test's own fixture, never ChatGPT.
                        holder.wait(timeout=5)
                service.shutdown()
                service.server_close()
                thread.join(timeout=2)
        print("PASS guest authentication synthetic suite; Apple issuance/OpenAI acceptance NOT TESTED", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL guest authentication fixture: {exc}", file=sys.stderr, flush=True)
        raise
