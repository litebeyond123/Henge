#!/usr/bin/env python3
"""Real HTTP route + C queue, with a controlled synthetic backend and no Apple identity access.

macOS defaults to the production Unix listener. Restricted Linux can use the existing socketpair
courier. HENGE_TEST_SOURCE_ROOT optionally selects an integration tree during parallel development.
"""
import array
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import time
from typing import NamedTuple
import unittest

from test_host_services import Server

ROOT = Path(os.environ.get("HENGE_TEST_SOURCE_ROOT", Path(__file__).resolve().parents[1])).resolve()
HERE = Path(__file__).resolve().parent
SESSION = "01234567-89AB-CDEF-0123-456789ABCDEF"
OTHER = "11234567-89AB-CDEF-0123-456789ABCDEF"
LAUNCH = "22234567-89AB-CDEF-0123-456789ABCDEF"
LAUNCH_TWO = "33234567-89AB-CDEF-0123-456789ABCDEF"
REQUEST = "44234567-89AB-CDEF-0123-456789ABCDEF"
PREFIX = "/.henge/v1/auth/"
os.environ.setdefault("HENGE_TEST_LISTENER", "1" if sys.platform == "darwin" else "0")


class HTTPResult(NamedTuple):
    status: int
    headers: dict
    body: bytes


class AuthServer(Server):
    def request(self, method, path, body=b"", headers=(), include_length=True):
        if isinstance(body, str):
            body = body.encode()
        lines = [f"{method} {path} HTTP/1.1", "Host: 10.0.2.4", "Connection: close"]
        if include_length:
            lines.append(f"Content-Length: {len(body)}")
        lines.extend(headers)
        if self.courier is not None:
            sock, server = socket.socketpair()
            try:
                with self.courier_lock:
                    self.courier.sendmsg([b"c"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [server.fileno()]))])
            finally:
                server.close()
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.sock)
        with sock:
            sock.settimeout(16)
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
            pieces = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                pieces.append(chunk)
        raw = b"".join(pieces)
        head, separator, payload = raw.partition(b"\r\n\r\n")
        if not separator:
            raise AssertionError(f"Incomplete auth HTTP response: {len(raw)} bytes; process={self.process.poll()}")
        header_lines = head.split(b"\r\n")
        status = int(header_lines[0].split()[1])
        parsed = {}
        for line in header_lines[1:]:
            key, separator, value = line.partition(b":")
            if not separator:
                raise AssertionError("Malformed HTTP response header")
            parsed[key.decode().lower()] = value.decode().strip()
        if "content-length" not in parsed or len(payload) != int(parsed["content-length"]):
            raise AssertionError("Auth HTTP response was truncated")
        return HTTPResult(status, parsed, payload)

    def auth_state(self, capability=False):
        response = self.request("GET", PREFIX + "state" + ("?capability=3" if capability else ""))
        if response.status != 200:
            raise AssertionError(f"Cannot read auth state: HTTP {response.status}")
        return json.loads(response.body)

    def auth_post(self, value, endpoint="request", session=SESSION, extra=()):
        body = json.dumps(value, separators=(",", ":")) if isinstance(value, dict) else value
        return self.request("POST", PREFIX + endpoint, body,
                            (f"X-Henge-Session: {session}", "Content-Type: application/json", *extra))

    def wait_pending(self):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.auth_state()["busy"]:
                return
            time.sleep(0.005)
        raise AssertionError("Auth request did not reach the production C queue")


class DeviceAuthHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="henge-auth-http-build-")
        cls.executable = Path(cls.build.name) / "auth-http-driver"
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", "-I" + str(ROOT), "-I" + str(ROOT / "host"),
        ]
        if sys.platform != "darwin":
            compat = ROOT / "tests/share_posix_compat"
            command += ["-D_GNU_SOURCE", "-I" + str(compat), "-include", str(compat / "compat.h")]
        command += [str(HERE / "device_auth_http_driver.c"), str(ROOT / "host/device_auth.c"), "-o", str(cls.executable)]
        subprocess.run(command, check=True, timeout=60)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="henge-auth-http-")
        self.server = AuthServer(self.executable, Path(self.directory.name))
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.assertEqual(self.server.control("begin " + SESSION), "ok")
        self.assertEqual(self.server.control("publish 1 1"), "ok")

    def tearDown(self):
        self.pool.shutdown(wait=True)
        self.server.close()
        self.directory.cleanup()

    def enable(self, mode="public_token", launch=LAUNCH):
        self.assertEqual(self.server.control(f"enable {mode} {launch}"), "enabled ok")

    def request_json(self, **overrides):
        body = {"protocol": 1, "launch_id": LAUNCH, "request_id": REQUEST, "operation": "probe"}
        body.update(overrides)
        return body

    def assert_no_store(self, response):
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        self.assertNotIn("access-control-allow-origin", response.headers)

    def assert_error(self, response, status, error):
        self.assertEqual(response.status, status)
        self.assertEqual(json.loads(response.body)["error"], error)
        self.assert_no_store(response)
        self.assertNotIn(b"SYNTHETIC_MATERIAL", response.body)
        self.assertNotIn(b"U1lOVEhFVElDX01BVEVSSUFM", response.body)

    def complete_request(self, body=None, native_error=False):
        future = self.pool.submit(self.server.auth_post, body or self.request_json())
        self.server.wait_pending()
        self.assertEqual(self.server.control("take"), "taken 1")
        self.assertEqual(self.server.control("complete-error" if native_error else "complete"), "completed 1")
        return future.result(timeout=3)

    def test_default_disabled_and_synthetic_correlated_round_trip(self):
        state = self.server.auth_state()
        self.assertEqual(state["session"], SESSION)
        self.assertFalse(state["enabled"])
        self.assert_error(self.server.auth_post(self.request_json()), 409, "not_enabled")
        self.assertEqual(self.server.control("stats"), "wakes 0 takes 0")
        self.enable()
        response = self.complete_request()
        self.assertEqual(response.status, 200)
        self.assert_no_store(response)
        body = json.loads(response.body)
        self.assertEqual((body["session"], body["launch_id"], body["request_id"]), (SESSION, LAUNCH, REQUEST))
        self.assertEqual(body["status"], "ok")
        self.assertEqual(base64.b64decode(body["resultBase64"], validate=True), b"SYNTHETIC_MATERIAL")
        state = self.server.auth_state()
        self.assertEqual(state["accepted_requests"], 1)
        self.assertEqual(state["completed_requests"], 1)
        self.assertFalse(state["busy"])
        self.assertEqual(state["events"][-1]["launch_id"], LAUNCH)
        self.assertNotIn("resultBase64", json.dumps(state))
        self.assertNotIn("SYNTHETIC_MATERIAL", json.dumps(state))
        self.assertFalse(state["serverAcceptanceVerified"])

    def test_native_error_is_a_correlated_error_response(self):
        self.enable()
        response = self.complete_request(native_error=True)
        self.assertEqual(response.status, 200)
        self.assert_no_store(response)
        body = json.loads(response.body)
        self.assertEqual((body["session"], body["launch_id"], body["request_id"]), (SESSION, LAUNCH, REQUEST))
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["diagnostics"], {"errorDomain": "com.apple.devicecheck.error", "errorCode": 4})
        self.assertNotIn("resultBase64", body)

    def test_enable_diagnostics_cover_failure_idempotence_and_epoch_reset(self):
        state = self.server.auth_state()
        self.assertEqual((state["enable_attempts"], state["enable_successes"], state["enable_failures"]), (0, 0, 0))
        self.assertEqual((state["last_enable_error"], state["last_enable_mode"]), ("not_attempted", "not_attempted"))
        self.assertIs(state["backend_registered"], True)
        self.assertIs(state["last_enable_backend_registered"], False)

        self.assertEqual(self.server.control("enable public_token SYNTHETIC_INPUT_MATERIAL"), "enabled launch_required")
        state = self.server.auth_state()
        self.assertEqual((state["enable_attempts"], state["enable_successes"], state["enable_failures"]), (1, 0, 1))
        self.assertEqual((state["last_enable_error"], state["last_enable_mode"]), ("launch_required", "public_token"))
        self.assertEqual((state["enabled"], state["launch_id"], state["mode"], state["events"]), (False, "", "none", []))
        self.assertNotIn("SYNTHETIC_INPUT_MATERIAL", json.dumps(state))
        self.assertEqual(self.server.control(f"enable invalid {LAUNCH}"), "enabled invalid_request")
        state = self.server.auth_state()
        self.assertEqual((state["last_enable_error"], state["last_enable_mode"]), ("invalid_request", "invalid"))
        self.assertEqual(self.server.control("publish 0 1"), "ok")
        self.assertEqual(self.server.control(f"enable baa {LAUNCH}"), "enabled host_inactive")
        self.assertEqual(self.server.control("publish 1 1"), "ok")
        self.enable()
        authorized = self.server.auth_state()
        self.assertEqual((authorized["enable_attempts"], authorized["enable_successes"], authorized["enable_failures"]), (4, 1, 3))
        self.assertEqual(authorized["events"][-1]["stage"], "host_bridge_enabled")
        self.enable()  # Idempotent OK is a successful call, not a second stage.
        self.assertEqual(self.server.control(f"enable baa {LAUNCH_TWO}"), "enabled mode_conflict")
        state = self.server.auth_state()
        self.assertEqual((state["enable_attempts"], state["enable_successes"], state["enable_failures"]), (6, 2, 4))
        self.assertEqual((state["enabled"], state["launch_id"], state["mode"]), (True, LAUNCH, "public_token"))
        self.assertEqual([event["sequence"] for event in state["events"]], [event["sequence"] for event in authorized["events"]])
        self.assertEqual((state["last_enable_error"], state["last_enable_mode"]), ("mode_conflict", "baa"))
        self.assertIs(state["last_enable_backend_registered"], True)
        self.assertEqual((state["accepted_requests"], state["completed_requests"], state["refused_requests"]), (0, 0, 0))

        self.assertEqual(self.server.control("disable"), "ok")
        self.assertEqual(self.server.control(f"enable public_token {LAUNCH}"), "enabled launch_reused")
        state = self.server.auth_state()
        self.assertEqual((state["enable_attempts"], state["enable_successes"], state["enable_failures"]), (7, 2, 5))
        self.assertEqual((state["enabled"], state["launch_id"], state["mode"]), (False, LAUNCH, "public_token"))
        self.assertEqual(self.server.control("begin " + OTHER), "ok")
        state = self.server.auth_state()
        self.assertEqual((state["enable_attempts"], state["enable_successes"], state["enable_failures"]), (0, 0, 0))
        self.assertEqual((state["last_enable_error"], state["last_enable_mode"]), ("not_attempted", "not_attempted"))
        self.assertIs(state["last_enable_backend_registered"], False)
        self.assertEqual((state["session"], state["enabled"], state["launch_id"], state["mode"], state["events"]), (OTHER, False, "", "none", []))

    def test_modes_are_enforced_before_backend_claim(self):
        self.enable()
        self.assert_error(self.server.auth_post(self.request_json(operation="baa_data", payloadBase64="YQ==")), 403, "mode_forbidden")
        self.server.control("disable")
        self.enable("baa", LAUNCH_TWO)
        self.assert_error(self.server.auth_post(self.request_json(operation="dc_token", launch_id=LAUNCH_TWO)), 403, "mode_forbidden")
        self.assertEqual(self.server.control("stats"), "wakes 0 takes 0")
        response = self.complete_request(self.request_json(operation="baa_data", payloadBase64="YQ==", launch_id=LAUNCH_TWO))
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body)["launch_id"], LAUNCH_TWO)

    def test_http_headers_methods_and_size_limits(self):
        self.enable()
        body = self.request_json()
        for extra, status, error in (
            (("Origin: https://example.invalid",), 403, "browser_origin_not_allowed"),
            (("Content-Length: 0",), 400, "invalid_headers"),
            ((f"X-Henge-Session: {SESSION}",), 400, "invalid_headers"),
            (("Content-Type: application/json",), 400, "invalid_headers"),
            (("Transfer-Encoding: chunked",), 400, "invalid_headers"),
        ):
            with self.subTest(extra=extra):
                self.assert_error(self.server.auth_post(body, extra=extra), status, error)
        self.assert_error(self.server.request("POST", PREFIX + "request", "{}"), 415, "application_json_required")
        self.assert_error(self.server.request("POST", PREFIX + "request", "{}", ("Content-Type: application/json",)), 403, "session_required")
        self.assert_error(self.server.request("POST", PREFIX + "request", include_length=False), 411, "content_length_required")
        self.assert_error(self.server.request("POST", PREFIX + "request", headers=("Content-Length: 131073",), include_length=False), 413, "body_size")
        self.assert_error(self.server.request("POST", PREFIX + "event", headers=("Content-Length: 2049",), include_length=False), 413, "body_size")
        self.assert_error(self.server.request("GET", PREFIX + "request"), 405, "post_required")
        self.assert_error(self.server.request("POST", PREFIX + "state"), 405, "get_required")
        self.assert_error(self.server.request("GET", PREFIX + "state", "x"), 400, "unexpected_body")
        self.assert_error(self.server.request("GET", PREFIX + "state?x=1"), 400, "unexpected_query")
        self.assert_error(self.server.request("GET", PREFIX + "state", headers=("Origin: null",)), 403, "browser_origin_not_allowed")
        self.assertEqual(self.server.control("stats"), "wakes 0 takes 0")

    def test_flat_json_rejects_ambiguous_or_unbounded_input(self):
        self.enable()
        normal = json.dumps(self.request_json(), separators=(",", ":"))
        invalid = [normal + "garbage", normal + "\0", "{}", "[]", normal[:-1] + ',"protocol":1}',
                   normal.replace('"protocol":1', '"protocol":true'),
                   normal.replace('"protocol":1', '"protocol":1.0'),
                   normal.replace('"protocol":1', '"protocol":999999999999999999999'),
                   json.dumps(self.request_json(extra="unapproved")),
                   json.dumps(self.request_json(request_id="not-a-uuid")),
                   json.dumps(self.request_json(operation={"nested": True})),
                   json.dumps(self.request_json(operation="baa_data", payloadBase64="!"))]
        for index, body in enumerate(invalid):
            with self.subTest(index=index):
                self.assert_error(self.server.auth_post(body), 400, "invalid_auth_json")
        self.assert_error(self.server.auth_post(self.request_json(operation="other")), 400, "invalid_auth_operation")
        self.assert_error(self.server.auth_post(self.request_json(payloadBase64="YQ==")), 400, "invalid_auth_payload")
        self.assert_error(self.server.auth_post(self.request_json(operation="baa_data")), 400, "invalid_auth_payload")
        self.assertEqual(self.server.control("stats"), "wakes 0 takes 0")

    def test_event_allowlist_and_launch_correlation(self):
        self.enable()
        event = {"protocol": 1, "launch_id": LAUNCH, "request_id": REQUEST, "stage": "token_result",
                 "errorDomain": "com.apple.devicecheck.error", "errorCode": 4, "elapsedMs": 12,
                 "inputBytes": 0, "resultBytes": 0}
        self.assert_error(self.server.auth_post(event, "event", session=OTHER), 409, "session_changed")
        self.assert_error(self.server.auth_post(dict(event, launch_id=LAUNCH_TWO), "event"), 409, "launch_changed")
        self.assert_error(self.server.auth_post(dict(event, stage="host_request_completed"), "event"), 400, "invalid_request")
        self.assert_error(self.server.auth_post(dict(event, rawDescription="not stored"), "event"), 400, "invalid_auth_json")
        for _ in range(35):
            response = self.server.auth_post(event, "event")
            self.assertEqual(response.status, 200)
            self.assert_no_store(response)
        state = self.server.auth_state()
        self.assertEqual(len(state["events"]), 32)
        last = state["events"][-1]
        self.assertEqual((last["request_id"], last["launch_id"]), (REQUEST, LAUNCH))
        self.assertEqual((last["errorDomain"], last["errorCode"]), ("com.apple.devicecheck.error", 4))
        self.assertTrue(last["from_guest"])
        self.assertEqual(self.server.control("stats"), "wakes 0 takes 0")

    def test_disabled_queued_work_cannot_be_claimed_later(self):
        self.enable()
        future = self.pool.submit(self.server.auth_post, self.request_json())
        self.server.wait_pending()
        self.server.control("disable")
        self.assert_error(future.result(timeout=3), 409, "cancelled")
        self.assertEqual(self.server.control("take"), "taken 0")
        self.assertEqual(self.server.control("stats"), "wakes 1 takes 0")
        self.assertEqual(self.server.control("enable public_token " + LAUNCH), "enabled launch_reused")

    def test_fixed_guest_preflight_observations_do_not_allow_host_stages_or_raw_metadata(self):
        self.enable()
        stages = ["target_process_running", "target_process_not_running", "policy_flags_unavailable",
                  "policy_runtime_on", "policy_runtime_off", "policy_library_flag_on", "policy_library_flag_off",
                  "policy_dyld_env_allowed", "policy_dyld_env_not_allowed", "policy_library_exception_on",
                  "policy_library_exception_off", "policy_predicts_restriction", "policy_predicts_permission",
                  "quit_requested", "quit_completed", "quit_refused", "quit_timeout",
                  "target_exited_before_adapter", "adapter_initialization_failed", "force_quit_requested",
                  "force_quit_completed", "force_quit_refused", "force_quit_timeout",
                  "process_identity_unavailable", "target_process_changed", "target_reappeared"]
        event = {"protocol": 1, "launch_id": LAUNCH, "request_id": REQUEST,
                 "errorCode": 0, "elapsedMs": 0, "inputBytes": 0, "resultBytes": 0}
        for stage in stages:
            with self.subTest(stage=stage):
                response = self.server.auth_post(dict(event, stage=stage), "event")
                self.assertEqual(response.status, 200)
                self.assert_no_store(response)
        for stage in ["host_request_queued", "host_request_started", "host_request_completed", "host_request_failed",
                      "host_request_cancelled", "host_bridge_enabled", "host_bridge_disabled"]:
            self.assert_error(self.server.auth_post(dict(event, stage=stage), "event"), 400, "invalid_request")
        self.assert_error(self.server.auth_post(dict(event, stage=stages[0], signatureInfo="SYNTHETIC_INPUT_MATERIAL"), "event"),
                          400, "invalid_auth_json")
        # Old helper receipts remain readable; new policy predictions are only observations.
        refused = dict(event, stage="signature_policy_blocked", errorDomain="HengeAuthBridge", errorCode=1010)
        self.assertEqual(self.server.auth_post(refused, "event").status, 200)
        state = self.server.auth_state()
        observed = state["events"][1:]
        self.assertEqual([entry["stage"] for entry in observed], stages + ["signature_policy_blocked"])
        allowed = {"sequence", "age_ms", "from_guest", "request_id", "launch_id", "stage", "errorDomain", "errorCode",
                   "elapsedMs", "inputBytes", "resultBytes", "targetPid", "observedPid"}
        for entry in observed:
            self.assertEqual(set(entry), allowed)
            self.assertTrue(entry["from_guest"])
            self.assertEqual((entry["request_id"], entry["launch_id"]), (REQUEST, LAUNCH))
            self.assertEqual((entry["elapsedMs"], entry["inputBytes"], entry["resultBytes"]), (0, 0, 0))
            self.assertEqual((entry["targetPid"], entry["observedPid"]), (0, 0))
        self.assertTrue(all(entry["errorDomain"] == "" and entry["errorCode"] == 0 for entry in observed[:-1]))
        self.assertEqual((observed[-1]["errorDomain"], observed[-1]["errorCode"]), ("HengeAuthBridge", 1010))
        self.assertNotIn("SYNTHETIC_INPUT_MATERIAL", json.dumps(state))
        self.assertEqual((state["enabled"], state["mode"], state["launch_id"]), (True, "public_token", LAUNCH))
        self.assertEqual((state["accepted_requests"], state["completed_requests"]), (0, 0))
        self.assertEqual(self.server.control("stats"), "wakes 0 takes 0")
        self.assertFalse(state["serverAcceptanceVerified"])

    def test_startup_cache_survives_ring_wrap_and_state_stays_within_guest_limit(self):
        self.enable()
        stages = ["launch_requested", "target_not_found", "target_identity_mismatch", "target_signature_invalid",
                  "signature_policy_blocked", "already_running", "launch_started", "launch_failed", "launch_timeout",
                  "adapter_loaded", "adapter_not_loaded", "adapter_target_rejected", "adapter_abi_mismatch", "adapter_ready",
                  "target_process_running", "target_process_not_running", "policy_flags_unavailable", "policy_runtime_on",
                  "policy_runtime_off", "policy_library_flag_on", "policy_library_flag_off", "policy_dyld_env_allowed",
                  "policy_dyld_env_not_allowed", "policy_library_exception_on", "policy_library_exception_off",
                  "policy_predicts_restriction", "policy_predicts_permission", "quit_requested", "quit_completed",
                  "quit_refused", "quit_timeout", "target_exited_before_adapter", "adapter_initialization_failed",
                  "force_quit_requested", "force_quit_completed", "force_quit_refused", "force_quit_timeout",
                  "process_identity_unavailable", "target_process_changed", "target_reappeared"]
        event = {"protocol": 1, "launch_id": LAUNCH, "request_id": REQUEST,
                 "errorDomain": "com.apple.MobileActivation.ErrorDomain", "errorCode": -(2 ** 31),
                 "elapsedMs": 300000, "inputBytes": 128 * 1024, "resultBytes": 96 * 1024,
                 "targetPid": 2 ** 31 - 1, "observedPid": 2 ** 31 - 1}
        for stage in stages:
            self.assertEqual(self.server.auth_post(dict(event, stage=stage), "event").status, 200)
        for _ in range(70):
            self.assertEqual(self.server.auth_post(dict(event, stage="probe_result"), "event").status, 200)
        response = self.server.request("GET", PREFIX + "state")
        self.assertEqual(response.status, 200)
        self.assert_no_store(response)
        self.assertLess(len(response.body), 32 * 1024)  # Existing guest parser's hard bound.
        state = json.loads(response.body)
        # Include the maximum decimal width of service-owned sequence/age values
        # and a longest-stage recent ring without manufacturing billions of events.
        sequence_age_growth = sum(40 - len(str(item["sequence"])) - len(str(item["age_ms"]))
                                  for item in state["events"] + state["startup_events"])
        stage_growth = 32 * (max(map(len, stages)) - len("probe_result"))
        # Conservative fixed-header growth: every counter may reach uint64 width,
        # age int64 width, error name up to 32 bytes, and booleans may become false.
        header_growth = 6 * 20 + 20 + 32 + 16
        self.assertLess(len(response.body) + sequence_age_growth + stage_growth + header_growth, 32 * 1024)
        self.assertEqual(len(state["events"]), 32)
        self.assertEqual({item["stage"] for item in state["events"]}, {"probe_result"})
        self.assertEqual([item["stage"] for item in state["startup_events"]], ["host_bridge_enabled"] + stages)
        self.assertTrue(all(item["launch_id"] == LAUNCH for item in state["startup_events"]))
        # Repeated fixed stages replace their own slot, never another startup fact.
        self.assertEqual(self.server.auth_post(dict(event, stage="quit_requested"), "event").status, 200)
        cached = self.server.auth_state()["startup_events"]
        self.assertEqual(len(cached), len(stages) + 1)
        self.assertEqual(cached[-1]["stage"], "quit_requested")
        self.assertEqual([item["sequence"] for item in cached], sorted(item["sequence"] for item in cached))
        self.assertEqual(self.server.control("disable"), "ok")
        stopped_response = self.server.request("GET", PREFIX + "state")
        self.assertEqual(stopped_response.status, 200)
        bounded_size = len(stopped_response.body) + sequence_age_growth + stage_growth + header_growth + 40
        self.assertLess(bounded_size, 32 * 1024)
        print(f"PASS auth state size: {len(stopped_response.body)} actual bytes; {bounded_size} conservative bytes; 32768-byte guest bound")
        stopped = json.loads(stopped_response.body)
        self.assertEqual(len(stopped["startup_events"]), len(stages) + 2)
        self.assertIn("adapter_ready", [item["stage"] for item in stopped["startup_events"]])
        self.assertEqual(self.server.control("enable public_token " + LAUNCH_TWO), "enabled ok")
        fresh = self.server.auth_state()
        self.assertEqual(len(fresh["startup_events"]), 1)
        self.assertEqual(fresh["startup_events"][0]["launch_id"], LAUNCH_TWO)
        self.assertEqual(self.server.control("stats"), "wakes 0 takes 0")
        self.assertFalse(fresh["serverAcceptanceVerified"])

    def test_background_discards_claimed_response_and_requires_new_enable(self):
        self.enable()
        future = self.pool.submit(self.server.auth_post, self.request_json())
        self.server.wait_pending()
        self.assertEqual(self.server.control("take"), "taken 1")
        self.server.control("publish 1 0")
        self.assert_error(future.result(timeout=3), 409, "host_inactive")
        self.assertTrue(self.server.auth_state()["busy"])
        self.assertEqual(self.server.control("complete"), "completed 1")
        self.assertFalse(self.server.auth_state()["busy"])
        self.server.control("publish 1 1")
        self.assert_error(self.server.auth_post(self.request_json()), 409, "not_enabled")
        self.assertEqual(self.server.auth_state()["completed_requests"], 0)

    def test_launch_action_and_capability_query_keep_old_helpers_out_of_force_attempts(self):
        self.enable()
        normal = self.server.auth_state()
        self.assertEqual((normal["launch_action"], normal["last_enable_action"]), ("normal_quit", "normal_quit"))
        self.assertEqual(self.server.auth_state(capability=True)["launch_id"], LAUNCH)
        self.assertEqual(self.server.control(f"enable-action public_token force_quit {LAUNCH}"),
                         "enabled action_conflict")
        unchanged = self.server.auth_state()
        self.assertTrue(unchanged["enabled"])
        self.assertEqual((unchanged["launch_id"], unchanged["launch_action"]), (LAUNCH, "normal_quit"))
        self.assertEqual((unchanged["last_enable_action"], unchanged["last_enable_error"]),
                         ("force_quit", "action_conflict"))
        self.assertEqual(self.server.control("disable"), "ok")
        self.assertEqual(self.server.control(f"enable-action public_token force_quit {LAUNCH_TWO}"), "enabled ok")
        old = self.server.request("GET", PREFIX + "state")
        self.assert_no_store(old)
        self.assertEqual(json.loads(old.body), {"protocol": 1, "enabled": False})
        capable = self.server.auth_state(capability=True)
        self.assertEqual((capable["enabled"], capable["launch_id"], capable["launch_action"]),
                         (True, LAUNCH_TWO, "force_quit"))
        # Reading the old view must not revoke, change, or claim the current authorization.
        self.assertEqual(self.server.control(f"enable-action public_token force_quit {LAUNCH_TWO}"), "enabled ok")
        self.assertEqual(self.server.control(f"enable public_token {LAUNCH_TWO}"), "enabled action_conflict")
        for query in ["capability=2", "capability=03", "capability=3&capability=3", "capability=3&x=1",
                      "x=1", "capability=3%00", "capability=3?"]:
            with self.subTest(query=query):
                self.assert_error(self.server.request("GET", PREFIX + "state?" + query), 400, "unexpected_query")
        for endpoint in ["request", "event"]:
            self.assert_error(self.server.auth_post(self.request_json(), endpoint + "?capability=3"),
                              400, "unexpected_query")
        self.assertEqual(self.server.auth_state(capability=True)["launch_action"], "force_quit")
        self.assertEqual(self.server.control("publish 1 0"), "ok")
        revoked = self.server.auth_state(capability=True)
        self.assertFalse(revoked["enabled"])
        self.assertEqual(revoked["launch_action"], "force_quit")
        # Once revoked there is no claimable force permission; diagnostics remain readable.
        self.assertEqual(self.server.auth_state()["launch_action"], "force_quit")
        self.assertEqual(self.server.control("begin " + OTHER), "ok")
        reset = self.server.auth_state(capability=True)
        self.assertEqual((reset["launch_action"], reset["last_enable_action"]), ("normal_quit", "not_attempted"))
        self.assertEqual(reset["startup_events"], [])

    def test_process_pid_fields_are_optional_fixed_int32_metadata(self):
        self.enable()
        event = {"protocol": 1, "launch_id": LAUNCH, "request_id": REQUEST, "stage": "target_process_running"}
        self.assertEqual(self.server.auth_post(event, "event").status, 200)
        last = self.server.auth_state()["events"][-1]
        self.assertEqual((last["targetPid"], last["observedPid"]), (0, 0))
        for target, observed in [(0, 0), (1, 0), (2 ** 31 - 1, 2 ** 31 - 1), (541, 812)]:
            self.assertEqual(self.server.auth_post(dict(event, targetPid=target, observedPid=observed), "event").status, 200)
            last = self.server.auth_state()["events"][-1]
            self.assertEqual((last["targetPid"], last["observedPid"]), (target, observed))
        for field in ["targetPid", "observedPid"]:
            for invalid in [-1, 2 ** 31, True, 1.5, "123", None]:
                with self.subTest(field=field, invalid=invalid):
                    self.assert_error(self.server.auth_post(dict(event, **{field: invalid}), "event"),
                                      400, "invalid_auth_json")
            duplicate = json.dumps(dict(event, **{field: 123}))[:-1] + f',"{field}":124}}'
            self.assert_error(self.server.auth_post(duplicate, "event"), 400, "invalid_auth_json")
        self.assert_error(self.server.auth_post(self.request_json(targetPid=123)), 400, "invalid_auth_json")
        self.assertEqual(self.server.control("stats"), "wakes 0 takes 0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
