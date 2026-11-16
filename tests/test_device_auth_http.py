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

    def auth_state(self):
        response = self.request("GET", PREFIX + "state")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
