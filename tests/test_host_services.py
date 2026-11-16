#!/usr/bin/env python3
"""Exercise the production HTTP server through Unix socketpairs, with a controlled fake UI thread.

Runs on macOS or Linux with a C compiler and Python 3. Linux shims cover only unrelated Apple filesystem
APIs; they do not replace service routes, HTTP parsing, session/permission checks, timeout or execution.
Socketpairs work in restricted runners without opening any listening socket. HENGE_TEST_LISTENER=1
uses the production Unix listener too, on machines that permit local listeners.
"""
import array
import concurrent.futures
import json
import os
from pathlib import Path
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SESSION = "11111111-2222-3333-4444-555555555555"
OTHER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class Server:
    def __init__(self, executable, directory):
        self.sock = str(directory / "s.sock")
        self.courier = None
        self.courier_lock = threading.Lock()
        child = None
        destination = self.sock
        inherited = ()
        if os.environ.get("HENGE_TEST_LISTENER") != "1":
            self.courier, child = socket.socketpair()
            destination = f"fd:{child.fileno()}"
            inherited = (child.fileno(),)
        self.process = subprocess.Popen([str(executable), str(directory), destination], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, pass_fds=inherited)
        if child is not None:
            child.close()
        try:
            assert self.read() == "ready"
        except BaseException:
            self.process.kill()
            self.process.wait()
            self.close()
            raise

    def read(self):
        if not select.select([self.process.stdout], [], [], 5)[0]:
            raise AssertionError("Host service driver did not answer")
        line = self.process.stdout.readline()
        if not line:
            raise AssertionError("Host service driver exited: " + self.process.stderr.read())
        return line.strip()

    def control(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self.read()

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
            sock.settimeout(6)
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
            pieces = []
            ended = "peer EOF"
            while True:
                try:
                    data = sock.recv(4096)
                except ConnectionResetError as error:
                    # Some rejected body-bearing requests close with reset. Only a complete HTTP
                    # response below is accepted; an empty/truncated response must remain a failure.
                    ended = f"connection reset (errno {error.errno})"
                    break
                if not data:
                    break
                pieces.append(data)
        raw = b"".join(pieces)
        head, separator, data = raw.partition(b"\r\n\r\n")
        if not separator:
            raise AssertionError(
                f"Incomplete HTTP response for {method} {path}: {len(raw)} bytes, {ended}, "
                f"driver exit={self.process.poll()}, prefix={raw[:120]!r}")
        status = int(head.split()[1])
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                assert len(data) == int(line.split(b":", 1)[1]), (head, data)
        return status, data

    def state(self):
        status, data = self.request("GET", "/.henge/v1/state")
        assert status == 200
        return json.loads(data)

    def post(self, body='{"value":0.6}', session=SESSION, extra=()):
        return self.request("POST", "/.henge/v1/brightness", body,
                            (f"X-Henge-Session: {session}", "Content-Type: application/json", *extra))

    def wait_pending(self):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if self.state()["brightness"]["pending"]:
                return
            time.sleep(0.01)
        raise AssertionError("No request reached the host queue")

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write("quit\n")
            self.process.stdin.flush()
            self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()
        if self.courier is not None:
            self.courier.close()


class HostServicesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="henge-host-test-")
        cls.executable = Path(cls.build.name) / "host-services-driver"
        command = shlex.split(os.environ.get("CC", "cc")) + ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", "-I" + str(ROOT / "host")]
        if sys.platform != "darwin":
            compat = ROOT / "tests/share_posix_compat"
            command += ["-D_GNU_SOURCE", "-I" + str(compat), "-include", str(compat / "compat.h")]
        command += [str(ROOT / "tests/host_services_driver.c"), str(ROOT / "host/device_auth.c"), "-o", str(cls.executable)]
        subprocess.run(command, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="henge-host-socket-")
        self.server = Server(self.executable, Path(self.directory.name))
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.server.control("begin " + SESSION)
        self.server.control("publish 1 1 0 0.5 0.25")

    def tearDown(self):
        self.pool.shutdown(wait=True)
        self.server.close()
        self.directory.cleanup()

    def enable(self):
        self.server.control("publish 1 1 1 0.5 0.25")

    def assert_error(self, response, status, error):
        self.assertEqual(response[0], status, response)
        self.assertEqual(json.loads(response[1])["error"], error)

    def test_capabilities_and_state_are_actual_and_read_only_by_default(self):
        status, data = self.server.request("GET", "/.henge/v1/capabilities")
        self.assertEqual(status, 200)
        caps = json.loads(data)
        self.assertEqual(caps["session"], SESSION)
        self.assertFalse(caps["features"]["brightness"]["controlEnabled"])
        for feature in ("wifiControl", "bluetoothControl", "appleAccount", "deviceCheck"):
            self.assertFalse(caps["features"][feature])
        state = self.server.state()
        self.assertEqual(state["brightness"]["value"], 0.5)
        self.assertEqual(state["outputVolume"]["value"], 0.25)
        self.assert_error(self.server.post(), 403, "brightness_control_disabled")
        self.assertEqual(self.server.control("calls"), "calls 0")

    def test_real_round_trip_applies_on_host_and_returns_actual_value(self):
        self.enable()
        future = self.pool.submit(self.server.post, '{ "value" : 6e-1 }')
        self.server.wait_pending()
        self.assertIn("applied 1 calls 1 value 0.600000000", self.server.control("apply"))
        status, data = future.result(timeout=3)
        self.assertEqual(status, 200)
        result = json.loads(data)
        self.assertEqual(result["brightness"], 0.6)
        self.assertGreater(result["requestId"], 0)
        self.assertEqual(self.server.state()["brightness"]["value"], 0.6)
        self.assertFalse(self.server.state()["brightness"]["pending"])

    def test_invalid_numbers_json_and_oversized_bodies_never_execute(self):
        self.enable()
        for value in ("NaN", "Infinity", "1e999", "-0.1", "1.1", "0x1", "+0.5", ".5", "01", "1.", '"0.5"', "null", "true"):
            with self.subTest(value=value):
                self.assert_error(self.server.post('{"value":' + value + '}'), 400, "invalid_brightness")
        for body in ('{"value":0.1,"value":0.8}', '{"value":0.1,"other":2}', '{"value":0.1}garbage', '{"value":0.1}\x00', '[]', '{}'):
            with self.subTest(body=body):
                self.assert_error(self.server.post(body), 400, "invalid_brightness")
        self.assert_error(self.server.post(" " * 129), 413, "body_size")
        self.assertEqual(self.server.control("calls"), "calls 0")

    def test_session_end_and_replacement_cancel_pending_work(self):
        self.enable()
        self.assert_error(self.server.post(session=OTHER), 409, "session_changed")
        future = self.pool.submit(self.server.post)
        self.server.wait_pending()
        self.server.control("begin " + OTHER)
        self.assert_error(future.result(timeout=3), 409, "session_changed")
        self.server.control("publish 1 1 1 0.5 0.25")
        self.assert_error(self.server.post(), 409, "session_changed")
        future = self.pool.submit(self.server.post, '{"value":0.6}', OTHER)
        self.server.wait_pending()
        self.server.control("end")
        self.assert_error(future.result(timeout=3), 409, "session_ended")
        self.assertIn("calls 0", self.server.control("apply"))
        self.assertFalse(self.server.state()["active"])

    def test_revoking_permission_or_backgrounding_cancels_queued_request(self):
        for state, status, error in (("1 1 0", 403, "brightness_control_disabled"), ("1 0 1", 503, "host_inactive"), ("0 1 1", 503, "host_inactive")):
            with self.subTest(state=state):
                self.enable()
                future = self.pool.submit(self.server.post)
                self.server.wait_pending()
                self.server.control("publish " + state + " 0.5 0.25")
                self.assert_error(future.result(timeout=3), status, error)
                self.assertIn("calls 0", self.server.control("apply"))

    def test_timeout_cancels_request_before_late_host_tick(self):
        self.enable()
        self.assert_error(self.server.post(), 504, "request_expired")
        self.assertIn("applied 0 calls 0", self.server.control("apply"))

    def test_only_one_inflight_request_and_apply_failures_are_reported(self):
        self.enable()
        future = self.pool.submit(self.server.post)
        self.server.wait_pending()
        self.assert_error(self.server.post(), 429, "request_in_progress")
        self.assertIn("applied -1 calls 1", self.server.control("refuse"))
        self.assert_error(future.result(timeout=3), 503, "brightness_apply_failed")
        self.assertEqual(self.server.state()["brightness"]["value"], 0.5)

    def test_stale_snapshot_cannot_authorize_changes(self):
        self.enable()
        time.sleep(5.1)
        state = self.server.state()
        self.assertFalse(state["fresh"])
        self.assertIsNone(state["brightness"]["value"])
        self.assert_error(self.server.post(), 503, "host_inactive")

    def test_http_permission_and_framing_boundaries(self):
        self.enable()
        self.assert_error(self.server.post(extra=("Origin: https://example.org",)), 403, "browser_origin_not_allowed")
        self.assert_error(self.server.post(extra=("Content-Length: 13",)), 400, "invalid_headers")
        self.assert_error(self.server.post(extra=(f"X-Henge-Session: {SESSION}",)), 400, "invalid_headers")
        self.assert_error(self.server.post(extra=("Transfer-Encoding: chunked",)), 400, "invalid_headers")
        self.assert_error(self.server.request("POST", "/.henge/v1/brightness", "{}", ("Content-Type: application/json",)), 403, "session_required")
        self.assert_error(self.server.request("POST", "/.henge/v1/brightness", "{}", (f"X-Henge-Session: {SESSION}",)), 415, "application_json_required")
        self.assert_error(self.server.request("POST", "/.henge/v1/brightness", include_length=False), 411, "content_length_required")
        self.assert_error(self.server.request("GET", "/.henge/v1/brightness"), 405, "post_required")
        self.assert_error(self.server.request("POST", "/.henge/v1/state"), 405, "get_required")
        self.assert_error(self.server.request("GET", "/.henge/v1/state", "x"), 400, "unexpected_body")
        self.assert_error(self.server.request("GET", "/.henge/v1/missing"), 404, "unknown_service")
        self.assertEqual(self.server.control("calls"), "calls 0")

    def test_existing_shared_files_clipboard_and_installer_are_preserved(self):
        self.assertEqual(self.server.request("PUT", "/bridge-test.txt", "hello mac")[0], 201)
        self.assertEqual(self.server.request("GET", "/bridge-test.txt"), (200, b"hello mac"))
        self.assertEqual(self.server.request("PUT", "/.henge/clipboard", "hello device")[0], 204)
        self.assertEqual(self.server.control("take-clipboard"), "clipboard hello device")
        self.server.control("clipboard hello guest")
        self.assertEqual(self.server.request("GET", "/.henge/clipboard?since=0"), (200, b"hello guest"))
        status, script = self.server.request("GET", "/.henge/install")
        self.assertEqual(status, 200)
        self.assertIn(b"com.henge.agent", script)
        self.assertIn(b"--health-check", script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
