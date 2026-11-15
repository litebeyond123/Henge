#!/usr/bin/env python3
"""Bounded CI-only TCP bridge to the production Unix HTTP server.

Runs as root only to bind the real helper's 10.0.2.4:80 endpoint. It forwards fixed health/heartbeat
routes, never clipboard or filesystem/mount requests. It does not log request headers or bodies.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import threading
from urllib.parse import urlsplit

parser = argparse.ArgumentParser()
parser.add_argument("--socket", required=True)
parser.add_argument("--stop", required=True)
parser.add_argument("--stats", required=True)
args = parser.parse_args()
stop = threading.Event()
lock = threading.Lock()
stats = {"clipboard_requests_blocked": 0, "report_requests_blocked": 0, "other_requests_blocked": 0,
         "forwarded_health_requests": 0, "forwarded_collector_requests": 0}


def increment(key):
    with lock:
        stats[key] += 1


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def reject(self, status=503):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def dispatch(self):
        self.close_connection = True
        self.connection.settimeout(5)
        path = urlsplit(self.path).path
        if path == "/.henge/clipboard":
            # No body read, storage, forwarding or logging. An empty connection makes the existing
            # helper use its error backoff instead of spinning on an immediate empty HTTP response.
            increment("clipboard_requests_blocked")
            return
        if path == "/Henge-Chat-Diagnostics/report.json":
            increment("report_requests_blocked")
            self.reject(403)
            return
        allowed = ((self.command == "GET" and path in ("/.henge/helper/health", "/.henge/helper/ping")) or
                   (self.command == "POST" and path == "/.henge/helper/install-status") or
                   (self.command == "GET" and path == "/Henge-Chat-Diagnostics/request.json") or
                   (self.command == "PUT" and path == "/Henge-Chat-Diagnostics/agent-status.json"))
        if not allowed or len(self.path) > 1024 or self.headers.get("Transfer-Encoding"):
            increment("other_requests_blocked")
            self.reject()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.reject(400)
            return
        if length < 0 or length > 4096 or (self.command != "PUT" and length):
            self.reject(413)
            return
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self.reject(400)
            return
        if self.command == "PUT":
            try:
                value = json.loads(body)
                if not isinstance(value, dict) or set(value) != {"schema_version", "collector_version", "vm_session_id", "seen_utc"}:
                    raise ValueError()
            except (ValueError, UnicodeError):
                self.reject(400)
                return
        headers = [f"{self.command} {self.path} HTTP/1.1", "Host: 10.0.2.4", "Connection: close",
                   f"Content-Length: {length}"]
        for name in ("X-Henge-Session", "Content-Type"):
            if self.headers.get(name):
                headers.append(f"{name}: {self.headers[name]}")
        response = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                upstream.settimeout(5)
                upstream.connect(args.socket)
                upstream.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)
                while True:
                    part = upstream.recv(8192)
                    if not part:
                        break
                    response.extend(part)
                    if len(response) > 65536:
                        raise ValueError()
            if b"\r\n\r\n" not in response:
                raise ValueError()
            increment("forwarded_health_requests" if path.startswith("/.henge/helper/") else "forwarded_collector_requests")
            self.wfile.write(response)
        except (OSError, ValueError, UnicodeError):
            if not response:
                self.reject(502)

    do_GET = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_OPTIONS = dispatch
    do_PROPFIND = dispatch
    do_HEAD = dispatch


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, lambda *_: stop.set())
try:
    server = Server(("10.0.2.4", 80), Handler)
except OSError as error:
    print(json.dumps({"ready": False, "errno": error.errno}), flush=True)
    raise SystemExit(1)
server.timeout = 0.25
print(json.dumps({"ready": True, "pid": os.getpid()}), flush=True)
try:
    while not stop.is_set() and not Path(args.stop).exists():
        server.handle_request()
finally:
    server.server_close()
    Path(args.stats).write_text(json.dumps(stats, sort_keys=True))
