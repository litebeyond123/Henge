#!/usr/bin/env python3
"""Real C health protocol plus the exact served installer in an isolated, controlled guest environment."""
import json
import os
import select
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_host_services as existing

ROOT = Path(__file__).resolve().parents[1]
SESSION = existing.SESSION
OTHER = existing.OTHER


class HelperInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        existing.HostServicesTests.setUpClass()
        cls.executable = existing.HostServicesTests.executable

    @classmethod
    def tearDownClass(cls):
        existing.HostServicesTests.tearDownClass()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="henge-helper-test-")
        self.directory = Path(self.temporary.name)
        self.server = existing.Server(self.executable, self.directory)
        self.server.control("begin " + SESSION)

    def tearDown(self):
        self.server.close()
        self.temporary.cleanup()

    def health(self):
        status, body = self.server.request("GET", "/.henge/helper/health")
        self.assertEqual(status, 200)
        return json.loads(body)

    def ping(self, kind="agent", pid=123, stage="network_ready", session=SESSION):
        return self.server.request("GET", f"/.henge/helper/ping?kind={kind}&protocol=4&pid={pid}&stage={stage}",
                                   headers=(f"X-Henge-Session: {session}",))

    def receipt(self, stage, reason="none", code=0, pid=0, session=SESSION):
        return self.server.request("POST", f"/.henge/helper/install-status?stage={stage}&error={reason}&code={code}&pid={pid}",
                                   headers=(f"X-Henge-Session: {session}",))

    def test_probe_is_not_daemon_and_receipts_require_real_matching_liveness(self):
        self.assertEqual(self.health()["agent_seen_s"], -1)
        self.assertEqual(self.ping("probe")[0], 200)
        health = self.health()
        self.assertEqual(health["helper_protocol"], 0)
        self.assertEqual(health["agent_seen_s"], -1)
        self.assertGreaterEqual(health["probe_seen_s"], 0)
        self.assertEqual(self.receipt("confirmed", pid=123)[0], 409)
        self.assertEqual(self.ping(stage="clipboard_starting")[0], 200)
        self.assertEqual(self.health()["startup_stage"], "clipboard_starting")
        self.assertEqual(self.receipt("launch_requested")[0], 200)
        self.assertEqual(self.health()["agent_seen_s"], -1)
        self.assertEqual(self.receipt("confirmed", pid=123)[0], 409)
        self.assertEqual(self.ping(pid=456, stage="ready")[0], 200)
        self.assertEqual(self.receipt("confirmed", pid=123)[0], 409)
        self.assertEqual(self.receipt("confirmed", pid=456)[0], 200)
        self.assertEqual(self.health()["install_stage"], "confirmed")

    def test_native_log_keeps_fixed_receipts_and_changed_health_only(self):
        self.assertEqual(self.ping()[0], 200)
        self.assertEqual(self.ping()[0], 200)  # ordinary repeated heartbeat is silent
        self.assertEqual(self.ping(stage="ready")[0], 200)
        self.assertEqual(self.ping(pid=456, stage="ready")[0], 200)
        self.assertEqual(self.ping("probe", pid=789)[0], 200)  # probe is not daemon startup
        self.assertEqual(self.receipt("launch_requested")[0], 200)
        self.assertEqual(self.ping(pid=456, stage="ready")[0], 200)
        self.assertEqual(self.receipt("confirmed", pid=456)[0], 200)
        self.assertEqual(self.receipt("failed", "bootstrap_failed", 5)[0], 200)
        self.assertEqual(self.ping(stage="private_raw_request")[0], 400)
        self.assertEqual(self.receipt("failed", "private_raw_error", 1)[0], 400)
        # The production route writes before sending its HTTP response, so all accepted lines are
        # available here. Read only the existing pipe; no retries, timing sleeps or test-only log hooks.
        pieces = []
        descriptor = self.server.process.stderr.fileno()
        while select.select([descriptor], [], [], 0)[0]:
            piece = os.read(descriptor, 65536)
            if not piece:
                break
            pieces.append(piece)
        log = b"".join(pieces).decode("utf-8")
        lines = [line for line in log.splitlines() if line.startswith("hengevm: helper-")]
        self.assertEqual(lines, [
            "hengevm: helper-health protocol=4 pid=123 stage=network_ready",
            "hengevm: helper-health protocol=4 pid=123 stage=ready",
            "hengevm: helper-health protocol=4 pid=456 stage=ready",
            "hengevm: helper-install stage=launch_requested error=none exit_code=0 pid=0",
            "hengevm: helper-health protocol=4 pid=456 stage=ready",
            "hengevm: helper-install stage=confirmed error=none exit_code=0 pid=456",
            "hengevm: helper-install stage=failed error=bootstrap_failed exit_code=5 pid=0",
        ])
        self.assertNotIn("private_raw", log)

    def test_new_session_clears_health_and_rejects_old_receipts(self):
        self.ping()
        self.receipt("failed", "bootstrap_failed", 5)
        self.server.control("begin " + OTHER)
        health = self.health()
        self.assertEqual(health["session"], OTHER)
        self.assertEqual(health["agent_seen_s"], -1)
        self.assertEqual(health["install_stage"], "not_started")
        self.assertEqual(self.ping()[0], 409)
        self.assertEqual(self.receipt("script_started")[0], 409)
        self.server.control("end")
        self.assertEqual(self.health()["session"], "")

    def test_fixed_protocol_rejects_unknown_or_unbounded_values(self):
        for query in (
            "kind=agent&protocol=3&pid=1&stage=ready",
            "kind=agent&protocol=4&pid=-0&stage=ready",
            "kind=agent&protocol=4&pid=+1&stage=ready",
            "kind=agent&protocol=4&pid=2147483648&stage=ready",
            "kind=agent&protocol=4&pid=1&stage=raw_user_message",
            "kind=agent&protocol=4&pid=1&stage=ready&extra=secret",
        ):
            with self.subTest(query=query):
                status, _ = self.server.request("GET", "/.henge/helper/ping?" + query,
                                                headers=(f"X-Henge-Session: {SESSION}",))
                self.assertEqual(status, 400)
        self.assertEqual(self.receipt("failed", "raw_secret")[0], 400)
        self.assertEqual(self.receipt("failed", "bootstrap_failed", 256)[0], 400)
        self.assertEqual(self.receipt("verified", "bootstrap_failed", 5)[0], 400)
        status, _ = self.server.request("GET", "/.henge/helper/health", headers=("Origin: https://example.com",))
        self.assertEqual(status, 403)
        self.assertEqual(self.health()["agent_seen_s"], -1)

    def script(self):
        status, script = self.server.request("GET", "/.henge/install")
        self.assertEqual(status, 200)
        expected = (f"#!/bin/sh\nHENGE_INSTALL_SESSION='{SESSION}'\n".encode()
                    + (ROOT / "tools/install-guest-helper.sh").read_bytes())
        self.assertEqual(script, expected, "Regenerate host/helper-install-script.inc after editing installer source")
        return script

    def install(self, scenario="ok", previous_app=False):
        state = self.directory / "state"; state.mkdir()
        home = self.directory / "test home & apostrophe'"
        directory = home / "Library/Application Support/Henge"; directory.mkdir(parents=True)
        plist = home / "Library/LaunchAgents/com.henge.agent.plist"; plist.parent.mkdir(parents=True)
        binary = directory / "henge-agent"; binary.write_bytes(b"old helper intact\n"); binary.chmod(0o755)
        plist.write_bytes(b"old plist intact\n")
        (state / "launch-state.json").write_text(json.dumps({"loaded": True, "pid": 321, "bootstraps": 0,
            "app_running": previous_app, "app_marker": "old", "slept_seconds": 0, "health_checks": 0}))
        payload = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root=Path(os.environ["HENGE_INSTALL_TEST_STATE"])
p=root/"launch-state.json"; state=json.loads(p.read_text())
scenario=os.environ.get("HENGE_INSTALL_TEST_SCENARIO", "ok")
mode=sys.argv[1]
with (root/"helper-calls.jsonl").open("a") as out: out.write(json.dumps(sys.argv[1:])+"\\n")
if mode == "--version":
    print("henge-agent 4" if scenario == "version_invalid" else "henge-agent 7"); sys.exit(0)
if mode == "--app-pid":
    if not state["app_running"]: sys.exit(1)
    print(999); sys.exit(0)
if mode == "--quit-app":
    state["app_running"]=False; p.write_text(json.dumps(state)); sys.exit(0)
if mode == "--startup-status": print('{"pid":999,"startup":"running","network":"waiting","login":"requires_approval"}'); sys.exit(0)
if mode == "--unregister-login": sys.exit(0)
if mode == "--login-status": print("requires_approval"); sys.exit(0)
if mode == "--health-check":
    state["health_checks"]+=1; p.write_text(json.dumps(state))
    success=scenario != "awaiting_connection" and (scenario != "late_connection" or state["slept_seconds"]>=15)
    sys.exit(0 if success and sys.argv[2] == "999" else 1)
sys.exit(2)
'''
        (state / "new-agent").write_text(payload)
        app = home / "Applications/Henge Helper.app"
        if previous_app:
            (app / "Contents/MacOS").mkdir(parents=True)
            old = app / "Contents/MacOS/henge-agent"; old.write_text(payload); old.chmod(0o755)
            (app / "Contents/marker").write_text("old")
        commands = self.directory / "bin"; commands.mkdir()
        for name in ("curl", "codesign", "launchctl", "open", "sleep", "mv", "cp", "rm"):
            target=commands/name; target.write_bytes((ROOT / "tests/helper_install_stub.py").read_bytes()); target.chmod(0o755)
        script=self.directory/"install.sh"; script.write_bytes(self.script())
        environment=dict(os.environ, HOME=str(home), PATH=str(commands)+os.pathsep+os.environ["PATH"],
            HENGE_INSTALL_TEST_STATE=str(state), HENGE_INSTALL_TEST_SCENARIO=scenario)
        result=subprocess.run(["/bin/sh", str(script)], env=environment, capture_output=True, text=True, timeout=20)
        receipts=[json.loads(line) for line in (state/"receipts.jsonl").read_text().splitlines()]
        return result, receipts, binary, plist, app, json.loads((state/"launch-state.json").read_text())

    def test_success_uses_real_app_pid_and_removes_legacy_job(self):
        result, receipts, binary, plist, app, launch=self.install()
        self.assertEqual(result.returncode, 0, result.stderr+result.stdout)
        self.assertEqual(binary.read_bytes(), b"old helper intact\n")
        self.assertTrue((app/"Contents/MacOS/henge-agent").is_file())
        self.assertFalse(plist.exists()); self.assertFalse(launch["loaded"])
        self.assertTrue(launch["app_running"])
        self.assertEqual(receipts[-1], {"stage":"confirmed", "error":"none", "code":"0", "pid":"999"})
        self.assertIn("connection is confirmed", result.stdout)

    def assert_preserved(self, scenario, expected, rolled_back=False):
        result, receipts, binary, plist, app, launch=self.install(scenario)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(binary.read_bytes(), b"old helper intact\n")
        self.assertEqual(plist.read_bytes(), b"old plist intact\n")
        self.assertTrue(launch["loaded"]); self.assertFalse(app.exists())
        self.assertEqual(receipts[-1]["stage"], "rolled_back" if rolled_back else "failed")
        self.assertEqual(receipts[-1]["error"], expected)
        self.assertFalse(any(x["stage"] == "confirmed" for x in receipts))
        return launch

    def test_download_failure_preserves_running_helper(self): self.assert_preserved("download_failed", "download_failed")
    def test_invalid_gzip_preserves_running_helper(self): self.assert_preserved("gzip_invalid", "gzip_invalid")
    def test_archive_traversal_rejected_before_extraction(self): self.assert_preserved("archive_traversal", "gzip_invalid")
    def test_archive_symlink_rejected_before_extraction(self): self.assert_preserved("archive_symlink", "gzip_invalid")
    def test_archive_hardlink_rejected_before_extraction(self): self.assert_preserved("archive_hardlink", "gzip_invalid")
    def test_signature_failure_preserves_running_helper(self): self.assert_preserved("signature_invalid", "signature_invalid")
    def test_wrong_version_preserves_running_helper(self): self.assert_preserved("version_invalid", "version_invalid")
    def test_bootout_failure_is_explicit(self): self.assert_preserved("bootout_failed", "bootout_failed", True)
    def test_app_launch_failure_restores_legacy_job(self): self.assert_preserved("bootstrap_failed", "bootstrap_failed", True)
    def test_absent_app_after_full_window_restores_prior_agent(self):
        state=self.assert_preserved("health_unconfirmed", "health_unconfirmed", True)
        self.assertEqual(state["slept_seconds"], 60)
    def test_connection_after_ten_seconds_is_not_rolled_back(self):
        result, receipts, _, _, _, launch=self.install("late_connection")
        self.assertEqual(result.returncode, 0, result.stderr+result.stdout)
        self.assertEqual(receipts[-1]["stage"], "confirmed")
        self.assertEqual(launch["slept_seconds"], 15)
    def test_running_app_is_preserved_awaiting_permission_not_claimed_success(self):
        result, receipts, _, plist, app, launch=self.install("awaiting_connection")
        self.assertEqual(result.returncode, 0, result.stderr+result.stdout)
        self.assertEqual(launch["slept_seconds"], 60)
        self.assertTrue(app.exists() and launch["app_running"])
        self.assertFalse(plist.exists() or launch["loaded"])
        self.assertEqual(receipts[-1]["stage"], "awaiting_connection")
        self.assertFalse(any(x["stage"] == "confirmed" for x in receipts))
        self.assertIn("NOT confirmed", result.stdout); self.assertIn("Do not repeat", result.stdout)
        self.assertIn("Login Items", result.stdout)
    def test_failed_app_replacement_restores_previous_app_and_running_state(self):
        result, receipts, _, _, app, launch=self.install("bootstrap_failed", previous_app=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((app/"Contents/marker").read_text(), "old")
        self.assertTrue(launch["app_running"] and launch["loaded"])
        self.assertEqual(receipts[-1]["stage"], "rolled_back")
    def test_signal_after_removal_restores_previous_app_from_complete_backup(self):
        result, receipts, _, _, app, launch=self.install("interrupt_replacement", previous_app=True)
        self.assertEqual(result.returncode, 130, result.stderr+result.stdout)
        self.assertEqual((app/"Contents/marker").read_text(), "old")
        self.assertTrue(launch["app_running"] and launch["loaded"])
        self.assertEqual(receipts[-1]["stage"], "rolled_back")
    def test_failed_rollback_retains_backup(self):
        result, receipts, _, _, app, _=self.install("rollback_failed")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipts[-1]["error"], "rollback_failed")
        self.assertEqual(len(list(app.parent.glob(".henge-install.*/previous.plist"))), 1)
    def test_launch_receipt_failure_restores_prior_state(self): self.assert_preserved("receipt_failed", "connection_failed", True)

    def test_app_archive_endpoint_uses_legacy_resource_directory(self):
        resource=self.directory/"resources"; resource.mkdir()
        (resource/"henge-agent.gz").write_bytes(b"legacy-fixture")
        archive=resource/"henge-helper.app.tar.gz"; archive.write_bytes(b"signed-app-fixture")
        self.server.control("agent-path "+str(resource/"henge-agent.gz"))
        self.assertEqual(self.server.request("GET", "/.henge/helper/app"), (200, b"signed-app-fixture"))
        self.assertEqual(self.server.request("GET", "/.henge/agent"), (200, b"legacy-fixture"))
        self.assertEqual(self.server.request("POST", "/.henge/helper/app")[0], 400)
        archive.unlink()
        self.assertEqual(self.server.request("GET", "/.henge/helper/app")[0], 404)

    def test_awaiting_connection_is_not_confirmed_until_pid_really_connects(self):
        self.assertEqual(self.receipt("awaiting_connection", pid=999)[0], 200)
        self.assertEqual(self.health()["install_stage"], "awaiting_connection")
        self.assertEqual(self.receipt("confirmed", pid=999)[0], 409)
        self.assertEqual(self.ping(pid=999)[0], 200)
        self.assertEqual(self.receipt("confirmed", pid=999)[0], 200)
        self.assertEqual(self.health()["install_stage"], "confirmed")
        self.assertEqual(self.receipt("awaiting_connection", pid=999)[0], 200)
        self.assertEqual(self.health()["install_stage"], "confirmed") # late installer cannot downgrade a live app
        self.assertEqual(self.receipt("awaiting_connection", pid=0)[0], 400)
        self.assertEqual(self.receipt("awaiting_connection", "health_unconfirmed", 1, pid=999)[0], 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
