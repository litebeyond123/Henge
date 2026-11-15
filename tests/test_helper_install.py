#!/usr/bin/env python3
"""Real C health protocol plus the exact served installer in an isolated, controlled guest environment."""
import json
import os
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

    def install(self, scenario="ok"):
        state = self.directory / "state"
        state.mkdir()
        home = self.directory / "test home & apostrophe'"
        directory = home / "Library/Application Support/Henge"
        directory.mkdir(parents=True)
        plist = home / "Library/LaunchAgents/com.henge.agent.plist"
        plist.parent.mkdir(parents=True)
        binary = directory / "henge-agent"
        binary.write_bytes(b"old helper intact\n")
        binary.chmod(0o755)
        plist.write_bytes(b"old plist intact\n")
        (state / "launch-state.json").write_text(json.dumps({"loaded": True, "pid": 321, "bootstraps": 0}))
        payload = '''#!/usr/bin/env python3
import os, sys
scenario = os.environ.get("HENGE_INSTALL_TEST_SCENARIO", "ok")
if sys.argv[1] == "--version":
    print("henge-agent 3" if scenario == "version_invalid" else "henge-agent 4")
    sys.exit(0)
if sys.argv[1] == "--connection-check":
    sys.exit(1 if scenario == "probe_failed" else 0)
if sys.argv[1] == "--health-check":
    sys.exit(0 if scenario not in ("health_unconfirmed", "health_clock_backwards", "rollback_failed") and sys.argv[2] == "999" else 1)
sys.exit(2)
'''
        (state / "new-agent").write_text(payload)
        commands = self.directory / "bin"
        commands.mkdir()
        for name in ("curl", "codesign", "plutil", "launchctl", "date", "sleep", "mv"):
            target = commands / name
            target.write_bytes((ROOT / "tests/helper_install_stub.py").read_bytes())
            target.chmod(0o755)
        script = self.directory / "install.sh"
        script.write_bytes(self.script())
        # HOME remains the home of this isolated subprocess; no real user files or services are touched.
        environment = dict(os.environ, HOME=str(home), PATH=str(commands) + os.pathsep + os.environ["PATH"],
                           HENGE_INSTALL_TEST_STATE=str(state), HENGE_INSTALL_TEST_SCENARIO=scenario)
        result = subprocess.run(["/bin/sh", str(script)], env=environment, capture_output=True, text=True, timeout=10)
        receipts = [json.loads(line) for line in (state / "receipts.jsonl").read_text().splitlines()]
        return result, receipts, binary, plist, json.loads((state / "launch-state.json").read_text())

    def test_success_requires_new_daemon_pid_and_escaped_plist(self):
        result, receipts, binary, plist, launch = self.install()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn(b"--health-check", binary.read_bytes())
        self.assertIn(b"&amp;", plist.read_bytes())
        self.assertEqual(receipts[-1], {"stage": "confirmed", "error": "none", "code": "0", "pid": "999"})
        self.assertEqual(launch["pid"], 999)
        self.assertIn("has connected to Henge", result.stdout)

    def assert_preserved(self, scenario, expected, rolled_back=False):
        result, receipts, binary, plist, launch = self.install(scenario)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(binary.read_bytes(), b"old helper intact\n")
        self.assertEqual(plist.read_bytes(), b"old plist intact\n")
        self.assertEqual(launch["pid"], 321)
        self.assertTrue(launch["loaded"])
        self.assertEqual(receipts[-1]["stage"], "rolled_back" if rolled_back else "failed")
        self.assertEqual(receipts[-1]["error"], expected)
        self.assertNotIn("has connected to Henge", result.stdout)
        self.assertFalse(any(x["stage"] == "confirmed" for x in receipts))

    def test_download_failure_preserves_running_helper(self):
        self.assert_preserved("download_failed", "download_failed")

    def test_invalid_gzip_preserves_running_helper(self):
        self.assert_preserved("gzip_invalid", "gzip_invalid")

    def test_signature_failure_preserves_running_helper(self):
        self.assert_preserved("signature_invalid", "signature_invalid")

    def test_wrong_version_preserves_running_helper(self):
        self.assert_preserved("version_invalid", "version_invalid")

    def test_probe_failure_preserves_running_helper(self):
        self.assert_preserved("probe_failed", "connection_failed")

    def test_bootout_failure_is_explicit(self):
        self.assert_preserved("bootout_failed", "bootout_failed")

    def test_bootstrap_failure_restores_prior_files_and_running_agent(self):
        self.assert_preserved("bootstrap_failed", "bootstrap_failed", True)

    def test_missing_heartbeat_restores_prior_agent_without_success(self):
        self.assert_preserved("health_unconfirmed", "health_unconfirmed", True)

    def test_clock_stall_still_has_fixed_confirmation_attempt_limit(self):
        self.assert_preserved("health_clock_backwards", "health_unconfirmed", True)

    def test_failed_rollback_retains_unrestored_backup(self):
        result, receipts, binary, _, _ = self.install("rollback_failed")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipts[-1]["error"], "rollback_failed")
        backups = list(binary.parent.glob(".install.*/previous-agent"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"old helper intact\n")
        self.assertNotIn("has connected to Henge", result.stdout)

    def test_launch_receipt_failure_cannot_reuse_old_liveness(self):
        self.assert_preserved("receipt_failed", "connection_failed", True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
