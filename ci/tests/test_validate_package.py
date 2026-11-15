"""Regression tests using structural fixtures, never installable app packages."""

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "ci/validate-package.py"
SPEC = importlib.util.spec_from_file_location("package_validator", VALIDATOR)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def blob(magic, payload):
    return struct.pack(">II", magic, len(payload) + 8) + payload


def signature(entitlements=None, der=None):
    # This dummy CodeDirectory is sufficient to test parsing, not codesign.
    items = [(0, blob(0xFADE0C02, bytes(36)))]
    if entitlements is not None:
        items.append((5, blob(0xFADE7171, plistlib.dumps(entitlements))))
    if der is not None:
        items.append((7, blob(0xFADE7172, der)))
    position = 12 + len(items) * 8
    indexes, bodies = [], []
    for slot, body in items:
        indexes.append(struct.pack(">II", slot, position))
        bodies.append(body)
        position += len(body)
    return struct.pack(">III", 0xFADE0CC0, position, len(items)) + b"".join(indexes + bodies)


def der_key(key):
    value = key.encode()
    pair = b"\x0c" + bytes([len(value)]) + value + b"\x01\x01\xff"
    pair = b"\x30" + bytes([len(pair)]) + pair
    return b"\x31" + bytes([len(pair)]) + pair


def macho(entitlements=None, der=None, minimum=0x110000, platform=2,
          cpu=0x0100000C, signed=True, filetype=2):
    build = struct.pack("<6I", 0x32, 24, platform, minimum, 0x1B0000, 0)
    commands = build
    if signed:
        sign = signature(entitlements, der)
        commands += struct.pack("<4I", 0x1D, 16, 32 + len(build) + 16, len(sign))
    else:
        sign = b""
    header = struct.pack("<8I", 0xFEEDFACF, cpu, 0, filetype,
                         2 if signed else 1, len(commands), 0, 0)
    return header + commands + sign


def guest_app_archive(binary=None, extra=None):
    info = {"CFBundleIdentifier": "com.henge.guesthelper", "CFBundleExecutable": "henge-agent",
            "CFBundleVersion": "5", "CFBundlePackageType": "APPL", "LSUIElement": True,
            "LSMinimumSystemVersion": "13.0", "NSLocalNetworkUsageDescription": "Connect to Henge."}
    files = {"Henge Helper.app/Contents/Info.plist": plistlib.dumps(info),
             "Henge Helper.app/Contents/MacOS/henge-agent": binary if binary is not None else macho(platform=1, minimum=0x0D0000),
             "Henge Helper.app/Contents/_CodeSignature/CodeResources": b"structural fixture"}
    if extra:
        files.update(extra)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def members():
    info = {
        "CFBundleIdentifier": "com.henge.app", "CFBundleExecutable": "Henge",
        "CFBundleShortVersionString": "0.4.0", "CFBundleVersion": "4006",
        "MinimumOSVersion": "17.0", "HengeBuildCommit": COMMIT[:12],
        "HengeBuildDate": "2026-11-15T00:00:00Z",
    }
    return {
        "Info.plist": plistlib.dumps(info),
        "Henge": macho({"get-task-allow": True}, der_key("get-task-allow")),
        "henge-jit.js": b"// structural test fixture\n",
        "henge-agent.gz": gzip.compress(b"structural test fixture, not a guest executable"),
        "henge-helper.app.tar.gz": guest_app_archive(),
        "guest-chat-diagnostics.command": b"#!/bin/sh\n# structural test fixture\n",
        "PlugIns/HengeJITHelper.appex/Info.plist": plistlib.dumps({"CFBundleExecutable": "HengeJITHelper"}),
        # Only the main app must target iOS <= 17; the guarded helper targets 26.
        "PlugIns/HengeJITHelper.appex/HengeJITHelper": macho(minimum=0x1A0000),
        "Frameworks/StikJIT.framework/Info.plist": plistlib.dumps({"CFBundleExecutable": "StikJIT"}),
        "Frameworks/StikJIT.framework/StikJIT": macho(minimum=0x110400, filetype=6),
    }


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.package = self.folder / "Henge.tipa"

    def write(self, files=None):
        with zipfile.ZipFile(self.package, "w") as archive:
            for name, data in (members() if files is None else files).items():
                archive.writestr(validator.APP + name, data)

    def validate(self, **kwargs):
        return validator.validate_package(self.package, COMMIT, **kwargs)

    def test_valid_tipa_reports_structure_and_actual_hash(self):
        self.write()
        report = self.validate(husk_commit="1" * 40)
        self.assertEqual(report["application"]["version"], "0.4.0")
        self.assertEqual(report["source"]["husk_commit"], "1" * 40)
        self.assertEqual(len(report["validation"]["signed_macho_files"]), 3)
        self.assertEqual(report["package"]["sha256"], hashlib.sha256(self.package.read_bytes()).hexdigest())
        self.assertEqual(report["validation"]["guest_helper_application"]["bundle_id"], "com.henge.guesthelper")

    def test_guest_app_must_be_signed_macos_code(self):
        for binary in (macho(platform=2, minimum=0x0D0000), macho(platform=1, minimum=0x0D0000, signed=False)):
            files = members()
            files["henge-helper.app.tar.gz"] = guest_app_archive(binary)
            self.write(files)
            with self.assertRaises(validator.InvalidPackage):
                self.validate()

    def test_guest_app_archive_must_not_escape_bundle(self):
        files = members()
        files["henge-helper.app.tar.gz"] = guest_app_archive(extra={"Henge Helper.app/../../escaped": b"bad"})
        self.write(files)
        with self.assertRaisesRegex(validator.InvalidPackage, "Unsafe guest app archive path"):
            self.validate()

    def test_rejects_stale_version_build_or_commit(self):
        for field, value in [("CFBundleShortVersionString", "0.3.0"),
                             ("CFBundleVersion", "101"), ("HengeBuildCommit", "f" * 12)]:
            with self.subTest(field=field):
                files = members()
                info = plistlib.loads(files["Info.plist"])
                info[field] = value
                files["Info.plist"] = plistlib.dumps(info)
                self.write(files)
                with self.assertRaises(validator.InvalidPackage):
                    self.validate()

    def test_rejects_newer_os_simulator_and_wrong_cpu(self):
        for kwargs in ({"minimum": 0x110100}, {"platform": 7}, {"cpu": 0x01000007}):
            with self.subTest(kwargs=kwargs):
                files = members()
                files["Henge"] = macho({"get-task-allow": True}, **kwargs)
                self.write(files)
                with self.assertRaisesRegex(validator.InvalidPackage, "newer iOS|arm64"):
                    self.validate()

    def test_checks_info_minimum_os_separately(self):
        files = members()
        info = plistlib.loads(files["Info.plist"])
        info["MinimumOSVersion"] = "17.4"
        files["Info.plist"] = plistlib.dumps(info)
        self.write(files)
        with self.assertRaisesRegex(validator.InvalidPackage, "Info.plist requires"):
            self.validate()

    def test_banned_xml_entitlement_in_main_or_nested_binary(self):
        for name in ("Henge", "PlugIns/HengeJITHelper.appex/HengeJITHelper"):
            with self.subTest(name=name):
                files = members()
                files[name] = macho({"dynamic-codesigning": False})
                self.write(files)
                with self.assertRaisesRegex(validator.InvalidPackage, "banned TrollStore"):
                    self.validate()

    def test_banned_der_entitlement_is_not_hidden_by_clean_xml(self):
        for key in validator.BANNED_ENTITLEMENTS:
            with self.subTest(key=key):
                files = members()
                files["Henge"] = macho({"get-task-allow": True}, der_key(key))
                self.write(files)
                with self.assertRaisesRegex(validator.InvalidPackage, "banned TrollStore"):
                    self.validate()

    def test_ipa_keeps_non_trollstore_entitlements(self):
        files = members()
        files["Henge"] = macho({"dynamic-codesigning": True})
        self.write(files)
        self.assertFalse(self.validate(kind="ipa")["validation"]["trollstore_entitlements_checked"])

    def test_rejects_unsigned_and_malformed_signatures(self):
        for binary in (macho(signed=False), macho({"get-task-allow": True})[:-1],
                       macho({"get-task-allow": True}, b"\x31\x80")):
            with self.subTest(binary_length=len(binary)):
                files = members()
                files["Henge"] = binary
                self.write(files)
                with self.assertRaises(validator.InvalidPackage):
                    self.validate()

    def test_rejects_missing_resource_and_corrupt_guest_helper(self):
        for missing in (True, False):
            files = members()
            if missing:
                del files["henge-jit.js"]
            else:
                files["henge-agent.gz"] = files["henge-agent.gz"][:-4]
            self.write(files)
            with self.assertRaises(validator.InvalidPackage):
                self.validate()

    def test_rejects_boot_rom_and_unsafe_path(self):
        for name in ("Resources/AVPBooter.vmapple2.bin", "../../../escape"):
            files = members()
            files[name] = b"test"
            self.write(files)
            with self.assertRaises(validator.InvalidPackage):
                self.validate()

    def test_rejects_duplicate_zip_members(self):
        self.write()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.package, "a") as archive:
                archive.writestr(validator.APP + "Henge", b"replacement")
        with self.assertRaisesRegex(validator.InvalidPackage, "duplicate"):
            self.validate()

    def test_cli_writes_manifest_and_removes_stale_reports_on_failure(self):
        self.write()
        manifest, checksum = self.folder / "manifest.json", self.folder / "SHA256SUMS"
        command = [sys.executable, str(VALIDATOR), str(self.package), "--expected-commit", COMMIT,
                   "--manifest", str(manifest), "--sha256-file", str(checksum)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(manifest.read_text())
        self.assertEqual(checksum.read_text(), f"{report['package']['sha256']}  Henge.tipa\n")
        result = subprocess.run(command + ["--expected-build", "9999"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(manifest.exists())
        self.assertFalse(checksum.exists())
        self.assertTrue(self.package.exists())

    @unittest.skipUnless(shutil.which("zsh") and shutil.which("git"), "Needs zsh and git")
    def test_early_packaging_failure_removes_previous_advertised_output(self):
        repo = self.folder / "source"
        scripts = repo / "ios/scripts"
        scripts.mkdir(parents=True)
        (repo / "ios/deps/StikJIT.xcframework").mkdir(parents=True)
        packager = scripts / "package_ipa.sh"
        shutil.copyfile(ROOT / "ios/scripts/package_ipa.sh", packager)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "ios/scripts/package_ipa.sh"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Package Test", "-c",
                        "user.email=package-test@example.invalid", "commit", "-qm", "fixture"], check=True)
        fakebin = self.folder / "fakebin"
        fakebin.mkdir()
        tool = fakebin / "xcodegen"
        tool.write_text("#!/bin/sh\nexit 7\n")
        tool.chmod(0o755)
        output = self.folder / "output"
        output.mkdir()
        for name in ("Henge.tipa", "Henge.tipa.manifest.json", "Henge.tipa.sha256"):
            (output / name).write_text("old test fixture")
        env = dict(os.environ, HENGE_PACKAGE_OUTPUT_DIR=str(output),
                   PATH=str(fakebin) + os.pathsep + os.environ.get("PATH", ""))
        result = subprocess.run(["zsh", str(packager), "--trollstore"], env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
