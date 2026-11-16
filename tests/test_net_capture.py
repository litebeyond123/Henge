#!/usr/bin/env python3
"""Portable Test11 capture gate; no live network or personal data is read."""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[1]
    compiler = os.environ.get("CC") or shutil.which("clang") or shutil.which("cc")
    if not compiler:
        raise SystemExit("C compiler required; capture tests were not run")
    env = os.environ.copy()
    env.pop("SDKROOT", None)
    env.pop("IPHONEOS_DEPLOYMENT_TARGET", None)
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-pthread", "-O2"]
    with tempfile.TemporaryDirectory(prefix="henge-capture-test-") as directory:
        temporary = Path(directory)
        # Compile the normal production translation unit as well as the test's
        # deterministic-clock inclusion, so fixture macros cannot hide errors.
        subprocess.run([compiler, *flags, "-c", str(root / "host/net_capture.c"),
                        "-o", str(temporary / "production.o")], env=env, check=True)
        executable = temporary / "test-net-capture"
        subprocess.run([compiler, *flags, str(root / "tests/test_net_capture.c"),
                        "-o", str(executable)], env=env, check=True)
        subprocess.run([str(executable), directory], env=env, check=True)
        metadata = json.loads((temporary / "synthetic-metadata.json").read_text())
        pcap = (temporary / "synthetic-headers.pcap").read_bytes()
        assert metadata["pcap_bytes"] == len(pcap) <= 2 * 1024 * 1024
        assert metadata["status"] == "stopped" and metadata["stop_reason"] == "user"
        assert metadata["maximum_seconds"] == 120 and metadata["captured_frames"] == 3
        assert metadata["application_payload_included"] is False
        assert metadata["host_native_devicecheck_traffic_included"] is False
        assert metadata["http_status_observable"] is False and metadata["process_attribution"] is False
        assert b"HENGE_SECRET_CANARY" not in pcap
        assert "HENGE_SECRET_CANARY" not in json.dumps(metadata)
        assert struct.unpack_from("<IHHIIII", pcap) == (0xA1B2C3D4, 2, 4, 0, 0, 512, 1)
        offset = 24
        captured = []
        while offset < len(pcap):
            seconds, microseconds, included, original = struct.unpack_from("<IIII", pcap, offset)
            assert seconds == 1760000000 and microseconds == 123456
            assert 0 < included <= original and included <= 512
            packet = pcap[offset + 16:offset + 16 + included]
            assert len(packet) == included
            captured.append(packet)
            offset += 16 + included
        assert offset == len(pcap) and [len(packet) for packet in captured] == [54, 42, 90]
        # Confirm the real local auth bridge address/ports are intact, while
        # the HTTP cookie/token/signature canary following its TCP header is absent.
        assert captured[0][26:34] == bytes([10, 0, 2, 15, 10, 0, 2, 4])
        assert struct.unpack_from(">HH", captured[0], 34) == (45000, 80)
        assert metadata["tx_captured_frames"] == 2 and metadata["rx_delivered_captured_frames"] == 1
        assert len(metadata["flows"]) == 3
        assert sum(flow["packets"] for flow in metadata["flows"]) == 3
        assert sum(flow["captured_header_bytes"] for flow in metadata["flows"]) == 186
        print("net_capture: independent JSON + PCAP decode PASS; local HTTP body absent; not a live-device capture", flush=True)


if __name__ == "__main__":
    main()
