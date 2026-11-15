#!/usr/bin/env python3
"""Controlled OS tools for executing the real installer inside a temporary test home.

No network or launchd operations are performed by this harness. Actual macOS binary/signature
validation is a separate CI gate; these tests verify transaction/error/receipt control flow.
"""
import gzip
import json
import os
from pathlib import Path
import plistlib
import sys
import subprocess
from urllib.parse import parse_qs, urlparse

root = Path(os.environ["HENGE_INSTALL_TEST_STATE"])
scenario = os.environ.get("HENGE_INSTALL_TEST_SCENARIO", "ok")
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "commands.jsonl").open("a") as out:
    out.write(json.dumps({"tool": name, "args": args}) + "\n")

if name == "curl":
    url = next((x for x in args if x.startswith("http://")), "")
    if "/install-status?" in url:
        receipt = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        with (root / "receipts.jsonl").open("a") as out:
            out.write(json.dumps(receipt) + "\n")
        if scenario == "receipt_failed" and receipt["stage"] == "launch_requested":
            sys.exit(7)
        print('{"ok":true}')
    elif url.endswith("/.henge/agent"):
        if scenario == "download_failed":
            sys.exit(7)
        destination = Path(args[args.index("-o") + 1])
        data = (root / "new-agent").read_bytes()
        destination.write_bytes(b"not gzip" if scenario == "gzip_invalid" else gzip.compress(data))
    else:
        sys.exit(2)
elif name == "codesign":
    sys.exit(4 if scenario == "signature_invalid" else 0)
elif name == "plutil":
    try:
        with Path(args[-1]).open("rb") as stream:
            value = plistlib.load(stream)
        assert value["ProgramArguments"][0] == str(Path(os.environ["HOME"]) / "Library/Application Support/Henge/henge-agent")
        (root / "parsed-plist.json").write_text(json.dumps(value))
    except Exception:
        sys.exit(2)
elif name == "launchctl":
    path = root / "launch-state.json"
    state = json.loads(path.read_text())
    if args[0] == "print":
        if not state["loaded"]:
            sys.exit(113)
        print(f"service = {{\n\tpid = {state['pid']}\n}}")
    elif args[0] == "bootout":
        if scenario == "bootout_failed":
            sys.exit(5)
        if not state["loaded"]:
            sys.exit(113)
        state["loaded"] = False
    elif args[0] == "bootstrap":
        state["bootstraps"] += 1
        if scenario == "bootstrap_failed" and state["bootstraps"] == 1:
            path.write_text(json.dumps(state))
            sys.exit(5)
        state["loaded"] = True
        binary = Path(os.environ["HOME"]) / "Library/Application Support/Henge/henge-agent"
        state["pid"] = 321 if binary.read_bytes().startswith(b"old helper") else 999
    else:
        sys.exit(2)
    path.write_text(json.dumps(state))
elif name == "date":
    path = root / "clock"
    now = int(path.read_text()) + 8 if path.exists() else 100
    path.write_text(str(now))
    print(100 if scenario == "health_clock_backwards" else now)
elif name == "sleep":
    pass
elif name == "mv":
    if scenario == "rollback_failed" and any(arg.endswith("previous-agent") for arg in args):
        sys.exit(5)
    sys.exit(subprocess.run(["/bin/mv", *args]).returncode)
else:
    sys.exit(2)
