#!/usr/bin/env python3
"""Controlled OS tools for the real installer. No actual launchd/network operations occur."""
import io, json, os, plistlib, signal, subprocess, sys, tarfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse
root = Path(os.environ["HENGE_INSTALL_TEST_STATE"])
scenario = os.environ.get("HENGE_INSTALL_TEST_SCENARIO", "ok")
name, args = Path(sys.argv[0]).name, sys.argv[1:]
with (root / "commands.jsonl").open("a") as out:
    out.write(json.dumps({"tool": name, "args": args}) + "\n")
statepath = root / "launch-state.json"
state = json.loads(statepath.read_text())
if name == "curl":
    url = next((x for x in args if x.startswith("http://")), "")
    if "/install-status?" in url:
        receipt = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        with (root / "receipts.jsonl").open("a") as out: out.write(json.dumps(receipt) + "\n")
        if scenario == "receipt_failed" and receipt["stage"] == "launch_requested": sys.exit(7)
        print('{"ok":true}')
    elif url.endswith("/.henge/helper/app"):
        if scenario == "download_failed": sys.exit(7)
        destination = Path(args[args.index("-o") + 1])
        if scenario == "gzip_invalid": destination.write_bytes(b"not gzip")
        else:
            with tarfile.open(destination, "w:gz") as archive:
                for entry, data, mode in (
                    ("Henge Helper.app/Contents/MacOS/henge-agent", (root / "new-agent").read_bytes(), 0o755),
                    ("Henge Helper.app/Contents/Info.plist", plistlib.dumps({"CFBundleIdentifier":"com.henge.helper"}), 0o644),
                    ("Henge Helper.app/Contents/marker", b"new", 0o644)):
                    item = tarfile.TarInfo(entry); item.size=len(data); item.mode=mode
                    archive.addfile(item, io.BytesIO(data))
                if scenario == "archive_traversal":
                    item=tarfile.TarInfo("../escaped"); item.size=4
                    archive.addfile(item, io.BytesIO(b"bad!"))
                if scenario in ("archive_symlink", "archive_hardlink"):
                    item=tarfile.TarInfo("Henge Helper.app/Contents/escape")
                    item.type=tarfile.SYMTYPE if scenario == "archive_symlink" else tarfile.LNKTYPE
                    item.linkname="../../../escaped"
                    archive.addfile(item)
    else: sys.exit(2)
elif name == "codesign": sys.exit(4 if scenario == "signature_invalid" else 0)
elif name == "launchctl":
    if args[0] == "print":
        if not state["loaded"]: sys.exit(113)
        print(f"service = {{\n\tpid = {state['pid']}\n}}")
    elif args[0] == "bootout":
        if scenario == "bootout_failed": sys.exit(5)
        if not state["loaded"]: sys.exit(113)
        state["loaded"] = False
    elif args[0] == "bootstrap": state["loaded"] = True; state["pid"] = 321; state["bootstraps"] += 1
    else: sys.exit(2)
    statepath.write_text(json.dumps(state))
elif name == "open":
    app=Path(args[args.index("-a")+1]); marker=(app/"Contents/marker").read_text()
    if scenario == "bootstrap_failed" and marker == "new": sys.exit(5)
    state["app_running"] = scenario not in ("health_unconfirmed", "rollback_failed") or marker == "old"
    state["app_marker"] = marker
    statepath.write_text(json.dumps(state))
elif name == "sleep":
    state["slept_seconds"] += int(args[0]); statepath.write_text(json.dumps(state))
elif name in ("mv", "cp", "rm"):
    if scenario == "rollback_failed" and len(args) >= 2 and args[-2].endswith("previous.plist"): sys.exit(5)
    result=subprocess.run(["/bin/"+name, *args]).returncode
    if name == "rm" and scenario == "interrupt_replacement" and args[-1].endswith("Henge Helper.app") and not (root/"interrupted").exists():
        (root/"interrupted").touch()
        os.kill(os.getppid(), signal.SIGTERM)
    sys.exit(result)
else: sys.exit(2)
