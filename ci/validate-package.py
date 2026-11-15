#!/usr/bin/env python3
"""Validate a Henge IPA/TIPA without extracting or executing it.

Uses only the Python standard library, including on Linux. This checks package
structure and embedded entitlement blobs; it does not replace codesign's
cryptographic verification or an installation/run on a real iPad.
"""

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import struct
import sys
import tempfile
import zipfile


BANNED_ENTITLEMENTS = frozenset({
    "com.apple.private.cs.debugger",
    "dynamic-codesigning",
    "com.apple.private.skip-library-validation",
})
APP = "Payload/Henge.app/"
REQUIRED = (
    "Info.plist", "Henge", "henge-jit.js", "henge-agent.gz",
    "PlugIns/HengeJITHelper.appex/Info.plist",
    "PlugIns/HengeJITHelper.appex/HengeJITHelper",
    "Frameworks/StikJIT.framework/Info.plist",
    "Frameworks/StikJIT.framework/StikJIT",
)
MACH_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
               b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
               b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")


class InvalidPackage(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidPackage(message)


def version(value):
    require(isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+){0,2}", value),
            f"Invalid OS version: {value!r}")
    parts = tuple(int(x) for x in value.split("."))
    return parts + (0,) * (3 - len(parts))


def packed_version(value):
    return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"


def der_strings(data):
    """Inspect DER entitlement strings as well as the XML entitlement slot.

    Apple DER entitlements are constructed ASN.1 values containing UTF-8 keys.
    Traverse the bounded TLV tree rather than scanning unrelated Mach-O strings.
    Reject malformed/unsupported encodings instead of declaring them clean.
    """
    strings = set()

    def walk(start, end, depth):
        require(depth <= 32, "DER entitlement nesting is too deep")
        pos = start
        while pos < end:
            require(pos + 2 <= end, "Truncated DER entitlement")
            tag, length = data[pos], data[pos + 1]
            pos += 2
            require(tag & 31 != 31, "Unsupported DER entitlement tag")
            if length & 128:
                count = length & 127
                require(0 < count <= 4 and pos + count <= end,
                        "Invalid DER entitlement length")
                length = int.from_bytes(data[pos:pos + count], "big")
                pos += count
            stop = pos + length
            require(stop <= end, "DER entitlement exceeds its blob")
            if tag & 32:
                walk(pos, stop, depth + 1)
            elif tag in (12, 19, 22):
                try:
                    strings.add(data[pos:stop].decode("utf-8"))
                except UnicodeDecodeError as exc:
                    raise InvalidPackage("Invalid DER entitlement string") from exc
            pos = stop
        require(pos == end, "Invalid DER entitlement boundary")

    require(bool(data), "Empty DER entitlement blob")
    walk(0, len(data), 0)
    return strings


def signature_entitlements(data):
    require(len(data) >= 12, "Missing embedded code signature")
    magic, length, count = struct.unpack_from(">III", data)
    require(magic == 0xFADE0CC0 and 12 + count * 8 <= length <= len(data),
            "Invalid code-signature superblob")
    keys, der_values, has_entitlements, has_directory = set(), set(), False, False
    slots = set()
    for index in range(count):
        slot, offset = struct.unpack_from(">II", data, 12 + index * 8)
        require(slot not in slots, "Duplicate code-signature slot")
        slots.add(slot)
        require(12 + count * 8 <= offset <= length - 8, "Invalid signature blob offset")
        blob_magic, blob_length = struct.unpack_from(">II", data, offset)
        require(8 <= blob_length <= length - offset, "Invalid signature blob length")
        payload = data[offset + 8:offset + blob_length]
        if slot == 0:
            require(blob_magic == 0xFADE0C02, "Missing CodeDirectory")
            has_directory = True
        if slot == 5 or blob_magic == 0xFADE7171:
            require(slot == 5 and blob_magic == 0xFADE7171, "Invalid XML entitlement slot")
            try:
                entitlements = plistlib.loads(payload.rstrip(b"\0"))
            except Exception as exc:
                raise InvalidPackage("Cannot parse signed XML entitlements") from exc
            require(isinstance(entitlements, dict), "Signed entitlements are not a dictionary")
            keys.update(entitlements)
            has_entitlements = True
        if slot == 7 or blob_magic == 0xFADE7172:
            require(slot == 7 and blob_magic == 0xFADE7172, "Invalid DER entitlement slot")
            der_values.update(der_strings(payload))
            has_entitlements = True
    require(has_directory, "Signature has no CodeDirectory")
    return keys, der_values, has_entitlements


def macho_slices(data):
    magic = data[:4]
    if magic in MACH_MAGICS[:2]:
        return [data]
    require(magic in MACH_MAGICS[2:] and len(data) >= 8, "Not a 64-bit Mach-O executable")
    endian = ">" if magic in (MACH_MAGICS[2], MACH_MAGICS[4]) else "<"
    fat64 = magic in MACH_MAGICS[4:]
    count = struct.unpack_from(endian + "I", data, 4)[0]
    entry_size = 32 if fat64 else 20
    require(0 < count <= 32 and 8 + count * entry_size <= len(data), "Invalid fat Mach-O header")
    slices, regions = [], []
    for index in range(count):
        at = 8 + index * entry_size
        offset, size = struct.unpack_from(endian + ("QQ" if fat64 else "II"), data, at + 8)
        require(offset >= 8 + count * entry_size and size >= 32 and offset + size <= len(data),
                "Invalid fat Mach-O slice")
        require(all(offset + size <= lo or offset >= hi for lo, hi in regions),
                "Overlapping fat Mach-O slices")
        regions.append((offset, offset + size))
        slices.append(data[offset:offset + size])
    return slices


def inspect_macho(data, name, trollstore, main=False, maximum_ios="17.0"):
    reports = []
    for data in macho_slices(data):
        require(len(data) >= 32 and data[:4] in MACH_MAGICS[:2], f"{name}: invalid Mach-O slice")
        endian = "<" if data[:4] == MACH_MAGICS[0] else ">"
        _, cpu, subtype, filetype, count, command_bytes, _, _ = struct.unpack_from(endian + "8I", data)
        require(count <= 4096 and 32 + command_bytes <= len(data), f"{name}: invalid load commands")
        pos, stop, signature, minimum = 32, 32 + command_bytes, None, []
        for _ in range(count):
            require(pos + 8 <= stop, f"{name}: truncated load command")
            command, size = struct.unpack_from(endian + "II", data, pos)
            require(size >= 8 and pos + size <= stop, f"{name}: invalid load command size")
            if command == 0x1D:  # LC_CODE_SIGNATURE
                require(size >= 16 and signature is None, f"{name}: invalid signature command")
                offset, length = struct.unpack_from(endian + "II", data, pos + 8)
                require(offset >= stop and length > 0 and offset + length <= len(data),
                        f"{name}: invalid code signature range")
                signature = data[offset:offset + length]
            elif command == 0x32:  # LC_BUILD_VERSION
                require(size >= 24, f"{name}: truncated build version")
                platform, min_os = struct.unpack_from(endian + "II", data, pos + 8)
                minimum.append((platform, packed_version(min_os)))
            elif command == 0x25:  # LC_VERSION_MIN_IPHONEOS
                require(size >= 16, f"{name}: truncated minimum iOS version")
                minimum.append((2, packed_version(struct.unpack_from(endian + "I", data, pos + 8)[0])))
            pos += size
        require(pos == stop, f"{name}: load-command size mismatch")
        require(signature is not None, f"{name}: executable is unsigned")
        keys, der_values, has_entitlements = signature_entitlements(signature)
        if trollstore:
            bad = BANNED_ENTITLEMENTS & (keys | der_values)
            require(not bad, f"{name}: banned TrollStore entitlements: {', '.join(sorted(bad))}")
        if main:
            require(cpu == 0x0100000C and (subtype & 0xFFFFFF) in (0, 2) and filetype == 2,
                    f"{name}: main executable must be arm64 for an iOS device")
            require(bool(minimum), f"{name}: missing minimum iOS version")
            require(all(platform == 2 and version(v) <= version(maximum_ios) for platform, v in minimum),
                    f"{name}: main executable requires a newer iOS or targets a simulator/non-iOS platform")
            require(has_entitlements, f"{name}: no signed entitlements")
        reports.append({"cpu_type": cpu, "cpu_subtype": subtype,
                        "minimum_versions": [{"platform": p, "version": v} for p, v in minimum],
                        "xml_entitlement_keys": sorted(keys), "has_entitlements": has_entitlements})
    return reports


def validate_package(package, expected_commit, expected_version="0.4.0", expected_build="4002",
                     kind=None, maximum_ios="17.0", husk_commit=None, run_url=None):
    package = Path(package)
    require(bool(re.fullmatch(r"[0-9a-f]{40}", expected_commit)), "Expected commit must be a full git SHA-1")
    kind = kind or package.suffix.lstrip(".")
    require(kind in ("ipa", "tipa"), "Package kind must be ipa or tipa")
    if husk_commit is not None:
        require(bool(re.fullmatch(r"[0-9a-f]{40}", husk_commit)), "Husk commit must be a full git SHA-1")
    with zipfile.ZipFile(package) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        require(len(names) == len(set(names)), "Package has duplicate ZIP entries")
        require(sum(entry.file_size for entry in entries) <= 1024 ** 3, "Package is unexpectedly large")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in entry.filename,
                    "Unsafe ZIP member path")
            require(entry.file_size <= 256 * 1024 ** 2, "ZIP member is unexpectedly large")
            require(not path.name.lower().startswith(("avpbooter", "avpsepbooter")),
                    "Apple boot ROM must not be bundled")
        apps = {name.split("/")[1] for name in names if name.startswith("Payload/")
                and len(name.split("/")) > 2 and name.split("/")[1].endswith(".app")}
        require(apps == {"Henge.app"}, "Expected exactly Payload/Henge.app")
        require(archive.testzip() is None, "ZIP checksum failure")
        for name in REQUIRED:
            require(APP + name in names and archive.getinfo(APP + name).file_size > 0,
                    f"Missing required resource: {name}")
        try:
            info = plistlib.loads(archive.read(APP + "Info.plist"))
            for name in ("PlugIns/HengeJITHelper.appex/Info.plist", "Frameworks/StikJIT.framework/Info.plist"):
                require(isinstance(plistlib.loads(archive.read(APP + name)), dict), f"Invalid {name}")
        except InvalidPackage:
            raise
        except Exception as exc:
            raise InvalidPackage("Cannot parse bundle Info.plist") from exc
        require(isinstance(info, dict), "Application Info.plist is not a dictionary")
        require(info.get("CFBundleExecutable") == "Henge", "Unexpected main executable")
        require(info.get("CFBundleShortVersionString") == expected_version, "Application version mismatch")
        require(info.get("CFBundleVersion") == expected_build, "Application build number mismatch")
        require(info.get("HengeBuildCommit") == expected_commit[:12], "Build commit mismatch (possibly an old package)")
        require(version(info.get("MinimumOSVersion")) <= version(maximum_ios), "Info.plist requires a newer iOS")
        try:
            datetime.strptime(info.get("HengeBuildDate", ""), "%Y-%m-%dT%H:%M:%SZ")
            with gzip.GzipFile(fileobj=io.BytesIO(archive.read(APP + "henge-agent.gz"))) as agent:
                total = 0
                for block in iter(lambda: agent.read(1024 ** 2), b""):
                    total += len(block)
                    require(total <= 64 * 1024 ** 2, "Guest helper is unexpectedly large")
                require(total > 0, "Empty guest helper")
        except InvalidPackage:
            raise
        except (ValueError, OSError, EOFError, TypeError) as exc:
            raise InvalidPackage("Invalid build date or compressed guest helper") from exc
        binaries = {}
        for entry in entries:
            if entry.is_dir() or not entry.filename.startswith(APP) or entry.file_size < 4:
                continue
            with archive.open(entry) as stream:
                magic = stream.read(4)
            if magic in MACH_MAGICS:
                relative = entry.filename[len(APP):]
                binaries[relative] = inspect_macho(archive.read(entry), relative, kind == "tipa",
                                                  main=relative == "Henge", maximum_ios=maximum_ios)
        for name in ("Henge", "PlugIns/HengeJITHelper.appex/HengeJITHelper", "Frameworks/StikJIT.framework/StikJIT"):
            require(name in binaries, f"Required executable is not Mach-O: {name}")
    digest = hashlib.sha256()
    with package.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b""):
            digest.update(block)
    return {
        "schema_version": 1,
        "package": {"filename": package.name, "kind": kind, "size_bytes": package.stat().st_size,
                    "sha256": digest.hexdigest()},
        "application": {"bundle_identifier": info.get("CFBundleIdentifier"), "version": expected_version,
                        "build": expected_build, "minimum_ios": info["MinimumOSVersion"],
                        "build_commit": info["HengeBuildCommit"], "build_date": info["HengeBuildDate"],
                        "base_commit": info.get("HengeBaseCommit"), "test_build_name": info.get("HengeTestBuildName")},
        "source": {"henge_commit": expected_commit, "husk_commit": husk_commit},
        "workflow_run_url": run_url,
        "validation": {"checked_at": datetime.now(timezone.utc).isoformat(), "maximum_main_ios": maximum_ios,
                       "trollstore_entitlements_checked": kind == "tipa", "signed_macho_files": binaries,
                       "scope": "ZIP, resources, version, commit, Mach-O platform and embedded entitlement structure; not a device test or cryptographic signature verification"},
    }


def atomic_text(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-version", default="0.4.0")
    parser.add_argument("--expected-build", default="4002")
    parser.add_argument("--kind", choices=("ipa", "tipa"))
    parser.add_argument("--maximum-ios", default="17.0")
    parser.add_argument("--husk-commit")
    parser.add_argument("--run-url")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--sha256-file", type=Path)
    args = parser.parse_args()
    try:
        outputs = [path for path in (args.manifest, args.sha256_file) if path is not None]
        paths = [args.package.resolve(), *(path.resolve() for path in outputs)]
        require(len(paths) == len(set(paths)), "Package and report paths must be different")
        # A failed check must not leave an earlier successful report behind.
        for path in outputs:
            path.unlink(missing_ok=True)
        report = validate_package(args.package, args.expected_commit, args.expected_version, args.expected_build,
                                  args.kind, args.maximum_ios, args.husk_commit, args.run_url)
        if args.manifest:
            atomic_text(args.manifest, json.dumps(report, indent=2, sort_keys=True) + "\n")
        if args.sha256_file:
            atomic_text(args.sha256_file, f"{report['package']['sha256']}  {args.package.name}\n")
        print(f"Validated {args.package.name}: {args.expected_version} ({args.expected_build}), "
              f"commit {args.expected_commit[:12]}, {len(report['validation']['signed_macho_files'])} signed Mach-O files")
        return 0
    except (InvalidPackage, OSError, zipfile.BadZipFile, struct.error) as exc:
        print(f"Package validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
