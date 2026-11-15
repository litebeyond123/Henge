# Chat diagnostics in an existing Mac

This adds a fixed error-summary collector to `henge-agent`. It does not generate
a DeviceCheck token, forward an iPad identity, change ChatGPT, or probe Apple's
DeviceCheck API. An observed DeviceCheck error remains a diagnosis, not a native
Chat fix.

## Enable once, then use one host button

1. Install the new Henge test build and start the existing Mac.
2. Open Terminal in the Mac and leave its input focused. In Henge's running-Mac
   Details, Sharing, tap **Type the Update Helper Command** (or **Type the Set Up
   Command** if sharing has not been installed). Return to Terminal and press
   Return. Allow the helper's local-network access if macOS asks.
3. After reproducing the Chat error, tap **Collect Chat diagnostics** in Henge.
   Henge waits asynchronously for at most 15 seconds, then produces its one host
   report. A completed Mac summary is included automatically. If the guest
   finishes later, its validated summary triggers an automatic report refresh.

No VM image rebuild is required. The old helper has no command-dispatch feature;
updating the iPad app alone cannot update an already installed guest helper.
The setup button types a command only: Henge does not guess the focused guest
application or automatically press Return.

Host files are in `Documents/Shared/Henge-Chat-Diagnostics`. The existing helper
mounts `Documents/Shared` at `~/Henge` inside macOS. The optional **Enable Chat
Diagnostics.command** performs the same helper update; WebDAV can prevent
double-click execution, so the Terminal/setup-button procedure above is the
primary path. **ChatGPT in Browser.webloc** opens `https://chatgpt.com/` as an
alternative, not as a repair to the native client.

## Scope and privacy

The helper reads only the product/build version, architecture, `hw.model`, and
Info.plist/signature metadata of `/Applications/ChatGPT.app` or
`~/Applications/ChatGPT.app`. The bundle identifier is read, not assumed. It
does not enumerate the rest of the home folder. Signature verification covers
the main bundle and has a short deadline; a timeout is not called a bad signature.

A read-only `log show --last 15m --style json --info --debug` query uses a fixed
predicate for ChatGPT and DeviceCheck system services. Debug is included because
`DeviceCheck is not supported.` can be a debug-level record. The raw query result
exists only in bounded memory. The output contains fixed error categories,
counts and normalized times; no raw event message or arbitrary exception text
is retained. Invalid, timed-out or oversized log output is explicitly marked.
An empty result means no recognized error was observed in that query, not that
ChatGPT or DeviceCheck works.

`source_scope=mixed_chatgpt_device_services` is explicit. Matches from ChatGPT,
system device services and unknown sources have separate counters. A daemon's
DeviceCheck message alone does not establish that ChatGPT was its requester.

The collector does not read conversation databases, cookies, credentials,
tokens, keychain contents, process environments or complete application archives.
It does not change accounts, authentication, SIP or other system settings.

## Protocol and limits

Only `task=chat_error_summary` is accepted. `request.json` contains a new random
VM-session UUID, a request UUID, and created/expires timestamps 60 seconds apart.
The guest checks the identifiers and deadline before collecting and again before
uploading `report.json`. There is one in-flight collection per helper process.
The two-second poll itself does not scan logs; collection occurs once per fresh
request. A lightweight heartbeat is updated at most every 15 seconds. While
Henge is active and the Mac is running, the host requests at most one automatic
summary every 120 seconds, without replacing a pending manual request. These
are separate snapshots of the last 15 minutes, not cumulative error totals.

The host rotates the session at every VM start, invalidates requests when that
VM stops, and refreshes a startup request with less than 20 seconds left once
the updated helper is first detected. It independently checks both UUIDs and both request timestamps,
the completion time, scalar types, enumerated strings and every count. It
rebuilds a flat allowlisted JSON object, never copying the raw guest file.

Request/heartbeat reads are capped at 4 KiB and report reads at 16 KiB. Host file
reads use `openat`, `O_NOFOLLOW` and a hard read ceiling, so a file growing after
`stat` does not bypass the cap. Writes are atomic. The only imported file is
`Documents/HengeDiagnostics/Inputs/guest-chat.json`. A late valid import posts
`HengeGuestChatDiagnosticsUpdated`; unrelated shared files are not imported.
If saving fails, the old input is removed when possible and a fixed
`summary_write_failed` status plus error number is recorded. The diagnostic
writer can read `GuestChatDiagnosticsPersistence.status` from any queue; a
failed write is never reported as a successful fresh import.

The command budget is 10 seconds for metadata and the log query, with a 2 MiB
log-output ceiling enforced while reading. Child processes are killed at the
deadline/output ceiling without an unbounded `waitUntilExit`. Collection can
still be unavailable because of log access restrictions, guest clock skew,
network permissions, a stopped VM, or an old helper. These states are reported,
and host diagnostics remain available. A prior captured summary, when retained
during another request, is explicitly labelled stale.

## Validation

On macOS:

```sh
make build/test_guest_chat_diagnostics
build/test_guest_chat_diagnostics
xcrun --sdk macosx swiftc -swift-version 5 ios/Henge/GuestChatDiagnostics.swift tests/test_guest_chat_diagnostics.swift -o /tmp/henge-test-guest-chat
/tmp/henge-test-guest-chat
sh -n ios/Henge/Resources/guest-chat-diagnostics.command
```

The Objective-C tests execute the production error classifier and request
parser with synthetic secret-bearing messages and the observed DeviceCheck
wording. They also execute the actual bounded child-process reader against
normal, empty, timed-out and oversized output. The Foundation Swift tests execute
the actual host allowlist and file I/O against wrong requests/sessions, expiry,
invalid scalar types, injected fields, oversized files and symlinks. These tests
do not establish that a real VM can produce a valid DeviceCheck token or that
the native Chat app is repaired. Guest execution and the iOS bridge still need
the actual macOS/iPad test build.
