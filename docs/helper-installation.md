# Guest helper repair and connection status (Test 4)

The button is always **Type Install / Repair Command**. First open Terminal inside the Mac and focus its
prompt, then use the button in Henge → Details → Sharing, return to Terminal, and press Return. The
command downloads the script successfully before running it. It does not infer installation from
clipboard traffic, and it does not require rebuilding the Mac disk.

The installer downloads into a temporary directory alongside the installed helper, validates the whole
gzip stream, verifies the helper's signature, and executes `--version` before touching the installed
binary. A foreground `--connection-check` verifies the guest-only HTTP route. That probe is recorded
separately and cannot mark the background daemon online. Existing binary and LaunchAgent files are
saved, replacement uses rename, and launch failures restore those files and the previously loaded job.
Rollback blocks repeated terminal signals; if restoration itself fails, the remaining backup files are
retained rather than removed by cleanup.
The installer checks the actual `launchctl` result and confirms that the PID printed for the new job has
reported a fresh independent heartbeat to the current Henge VM session. Only then does it print success.
There is a 20-second retry window and a separate limit of ten attempts, so a guest clock jump cannot
create an endless wait; a final bounded HTTP request can finish just after that window.

The heartbeat starts before the first NSPasteboard call. Heartbeats and the fixed Chat diagnostic poll
run on a utility queue even if clipboard initialization or the main run loop stalls. A fresh heartbeat
means that the helper connected, not that the clipboard, shared-folder mount, diagnostic collection or
DeviceCheck succeeded. Clipboard exceptions produce the fixed `clipboard_unavailable` stage. The
collector remains request-controlled: new hosts send an explicit JSON `collect: false` for startup
heartbeats, which the new helper honors even if guest time is behind host time. Missing `collect` retains
the old-host behavior; an explicitly present value must be a JSON Boolean. An already installed older
helper does not understand this new flag until repaired.

## Fixed status bridge

`hv_share_helper_health()` and the iOS bridge `henge_share_helper_health()` return a malloc-owned JSON
string. The caller must free it. Access is protected by the existing host-service mutex; VM begin/end
reset every helper field. All ages use the host monotonic clock, not the Mac's wall clock.

Fields are `protocol` (1), `session`, `helper_protocol` (0 or 4), `helper_pid`, `agent_seen_s`,
`probe_seen_s`, `install_seen_s`, `startup_stage`, `install_stage`, `install_error`, and `install_exit_code`.
An age of -1 means unseen. A daemon is recently connected only with protocol 4, a positive PID and
`agent_seen_s` in 0…29. This remains separate from the legacy clipboard timestamp.

- Startup: `unseen`, `network_ready`, `clipboard_starting`, `ready`, `clipboard_unavailable`.
- Installation: `not_started`, `script_started`, `downloaded`, `verified`, `replacing`,
  `launch_requested`, `confirmed`, `failed`, `rolled_back`.
- Error: `none`, `download_failed`, `gzip_invalid`, `signature_invalid`, `version_invalid`,
  `replace_failed`, `plist_invalid`, `bootout_failed`, `bootstrap_failed`, `connection_failed`,
  `health_unconfirmed`, `rollback_failed`.

The guest-only HTTP endpoints accept only the fixed protocol, enums and numeric status. Pings and
receipts require the current `X-Henge-Session`; browser-origin requests and body-bearing/chunked health
requests are rejected. Receipt text cannot contain usernames, paths, command output or stderr. Starting
a new launch clears prior daemon liveness; confirming requires a matching recent PID. These are
connection diagnostics inside one VM, not authentication or proof of a particular trusted application.

## Validation

`python3 tests/test_helper_install.py` exercises the real C routes and the exact served shell script.
The script runs only inside a temporary test home with controlled curl/launchctl/codesign stubs. Tests
verify successful PID confirmation, XML path escaping, separate probe liveness, session reset/rejection,
and preservation/rollback after download, gzip, signature, version, connection, launch or receipt
failures. Stubs do not prove an actual macOS signature or launchd behavior.

On a Mac, run `make build/test_helper_health && build/test_helper_health` for production Foundation
parsers and transport flow. Build the actual executable with `make build/henge-agent.gz`, verify it
with `codesign --verify --strict build/henge-agent`, and run `build/henge-agent --version` (expected
`henge-agent 4`). These offline gates are independent of guest launch/connection confirmation, which
still requires the running VM. The existing host-service and guest-collector regression suites remain
required.

The Test 3 user reports contained no accepted guest snapshot and did not identify a dyld, launchd or
helper exception. These changes repair confirmed installer/observability defects; they do not establish
why the previous VM or Henge process exited, and they do not alter DeviceCheck or native Chat identity.
