# Host services, protocol 1

The 0.4 bridge uses Henge's existing guest-only HTTP connection at
http://10.0.2.4/.henge/v1/. libslirp routes it to the app's private Unix socket.
It adds live main-screen brightness and output-volume readings, and optional
main-screen brightness control. The shared folder and clipboard retain their
existing routes and behavior.

## Using the guest helper

Update the helper inside the running Mac using the Sharing setup command:

    curl -fsS http://10.0.2.4/.henge/install | sh

The helper remains at:

    "$HOME/Library/Application Support/Henge/henge-agent"

Without arguments it runs the folder/clipboard LaunchAgent as before. The same
executable also provides a CLI:

    "$HOME/Library/Application Support/Henge/henge-agent" --host-capabilities
    "$HOME/Library/Application Support/Henge/henge-agent" --host-state
    "$HOME/Library/Application Support/Henge/henge-agent" --host-brightness 0.6

The last command asks for 60% brightness. First enable **Allow Mac to change iPad
brightness** in the running Mac's **Details → iPad services**. This changes the
iPad's actual main-screen brightness through UIKit; Henge's existing Display
brightness slider continues to dim only the Mac's picture.

The CLI exits 0 for an HTTP 200 result, 1 for an unavailable/rejected service, and
2 for invalid command-line arguments. It prints successful JSON to stdout and
errors to stderr. It fetches the current session UUID before a brightness write.

Permission is off at every new Mac session and is not persisted. Writes are
accepted only while the Mac is running and Henge is active. Disabling permission,
ending a session or backgrounding Henge cancels queued writes. When permission
ends, Henge restores the brightness saved on opt-in if the screen still matches
the last value applied by the bridge. A different value subsequently selected
in Control Center is preserved.

This version does not implement Wi-Fi control, Bluetooth control, Apple Account
or DeviceCheck forwarding. Those capabilities are explicitly false. Reading
the output volume does not authorize or implement changing it.

## HTTP interface

All responses are JSON with protocol: 1 and Cache-Control: no-store.
Requests must not carry an Origin header. Browser CORS access is not offered.

### GET capabilities

    GET /.henge/v1/capabilities

Returns the current session, whether the host is active, and features.
Brightness and output-volume availability reflect a fresh published host
snapshot. brightness.controlEnabled is true only when the current session
is running, foreground, and opted in. A stale snapshot never grants writes.

### GET state

    GET /.henge/v1/state

Returns session, active, running, foreground, fresh, ageMs, brightness and
outputVolume. Brightness has scope: "mainScreen", value, controlEnabled and
pending. Output volume has value and writable: false. Values are null when
the snapshot is absent or more than five seconds old.

The iOS main actor publishes a snapshot at each half-second Sharing tick and
when app activity or the permission switch changes. Ending or failing a VM
also revokes the service immediately in the C lifecycle callbacks.

### POST brightness

    POST /.henge/v1/brightness
    Content-Type: application/json
    X-Henge-Session: <UUID returned by this session's state>
    Content-Length: <body byte count>

    {"value":0.6}

The body must be a single JSON number field named value, between 0 and 1.
It is limited to 128 bytes. Extra/duplicate fields, nonfinite values, duplicate
framing/session headers, chunked bodies and missing content length are rejected.
The session UUID is required and changes on each boot attempt.

There is at most one in-flight brightness request. The HTTP worker waits up to
two seconds for the UI thread. Immediately before applying, the UI thread
rechecks session state, permission, foreground state and expiry, invokes a short
synchronous UIKit setter, and returns the actual brightness. A timed-out queued
request is removed and cannot be applied by a later UI tick. A successful result
contains protocol, session, requestId and the applied brightness.

The callback runs with the service mutex held. It must not recurse into the C
service, dispatch synchronously to another thread, or spin an event loop.

Errors use HTTP 400 for malformed input, 403 for missing/disabled permission or
a browser origin, 409 for a changed/ended session, 411 for missing length, 413
for body size, 415 for content type, 429 for an existing request, 503 for an
inactive/unavailable host or failed setter, and 504 for an expired request.
Unknown routes use 404; incorrect methods use 405.

The UUID binds requests to the current session. It is not authentication between
processes in the guest: any guest process that can read the endpoint can obtain
it. The user opts the whole running Mac into brightness control. There are no
generic command-execution, arbitrary path, credential or private-radio methods.

## Validation

Run:

    python3 tests/test_host_services.py

The suite compiles the actual C HTTP implementation and exercises request
parsing, route dispatch, state publication, explicit permission, stale/ended
sessions, foreground changes, one-request bounds, timeout cancellation, actual
apply acknowledgments, and the existing file/clipboard routes. Its fake UI
thread provides a controlled setter; it does not claim to test UIKit hardware.

The default transport uses Unix socketpairs without opening a listening port.
Where local listeners are permitted, also run:

    HENGE_TEST_LISTENER=1 python3 tests/test_host_services.py

On Linux, small test-only shims cover Apple filesystem APIs used by unrelated
recursive COPY/DELETE routes. On macOS those shims are not used. The guest helper
and Swift UI still require the normal macOS/Xcode build, and physical iPad
brightness/lifecycle behavior requires an on-device test.
