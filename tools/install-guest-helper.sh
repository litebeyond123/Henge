#!/bin/sh
# Served with a validated HENGE_INSTALL_SESSION prefix by the current Henge VM session.
# Receipts contain fixed categories and numeric exit codes, never command output or user paths.
umask 077
HENGE_LEGACY_DIR="$HOME/Library/Application Support/Henge"
HENGE_HELPER_PLIST="$HOME/Library/LaunchAgents/com.henge.agent.plist"
HENGE_HELPER_JOB="gui/$(id -u)/com.henge.agent"
HENGE_HELPER_DOMAIN="gui/$(id -u)"
HENGE_HELPER_APP="$HOME/Applications/Henge Helper.app"
HENGE_HELPER_BINARY="$HENGE_HELPER_APP/Contents/MacOS/henge-agent"
HENGE_HELPER_TMP=
HENGE_HELPER_MUTATED=0
HENGE_HELPER_WAS_LOADED=0
HENGE_HELPER_HAD_PLIST=0
HENGE_HELPER_APP_CHANGED=0
HENGE_HELPER_HAD_APP=0
HENGE_HELPER_APP_WAS_RUNNING=0
HENGE_HELPER_KEEP_BACKUP=0

receipt() {
    curl --fail --silent --show-error --connect-timeout 2 --max-time 4 \
        -H "X-Henge-Session: $HENGE_INSTALL_SESSION" -X POST \
        "http://10.0.2.4/.henge/helper/install-status?stage=$1&error=$2&code=$3&pid=${4:-0}" \
        >/dev/null 2>&1
}

cleanup() {
    [ "$HENGE_HELPER_KEEP_BACKUP" -eq 1 ] || [ -z "$HENGE_HELPER_TMP" ] || rm -rf "$HENGE_HELPER_TMP"
}

app_pid() {
    HENGE_HELPER_PID=$("$HENGE_HELPER_BINARY" --app-pid 2>/dev/null) || HENGE_HELPER_PID=
    case "$HENGE_HELPER_PID" in ''|*[!0-9]*|0) return 1 ;; esac
    return 0
}

rollback() {
    HENGE_HELPER_ROLLBACK_OK=1
    if [ "$HENGE_HELPER_APP_CHANGED" -eq 1 ]; then
        if [ -x "$HENGE_HELPER_BINARY" ]; then
            "$HENGE_HELPER_BINARY" --quit-app >/dev/null 2>&1 || HENGE_HELPER_ROLLBACK_OK=0
            if [ "$HENGE_HELPER_HAD_APP" -eq 0 ] && [ "$HENGE_HELPER_ROLLBACK_OK" -eq 1 ]; then
                "$HENGE_HELPER_BINARY" --unregister-login >/dev/null 2>&1 || HENGE_HELPER_ROLLBACK_OK=0
            fi
        fi
        if [ "$HENGE_HELPER_ROLLBACK_OK" -eq 1 ]; then
            rm -rf "$HENGE_HELPER_APP" || HENGE_HELPER_ROLLBACK_OK=0
            if [ "$HENGE_HELPER_HAD_APP" -eq 1 ]; then
                mv "$HENGE_HELPER_TMP/previous.app" "$HENGE_HELPER_APP" || HENGE_HELPER_ROLLBACK_OK=0
            fi
        fi
    fi
    # Do not restart an old helper while the replacement could still be alive.
    [ "$HENGE_HELPER_ROLLBACK_OK" -eq 1 ] || return 1
    if [ "$HENGE_HELPER_HAD_PLIST" -eq 1 ]; then
        cp -p "$HENGE_HELPER_TMP/previous.plist" "$HENGE_HELPER_PLIST" || HENGE_HELPER_ROLLBACK_OK=0
    fi
    if [ "$HENGE_HELPER_WAS_LOADED" -eq 1 ] && [ "$HENGE_HELPER_ROLLBACK_OK" -eq 1 ]; then
        if ! launchctl print "$HENGE_HELPER_JOB" >/dev/null 2>&1; then
            launchctl bootstrap "$HENGE_HELPER_DOMAIN" "$HENGE_HELPER_PLIST" || HENGE_HELPER_ROLLBACK_OK=0
        fi
    fi
    if [ "$HENGE_HELPER_APP_WAS_RUNNING" -eq 1 ] && [ "$HENGE_HELPER_ROLLBACK_OK" -eq 1 ]; then
        open -a "$HENGE_HELPER_APP" --args --install || HENGE_HELPER_ROLLBACK_OK=0
    fi
    [ "$HENGE_HELPER_ROLLBACK_OK" -eq 1 ]
}

fail() {
    trap '' HUP INT TERM
    HENGE_HELPER_FAILURE=$1
    HENGE_HELPER_CODE=$2
    case "$HENGE_HELPER_CODE" in ''|*[!0-9]*) HENGE_HELPER_CODE=1 ;; esac
    [ "$HENGE_HELPER_CODE" -gt 0 ] && [ "$HENGE_HELPER_CODE" -le 255 ] || HENGE_HELPER_CODE=1
    receipt failed "$HENGE_HELPER_FAILURE" "$HENGE_HELPER_CODE" || :
    if [ "$HENGE_HELPER_MUTATED" -eq 1 ]; then
        if rollback; then
            receipt rolled_back "$HENGE_HELPER_FAILURE" "$HENGE_HELPER_CODE" || :
            echo 'Repair did not complete. The previous helper files and startup state were restored.'
        else
            HENGE_HELPER_KEEP_BACKUP=1
            receipt failed rollback_failed "$HENGE_HELPER_CODE" || :
            echo 'Repair and recovery did not complete. Saved backup files have been retained.'
            echo 'Keep this Terminal window open.'
        fi
    fi
    printf 'Henge helper repair failed: %s (exit %s).\n' "$HENGE_HELPER_FAILURE" "$HENGE_HELPER_CODE"
    echo 'Return to Henge and save the unified diagnostics report; installation status is included.'
    exit "$HENGE_HELPER_CODE"
}

trap cleanup EXIT
trap 'fail connection_failed 130' HUP INT TERM
[ -n "${HENGE_INSTALL_SESSION:-}" ] || fail connection_failed 1
receipt script_started none 0 || fail connection_failed 1
mkdir -p "$HOME/Applications" || fail replace_failed "$?"
HENGE_HELPER_TMP=$(mktemp -d "$HOME/Applications/.henge-install.XXXXXX") || fail replace_failed "$?"

echo 'Downloading and checking Henge Helper.app before changing the installed copy...'
curl --fail --silent --show-error --connect-timeout 3 --max-time 30 \
    http://10.0.2.4/.henge/helper/app -o "$HENGE_HELPER_TMP/helper.tar.gz" || fail download_failed "$?"
receipt downloaded none 0 || fail connection_failed 1
gzip -t "$HENGE_HELPER_TMP/helper.tar.gz" || fail gzip_invalid "$?"
# Only the named app and its descendants belong in this archive. Reject traversal before extraction.
tar -tzf "$HENGE_HELPER_TMP/helper.tar.gz" > "$HENGE_HELPER_TMP/archive.list" || fail gzip_invalid "$?"
awk 'BEGIN { valid=1; count=0 } { count++; if ($0 !~ /^Henge Helper[.]app(\/|$)/ || $0 ~ /(^|\/)\.\.(\/|$)/) valid=0 } END { exit !(valid && count>0) }' \
    "$HENGE_HELPER_TMP/archive.list" || fail gzip_invalid 1
# An in-tree symlink or hard link could still redirect a later extraction outside the staging directory.
# The shipped app needs only regular files and directories; reject all other archive entry types.
tar -tvzf "$HENGE_HELPER_TMP/helper.tar.gz" > "$HENGE_HELPER_TMP/archive.types" || fail gzip_invalid "$?"
awk 'BEGIN { valid=1; count=0 } { count++; if (substr($0,1,1)!="-" && substr($0,1,1)!="d") valid=0 } END { exit !(valid && count>0) }' \
    "$HENGE_HELPER_TMP/archive.types" || fail gzip_invalid 1
tar -xzf "$HENGE_HELPER_TMP/helper.tar.gz" -C "$HENGE_HELPER_TMP" || fail gzip_invalid "$?"
HENGE_STAGED_APP="$HENGE_HELPER_TMP/Henge Helper.app"
HENGE_STAGED_BINARY="$HENGE_STAGED_APP/Contents/MacOS/henge-agent"
[ -d "$HENGE_STAGED_APP" ] && [ ! -L "$HENGE_STAGED_APP" ] && [ -x "$HENGE_STAGED_BINARY" ] || fail gzip_invalid 1
codesign --verify --deep --strict "$HENGE_STAGED_APP" || fail signature_invalid "$?"
HENGE_HELPER_VERSION=$("$HENGE_STAGED_BINARY" --version) || fail version_invalid "$?"
[ "$HENGE_HELPER_VERSION" = 'henge-agent 11' ] || fail version_invalid 1
# A Terminal probe cannot prove a LaunchServices app has local-network permission.
# Start the verified application below and confirm its own PID/health instead.
receipt verified none 0 || fail connection_failed 1

if [ -e "$HENGE_HELPER_APP" ]; then
    [ -d "$HENGE_HELPER_APP" ] && [ ! -L "$HENGE_HELPER_APP" ] && [ -x "$HENGE_HELPER_BINARY" ] || fail replace_failed 1
    # Complete the backup while the original app and startup state are untouched.
    # A signal during this copy can safely discard the partial backup, never the original.
    cp -Rp "$HENGE_HELPER_APP" "$HENGE_HELPER_TMP/previous.app" || fail replace_failed "$?"
    HENGE_HELPER_HAD_APP=1
    if app_pid; then HENGE_HELPER_APP_WAS_RUNNING=1; fi
fi
if [ -f "$HENGE_HELPER_PLIST" ]; then
    cp -p "$HENGE_HELPER_PLIST" "$HENGE_HELPER_TMP/previous.plist" || fail replace_failed "$?"
    HENGE_HELPER_HAD_PLIST=1
fi
if launchctl print "$HENGE_HELPER_JOB" >/dev/null 2>&1; then
    HENGE_HELPER_WAS_LOADED=1
    HENGE_HELPER_MUTATED=1
    launchctl bootout "$HENGE_HELPER_JOB" || fail bootout_failed "$?"
fi
HENGE_HELPER_MUTATED=1
if [ "$HENGE_HELPER_HAD_APP" -eq 1 ]; then
    "$HENGE_HELPER_BINARY" --quit-app || fail bootout_failed "$?"
fi
receipt replacing none 0 || fail connection_failed 1
# Mark the transaction before the first destructive operation, so a signal between any two
# commands restores the already complete backup. The only prior copy is never moved into staging.
HENGE_HELPER_APP_CHANGED=1
rm -rf "$HENGE_HELPER_APP" || fail replace_failed "$?"
mv "$HENGE_STAGED_APP" "$HENGE_HELPER_APP" || fail replace_failed "$?"
# Keep the old bare binary for recovery, but remove its job to prevent two helpers at next login.
rm -f "$HENGE_HELPER_PLIST" || fail replace_failed "$?"
receipt launch_requested none 0 || fail connection_failed 1
open -a "$HENGE_HELPER_APP" --args --install || fail bootstrap_failed "$?"

echo 'Henge Helper is opening. Allow its Local Network request in the Mac if asked.'
echo 'Waiting at least 60 seconds for its own connection; the Mac app shows any permission or login-item action.'
HENGE_HELPER_CONNECTED=0
HENGE_HELPER_ATTEMPTS=0
# Each failed attempt sleeps one second. No wall-clock jump or fast failed check shortens this window.
# All helper CLI and HTTP operations are separately bounded. Sixty retries also bound a stalled clock.
while [ "$HENGE_HELPER_ATTEMPTS" -lt 60 ]; do
    HENGE_HELPER_ATTEMPTS=$(( HENGE_HELPER_ATTEMPTS + 1 ))
    if app_pid && "$HENGE_HELPER_BINARY" --health-check "$HENGE_HELPER_PID"; then
        if receipt confirmed none 0 "$HENGE_HELPER_PID"; then HENGE_HELPER_CONNECTED=1; break; fi
    fi
    sleep 1
done
if [ "$HENGE_HELPER_CONNECTED" -eq 0 ]; then
    if app_pid; then
        # A running app may be waiting for an interactive permission prompt. Keep it available.
        HENGE_HELPER_MUTATED=0
        if ! receipt awaiting_connection none 0 "$HENGE_HELPER_PID"; then
            echo 'The installation status could not reach Henge. The running Mac app is being kept for reconnection.'
        fi
        echo 'Henge Helper.app is installed and running, but its connection is NOT confirmed yet.'
        echo 'Leave the Mac app open and allow its Local Network request. Do not repeat installation.'
        HENGE_LOGIN_STATUS=$("$HENGE_HELPER_BINARY" --login-status 2>/dev/null) || HENGE_LOGIN_STATUS=unavailable
        case "$HENGE_LOGIN_STATUS" in
            requires_approval) echo 'Login startup needs approval in Mac System Settings > General > Login Items.' ;;
            not_registered) echo 'Automatic login startup is not registered; check the Henge Helper window.' ;;
            enabled) echo 'Automatic login startup is enabled.' ;;
            *) echo 'Automatic login startup status is unavailable; check the Henge Helper window.' ;;
        esac
        echo 'Henge will update the connection status automatically after the app connects.'
        echo 'Current fixed startup status:'
        "$HENGE_HELPER_BINARY" --startup-status || echo 'Startup status is currently unavailable.'
        exit 0
    fi
    fail health_unconfirmed 1
fi
HENGE_HELPER_MUTATED=0
echo 'Henge Helper.app is running and its connection is confirmed.'
echo 'Return to Henge and use Collect Chat diagnostics. Clipboard readiness is shown separately.'
echo 'This confirms the helper connection; it does not change DeviceCheck support or native Chat authentication.'
