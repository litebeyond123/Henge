#!/bin/sh
# Served with a validated HENGE_INSTALL_SESSION prefix by the current Henge VM session.
# Installation receipts contain only fixed categories and numeric exit codes.
umask 077
HENGE_HELPER_DIR="$HOME/Library/Application Support/Henge"
HENGE_HELPER_PLIST="$HOME/Library/LaunchAgents/com.henge.agent.plist"
HENGE_HELPER_JOB="gui/$(id -u)/com.henge.agent"
HENGE_HELPER_DOMAIN="gui/$(id -u)"
HENGE_HELPER_TMP=
HENGE_HELPER_MUTATED=0
HENGE_HELPER_WAS_LOADED=0
HENGE_HELPER_HAD_BINARY=0
HENGE_HELPER_HAD_PLIST=0
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

# Restore exactly the prior files and, if it was loaded, the prior LaunchAgent.
rollback() {
    HENGE_HELPER_ROLLBACK_OK=1
    if launchctl print "$HENGE_HELPER_JOB" >/dev/null 2>&1; then
        launchctl bootout "$HENGE_HELPER_JOB" >/dev/null 2>&1 || HENGE_HELPER_ROLLBACK_OK=0
    fi
    if [ "$HENGE_HELPER_HAD_BINARY" -eq 1 ]; then
        mv -f "$HENGE_HELPER_TMP/previous-agent" "$HENGE_HELPER_DIR/henge-agent" || HENGE_HELPER_ROLLBACK_OK=0
    else
        rm -f "$HENGE_HELPER_DIR/henge-agent" || HENGE_HELPER_ROLLBACK_OK=0
    fi
    if [ "$HENGE_HELPER_HAD_PLIST" -eq 1 ]; then
        mv -f "$HENGE_HELPER_TMP/previous.plist" "$HENGE_HELPER_PLIST" || HENGE_HELPER_ROLLBACK_OK=0
    else
        rm -f "$HENGE_HELPER_PLIST" || HENGE_HELPER_ROLLBACK_OK=0
    fi
    if [ "$HENGE_HELPER_WAS_LOADED" -eq 1 ] && [ "$HENGE_HELPER_ROLLBACK_OK" -eq 1 ]; then
        launchctl bootstrap "$HENGE_HELPER_DOMAIN" "$HENGE_HELPER_PLIST" || HENGE_HELPER_ROLLBACK_OK=0
    fi
    [ "$HENGE_HELPER_ROLLBACK_OK" -eq 1 ]
}

fail() {
    # Rollback consumes its saved files once; repeated terminal signals must not re-enter it.
    trap '' HUP INT TERM
    HENGE_HELPER_FAILURE=$1
    HENGE_HELPER_CODE=$2
    case "$HENGE_HELPER_CODE" in ''|*[!0-9]*) HENGE_HELPER_CODE=1 ;; esac
    [ "$HENGE_HELPER_CODE" -gt 0 ] && [ "$HENGE_HELPER_CODE" -le 255 ] || HENGE_HELPER_CODE=1
    receipt failed "$HENGE_HELPER_FAILURE" "$HENGE_HELPER_CODE" || :
    if [ "$HENGE_HELPER_MUTATED" -eq 1 ]; then
        if rollback; then
            receipt rolled_back "$HENGE_HELPER_FAILURE" "$HENGE_HELPER_CODE" || :
            echo 'Repair did not complete. The previous helper files were restored.'
        else
            HENGE_HELPER_KEEP_BACKUP=1
            receipt failed rollback_failed "$HENGE_HELPER_CODE" || :
            echo 'Repair and recovery did not complete. Saved backup files have been retained.'
            echo 'Keep this Terminal window open.'
        fi
    fi
    printf 'Henge helper repair failed: %s (exit %s).\n' "$HENGE_HELPER_FAILURE" "$HENGE_HELPER_CODE"
    echo 'Return to Henge and save the unified diagnostics report; the fixed installation status is included.'
    exit "$HENGE_HELPER_CODE"
}

trap cleanup EXIT
trap 'fail connection_failed 130' HUP INT TERM
[ -n "${HENGE_INSTALL_SESSION:-}" ] || fail connection_failed 1
receipt script_started none 0 || fail connection_failed 1
mkdir -p "$HENGE_HELPER_DIR" "$HOME/Library/LaunchAgents" || fail replace_failed "$?"
HENGE_HELPER_TMP=$(mktemp -d "$HENGE_HELPER_DIR/.install.XXXXXX") || fail replace_failed "$?"

echo 'Downloading and checking the helper before changing the installed copy...'
curl --fail --silent --show-error --connect-timeout 3 --max-time 20 \
    http://10.0.2.4/.henge/agent -o "$HENGE_HELPER_TMP/agent.gz" || fail download_failed "$?"
receipt downloaded none 0 || fail connection_failed 1
gzip -t "$HENGE_HELPER_TMP/agent.gz" || fail gzip_invalid "$?"
gzip -dc "$HENGE_HELPER_TMP/agent.gz" > "$HENGE_HELPER_TMP/henge-agent" || fail gzip_invalid "$?"
chmod 755 "$HENGE_HELPER_TMP/henge-agent" || fail replace_failed "$?"
codesign --verify --strict "$HENGE_HELPER_TMP/henge-agent" || fail signature_invalid "$?"
HENGE_HELPER_VERSION=$("$HENGE_HELPER_TMP/henge-agent" --version) || fail version_invalid "$?"
[ "$HENGE_HELPER_VERSION" = 'henge-agent 4' ] || fail version_invalid 1
# This foreground probe is distinct from launchd liveness; it cannot mark the daemon online.
"$HENGE_HELPER_TMP/henge-agent" --connection-check || fail connection_failed "$?"
receipt verified none 0 || fail connection_failed 1

# Escape the path for XML; spaces and '&' in a home directory must not break the LaunchAgent.
HENGE_HELPER_XML_PATH=$(printf '%s' "$HENGE_HELPER_DIR/henge-agent" | sed -e 's/\&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&apos;/g")
cat > "$HENGE_HELPER_TMP/new.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.henge.agent</string>
<key>ProgramArguments</key><array><string>$HENGE_HELPER_XML_PATH</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>ProcessType</key><string>Background</string>
</dict></plist>
EOF
[ "$?" -eq 0 ] || fail plist_invalid 1
plutil -lint "$HENGE_HELPER_TMP/new.plist" >/dev/null || fail plist_invalid "$?"
if [ -f "$HENGE_HELPER_DIR/henge-agent" ]; then
    cp -p "$HENGE_HELPER_DIR/henge-agent" "$HENGE_HELPER_TMP/previous-agent" || fail replace_failed "$?"
    HENGE_HELPER_HAD_BINARY=1
fi
if [ -f "$HENGE_HELPER_PLIST" ]; then
    cp -p "$HENGE_HELPER_PLIST" "$HENGE_HELPER_TMP/previous.plist" || fail replace_failed "$?"
    HENGE_HELPER_HAD_PLIST=1
fi
if launchctl print "$HENGE_HELPER_JOB" >/dev/null 2>&1; then
    HENGE_HELPER_WAS_LOADED=1
    HENGE_HELPER_MUTATED=1
    launchctl bootout "$HENGE_HELPER_JOB"
    HENGE_HELPER_BOOTOUT_RC=$?
    if [ "$HENGE_HELPER_BOOTOUT_RC" -ne 0 ]; then
        HENGE_HELPER_MUTATED=0
        fail bootout_failed "$HENGE_HELPER_BOOTOUT_RC"
    fi
fi
# From this point an interrupted/failed repair restores the saved files and prior job.
HENGE_HELPER_MUTATED=1
receipt replacing none 0 || fail connection_failed 1
mv -f "$HENGE_HELPER_TMP/henge-agent" "$HENGE_HELPER_DIR/henge-agent" || fail replace_failed "$?"
mv -f "$HENGE_HELPER_TMP/new.plist" "$HENGE_HELPER_PLIST" || fail replace_failed "$?"
# The host clears old daemon liveness here. A foreground --version/probe cannot satisfy confirmation.
receipt launch_requested none 0 || fail connection_failed 1
launchctl bootstrap "$HENGE_HELPER_DOMAIN" "$HENGE_HELPER_PLIST" || fail bootstrap_failed "$?"

echo 'Waiting briefly for the new helper to connect to Henge (20-second retry window)...'
HENGE_HELPER_DEADLINE=$(( $(date +%s) + 20 ))
HENGE_HELPER_CONNECTED=0
HENGE_HELPER_ATTEMPTS=0
while [ "$HENGE_HELPER_ATTEMPTS" -lt 10 ] && [ "$(date +%s)" -lt "$HENGE_HELPER_DEADLINE" ]; do
    HENGE_HELPER_ATTEMPTS=$(( HENGE_HELPER_ATTEMPTS + 1 ))
    HENGE_HELPER_PID=$(launchctl print "$HENGE_HELPER_JOB" 2>/dev/null | awk '/^[[:space:]]*pid = [0-9]+/ { print $3; exit }')
    case "$HENGE_HELPER_PID" in
        ''|*[!0-9]*) ;;
        *) if "$HENGE_HELPER_DIR/henge-agent" --health-check "$HENGE_HELPER_PID"; then
               if receipt confirmed none 0 "$HENGE_HELPER_PID"; then HENGE_HELPER_CONNECTED=1; HENGE_HELPER_MUTATED=0; break; fi
           fi ;;
    esac
    sleep 1
done
[ "$HENGE_HELPER_CONNECTED" -eq 1 ] || fail health_unconfirmed 1
HENGE_HELPER_MUTATED=0
echo 'The installed helper is running and has connected to Henge.'
echo 'Return to Henge and use Collect Chat diagnostics. Clipboard readiness is shown separately.'
echo 'This confirms the helper connection; it does not change DeviceCheck support or fix native Chat authentication.'
