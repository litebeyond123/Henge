#!/bin/sh
set -eu
umask 022
[ "$#" -eq 3 ] || { echo 'Usage: build-helper-app.sh binary Info.plist output.tar.gz' >&2; exit 2; }
HENGE_APP_BINARY=$1
HENGE_APP_INFO=$2
HENGE_APP_OUTPUT=$3
HENGE_APP_STAGE=$(mktemp -d "$(dirname "$HENGE_APP_OUTPUT")/.helper-app.XXXXXX")
trap 'rm -rf "$HENGE_APP_STAGE"' EXIT HUP INT TERM
HENGE_APP_BUNDLE="$HENGE_APP_STAGE/Henge Helper.app"
mkdir -p "$HENGE_APP_BUNDLE/Contents/MacOS"
cp "$HENGE_APP_INFO" "$HENGE_APP_BUNDLE/Contents/Info.plist"
cp "$HENGE_APP_BINARY" "$HENGE_APP_BUNDLE/Contents/MacOS/henge-agent"
chmod 755 "$HENGE_APP_BUNDLE/Contents/MacOS/henge-agent"
plutil -lint "$HENGE_APP_BUNDLE/Contents/Info.plist"
codesign --force --sign - --identifier com.henge.guesthelper "$HENGE_APP_BUNDLE"
codesign --verify --deep --strict "$HENGE_APP_BUNDLE"
test "$("$HENGE_APP_BUNDLE/Contents/MacOS/henge-agent" --version)" = 'henge-agent 6'
COPYFILE_DISABLE=1 tar --format=ustar -czf "$HENGE_APP_OUTPUT.tmp" -C "$HENGE_APP_STAGE" 'Henge Helper.app'
mv -f "$HENGE_APP_OUTPUT.tmp" "$HENGE_APP_OUTPUT"
