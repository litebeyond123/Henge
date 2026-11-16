#!/bin/sh
set -eu
umask 022
[ "$#" -eq 5 ] || { echo 'Usage: build-helper-app.sh binary Info.plist output.tar.gz auth-launcher auth-adapter.dylib' >&2; exit 2; }
HENGE_APP_BINARY=$1
HENGE_APP_INFO=$2
HENGE_APP_OUTPUT=$3
HENGE_AUTH_LAUNCHER=$4
HENGE_AUTH_ADAPTER=$5
HENGE_APP_STAGE=$(mktemp -d "$(dirname "$HENGE_APP_OUTPUT")/.helper-app.XXXXXX")
trap 'rm -rf "$HENGE_APP_STAGE"' EXIT HUP INT TERM
HENGE_APP_BUNDLE="$HENGE_APP_STAGE/Henge Helper.app"
mkdir -p "$HENGE_APP_BUNDLE/Contents/MacOS" "$HENGE_APP_BUNDLE/Contents/Resources"
cp "$HENGE_APP_INFO" "$HENGE_APP_BUNDLE/Contents/Info.plist"
cp "$HENGE_APP_BINARY" "$HENGE_APP_BUNDLE/Contents/MacOS/henge-agent"
chmod 755 "$HENGE_APP_BUNDLE/Contents/MacOS/henge-agent"
cp "$HENGE_AUTH_LAUNCHER" "$HENGE_APP_BUNDLE/Contents/Resources/henge-auth-launcher"
cp "$HENGE_AUTH_ADAPTER" "$HENGE_APP_BUNDLE/Contents/Resources/henge-auth-adapter.dylib"
chmod 755 "$HENGE_APP_BUNDLE/Contents/Resources/henge-auth-launcher"
codesign --force --sign - --identifier com.henge.auth-launcher "$HENGE_APP_BUNDLE/Contents/Resources/henge-auth-launcher"
codesign --force --sign - --identifier com.henge.auth-adapter "$HENGE_APP_BUNDLE/Contents/Resources/henge-auth-adapter.dylib"
codesign --verify --strict "$HENGE_APP_BUNDLE/Contents/Resources/henge-auth-launcher"
codesign --verify --strict "$HENGE_APP_BUNDLE/Contents/Resources/henge-auth-adapter.dylib"
plutil -lint "$HENGE_APP_BUNDLE/Contents/Info.plist"
codesign --force --sign - --identifier com.henge.guesthelper "$HENGE_APP_BUNDLE"
codesign --verify --deep --strict "$HENGE_APP_BUNDLE"
HENGE_EXPECTED_HELPER_VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$HENGE_APP_BUNDLE/Contents/Info.plist")
test "$("$HENGE_APP_BUNDLE/Contents/MacOS/henge-agent" --version)" = "henge-agent $HENGE_EXPECTED_HELPER_VERSION"
COPYFILE_DISABLE=1 tar --format=ustar -czf "$HENGE_APP_OUTPUT.tmp" -C "$HENGE_APP_STAGE" 'Henge Helper.app'
mv -f "$HENGE_APP_OUTPUT.tmp" "$HENGE_APP_OUTPUT"
