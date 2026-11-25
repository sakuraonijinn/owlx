#!/usr/bin/env bash
# Run on the NixOS laptop. Downloads the frida-server build matching our Python
# bindings and pushes it to the tablet's shared storage for the Magisk module.
set -euo pipefail

VERSION="${FRIDA_VERSION:-17.27.5}"
ARCH="${FRIDA_ARCH:-arm64}"          # Galaxy Tab A Lite is arm64
TABLET_SERIAL="${TABLET_SERIAL:-}"   # set if more than one device is attached
DEST="${FRIDA_DEST:-/sdcard/Download/frida-server}"

command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
command -v adb >/dev/null || { echo "adb is required (nix-shell -p android-tools)" >&2; exit 2; }

adb_args=()
[ -n "$TABLET_SERIAL" ] && adb_args+=("-s" "$TABLET_SERIAL")
adb "${adb_args[@]}" get-state >/dev/null || { echo "no tablet on adb" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
asset="frida-server-${VERSION}-android-${ARCH}.xz"
url="https://github.com/frida/frida/releases/download/${VERSION}/${asset}"

echo "downloading $url"
curl -fL --retry 3 -o "$work/$asset" "$url"
xz -dc "$work/$asset" > "$work/frida-server"
chmod 0755 "$work/frida-server"

echo "pushing to $DEST"
adb "${adb_args[@]}" push "$work/frida-server" "$DEST"
adb "${adb_args[@]}" shell chmod 0755 "$DEST"
echo "done: $DEST ($(stat -c%s "$work/frida-server") bytes)"
