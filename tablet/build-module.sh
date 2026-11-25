#!/usr/bin/env bash
# Run on the NixOS laptop (or here in proot). Packs the Magisk module for the
# Magisk app. Uses Python's zipfile so no extra package is needed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/owlx-frida.zip}"

python3 - "$HERE/magisk" "$OUT" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(src):
        for name in sorted(files):
            path = os.path.join(root, name)
            z.write(path, os.path.relpath(path, src))
print("built", out)
PY
echo "install it in Magisk (Modules > Install from storage), then reboot."
