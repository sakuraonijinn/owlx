#!/system/bin/sh
# Magisk installs the module zip, then runs this once. The binary is too large
# to keep in git, so fetch-frida-server.sh pushes it to /sdcard/Download first.
MODDIR=${0%/*}
mkdir -p "$MODDIR/bin"

SRC=/sdcard/Download/frida-server
if [ -f "$SRC" ]; then
  cp "$SRC" "$MODDIR/bin/frida-server"
  chmod 0755 "$MODDIR/bin/frida-server"
  ui_print "- owlx: installed frida-server from $SRC"
else
  ui_print "! owlx: $SRC missing; service.sh will fall back to /data/local/tmp/frida-server"
fi
exit 0
