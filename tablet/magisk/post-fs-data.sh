#!/system/bin/sh
MODDIR=${0%/*}
chmod 0755 "$MODDIR/service.sh" "$MODDIR/bin/frida-server" 2>/dev/null || true
exit 0
