#!/system/bin/sh
# Runs at late_start, after Android is up. Listens on all interfaces so the
# NixOS laptop can attach over the LAN with remote:TABLET_IP:27042.
MODDIR=${0%/*}

BIN="$MODDIR/bin/frida-server"
[ -x "$BIN" ] || BIN=/data/local/tmp/frida-server
if [ ! -x "$BIN" ]; then
  echo "owlx: no frida-server binary found" >/data/local/tmp/owlx-frida.log
  exit 0
fi

# Wait for boot to finish before touching the process table.
i=0
while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
  i=$((i + 1))
  [ "$i" -ge 60 ] && break
  sleep 5
done

# Magisk may run service.sh more than once; don't start a second server.
if pidof frida-server >/dev/null 2>&1; then
  echo "owlx: frida-server already running" >>/data/local/tmp/owlx-frida.log
  exit 0
fi

nohup "$BIN" -l 0.0.0.0:27042 >/data/local/tmp/owlx-frida.log 2>&1 &
echo "owlx: started $BIN -l 0.0.0.0:27042" >>/data/local/tmp/owlx-frida.log
exit 0
