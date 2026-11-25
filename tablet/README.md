# Tablet half: rooted Galaxy Tab A Lite

The tablet only runs `frida-server`. Everything else lives on the NixOS laptop.

Our Python bindings are frida **17.27.5**, so the server must be exactly that version.

## One-time setup (on the laptop)

```bash
nix-shell -p android-tools curl xz
export TABLET_SERIAL=<adb serial>       # optional if only one device is attached
./tablet/fetch-frida-server.sh          # -> /sdcard/Download/frida-server on the tablet
./tablet/build-module.sh                # -> tablet/owlx-frida.zip
```

Install `owlx-frida.zip` in Magisk (Modules → Install from storage), then reboot.
`customize.sh` copies the pushed binary into the module; `service.sh` starts it at
late_start with:

```
frida-server -l 0.0.0.0:27042
```

Logs go to `/data/local/tmp/owlx-frida.log`. If the pushed binary is missing, the
module falls back to `/data/local/tmp/frida-server`.

## Verify from the laptop

```bash
nix-shell -p frida-tools
frida-ps -H 10.10.10.119:27042 | head
```

If the tablet's IP changes, either set a static DHCP lease or pass `TABLET_IP=<ip>`
to the engine launcher. To keep frida-server on localhost only and use adb forwarding
instead, change `-l 0.0.0.0:27042` to `-l 127.0.0.1:27042` in `magisk/service.sh`,
reinstall the module, then `adb forward tcp:27042 tcp:27042` and use
`--device remote:127.0.0.1:27042` on the laptop.

## Notes

- Root on the tablet means no gadget repackaging for apps *on this device*.
- A separate non-rooted target still needs a gadget-injected, re-signed APK.
- frida-server must be started from the Android side: proot cannot ptrace host
  processes, but a host-side root server can.
