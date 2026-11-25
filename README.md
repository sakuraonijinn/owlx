# owlx

Phone-side control service, OWL dashboard, and NixOS CLI for driving Frida and mitmproxy on your own test devices.

## What is real now

- **`phone/owlx_service.py`** — authenticated aiohttp JSON + WebSocket service. It attaches real Frida
  scripts to PIDs through `frida-server` (or the local/USB device), enumerates processes, loads and
  unloads scripts from `hooks/`, streams Frida `send()` messages over `/ws`, starts/stops mitmproxy as a
  child process, tails its log, and can set or clear a target's `http_proxy`.
- **`nixos/owlx.py`** — dependency-light CLI for status, processes, script upload, hook attach/detach,
  mitmproxy control, proxy control, and live event streaming.
- **`dashboard/owlx.owl`** — OWL app for the phone showing attached hooks, processes, mitm state and
  events, with tap-to-attach/detach.
- **`hooks/default.js`** — a small example that reports `java.net.URL` construction.
- **`tests/test_service.py`** — offline tests with a fake Frida device; no root or device needed.

The first milestone is no longer an in-memory stand-in: `hooks list` reflects real Frida sessions.

## Setup

### Phone side (this proot / Linux-on-Android)

```bash
pacman -S --needed python python-aiohttp python-websockets mitmproxy
pip install --break-system-packages frida
export OWLX_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
python3 phone/owlx_service.py --host 0.0.0.0 --port 8787 \
  --device remote:127.0.0.1:27042
```

`--device` accepts `local`, `usb`, `remote:host:port`, or `host:port`. For a rooted phone, run
`frida-server` on the Android side and point at it; proot itself cannot ptrace host processes.
Set `OWLX_HOOKS_DIR` to keep hook scripts somewhere else. All API and WebSocket requests except
`/healthz` require `Authorization: Bearer $OWLX_TOKEN`.

### NixOS laptop

```bash
nix-shell -p python3 python3Packages.websockets android-tools
export OWLX_URL=http://PHONE:8787
export OWLX_TOKEN=<same token>
python3 nixos/owlx.py status
python3 nixos/owlx.py processes --filter example
python3 nixos/owlx.py scripts put myhook.js hooks/default.js
python3 nixos/owlx.py hooks attach 1234 --script myhook.js
python3 nixos/owlx.py events --follow
python3 nixos/owlx.py mitm start --port 8080
python3 nixos/owlx.py proxy set --host PHONE --port 8080 --device <adb-serial>
```

`proxy set` runs `settings put global http_proxy` through `adb` when `--device` is given, or locally
when `adb` is absent. It does not create a VPN tunnel; for always-on routing on non-rooted devices you
still need a VpnService app or the OEM's proxy setting. Install mitmproxy's CA on the target and use a
Frida pinning-bypass hook for HTTPS apps that pin certificates.

### Dashboard

Copy `dashboard/owlx.owl` into `~/.config/omalauncher/widgets/`, open it from the app drawer, type the
phone service URL and token, then tap a PID's **hook** to attach. The token is a plain `persist` state
because OWL secrets require an `https://` server; keep the service on a trusted LAN.

## Roles recap

- **NixOS laptop** — build/version hooks, drive the API, inspect events and flows.
- **Phone with the service** — hosts Frida attachment and mitmproxy, streams events.
- **Rooted tablet** — optional local frida-server for developing hooks before targeting another device.
- **Non-rooted target** — needs a gadget-repackaged, re-signed app; this service cannot inject into it
  unless a gadget is listening and reachable.

## Development

```bash
python3 -m py_compile phone/owlx_service.py nixos/owlx.py
python3 -m unittest discover -s tests -v
```

## Security

Never paste tokens into the OWL chat mailbox, commit them, or leave them in shell history. The service
binds to `127.0.0.1` unless you pass `--host 0.0.0.0`; do the latter only on a network you control.
