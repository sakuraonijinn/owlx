# owlx

Laptop-hosted control service, OWL dashboard, and NixOS CLI for driving Frida and mitmproxy on your own test devices.

```
tablet (rooted Galaxy Tab A Lite)          NixOS laptop                     OWL dashboard
  Magisk -> frida-server                     owlx_service.py  <-- HTTP/WS --  dashboard/owlx.owl
  0.0.0.0:27042  <--- Frida RPC ---          mitmproxy                       (phone/launcher)
                                             nixos/owlx.py
```

The tablet only provides a root Frida server. The engine, its logs and the flows live on the laptop.

## What is real now

- **`phone/owlx_service.py`** — authenticated aiohttp JSON + WebSocket service. It attaches real Frida
  scripts to PIDs through `frida-server` over the LAN, enumerates processes, loads and unloads scripts
  from `hooks/`, streams Frida `send()` messages over `/ws`, starts/stops mitmproxy as a child process,
  tails its log, and can set or clear a target's `http_proxy`.
- **`nixos/owlx.py`** — dependency-light CLI for status, processes, script upload, hook attach/detach,
  mitmproxy control, proxy control, and live event streaming.
- **`nixos/start-engine.sh`** — foreground/background launcher for the engine, plus a sample
  `owlx-engine.service` systemd user unit.
- **`tablet/magisk/`** — Magisk module that starts the matching `frida-server` at boot.
  See `tablet/README.md` for version-matched install steps.
- **`dashboard/owlx.owl`** — OWL app showing attached hooks, processes, mitm state and events,
  with tap-to-attach/detach.
- **`hooks/default.js`** — a small example that reports `java.net.URL` construction.
- **`tests/test_service.py`** — offline tests with a fake Frida device; no root or device needed.

The first milestone is no longer an in-memory stand-in: `hooks list` reflects real Frida sessions.

## Setup

### 1. Tablet (rooted Tab A Lite)

On the laptop, push the version-matched server and build the module:

```bash
nix-shell -p android-tools curl xz
./tablet/fetch-frida-server.sh     # frida-server 17.27.5 -> /sdcard/Download
./tablet/build-module.sh           # -> tablet/owlx-frida.zip
```

Install the zip in Magisk, reboot, then check `frida-ps -H TABLET_IP:27042`.
Full details, including the localhost + `adb forward` variant, are in `tablet/README.md`.
proot cannot ptrace host processes, so frida-server must run from the Android side;
the Python side only speaks Frida's RPC over TCP.

### 2. Laptop engine

```bash
nix-shell -p python3 python3Packages.aiohttp python3Packages.websockets mitmproxy frida-tools
umask 077
mkdir -p ~/.config/owlx
python3 -c 'import secrets; print(secrets.token_hex(32))' > ~/.config/owlx/token

export TABLET_IP=10.10.10.119       # or set in ~/.config/owlx/engine.env
./nixos/start-engine.sh start       # starts the service and mitmproxy
./nixos/start-engine.sh status
```

`start-engine.sh` binds the API to `0.0.0.0:8787`, connects to
`remote:$TABLET_IP:27042`, writes logs under `~/.local/state/owlx`, and starts
mitmproxy on `8080`. `OWLX_MITM=0` leaves mitmproxy off. For boot persistence on
NixOS, copy `nixos/owlx-engine.service` into `~/.config/systemd/user/`, set
`OWLX_ROOT` to the checkout, then `systemctl --user enable --now owlx-engine`.
The token stays in `~/.config/owlx/token`, never in the unit file.

CLI examples:

```bash
export OWLX_URL=http://127.0.0.1:8787
python3 nixos/owlx.py status
python3 nixos/owlx.py processes --filter example
python3 nixos/owlx.py scripts put myhook.js hooks/default.js
python3 nixos/owlx.py hooks attach 1234 --script myhook.js
python3 nixos/owlx.py events --follow
python3 nixos/owlx.py mitm log -n 20
python3 nixos/owlx.py proxy set --host <laptop-ip> --port 8080 --device <adb-serial>
```

`proxy set` runs `settings put global http_proxy` through `adb` when `--device` is
given, or locally when `adb` is absent. It does not create a VPN tunnel; for
always-on routing on non-rooted devices you still need a VpnService app. Install
mitmproxy's CA on the target and use a Frida pinning-bypass hook for HTTPS apps
that pin certificates.

### 3. Dashboard

Copy `dashboard/owlx.owl` into `~/.config/omalauncher/widgets/` and edit its one
`let api = "http://LAPTOP_IP:8787"` line to the laptop's real IP — OWL needs the
scheme and host as fixed text, so it cannot be typed into a field at runtime. Open
the app from the drawer, type the token from `~/.config/owlx/token`, then tap a PID's
**hook** to attach. The token is a plain `persist` state because OWL secrets require
an `https://` server; keep the service on a trusted LAN.

## Roles recap

- **NixOS laptop** — hosts the control service and mitmproxy; build/version hooks, drive the API,
  inspect events and flows.
- **Rooted Tab A Lite** — runs only `frida-server` at boot; Magisk also installs mitmproxy's CA.
- **OWL dashboard** — thin touch UI on the phone/launcher, pointed at the laptop.
- **Non-rooted target** — needs a gadget-repackaged, re-signed app; this service cannot inject into it
  unless a gadget is listening and reachable.

## Development

```bash
python3 -m py_compile phone/owlx_service.py nixos/owlx.py
python3 -m unittest discover -s tests -v
```

## Security

Never paste tokens into the OWL chat mailbox, commit them, or leave them in shell history. Keep the
token file mode 600. The service binds to `0.0.0.0` only for LAN access from the dashboard; use a
firewall and a trusted network.
