# owlx

Phone-side control service, OWL dashboard, and NixOS CLI for Frida/mitmproxy automation.

## Layout

- `phone/owlx_service.py` - authenticated aiohttp JSON/WebSocket service on the phone
- `dashboard/owlx.owl` - OWL control dashboard
- `nixos/owlx.py` - NixOS CLI for attach/detach/list and event streaming

## First milestone: hooked-PID round-trip

The phone service keeps an in-memory hooked PID set. The NixOS CLI can attach, list, and detach PIDs over HTTP.

### Phone service

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install aiohttp
export OWLX_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
python3 phone/owlx_service.py --host 0.0.0.0 --port 8787
```

### NixOS CLI

```bash
python3 nixos/owlx.py --url http://PHONE:8787 --token "$OWLX_TOKEN" hooks list
python3 nixos/owlx.py --url http://PHONE:8787 --token "$OWLX_TOKEN" hooks attach 1234 --name demo
python3 nixos/owlx.py --url http://PHONE:8787 --token "$OWLX_TOKEN" hooks detach 1234
python3 nixos/owlx.py --url http://PHONE:8787 --token "$OWLX_TOKEN" events
```

## Auth

All API and WebSocket requests require `Authorization: Bearer <OWLX_TOKEN>`.
