#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import sys
import urllib.request

try:
    import websockets
except Exception:
    websockets = None


def req(url, token, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Authorization", f"Bearer {token}")
    r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, timeout=10) as resp:
        return json.loads(resp.read().decode())


async def events(url, token):
    if websockets is None:
        print("install websockets for event streaming: pip install websockets", file=sys.stderr)
        raise SystemExit(2)
    ws_url = url.replace("http://", "ws://").replace("https://", "wss://").rstrip("/") + "/ws"
    async with websockets.connect(ws_url, additional_headers={"Authorization": f"Bearer {token}"}) as ws:
        async for msg in ws:
            print(msg, flush=True)


def main():
    ap = argparse.ArgumentParser(prog="owlx")
    ap.add_argument("--url", default=os.environ.get("OWLX_URL", "http://127.0.0.1:8787"))
    ap.add_argument("--token", default=os.environ.get("OWLX_TOKEN"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    hooks = sub.add_parser("hooks")
    hsub = hooks.add_subparsers(dest="hooks_cmd", required=True)
    hsub.add_parser("list")
    att = hsub.add_parser("attach")
    att.add_argument("pid", type=int)
    att.add_argument("--name")
    det = hsub.add_parser("detach")
    det.add_argument("pid", type=int)
    sub.add_parser("events")
    args = ap.parse_args()
    if not args.token:
        raise SystemExit("OWLX_TOKEN or --token required")
    base = args.url.rstrip("/")
    if args.cmd == "hooks" and args.hooks_cmd == "list":
        print(json.dumps(req(base + "/api/hooks", args.token), indent=2))
    elif args.cmd == "hooks" and args.hooks_cmd == "attach":
        print(json.dumps(req(base + "/api/hooks", args.token, "POST", {"pid": args.pid, "name": args.name}), indent=2))
    elif args.cmd == "hooks" and args.hooks_cmd == "detach":
        print(json.dumps(req(base + f"/api/hooks/{args.pid}", args.token, "DELETE"), indent=2))
    elif args.cmd == "events":
        asyncio.run(events(base, args.token))


if __name__ == "__main__":
    main()
