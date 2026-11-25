#!/usr/bin/env python3
"""owlx CLI for the NixOS lab box: talk to the phone-side control service."""
import argparse
import asyncio
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import websockets
except Exception:
    websockets = None


def req(base, token, path, method="GET", body=None, params=None):
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", "Bearer " + token)
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise SystemExit(f"{method} {path}: HTTP {exc.code} {detail}")


def show(value):
    print(json.dumps(value, indent=2))


def load_token(args):
    """Prefer an explicit token, then the environment, then the token file."""
    token = args.token or os.environ.get("OWLX_TOKEN")
    if not token and args.token_file:
        try:
            token = Path(os.path.expanduser(args.token_file)).read_text(encoding="utf-8").strip()
        except OSError:
            token = ""
    if not token:
        raise SystemExit("OWLX_TOKEN, --token or --token-file with a token is required")
    return token


async def follow(base, token):
    if websockets is None:
        raise SystemExit("event streaming needs websockets: pip install websockets")
    url = base.replace("http://", "ws://").replace("https://", "wss://").rstrip("/") + "/ws"
    async with websockets.connect(url, additional_headers={"Authorization": "Bearer " + token}) as ws:
        async for message in ws:
            print(message, flush=True)


def build_parser():
    ap = argparse.ArgumentParser(prog="owlx")
    ap.add_argument("--url", default=os.environ.get("OWLX_URL", "http://127.0.0.1:8787"))
    ap.add_argument("--token", default=os.environ.get("OWLX_TOKEN"),
                    help="token itself; prefer OWLX_TOKEN or --token-file")
    ap.add_argument("--token-file", default=os.environ.get("OWLX_TOKEN_FILE", "~/.config/owlx/token"),
                    help="read the token from this file (default: ~/.config/owlx/token)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="frida, hooks, mitm and proxy status")

    procs = sub.add_parser("processes", help="list processes on the frida device")
    procs.add_argument("--filter", default="")

    scripts = sub.add_parser("scripts", help="manage hook scripts on the phone")
    ssub = scripts.add_subparsers(dest="sub", required=True)
    ssub.add_parser("list")
    put = ssub.add_parser("put", help="upload a local .js file as a hook")
    put.add_argument("name")
    put.add_argument("file")
    show_script = ssub.add_parser("show")
    show_script.add_argument("name")

    hooks = sub.add_parser("hooks", help="attach and detach Frida scripts")
    hsub = hooks.add_subparsers(dest="sub", required=True)
    hsub.add_parser("list")
    attach = hsub.add_parser("attach")
    attach.add_argument("pid", type=int)
    attach.add_argument("--script", default="default.js")
    detach = hsub.add_parser("detach")
    detach.add_argument("pid", type=int)

    mitm = sub.add_parser("mitm", help="control mitmproxy on the phone")
    msub = mitm.add_subparsers(dest="sub", required=True)
    msub.add_parser("show")
    start = msub.add_parser("start")
    start.add_argument("--port", type=int, default=8080)
    start.add_argument("--out", default="")
    msub.add_parser("stop")
    log = msub.add_parser("log")
    log.add_argument("-n", type=int, default=50)

    proxy = sub.add_parser("proxy", help="set or clear the target's HTTP proxy")
    psub = proxy.add_subparsers(dest="sub", required=True)
    psub.add_parser("show")
    pset = psub.add_parser("set")
    pset.add_argument("--host", required=True)
    pset.add_argument("--port", type=int, default=8080)
    pset.add_argument("--device", default="", help="adb serial; empty uses local settings")
    pclear = psub.add_parser("clear")
    pclear.add_argument("--device", default="")

    events = sub.add_parser("events", help="recent events, or stream them live")
    events.add_argument("-n", type=int, default=50)
    events.add_argument("--follow", action="store_true")
    return ap


def main():
    args = build_parser().parse_args()
    token = load_token(args)
    base = args.url.rstrip("/")

    if args.cmd == "status":
        result = req(base, token, "/api/status")
        show(result)
        print("frida: " + str(result.get("frida", {}).get("message", "unknown")), file=sys.stderr)
    elif args.cmd == "processes":
        show(req(base, token, "/api/processes", params={"filter": args.filter}))
    elif args.cmd == "scripts":
        if args.sub == "list":
            show(req(base, token, "/api/scripts"))
        elif args.sub == "put":
            with open(args.file, encoding="utf-8") as handle:
                source = handle.read()
            show(req(base, token, "/api/scripts", "POST", {"name": args.name, "source": source}))
        elif args.sub == "show":
            found = req(base, token, "/api/scripts")["scripts"]
            match = next((s for s in found if s["name"] == args.name), None)
            if not match:
                raise SystemExit(f"no hook named {args.name}")
            print(match["name"], match["bytes"])
    elif args.cmd == "hooks":
        if args.sub == "list":
            show(req(base, token, "/api/hooks"))
        elif args.sub == "attach":
            show(req(base, token, "/api/hooks", "POST",
                     {"pid": args.pid, "script": args.script}))
        elif args.sub == "detach":
            show(req(base, token, f"/api/hooks/{args.pid}", "DELETE"))
    elif args.cmd == "mitm":
        if args.sub == "show":
            show(req(base, token, "/api/mitm"))
        elif args.sub == "start":
            body = {"action": "start", "port": args.port}
            if args.out:
                body["out"] = args.out
            show(req(base, token, "/api/mitm", "POST", body))
        elif args.sub == "stop":
            show(req(base, token, "/api/mitm", "POST", {"action": "stop"}))
        elif args.sub == "log":
            show(req(base, token, "/api/mitm/log", params={"n": args.n}))
    elif args.cmd == "proxy":
        if args.sub == "show":
            show(req(base, token, "/api/proxy"))
        elif args.sub == "set":
            show(req(base, token, "/api/proxy", "POST",
                     {"action": "set", "host": args.host, "port": args.port,
                      "device": args.device}))
        elif args.sub == "clear":
            show(req(base, token, "/api/proxy", "POST",
                     {"action": "clear", "device": args.device}))
    elif args.cmd == "events":
        if args.follow:
            asyncio.run(follow(base, token))
        else:
            show(req(base, token, "/api/events", params={"n": args.n}))


if __name__ == "__main__":
    main()
