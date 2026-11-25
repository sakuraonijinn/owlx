#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import time
from aiohttp import web, WSMsgType

HOOKS = {}  # pid -> {pid,name,attached_at}
CLIENTS = set()


def now():
    return time.time()


def auth_ok(request):
    token = os.environ.get("OWLX_TOKEN", "")
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Bearer "):
        hdr = hdr[7:]
    return token and hdr == token


@web.middleware
async def auth_middleware(request, handler):
    if request.path == "/healthz":
        return await handler(request)
    if not auth_ok(request):
        return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


async def broadcast(event):
    msg = json.dumps(event, separators=(",", ":"))
    dead = []
    for ws in CLIENTS:
        try:
            await ws.send_str(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        CLIENTS.discard(ws)


async def healthz(_request):
    return web.json_response({"ok": True, "hooks": len(HOOKS)})


async def list_hooks(_request):
    hooks = sorted(HOOKS.values(), key=lambda h: h["pid"])
    return web.json_response({"hooks": hooks})


async def attach_hook(request):
    body = await request.json()
    pid = int(body["pid"])
    if pid <= 0:
        return web.json_response({"error": "pid must be > 0"}, status=400)
    hook = HOOKS.get(pid)
    if not hook:
        hook = {"pid": pid, "name": body.get("name") or str(pid), "attached_at": now()}
        HOOKS[pid] = hook
        await broadcast({"type": "hook.attached", "hook": hook, "ts": now()})
    return web.json_response({"hook": hook, "attached": True})


async def detach_hook(request):
    pid = int(request.match_info["pid"])
    hook = HOOKS.pop(pid, None)
    if hook:
        await broadcast({"type": "hook.detached", "hook": hook, "ts": now()})
        return web.json_response({"hook": hook, "detached": True})
    return web.json_response({"error": "not found", "pid": pid}, status=404)


async def events_ws(request):
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    CLIENTS.add(ws)
    await ws.send_str(json.dumps({"type": "hello", "hooks": sorted(HOOKS.values(), key=lambda h: h["pid"]), "ts": now()}))
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT and msg.data == "ping":
                await ws.send_str(json.dumps({"type": "pong", "ts": now()}))
    finally:
        CLIENTS.discard(ws)
    return ws


def make_app():
    app = web.Application(middlewares=[auth_middleware])
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/api/hooks", list_hooks)
    app.router.add_post("/api/hooks", attach_hook)
    app.router.add_delete("/api/hooks/{pid}", detach_hook)
    app.router.add_get("/ws", events_ws)
    return app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    if not os.environ.get("OWLX_TOKEN"):
        raise SystemExit("OWLX_TOKEN is required")
    web.run_app(make_app(), host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
