#!/usr/bin/env python3
"""owlx phone-side control service.

Authenticated JSON + WebSocket API around real Frida sessions and mitmproxy.
Frida attachment happens in-process through frida-server (remote) or the local
device; mitmproxy runs as a child process whose log is streamed to clients.
"""
import argparse
import asyncio
import hmac
import json
import os
import re
import shutil
import threading
import time
from collections import deque
from pathlib import Path

from aiohttp import web, WSMsgType

try:
    import frida
except Exception:  # service still runs so the dashboard can report the problem
    frida = None

VERSION = "0.2.0"
STATE_KEY = web.AppKey("state", object)
TOKEN_KEY = web.AppKey("token", str)
ROOT = Path(__file__).resolve().parents[1]
EVENT_LIMIT = 200
LOG_LIMIT = 200
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def hook_path(hooks_dir, name):
    """Resolve a hook name safely inside hooks_dir."""
    if not name or not NAME_RE.match(name) or ".." in name:
        raise ValueError("invalid hook name")
    path = Path(hooks_dir) / (name if name.endswith(".js") else name + ".js")
    if not path.resolve().is_relative_to(Path(hooks_dir).resolve()):
        raise ValueError("hook path escapes hooks directory")
    return path


def get_device(spec):
    if frida is None:
        raise RuntimeError("frida Python bindings are not installed")
    if spec in ("local", "usb"):
        return frida.get_local_device() if spec == "local" else frida.get_usb_device()
    if spec.startswith("remote:"):
        spec = spec[len("remote:"):]
    return frida.get_device_manager().add_remote_device(spec)


class State:
    def __init__(self, device_spec, hooks_dir):
        self.device_spec = device_spec
        self.hooks_dir = Path(hooks_dir)
        self.device = None
        self.device_error = ""
        self.loop = None
        self.clients = set()
        self.events = deque(maxlen=EVENT_LIMIT)
        self.sessions = {}       # pid -> {session, script, name, attached_at}
        self.lock = threading.Lock()
        self.mitm_proc = None
        self.mitm_task = None
        self.mitm_log = deque(maxlen=LOG_LIMIT)
        self.mitm_options = {}
        self.proxy = {"mode": "none", "host": "", "port": 0, "device": ""}


async def emit(state, kind, **data):
    event = {"type": kind, "ts": time.time(), **data}
    state.events.append(event)
    message = json.dumps(event, separators=(",", ":"))
    for ws in list(state.clients):
        try:
            await ws.send_str(message)
        except Exception:
            state.clients.discard(ws)


def frida_message(state, pid, name, message, payload):
    data = None
    if payload:
        data = bytes(payload).hex()[:512]
    coro = emit(state, "hook.message", pid=pid, script=name, message=message, data=data)
    if state.loop:
        asyncio.run_coroutine_threadsafe(coro, state.loop)


def auth_ok(request, token):
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        header = header[7:]
    candidate = header or request.query.get("token", "")
    return bool(token) and hmac.compare_digest(candidate, token)


@web.middleware
async def auth_middleware(request, handler):
    if request.path == "/healthz":
        return await handler(request)
    if not auth_ok(request, request.app[TOKEN_KEY]):
        return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


def hook_info(hook):
    return {"pid": hook["pid"], "script": hook["script_name"],
            "attached_at": hook["attached_at"]}


async def healthz(_request):
    return web.json_response({"ok": True})


async def status(request):
    state = request.app[STATE_KEY]
    return web.json_response({
        "version": VERSION,
        "frida": {"available": frida is not None, "device": state.device_spec,
                  "connected": state.device is not None, "error": state.device_error},
        "hooks": [hook_info(h) for h in sorted(state.sessions.values(), key=lambda h: h["pid"])],
        "mitm": {"running": state.mitm_proc is not None and state.mitm_proc.returncode is None,
                 "options": state.mitm_options, "log_lines": len(state.mitm_log)},
        "proxy": state.proxy,
        "events": len(state.events),
    })


async def processes(request):
    state = request.app[STATE_KEY]
    if state.device is None:
        return web.json_response({"error": state.device_error or "no frida device"}, status=503)
    needle = request.query.get("filter", "").lower()
    try:
        found = await asyncio.to_thread(state.device.enumerate_processes)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=502)
    items = [{"pid": p.pid, "name": p.name} for p in found]
    if needle:
        items = [p for p in items if needle in p["name"].lower()]
    return web.json_response({"processes": items[:300], "total": len(items)})


async def scripts_list(request):
    state = request.app[STATE_KEY]
    state.hooks_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for path in sorted(state.hooks_dir.glob("*.js")):
        files.append({"name": path.name, "bytes": path.stat().st_size})
    return web.json_response({"scripts": files, "dir": str(state.hooks_dir)})


async def scripts_save(request):
    state = request.app[STATE_KEY]
    body = await request.json()
    name = body.get("name", "")
    source = body.get("source", "")
    try:
        path = hook_path(state.hooks_dir, name)
    except ValueError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    await emit(state, "script.saved", name=path.name)
    return web.json_response({"script": path.name, "bytes": path.stat().st_size})


def do_attach(state, pid, name):
    if state.device is None:
        raise RuntimeError(state.device_error or "no frida device")
    path = hook_path(state.hooks_dir, name)
    source = path.read_text(encoding="utf-8")
    with state.lock:
        if pid in state.sessions:
            return state.sessions[pid]
        session = state.device.attach(pid)
        script = session.create_script(name=path.name, source=source)
        script.on("message", lambda m, d, p=pid, n=path.name: frida_message(state, p, n, m, d))
        script.load()
        hook = {"pid": pid, "session": session, "script": script,
                "script_name": path.name, "attached_at": time.time()}
        state.sessions[pid] = hook
        return hook


async def hooks_add(request):
    state = request.app[STATE_KEY]
    body = await request.json()
    try:
        pid = int(body["pid"])
    except (KeyError, TypeError, ValueError):
        return web.json_response({"error": "pid must be an integer"}, status=400)
    name = body.get("script") or "default.js"
    try:
        hook = await asyncio.to_thread(do_attach, state, pid, name)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=502)
    await emit(state, "hook.attached", pid=pid, script=hook["script_name"])
    return web.json_response({"hook": hook_info(hook), "attached": True})


def do_detach(state, pid):
    with state.lock:
        hook = state.sessions.pop(pid, None)
        if not hook:
            return None
        try:
            hook["script"].unload()
        finally:
            hook["session"].detach()
        return hook


async def hooks_remove(request):
    state = request.app[STATE_KEY]
    try:
        pid = int(request.match_info["pid"])
    except ValueError:
        return web.json_response({"error": "bad pid"}, status=400)
    try:
        hook = await asyncio.to_thread(do_detach, state, pid)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=502)
    if not hook:
        return web.json_response({"error": "not found", "pid": pid}, status=404)
    await emit(state, "hook.detached", pid=pid)
    return web.json_response({"detached": True, "pid": pid})


async def hooks_list(request):
    state = request.app[STATE_KEY]
    with state.lock:
        hooks = [hook_info(h) for h in sorted(state.sessions.values(), key=lambda h: h["pid"])]
    return web.json_response({"hooks": hooks})


async def read_mitm(state, proc):
    assert proc.stdout is not None
    async for line in proc.stdout:
        text = line.decode("utf-8", "replace").rstrip()
        if text:
            state.mitm_log.append(text)
    await proc.wait()


async def mitm_control(request):
    state = request.app[STATE_KEY]
    body = await request.json() if request.can_read_body else {}
    action = body.get("action", "status")
    running = state.mitm_proc is not None and state.mitm_proc.returncode is None
    if action == "start":
        if running:
            return web.json_response({"error": "mitmproxy already running"}, status=409)
        port = int(body.get("port", 8080))
        out = body.get("out") or str(ROOT / "flows.mitm")
        cmd = ["mitmproxy", "-l", str(port), "-w", out]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=502)
        state.mitm_proc = proc
        state.mitm_options = {"port": port, "out": out, "pid": proc.pid}
        state.mitm_log.clear()
        state.mitm_task = asyncio.create_task(read_mitm(state, proc))
        await emit(state, "mitm.started", port=port, pid=proc.pid)
        return web.json_response({"running": True, "options": state.mitm_options})
    if action == "stop":
        if not running:
            return web.json_response({"error": "mitmproxy not running"}, status=409)
        state.mitm_proc.terminate()
        try:
            await asyncio.wait_for(state.mitm_proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            state.mitm_proc.kill()
        await emit(state, "mitm.stopped")
        return web.json_response({"running": False})
    return web.json_response({"running": running, "options": state.mitm_options})


async def mitm_log(request):
    state = request.app[STATE_KEY]
    try:
        n = int(request.query.get("n", "50"))
    except ValueError:
        n = 50
    return web.json_response({"lines": list(state.mitm_log)[-n:]})


async def proxy_control(request):
    state = request.app[STATE_KEY]
    if request.method == "GET":
        return web.json_response({"proxy": state.proxy})
    body = await request.json()
    action = body.get("action", "")
    if action == "clear":
        value = ":0"
    elif action == "set":
        host = body.get("host", "")
        port = int(body.get("port", 8080))
        if not host:
            return web.json_response({"error": "host required"}, status=400)
        value = f"{host}:{port}"
    else:
        return web.json_response({"error": "action must be set or clear"}, status=400)
    device = body.get("device", "")
    cmd = ["adb"] + (["-s", device] if device else []) + ["shell", "settings", "put", "global", "http_proxy", value]
    if not device and not shutil.which("adb"):
        cmd = ["settings", "put", "global", "http_proxy", value]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
    except Exception as exc:
        return web.json_response({"error": str(exc), "command": " ".join(cmd)}, status=502)
    state.proxy = {"mode": action, "host": body.get("host", ""),
                   "port": int(body.get("port", 0)) if action == "set" else 0,
                   "device": device, "value": value}
    await emit(state, "proxy.changed", action=action, value=value)
    return web.json_response({"proxy": state.proxy, "command": " ".join(cmd),
                              "output": out.decode("utf-8", "replace").strip(), "code": proc.returncode})


async def events_list(request):
    state = request.app[STATE_KEY]
    try:
        n = int(request.query.get("n", "50"))
    except ValueError:
        n = 50
    return web.json_response({"events": list(state.events)[-n:]})


async def websocket(request):
    state = request.app[STATE_KEY]
    if not auth_ok(request, request.app[TOKEN_KEY]):
        return web.Response(status=401, text="unauthorized")
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    state.clients.add(ws)
    await ws.send_str(json.dumps({"type": "hello", "ts": time.time(),
                                  "events": list(state.events)[-20:]}))
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT and msg.data == "ping":
                await ws.send_str(json.dumps({"type": "pong", "ts": time.time()}))
    finally:
        state.clients.discard(ws)
    return ws


async def on_startup(app):
    state = app[STATE_KEY]
    state.loop = asyncio.get_running_loop()
    state.hooks_dir.mkdir(parents=True, exist_ok=True)
    try:
        state.device = await asyncio.to_thread(get_device, state.device_spec)
        await emit(state, "device.connected", spec=state.device_spec)
    except Exception as exc:
        state.device_error = str(exc)
        await emit(state, "device.error", error=state.device_error)


async def on_cleanup(app):
    state = app[STATE_KEY]
    for pid in list(state.sessions):
        try:
            await asyncio.to_thread(do_detach, state, pid)
        except Exception:
            pass
    if state.mitm_proc is not None and state.mitm_proc.returncode is None:
        state.mitm_proc.terminate()


def make_app(state, token):
    app = web.Application(middlewares=[auth_middleware])
    app[STATE_KEY] = state
    app[TOKEN_KEY] = token
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/api/status", status)
    app.router.add_get("/api/processes", processes)
    app.router.add_get("/api/scripts", scripts_list)
    app.router.add_post("/api/scripts", scripts_save)
    app.router.add_get("/api/hooks", hooks_list)
    app.router.add_post("/api/hooks", hooks_add)
    app.router.add_delete("/api/hooks/{pid}", hooks_remove)
    app.router.add_get("/api/mitm", mitm_control)
    app.router.add_post("/api/mitm", mitm_control)
    app.router.add_get("/api/mitm/log", mitm_log)
    app.router.add_get("/api/proxy", proxy_control)
    app.router.add_post("/api/proxy", proxy_control)
    app.router.add_get("/api/events", events_list)
    app.router.add_get("/ws", websocket)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


def main():
    ap = argparse.ArgumentParser(prog="owlx-service")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--device", default=os.environ.get("OWLX_DEVICE", "remote:127.0.0.1:27042"),
                    help="local, usb, remote:host:port or host:port (frida-server)")
    ap.add_argument("--hooks-dir", default=os.environ.get("OWLX_HOOKS_DIR", str(ROOT / "hooks")))
    args = ap.parse_args()
    token = os.environ.get("OWLX_TOKEN", "")
    if not token:
        raise SystemExit("OWLX_TOKEN is required")
    state = State(args.device, args.hooks_dir)
    web.run_app(make_app(state, token), host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
