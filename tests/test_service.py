#!/usr/bin/env python3
"""Offline checks for the owlx service (no frida-server or mitmproxy needed)."""
import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "phone"))
import owlx_service as svc  # noqa: E402

from aiohttp.test_utils import TestClient, TestServer  # noqa: E402


class FakeScript:
    def __init__(self):
        self.loaded = False
        self.callback = None

    def on(self, kind, callback):
        self.callback = callback

    def load(self):
        self.loaded = True

    def unload(self):
        self.loaded = False


class FakeSession:
    def __init__(self):
        self.script = FakeScript()
        self.detached = False

    def create_script(self, name, source):
        self.script.name = name
        self.script.source = source
        return self.script

    def detach(self):
        self.detached = True


class FakeProc:
    def __init__(self, pid, name):
        self.pid = pid
        self.name = name


class FakeDevice:
    def __init__(self):
        self.sessions = {}

    def attach(self, pid):
        session = FakeSession()
        self.sessions[pid] = session
        return session

    def enumerate_processes(self):
        return [FakeProc(1, "com.example.app"), FakeProc(2, "system_server")]


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hooks = Path(self.tmp.name)
        self.state = svc.State("local", str(self.hooks))
        self.app = svc.make_app(self.state, "secret-token")
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        # on_startup may connect to a real local frida device; swap in the fake.
        self.state.device = FakeDevice()

    async def asyncTearDown(self):
        await self.client.close()
        self.tmp.cleanup()

    def headers(self):
        return {"Authorization": "Bearer secret-token"}

    async def test_auth_required(self):
        response = await self.client.get("/api/status")
        self.assertEqual(response.status, 401)
        response = await self.client.get("/healthz")
        self.assertEqual(response.status, 200)

    async def test_status_and_processes(self):
        status = await (await self.client.get("/api/status", headers=self.headers())).json()
        self.assertEqual(status["version"], svc.VERSION)
        self.assertTrue(status["frida"]["connected"])
        procs = await (await self.client.get("/api/processes", headers=self.headers())).json()
        self.assertEqual(procs["total"], 2)
        filtered = await (await self.client.get("/api/processes?filter=example", headers=self.headers())).json()
        self.assertEqual(filtered["processes"][0]["name"], "com.example.app")

    async def test_scripts_and_hook_round_trip(self):
        response = await self.client.post("/api/scripts", headers=self.headers(),
                                          json={"name": "demo.js", "source": "send('hi')"})
        self.assertEqual(response.status, 200)
        scripts = await (await self.client.get("/api/scripts", headers=self.headers())).json()
        self.assertEqual([s["name"] for s in scripts["scripts"]], ["demo.js"])
        response = await self.client.post("/api/hooks", headers=self.headers(),
                                          json={"pid": 1, "script": "demo.js"})
        self.assertEqual(response.status, 200)
        hooks = await (await self.client.get("/api/hooks", headers=self.headers())).json()
        self.assertEqual(hooks["hooks"][0]["script"], "demo.js")
        response = await self.client.delete("/api/hooks/1", headers=self.headers())
        self.assertEqual(response.status, 200)
        hooks = await (await self.client.get("/api/hooks", headers=self.headers())).json()
        self.assertEqual(hooks["hooks"], [])
        self.assertTrue(self.state.device.sessions[1].detached)

    async def test_hook_name_rejected(self):
        response = await self.client.post("/api/scripts", headers=self.headers(),
                                          json={"name": "../evil", "source": "x"})
        self.assertEqual(response.status, 400)

    async def test_mitm_and_proxy_status(self):
        mitm = await (await self.client.get("/api/mitm", headers=self.headers())).json()
        self.assertFalse(mitm["running"])
        proxy = await (await self.client.get("/api/proxy", headers=self.headers())).json()
        self.assertEqual(proxy["proxy"]["mode"], "none")
        events = await (await self.client.get("/api/events", headers=self.headers())).json()
        self.assertIsInstance(events["events"], list)


class HelperTests(unittest.TestCase):
    def test_hook_path_safety(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(svc.hook_path(tmp, "demo").name, "demo.js")
            with self.assertRaises(ValueError):
                svc.hook_path(tmp, "../evil")

    def test_auth_ok_query_token(self):
        class Req:
            headers = {}
            query = {"token": "abc"}
        self.assertTrue(svc.auth_ok(Req(), "abc"))
        self.assertFalse(svc.auth_ok(Req(), "other"))


if __name__ == "__main__":
    unittest.main()
