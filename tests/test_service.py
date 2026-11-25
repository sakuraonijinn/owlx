#!/usr/bin/env python3
"""Offline checks for the owlx service (no frida-server or mitmproxy needed)."""
import asyncio
import json
import sys
import tempfile
import unittest
import unittest.mock as mock
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


class FakeManager:
    def __init__(self, device):
        self.device = device
        self.specs = []

    def add_remote_device(self, spec):
        self.specs.append(spec)
        return self.device


class FakeFrida:
    __version__ = "17.27.5"

    def __init__(self, device):
        self.manager = FakeManager(device)

    def get_device_manager(self):
        return self.manager


class BrokenDevice(FakeDevice):
    def enumerate_processes(self):
        raise RuntimeError("frida-server version mismatch: 16.2.1 vs 17.2.5")


class FridaConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = svc.State("remote:10.10.10.119:27042", self.tmp.name, 3)
        self.app = svc.make_app(self.state, "secret-token")
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        self.headers = {"Authorization": "Bearer secret-token"}

    async def asyncTearDown(self):
        await self.client.close()
        self.tmp.cleanup()

    async def test_remote_connected_status(self):
        fake = FakeFrida(FakeDevice())

        async def tcp_ok(host, port, timeout):
            self.assertEqual((host, port), ("10.10.10.119", 27042))
            self.assertEqual(timeout, 3)
            return True, ""

        with mock.patch.object(svc, "frida", fake), mock.patch.object(svc, "check_tcp", tcp_ok):
            device = await svc.connect_device(self.state)
        self.assertIs(device, fake.manager.device)
        self.assertEqual(fake.manager.specs, ["10.10.10.119:27042"])

        result = await (await self.client.get("/api/status", headers=self.headers)).json()
        info = result["frida"]
        self.assertTrue(info["connected"])
        self.assertEqual(info["state"], "connected")
        self.assertIn("frida connected", info["message"])
        self.assertEqual(info["process_count"], 2)
        self.assertEqual(info["diagnostic"], "")
        self.assertEqual(info["bindings_version"], "17.27.5")
        procs = await (await self.client.get("/api/processes", headers=self.headers)).json()
        self.assertEqual(procs["total"], 2)

    async def test_server_not_running_is_explained(self):
        async def tcp_refused(_host, _port, _timeout):
            return False, "ConnectionRefusedError: Connection refused"

        with mock.patch.object(svc, "frida", FakeFrida(FakeDevice())), \
                mock.patch.object(svc, "check_tcp", tcp_refused):
            self.assertIsNone(await svc.connect_device(self.state))

        result = await (await self.client.get("/api/status", headers=self.headers)).json()
        info = result["frida"]
        self.assertFalse(info["connected"])
        self.assertIn("cannot reach", info["diagnostic"])
        self.assertIn("frida-server", info["diagnostic"])
        self.assertIn("10.10.10.119:27042", info["diagnostic"])
        response = await self.client.get("/api/processes", headers=self.headers)
        self.assertEqual(response.status, 503)
        self.assertIn("cannot reach", (await response.json())["error"])

    async def test_timeout_is_explained(self):
        async def tcp_timeout(_host, _port, _timeout):
            return False, "timed out after 3s"

        with mock.patch.object(svc, "frida", FakeFrida(FakeDevice())), \
                mock.patch.object(svc, "check_tcp", tcp_timeout):
            await svc.connect_device(self.state)
        info = (await (await self.client.get("/api/status", headers=self.headers)).json())["frida"]
        self.assertFalse(info["connected"])
        self.assertIn("timed out", info["diagnostic"])
        self.assertIn("27042", info["diagnostic"])

    async def test_version_mismatch_is_explained(self):
        async def tcp_ok(_host, _port, _timeout):
            return True, ""

        with mock.patch.object(svc, "frida", FakeFrida(BrokenDevice())), \
                mock.patch.object(svc, "check_tcp", tcp_ok):
            await svc.connect_device(self.state)
        info = (await (await self.client.get("/api/status", headers=self.headers)).json())["frida"]
        self.assertFalse(info["connected"])
        self.assertIn("version mismatch", info["error"])
        self.assertIn("protocol/version mismatch", info["diagnostic"])
        self.assertIn("17.27.5", info["diagnostic"])


class MitmCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_mitm_terminates_child_and_drains_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = svc.State("local", tmp)

            class Proc:
                def __init__(self):
                    self.returncode = None
                    self.terminated = False
                    self.killed = False
                    self.stdout = None

                def terminate(self):
                    self.terminated = True
                    self.returncode = 0

                def kill(self):
                    self.killed = True
                    self.returncode = -9

                async def wait(self):
                    return self.returncode

            proc = Proc()
            reader = asyncio.create_task(asyncio.sleep(10))
            state.mitm_proc = proc
            state.mitm_task = reader
            state.mitm_options = {"port": 8080}

            self.assertTrue(await svc.stop_mitm(state))
        self.assertTrue(proc.terminated)
        self.assertFalse(proc.killed)
        self.assertTrue(reader.cancelled())
        self.assertIsNone(state.mitm_proc)
        self.assertIsNone(state.mitm_task)
        self.assertEqual(state.mitm_options, {})


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

    def test_remote_target_parsing(self):
        self.assertEqual(svc.remote_target("remote:10.0.0.1:27042"), ("10.0.0.1", 27042))
        self.assertEqual(svc.remote_target("10.0.0.1:27042"), ("10.0.0.1", 27042))
        self.assertIsNone(svc.remote_target("local"))
        with self.assertRaises(ValueError):
            svc.remote_target("remote:10.0.0.1")
        with self.assertRaises(ValueError):
            svc.remote_target("remote:10.0.0.1:not-a-port")

    def test_missing_bindings_diagnostic(self):
        with mock.patch.object(svc, "frida", None):
            text = svc.diagnose_frida_error("remote:10.0.0.1:27042", RuntimeError("x"))
        self.assertIn("not installed", text)
        self.assertIn("17.27.5", text)


if __name__ == "__main__":
    unittest.main()
