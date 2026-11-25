#!/usr/bin/env python3
"""Offline checks for nixos/start-engine.sh with fake python3/curl/ip."""
import os
import signal
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nixos" / "start-engine.sh"
TOKEN = "unit-test-token-not-a-secret"


def write_script(path, body):
    path.write_text("#!/usr/bin/env bash\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o755)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.bin = self.base / "bin"
        self.home = self.base / "home"
        self.bin.mkdir()
        (self.home / ".config" / "owlx").mkdir(parents=True)
        token_file = self.home / ".config" / "owlx" / "token"
        token_file.write_text(TOKEN + "\n", encoding="utf-8")
        token_file.chmod(0o600)

        self.actions = self.base / "actions"
        self.args_file = self.base / "service.args"
        self.token_seen = self.base / "token.seen"

        write_script(self.bin / "python3", f"""
            printf '%s\\n' "$*" >> "{self.actions}"
            printf '%s' "$OWLX_TOKEN" > "{self.token_seen}"
            case "$1" in
              *owlx_service.py)
                printf '%s\\n' "$*" > "{self.args_file}"
                trap 'rm -f "{self.args_file}"; exit 0' TERM INT
                while true; do sleep 0.2; done
                ;;
              *owlx.py)
                echo '{{"version":"0.3.0","frida":{{"connected":true,"state":"connected","message":"frida connected to remote:192.0.2.10:12345 (2 processes)","diagnostic":""}}}}'
                ;;
            esac
        """)
        write_script(self.bin / "curl", "exit 0\n")
        write_script(self.bin / "ip",
                     "echo '2: eth0    inet 192.0.2.77/24 brd 192.0.2.255 scope global eth0'\n")

        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{self.bin}:{self.env.get('PATH', '')}",
            "HOME": str(self.home),
            "TABLET_IP": "192.0.2.10",
            "FRIDA_PORT": "12345",
            "OWLX_PORT": "18987",
            "OWLX_MITM": "1",
            "OWLX_FRIDA_TIMEOUT": "3",
            "OWLX_HEALTH_TIMEOUT": "5",
            "OWLX_STOP_TIMEOUT": "3",
        })
        for key in ("OWLX_TOKEN", "OWLX_ROOT", "OWLX_TOKEN_FILE", "OWLX_RUN_DIR"):
            self.env.pop(key, None)

    def tearDown(self):
        self._kill_fake_service()
        self.tmp.cleanup()

    def _kill_fake_service(self):
        pid_file = self.home / ".local" / "state" / "owlx" / "service.pid"
        if pid_file.exists():
            try:
                fields = pid_file.read_text().split()
                if fields:
                    os.kill(int(fields[0]), signal.SIGKILL)
            except (ValueError, OSError):
                pass
            pid_file.unlink(missing_ok=True)

    def run_engine(self, action, timeout=15):
        return subprocess.run(["bash", str(SCRIPT), action], env=self.env,
                              text=True, capture_output=True, timeout=timeout)

    def test_start_status_stop(self):
        started = self.run_engine("start")
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assertIn("remote:192.0.2.10:12345", started.stdout)
        self.assertIn("http://192.0.2.77:18987", started.stdout)
        pid_file = self.home / ".local/state/owlx/service.pid"
        self.assertTrue(pid_file.exists())

        args = self.args_file.read_text()
        self.assertIn("--device remote:192.0.2.10:12345", args)
        self.assertIn("--frida-timeout 3", args)
        self.assertEqual(self.token_seen.read_text(), TOKEN)
        self.assertIn("mitm start", self.actions.read_text())

        status = self.run_engine("status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("dashboard base: http://192.0.2.77:18987", status.stdout)
        self.assertIn("frida connected", status.stdout)

        stopped = self.run_engine("stop")
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        self.assertFalse(pid_file.exists())
        self.assertIn("mitm stop", self.actions.read_text())

    def test_stale_pid_is_ignored(self):
        pid_file = self.home / ".local/state/owlx/service.pid"
        pid_file.parent.mkdir(parents=True, exist_ok=True)
        sleeper = subprocess.Popen(["sleep", "30"])
        try:
            pid_file.write_text(f"{sleeper.pid} owlx-service\n")
            status = self.run_engine("status")
            self.assertEqual(status.returncode, 1)
            self.assertIn("engine stopped", status.stdout)
            self.assertFalse(pid_file.exists())
            self.assertIsNone(sleeper.poll())
        finally:
            sleeper.terminate()
            sleeper.wait(timeout=5)

    def test_bad_config_is_rejected(self):
        self.env["OWLX_PORT"] = "not-a-port"
        result = self.run_engine("status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("OWLX_PORT", result.stderr)

    def test_mitm_can_be_disabled(self):
        self.env["OWLX_MITM"] = "0"
        result = self.run_engine("start")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("mitm start", self.actions.read_text())
        self.assertIn("mitm 0", result.stdout)


if __name__ == "__main__":
    unittest.main()
