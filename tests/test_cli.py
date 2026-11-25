#!/usr/bin/env python3
"""Offline checks for the laptop CLI's token handling."""
import argparse
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "nixos"))
import owlx  # noqa: E402


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "token"
        self.path.write_text("file-token\n", encoding="utf-8")
        self.path.chmod(0o600)
        self.args = argparse.Namespace(token=None, token_file=str(self.path))
        self.saved = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)
        self.tmp.cleanup()

    def test_reads_token_file_without_passing_a_secret(self):
        os.environ.pop("OWLX_TOKEN", None)
        self.assertEqual(owlx.load_token(self.args), "file-token")

    def test_explicit_token_wins(self):
        self.args.token = "explicit-token"
        self.assertEqual(owlx.load_token(self.args), "explicit-token")

    def test_missing_token_is_an_error(self):
        os.environ.pop("OWLX_TOKEN", None)
        self.args.token_file = str(Path(self.tmp.name) / "absent")
        with self.assertRaises(SystemExit):
            owlx.load_token(self.args)

    def test_token_file_option_defaults_to_home(self):
        parser = owlx.build_parser()
        options = parser.parse_args(["--token-file", "/tmp/example", "status"])
        self.assertEqual(options.token_file, "/tmp/example")


if __name__ == "__main__":
    unittest.main()
