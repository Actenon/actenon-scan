"""Tests for CLI."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class CliTests(unittest.TestCase):
    def test_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "actenon_scan", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(0, result.returncode)
        self.assertIn("actenon-scan", result.stdout)

    def test_rules(self):
        result = subprocess.run(
            [sys.executable, "-m", "actenon_scan", "rules"],
            capture_output=True, text=True,
        )
        self.assertEqual(0, result.returncode)
        self.assertIn("PAY", result.stdout)

    def test_scan_pretty(self):
        result = subprocess.run(
            [sys.executable, "-m", "actenon_scan", "scan", str(FIXTURES / "vulnerable" / "refund_tool.py"), "--format", "pretty"],
            capture_output=True, text=True,
        )
        self.assertEqual(1, result.returncode)  # has findings
        self.assertIn("refund", result.stdout.lower())

    def test_scan_json(self):
        result = subprocess.run(
            [sys.executable, "-m", "actenon_scan", "scan", str(FIXTURES / "vulnerable" / "refund_tool.py"), "--format", "json"],
            capture_output=True, text=True,
        )
        self.assertEqual(1, result.returncode)
        data = json.loads(result.stdout)
        self.assertGreater(data["finding_count"], 0)

    def test_scan_sarif(self):
        result = subprocess.run(
            [sys.executable, "-m", "actenon_scan", "scan", str(FIXTURES / "vulnerable" / "refund_tool.py"), "--format", "sarif"],
            capture_output=True, text=True,
        )
        self.assertEqual(1, result.returncode)
        data = json.loads(result.stdout)
        self.assertEqual("2.1.0", data["version"])

    def test_scan_safe_dir_no_findings(self):
        result = subprocess.run(
            [sys.executable, "-m", "actenon_scan", "scan", str(FIXTURES / "safe"), "--format", "json", "--fail-on", "none"],
            capture_output=True, text=True,
        )
        self.assertEqual(0, result.returncode)
        data = json.loads(result.stdout)
        self.assertEqual(0, data["finding_count"])

    def test_scan_exit_code_none(self):
        result = subprocess.run(
            [sys.executable, "-m", "actenon_scan", "scan", str(FIXTURES / "vulnerable" / "refund_tool.py"), "--fail-on", "none"],
            capture_output=True, text=True,
        )
        self.assertEqual(0, result.returncode)

    def test_init(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "actenon_scan", "init"],
                    capture_output=True, text=True,
                )
                self.assertEqual(0, result.returncode)
                self.assertTrue(Path("actenon-scan.json").exists())
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
