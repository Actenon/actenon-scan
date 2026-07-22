"""Tests for sink detection."""

import unittest
from pathlib import Path

from actenon_scan.engine import scan_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class SinkDetectionTests(unittest.TestCase):
    def test_vulnerable_refund_flags_stripe(self):
        result = scan_path(FIXTURES / "vulnerable" / "refund_tool.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertGreater(len(findings), 0, "refund_tool.py should flag stripe refund")
        self.assertTrue(any(f.category == "payments" for f in findings))

    def test_vulnerable_delete_flags_sql_and_rmtree(self):
        result = scan_path(FIXTURES / "vulnerable" / "delete_tool.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertGreater(len(findings), 0, "delete_tool.py should flag DELETE/rmtree")
        self.assertTrue(any(f.category == "data_destruction" for f in findings))

    def test_vulnerable_deploy_flags_subprocess(self):
        result = scan_path(FIXTURES / "vulnerable" / "deploy_tool.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertGreater(len(findings), 0, "deploy_tool.py should flag kubectl subprocess")

    def test_vulnerable_replit_incident_flags(self):
        result = scan_path(FIXTURES / "vulnerable" / "replit_incident.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertGreater(len(findings), 0, "replit_incident.py should flag destructive calls")


if __name__ == "__main__":
    unittest.main()
