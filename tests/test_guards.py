"""Tests for guard detection."""

import unittest
from pathlib import Path

from actenon_scan.engine import scan_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class GuardTests(unittest.TestCase):
    def test_safe_actenon_guard_no_findings(self):
        """refund_tool_actenon.py has an actenon verify_proof call before the sink."""
        result = scan_path(FIXTURES / "safe" / "refund_tool_actenon.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertEqual(0, len(findings), "refund_tool_actenon.py should have no findings — guarded by actenon")

    def test_safe_generic_guard_no_findings(self):
        """refund_tool_generic.py has a generic authorize() call before the sink."""
        result = scan_path(FIXTURES / "safe" / "refund_tool_generic.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertEqual(0, len(findings), "refund_tool_generic.py should have no findings — guarded by generic authorize()")


if __name__ == "__main__":
    unittest.main()
