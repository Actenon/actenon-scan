"""Tests for reachability detection."""

import unittest
from pathlib import Path

from actenon_scan.engine import scan_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class ReachabilityTests(unittest.TestCase):
    def test_safe_not_an_agent_no_findings(self):
        """A refund in a plain script with no agent signals should NOT flag."""
        result = scan_path(FIXTURES / "safe" / "not_an_agent.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertEqual(0, len(findings), "not_an_agent.py should have no findings — no agent reachability")

    def test_vulnerable_refund_has_high_confidence(self):
        """refund_tool.py has @tool decorator — should be HIGH confidence."""
        result = scan_path(FIXTURES / "vulnerable" / "refund_tool.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.confidence == "high" for f in findings))


if __name__ == "__main__":
    unittest.main()
