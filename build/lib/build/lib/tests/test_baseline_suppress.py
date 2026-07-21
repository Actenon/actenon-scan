"""Tests for baseline + suppression."""

import json
import tempfile
import unittest
from pathlib import Path

from actenon_scan.baseline import load_baseline, write_baseline
from actenon_scan.engine import scan_path
from actenon_scan.report.json_out import format_json
from actenon_scan.suppress import parse_suppressions

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class BaselineTests(unittest.TestCase):
    def test_baseline_suppresses_known_findings(self):
        """Generate a baseline, then re-scan with it — known findings are suppressed."""
        vuln_file = FIXTURES / "vulnerable" / "refund_tool.py"

        # First scan — generate baseline
        result1 = scan_path(vuln_file)
        findings1 = [f for f in result1.findings if not f.suppressed]
        self.assertGreater(len(findings1), 0)

        # Write baseline
        baseline_data = [
            {"file": f.file, "snippet_hash": f.snippet_hash, "rule_id": f.rule_id}
            for f in findings1
        ]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as bf:
            json.dump({"version": "1", "findings": baseline_data}, bf)
            baseline_path = bf.name

        # Second scan with baseline
        baseline = load_baseline(baseline_path)
        result2 = scan_path(vuln_file, baseline_findings=baseline)
        findings2 = [f for f in result2.findings if not f.suppressed]
        self.assertEqual(0, len(findings2), "Baseline should suppress all known findings")


class SuppressionTests(unittest.TestCase):
    def test_inline_suppression(self):
        """A # actenon-scan: ignore[rule-id] comment suppresses the finding."""
        source = '''"""test"""
from langchain.tools import tool

@tool
def bad_refund():
    # actenon-scan: ignore[PAY-GENERIC-REFUND]
    refund(amount=100)
'''
        sups = parse_suppressions(source, "test.py")
        self.assertIn(("test.py", "PAY-GENERIC-REFUND"), sups)


if __name__ == "__main__":
    unittest.main()
