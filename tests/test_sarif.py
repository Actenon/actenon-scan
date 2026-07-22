"""Tests for SARIF output format."""

import json
import unittest
from pathlib import Path

from actenon_scan.engine import scan_path
from actenon_scan.report.sarif import format_sarif

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class SarifTests(unittest.TestCase):
    def test_sarif_output_is_valid_json(self):
        result = scan_path(FIXTURES / "vulnerable" / "refund_tool.py")
        sarif_text = format_sarif(result)
        data = json.loads(sarif_text)
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("runs", data)
        self.assertEqual(len(data["runs"]), 1)
        run = data["runs"][0]
        self.assertIn("tool", run)
        self.assertIn("driver", run["tool"])
        self.assertEqual(run["tool"]["driver"]["name"], "actenon-scan")
        self.assertGreater(len(run["results"]), 0)

    def test_sarif_result_has_required_fields(self):
        result = scan_path(FIXTURES / "vulnerable" / "refund_tool.py")
        sarif_text = format_sarif(result)
        data = json.loads(sarif_text)
        for r in data["runs"][0]["results"]:
            self.assertIn("ruleId", r)
            self.assertIn("level", r)
            self.assertIn("message", r)
            self.assertIn("locations", r)
            loc = r["locations"][0]["physicalLocation"]
            self.assertIn("artifactLocation", loc)
            self.assertIn("uri", loc["artifactLocation"])
            self.assertIn("region", loc)
            self.assertIn("startLine", loc["region"])

    def test_sarif_rules_array_populated(self):
        result = scan_path(FIXTURES / "vulnerable" / "refund_tool.py")
        sarif_text = format_sarif(result)
        data = json.loads(sarif_text)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        self.assertGreater(len(rules), 0)
        for rule in rules:
            self.assertIn("id", rule)
            self.assertIn("name", rule)
            self.assertIn("defaultConfiguration", rule)
            self.assertIn("level", rule["defaultConfiguration"])


if __name__ == "__main__":
    unittest.main()
