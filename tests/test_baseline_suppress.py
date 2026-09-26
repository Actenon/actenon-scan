"""Tests for baseline + suppression."""

import json
import tempfile
import unittest
from pathlib import Path

from actenon_scan.baseline import load_baseline
from actenon_scan.engine import scan_path
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


class InlineSuppressionScopeTests(unittest.TestCase):
    """An inline suppression covers the finding on its own line or the next
    line only — never every finding of that rule in the file."""

    SOURCE = (
        "import subprocess\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "\n"
        "@mcp.tool()\n"
        "def safe_version() -> str:\n"
        "    # actenon-scan: ignore[EXEC-SHELL]\n"
        "    return subprocess.run(['git', '--version']).stdout\n"
        "\n"
        "@mcp.tool()\n"
        "def run_anything(cmd: str) -> str:\n"
        "    return subprocess.run(cmd, shell=True).stdout\n"
    )

    def _scan(self, use_cache: bool):
        from actenon_scan.cache import FileCache
        from actenon_scan.suppress import collect_suppressions_from_file

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "agent.py").write_text(self.SOURCE)
            sups = collect_suppressions_from_file(root / "agent.py", root)
            cache = FileCache(Path(tmp) / "cache") if use_cache else None
            if cache is not None:
                scan_path(root, suppressions=sups, cache=cache)  # warm it
            result = scan_path(root, suppressions=sups, cache=cache)
            return {
                (f.line, f.suppressed)
                for f in result.findings
                if f.rule_id.startswith("EXEC-SHELL")
            }

    def test_suppression_does_not_cover_other_findings_of_the_same_rule(self):
        self.assertEqual({(8, True), (12, False)}, self._scan(use_cache=False))

    def test_suppression_scope_is_the_same_on_a_cache_hit(self):
        self.assertEqual({(8, True), (12, False)}, self._scan(use_cache=True))

    def test_trailing_comment_suppresses_its_own_line(self):
        from actenon_scan.suppress import is_suppressed

        sups = parse_suppressions(
            "x = 1\nsubprocess.run(c)  # actenon-scan: ignore[EXEC-SHELL]\n",
            "t.py",
        )
        self.assertTrue(is_suppressed(sups, "t.py", "EXEC-SHELL", 2))
        self.assertFalse(is_suppressed(sups, "t.py", "EXEC-SHELL", 4))
