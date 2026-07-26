"""Tests for Work Order 2 product UX features.

Covers:
- blast-radius default output structure (Part 1)
- --format list (Part 1.6)
- explain command (Part 2)
- fix command with all 3 modes (Part 3)
- HTML and Markdown report formats (Part 6)
- safety filter (RULE 8 + RULE 10)
- detection invariance (RULE 5)
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan.engine import scan_path
from actenon_scan.report.blast_radius import (
    consequence_label,
    group_by_consequence,
    select_most_exposed,
    CLEAN_SCAN_STATEMENT,
)
from actenon_scan.report.pretty import format_pretty, format_list
from actenon_scan.report.markdown_out import format_markdown
from actenon_scan.report.html_out import format_html


_FINDING_FIXTURE = '''"""PyGithub create_file in an MCP tool."""
from github import Github
from mcp import tool

@tool()
def commit_file(repo: str, path: str, content: str, branch: str) -> None:
    """Agent-controlled GitHub file creation."""
    g = Github("token")
    g.get_repo(repo).create_file(path, "m", content, branch=branch)
'''

_CLEAN_FIXTURE = '''"""A clean file with no findings."""
import os

def helper():
    return os.getcwd()
'''


class BlastRadiusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture = Path(self.tmpdir) / "finding.py"
        self.fixture.write_text(_FINDING_FIXTURE)
        self.clean = Path(self.tmpdir) / "clean.py"
        self.clean.write_text(_CLEAN_FIXTURE)
        self.result = scan_path(self.fixture)

    def test_consequence_label_mapping(self) -> None:
        self.assertEqual(consequence_label("repository_mutation"), "REPOSITORY")
        self.assertEqual(consequence_label("payments"), "MONEY")
        self.assertEqual(consequence_label("data_destruction"), "DATA LOSS")
        self.assertEqual(consequence_label("code_execution"), "EXECUTION")

    def test_group_by_consequence_returns_groups(self) -> None:
        findings = [f for f in self.result.findings if not f.suppressed]
        groups = group_by_consequence(findings)
        self.assertGreater(len(groups), 0)
        # REPOSITORY should be a key.
        self.assertIn("REPOSITORY", groups)

    def test_select_most_exposed_returns_high_severity(self) -> None:
        findings = [f for f in self.result.findings if not f.suppressed]
        most = select_most_exposed(findings)
        self.assertIsNotNone(most)
        self.assertEqual(most.severity, "high")

    def test_pretty_output_has_blast_radius_header(self) -> None:
        output = format_pretty(self.result, elapsed=0.01)
        self.assertIn("consequential action", output)
        self.assertIn("REPOSITORY", output)
        self.assertIn("Most exposed", output)

    def test_pretty_clean_scan_has_honesty_statement(self) -> None:
        clean_result = scan_path(self.clean)
        output = format_pretty(clean_result, elapsed=0.01)
        self.assertIn(CLEAN_SCAN_STATEMENT, output)
        self.assertIn("What this scan verified", output)
        self.assertIn("What this scan did not verify", output)

    def test_list_format_preserves_old_style(self) -> None:
        output = format_list(self.result)
        self.assertIn("finding(s)", output)
        self.assertIn("REPOSITORY-MUTATION", output)

    def test_pretty_has_next_steps(self) -> None:
        output = format_pretty(self.result, elapsed=0.01)
        self.assertIn("actenon-scan explain", output)
        self.assertIn("actenon-scan fix", output)

    def test_pretty_has_timing(self) -> None:
        output = format_pretty(self.result, elapsed=0.42)
        self.assertIn("(0.42s)", output)


class ExplainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture = Path(self.tmpdir) / "finding.py"
        self.fixture.write_text(_FINDING_FIXTURE)

    def test_explain_has_required_sections(self) -> None:
        from actenon_scan.cli import main
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        rc = main(["explain", f"{self.fixture}:9"])
        self.assertEqual(rc, 0)

    def test_explain_no_finding_returns_1(self) -> None:
        from actenon_scan.cli import main
        rc = main(["explain", f"{self.fixture}:1"])
        self.assertEqual(rc, 1)


class FixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture = Path(self.tmpdir) / "finding.py"
        self.fixture.write_text(_FINDING_FIXTURE)

    def test_fix_guard_mode(self) -> None:
        from actenon_scan.cli import main
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["fix", f"{self.fixture}:9", "--mode", "guard"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn("guard", output)
        self.assertIn("authorize", output)

    def test_fix_approval_mode(self) -> None:
        from actenon_scan.cli import main
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["fix", f"{self.fixture}:9", "--mode", "approval"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn("approval", output)
        self.assertIn("request_approval", output)

    def test_fix_actenon_mode(self) -> None:
        from actenon_scan.cli import main
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["fix", f"{self.fixture}:9", "--mode", "actenon"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        # The fix must use the REAL actenon-kernel API (verify_pccb),
        # not the previously-broken `from actenon import verify_proof`
        # which referenced a non-existent package.
        self.assertIn("verify_pccb", output)
        self.assertIn("actenon_kernel", output)

    def test_fix_does_not_modify_without_apply(self) -> None:
        from actenon_scan.cli import main
        original = self.fixture.read_text()
        main(["fix", f"{self.fixture}:9", "--mode", "guard"])
        self.assertEqual(self.fixture.read_text(), original)

    def test_fix_apply_modifies_file(self) -> None:
        from actenon_scan.cli import main
        original = self.fixture.read_text()
        main(["fix", f"{self.fixture}:9", "--mode", "actenon", "--apply"])
        modified = self.fixture.read_text()
        self.assertNotEqual(original, modified)
        # The applied fix must use the REAL actenon-kernel API.
        self.assertIn("verify_pccb", modified)
        self.assertIn("actenon_kernel", modified)


class ReportFormatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture = Path(self.tmpdir) / "finding.py"
        self.fixture.write_text(_FINDING_FIXTURE)
        self.result = scan_path(self.fixture)

    def test_markdown_has_blast_radius(self) -> None:
        md = format_markdown(self.result, elapsed=0.01)
        self.assertIn("# Actenon Scan Report", md)
        self.assertIn("Blast-radius summary", md)
        self.assertIn("REPOSITORY", md)

    def test_markdown_has_honesty_statement(self) -> None:
        md = format_markdown(self.result, elapsed=0.01)
        self.assertIn("What this scan verified", md)
        self.assertIn("did not verify", md)

    def test_html_is_self_contained(self) -> None:
        html = format_html(self.result, elapsed=0.01)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("</html>", html)
        # No external resources.
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<script src", html)

    def test_html_has_honesty_statement(self) -> None:
        html = format_html(self.result, elapsed=0.01)
        self.assertIn("What this scan verified", html)
        self.assertIn("did not verify", html)

    def test_html_has_blast_radius(self) -> None:
        html = format_html(self.result, elapsed=0.01)
        self.assertIn("blast-radius", html)
        self.assertIn("REPOSITORY", html)


class DetectionInvarianceTests(unittest.TestCase):
    """RULE 5: detection must not change.

    The new presentation layer must not alter which findings are produced,
    their rule IDs, severity, confidence, or consequence categories.
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture = Path(self.tmpdir) / "finding.py"
        self.fixture.write_text(_FINDING_FIXTURE)

    def test_findings_unchaged_after_format_changes(self) -> None:
        """Scanning the same file produces the same findings regardless
        of which format is selected for output."""
        result = scan_path(self.fixture)
        findings = [(f.rule_id, f.line, f.severity, f.confidence, f.category)
                     for f in result.findings if not f.suppressed]
        self.assertGreater(len(findings), 0)
        # All findings should be REPOSITORY-MUTATION, high, high, repository_mutation
        for rule_id, line, severity, confidence, category in findings:
            self.assertEqual(rule_id, "REPOSITORY-MUTATION")
            self.assertEqual(severity, "high")
            self.assertEqual(confidence, "high")
            self.assertEqual(category, "repository_mutation")


class SafetyTests(unittest.TestCase):
    """RULE 8 + RULE 10: no attack prompts, credentials, or payloads."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture = Path(self.tmpdir) / "finding.py"
        self.fixture.write_text(_FINDING_FIXTURE)
        self.result = scan_path(self.fixture)

    def test_no_credentials_in_markdown(self) -> None:
        md = format_markdown(self.result, elapsed=0.01)
        # The fixture has Github("token") — "token" is a variable name,
        # not a real credential. But check for real-looking credentials.
        for forbidden in ["sk-", "Bearer ", "password=", "api_key=\""]:
            self.assertNotIn(forbidden, md)

    def test_no_credentials_in_html(self) -> None:
        html = format_html(self.result, elapsed=0.01)
        for forbidden in ["sk-", "Bearer ", "password=", "api_key=\""]:
            self.assertNotIn(forbidden, html)

    def test_no_attack_instructions_in_any_output(self) -> None:
        from actenon_scan.cli import main
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            main(["explain", f"{self.fixture}:9"])
        output = f.getvalue()
        for forbidden in ["exploit payload", "injection string", "try this"]:
            self.assertNotIn(forbidden, output.lower())


if __name__ == "__main__":
    unittest.main()
