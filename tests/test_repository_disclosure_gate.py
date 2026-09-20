"""CI gate: if the repository layer is ENABLED, its unfollowed count
MUST appear in scan output.

This gate enforces the principle "silence must never imply safety" for
the repository-level analysis layer. A resolver that resolves nothing
must say so — the user needs to know how many agent-reachable calls
were not followed so they can audit them manually.

The gate scans a small test directory (which triggers the repo layer
by default) and asserts that:
  1. ``repository_analysis_enabled == True`` in the JSON output
  2. ``transitive_unfollowed_count`` is present in the JSON output
  3. The pretty/text output contains the disclosure line

If the repo layer is DISABLED (--no-repository-analysis), the gate
asserts the disclosure line is OMITTED (backwards compat).
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from actenon_scan.engine import scan_path
from actenon_scan.report.blast_radius import transitive_disclosure_line
from actenon_scan.report.json_out import format_json
from actenon_scan.report.pretty import format_pretty, format_list
from actenon_scan.report.markdown_out import format_markdown
from actenon_scan.report.html_out import format_html
from actenon_scan.report.sarif import format_sarif


def _make_test_repo() -> str:
    """Create a small test repo with an agent entrypoint + helper."""
    tmp = tempfile.mkdtemp()
    Path(tmp, "agent.py").write_text(
        "from langchain.tools import tool\n"
        "import subprocess\n"
        "\n"
        "@tool\n"
        "def my_tool():\n"
        "    helper()\n"
        "\n"
        "def helper():\n"
        "    subprocess.run('ls', shell=True)\n",
        encoding="utf-8",
    )
    return tmp


class RepositoryDisclosureGateTests(unittest.TestCase):
    """Asserts the repo-layer unfollowed count appears in output."""

    def test_json_output_has_transitive_fields_when_enabled(self) -> None:
        """When repo layer is ENABLED, JSON output MUST include
        repository_analysis_enabled, transitive_followed_count, and
        transitive_unfollowed_count."""
        repo = _make_test_repo()
        result = scan_path(repo, cache=None)  # default: repo layer ON
        json_str = format_json(result)
        d = json.loads(json_str)
        self.assertTrue(
            d.get("repository_analysis_enabled", False),
            "repository_analysis_enabled must be True when repo layer runs",
        )
        self.assertIn(
            "transitive_followed_count", d,
            "transitive_followed_count must be present in JSON output",
        )
        self.assertIn(
            "transitive_unfollowed_count", d,
            "transitive_unfollowed_count must be present in JSON output",
        )

    def test_pretty_output_has_disclosure_line_when_enabled(self) -> None:
        """Pretty output MUST contain the disclosure line when repo
        layer is enabled — both in the clean-scan case and the
        findings case."""
        repo = _make_test_repo()
        result = scan_path(repo, cache=None)
        pretty = format_pretty(result)
        self.assertIn(
            "Repository analysis:", pretty,
            "Pretty output must contain 'Repository analysis:' disclosure line",
        )

    def test_list_output_has_disclosure_line_when_enabled(self) -> None:
        """List output MUST contain the disclosure line."""
        repo = _make_test_repo()
        result = scan_path(repo, cache=None)
        list_out = format_list(result)
        self.assertIn(
            "Repository analysis:", list_out,
            "List output must contain 'Repository analysis:' disclosure line",
        )

    def test_markdown_output_has_disclosure_when_enabled(self) -> None:
        """Markdown output MUST contain the disclosure line."""
        repo = _make_test_repo()
        result = scan_path(repo, cache=None)
        md = format_markdown(result)
        self.assertIn(
            "Repository analysis:", md,
            "Markdown output must contain disclosure line",
        )

    def test_html_output_has_disclosure_when_enabled(self) -> None:
        """HTML output MUST contain the disclosure line."""
        repo = _make_test_repo()
        result = scan_path(repo, cache=None)
        html = format_html(result)
        self.assertIn(
            "Repository analysis:", html,
            "HTML output must contain disclosure line",
        )

    def test_sarif_output_has_transitive_properties_when_enabled(self) -> None:
        """SARIF output MUST include transitive counts as driver
        properties AND as a run-level notification."""
        repo = _make_test_repo()
        result = scan_path(repo, cache=None)
        sarif_str = format_sarif(result)
        d = json.loads(sarif_str)
        driver = d["runs"][0]["tool"]["driver"]
        self.assertIn("properties", driver, "SARIF driver must have properties")
        props = driver["properties"]
        self.assertIn("repository_analysis_enabled", props)
        self.assertIn("transitive_followed_count", props)
        self.assertIn("transitive_unfollowed_count", props)
        # Also check the notification
        invocations = d["runs"][0].get("invocations", [])
        self.assertTrue(
            len(invocations) > 0,
            "SARIF run must have invocations with toolExecutionNotifications",
        )
        notifs = invocations[0].get("toolExecutionNotifications", [])
        self.assertTrue(
            len(notifs) > 0,
            "SARIF invocation must have toolExecutionNotifications",
        )
        notif_text = notifs[0]["message"]["text"]
        self.assertIn(
            "Repository analysis", notif_text,
            "SARIF notification must mention 'Repository analysis'",
        )

    def test_disclosure_omitted_when_repo_layer_disabled(self) -> None:
        """When repo layer is DISABLED (--no-repository-analysis), the
        disclosure line MUST be omitted (backwards compat)."""
        repo = _make_test_repo()
        result = scan_path(repo, cache=None, repository_analysis=False)
        self.assertFalse(
            result.repository_analysis_enabled,
            "repository_analysis_enabled must be False when disabled",
        )
        pretty = format_pretty(result)
        self.assertNotIn(
            "Repository analysis:", pretty,
            "Disclosure line must NOT appear when repo layer is disabled",
        )

    def test_disclosure_line_returns_none_when_disabled(self) -> None:
        """transitive_disclosure_line() returns None when the layer
        didn't run, so reporters can skip the line."""
        repo = _make_test_repo()
        result = scan_path(repo, cache=None, repository_analysis=False)
        self.assertIsNone(
            transitive_disclosure_line(result),
            "transitive_disclosure_line must return None when layer disabled",
        )


if __name__ == "__main__":
    unittest.main()
