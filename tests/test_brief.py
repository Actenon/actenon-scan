"""Tests for the execution-boundary brief (Work Order 1, Part 6).

Covers:
- brief construction from a finding
- text and markdown formats
- required sections are present
- safety filter redacts credentials (RULE 9 + RULE 10)
- safety filter does not redact variable names
- remediation ordering (repository guard → framework approval → actenon proof)
- the mandatory "What this does NOT establish" limitation statement
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan.brief import (
    Brief,
    build_brief,
    format_brief_markdown,
    format_brief_text,
    _assert_safe,
    _redact_forbidden,
)


# A fixture with a PyGithub repository mutation finding.
# The finding (g.get_repo(repo).create_file(...)) is at line 9.
_PYGITHUB_FIXTURE = '''"""PyGithub create_file in an MCP tool."""
from github import Github
from mcp import tool

@tool()
def commit_file(repo: str, path: str, content: str, branch: str) -> None:
    """Agent-controlled GitHub file creation."""
    g = Github("token")
    g.get_repo(repo).create_file(path, "m", content, branch=branch)
'''

# Line number of the finding in _PYGITHUB_FIXTURE.
_PYGITHUB_FINDING_LINE = 9

# A fixture with a hardcoded credential value in the call text.
_CREDENTIAL_FIXTURE = '''"""Fixture with a hardcoded credential VALUE."""
from mcp import tool

@tool()
def send_email(to: str) -> None:
    """Agent-controlled email send with a hardcoded token."""
    import requests
    requests.post(
        "https://api.example.com/send",
        headers={"Authorization": "Bearer sk-1234567890abcdef1234567890abcdef"},
        json={"to": to},
    )
'''


class BriefConstructionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture_path = Path(self.tmpdir) / "fixture.py"
        self.fixture_path.write_text(_PYGITHUB_FIXTURE)

    def test_build_brief_returns_brief_for_valid_finding(self) -> None:
        # The finding is at line 10 (g.get_repo(repo).create_file(...)).
        brief = build_brief(str(self.fixture_path), _PYGITHUB_FINDING_LINE)
        self.assertIsNotNone(brief)
        self.assertEqual(brief.identity.rule_id, "REPOSITORY-MUTATION")

    def test_build_brief_returns_none_for_no_finding(self) -> None:
        brief = build_brief(str(self.fixture_path), 1)
        self.assertIsNone(brief)

    def test_brief_has_agent_entry_point(self) -> None:
        brief = build_brief(str(self.fixture_path), _PYGITHUB_FINDING_LINE)
        self.assertEqual(brief.agent_entry_point.function_name, "commit_file")
        self.assertIn("tool", brief.agent_entry_point.decorator)

    def test_brief_has_caller_controlled_parameters(self) -> None:
        brief = build_brief(str(self.fixture_path), _PYGITHUB_FINDING_LINE)
        param_names = {p.name for p in brief.caller_controlled_parameters}
        # path, content, branch should be identified as caller-controlled.
        self.assertIn("path", param_names)
        self.assertIn("content", param_names)
        self.assertIn("branch", param_names)

    def test_brief_has_receiver_chain(self) -> None:
        brief = build_brief(str(self.fixture_path), _PYGITHUB_FINDING_LINE)
        self.assertIsNotNone(brief.receiver_chain)
        self.assertEqual(brief.receiver_chain.confidence, "strong")


class BriefFormatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture_path = Path(self.tmpdir) / "fixture.py"
        self.fixture_path.write_text(_PYGITHUB_FIXTURE)
        self.brief = build_brief(str(self.fixture_path), _PYGITHUB_FINDING_LINE)

    def test_text_format_has_required_sections(self) -> None:
        text = format_brief_text(self.brief)
        for section in [
            "Repository / file / line",
            "Consequential action",
            "Agent entry point",
            "How the model reaches the operation",
            "Caller-controlled parameters",
            "Receiver and execution path",
            "Existing checks found",
            "Why those checks do or do not establish authority",
            "Data flow",
            "Expected boundary",
            "Minimal remediation options",
            "What this does NOT establish",
        ]:
            self.assertIn(section, text, f"Missing required section: {section}")

    def test_markdown_format_has_required_sections(self) -> None:
        md = format_brief_markdown(self.brief)
        for section in [
            "## Repository / file / line",
            "## Consequential action",
            "## Agent entry point",
            "## How the model reaches the operation",
            "## Caller-controlled parameters",
            "## Receiver and execution path",
            "## Existing checks found",
            "## Why those checks do or do not establish authority",
            "## Data flow",
            "## Expected boundary",
            "## Minimal remediation options",
            "## What this does NOT establish",
        ]:
            self.assertIn(section, md, f"Missing required markdown section: {section}")

    def test_remediation_ordering(self) -> None:
        """Part 6.4: repository guard → framework approval → actenon proof."""
        opts = self.brief.remediation_options
        self.assertEqual(len(opts), 3)
        self.assertEqual(opts[0].kind, "repository_guard")
        self.assertEqual(opts[1].kind, "framework_approval")
        self.assertEqual(opts[2].kind, "actenon_proof")
        self.assertEqual(opts[0].rank, 1)
        self.assertEqual(opts[1].rank, 2)
        self.assertEqual(opts[2].rank, 3)

    def test_mandatory_limitation_statement(self) -> None:
        """Part 6.3: every brief must state what the scan does NOT establish."""
        text = format_brief_text(self.brief)
        self.assertIn("What this does NOT establish", text)
        self.assertIn("did not establish", text)
        self.assertIn("externally reachable", text)
        self.assertIn("no guard exists elsewhere", text)
        self.assertIn("exploitation is practical", text)
        self.assertIn("irreversible", text)


class BriefSafetyTests(unittest.TestCase):
    """Part 6.6 + RULE 9 + RULE 10: briefs must never include credentials."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.cred_path = Path(self.tmpdir) / "cred.py"
        self.cred_path.write_text(_CREDENTIAL_FIXTURE)

    def test_brief_redacts_hardcoded_credentials(self) -> None:
        """A hardcoded Bearer token in the call text must be redacted."""
        brief = build_brief(str(self.cred_path), 8)
        self.assertIsNotNone(brief)
        text = format_brief_text(brief)
        # The credential value must NOT appear.
        self.assertNotIn("sk-1234567890abcdef", text)
        self.assertNotIn("1234567890abcdef1234567890abcdef", text)
        # The redaction marker should appear.
        self.assertIn("<redacted>", text)

    def test_brief_redacts_markdown_credentials(self) -> None:
        brief = build_brief(str(self.cred_path), 8)
        md = format_brief_markdown(brief)
        self.assertNotIn("sk-1234567890abcdef", md)
        self.assertIn("<redacted>", md)

    def test_assert_safe_raises_on_leaked_credential(self) -> None:
        """If a credential somehow survived redaction, _assert_safe raises."""
        with self.assertRaises(AssertionError):
            _assert_safe('api_key = "sk-leaked1234567890abcdef"')

    def test_redact_preserves_variable_name(self) -> None:
        """The variable NAME is preserved; only the VALUE is redacted."""
        redacted = _redact_forbidden('api_key = "sk-secret1234567890"')
        self.assertIn("api_key", redacted)
        self.assertIn("<redacted>", redacted)
        self.assertNotIn("sk-secret1234567890", redacted)

    def test_no_attack_prompts_in_brief(self) -> None:
        """Part 6.6 + RULE 9: briefs must not include attack material.

        The brief formatter does not add attack prompts, prompt-injection
        strings, or exploitation payloads. The call_text is reproduced
        verbatim from the source, so an attack prompt in the source would
        appear — but the brief itself never GENERATES attack material.
        This test confirms the remediation/limitation text is clean.
        """
        brief = build_brief(str(self.cred_path), 8)
        text = format_brief_text(brief)
        # The brief's own prose (not the reproduced call_text) must not
        # contain attack-instruction language.
        for forbidden in [
            "exploit payload",
            "prompt injection string",
            "attack prompt",
            "instructions for destructive use",
        ]:
            self.assertNotIn(
                forbidden, text.lower(),
                f"Brief prose contains forbidden phrase: {forbidden}",
            )


class BriefCliIntegrationTests(unittest.TestCase):
    """Integration test: `actenon-scan brief file:line` works end-to-end."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture_path = Path(self.tmpdir) / "fixture.py"
        self.fixture_path.write_text(_PYGITHUB_FIXTURE)

    def test_cli_brief_text(self) -> None:
        from actenon_scan.cli import main
        rc = main([
            "brief", f"{self.fixture_path}:{_PYGITHUB_FINDING_LINE}", "--format", "text",
        ])
        self.assertEqual(rc, 0)

    def test_cli_brief_markdown(self) -> None:
        from actenon_scan.cli import main
        rc = main([
            "brief", f"{self.fixture_path}:{_PYGITHUB_FINDING_LINE}", "--format", "markdown",
        ])
        self.assertEqual(rc, 0)

    def test_cli_brief_no_finding_returns_1(self) -> None:
        from actenon_scan.cli import main
        rc = main([
            "brief", f"{self.fixture_path}:1",
        ])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
