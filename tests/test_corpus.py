"""Validation corpus tests.

For each rule, the corpus has:
  - vulnerable/*.py: files that MUST fire the rule (agent-reachable, unguarded)
  - safe/*.py: files that MUST NOT fire (guarded, non-agent-reachable, or read-only)

CI asserts both directions. This is what makes precision fixes safe —
if a matching change silently costs recall, the vulnerable fixtures fail.
If a matching change introduces false positives, the safe fixtures fail.
"""

import unittest
from pathlib import Path

from actenon_scan.engine import scan_path

CORPUS = Path(__file__).resolve().parent / "corpus"


def _scan(file_path: Path):
    """Scan a single file and return the list of non-suppressed findings.

    Also asserts that the scan produced NO analysis_errors. A safe fixture
    that crashes silently inside the per-file try/except wrapper would
    otherwise look identical to a correctly-suppressed fixture (both yield
    0 findings). The v0.2.2 crash snuck through exactly this way: the
    constructor_params branch AttributeError was swallowed, the safe
    fixture's "0 findings" assertion passed, and the bug shipped.
    """
    result = scan_path(file_path)
    assert result.analysis_errors == [], (
        f"{file_path.name} produced analysis_errors during scan — "
        f"this means part of the file was skipped due to a detector crash, "
        f"not correctly suppressed. Errors: {result.analysis_errors}"
    )
    return [f for f in result.findings if not f.suppressed]


class CorpusTests(unittest.TestCase):
    """Every vulnerable fixture must fire; every safe fixture must stay silent."""

    def test_corpus_directories_exist(self):
        """Sanity check: the corpus directory structure is in place."""
        self.assertTrue(CORPUS.exists(), f"corpus dir not found: {CORPUS}")
        rules = [d.name for d in CORPUS.iterdir() if d.is_dir()]
        self.assertGreater(len(rules), 0, "no rule directories in corpus")

    def _run_rule(self, rule_id: str):
        """Run all vulnerable + safe fixtures for a rule."""
        rule_dir = CORPUS / rule_id
        if not rule_dir.exists():
            self.skipTest(f"no corpus for {rule_id}")

        vuln_dir = rule_dir / "vulnerable"
        safe_dir = rule_dir / "safe"

        # Vulnerable files MUST fire
        if vuln_dir.exists():
            for fixture in sorted(vuln_dir.glob("*.py")):
                with self.subTest(rule=rule_id, fixture=fixture.name, expected="vulnerable"):
                    findings = _scan(fixture)
                    self.assertGreater(
                        len(findings), 0,
                        f"{fixture.name} should fire {rule_id} but produced 0 findings",
                    )

        # Safe files MUST NOT fire — UNLESS the file is testing severity
        # escalation (where a finding at the BASE severity is correct, but
        # escalation to high must NOT happen). These files are named
        # "hardcoded_*" and are asserted at medium, not zero.
        if safe_dir.exists():
            for fixture in sorted(safe_dir.glob("*.py")):
                with self.subTest(rule=rule_id, fixture=fixture.name, expected="safe"):
                    findings = _scan(fixture)
                    if fixture.name.startswith("hardcoded_"):
                        # These files should fire at the BASE severity (medium),
                        # never at the ESCALATED severity (high). This tests
                        # that the escalate_when gate works correctly.
                        for f in findings:
                            self.assertNotEqual(
                                f.severity, "high",
                                f"{fixture.name} should never escalate to high — "
                                f"got {f.severity} for {f.rule_id} at line {f.line}",
                            )
                    else:
                        self.assertEqual(
                            len(findings), 0,
                            f"{fixture.name} should NOT fire but produced {len(findings)} findings: "
                            f"{[(f.rule_id, f.line) for f in findings]}",
                        )

    # --- One test per rule ---

    def test_exec_code(self):
        self._run_rule("EXEC-CODE")

    def test_exec_shell(self):
        self._run_rule("EXEC-SHELL")

    def test_exec_container(self):
        self._run_rule("EXEC-CONTAINER")

    def test_browser_action(self):
        self._run_rule("BROWSER-ACTION")

    def test_file_write(self):
        self._run_rule("FILE-WRITE")

    def test_file_open_write(self):
        self._run_rule("FILE-OPEN-WRITE")

    def test_net_egress(self):
        self._run_rule("NET-EGRESS")

    def test_git_mutate(self):
        self._run_rule("GIT-MUTATE")

    def test_secret_read(self):
        self._run_rule("SECRET-READ")

    def test_declarative_guard(self):
        self._run_rule("DECLARATIVE-GUARD")


if __name__ == "__main__":
    unittest.main()
