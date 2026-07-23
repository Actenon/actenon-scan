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
    """Scan a single file and return the list of non-suppressed findings."""
    result = scan_path(file_path)
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

        # Safe files MUST NOT fire
        if safe_dir.exists():
            for fixture in sorted(safe_dir.glob("*.py")):
                with self.subTest(rule=rule_id, fixture=fixture.name, expected="safe"):
                    findings = _scan(fixture)
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


if __name__ == "__main__":
    unittest.main()
