"""Corpus completeness gate.

Every sink rule MUST have a directory tests/corpus/<RULE-ID>/ containing
at least 3 files under vulnerable/ and at least 3 under safe/.

This test fails if any rule lacks its directories or minimum file counts.
This prevents new rules from being merged without fixtures — the lesson
from v0.2.0 where 9 rules shipped without safe fixtures and precision
collapsed to ~1.5%.
"""

import unittest
from pathlib import Path

from actenon_scan.rules.loader import load_rules

CORPUS = Path(__file__).resolve().parent / "corpus"
MIN_VULNERABLE = 3
MIN_SAFE = 3


class CorpusCompletenessTests(unittest.TestCase):
    """Every rule must have a complete corpus with fixtures in both directions."""

    def test_every_rule_has_corpus_directory(self):
        """Every sink rule must have a tests/corpus/<RULE-ID>/ directory."""
        rules = load_rules()
        missing = []
        for rule in rules.sinks:
            rule_dir = CORPUS / rule.id
            if not rule_dir.exists():
                missing.append(rule.id)
        self.assertEqual(
            missing, [],
            f"Rules without corpus directories: {missing}. "
            f"Every rule must have tests/corpus/<RULE-ID>/ with vulnerable/ and safe/ fixtures."
        )

    def test_every_rule_has_min_vulnerable_fixtures(self):
        """Every rule must have at least 3 vulnerable fixtures."""
        rules = load_rules()
        insufficient = []
        for rule in rules.sinks:
            vuln_dir = CORPUS / rule.id / "vulnerable"
            if not vuln_dir.exists():
                insufficient.append(f"{rule.id} (no vulnerable/ dir)")
            else:
                count = len(list(vuln_dir.glob("*.py")))
                if count < MIN_VULNERABLE:
                    insufficient.append(f"{rule.id} ({count} files, need {MIN_VULNERABLE})")
        self.assertEqual(
            insufficient, [],
            f"Rules with insufficient vulnerable fixtures: {insufficient}. "
            f"Each rule needs at least {MIN_VULNERABLE} vulnerable fixtures."
        )

    def test_every_rule_has_min_safe_fixtures(self):
        """Every rule must have at least 3 safe fixtures."""
        rules = load_rules()
        insufficient = []
        for rule in rules.sinks:
            safe_dir = CORPUS / rule.id / "safe"
            if not safe_dir.exists():
                insufficient.append(f"{rule.id} (no safe/ dir)")
            else:
                count = len(list(safe_dir.glob("*.py")))
                if count < MIN_SAFE:
                    insufficient.append(f"{rule.id} ({count} files, need {MIN_SAFE})")
        self.assertEqual(
            insufficient, [],
            f"Rules with insufficient safe fixtures: {insufficient}. "
            f"Each rule needs at least {MIN_SAFE} safe fixtures."
        )

    def test_global_safe_fixtures_exist(self):
        """The _global_safe/ directory must exist with the v0.2.0 collision fixtures."""
        global_safe = CORPUS / "_global_safe"
        if not global_safe.exists():
            self.skipTest("_global_safe/ not yet created")
        files = list(global_safe.glob("*.py"))
        self.assertGreater(
            len(files), 0,
            "_global_safe/ must contain at least the v0.2.0 collision fixtures"
        )

    def test_global_safe_fixtures_produce_zero_findings(self):
        """The _global_safe/ collision fixtures must produce ZERO findings.

        These are the v0.2.0 false-positive patterns (asyncio.run, re.compile,
        str.replace, os.path.join().replace(), requests.get) that must never
        fire. If any of these produce a finding, a matching regression has
        been introduced.
        """
        from actenon_scan.engine import scan_path
        global_safe = CORPUS / "_global_safe"
        if not global_safe.exists():
            self.skipTest("_global_safe/ not yet created")

        for fixture in sorted(global_safe.glob("*.py")):
            with self.subTest(fixture=fixture.name):
                result = scan_path(fixture)
                active_findings = [f for f in result.findings if not f.suppressed]
                self.assertEqual(
                    len(active_findings), 0,
                    f"{fixture.name} must produce 0 findings but got "
                    f"{len(active_findings)}: {[(f.rule_id, f.line) for f in active_findings]}"
                )


if __name__ == "__main__":
    unittest.main()
