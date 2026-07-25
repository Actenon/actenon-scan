"""The coverage gate must reject each failure mode it was built for.

A gate that passes everything is worse than no gate, because it converts an
unchecked claim into a checked-looking one. These tests run the real checker
against deliberately broken copies of the repo.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]


class CoverageContractGateTests(unittest.TestCase):
    def _run_against(self, mutate) -> tuple[int, str]:
        """Copy the repo skeleton, mutate it, and run the real checker."""
        with TemporaryDirectory() as tmp:
            work = Path(tmp) / "repo"
            (work / "docs").mkdir(parents=True)
            (work / "scripts").mkdir(parents=True)
            (work / "tests" / "benchmark" / "recall").mkdir(parents=True)
            shutil.copy(ROOT / "docs" / "COVERAGE.md", work / "docs" / "COVERAGE.md")
            shutil.copy(
                ROOT / "scripts" / "check_coverage_contract.py",
                work / "scripts" / "check_coverage_contract.py",
            )
            for name in ("corpus-evidence.json", "baseline.json"):
                shutil.copy(ROOT / "tests" / "benchmark" / name,
                            work / "tests" / "benchmark" / name)
            for fx in (ROOT / "tests" / "benchmark" / "recall").glob("r*.py"):
                shutil.copy(fx, work / "tests" / "benchmark" / "recall" / fx.name)

            mutate(work)

            proc = subprocess.run(
                [sys.executable, str(work / "scripts" / "check_coverage_contract.py")],
                capture_output=True, text=True,
            )
            return proc.returncode, proc.stdout + proc.stderr

    def test_unmodified_repo_passes(self) -> None:
        code, out = self._run_against(lambda _: None)
        self.assertEqual(0, code, out)
        self.assertIn("3 COVERED", out)

    def test_covered_without_citation_fails(self) -> None:
        def mutate(work: Path) -> None:
            p = work / "docs" / "COVERAGE.md"
            p.write_text(p.read_text().replace(
                "| `r04` | Function-tool decorator — `@function_tool` | PARTIAL | - |",
                "| `r04` | Function-tool decorator — `@function_tool` | COVERED | - |",
            ))

        code, out = self._run_against(mutate)
        self.assertEqual(1, code, out)
        self.assertIn("cites no corpus evidence", out)

    def test_covered_citing_a_false_positive_entry_fails(self) -> None:
        def mutate(work: Path) -> None:
            p = work / "docs" / "COVERAGE.md"
            p.write_text(p.read_text().replace(
                "| `r04` | Function-tool decorator — `@function_tool` | PARTIAL | - |",
                "| `r04` | Function-tool decorator — `@function_tool` | COVERED | "
                "`r04_openai_function_tool` |",
            ))

        code, out = self._run_against(mutate)
        self.assertEqual(1, code, out)
        self.assertIn("false_positive", out)

    def test_covered_count_disagreeing_with_baseline_fails(self) -> None:
        def mutate(work: Path) -> None:
            p = work / "tests" / "benchmark" / "baseline.json"
            d = json.loads(p.read_text())
            d["recall_corpus"] = 2
            p.write_text(json.dumps(d, indent=2))

        code, out = self._run_against(mutate)
        self.assertEqual(1, code, out)
        self.assertIn("recall_corpus=2", out)


if __name__ == "__main__":
    unittest.main()
