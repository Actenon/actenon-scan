"""Regression: the all-guarded summary must not crash when unsupported files exist.

Before the fix, ``format_pretty`` called an undefined ``_format_unsupported``
whenever every capability had a recognised guard and the repository also held
a file in a language Scan does not parse, so ``actenon-scan scan .`` exited
with a NameError traceback for the best-guarded repositories.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan.capability import Capability
from actenon_scan.engine import ScanResult
from actenon_scan.report.pretty import format_pretty


def _guarded() -> Capability:
    return Capability(
        file="tools.py", line=3, col=1, rule_id="REPOSITORY-MUTATION", category="repository_mutation",
        severity="high", call_text="g.create_file(p)", state="GUARD_FOUND", guard_status="guarded",
    )


def test_all_guarded_with_unsupported_files_reports_them():
    result = ScanResult(capabilities=[_guarded()], files_scanned=1, unsupported_files=[("helper.rs", "Rust")])
    out = format_pretty(result)
    assert "1 file(s) NOT scanned" in out
    assert "{'Rust': 1}" in out
    assert "Other languages are not supported." in out


def test_all_guarded_with_missing_extra_suggests_it():
    result = ScanResult(capabilities=[_guarded()], files_scanned=1, unsupported_files=[("web/a.ts", "TypeScript")])
    out = format_pretty(result)
    assert 'pip install "actenon-scan[typescript]"' in out
