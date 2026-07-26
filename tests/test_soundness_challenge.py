"""Test runner for soundness challenge fixtures.

Each challenge fixture is a source file + a metadata YAML in
tests/challenge/CHALLENGE-*. The metadata specifies:
  - expected: "finding" (should be flagged) or "clean" (should NOT be flagged)
  - status: "open" (unfixed — expected to fail) or "fixed" (expected to pass)
  - rule_id: the expected rule ID (if finding)

For OPEN cases (unfixed misses), the test is marked xfail — it's
expected to fail, and the test suite cannot disagree with the scoreboard.
When the scanner is fixed, the test starts passing and the fixture's
status is updated to "fixed".

For FIXED cases, the test must pass — if it fails, the scanner regressed.

This is the mechanism that makes the scoreboard's open-miss list and
the test suite agree: an open miss is an xfail test, not a missing test.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

# Skip the entire module if pyyaml is not installed (Base install CI job).
try:
    import yaml
except ImportError:
    pytestmark = pytest.mark.skip(reason="pyyaml not installed — required for challenge fixture metadata")
else:
    # Skip if tree-sitter-go is not installed (for Go challenge fixtures)
    from actenon_scan.detectors.go import is_go_extra_available

    CHALLENGE_DIR = Path(__file__).parent / "challenge"

    def _load_challenge_cases():
        """Load all challenge cases: (case_id, metadata, source_file)."""
        cases = []
        for yml_file in sorted(CHALLENGE_DIR.glob("CHALLENGE-*.yml")):
            with open(yml_file) as f:
                metadata = yaml.safe_load(f)
            case_id = yml_file.stem
            source_file = None
            for ext in (".py", ".go", ".ts", ".tsx", ".js", ".jsx"):
                candidate = CHALLENGE_DIR / f"{case_id}{ext}"
                if candidate.exists():
                    source_file = candidate
                    break
            if source_file is None:
                continue
            cases.append((case_id, metadata, source_file))
        return cases

    def _should_skip(metadata):
        """Return a skip reason if the case should be skipped, else None."""
        language = metadata.get("language", "").lower()
        if language == "go" and not is_go_extra_available():
            return "[go] extra not installed — tree-sitter-go required"
        if language == "typescript" and not _is_ts_extra_available():
            return "[typescript] extra not installed"
        return None

    def _is_ts_extra_available():
        try:
            import tree_sitter_typescript  # noqa: F401
            return True
        except ImportError:
            return False

    _CASES = _load_challenge_cases()

    def _test_challenge(case_id, metadata, source_file):
        """Run the scanner on a challenge fixture and check the result."""
        from actenon_scan.engine import scan_path

        result = scan_path(source_file)
        findings = [f for f in result.findings if not f.suppressed]

        expected = metadata.get("expected", "")
        expected_rule = metadata.get("rule_id", "")
        status = metadata.get("status", "")

        if expected == "clean":
            assert len(findings) == 0, (
                f"Challenge {case_id}: expected CLEAN but got {len(findings)} finding(s): "
                f"{[(f.rule_id, f.line) for f in findings]}"
            )
        elif expected == "finding":
            if expected_rule:
                matching = [f for f in findings if f.rule_id == expected_rule]
                if status == "open":
                    if matching:
                        pytest.xfail(
                            f"Challenge {case_id}: scanner now detects {expected_rule} — "
                            f"update status to 'fixed' in the metadata"
                        )
                    assert not matching, (
                        f"Challenge {case_id}: scanner found {expected_rule} — "
                        f"this open miss may be fixed. Update the metadata."
                    )
                else:
                    assert matching, (
                        f"Challenge {case_id}: expected {expected_rule} but got "
                        f"{[f.rule_id for f in findings]}"
                    )
            else:
                if status == "open":
                    if findings:
                        pytest.xfail(
                            f"Challenge {case_id}: scanner now finds something — "
                            f"update status to 'fixed'"
                        )
                    assert len(findings) == 0, (
                        f"Challenge {case_id}: scanner found findings — "
                        f"this open miss may be fixed."
                    )
                else:
                    assert len(findings) > 0, (
                        f"Challenge {case_id}: expected at least one finding but got none"
                    )

    # Generate parametrized tests
    for _case_id, _metadata, _source_file in _CASES:
        _skip_reason = _should_skip(_metadata)
        _status = _metadata.get("status", "")
        _xfail = _status == "open"

        def _make_test(cid, meta, src, skip_reason, xfail):
            def test_func():
                if skip_reason:
                    pytest.skip(skip_reason)
                if xfail:
                    pytest.xfail(f"Open challenge case — not yet fixed (see scoreboard)")
                _test_challenge(cid, meta, src)
            test_func.__name__ = f"test_challenge_{cid.lower()}"
            return test_func

        _test_func = _make_test(_case_id, _metadata, _source_file, _skip_reason, _xfail)
        globals()[_test_func.__name__] = _test_func
