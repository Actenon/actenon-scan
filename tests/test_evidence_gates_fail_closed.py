"""Evidence gates must fail closed: a gate that did not measure, or measured less, must not pass.

Independent audit findings reproduced and pinned here:
- check_corpus_triage.py turned a scanner exception into "0 findings";
- it rejected new untriaged findings but not triaged TRUE_POSITIVEs that disappeared;
- it never noticed a pinned repository with no result, or files that failed to analyse;
- its control-repository check compared short names to owner/name keys, so it never ran on
  committed results, and re-measured findings were keyed by short name (all "untriaged");
- it accepted one finding triaged twice (TRUE_POSITIVE and FALSE_POSITIVE), which double-counted;
- check_benchmark_integrity.py --check only warned on a fixture-lock mismatch;
- check_perf_gate.py printed SKIP and exited 0 when its fixture was missing;
- generate_corpus_study.py stated "Zero false positives" while the triage recorded one.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


triage_gate = _load("check_corpus_triage")
integrity = _load("check_benchmark_integrity")
perf_gate = _load("check_perf_gate")
study = _load("generate_corpus_study")

AGENT = {"repo": "acme/agent", "name": "agent", "category": "application", "sha": "a" * 40}
CONTROL = {"repo": "acme/lib", "name": "lib", "category": "control", "sha": "b" * 40}
TP = {"repo": "acme/agent", "file": "tools.py", "line": 10, "rule_id": "PAY-STRIPE-REFUND",
      "verdict": "TRUE_POSITIVE"}
FINDING = {"repo": "acme/agent", "file": "tools.py", "line": 10, "rule_id": "PAY-STRIPE-REFUND"}


def _pinned(*repos):
    return {"repos": list(repos)}


def _results(repos: dict, findings: list):
    return {"repos": repos, "findings": findings}


def _measured(**extra):
    return {"findings": 1, "category": "application", "sha": "a" * 40, **extra}


# -- check_corpus_triage: the four fail-open paths --------------------------------------------------


def test_disappearing_true_positive_fails_the_gate():
    """The audit's reproduction: a recorded TRUE_POSITIVE whose scan output is now empty."""
    problems = triage_gate.check_triage(
        {"entries": [TP]},
        _results({"acme/agent": _measured(findings=0)}, []),
        _pinned(AGENT),
    )
    assert any(p.startswith("MISSING TRUE POSITIVE") for p in problems), problems


def test_scanner_exception_is_a_failure_not_zero_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(triage_gate, "_clone_repo", lambda _full, _sha, dest: dest.mkdir() or True)

    def crash(*_a, **_k):
        raise RuntimeError("parser crashed")

    monkeypatch.setattr("actenon_scan.engine.scan_path", crash)
    results = triage_gate.remeasure_corpus(_pinned(AGENT), tmp_path)
    assert results["repos"]["acme/agent"]["error"] == "scan_failed"
    assert "parser crashed" in results["repos"]["acme/agent"]["detail"]
    problems = triage_gate.check_triage({"entries": [TP]}, results, _pinned(AGENT))
    assert any(p.startswith("NOT MEASURED: acme/agent scan_failed") for p in problems), problems


def test_pinned_repository_without_a_result_fails():
    problems = triage_gate.check_triage({"entries": []}, _results({}, []), _pinned(AGENT, CONTROL))
    assert "NOT MEASURED: acme/agent is pinned but has no result." in problems
    assert "NOT MEASURED: acme/lib is pinned but has no result." in problems


def test_incomplete_coverage_fails_unless_explicitly_accepted():
    results = _results({"acme/agent": _measured(analysis_errors=2, analysis_error_files=["a.py", "b.py"])},
                       [FINDING])
    problems = triage_gate.check_triage({"entries": [TP]}, results, _pinned(AGENT))
    assert any(p.startswith("INCOMPLETE COVERAGE: acme/agent had 2") for p in problems), problems
    accepted = {**AGENT, "accepted_analysis_errors": 2, "accepted_analysis_errors_reason": "py2 vendored files"}
    assert triage_gate.check_triage({"entries": [TP]}, results, _pinned(accepted)) == []


# -- check_corpus_triage: identity and consistency -------------------------------------------------


def test_control_repository_finding_fails_on_owner_name_keys():
    """Committed results key repos by owner/name; the check used short names and never ran."""
    results = _results({"acme/agent": _measured(findings=0), "acme/lib": {"findings": 1, "category": "control"}}, [])
    problems = triage_gate.check_triage({"entries": []}, results, _pinned(AGENT, CONTROL))
    assert any(p.startswith("CONTROL REPO FINDING: acme/lib") for p in problems), problems


def test_remeasured_findings_use_the_same_identity_as_triage(monkeypatch, tmp_path):
    monkeypatch.setattr(triage_gate, "_clone_repo", lambda _full, _sha, dest: dest.mkdir() or True)
    monkeypatch.setattr(triage_gate, "_scan_repo", lambda _path: ([dict(FINDING, repo=None)], []))
    results = triage_gate.remeasure_corpus(_pinned(AGENT), tmp_path)
    assert set(results["repos"]) == {"acme/agent"}
    assert results["findings"][0]["repo"] == "acme/agent"
    assert results["repos"]["acme/agent"]["analysis_errors"] == 0
    assert triage_gate.check_triage({"entries": [TP]}, results, _pinned(AGENT)) == []


def test_one_finding_triaged_twice_fails():
    fp = {**TP, "verdict": "FALSE_POSITIVE", "status": "recorded", "recorded_date": "2026-07-29",
          "tracking_issue": 81, "rationale": "not a tool handler"}
    problems = triage_gate.check_triage(
        {"entries": [TP, fp]}, _results({"acme/agent": _measured()}, [FINDING]), _pinned(AGENT)
    )
    assert any(p.startswith("CONFLICTING TRIAGE: acme/agent tools.py:10") for p in problems), problems


def test_totals_that_disagree_with_entries_fail():
    problems = triage_gate.check_triage(
        {"entries": [TP], "totals": {"findings": 2, "true_positives": 2, "false_positives": 0}},
        _results({"acme/agent": _measured()}, [FINDING]),
        _pinned(AGENT),
    )
    assert "TOTALS MISMATCH: corpus-triage.json totals.findings is 2, but the entries give 1." in problems


def test_recorded_false_positive_that_stopped_firing_is_flagged():
    fp = {**TP, "verdict": "FALSE_POSITIVE", "status": "recorded", "recorded_date": "2026-07-29",
          "tracking_issue": 81, "rationale": "x"}
    problems = triage_gate.check_triage(
        {"entries": [fp]}, _results({"acme/agent": _measured(findings=0)}, []), _pinned(AGENT)
    )
    assert any(p.startswith("STALE RECORDED FALSE POSITIVE") for p in problems), problems


def test_committed_corpus_data_is_consistent():
    """The repository's own triage, results and pins satisfy every check above."""
    bench = ROOT / "tests" / "benchmark"
    triage = json.loads((bench / "corpus-triage.json").read_text())
    results = json.loads((bench / "corpus-results.json").read_text())
    pinned = json.loads((bench / "pinned_repos.json").read_text())
    assert triage_gate.check_triage(triage, results, pinned) == []


# -- check_benchmark_integrity: the lock is blocking under --check ----------------------------------


def test_fixture_lock_mismatch_fails_under_check(monkeypatch, tmp_path, capsys):
    bench = tmp_path / "tests" / "benchmark"
    bench.mkdir(parents=True)
    (bench / "fixture.py").write_text("x = 1\n")
    monkeypatch.setattr(integrity, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(integrity, "BENCHMARK_DIR", bench)
    monkeypatch.setattr(integrity, "FIXTURE_LOCK", bench / "fixture-lock.json")
    integrity.update_fixture_lock()
    (bench / "fixture.py").write_text("x = 2\n")  # evidence changed, lock not updated
    monkeypatch.setattr(sys, "argv", ["check_benchmark_integrity.py", "--check"])
    assert integrity.main() == 1
    assert "FAIL: benchmark fixtures have changed" in capsys.readouterr().out


def test_fixture_lock_in_sync_passes_the_lock_check(monkeypatch, tmp_path):
    bench = tmp_path / "tests" / "benchmark"
    bench.mkdir(parents=True)
    (bench / "fixture.py").write_text("x = 1\n")
    monkeypatch.setattr(integrity, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(integrity, "BENCHMARK_DIR", bench)
    monkeypatch.setattr(integrity, "FIXTURE_LOCK", bench / "fixture-lock.json")
    integrity.update_fixture_lock()
    assert integrity.check_fixture_lock() == (True, [])


def test_repository_fixture_lock_is_in_sync():
    assert integrity.check_fixture_lock() == (True, [])


# -- check_perf_gate: nothing measured is a failure -------------------------------------------------


def test_perf_gate_fails_when_the_fixture_is_missing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", ["check_perf_gate.py", "--fixture", str(tmp_path / "absent")])
    assert perf_gate.main() == 2
    assert "FAIL: fixture not present" in capsys.readouterr().err


def test_perf_gate_fails_when_the_fixture_has_no_files(monkeypatch, tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(sys, "argv", ["check_perf_gate.py", "--fixture", str(empty)])
    assert perf_gate.main() == 2
    assert "contains no scannable files" in capsys.readouterr().err


# -- generate_corpus_study: statements come from the data -------------------------------------------


def test_study_never_claims_zero_false_positives_when_one_is_recorded():
    fp = {**TP, "line": 11, "verdict": "FALSE_POSITIVE", "status": "recorded", "tracking_issue": 81,
          "rationale": "not a tool handler"}
    text = "\n".join(study.current_measurement_lines([TP, fp]))
    assert "### Current measurement: 1/2 (50.0% precision)" in text
    assert "1 FALSE_POSITIVE (1 recorded and unfixed, 0 fixed)" in text
    assert "tracking issue #81" in text
    for overclaim in ("Zero false positives", "stayed at zero", "all hand-triaged as TRUE_POSITIVE"):
        assert overclaim not in text


def test_study_says_all_true_positives_only_when_true():
    text = "\n".join(study.current_measurement_lines([TP]))
    assert "1 findings, all hand-triaged TRUE_POSITIVE" in text


def test_published_study_matches_the_triage_data():
    triage = json.loads((ROOT / "tests" / "benchmark" / "corpus-triage.json").read_text())
    entries = triage["entries"]
    tp = sum(1 for e in entries if e["verdict"] == "TRUE_POSITIVE")
    fp = sum(1 for e in entries if e["verdict"] == "FALSE_POSITIVE")
    published = (ROOT / "docs" / "CORPUS_STUDY.md").read_text()
    assert f"### Current measurement: {tp}/{tp + fp} " in published
    if fp:
        assert "Zero false positives" not in published
