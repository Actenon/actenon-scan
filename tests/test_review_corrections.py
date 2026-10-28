"""Regression tests for F09 (remediation scaffold status) and R2/F06 (structured version waiver)."""

from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path
import sys
import textwrap

from packaging.version import Version
import pytest

from actenon_scan.fix import generate_fix


def _load_coherence_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "check_version_coherence.py"
    spec = importlib.util.spec_from_file_location("check_version_coherence_scan", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_guard_and_approval_scaffolds_never_claim_applied_or_enforced(tmp_path: Path) -> None:
    """F09: Commented-out guard/approval scaffolds must never report applied=True or enforced=True."""
    for mode in ("guard", "approval"):
        src = tmp_path / f"tool_{mode}.py"
        src.write_text(
            textwrap.dedent(
                """\
                import subprocess
                from mcp import tool

                @tool
                def run(cmd: str) -> str:
                    return subprocess.run(cmd, shell=True).stdout.decode()
                """
            ),
            encoding="utf-8",
        )
        lines = src.read_text(encoding="utf-8").splitlines()
        finding_line = next(i + 1 for i, l in enumerate(lines) if "subprocess.run" in l)

        res = generate_fix(src, finding_line, mode=mode, apply=True)
        assert res is not None
        assert res.applied is False
        assert res.enforced is False
        assert res.status == "scaffold"
        assert "NOT ENFORCED" in res.note


def test_actenon_fix_mode_passes_explicit_proof_and_intent_args(tmp_path: Path) -> None:
    """F09: actenon mode must pass active proof=... and intent=... arguments (not commented out)."""
    src = tmp_path / "tool_actenon.py"
    src.write_text(
        textwrap.dedent(
            """\
            import subprocess
            from mcp import tool

            @tool
            def run(cmd: str) -> str:
                return subprocess.run(cmd, shell=True).stdout.decode()
            """
        ),
        encoding="utf-8",
    )
    lines = src.read_text(encoding="utf-8").splitlines()
    finding_line = next(i + 1 for i, l in enumerate(lines) if "subprocess.run" in l)

    res = generate_fix(src, finding_line, mode="actenon", apply=True)
    assert res is not None
    assert res.applied is True
    assert res.enforced is True
    assert res.status == "applied"
    assert "proof=locals().get(\"pccb\")" in res.diff
    assert "intent=locals().get(\"intent\")" in res.diff
    assert "# proof=" not in res.diff


def test_scan_version_waiver_rejects_prose_and_requires_structured_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _load_coherence_module()
    bad_findings = tmp_path / "FINDINGS.md"
    bad_findings.write_text("# FINDINGS\nDo not publish 1.6.0 or 11.6.0.\n", encoding="utf-8")

    ok, _ = mod.validate_staged_candidate_waiver(
        "actenon-scan",
        Version("1.6.0"),
        Version("1.5.0"),
        findings_path=bad_findings,
        today=date(2026, 10, 28),
    )
    assert ok is False

    repo_root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(repo_root)
    monkeypatch.setattr(mod, "pypi_latest", lambda _pkg: Version("1.5.0"))
    monkeypatch.setattr(mod, "newest_release_tag", lambda: Version("1.5.0"))
    monkeypatch.setattr(mod, "version_bump_age_seconds", lambda _v: 20 * 86400)
    assert mod.main(["--mode", "main"]) == 0
    assert mod.main(["--mode", "release"]) == 1
