"""Tests for agent-reach-grade onboarding, SKILL.md management, doctor, pre-commit, and CLI shorthand."""

from __future__ import annotations

import json
import stat
import sys
import textwrap
from pathlib import Path

import pytest

from actenon_scan.cli import main as cli_main
from actenon_scan.onboarding import (
    collect_doctor_report,
    install_and_link_skill,
    install_pre_commit,
    skill_status,
    uninstall_skill,
)
from actenon_scan.skill import SKILL_MARKER, get_skill_markdown

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_embedded_skill_and_docs_exist() -> None:
    skill_md = get_skill_markdown()
    assert "name: actenon-scan" in skill_md
    assert SKILL_MARKER in skill_md
    assert "Authentication and validation are NOT action authorization" in skill_md

    install_doc = REPO_ROOT / "docs" / "install.md"
    llms_txt = REPO_ROOT / "llms.txt"
    assert install_doc.is_file()
    assert "actenon-scan setup" in install_doc.read_text(encoding="utf-8")
    assert llms_txt.is_file()
    assert "docs/install.md" in llms_txt.read_text(encoding="utf-8")


def test_skill_setup_links_detected_harnesses_and_preserves_foreign_files(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    # Simulate Claude Code, Antigravity, and Cursor installed on the machine.
    (fake_home / ".claude").mkdir()
    (fake_home / ".gemini" / "antigravity").mkdir(parents=True)
    cursor_foreign = fake_home / ".cursor" / "skills" / "actenon-scan"
    cursor_foreign.mkdir(parents=True)
    (cursor_foreign / "SKILL.md").write_text("# User custom foreign skill\n", encoding="utf-8")

    # Dry-run writes nothing.
    dry = install_and_link_skill(home_dir=fake_home, dry_run=True)
    assert not (fake_home / ".agents" / "skills" / "actenon-scan" / "SKILL.md").exists()
    assert any(lnk.status == "would_link" for lnk in dry.links)
    assert any(lnk.status == "skipped_foreign" and lnk.harness == "Cursor" for lnk in dry.links)

    # Real install writes canonical skill + links Claude & Antigravity, skips foreign Cursor, ignores absent Codex.
    rep = install_and_link_skill(home_dir=fake_home, dry_run=False)
    assert rep.installed
    assert not rep.errors

    canonical_file = fake_home / ".agents" / "skills" / "actenon-scan" / "SKILL.md"
    assert canonical_file.is_file()
    if sys.platform != "win32":
        mode = stat.S_IMODE(canonical_file.stat().st_mode)
        assert mode == 0o600

    assert (fake_home / ".claude" / "skills" / "actenon-scan" / "SKILL.md").is_file()
    assert (fake_home / ".gemini" / "antigravity" / "skills" / "actenon-scan" / "SKILL.md").is_file()
    assert not (fake_home / ".codex").exists(), "Must never create config dirs for absent harnesses"
    assert (cursor_foreign / "SKILL.md").read_text(encoding="utf-8") == "# User custom foreign skill\n"

    # Status reflects linked + foreign accurately.
    st = skill_status(home_dir=fake_home)
    assert st.installed
    statuses = {lnk.harness: lnk.status for lnk in st.links}
    assert statuses["Claude Code"] == "linked"
    assert statuses["Antigravity"] == "linked"
    assert statuses["Cursor"] == "skipped_foreign"

    # Uninstall removes owned links + canonical dir, leaves foreign Cursor skill untouched!
    un = uninstall_skill(home_dir=fake_home)
    assert not un.installed
    assert not (fake_home / ".agents" / "skills" / "actenon-scan").exists()
    assert not (fake_home / ".claude" / "skills" / "actenon-scan").exists()
    assert (cursor_foreign / "SKILL.md").read_text(encoding="utf-8") == "# User custom foreign skill\n"


def test_skill_setup_refuses_symlinked_canonical_dir(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    outside = tmp_path / "outside"
    outside.mkdir()
    agents_skills = fake_home / ".agents" / "skills"
    agents_skills.mkdir(parents=True)
    (agents_skills / "actenon-scan").symlink_to(outside, target_is_directory=True)

    rep = install_and_link_skill(home_dir=fake_home)
    assert not rep.installed
    assert rep.errors
    assert not (outside / "SKILL.md").exists()


def test_doctor_and_cli_setup_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Deliberately do NOT pre-create fake_home first so ACTENON_SCAN_HOME
    # pointing at a fresh directory works out of the box.
    fake_home = tmp_path / "uncreated_home"
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "agent.py").write_text("print('hi')\n", encoding="utf-8")

    monkeypatch.setenv("ACTENON_SCAN_HOME", str(fake_home))
    monkeypatch.chdir(ws)

    rc = cli_main(["setup", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["skill"]["installed"] is True
    assert payload["doctor"]["workspace"]["file_counts"]["python"] == 1

    rc_doc = cli_main(["doctor", "--json"])
    assert rc_doc == 0
    doc_payload = json.loads(capsys.readouterr().out)
    assert doc_payload["skill"]["installed"] is True
    assert doc_payload["parsers"]["python"] is True


def test_install_pre_commit_subcommand(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "tool.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "tool.ts").write_text("export const x = 1;\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    rc_dry = cli_main(["install", "pre-commit", "--dry-run"])
    assert rc_dry == 0
    assert not (tmp_path / ".pre-commit-config.yaml").exists()

    rc = cli_main(["install", "pre-commit"])
    assert rc == 0
    cfg_text = (tmp_path / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "id: actenon-scan" in cfg_text
    assert "id: actenon-scan-typescript" in cfg_text

    # Idempotent when run a second time without --force
    code2, msg2 = install_pre_commit(cwd=tmp_path)
    assert code2 == 0
    assert "already configures" in msg2


def test_zero_friction_cli_dot_shorthand_and_bare_help(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "vuln.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool()
        def run_it(cmd: str) -> None:
            subprocess.run(cmd, shell=True)
    """))
    monkeypatch.chdir(tmp_path)

    # `actenon-scan . --format json --fail-on none` routes directly to `scan`
    rc = cli_main([".", "--format", "json", "--fail-on", "none"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["finding_count"] == 1

    # Bare `actenon-scan` prints quick-start + help and exits 0
    rc_bare = cli_main([])
    assert rc_bare == 0
    bare_out = capsys.readouterr().out
    assert "actenon-scan ." in bare_out
    assert "actenon-scan setup" in bare_out

    # Unknown non-existent subcommand still fails with SystemExit(2)
    with pytest.raises(SystemExit) as excinfo:
        cli_main(["definitely_not_a_command_or_path"])
    assert excinfo.value.code == 2
