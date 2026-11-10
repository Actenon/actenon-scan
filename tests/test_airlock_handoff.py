"""Scan -> Airlock handoff: Scan offers Airlock only where Airlock can act, and says exactly what it
would do.

The handoff must never overclaim:
* Scan's repository-native remediation stays the default; Airlock is an optional second option;
* only ``github.contents.write`` in Python gets a handoff (the one consequence exercised end to end);
  HTTP calls, other GitHub actions, shells and non-Python findings get none;
* a target the model chooses stays blocked in Airlock, so no approve step is printed for it;
* Scan never imports Airlock, never writes Airlock state and never approves anything;
* Local Mode enforcement is never described as a verified outcome;
* the printed follow-up commands must be runnable the way the user launched Scan.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan import cli
from actenon_scan.report import airlock_handoff as ah
from actenon_scan.report.blast_radius import is_literal_argument_value

HEADER = "Optional: enforce it at runtime with Actenon Airlock"

MODEL_CHOSEN_REPO = '''"""An MCP server that lets an agent publish release notes."""
import os

from github import Github
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("release-notes")
gh = Github(os.environ["GITHUB_TOKEN"])


@mcp.tool()
def publish_release_notes(repo: str, path: str, content: str, message: str) -> str:
    repository = gh.get_repo(repo)
    result = repository.create_file(path, message, content, branch="main")
    return result["commit"].sha


if __name__ == "__main__":
    mcp.run()
'''

FIXED_REPO = MODEL_CHOSEN_REPO.replace(
    'gh = Github(os.environ["GITHUB_TOKEN"])',
    'gh = Github(os.environ["GITHUB_TOKEN"])\nRELEASE_REPO = "acme/release-notes"',
).replace("def publish_release_notes(repo: str, path", "def publish_release_notes(path").replace(
    "gh.get_repo(repo)", "gh.get_repo(RELEASE_REPO)"
)

ALIASED_MODEL_REPO = MODEL_CHOSEN_REPO.replace(
    "    repository = gh.get_repo(repo)", "    target = repo\n    repository = gh.get_repo(target)"
)

ALIASED_CONSTANT_REPO = FIXED_REPO.replace(
    "    repository = gh.get_repo(RELEASE_REPO)", "    target = RELEASE_REPO\n    repository = gh.get_repo(target)"
)

DYNAMIC_REPO = FIXED_REPO.replace(
    'RELEASE_REPO = "acme/release-notes"', "RELEASE_REPO = lookup_target()"
)

ENV_REPO = FIXED_REPO.replace('RELEASE_REPO = "acme/release-notes"', 'RELEASE_REPO = os.environ["RELEASE_REPO"]')

PLAIN_AGENT_FIXED_REPO = '''from github import Github
from langchain.tools import tool

gh = Github("token")


@tool
def write_notes(path: str, content: str) -> None:
    gh.get_repo("acme/notes").create_file(path, "notes", content)
'''

ISSUE_TOOL = '''from github import Github
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("issues")
gh = Github("token")


@mcp.tool()
def open_issue(title: str, body: str) -> None:
    gh.get_repo("acme/notes").create_issue(title=title, body=body)
'''

HTTP_TOOL = '''import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("events")


@mcp.tool()
def post_event(message: str) -> None:
    requests.post("https://api.example.com/events", json={"message": message})
'''

SHELL_TOOL = '''import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")


@mcp.tool()
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
'''


def _project(tmp_path: Path, source: str, name: str = "app/server.py") -> Path:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source)
    return tmp_path


def _scan(project: Path, capsys, monkeypatch, *extra: str) -> str:
    monkeypatch.chdir(project)
    cli.main(["scan", ".", *extra])
    return capsys.readouterr().out


def _line_of(source: str, needle: str) -> int:
    return next(i for i, text in enumerate(source.splitlines(), 1) if needle in text)


def _handoff(tmp_path: Path, source: str, needle: str = "create_file", name: str = "app/server.py"):
    project = _project(tmp_path, source, name)
    return ah.find_airlock_handoff(project, name, _line_of(source, needle))


# -- what Airlock would do --------------------------------------------------------------------------


def test_model_chosen_repository_is_reported_as_blocked_not_approvable(tmp_path):
    h = _handoff(tmp_path, MODEL_CHOSEN_REPO)
    assert h is not None
    assert h.action == "github.contents.write"
    assert h.state == "UNRESOLVED" and h.resource is None and not h.approvable
    assert h.model_chooses_target
    assert h.target_origins == ("parameter `repo` of tool `publish_release_notes`",)
    text = "\n".join(ah.format_handoff(h))
    assert "the model chooses the repository" in text
    assert "keeps this call blocked, even after approval" in text
    assert "repository-native guard above" in text
    # No approve or run step for something Airlock would keep blocked.
    assert "--approve" not in text and "airlock run" not in text
    assert "airlock init --command app/server.py" in text and "approves nothing" in text


def test_aliased_model_parameter_is_still_model_chosen(tmp_path):
    h = _handoff(tmp_path, ALIASED_MODEL_REPO)
    assert h is not None and not h.approvable and h.model_chooses_target
    assert "parameter `repo` of tool `publish_release_notes`" in h.target_origins


def test_fixed_repository_gets_review_approve_run(tmp_path):
    h = _handoff(tmp_path, FIXED_REPO)
    assert h is not None and h.approvable
    assert (h.action, h.resource) == ("github.contents.write", "github.com/acme/release-notes")
    assert h.entry_script == "app/server.py"
    text = "\n".join(ah.format_handoff(h))
    assert "Airlock power:  github.contents.write on github.com/acme/release-notes" in text
    assert "Finding this approves nothing" in text
    assert "airlock init --command app/server.py" in text
    assert "airlock init --approve --command app/server.py" in text
    assert "airlock run -- app/server.py" in text
    assert "In your agent's Python environment:" in text
    assert "Keep GITHUB_TOKEN in the shell that runs airlock" in text
    assert "<entry>" not in text


def test_aliased_constant_repository_is_resolved(tmp_path):
    h = _handoff(tmp_path, ALIASED_CONSTANT_REPO)
    assert h is not None and h.approvable and h.resource == "github.com/acme/release-notes"


def test_dynamic_target_is_unresolved_but_not_attributed_to_the_model(tmp_path):
    h = _handoff(tmp_path, DYNAMIC_REPO)
    assert h is not None and not h.approvable and not h.model_chooses_target
    text = "\n".join(ah.format_handoff(h))
    assert "unresolved repository blocked" in text
    assert "model chooses" not in text and "--approve" not in text


def test_environment_target_resolves_from_project_configuration(tmp_path):
    project = _project(tmp_path, ENV_REPO)
    line = _line_of(ENV_REPO, "create_file")
    unresolved = ah.find_airlock_handoff(project, "app/server.py", line)
    assert unresolved is not None and not unresolved.approvable
    assert "env value `RELEASE_REPO`" in unresolved.target_origins
    (project / ".env").write_text("RELEASE_REPO=acme/release-notes\n")
    resolved = ah.find_airlock_handoff(project, "app/server.py", line)
    assert resolved is not None and resolved.approvable and resolved.resource == "github.com/acme/release-notes"


def test_agent_without_main_block_says_to_fill_in_the_entry_script(tmp_path):
    h = _handoff(tmp_path, PLAIN_AGENT_FIXED_REPO, name="tools.py")
    assert h is not None and h.approvable and h.entry_script is None
    text = "\n".join(ah.format_handoff(h))
    assert "Replace <entry> with the script that starts your agent" in text
    assert "airlock init --command <entry>" in text


# -- where Scan stays silent ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "needle"),
    [(HTTP_TOOL, "requests.post"), (ISSUE_TOOL, "create_issue"), (SHELL_TOOL, "subprocess.run")],
    ids=["http-post", "github-issue", "shell"],
)
def test_unsupported_consequences_get_no_handoff(tmp_path, source, needle):
    assert _handoff(tmp_path, source, needle) is None


@pytest.mark.parametrize("name", ["src/agent.ts", "agent.go", "agent.js"])
def test_non_python_findings_get_no_handoff(tmp_path, name):
    assert ah.find_airlock_handoff(tmp_path, name, 1) is None


def test_read_only_call_on_the_line_gets_no_handoff(tmp_path):
    assert _handoff(tmp_path, MODEL_CHOSEN_REPO, "get_repo(repo)") is None


def test_unrelated_finding_category_skips_authority_extraction(tmp_path, monkeypatch):
    project = _project(tmp_path, FIXED_REPO)
    calls = []
    monkeypatch.setattr("actenon_scan.authority.extract_authority", lambda *a, **k: calls.append(a))
    line = _line_of(FIXED_REPO, "create_file")
    assert ah.find_airlock_handoff(project, "app/server.py", line, category="shell_execution") is None
    assert calls == []


def test_extraction_failure_means_no_handoff(tmp_path, monkeypatch):
    project = _project(tmp_path, FIXED_REPO)

    def boom(*_a, **_k):
        raise RuntimeError("analysis crashed")

    monkeypatch.setattr("actenon_scan.authority.extract_authority", boom)
    assert ah.find_airlock_handoff(project, "app/server.py", 5) is None


# -- the scan report --------------------------------------------------------------------------------


def test_scan_report_offers_both_options_with_native_guard_first(tmp_path, capsys, monkeypatch):
    out = _scan(_project(tmp_path, MODEL_CHOSEN_REPO), capsys, monkeypatch)
    assert "Target:                    repository chosen by the model (parameter `repo`" in out
    assert "# default remediation: a repository-native guard" in out
    assert out.index("default remediation") < out.index(HEADER)
    assert "--approve" not in out


def test_scan_report_for_fixed_target_offers_review_approve_run(tmp_path, capsys, monkeypatch):
    out = _scan(_project(tmp_path, FIXED_REPO), capsys, monkeypatch)
    assert "Target:                    github.com/acme/release-notes" in out
    assert "airlock init --approve --command app/server.py" in out


def test_no_false_claim_of_verified_execution(tmp_path, capsys, monkeypatch):
    out = _scan(_project(tmp_path, FIXED_REPO), capsys, monkeypatch)
    section = out[out.index(HEADER):]
    assert "does not verify the outcome on GitHub" in section
    assert "not a sandbox" in section
    for overclaim in ("CONFIRMED", "COMMITTED", "verified by", "guarantee", "MCP"):
        assert overclaim not in section


@pytest.mark.parametrize("source", [HTTP_TOOL, ISSUE_TOOL, SHELL_TOOL], ids=["http-post", "github-issue", "shell"])
def test_scan_without_supported_finding_is_unchanged(tmp_path, capsys, monkeypatch, source):
    out = _scan(_project(tmp_path, source), capsys, monkeypatch)
    # (Scan 1.6.0 reports the HTTP POST and the shell call; it does not report create_issue at all.)
    assert "Airlock" not in out and "Target:" not in out and "default remediation" not in out


@pytest.mark.parametrize("fmt", ["json", "sarif", "list", "markdown"])
def test_machine_and_alternate_formats_are_unchanged(tmp_path, capsys, monkeypatch, fmt):
    out = _scan(_project(tmp_path, FIXED_REPO), capsys, monkeypatch, "--format", fmt)
    assert "Airlock" not in out
    if fmt in ("json", "sarif"):
        json.loads(out)


def test_scan_never_imports_airlock_or_writes_airlock_state(tmp_path, capsys, monkeypatch):
    project = _project(tmp_path, FIXED_REPO)
    before = sorted(p.relative_to(project) for p in project.rglob("*"))
    _scan(project, capsys, monkeypatch)
    after = sorted(p.relative_to(project) for p in project.rglob("*"))
    assert after == before and not (project / ".airlock").exists()
    assert "actenon_airlock" not in sys.modules
    assert "actenon_airlock" not in (ROOT / "actenon_scan/report/airlock_handoff.py").read_text()


def test_default_fix_remediation_does_not_mention_airlock(tmp_path, capsys, monkeypatch):
    project = _project(tmp_path, FIXED_REPO)
    monkeypatch.chdir(project)
    cli.main(["fix", f"app/server.py:{_line_of(FIXED_REPO, 'create_file')}"])
    out = capsys.readouterr().out
    assert out.startswith("--- app/server.py")
    assert "airlock" not in out.lower()


def test_explain_includes_the_handoff_after_the_limitations(tmp_path, capsys, monkeypatch):
    project = _project(tmp_path, FIXED_REPO)
    monkeypatch.chdir(project)
    assert cli.main(["explain", f"app/server.py:{_line_of(FIXED_REPO, 'create_file')}"]) == 0
    out = capsys.readouterr().out
    assert "github.contents.write on github.com/acme/release-notes" in out
    assert out.index("What this does NOT establish") < out.index(HEADER) < out.index("Coverage")


# -- model-controlled inputs ------------------------------------------------------------------------


def test_literal_keyword_values_are_not_model_controlled(tmp_path, capsys, monkeypatch):
    out = _scan(_project(tmp_path, MODEL_CHOSEN_REPO), capsys, monkeypatch)
    inputs = next(line for line in out.splitlines() if "Model-controlled inputs:" in line)
    assert "branch" not in inputs
    assert "path" in inputs and "content" in inputs


@pytest.mark.parametrize(
    ("value", "literal"),
    [('"main"', True), ("'x'", True), ('rb"x"', True), ("42", True), ("1.5e3", True), ("None", True),
     ('f"{x}"', False), ("branch", False), ("inf", False), ("x.y", False), ("[a]", False), ("", False)],
)
def test_is_literal_argument_value(value, literal):
    assert is_literal_argument_value(value) is literal


# -- runnable next steps ----------------------------------------------------------------------------


def test_next_steps_use_uvx_when_scan_was_launched_by_uvx(monkeypatch, tmp_path):
    # uvx runs Scan from a throwaway env in its cache and puts that env's bin on PATH for the
    # child only, so from inside Scan the command looks installed. It is gone once Scan exits.
    env_prefix = tmp_path / "uvcache" / "archive-v0" / "abc123"
    monkeypatch.setenv("UV", "/usr/local/bin/uv")
    monkeypatch.delenv("UV_CACHE_DIR", raising=False)
    monkeypatch.setattr(sys, "prefix", str(env_prefix))
    assert ah.scan_command() == "uvx actenon-scan"


def test_uv_cache_dir_override_is_recognised(monkeypatch, tmp_path):
    cache = tmp_path / "custom-cache"
    env_prefix = cache / "environments-v2" / "actenon-scan-abc"
    env_prefix.mkdir(parents=True)
    monkeypatch.setenv("UV", "/usr/local/bin/uv")
    monkeypatch.setenv("UV_CACHE_DIR", str(cache))
    monkeypatch.setattr(sys, "prefix", str(env_prefix))
    assert ah.scan_command() == "uvx actenon-scan"


def test_uv_managed_project_or_tool_env_keeps_the_plain_command(monkeypatch, tmp_path):
    # `uv run` in a project and `uv tool install` both leave actenon-scan on the user's PATH.
    for prefix in (tmp_path / "project" / ".venv", tmp_path / ".local/share/uv/tools/actenon-scan"):
        prefix.mkdir(parents=True)
        monkeypatch.setenv("UV", "/usr/local/bin/uv")
        monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setattr(sys, "prefix", str(prefix))
        assert ah.scan_command() == "actenon-scan"


def test_next_steps_default_to_plain_command_outside_uv(monkeypatch, tmp_path):
    monkeypatch.delenv("UV", raising=False)
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "cache" / "archive-v0" / "x"))
    assert ah.scan_command() == "actenon-scan"
