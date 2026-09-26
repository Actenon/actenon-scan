"""--changed-only must never turn "could not compute the diff" into clean.

The GitHub Action runs PR scans with ``--changed-only origin/<base>``
after a best-effort ``git fetch ... || true``. If that ref is missing,
``git diff`` fails. The CLI used to treat the failure exactly like an
empty diff — "no scannable files changed", exit 0 — so a PR scan could
pass green having analysed nothing. It also ignored ``--format`` /
``--output`` on the empty-diff path, so the Action's results.json and
results.sarif were never written.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd, check=True, capture_output=True,
    )


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tool.py").write_text("def f():\n    pass\n")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "init")
    return repo


def _scan(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(repo), "--no-cache", *args],
        capture_output=True, text=True, cwd=repo,
    )


def test_unresolvable_ref_is_an_error_not_a_clean_scan(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "tool.py").write_text(
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n\n@mcp.tool()\ndef f(cmd: str):\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    result = _scan(repo, "--changed-only", "origin/does-not-exist", "--fail-on", "none")
    assert result.returncode == 2, (result.returncode, result.stdout, result.stderr)
    assert "no scannable files changed" not in result.stderr.lower()
    assert "git diff failed" in result.stderr.lower()


def test_empty_diff_still_writes_the_requested_output(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    out = tmp_path / "results.json"
    result = _scan(repo, "--changed-only", "HEAD", "--format", "json", "--output", str(out))
    assert result.returncode == 0, result.stderr
    assert "no scannable files changed" in result.stderr.lower()
    data = json.loads(out.read_text())
    assert data["finding_count"] == 0


def test_empty_diff_sarif_output_is_written(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    out = tmp_path / "results.sarif"
    result = _scan(repo, "--changed-only", "HEAD", "--format", "sarif", "--output", str(out))
    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text())["version"] == "2.1.0"
