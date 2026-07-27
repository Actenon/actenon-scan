"""Tests for actenon-scan install github."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


def _run_install(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    """Run actenon-scan install github with the given args in the given cwd."""
    return subprocess.run(
        [sys.executable, "-m", "actenon_scan", "install", "github"] + args,
        capture_output=True, text=True, cwd=str(cwd),
    )


def test_install_github_dry_run(tmp_path: Path) -> None:
    """--dry-run prints the workflow without writing to disk."""
    # Init a git repo so _find_git_root works
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install(["--dry-run"], tmp_path)
    assert result.returncode == 0
    assert "name: actenon-scan" in result.stdout
    assert "Actenon/actenon-scan@v1" in result.stdout
    # File must NOT be created
    assert not (tmp_path / ".github" / "workflows" / "actenon-scan.yml").exists()


def test_install_github_creates_workflow(tmp_path: Path) -> None:
    """Default invocation creates .github/workflows/actenon-scan.yml."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install([], tmp_path)
    assert result.returncode == 0
    workflow = tmp_path / ".github" / "workflows" / "actenon-scan.yml"
    assert workflow.exists()
    content = workflow.read_text()
    assert "name: actenon-scan" in content
    assert "Actenon/actenon-scan@v1" in content
    assert "fail-on: none" in content
    assert "pull-requests: write" in content
    assert "security-events: write" in content


def test_install_github_existing_file_refused(tmp_path: Path) -> None:
    """Existing workflow is not overwritten without --force."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    # Create an existing workflow
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "actenon-scan.yml").write_text("# existing\n")
    result = _run_install([], tmp_path)
    assert result.returncode == 1
    assert "already exists" in result.stderr


def test_install_github_force_overwrites(tmp_path: Path) -> None:
    """--force overwrites and creates a backup."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    original = "# existing workflow\n"
    (workflow_dir / "actenon-scan.yml").write_text(original)
    result = _run_install(["--force"], tmp_path)
    assert result.returncode == 0
    workflow = workflow_dir / "actenon-scan.yml"
    backup = workflow_dir / "actenon-scan.yml.bak"
    assert workflow.exists()
    assert backup.exists()
    assert backup.read_text() == original
    assert "name: actenon-scan" in workflow.read_text()


def test_install_github_blocking(tmp_path: Path) -> None:
    """--blocking sets fail-on: high."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install(["--blocking"], tmp_path)
    assert result.returncode == 0
    content = (tmp_path / ".github" / "workflows" / "actenon-scan.yml").read_text()
    assert "fail-on: high" in content


def test_install_github_default_non_blocking(tmp_path: Path) -> None:
    """Default is non-blocking (fail-on: none)."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install([], tmp_path)
    assert result.returncode == 0
    content = (tmp_path / ".github" / "workflows" / "actenon-scan.yml").read_text()
    assert "fail-on: none" in content
    assert "does not block merging" in result.stdout


def test_install_github_baseline(tmp_path: Path) -> None:
    """--baseline references the baseline file in the workflow."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install(["--baseline", "baseline.json"], tmp_path)
    assert result.returncode == 0
    content = (tmp_path / ".github" / "workflows" / "actenon-scan.yml").read_text()
    assert "baseline:" in content
    assert "baseline.json" in content


def test_install_github_config(tmp_path: Path) -> None:
    """--config references the config file in the workflow."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install(["--config", ".actenon-scan.json"], tmp_path)
    assert result.returncode == 0
    content = (tmp_path / ".github" / "workflows" / "actenon-scan.yml").read_text()
    assert "config:" in content
    assert ".actenon-scan.json" in content


def test_install_github_not_git_repo(tmp_path: Path) -> None:
    """Running outside a git repo exits with code 2."""
    result = _run_install([], tmp_path)
    assert result.returncode == 2
    assert "not inside a Git repository" in result.stderr


def test_install_github_nested_directory(tmp_path: Path) -> None:
    """Running from a subdirectory finds the git root."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    nested = tmp_path / "src" / "deep"
    nested.mkdir(parents=True)
    result = _run_install([], nested)
    assert result.returncode == 0
    assert (tmp_path / ".github" / "workflows" / "actenon-scan.yml").exists()


def test_install_github_stable_tag(tmp_path: Path) -> None:
    """Generated workflow uses @v1, not a specific patch version."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install([], tmp_path)
    assert result.returncode == 0
    content = (tmp_path / ".github" / "workflows" / "actenon-scan.yml").read_text()
    assert "@v1" in content
    # Must NOT contain a specific patch version like @v1.1.4
    assert "@v1." not in content


def test_install_github_no_write_all_permissions(tmp_path: Path) -> None:
    """Generated workflow must not use permissions: write-all."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install([], tmp_path)
    assert result.returncode == 0
    content = (tmp_path / ".github" / "workflows" / "actenon-scan.yml").read_text()
    assert "write-all" not in content
    # Must have scoped permissions
    assert "pull-requests: write" in content
    assert "security-events: write" in content
    assert "contents: read" in content


def test_install_github_no_secrets(tmp_path: Path) -> None:
    """Generated workflow must not reference any secrets."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    result = _run_install([], tmp_path)
    assert result.returncode == 0
    content = (tmp_path / ".github" / "workflows" / "actenon-scan.yml").read_text()
    assert "secrets" not in content.lower()
    assert "ACTENON_API_KEY" not in content
    assert "TOKEN" not in content


def test_install_help() -> None:
    """--help works for install and install github."""
    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "install", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "github" in result.stdout

    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "install", "github", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "--dry-run" in result.stdout
    assert "--force" in result.stdout
    assert "--blocking" in result.stdout
    assert "--baseline" in result.stdout
    assert "--config" in result.stdout
