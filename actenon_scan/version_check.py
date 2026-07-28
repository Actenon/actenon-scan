#!/usr/bin/env python3
"""Verify version coherence between pyproject.toml, git tags, and PyPI.

Work Order 1.11, Item 2: the four conditions are:
  pyproject == pypi                          PASS   normal steady state
  pyproject > pypi, no tag for that version  PASS   bump merged, not yet released
  pyproject > pypi, tag exists               FAIL   tag pushed but publish did not land
  pypi > pyproject                           FAIL   rollback, yank, or drift

Work Order 2, Phase 9: extracted into a testable function so the
conditions can be verified without mocking git or PyPI.
"""

from __future__ import annotations

import subprocess
from packaging.version import Version


def check_version_coherence(
    pyproject_version: str,
    pypi_version: str,
    tag_exists: bool,
) -> tuple[bool, str]:
    """Check whether pyproject and PyPI versions are coherent.

    Args:
        pyproject_version: The version in pyproject.toml.
        pypi_version: The latest version on PyPI.
        tag_exists: Whether a git tag `v{pyproject_version}` exists.

    Returns:
        (ok, message) — ok is True if the state is acceptable, False if
        it indicates a problem. message explains the state.
    """
    py = Version(pyproject_version)
    pypi = Version(pypi_version)

    if py == pypi:
        return True, "versions match"

    if py > pypi:
        if tag_exists:
            return False, (
                f"tag v{pyproject_version} exists but PyPI has {pypi_version} — "
                f"the publish workflow may have failed"
            )
        return True, (
            f"pyproject version is newer than PyPI "
            f"(unpublished bump, no tag yet)"
        )

    # pypi > pyproject
    return False, (
        f"PyPI version ({pypi_version}) is newer than pyproject ({pyproject_version}) — "
        f"rollback, yank, or drift"
    )


def git_tag_exists(version: str) -> bool:
    """Check if a git tag v{version} exists."""
    result = subprocess.run(
        ["git", "tag", "-l", f"v{version}"],
        capture_output=True, text=True,
    )
    return bool(result.stdout.strip())
