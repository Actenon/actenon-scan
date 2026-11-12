"""Embedded agent skill bundle for actenon-scan."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

SKILL_NAME = "actenon-scan"
SKILL_MARKER = "<!-- actenon-scan-managed-skill -->"


def get_skill_markdown() -> str:
    """Return the embedded SKILL.md contents shipped in the wheel."""
    return (
        resources.files("actenon_scan.skill")
        .joinpath("SKILL.md")
        .read_text(encoding="utf-8")
    )


def get_embedded_skill_path() -> Path:
    """Return the filesystem path to the embedded SKILL.md when available."""
    return Path(__file__).resolve().parent / "SKILL.md"
