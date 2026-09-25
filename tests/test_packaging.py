"""Packaging regression: the built wheel must contain every subpackage.

CI installs the package in editable mode (``pip install -e``), which puts
the source tree itself on ``sys.path``. An editable install therefore
imports ``actenon_scan.repository`` even when ``pyproject.toml`` forgets to
list it — and a real ``pip install actenon-scan`` / ``uvx actenon-scan``
(which installs the built wheel) then crashes on the first directory scan
with ``ModuleNotFoundError: No module named 'actenon_scan.repository'``.

This test pins the explicit ``[tool.setuptools] packages`` list to the
packages that actually exist on disk, so a new subpackage cannot be
silently left out of the wheel again.
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on the 3.10 CI leg
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def _packages_on_disk() -> set[str]:
    pkg_root = ROOT / "actenon_scan"
    found = set()
    for init in pkg_root.rglob("__init__.py"):
        rel = init.parent.relative_to(ROOT)
        if "__pycache__" in rel.parts:
            continue
        found.add(".".join(rel.parts))
    return found


def test_every_subpackage_is_listed_in_pyproject() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    listed = set(data["tool"]["setuptools"]["packages"])
    missing = _packages_on_disk() - listed
    assert not missing, (
        "These packages exist on disk but are not listed in "
        "[tool.setuptools] packages, so they are missing from the built "
        f"wheel: {sorted(missing)}"
    )
