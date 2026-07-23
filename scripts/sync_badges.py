#!/usr/bin/env python3
"""Keep the README Python badge aligned with pyproject.toml."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import quote

START = "<!-- PYTHON-BADGE:START -->"
END = "<!-- PYTHON-BADGE:END -->"


def render(root: Path) -> str:
    metadata = tomllib.loads((root / "pyproject.toml").read_text())
    requires_python = metadata["project"].get("requires-python")
    match = re.fullmatch(r">=\s*(\d+\.\d+)", requires_python or "")
    if match is None:
        raise ValueError(
            f"requires-python must be present and use the supported >=X.Y form; got {requires_python!r}"
        )
    version = match.group(1)
    badge_version = quote(f"{version}+", safe=".")
    return "\n".join(
        (
            START,
            f"[![Python {version}+](https://img.shields.io/badge/Python-{badge_version}-blue.svg)]"
            "(https://www.python.org/)",
            END,
        )
    )


def updated_readme(root: Path) -> tuple[str, str]:
    readme = root / "README.md"
    current = readme.read_text()
    pattern = re.compile(rf"{re.escape(START)}.*?{re.escape(END)}", re.DOTALL)
    if pattern.search(current) is None:
        raise ValueError(f"{readme} is missing the Python badge markers")
    return current, pattern.sub(render(root), current, count=1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail if README.md is out of date"
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    try:
        current, expected = updated_readme(root)
    except (KeyError, OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(error, file=sys.stderr)
        return 2

    if current == expected:
        print("README Python badge is up to date")
        return 0
    if args.check:
        sys.stdout.writelines(
            difflib.unified_diff(
                current.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile="README.md",
                tofile="README.md (generated)",
            )
        )
        return 1

    (root / "README.md").write_text(expected)
    print("Updated README Python badge")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
