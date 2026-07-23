#!/usr/bin/env python3
"""Verify that registry packages used by README install commands exist."""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

INSTALL_RE = re.compile(r"(?P<tool>pip|npm)\s+install\s+(?P<args>[^`\n|]+)")
PYPI_NAME_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?")


def install_specs(readme: str) -> tuple[set[str], set[str], list[str]]:
    pip_specs: set[str] = set()
    npm_specs: set[str] = set()
    local_commands: list[str] = []
    for match in INSTALL_RE.finditer(readme):
        fragment = match.group("args").split("#", 1)[0].strip()
        try:
            args = shlex.split(fragment)
        except ValueError as error:
            raise ValueError(f"cannot parse {match.group(0)!r}: {error}") from error
        if not args:
            raise ValueError(f"install command has no target: {match.group(0)!r}")
        if match.group("tool") == "pip":
            if (
                "-e" in args
                or "--editable" in args
                or any(arg.startswith(".") for arg in args)
            ):
                local_commands.append(f"pip install {fragment}")
                continue
            candidates = [arg for arg in args if not arg.startswith("-")]
            if not candidates:
                raise ValueError(
                    f"pip install command has no registry target: {match.group(0)!r}"
                )
            pip_specs.update(candidates)
        else:
            candidates = [arg for arg in args if not arg.startswith("-")]
            if not candidates:
                raise ValueError(
                    f"npm install command has no registry target: {match.group(0)!r}"
                )
            npm_specs.update(candidates)
    return pip_specs, npm_specs, local_commands


def get_json(url: str) -> dict[str, object]:
    request = Request(url, headers={"User-Agent": "actenon-readme-install-check/1"})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def pypi_version(spec: str) -> tuple[str, str]:
    match = PYPI_NAME_RE.match(spec)
    if match is None:
        raise ValueError(f"unsupported pip requirement in README.md: {spec!r}")
    name = match.group("name")
    payload = get_json(f"https://pypi.org/pypi/{quote(name, safe='')}/json")
    info = payload.get("info")
    if not isinstance(info, dict) or not isinstance(info.get("version"), str):
        raise ValueError(f"PyPI returned no version for {name}")
    return name, info["version"]


def npm_version(spec: str) -> str:
    payload = get_json(f"https://registry.npmjs.org/{quote(spec, safe='')}")
    tags = payload.get("dist-tags")
    if not isinstance(tags, dict) or not isinstance(tags.get("latest"), str):
        raise ValueError(f"npm returned no latest version for {spec}")
    return tags["latest"]


def main() -> int:
    readme = Path(__file__).resolve().parents[1] / "README.md"
    try:
        pip_specs, npm_specs, local_commands = install_specs(readme.read_text())
        if not pip_specs and not npm_specs:
            raise ValueError("README.md contains no registry install commands")
        print("README registry install commands:")
        for spec in sorted(pip_specs):
            name, version = pypi_version(spec)
            print(f"  pip install {spec} -> {name} {version}")
        for spec in sorted(npm_specs):
            print(f"  npm install {spec} -> {spec} {npm_version(spec)}")
        for command in sorted(set(local_commands)):
            print(f"  local command (not a registry lookup): {command}")
    except (HTTPError, OSError, URLError, ValueError) as error:
        print(f"README install check failed: {error}", file=sys.stderr)
        return 1
    print(f"Validated {len(pip_specs) + len(npm_specs)} registry install command(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
