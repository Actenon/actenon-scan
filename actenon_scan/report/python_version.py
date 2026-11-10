"""Explain analysis errors caused by running Scan on an older Python than the project needs.

Scan parses Python with the ``ast`` module of the interpreter it runs on, so code using newer syntax
(for example PEP 758 ``except A, B:``, Python 3.14) is a ``SyntaxError`` on an older interpreter. The
report already lists every such file as an analysis error. This module adds one line saying why and how
to rerun, when the evidence supports it:

* more than half of the analysis errors are ``SyntaxError`` in Python files, and
* the scanned project's ``pyproject.toml`` declares a ``requires-python`` lower bound newer than the
  running interpreter.

It never hides, removes or reclassifies an error. Anything it cannot read or parse means no line.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

#: How many directories above the scan target to look for ``pyproject.toml``.
_MAX_PARENTS = 3


def python_version_hint(
    analysis_errors: Sequence[tuple[str, str]],
    target: str | os.PathLike[str] | None,
    *,
    command: str = "actenon-scan",
    running: tuple[int, ...] | None = None,
) -> str | None:
    """One report line explaining a Python-version mismatch, or None.

    ``target`` is the path the user scanned, as they typed it; it is reused in the rerun command.
    ``command`` is :func:`actenon_scan.report.airlock_handoff.scan_command`. ``running`` defaults to
    ``sys.version_info``.
    """
    if target is None or not analysis_errors:
        return None
    total = len(analysis_errors)
    syntax = sum(1 for rel, err in analysis_errors if _is_python(rel) and err.startswith("SyntaxError:"))
    if syntax * 2 <= total:
        return None
    spec = read_requires_python(target)
    if spec is None:
        return None
    running = tuple(running if running is not None else sys.version_info[:3])
    needed = python_needed(spec, running)
    if needed is None:
        return None

    if syntax == total:
        what = "This is a SyntaxError" if total == 1 else f"All {total} are SyntaxErrors"
    else:
        what = f"{syntax} of {total} are SyntaxErrors"
    here = ".".join(str(p) for p in running[:2])
    rerun_target = shlex.quote(os.fspath(target))
    if command.startswith("uvx "):
        rerun = f"Rerun with: uvx --python {needed} {command[len('uvx '):]} scan {rerun_target}"
    else:
        rerun = f"Rerun with {command} installed on Python {needed}: {command} scan {rerun_target}"
    return f"{what} under Python {here}, and pyproject.toml requires Python {spec}. {rerun}"


def read_requires_python(target: str | os.PathLike[str]) -> str | None:
    """``[project] requires-python`` from the nearest ``pyproject.toml`` at or above ``target``.

    Looks in the target directory (or a file target's directory) and up to three parents, stopping at
    the first ``pyproject.toml`` and at a repository root (a directory containing ``.git``).
    """
    try:
        here = Path(target).resolve()
        if not here.is_dir():
            here = here.parent
        for _ in range(_MAX_PARENTS + 1):
            pyproject = here / "pyproject.toml"
            if pyproject.is_file():
                return _requires_python(pyproject)
            if (here / ".git").exists() or here.parent == here:
                return None
            here = here.parent
    except OSError:
        return None
    return None


def python_needed(spec: str, running: tuple[int, ...]) -> str | None:
    """The Python version to suggest when ``running`` is older than ``spec`` allows, else None.

    A suggestion is returned only when it satisfies every clause of ``spec``, so the rerun command is
    never one the project excludes. ``X.Y`` stands for any ``X.Y.z`` (what ``uvx --python X.Y`` may
    pick), so it is suggested only if the whole series satisfies the spec; ``X.Y.Z`` is one release.

    Understands final-release clauses ``>=``, ``>``, ``<=``, ``<``, ``==``, ``!=`` and ``~=`` with up
    to three components, and ``==``/``!=`` with ``.*``. Anything else (``===``, pre-releases, environment
    markers, more components) means None: no suggestion is better than a wrong one.
    """
    clauses = _parse_spec(spec)
    if not clauses:
        return None
    run = _pad(tuple(running))
    if all(_admits(run, c) for c in clauses):
        return None
    # Only a lower bound the running Python is below makes this a "too old" mismatch; failing an upper
    # bound or an exclusion is not something a newer interpreter fixes.
    if not any(_is_below(run, c) for c in clauses):
        return None
    candidate = max((_smallest(c) for c in clauses if c[0] in (">=", ">", "==")), key=_start, default=None)
    if candidate is None or _pad(candidate[1]) <= run:
        return None
    kind, version = candidate
    if kind == "series":
        if not all(_admits_series(version, c) for c in clauses):
            return None
        return f"{version[0]}.{version[1]}"
    if not all(_admits(version, c) for c in clauses):
        return None
    return ".".join(str(p) for p in version)


#: (operator, version as written, wildcard). ``~=`` is expanded into its ``>=`` and ``==X.*`` parts.
_Clause = tuple[str, tuple[int, ...], bool]

_CLAUSE = re.compile(r"^(~=|==|!=|<=|>=|<|>)\s*(\d+(?:\.\d+){0,2})(\.\*)?$")


def _parse_spec(spec: str) -> list[_Clause] | None:
    clauses: list[_Clause] = []
    for raw in spec.split(","):
        m = _CLAUSE.match(raw.strip())
        if m is None:
            return None
        op, version, wildcard = m.group(1), tuple(int(p) for p in m.group(2).split(".")), bool(m.group(3))
        if wildcard and op not in ("==", "!="):
            return None
        if op == "~=":
            if len(version) < 2:
                return None
            clauses += [(">=", version, False), ("==", version[:-1], True)]
        else:
            clauses.append((op, version, wildcard))
    return clauses


def _admits(v: tuple[int, int, int], clause: _Clause) -> bool:
    """Whether the single release ``v`` satisfies ``clause``."""
    op, version, wildcard = clause
    if wildcard:
        match = v[: len(version)] == version
        return match if op == "==" else not match
    bound = _pad(version)
    return {
        ">=": v >= bound, ">": v > bound, "<=": v <= bound, "<": v < bound, "==": v == bound, "!=": v != bound,
    }[op]


def _admits_series(series: tuple[int, int], clause: _Clause) -> bool:
    """Whether every release ``X.Y.z`` (any ``z``) of ``series`` satisfies ``clause``."""
    op, version, wildcard = clause
    if wildcard:
        if len(version) <= 2:
            match = series[: len(version)] == version
            return match if op == "==" else not match
        return op == "!=" and series != version[:2]
    bound = _pad(version)
    if op in (">=", ">"):
        return _admits((*series, 0), clause)  # the series' lowest release is X.Y.0
    if op in ("<=", "<"):
        return series < bound[:2]  # z is unbounded, so only an earlier series stays below
    if op == "!=":
        return series != bound[:2]
    return False  # == one release: a whole series never matches


def _is_below(v: tuple[int, int, int], clause: _Clause) -> bool:
    """Whether ``v`` fails ``clause`` by being too old for it."""
    op, version, wildcard = clause
    if op not in (">=", ">", "=="):
        return False
    if wildcard:
        return v[: len(version)] < version
    bound = _pad(version)
    return v <= bound if op == ">" else v < bound


def _smallest(clause: _Clause) -> tuple[str, tuple[int, ...]]:
    """The earliest suggestion a lower-bound clause allows: a series ``X.Y`` or one release ``X.Y.Z``."""
    op, version, wildcard = clause
    major, minor, micro = _pad(version)
    if wildcard:  # ==X.*, ==X.Y.*, ==X.Y.Z.*
        return ("series", (major, minor)) if len(version) <= 2 else ("release", (major, minor, micro))
    if op == ">":
        return ("series", (major, minor + 1)) if micro == 0 else ("release", (major, minor, micro + 1))
    return ("series", (major, minor)) if micro == 0 else ("release", (major, minor, micro))


def _start(candidate: tuple[str, tuple[int, ...]]) -> tuple[tuple[int, int, int], bool]:
    """Sort key: the candidate's earliest release, preferring a single release on a tie."""
    kind, version = candidate
    return _pad(version), kind == "release"


def _pad(version: tuple[int, ...]) -> tuple[int, int, int]:
    padded = (*version[:3], 0, 0, 0)
    return padded[0], padded[1], padded[2]


def _is_python(rel: str) -> bool:
    return rel.endswith((".py", ".pyi"))


def _requires_python(pyproject: Path) -> str | None:
    try:
        raw = pyproject.read_bytes()
    except OSError:
        return None
    try:
        try:
            import tomllib
        except ImportError:  # Python 3.10
            import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        return _requires_python_fallback(raw)
    try:
        value = tomllib.loads(raw.decode("utf-8")).get("project", {}).get("requires-python")
    except (UnicodeDecodeError, ValueError, AttributeError):
        return None
    if not isinstance(value, str):
        return None
    return value.strip() or None


_PROJECT_HEADER = re.compile(r"""^\[\s*(?:project|"project"|'project')\s*\]\s*(?:#.*)?$""")
_REQUIRES = re.compile(r"""^\s*requires-python\s*=\s*(?:"([^"\\]*)"|'([^']*)')\s*(?:#.*)?$""")


def _requires_python_fallback(raw: bytes) -> str | None:
    """Read ``requires-python`` without a TOML parser (Python 3.10 without tomli).

    Scan has no runtime dependencies, so on 3.10 it may have no TOML parser. This accepts only a
    single-line string value directly under a ``[project]`` header. Any line starting with ``[``
    (a table ``[...]``, an array of tables ``[[...]]``, quoted or dotted names) other than that header
    leaves ``[project]``. A multi-line string before the value makes the structure ambiguous, so
    that, like anything else unrecognised, means None.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    in_project = False
    for line in text.splitlines():
        if '"""' in line or "'''" in line:
            return None  # what follows may be string content, not TOML lines
        stripped = line.strip()
        if stripped.startswith("["):
            in_project = _PROJECT_HEADER.match(stripped) is not None
            continue
        if in_project:
            m = _REQUIRES.match(line)
            if m:
                value = (m.group(1) if m.group(1) is not None else m.group(2)).strip()
                return value or None
    return None
