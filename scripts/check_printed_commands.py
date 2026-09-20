#!/usr/bin/env python3
"""Printed-command gate: every command string this build prints must run.

The failure this prevents
-------------------------
A release ships output that advertises a subcommand the shipped build does
not have. The user copies the line the tool printed and gets
``invalid choice``. For a tool whose product is an honest account of what it
did and did not check, printing an instruction that does not resolve is the
same failure class as a silent miss: the output describes a build that is
not the one the user is holding.

This cannot be caught by testing ``main``. It is caught by asserting, inside
whatever build is under test, that every ``actenon-scan <word>`` invocation
reachable in the source resolves to a subparser registered by that same
build's ``build_parser()`` — never against a hand-kept list.

Prose versus invocation
-----------------------
A string literal mentions the tool in two ways: as prose ("the actenon-scan
repository", "an actenon-scan config file") and as an invocation the reader
is expected to run ("Next: actenon-scan explain foo.py:42"). Only the second
is a promise about this build. See ``_is_invocation``.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "actenon_scan"

# "actenon-scan explain foo.py:1" -> "explain". Also matches after "uvx ".
COMMAND_RE = re.compile(r"actenon-scan\s+([A-Za-z][\w-]*)")

# An occurrence counts as an invocation when BOTH hold:
#
#   1. It is introduced by a command marker — a backtick, a quote, a <code>
#      tag, "$ ", "uvx ", "Run ", a colon-space ("Next: ..."), "by ", or the
#      start of a line. Prose introducers ("the ", "an ", "in ", "between ",
#      "# ") are deliberately absent.
#   2. What follows the subcommand word is command-shaped — nothing, a flag,
#      a path, a placeholder, or a file:line — rather than more English.
#
# Requiring both means a bare unregistered hint ("Next: actenon-scan triage")
# still fails the gate, while "the actenon-scan repository for supported
# architectures" never reaches it.

_MARKERS = ("`", "<code>", "$ ", "uvx ", "Run ", ": ", "by ", "'", '"')

_COMMAND_SHAPED_REMAINDER = re.compile(
    r"""^(
          \s*$                      # nothing follows: "actenon-scan rules"
        | \s+--?[A-Za-z]            # a flag:          "--format list"
        | \s+[<{]                   # placeholder:     "<path>", "{loc}"
        | \s+[\w./~-]+[:/][\w.*{-]  # path/file:line:  "a/b.py:42", "./x"
        | \s+\.(\s|$|[`'")<])       # the "." target:  "scan .", "`scan .`"
        | \s+[a-z-]+\s+--           # target + flag:   "install github --help"
        )""",
    re.VERBOSE,
)


def _is_invocation(text: str, start: int, end: int) -> bool:
    """Is the match at [start:end] a command to run, or prose about the tool?"""
    before = text[:start]
    line_start = before.rsplit("\n", 1)[-1]
    at_line_start = line_start.strip() == ""
    if not (at_line_start or any(before.endswith(m) for m in _MARKERS)):
        return False
    return bool(_COMMAND_SHAPED_REMAINDER.match(text[end:]))


def registered_subcommands() -> set[str]:
    """Names registered by THIS build's parser, read from the live object."""
    from actenon_scan.cli import build_parser

    parser = build_parser()
    names: set[str] = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            names.update(action.choices.keys())
    return names


def iter_string_literals(path: Path):
    """Yield (lineno, value) for every string constant in a Python file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:  # pragma: no cover - source must parse
        print(f"FAIL: {path} does not parse: {exc}")
        raise SystemExit(1)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value
        elif isinstance(node, ast.JoinedStr):
            # f-string: keep the literal parts and stand a placeholder in for
            # each interpolation, so "actenon-scan explain {loc}" still yields
            # the word "explain" followed by a command-shaped remainder.
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    parts.append("{}")
            yield node.lineno, "".join(parts)


def main() -> int:
    registered = registered_subcommands()
    if not registered:
        print("FAIL: no subparsers registered — cannot verify printed commands.")
        return 1

    problems: list[str] = []
    seen: set[tuple[str, int, str]] = set()
    checked = 0
    files = sorted(PKG.rglob("*.py"))

    for path in files:
        rel = path.relative_to(REPO)
        for lineno, text in iter_string_literals(path):
            if "actenon-scan" not in text:
                continue
            for match in COMMAND_RE.finditer(text):
                if not _is_invocation(text, match.start(), match.end()):
                    continue
                checked += 1
                word = match.group(1)
                if word not in registered:
                    key = (str(rel), lineno, word)
                    if key in seen:
                        continue
                    seen.add(key)
                    problems.append(
                        f"{rel}:{lineno}: printed command 'actenon-scan {word}' "
                        f"is not a registered subcommand in this build "
                        f"(registered: {', '.join(sorted(registered))})"
                    )

    if problems:
        print("FAIL: printed commands do not resolve in this build:")
        for p in problems:
            print(f"  {p}")
        print()
        print(
            "Every command string the tool prints must run in the same build. "
            "Either register the subcommand or stop printing it."
        )
        return 1

    print(
        f"PASS: {checked} printed command invocation(s) across {len(files)} "
        f"source file(s) all resolve to registered subcommands."
    )
    print(f"  registered: {', '.join(sorted(registered))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
