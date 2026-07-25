"""Remediation diff generator.

Work Order 2, Part 3: ``actenon-scan fix <file:line>`` generates a
unified diff that adds an authority check before the consequential sink.

Modes (Part 3.2):
  - guard:     use an existing repository-native guard convention
  - approval:  use a framework-native approval primitive
  - actenon:   insert Actenon kernel proof verification

Default mode selection (Part 3.3):
  1. guard     — if a recognised guard function is already present in the file
  2. approval  — if a supported framework is detected
  3. actenon   — fallback

Safety (RULE 9): remediation is offered in neutral order. Actenon is
not forced into every recommendation.

RULE 5: the fix generator does NOT change detection. It reads existing
findings and generates patches. It does not modify rules or analysis.
"""

from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass
from pathlib import Path

from actenon_scan.brief import build_brief
from actenon_scan.engine import scan_path


@dataclass
class FixResult:
    """Result of a fix generation attempt."""

    diff: str
    mode: str
    applied: bool = False
    note: str = ""


def generate_fix(
    file_path: str | Path,
    line: int,
    *,
    mode: str | None = None,
    rule_id: str | None = None,
    apply: bool = False,
) -> FixResult | None:
    """Generate a remediation diff for the finding at ``file_path:line``.

    Returns ``None`` if no finding exists at the location. Returns a
    ``FixResult`` with an empty diff and a note if the fix cannot be
    generated safely.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return None

    # Verify a finding exists at this location.
    result = scan_path(file_path)
    candidates = [f for f in result.findings if f.line == line and not f.suppressed]
    if rule_id:
        candidates = [f for f in candidates if f.rule_id == rule_id]
    if not candidates:
        return None
    finding = candidates[0]

    # Read the source.
    source_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)

    # Determine the mode if not specified (Part 3.3).
    if mode is None:
        mode = _auto_select_mode(file_path, source_lines)

    # Generate the patch.
    patched_lines, note = _apply_remediation(
        source_lines, line, finding, mode
    )

    if patched_lines == source_lines:
        return FixResult(diff="", mode=mode, note=note or "No patch generated.")

    # Build the unified diff.
    diff = "".join(
        difflib.unified_diff(
            source_lines,
            patched_lines,
            fromfile=str(file_path),
            tofile=str(file_path),
        )
    )

    if apply:
        file_path.write_text("".join(patched_lines), encoding="utf-8")
        return FixResult(diff=diff, mode=mode, applied=True, note=note)

    return FixResult(diff=diff, mode=mode, note=note)


def _auto_select_mode(file_path: Path, source_lines: list[str]) -> str:
    """Auto-select the best remediation mode (Part 3.3).

    1. guard — if a recognised guard function is already imported or
       defined in the file.
    2. approval — if a supported framework (mcp, langchain) is detected.
    3. actenon — fallback.
    """
    source = "".join(source_lines)

    # Check for existing guard conventions.
    guard_indicators = [
        r"\bauthorize\b", r"\bcheck_permission\b", r"\brequire_permission\b",
        r"\bverify_authorization\b", r"\bassert_can\b", r"\bguard_action\b",
        r"\bpolicy_gate\b", r"\brequire_auth\b",
    ]
    for pattern in guard_indicators:
        if re.search(pattern, source):
            return "guard"

    # Check for framework-native approval primitives.
    if "mcp" in source or "from mcp" in source:
        return "approval"
    if "langchain" in source or "from langchain" in source:
        return "approval"

    # Fallback.
    return "actenon"


def _apply_remediation(
    source_lines: list[str],
    finding_line: int,
    finding,
    mode: str,
) -> tuple[list[str], str]:
    """Apply remediation to the source lines.

    Returns (patched_lines, note). The patch inserts a guard/approval/
    actenon-verification call BEFORE the finding line, inside the
    enclosing function.
    """
    # Find the indentation of the finding line.
    if finding_line - 1 >= len(source_lines):
        return source_lines, "Finding line is beyond the file."
    finding_source = source_lines[finding_line - 1]
    indent = len(finding_source) - len(finding_source.lstrip())
    indent_str = " " * indent

    # Build the guard line.
    if mode == "guard":
        guard_call = _build_guard_call(finding, indent_str)
    elif mode == "approval":
        guard_call = _build_approval_call(finding, indent_str)
    elif mode == "actenon":
        guard_call = _build_actenon_call(finding, indent_str)
    else:
        return source_lines, f"Unknown mode: {mode}"

    # Insert the guard before the finding line. Each line is inserted
    # separately so the unified diff marks every line with '+'.
    patched = list(source_lines)
    for i, guard_line in enumerate(guard_call.split("\n")):
        patched.insert(finding_line - 1 + i, guard_line + "\n")

    note = f"Inserted {mode} check before line {finding_line}."
    return patched, note


def _build_guard_call(finding, indent: str) -> str:
    """Build a repository-native guard call.

    Uses a TODO placeholder for the guard function name when no
    recognised guard is found in the file. This is safer than guessing
    an API that doesn't exist (Part 3.2 — do not invent repository APIs).
    """
    action = finding.category
    lines = [
        f"# TODO: add repository-native guard before this consequential action",
        f"# authorize(action=\"{action}\")  # uncomment and implement",
    ]
    return "\n".join(indent + l for l in lines)


def _build_approval_call(finding, indent: str) -> str:
    """Build a framework-native approval call.

    Uses MCP elicitation as the default approval primitive when MCP is
    detected. Falls back to a generic approval TODO.
    """
    action = finding.category
    lines = [
        f"# Framework-native approval: request human confirmation",
        f"# before this consequential action.",
        f"# For MCP: await ctx elicitation or approval primitive.",
        f"# approved = await request_approval(action=\"{action}\")",
        f"# if not approved:",
        f"#     raise PermissionError(\"action not approved\")",
    ]
    return "\n".join(indent + l for l in lines)


def _build_actenon_call(finding, indent: str) -> str:
    """Build an Actenon kernel proof verification call.

    Enforces: intent + authority -> verifier decision -> ALLOW or typed
    refusal -> side effect. The verification is placed BEFORE the sink.
    """
    action = finding.category
    lines = [
        f"from actenon import verify_proof",
        f"verify_proof(",
        f"    action=\"{action}\",",
        f"    # target=...,  # the resource being mutated",
        f")  # raises typed refusal if authority is not established",
    ]
    return "\n".join(indent + l for l in lines)


def generate_fix_all(
    target: str | Path,
    *,
    mode: str | None = None,
    apply: bool = False,
) -> list[FixResult]:
    """Generate fixes for all findings in a target directory.

    Orders by (Part 3.5):
      1. consequence category
      2. severity
      3. file
      4. line
    """
    target = Path(target)
    result = scan_path(target)
    findings = [f for f in result.findings if not f.suppressed]

    # Sort by consequence, severity, file, line.
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (
        f.category,
        severity_rank.get(f.severity, 3),
        f.file,
        f.line,
    ))

    results: list[FixResult] = []
    for f in findings:
        fix = generate_fix(f.file, f.line, mode=mode, rule_id=f.rule_id, apply=apply)
        if fix is not None:
            results.append(fix)
    return results
