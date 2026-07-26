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

    Language awareness: the fix generator currently only emits Python
    syntax (`#` comments, `raise PermissionError`, `from … import …`).
    Applying a Python-syntax patch to a `.ts`/`.go` file would corrupt
    it. For non-Python files, we refuse with a helpful note instead of
    silently emitting broken syntax.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return None

    # Refuse non-Python files with a clear note. The fix generators
    # (_build_guard_call, _build_approval_call, _build_actenon_call)
    # all emit Python syntax; inserting that into a .ts or .go file
    # produces invalid source. Generating TS/Go-correct syntax is a
    # future enhancement; for now, refuse safely.
    NON_PYTHON_SUFFIXES = (
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",  # TypeScript / JS
        ".go",                                            # Go
    )
    if file_path.suffix in NON_PYTHON_SUFFIXES:
        return FixResult(
            diff="",
            mode=mode or "skip",
            note=(
                f"Fix generation is not yet supported for {file_path.suffix} files. "
                f"The fix generator emits Python syntax (`#` comments, `raise …`), "
                f"which would corrupt a {file_path.suffix} file. "
                f"Please add the guard manually, or open an issue at "
                f"https://github.com/Actenon/actenon-scan/issues to request "
                f"{file_path.suffix} fix support."
            ),
        )

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

    Returns (patched_lines, note). The patch:

    1. Inserts any required IMPORTS at the top of the file (after any
       existing imports / module docstring), never inside a ``with`` block
       or function body.
    2. Inserts the guard/approval/actenon-verification call BEFORE the
       finding line, at the indentation of the ENCLOSING FUNCTION BODY
       (not the finding line itself — the finding line may be inside a
       ``with`` block whose deeper indentation would push the guard into
       the wrong scope).
    """
    # Find the indentation of the finding line.
    if finding_line - 1 >= len(source_lines):
        return source_lines, "Finding line is beyond the file."
    finding_source = source_lines[finding_line - 1]

    # Compute the enclosing-function indentation, NOT the finding line's
    # indentation. The finding may be inside a `with` block at a deeper
    # indent; inserting the guard there would put it inside the `with`,
    # which is wrong (the guard must run unconditionally when the function
    # is called, not conditionally on entering the `with`).
    func_indent_str = _enclosing_function_indent(source_lines, finding_line)
    if func_indent_str is None:
        # Couldn't determine — fall back to the finding line's indentation.
        # This preserves the previous (imperfect) behaviour for module-level
        # sinks and other edge cases the AST walk doesn't handle.
        indent = len(finding_source) - len(finding_source.lstrip())
        func_indent_str = " " * indent

    # Build the guard line(s). For actenon mode, this includes an import
    # that must be hoisted to the top of the file.
    if mode == "guard":
        guard_call = _build_guard_call(finding, func_indent_str)
        import_lines: list[str] = []
    elif mode == "approval":
        guard_call = _build_approval_call(finding, func_indent_str)
        import_lines = []
    elif mode == "actenon":
        guard_call, import_lines = _build_actenon_call(finding, func_indent_str)
    else:
        return source_lines, f"Unknown mode: {mode}"

    # Insert the guard before the finding line. Each line is inserted
    # separately so the unified diff marks every line with '+'.
    patched = list(source_lines)
    for i, guard_line in enumerate(guard_call.split("\n")):
        patched.insert(finding_line - 1 + i, guard_line + "\n")

    # Hoist any imports to the top of the file. We insert them after the
    # last existing import (or after the module docstring if no imports).
    if import_lines:
        insert_at = _find_import_insertion_point(patched)
        for i, imp_line in enumerate(import_lines):
            patched.insert(insert_at + i, imp_line + "\n")

    note = f"Inserted {mode} check before line {finding_line}."
    if import_lines:
        note += f" Hoisted {len(import_lines)} import(s) to top of file."
    return patched, note


def _enclosing_function_indent(source_lines: list[str], finding_line: int) -> str | None:
    """Return the indentation string of the function body enclosing the line.

    Returns ``None`` if no enclosing function is found (e.g., module-level
    code) or if the source can't be parsed.
    """
    source = "".join(source_lines)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    # Find the smallest function whose body contains finding_line.
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # node.lineno is the `def` line; the body starts at the first
            # statement's lineno. We want the indent of the body, which is
            # the indent of the first body statement.
            body_start = node.body[0].lineno if node.body else node.lineno + 1
            # Compute body_end from all child nodes that have a lineno /
            # end_lineno. Some AST nodes (e.g. `arguments`) lack these
            # attributes, so we filter them out instead of crashing.
            end_candidates: list[int] = []
            for n in ast.walk(node):
                end_ln = getattr(n, "end_lineno", None)
                if end_ln is None:
                    continue
                end_candidates.append(end_ln)
            body_end = max(end_candidates, default=body_start)
            if body_start <= finding_line <= body_end:
                if best is None or node.lineno > best.lineno:
                    best = node

    if best is None:
        return None

    # The body's first statement's indent is what we want.
    body_first_line_idx = best.body[0].lineno - 1
    if body_first_line_idx >= len(source_lines):
        return None
    line = source_lines[body_first_line_idx]
    indent = len(line) - len(line.lstrip())
    return " " * indent


def _find_import_insertion_point(source_lines: list[str]) -> int:
    """Find the line index where new imports should be inserted.

    Heuristic: after the module docstring (if any) and after the last
    existing top-level import / ``from __future__`` statement. Falls back
    to 0 (top of file) if no imports are found.
    """
    try:
        tree = ast.parse("".join(source_lines))
    except SyntaxError:
        return 0

    last_import_end = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            end_ln = getattr(node, "end_lineno", None) or node.lineno
            last_import_end = max(last_import_end, end_ln)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            # Module docstring — count as a "prefix" too.
            end_ln = getattr(node, "end_lineno", None) or node.lineno
            last_import_end = max(last_import_end, end_ln)

    return last_import_end  # 1-indexed lineno; insert AFTER that line → 0-indexed equals end_lineno


def _build_guard_call(finding, indent: str) -> str:
    """Build a repository-native guard CALL (not just a TODO comment).

    The previous implementation emitted pure comment placeholders, which
    meant `fix --mode guard --apply` wrote two comment lines into the file
    and the finding STILL fired on the next scan. The CLI said "Applied
    guard fix" — misleading.

    Now we emit an actual call (commented out, with a TODO to import or
    define the guard). The user uncomments when ready, but the call is
    already in place at the correct indentation. We do NOT invent an API
    that may not exist — `authorize(...)` is a convention, not a real
    function, so it stays commented until the user wires it up.
    """
    action = finding.category
    lines = [
        f"# TODO: import or define `authorize` (or your repo's guard convention),",
        f"# then uncomment to enforce the check before this consequential action.",
        f"# authorize(action=\"{action}\")  # raises PermissionError if denied",
    ]
    return "\n".join(indent + l for l in lines)


def _build_approval_call(finding, indent: str) -> str:
    """Build a framework-native approval CALL (not just a TODO comment).

    Generates a real `request_approval(...)` call (commented out) plus the
    raise-on-denial pattern. The user uncomments when they wire up the
    approval primitive; the structure is already in place.
    """
    action = finding.category
    lines = [
        f"# Framework-native approval: request human confirmation before",
        f"# this consequential action. Uncomment after wiring up the approval",
        f"# primitive (MCP elicitation, LangChain interrupt, custom UI, etc.).",
        f"# approved = await request_approval(action=\"{action}\")",
        f"# if not approved:",
        f"#     raise PermissionError(\"action not approved\")",
    ]
    return "\n".join(indent + l for l in lines)


def _build_actenon_call(finding, indent: str) -> tuple[str, list[str]]:
    """Build an Actenon kernel proof verification call.

    Enforces: intent + authority -> verifier decision -> ALLOW or typed
    refusal -> side effect. The verification is placed BEFORE the sink.

    Returns ``(guard_call_text, import_lines)``. The import lines are
    hoisted to the top of the file by the caller — never left inline,
    where they would land inside a ``with`` block or function body.

    NOTE: the import uses ``actenon_kernel`` (the real package on PyPI),
    NOT a bare ``actenon`` (which does not exist). The function name is
    ``verify_pccb`` (the actual Kernel API), NOT ``verify_proof``.
    The previous implementation imported from a non-existent package and
    called a non-existent function — `fix --mode actenon --apply` broke
    the user's code with ``ModuleNotFoundError: No module named 'actenon'``.
    """
    action = finding.category
    guard_lines = [
        f"verify_pccb(",
        f"    # proof=...,    # PCCB proof blob from actenon-permit",
        f"    # intent=...,   # the user's authorisation intent",
        f"    action=\"{action}\",",
        f")  # raises typed Refusal if authority is not established",
    ]
    guard_call = "\n".join(indent + l for l in guard_lines)
    import_lines = ["from actenon_kernel import verify_pccb  # pip install actenon-kernel"]
    return guard_call, import_lines


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
