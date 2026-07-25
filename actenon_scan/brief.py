"""Reusable execution-boundary brief foundation.

Work Order 1, Part 6: implements ``actenon-scan brief <file:line>``.

The brief is a one-page execution-boundary report for responsible
outreach. It consumes reusable typed internal representations rather
than duplicating its own analysis. Later work will expose these same
structures through ``actenon-scan explain``, ``actenon-scan fix``,
HTML reports, Markdown reports, and PR comments.

DESIGN CONSTRAINTS (Work Order 1, Part 6.1):
- Analysis and remediation logic MUST NOT live inside the CLI formatter.
- The brief consumes reusable typed internal objects.

SAFETY (Work Order 1, Part 6.6 + RULE 9 + RULE 10):
- The brief MUST NEVER include attack prompts, prompt-injection strings,
  exploitation payloads, credential values, or instructions for
  destructive use.
- It may describe the capability and the boundary failure.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from actenon_scan.detectors.sinks import (
    ReceiverOrigin,
    _build_import_aliases,
    _build_self_attr_origins,
    _build_var_type_map,
    _resolve_receiver_origin,
)


# ---------------------------------------------------------------------------
# Reusable typed internal representations (Part 6.1).
#
# These are the stable internal objects that the brief, explain, fix,
# HTML/Markdown reporters, and PR-comment renderer will all consume.
# Keeping them in a separate module (not inside the CLI formatter) is the
# explicit design constraint from Part 6.1.
# ---------------------------------------------------------------------------


@dataclass
class FindingIdentity:
    """Stable identity of a finding."""

    rule_id: str
    file: str
    line: int
    col: int


@dataclass
class RepositoryLocation:
    """Repository / file / line."""

    file: str
    line: int
    col: int = 0
    repository: str = ""


@dataclass
class AgentEntryPoint:
    """The agent entry point that reaches the sink."""

    function_name: str
    decorator: str = ""  # e.g., "@mcp.tool()", "@tool", "@function_tool"
    is_reachable: bool = True


@dataclass
class ReceiverChain:
    """Resolved receiver-origin chain."""

    expression: str
    origin: str
    chain: list[str]
    confidence: str  # "strong" | "heuristic" | "unknown"


@dataclass
class CallerControlledParameter:
    """A model-controlled parameter that reaches the sink."""

    name: str
    position: int | None = None
    keyword: str | None = None


@dataclass
class ConsequentialSink:
    """The consequential action (sink)."""

    rule_id: str
    category: str
    severity: str
    confidence: str
    description: str
    call_text: str


@dataclass
class ExistingCheck:
    """An existing authority check found in the analysed path."""

    kind: str  # e.g., "guard", "actenon_proof", "if-condition"
    description: str
    dominates: bool = False
    reason: str = ""


@dataclass
class GuardDominanceResult:
    """Whether existing checks establish authority at the execution edge."""

    dominated: bool
    checks: list[ExistingCheck] = field(default_factory=list)
    reason: str = ""


@dataclass
class DataFlowSummary:
    """input -> handler -> execution function -> side effect."""

    input_step: str = ""
    handler_step: str = ""
    execution_step: str = ""
    side_effect_step: str = ""


@dataclass
class ExpectedBoundary:
    """intent + authority -> ALLOW or typed refusal -> side effect."""

    description: str = (
        "intent + authority -> ALLOW or typed refusal -> side effect"
    )


@dataclass
class RemediationOption:
    """One minimal remediation option."""

    rank: int
    kind: str  # "repository_guard" | "framework_approval" | "actenon_proof"
    description: str


@dataclass
class Limitations:
    """What the scan does NOT establish (Part 6.3)."""

    text: str = (
        "The scan established that a model-controlled or agent-controlled "
        "parameter reaches a recognised consequential action and that no "
        "dominating authority check was identified in the analysed path.\n"
        "It did not establish that the agent is externally reachable, that "
        "no guard exists elsewhere in the system, that exploitation is "
        "practical, or that the action is irreversible."
    )


@dataclass
class Brief:
    """A complete execution-boundary brief (Part 6.2)."""

    identity: FindingIdentity
    location: RepositoryLocation
    agent_entry_point: AgentEntryPoint
    sink: ConsequentialSink
    receiver_chain: ReceiverChain | None
    caller_controlled_parameters: list[CallerControlledParameter]
    existing_checks: GuardDominanceResult
    data_flow: DataFlowSummary
    expected_boundary: ExpectedBoundary
    remediation_options: list[RemediationOption]
    limitations: Limitations

    # Convenience: how the model reaches the operation.
    def reach_summary(self) -> str:
        if self.agent_entry_point.decorator:
            return (
                f"The sink is reached through `{self.agent_entry_point.decorator}` "
                f"on `{self.agent_entry_point.function_name}`. The model selects "
                f"and invokes this entry point; its parameters flow to the sink."
            )
        return (
            f"The sink is reached through `{self.agent_entry_point.function_name}`. "
            f"The model selects and invokes this entry point; its parameters flow "
            f"to the sink."
        )


# ---------------------------------------------------------------------------
# Safety filter (Part 6.6 + RULE 9 + RULE 10).
# ---------------------------------------------------------------------------

# Patterns that MUST NOT appear in any brief output. The brief describes
# the capability and the boundary failure; it never includes attack
# material or credentials.
#
# Each pattern is paired with a replacement template. The replacement
# preserves the KEY name (e.g., `api_key`, `Authorization`) so the brief
# can still reference the parameter, but redacts the VALUE.
_FORBIDDEN_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Credential-looking assignments: api_key = "sk-...", token = "Bearer ..."
    # Replacement: api_key = "<redacted>"
    (
        re.compile(r'(api_key|token|password|passwd|secret|bearer)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        r'\1 = "<redacted>"',
    ),
    # Credential-looking dict entries: {"api_key": "sk-...", "token": "..."}
    # Replacement: {"api_key": "<redacted>"}
    (
        re.compile(r'(api_key|token|password|passwd|secret)\s*:\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        r'\1: "<redacted>"',
    ),
    # Authorization / Bearer / Basic headers with literal values.
    # Matches: Authorization: "Bearer sk-...", Bearer sk-...,
    #          Authorization: Basic <long-string>
    # Replacement: Authorization: "<redacted>"
    (
        re.compile(r'(Authorization|Bearer|Basic)(\s*[:\s]+\s*)["\']?[A-Za-z0-9_\-\.=+/]{8,}["\']?', re.IGNORECASE),
        r'\1: "<redacted>"',
    ),
]


def _redact_forbidden(text: str) -> str:
    """Redact credential values and forbidden patterns from brief text.

    Replaces matched substrings with `<redacted>` while preserving the
    key name (e.g., `api_key`, `Authorization`) so the brief can still
    reference the parameter.
    """
    for pattern, replacement in _FORBIDDEN_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _assert_safe(text: str) -> None:
    """Assert that brief text contains no forbidden patterns.

    Called by formatters to confirm the safety filter is effective. If a
    credential value survived redaction, this raises — the brief MUST
    NOT be emitted with credentials in it.
    """
    for pattern, _ in _FORBIDDEN_PATTERNS:
        m = pattern.search(text)
        if m:
            raise AssertionError(
                f"Brief output contains a forbidden pattern (credentials/attacks). "
                f"This violates Work Order 1 Part 6.6 + RULE 9 + RULE 10. "
                f"Matched: {m.group(0)[:60]}..."
            )


# ---------------------------------------------------------------------------
# Brief construction.
# ---------------------------------------------------------------------------


def build_brief(
    file_path: str | Path,
    line: int,
    rule_id: str | None = None,
) -> Brief | None:
    """Build a brief for the finding at ``file_path:line``.

    If ``rule_id`` is given, the finding at that line with the matching
    rule is used. Otherwise the first finding at that line is used.

    Returns ``None`` if no finding exists at the given location.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return None

    # Scan the single file to find findings at the requested line.
    from actenon_scan.engine import scan_path
    result = scan_path(file_path)
    candidates = [
        f for f in result.findings
        if f.line == line and not f.suppressed
    ]
    if rule_id:
        candidates = [f for f in candidates if f.rule_id == rule_id]
    if not candidates:
        return None
    finding = candidates[0]

    # Parse the file to gather context (receiver chain, enclosing function,
    # caller-controlled parameters, existing checks).
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError):
        tree = ast.Module(body=[], type_ignores=[])

    var_types = _build_var_type_map(tree)
    self_attrs = _build_self_attr_origins(tree)
    aliases = _build_import_aliases(tree)

    # Find the call node at the requested line.
    call_node = _find_call_at_line(tree, line)
    receiver_chain = None
    if call_node is not None and isinstance(call_node.func, ast.Attribute):
        origin = _resolve_receiver_origin(
            call_node.func.value, var_types, self_attrs, aliases,
        )
        if origin is not None:
            receiver_chain = ReceiverChain(
                expression=origin.expression,
                origin=origin.origin,
                chain=origin.chain,
                confidence=origin.confidence,
            )

    # Find the enclosing function (agent entry point).
    enclosing = _find_enclosing_function(tree, line)
    agent_entry = AgentEntryPoint(
        function_name=enclosing.name if enclosing else "<module-level>",
        decorator=_decorator_name(enclosing) if enclosing else "",
        is_reachable=enclosing is not None,
    )

    # Caller-controlled parameters: parameters of the enclosing function
    # that appear in the call's arguments.
    cc_params: list[CallerControlledParameter] = []
    if call_node is not None and enclosing is not None:
        param_names = {a.arg for a in enclosing.args.args}
        param_names |= {a.arg for a in enclosing.args.posonlyargs}
        param_names |= {a.arg for a in enclosing.args.kwonlyargs}
        for i, arg in enumerate(call_node.args):
            if _expr_references_param(arg, param_names):
                cc_params.append(CallerControlledParameter(
                    name=_expr_short_name(arg), position=i,
                ))
        for kw in call_node.keywords:
            if kw.arg and _expr_references_param(kw.value, param_names):
                cc_params.append(CallerControlledParameter(
                    name=kw.arg, keyword=kw.arg,
                ))

    # Existing checks: look for guard patterns / actenon proof calls in
    # the enclosing function body BEFORE the sink line.
    existing_checks: list[ExistingCheck] = []
    if enclosing is not None:
        for node in ast.walk(enclosing):
            if isinstance(node, ast.Call) and hasattr(node, "lineno") and node.lineno < line:
                check = _identify_check(node)
                if check is not None:
                    existing_checks.append(check)
    guard_result = GuardDominanceResult(
        dominated=any(c.dominates for c in existing_checks),
        checks=existing_checks,
        reason=(
            "A dominating authority check was identified in the analysed path."
            if any(c.dominates for c in existing_checks)
            else "No dominating authority check was identified in the analysed path."
        ),
    )

    # Data flow summary.
    data_flow = DataFlowSummary(
        input_step=f"tool parameters ({', '.join(p.name for p in cc_params) or 'none identified'})",
        handler_step=agent_entry.function_name,
        execution_step=finding.call_text[:60],
        side_effect_step=finding.category,
    )

    # Remediation options (Part 6.4 — always in this order).
    remediation = [
        RemediationOption(
            rank=1,
            kind="repository_guard",
            description=(
                "Add a repository-native guard convention (e.g., a branch "
                "protection rule, a CODEOWNERS check, or a pre-merge status "
                "check) that must pass before the mutation is allowed. "
                "Prefer the convention the repository already uses."
            ),
        ),
        RemediationOption(
            rank=2,
            kind="framework_approval",
            description=(
                "Add a framework-native approval or human gate (e.g., a "
                "confirmation step, a two-person rule, or a workflow pause) "
                "between the model's request and the sink. Prefer the gate "
                "the agent framework already provides."
            ),
        ),
        RemediationOption(
            rank=3,
            kind="actenon_proof",
            description=(
                "Bind the sink to an Actenon proof verification: require a "
                "signed authorised execution intent before the sink runs, "
                "and emit a receipt. This is the most invasive option and "
                "is recommended only when the first two are not available."
            ),
        ),
    ]

    return Brief(
        identity=FindingIdentity(
            rule_id=finding.rule_id,
            file=str(file_path),
            line=finding.line,
            col=finding.col,
        ),
        location=RepositoryLocation(
            file=str(file_path),
            line=finding.line,
            col=finding.col,
        ),
        agent_entry_point=agent_entry,
        sink=ConsequentialSink(
            rule_id=finding.rule_id,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            description=finding.description,
            call_text=finding.call_text,
        ),
        receiver_chain=receiver_chain,
        caller_controlled_parameters=cc_params,
        existing_checks=guard_result,
        data_flow=data_flow,
        expected_boundary=ExpectedBoundary(),
        remediation_options=remediation,
        limitations=Limitations(),
    )


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _find_call_at_line(tree: ast.Module, line: int) -> ast.Call | None:
    """Find the first Call node whose lineno matches ``line``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and hasattr(node, "lineno") and node.lineno == line:
            return node
    return None


def _find_enclosing_function(
    tree: ast.Module, line: int
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find the function that encloses the given line."""
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if hasattr(node, "lineno") and node.lineno <= line:
                end = getattr(node, "end_lineno", node.lineno)
                if line <= end:
                    if best is None or node.lineno > best.lineno:
                        best = node
    return best


def _decorator_name(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Get the first decorator name (e.g., '@mcp.tool')."""
    if not func.decorator_list:
        return ""
    d = func.decorator_list[0]
    if isinstance(d, ast.Call):
        target = d.func
    else:
        target = d
    if isinstance(target, ast.Name):
        return f"@{target.id}"
    if isinstance(target, ast.Attribute):
        parts = []
        cur = target
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return "@" + ".".join(reversed(parts))
    return ""


def _expr_references_param(node: ast.expr, param_names: set[str]) -> bool:
    """Check if an expression references any of the given parameter names."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in param_names:
            return True
    return False


def _expr_short_name(node: ast.expr) -> str:
    """Short name for a caller-controlled argument."""
    if isinstance(node, ast.Name):
        return node.id
    try:
        return ast.unparse(node)[:30]
    except Exception:
        return "<expr>"


# ---------------------------------------------------------------------------
# Check identification.
# ---------------------------------------------------------------------------

# Heuristics for identifying authority checks. These are intentionally
# conservative — we only mark a check as DOMINATING when it clearly
# establishes authority (e.g., an Actenon proof verification call).
_ACTENON_PROOF_NAMES = frozenset({
    "verify_proof", "verify_authorised_execution_intent",
    "actenon.verify", "actenon.verify_proof",
})


def _identify_check(node: ast.Call) -> ExistingCheck | None:
    """Identify whether a call is an authority check.

    Returns ``None`` if the call is not a recognised check. Returns an
    ``ExistingCheck`` with ``dominates=True`` only for checks that
    clearly establish authority at the execution edge (e.g., an Actenon
    proof verification).
    """
    # Get the call name.
    if isinstance(node.func, ast.Name):
        name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        # Walk the attribute chain.
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        name = ".".join(reversed(parts))
    else:
        return None

    low = name.lower()

    # Actenon proof verification — dominates.
    for proof_name in _ACTENON_PROOF_NAMES:
        if low == proof_name.lower() or low.endswith("." + proof_name.lower()):
            return ExistingCheck(
                kind="actenon_proof",
                description=f"Actenon proof verification call: `{name}(...)`",
                dominates=True,
                reason="An Actenon proof verification establishes cryptographic authority before the sink.",
            )

    # Recognised guard-pattern names (non-dominating unless we can verify
    # the body — we can't in this file-local analysis, so we record them
    # as non-dominating).
    guard_names = {"authorize", "check_permission", "require_permission",
                   "can_edit", "can_delete", "has_permission", "is_authorized"}
    final = low.rsplit(".", 1)[-1]
    if final in guard_names:
        return ExistingCheck(
            kind="guard",
            description=f"Permission check: `{name}(...)`",
            dominates=False,
            reason="A named permission check is present, but its body cannot be verified in file-local analysis. It is recorded but not treated as dominating.",
        )

    return None


# ---------------------------------------------------------------------------
# Formatters (Part 6.5 — text + markdown).
# ---------------------------------------------------------------------------


def format_brief_text(brief: Brief) -> str:
    """Format a brief as plain text suitable for email."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("ACTENON EXECUTION-BOUNDARY BRIEF")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Repository / file / line:")
    lines.append(f"  {brief.location.file}:{brief.location.line}")
    lines.append("")
    lines.append(f"Consequential action:")
    lines.append(f"  Rule: {brief.sink.rule_id}")
    lines.append(f"  Category: {brief.sink.category}")
    lines.append(f"  Severity: {brief.sink.severity} (confidence: {brief.sink.confidence})")
    lines.append(f"  Description: {brief.sink.description}")
    lines.append(f"  Call: {brief.sink.call_text}")
    lines.append("")
    lines.append(f"Agent entry point:")
    dec = f" decorated with {brief.agent_entry_point.decorator}" if brief.agent_entry_point.decorator else ""
    lines.append(f"  Function: {brief.agent_entry_point.function_name}{dec}")
    lines.append("")
    lines.append(f"How the model reaches the operation:")
    lines.append(f"  {brief.reach_summary()}")
    lines.append("")
    lines.append(f"Caller-controlled parameters:")
    if brief.caller_controlled_parameters:
        for p in brief.caller_controlled_parameters:
            loc = f"position {p.position}" if p.position is not None else f"keyword {p.keyword}"
            lines.append(f"  - {p.name} ({loc})")
    else:
        lines.append(f"  (none identified in the analysed path)")
    lines.append("")
    lines.append(f"Receiver and execution path:")
    if brief.receiver_chain:
        lines.append(f"  Expression: {brief.receiver_chain.expression}")
        lines.append(f"  Origin: {brief.receiver_chain.origin}")
        lines.append(f"  Chain: {' -> '.join(brief.receiver_chain.chain) or '(single hop)'}")
        lines.append(f"  Confidence: {brief.receiver_chain.confidence}")
    else:
        lines.append(f"  (receiver origin not resolved — bare name or module attribute)")
    lines.append("")
    lines.append(f"Existing checks found:")
    if brief.existing_checks.checks:
        for c in brief.existing_checks.checks:
            dom = " [DOMINATING]" if c.dominates else ""
            lines.append(f"  - {c.kind}{dom}: {c.description}")
            lines.append(f"    {c.reason}")
    else:
        lines.append(f"  (none identified in the analysed path)")
    lines.append("")
    lines.append(f"Why those checks do or do not establish authority:")
    lines.append(f"  {brief.existing_checks.reason}")
    lines.append("")
    lines.append(f"Data flow:")
    lines.append(f"  input: {brief.data_flow.input_step}")
    lines.append(f"  -> handler: {brief.data_flow.handler_step}")
    lines.append(f"  -> execution: {brief.data_flow.execution_step}")
    lines.append(f"  -> side effect: {brief.data_flow.side_effect_step}")
    lines.append("")
    lines.append(f"Expected boundary:")
    lines.append(f"  {brief.expected_boundary.description}")
    lines.append("")
    lines.append(f"Minimal remediation options:")
    for opt in brief.remediation_options:
        lines.append(f"  {opt.rank}. {opt.kind}: {opt.description}")
    lines.append("")
    lines.append(f"What this does NOT establish:")
    for para in brief.limitations.text.split("\n"):
        lines.append(f"  {para}")
    lines.append("")
    lines.append("=" * 72)
    out = "\n".join(lines)
    out = _redact_forbidden(out)
    _assert_safe(out)
    return out


def format_brief_markdown(brief: Brief) -> str:
    """Format a brief as Markdown suitable for an issue, advisory, or PR."""
    lines: list[str] = []
    lines.append("# Actenon execution-boundary brief")
    lines.append("")
    lines.append("## Repository / file / line")
    lines.append("")
    lines.append(f"`{brief.location.file}:{brief.location.line}`")
    lines.append("")
    lines.append("## Consequential action")
    lines.append("")
    lines.append(f"- **Rule:** `{brief.sink.rule_id}`")
    lines.append(f"- **Category:** `{brief.sink.category}`")
    lines.append(f"- **Severity:** {brief.sink.severity} (confidence: {brief.sink.confidence})")
    lines.append(f"- **Description:** {brief.sink.description}")
    lines.append(f"- **Call:** `{brief.sink.call_text}`")
    lines.append("")
    lines.append("## Agent entry point")
    lines.append("")
    dec = f" decorated with `{brief.agent_entry_point.decorator}`" if brief.agent_entry_point.decorator else ""
    lines.append(f"`{brief.agent_entry_point.function_name}`{dec}.")
    lines.append("")
    lines.append("## How the model reaches the operation")
    lines.append("")
    lines.append(brief.reach_summary())
    lines.append("")
    lines.append("## Caller-controlled parameters")
    lines.append("")
    if brief.caller_controlled_parameters:
        for p in brief.caller_controlled_parameters:
            loc = f"position `{p.position}`" if p.position is not None else f"keyword `{p.keyword}`"
            lines.append(f"- `{p.name}` ({loc})")
    else:
        lines.append("(none identified in the analysed path)")
    lines.append("")
    lines.append("## Receiver and execution path")
    lines.append("")
    if brief.receiver_chain:
        lines.append(f"- **Expression:** `{brief.receiver_chain.expression}`")
        lines.append(f"- **Origin:** `{brief.receiver_chain.origin}`")
        lines.append(f"- **Chain:** `{'` -> `'.join(brief.receiver_chain.chain) or '(single hop)'}`")
        lines.append(f"- **Confidence:** {brief.receiver_chain.confidence}")
    else:
        lines.append("(receiver origin not resolved — bare name or module attribute)")
    lines.append("")
    lines.append("## Existing checks found")
    lines.append("")
    if brief.existing_checks.checks:
        for c in brief.existing_checks.checks:
            dom = " **[DOMINATING]**" if c.dominates else ""
            lines.append(f"- **{c.kind}**{dom}: {c.description}")
            lines.append(f"  - {c.reason}")
    else:
        lines.append("(none identified in the analysed path)")
    lines.append("")
    lines.append("## Why those checks do or do not establish authority")
    lines.append("")
    lines.append(brief.existing_checks.reason)
    lines.append("")
    lines.append("## Data flow")
    lines.append("")
    lines.append("```")
    lines.append(f"input: {brief.data_flow.input_step}")
    lines.append(f"  -> handler: {brief.data_flow.handler_step}")
    lines.append(f"  -> execution: {brief.data_flow.execution_step}")
    lines.append(f"  -> side effect: {brief.data_flow.side_effect_step}")
    lines.append("```")
    lines.append("")
    lines.append("## Expected boundary")
    lines.append("")
    lines.append("```")
    lines.append(brief.expected_boundary.description)
    lines.append("```")
    lines.append("")
    lines.append("## Minimal remediation options")
    lines.append("")
    for opt in brief.remediation_options:
        lines.append(f"{opt.rank}. **{opt.kind}** — {opt.description}")
    lines.append("")
    lines.append("## What this does NOT establish")
    lines.append("")
    for para in brief.limitations.text.split("\n"):
        if para.strip():
            lines.append(f"> {para}")
        else:
            lines.append(">")
    lines.append("")
    out = "\n".join(lines)
    out = _redact_forbidden(out)
    _assert_safe(out)
    return out
