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

_TS_EXTENSIONS = frozenset({
    ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs",
})


def _extract_transitive_chain(reachability_reason: str) -> str:
    """Extract 'a -> b -> c' call chain from a reachability_reason string, if any."""
    if not reachability_reason:
        return ""
    if reachability_reason.startswith("transitive:"):
        chain = reachability_reason[len("transitive:"):]
        if " [" in chain:
            chain = chain.split(" [", 1)[0]
        return chain.strip()
    marker = "[transitive path:"
    idx = reachability_reason.find(marker)
    if idx != -1:
        rest = reachability_reason[idx + len(marker):]
        end = rest.find("]")
        if end != -1:
            return rest[:end].strip()
    return ""


def _file_has_sink_at_line(fp: Path, line: int) -> bool:
    """Fast single-file precheck: return True only if ``fp`` has any sink at ``line``.

    Prevents unnecessary directory scans when ``build_brief`` or ``generate_fix``
    is called on a line with no sink at all.
    """
    suffix = fp.suffix.lower()
    if suffix == ".py":
        try:
            src = fp.read_text(encoding="utf-8-sig", errors="replace")
            tree = ast.parse(src, filename=str(fp))
            from actenon_scan.detectors.sinks import detect_sinks
            from actenon_scan.rules.loader import load_default_rules

            rules = load_default_rules()
            return any(sf.line == line for sf in detect_sinks(tree, fp.name, rules.sinks))
        except Exception:
            return False
    if suffix in _TS_EXTENSIONS:
        try:
            from actenon_scan.detectors.typescript import discover_all_ts_sinks

            return any(s.get("line") == line for s in discover_all_ts_sinks(fp))
        except Exception:
            return False
    if suffix == ".go":
        try:
            from actenon_scan.detectors.go import discover_all_go_sinks

            return any(s.get("line") == line for s in discover_all_go_sinks(fp.name, fp.read_bytes()))
        except Exception:
            return False
    return False


def _infer_project_root(fp: Path) -> Path | None:
    """Infer enclosing project root for cross-file transitive finding lookup."""
    import tempfile

    resolved = fp.resolve()
    stop_dirs = {
        Path("/").resolve(),
        Path(tempfile.gettempdir()).resolve(),
    }
    try:
        stop_dirs.add(Path.home().resolve())
    except RuntimeError:
        pass

    markers = (
        ".actenon-scan.json",
        ".actenon-scan.yml",
        ".actenon-scan.yaml",
        "pyproject.toml",
        "package.json",
        "go.mod",
        ".git",
    )
    ancestors: list[Path] = []
    cur = resolved.parent
    for _ in range(6):
        if cur in stop_dirs or cur.parent == cur:
            break
        ancestors.append(cur)
        cur = cur.parent

    for anc in ancestors:
        if any((anc / m).exists() for m in markers):
            return anc

    # Temp-repo / markerless package fallback: walk up at most 2 levels while
    # siblings look like part of the same source tree.
    best: Path | None = None
    for depth, anc in enumerate(ancestors[:3]):
        if depth == 0:
            best = anc
            continue
        has_sources = any(
            any(anc.glob(pat))
            for pat in ("*.py", "*.ts", "*.tsx", "*.js", "*.go", "__init__.py")
        )
        if has_sources:
            best = anc
        else:
            break
    return best


def find_finding_at_location(
    file_path: str | Path,
    line: int,
    rule_id: str | None = None,
):
    """Locate an active Finding at ``file_path:line``, including cross-file transitive ones."""
    from actenon_scan.engine import scan_path

    fp = Path(file_path)
    if not fp.exists():
        return None

    result = scan_path(fp)
    candidates = [
        f for f in result.findings
        if f.line == line and not f.suppressed
    ]
    if rule_id:
        candidates = [f for f in candidates if f.rule_id == rule_id]
    if candidates:
        return candidates[0]

    # Cross-file fallback: only scan the enclosing project when this exact line
    # actually contains a consequential sink call.
    if not _file_has_sink_at_line(fp, line):
        return None
    project_root = _infer_project_root(fp)
    if project_root is None or not project_root.is_dir():
        return None

    resolved_fp = fp.resolve()
    dir_result = scan_path(project_root)
    dir_candidates = []
    for f in dir_result.findings:
        if f.line != line or f.suppressed:
            continue
        f_resolved = (project_root / f.file).resolve()
        if f_resolved == resolved_fp:
            dir_candidates.append(f)
    if rule_id:
        dir_candidates = [f for f in dir_candidates if f.rule_id == rule_id]
    if not dir_candidates:
        return None
    matched = dir_candidates[0]
    matched.file = str(fp)
    return matched


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
    finding = find_finding_at_location(file_path, line, rule_id=rule_id)
    if finding is None:
        return None

    # Parse the file to gather context (receiver chain, enclosing function,
    # caller-controlled parameters, existing checks).
    #
    # ITEM 3: Go and TypeScript/JS files can't be parsed by Python's ast module.
    # Use tree-sitter to extract the enclosing function name, caller-controlled
    # parameters, and guard evidence.
    if file_path.suffix.lower() == ".go":
        return _build_go_brief(finding, file_path, line)
    if file_path.suffix.lower() in _TS_EXTENSIONS:
        return _build_ts_brief(finding, file_path, line)

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
    transitive_chain = _extract_transitive_chain(getattr(finding, "reachability_reason", "") or "")
    entry_func_name = enclosing.name if enclosing else "<module-level>"
    entry_decorator = _decorator_name(enclosing) if enclosing else ""
    if transitive_chain and not entry_decorator:
        hops = [h.strip() for h in re.split(r"\s*(?:->|→)\s*", transitive_chain) if h.strip()]
        if hops:
            entry_func_name = hops[0]
            entry_decorator = f"transitive call ({transitive_chain})"
    agent_entry = AgentEntryPoint(
        function_name=entry_func_name,
        decorator=entry_decorator,
        is_reachable=(enclosing is not None) or bool(transitive_chain),
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
    reach_reason_str = getattr(finding, "reachability_reason", "") or ""
    if "does NOT authorize" in reach_reason_str and not existing_checks:
        existing_checks.append(ExistingCheck(
            kind="non_authorizing_check",
            description="Authentication or input validation check",
            dominates=False,
            reason="Authentication/validation checks identity or shape, not authorization for this action.",
        ))
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
    handler_step = transitive_chain if transitive_chain else agent_entry.function_name
    data_flow = DataFlowSummary(
        input_step=f"tool parameters ({', '.join(p.name for p in cc_params) or 'none identified'})",
        handler_step=handler_step,
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
# TypeScript / JavaScript brief construction.
# ---------------------------------------------------------------------------


def _ts_walk(node):
    yield node
    for child in node.children:
        yield from _ts_walk(child)


def _ts_extract_param_identifiers(params_node, source_bytes: bytes) -> set[str]:
    """Extract parameter identifier names (including destructured object properties)."""
    names: set[str] = set()
    if params_node is None:
        return names
    for sub in _ts_walk(params_node):
        if sub.type in ("identifier", "shorthand_property_identifier_pattern"):
            # Skip type annotations
            parent = sub.parent
            if parent is not None and parent.type in ("type_identifier", "type_annotation", "predefined_type"):
                continue
            txt = source_bytes[sub.start_byte:sub.end_byte].decode("utf-8", errors="replace").strip()
            if txt and txt not in ("this",):
                names.add(txt)
    return names


def _build_ts_brief(finding, file_path: Path, line: int) -> Brief | None:
    """Build a brief for a TypeScript/JavaScript finding using tree-sitter."""
    try:
        from actenon_scan.detectors.typescript import (
            is_typescript_extra_available,
            _check_ts_guard,
            _find_enclosing_ts_function,
            _find_call_at_line as _ts_find_call_at_line,
        )
    except ImportError:
        return _build_minimal_ts_brief(finding, file_path, line)

    if not is_typescript_extra_available():
        return _build_minimal_ts_brief(finding, file_path, line)

    try:
        import tree_sitter_typescript as tst
        from tree_sitter import Language, Parser
    except ImportError:
        return _build_minimal_ts_brief(finding, file_path, line)

    source_bytes = file_path.read_bytes()
    is_tsx = file_path.suffix.lower() in (".tsx", ".jsx")
    lang = Language(tst.language_tsx() if is_tsx else tst.language_typescript())
    parser = Parser(lang)
    tree = parser.parse(source_bytes)

    enclosing_func = _find_enclosing_ts_function(tree, line)
    sink_call = _ts_find_call_at_line(tree, line, source_bytes)

    func_name = ""
    if enclosing_func is not None:
        name_node = enclosing_func.child_by_field_name("name")
        if name_node is not None:
            func_name = source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        elif enclosing_func.parent is not None and enclosing_func.parent.type == "variable_declarator":
            vn = enclosing_func.parent.child_by_field_name("name")
            if vn is not None:
                func_name = source_bytes[vn.start_byte:vn.end_byte].decode("utf-8", errors="replace")
        elif enclosing_func.parent is not None and enclosing_func.parent.type == "pair":
            kn = enclosing_func.parent.child_by_field_name("key")
            if kn is not None:
                func_name = source_bytes[kn.start_byte:kn.end_byte].decode("utf-8", errors="replace")

    reach_reason = getattr(finding, "reachability_reason", "") or ""
    transitive_chain = _extract_transitive_chain(reach_reason)
    if not func_name:
        if transitive_chain:
            hops = [h.strip() for h in transitive_chain.split("->") if h.strip()]
            func_name = hops[-1] if hops else "agent tool"
        else:
            func_name = "inline tool handler"

    cc_params: list[CallerControlledParameter] = []
    if enclosing_func is not None and sink_call is not None:
        params_node = enclosing_func.child_by_field_name("parameters") or enclosing_func.child_by_field_name("parameter")
        param_names = _ts_extract_param_identifiers(params_node, source_bytes)
        sink_args = sink_call.child_by_field_name("arguments")
        if sink_args is not None and param_names:
            seen_params: set[str] = set()
            for idx, arg in enumerate(sink_args.named_children):
                arg_ids = {
                    source_bytes[sub.start_byte:sub.end_byte].decode("utf-8", errors="replace")
                    for sub in _ts_walk(arg)
                    if sub.type in ("identifier", "shorthand_property_identifier")
                }
                for pn in sorted(param_names & arg_ids):
                    if pn not in seen_params:
                        seen_params.add(pn)
                        cc_params.append(CallerControlledParameter(name=pn, position=idx))

    existing_checks: list[ExistingCheck] = []
    guard_dominated = False
    if enclosing_func is not None and sink_call is not None:
        from actenon_scan.rules.loader import load_default_rules

        rules = load_default_rules()
        gs, gm = _check_ts_guard(
            enclosing_func, sink_call, tree.root_node, source_bytes, rules.guard_patterns
        )
        if gs == "guarded":
            guard_dominated = True
            existing_checks.append(ExistingCheck(
                kind="guard",
                description=gm,
                dominates=True,
                reason="TypeScript guard check: dominates + parameter-bound + result used",
            ))
        elif gs == "weak":
            existing_checks.append(ExistingCheck(
                kind="guard",
                description=gm,
                dominates=False,
                reason="TypeScript guard check: guard found but return value discarded (-WEAK)",
            ))
        elif gs == "unbound":
            existing_checks.append(ExistingCheck(
                kind="guard",
                description=gm,
                dominates=False,
                reason="TypeScript guard check: guard found but not parameter-bound (-UNBOUND)",
            ))

    guard_result = GuardDominanceResult(
        dominated=guard_dominated,
        checks=existing_checks,
        reason=(
            "A dominating authority check was identified in the analysed path."
            if guard_dominated
            else "No dominating authority check was identified in the analysed path."
        ),
    )

    entry_func = func_name
    decorator = ""
    if transitive_chain:
        hops = [h.strip() for h in transitive_chain.split("->") if h.strip()]
        if hops:
            entry_func = hops[0]
        decorator = f"transitive call ({transitive_chain})"
    elif "tool_registration" in reach_reason:
        decorator = f"tool registration ({reach_reason})"
    elif reach_reason:
        decorator = reach_reason

    agent_entry = AgentEntryPoint(
        function_name=entry_func,
        decorator=decorator,
        is_reachable=True,
    )

    handler_step = transitive_chain if transitive_chain else func_name
    data_flow = DataFlowSummary(
        input_step=f"tool parameters ({', '.join(p.name for p in cc_params) or 'none identified'})",
        handler_step=handler_step,
        execution_step=finding.call_text[:60],
        side_effect_step=finding.category,
    )

    remediation = [
        RemediationOption(
            rank=1, kind="repository_guard",
            description="Add a repository-native guard convention that must pass before the mutation is allowed.",
        ),
        RemediationOption(
            rank=2, kind="framework_approval",
            description="Add a framework-native approval or human gate between the model's request and the sink.",
        ),
        RemediationOption(
            rank=3, kind="actenon_proof",
            description="Bind the sink to an Actenon proof verification.",
        ),
    ]

    return Brief(
        identity=FindingIdentity(
            rule_id=finding.rule_id, file=str(file_path), line=finding.line, col=finding.col,
        ),
        location=RepositoryLocation(file=str(file_path), line=finding.line, col=finding.col),
        agent_entry_point=agent_entry,
        sink=ConsequentialSink(
            rule_id=finding.rule_id, category=finding.category, severity=finding.severity,
            confidence=finding.confidence, description=finding.description, call_text=finding.call_text,
        ),
        receiver_chain=None,
        caller_controlled_parameters=cc_params,
        existing_checks=guard_result,
        data_flow=data_flow,
        expected_boundary=ExpectedBoundary(),
        remediation_options=remediation,
        limitations=Limitations(),
    )


def _build_minimal_ts_brief(finding, file_path: Path, line: int) -> Brief:
    """Build a minimal brief when tree-sitter-typescript is not available."""
    reach_reason = getattr(finding, "reachability_reason", "") or ""
    transitive_chain = _extract_transitive_chain(reach_reason)
    decorator = f"transitive call ({transitive_chain})" if transitive_chain else reach_reason
    return Brief(
        identity=FindingIdentity(
            rule_id=finding.rule_id, file=str(file_path), line=finding.line, col=finding.col,
        ),
        location=RepositoryLocation(file=str(file_path), line=finding.line, col=finding.col),
        agent_entry_point=AgentEntryPoint(
            function_name="(tree-sitter-typescript not installed)",
            decorator=decorator,
            is_reachable=True,
        ),
        sink=ConsequentialSink(
            rule_id=finding.rule_id, category=finding.category, severity=finding.severity,
            confidence=finding.confidence, description=finding.description, call_text=finding.call_text,
        ),
        receiver_chain=None,
        caller_controlled_parameters=[],
        existing_checks=GuardDominanceResult(
            dominated=False,
            checks=[],
            reason="No dominating authority check was identified in the analysed path.",
        ),
        data_flow=DataFlowSummary(
            input_step="tool parameters (none identified)",
            handler_step=transitive_chain or "agent handler",
            execution_step=finding.call_text[:60],
            side_effect_step=finding.category,
        ),
        expected_boundary=ExpectedBoundary(),
        remediation_options=[
            RemediationOption(
                rank=1, kind="repository_guard",
                description="Add a repository-native guard convention that must pass before the mutation is allowed.",
            ),
            RemediationOption(
                rank=2, kind="framework_approval",
                description="Add a framework-native approval or human gate between the model's request and the sink.",
            ),
            RemediationOption(
                rank=3, kind="actenon_proof",
                description="Bind the sink to an Actenon proof verification.",
            ),
        ],
        limitations=Limitations(),
    )


# ---------------------------------------------------------------------------
# Go-specific brief construction (ITEM 3).
# ---------------------------------------------------------------------------


def _build_go_brief(finding, file_path: Path, line: int) -> Brief | None:
    """Build a brief for a Go finding using tree-sitter instead of Python ast.

    Go files can't be parsed by Python's ast module. This function uses
    the tree-sitter-based Go detector to extract:
    - The enclosing function name (fixes the "<module-level>" placeholder)
    - Caller-controlled parameters (fixes the explain/scan contradiction)
    - Guard evidence (using the Go guard check from go.py)
    """
    try:
        from actenon_scan.detectors.go import (
            is_go_extra_available,
            _check_go_guard,
            _iter_functions,
            _iter_calls,
            _get_func_name,
            _walk,
        )
    except ImportError:
        return _build_minimal_go_brief(finding, file_path, line)

    if not is_go_extra_available():
        return _build_minimal_go_brief(finding, file_path, line)

    try:
        import tree_sitter_go as tsgo
        from tree_sitter import Language, Parser
    except ImportError:
        return _build_minimal_go_brief(finding, file_path, line)

    source_bytes = file_path.read_bytes()
    lang = Language(tsgo.language())
    parser = Parser(lang)
    tree = parser.parse(source_bytes)

    # Find the enclosing function and the sink call at the requested line.
    func_name = ""
    enclosing_func = None
    sink_call = None
    for func_node in _iter_functions(tree.root_node):
        start_line = func_node.start_point[0] + 1
        end_line = func_node.end_point[0] + 1
        if start_line <= line <= end_line:
            enclosing_func = func_node
            func_name = _get_func_name(func_node, source_bytes)
            # Find the call at the requested line within this function
            for call_node in _iter_calls(func_node):
                if call_node.start_point[0] + 1 == line:
                    sink_call = call_node
                    break
            break

    # If we didn't find the function, fall back to the finding's
    # reachability_reason.
    if not func_name:
        func_name = getattr(finding, "reachability_reason", "") or "agent tool"

    # Caller-controlled parameters: extract function parameters and check
    # which appear in the sink call's arguments.
    cc_params: list[CallerControlledParameter] = []
    if enclosing_func is not None and sink_call is not None:
        # Extract Go function parameter names from the parameter_list
        param_names: set[str] = set()
        params = enclosing_func.child_by_field_name("parameters")
        if params:
            for child in params.children:
                if child and child.type == "parameter_declaration":
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        param_names.add(
                            source_bytes[name_node.start_byte:name_node.end_byte]
                            .decode("utf-8", errors="replace")
                        )

        # Check which sink arguments reference these parameters
        sink_args = sink_call.child_by_field_name("arguments")
        if sink_args:
            for i, arg in enumerate(sink_args.children):
                if arg is None:
                    continue
                arg_text = source_bytes[arg.start_byte:arg.end_byte].decode("utf-8", errors="replace").strip()
                # Check if this argument references any parameter
                for pn in param_names:
                    if pn in arg_text:
                        cc_params.append(CallerControlledParameter(
                            name=pn, position=i,
                        ))
                        break

    # Guard evidence: use the Go guard check.
    existing_checks: list[ExistingCheck] = []
    guard_dominated = False
    if enclosing_func is not None and sink_call is not None:
        from actenon_scan.rules.loader import load_default_rules
        rules = load_default_rules()
        gs, gm = _check_go_guard(
            enclosing_func, sink_call, source_bytes, rules.guard_patterns
        )
        if gs == "guarded":
            guard_dominated = True
            existing_checks.append(ExistingCheck(
                kind="guard",
                description=gm,
                dominates=True,
                reason="Go guard check: dominates + bound + result used",
            ))
        elif gs == "weak":
            existing_checks.append(ExistingCheck(
                kind="guard",
                description=gm,
                dominates=False,
                reason="Go guard check: guard found but result discarded",
            ))
        elif gs == "unbound":
            existing_checks.append(ExistingCheck(
                kind="guard",
                description=gm,
                dominates=False,
                reason="Go guard check: guard found but not parameter-bound",
            ))

    guard_result = GuardDominanceResult(
        dominated=guard_dominated,
        checks=existing_checks,
        reason=(
            "A dominating authority check was identified in the analysed path."
            if guard_dominated
            else "No dominating authority check was identified in the analysed path."
        ),
    )

    # Build the agent entry point.
    reach_reason = getattr(finding, "reachability_reason", "") or "agent_framework_import"
    transitive_chain = _extract_transitive_chain(reach_reason)
    decorator = ""
    entry_func = func_name
    if transitive_chain:
        hops = [h.strip() for h in transitive_chain.split("->") if h.strip()]
        if hops:
            entry_func = hops[0]
        decorator = f"transitive call ({transitive_chain})"
    elif "tool_registration" in reach_reason:
        decorator = "tool registration (AddTool/RegisterTool)"
    elif "agent_framework_import" in reach_reason:
        decorator = "agent framework import"

    agent_entry = AgentEntryPoint(
        function_name=entry_func,
        decorator=decorator,
        is_reachable=True,
    )

    # Data flow summary.
    data_flow = DataFlowSummary(
        input_step=f"tool parameters ({', '.join(p.name for p in cc_params) or 'none identified'})",
        handler_step=transitive_chain or func_name,
        execution_step=finding.call_text[:60],
        side_effect_step=finding.category,
    )

    # Remediation options (same as Python).
    remediation = [
        RemediationOption(
            rank=1, kind="repository_guard",
            description="Add a repository-native guard convention that must pass before the mutation is allowed.",
        ),
        RemediationOption(
            rank=2, kind="framework_approval",
            description="Add a framework-native approval or human gate between the model's request and the sink.",
        ),
        RemediationOption(
            rank=3, kind="actenon_proof",
            description="Bind the sink to an Actenon proof verification.",
        ),
    ]

    return Brief(
        identity=FindingIdentity(
            rule_id=finding.rule_id, file=str(file_path), line=finding.line, col=finding.col,
        ),
        location=RepositoryLocation(file=str(file_path), line=finding.line, col=finding.col),
        agent_entry_point=agent_entry,
        sink=ConsequentialSink(
            rule_id=finding.rule_id, category=finding.category, severity=finding.severity,
            confidence=finding.confidence, description=finding.description, call_text=finding.call_text,
        ),
        receiver_chain=None,
        caller_controlled_parameters=cc_params,
        existing_checks=guard_result,
        data_flow=data_flow,
        expected_boundary=ExpectedBoundary(),
        remediation_options=remediation,
        limitations=Limitations(),
    )


def _build_minimal_go_brief(finding, file_path: Path, line: int) -> Brief:
    """Build a minimal brief when tree-sitter-go is not available."""
    reach_reason = getattr(finding, "reachability_reason", "") or "agent_framework_import"
    decorator = ""
    if "tool_registration" in reach_reason:
        decorator = "tool registration (AddTool/RegisterTool)"
    elif "agent_framework_import" in reach_reason:
        decorator = "agent framework import"

    return Brief(
        identity=FindingIdentity(
            rule_id=finding.rule_id, file=str(file_path), line=finding.line, col=finding.col,
        ),
        location=RepositoryLocation(file=str(file_path), line=finding.line, col=finding.col),
        agent_entry_point=AgentEntryPoint(
            function_name="(tree-sitter-go not installed)",
            decorator=decorator,
            is_reachable=True,
        ),
        sink=ConsequentialSink(
            rule_id=finding.rule_id, category=finding.category, severity=finding.severity,
            confidence=finding.confidence, description=finding.description, call_text=finding.call_text,
        ),
        receiver_chain=None,
        caller_controlled_parameters=[],
        existing_checks=GuardDominanceResult(
            dominated=False, checks=[],
            reason="No dominating authority check was identified in the analysed path.",
        ),
        data_flow=DataFlowSummary(
            input_step="tool parameters (none identified)",
            handler_step="(unavailable)",
            execution_step=finding.call_text[:60],
            side_effect_step=finding.category,
        ),
        expected_boundary=ExpectedBoundary(),
        remediation_options=[],
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
# Path context detection (Work Order 4, Part 3).
# ---------------------------------------------------------------------------

# Directory names that signal example/demo code rather than library code.
_EXAMPLE_PATH_SEGMENTS = frozenset({
    "cookbook", "example", "examples", "demo", "demos", "docs",
    "sample", "samples", "tutorial", "playground",
})

# Directory names that signal an approval pattern is in use.
_APPROVAL_PATH_SEGMENTS = frozenset({
    "human_in_the_loop",
})


def _path_context_caveat(file_path: str) -> str | None:
    """Detect whether a finding's path suggests example or demo code.

    Returns a human-readable caveat string, or None if the path doesn't
    match any known pattern.

    This does NOT change severity or suppress the finding. Example code
    can be copied into production and is worth fixing. It changes what
    the finding MEANS and how it should be communicated.
    """
    parts = Path(file_path).parts
    lower_parts = {p.lower() for p in parts}

    matched_example = lower_parts & _EXAMPLE_PATH_SEGMENTS
    matched_approval = lower_parts & _APPROVAL_PATH_SEGMENTS

    if matched_example and matched_approval:
        segments = sorted(matched_example | matched_approval)
        return (
            f"This file is under `{'/'.join(segments)}/` and appears to be "
            f"example code demonstrating an approval pattern. A maintainer "
            f"may reasonably respond that it is illustrative. Confirm "
            f"before sending."
        )
    if matched_example:
        segment = sorted(matched_example)[0]
        return (
            f"This file is under `{segment}/` and appears to be example "
            f"code rather than library code. A maintainer may reasonably "
            f"respond that it is illustrative. Confirm before sending."
        )
    if matched_approval:
        segment = sorted(matched_approval)[0]
        return (
            f"This file is under `{segment}/` which suggests an approval "
            f"pattern is in use. Verify that the approval mechanism is "
            f"not a dominating guard before reporting."
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
    # Path context caveat (Work Order 4, Part 3.1)
    path_caveat = _path_context_caveat(brief.location.file)
    if path_caveat:
        lines.append(f"CONTEXT: {path_caveat}")
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
    lines.append(f"- **Severity:** {brief.sink.severity} (sink match: {brief.sink.confidence})")
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

    # Path context caveat (Work Order 4, Part 3.4)
    path_caveat = _path_context_caveat(brief.location.file)
    if path_caveat:
        lines.append("## Context caveat")
        lines.append("")
        lines.append(f"> {path_caveat}")
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
