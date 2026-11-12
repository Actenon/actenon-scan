"""Engine augmentation: repository-level consequence analysis.

This module runs *after* the per-file scan and *augments* the per-file
findings with cross-file intelligence. It does NOT modify or suppress
existing findings — it only adds new findings (for transitively
reachable sinks the per-file scan missed) and augments existing
findings with call-chain evidence in the ``reachability_reason`` field.

The augmentation is opt-in via the ``repository_analysis`` flag on
``scan_path``. When disabled (the default for now, to preserve
backwards compatibility and avoid fixture-lock changes), the engine
behaves exactly as before.

Conservative properties:

- A sink is only added as a NEW finding if we can prove a transitive
  path from an agent entrypoint to it. The path's certainty is
  emitted; HEURISTIC paths are emitted but explicitly labelled.
- Existing findings are NEVER suppressed by this layer.
- Analysis errors are caught and recorded, never silently swallowed.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from actenon_scan.repository import (
    AnalysisCertainty,
    EffectType,
    RepositoryIndex,
    build_call_graph,
    effect_for_rule_id,
    propagate_effects,
    transitive_reachable,
)
from actenon_scan.repository.call_graph import CallPath
from actenon_scan.repository.symbol_index import (
    ResolutionCertainty,
    Symbol,
    SymbolKind,
)

if TYPE_CHECKING:
    from actenon_scan.engine import Finding, ScanResult
    from actenon_scan.capability import Capability


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class RepositoryAnalysisConfig:
    """Controls for the repository-level augmentation pass.

    Defaults are conservative: enable the augmentation but only emit
    *new* findings when the transitive path is RESOLVED (no heuristic
    edges). HEURISTIC paths are still recorded as evidence on existing
    findings.
    """

    enabled: bool = True
    # If True, emit new findings for transitively-reachable sinks even
    # when the path includes HEURISTIC edges (labelled as such). Default
    # False — only emit when path is fully RESOLVED.
    emit_heuristic_new_findings: bool = False
    # Maximum call-graph depth to explore. 32 is enough for almost all
    # real-world code; deeper than this we mark truncated.
    max_depth: int = 32
    # Maximum effect-propagation iterations (fixed-point bound).
    max_iterations: int = 16


# ---------------------------------------------------------------------------
# Entrypoint discovery
# ---------------------------------------------------------------------------


def _is_tool_decorator(deco_text: str, tool_decorators: list[str]) -> bool:
    """Match a decorator text against the configured tool_decorators list.

    Matches dotted forms (e.g. ``mcp.tool`` matches ``mcp.tool()`` and
    ``mcp.tool(...)``) and suffix matches (e.g. ``tool`` matches
    ``langchain.tools.tool``).
    """
    if not deco_text:
        return False
    # Strip trailing () and any call args
    base = deco_text.split("(", 1)[0].strip()
    if base in tool_decorators:
        return True
    # Suffix match
    for d in tool_decorators:
        if d and (base == d or base.endswith("." + d)):
            return True
    return False


def discover_entrypoints(
    index: RepositoryIndex,
    reachability_cfg: dict,
) -> list[Symbol]:
    """Find all agent-entrypoint symbols in the repository.

    Discovers functions/methods registered via:
      - ``tool_decorators`` (``@tool``, ``@mcp.tool()``, ``@function_tool``, ...)
      - ``tool_base_classes`` + ``tool_methods`` (``BaseTool._run``, ...)
      - ``tool_wrappers`` (``Tool.from_function(fn)``, ``StructuredTool.from_function(fn)``)
      - ``tool_list_params`` (``Agent(tools=[fn])``, ``Runner.run(..., tools=[fn])``)
      - ``dynamic_registration`` (``self.tools.append(self.fn)`` in toolkit ``__init__``)
      - ``raw_tool_schema`` dispatchers (``r07`` JSON-schema tool name dispatch)
      - ``resource_boundary`` decorators when explicitly opted in

    Deliberately excludes module-wide ``agent_framework_import`` so non-tool
    helper functions in files importing an agent SDK never become roots.
    """
    tool_decorators = reachability_cfg.get("tool_decorators", [])
    tool_base_classes = reachability_cfg.get("tool_base_classes", [])
    tool_methods = reachability_cfg.get("tool_methods", [])
    tool_wrappers = reachability_cfg.get("tool_wrappers", [])
    tool_list_params_set = set(reachability_cfg.get("tool_list_params", []))
    resource_decorators = (
        reachability_cfg.get("resource_boundary_decorators", [])
        if reachability_cfg.get("resource_boundary_enabled", False)
        else []
    )

    try:
        from actenon_scan.detectors.reachability import (
            _declared_tool_names,
            _get_call_name,
            _has_resource_boundary_decorator,
            _is_tool_schema_dispatch,
            _reachability_for_func,
        )
    except ImportError:
        _declared_tool_names = None  # type: ignore[assignment]
        _get_call_name = None  # type: ignore[assignment]
        _has_resource_boundary_decorator = None  # type: ignore[assignment]
        _reachability_for_func = None  # type: ignore[assignment]
        _is_tool_schema_dispatch = None  # type: ignore[assignment]

    # Pre-index per-file AST structures in a single walk per file so entrypoint
    # discovery stays O(N) even on multi-thousand-function repositories.
    file_hints: dict[
        str,
        tuple[
            ast.Module,
            dict[tuple[int, str], ast.FunctionDef | ast.AsyncFunctionDef],
            dict[str, ast.ClassDef],
            set[str],
            bool,
            set[str],
        ],
    ] = {}

    def _get_file_hints(file_rel: str):
        cached = file_hints.get(file_rel)
        if cached is not None:
            return cached
        ast_info = index.get_ast(file_rel)
        if ast_info is None:
            return None
        _src, tree = ast_info
        funcs: dict[tuple[int, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
        classes: dict[str, ast.ClassDef] = {}
        refs: set[str] = set()
        has_reg_call = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs[(node.lineno, node.name)] = node
            elif isinstance(node, ast.ClassDef):
                classes[node.name] = node
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                refs.add(node.id)
            elif (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "self"
            ):
                refs.add(node.attr)
            elif isinstance(node, ast.Call) and not has_reg_call:
                if any(kw.arg in tool_list_params_set for kw in node.keywords):
                    has_reg_call = True
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "append":
                    has_reg_call = True
                elif tool_wrappers and _get_call_name is not None:
                    cname = _get_call_name(node.func)
                    if cname and any(w in cname or cname in w for w in tool_wrappers):
                        has_reg_call = True
        schema_names = (
            _declared_tool_names(tree) if _declared_tool_names is not None else set()
        )
        entry = (tree, funcs, classes, refs, has_reg_call, schema_names)
        file_hints[file_rel] = entry
        return entry

    entrypoints: list[Symbol] = []
    seen_qnames: set[str] = set()
    for sym in index.symbols:
        if not sym.is_function_like:
            continue
        # 1. Decorator-based detection
        for dec in sym.decorators:
            if _is_tool_decorator(dec, tool_decorators):
                if sym.qualified_name not in seen_qnames:
                    entrypoints.append(sym)
                    seen_qnames.add(sym.qualified_name)
                break
        if sym.qualified_name in seen_qnames:
            continue

        # 2. Method-of-tool-base-class detection
        if sym.kind in (SymbolKind.METHOD, SymbolKind.ASYNC_METHOD):
            if sym.name in tool_methods and sym.enclosing_class:
                cls_sym = index.lookup_symbol(sym.enclosing_class)
                if cls_sym is not None:
                    cls_hints = _get_file_hints(cls_sym.location.file)
                    if cls_hints is not None:
                        cls_node = cls_hints[2].get(cls_sym.name)
                        if cls_node is not None:
                            for base in cls_node.bases:
                                try:
                                    base_text = ast.unparse(base)
                                except Exception:
                                    base_text = ""
                                if any(
                                    base_text == b
                                    or base_text.endswith("." + b)
                                    for b in tool_base_classes
                                ):
                                    entrypoints.append(sym)
                                    seen_qnames.add(sym.qualified_name)
                                    break
        if sym.qualified_name in seen_qnames:
            continue

        # 3. Structural Python reachability signals (opt-in resource boundary,
        #    wrappers, tools=[...], dynamic registration, raw tool-schema dispatch).
        hints = _get_file_hints(sym.location.file)
        if hints is None:
            continue
        tree, funcs, _classes, refs, has_reg_call, schema_names = hints
        func_node = funcs.get((sym.location.line, sym.name))
        if func_node is None:
            continue

        if (
            resource_decorators
            and func_node.decorator_list
            and _has_resource_boundary_decorator is not None
            and _has_resource_boundary_decorator(func_node, resource_decorators)
        ):
            entrypoints.append(sym)
            seen_qnames.add(sym.qualified_name)
            continue

        if (
            has_reg_call
            and sym.name in refs
            and _reachability_for_func is not None
        ):
            rr = _reachability_for_func(
                tree, func_node, reachability_cfg, None, sym.location.line
            )
            if rr.confidence == "high":
                entrypoints.append(sym)
                seen_qnames.add(sym.qualified_name)
                continue

        if schema_names and _is_tool_schema_dispatch is not None:
            for cnode in ast.walk(func_node):
                if isinstance(cnode, ast.Call) and getattr(cnode, "lineno", None):
                    if _is_tool_schema_dispatch(tree, func_node, cnode.lineno):
                        entrypoints.append(sym)
                        seen_qnames.add(sym.qualified_name)
                        break
    return entrypoints


# ---------------------------------------------------------------------------
# Sinks seeded from the per-file scan
# ---------------------------------------------------------------------------


def _seed_direct_sinks(
    index: RepositoryIndex,
    findings: list["Finding"],
    capabilities: list["Capability"],
    rules_sinks: list = None,
) -> dict[str, list[tuple[EffectType, tuple[str, int], str]]]:
    """Map sinks to call-graph nodes.

    Sources (in priority order — earlier wins on de-dup):

    1. Per-file findings/capabilities (the engine already classified
       reachability and guard status). Use the rule_id to look up the
       EffectType.
    2. Independent sink detection via ``detect_sinks`` for every file
       in the index. This catches sinks in functions that the per-file
       scan never flagged because the enclosing function isn't directly
       agent-reachable (e.g. ``layer_two`` in the Objective 2 scenario).
       These sinks become the substrate for transitive reachability —
       if the repository layer proves they're transitively reachable
       from an entrypoint, they become NEW findings.

    Returns a dict keyed by caller qualified name → list of
    (effect, (file, line), rule_id) tuples.
    """
    direct: dict[str, list[tuple[EffectType, tuple[str, int], str]]] = {}
    seen: set[tuple[str, int, str]] = set()

    # Source 1: per-file findings/capabilities
    for f in findings + capabilities:  # type: ignore[operator]
        rule_id = f.rule_id
        base_rule = rule_id
        for suffix in ("-WEAK", "-UNBOUND"):
            if base_rule.endswith(suffix):
                base_rule = base_rule[: -len(suffix)]
                break
        effect = effect_for_rule_id(rule_id)
        if effect is None:
            continue
        caller_qname = _find_enclosing_function_qname(index, f.file, f.line)
        if caller_qname is None:
            continue
        key = (caller_qname, f.line, base_rule)
        if key in seen:
            continue
        seen.add(key)
        direct.setdefault(caller_qname, []).append(
            (effect, (f.file, f.line), base_rule)
        )

    # Source 2: independent sink detection for every file in the index
    if rules_sinks is not None:
        try:
            from actenon_scan.detectors.sinks import detect_sinks
        except ImportError:
            detect_sinks = None  # type: ignore[assignment]
        if detect_sinks is not None:
            for file_rel in index.files:
                ast_info = index.get_ast(file_rel)
                if ast_info is None:
                    continue
                _src, tree = ast_info
                try:
                    sink_findings = detect_sinks(tree, file_rel, rules_sinks)
                except Exception:
                    # Defensive: any per-file sink-detection error is
                    # non-fatal to the repository layer.
                    continue
                for sf in sink_findings:
                    effect = effect_for_rule_id(sf.rule_id)
                    if effect is None:
                        continue
                    caller_qname = _find_enclosing_function_qname(
                        index, file_rel, sf.line
                    )
                    if caller_qname is None:
                        continue
                    key = (caller_qname, sf.line, sf.rule_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    direct.setdefault(caller_qname, []).append(
                        (effect, (file_rel, sf.line), sf.rule_id)
                    )

    return direct


def _find_enclosing_function_qname(
    index: RepositoryIndex, file_rel: str, line: int
) -> str | None:
    """Find the qualified name of the function enclosing a sink at file:line.

    Walks the file's AST looking for the innermost FunctionDef /
    AsyncFunctionDef whose line range contains `line`. Returns the
    qualified name (module_qname.ClassName.method or module_qname.func).
    """
    ast_info = index.get_ast(file_rel)
    if ast_info is None:
        return None
    _src, tree = ast_info
    module_qname = index._module_qualified_name(file_rel)
    # Build a per-call map of function ranges; we don't cache this
    # because it's called infrequently (once per sink, not per call-site).
    candidate: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    candidate_range: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", None) or start
        if start <= line <= end:
            # Pick the innermost (smallest range).
            if candidate_range is None or (end - start) < (candidate_range[1] - candidate_range[0]):
                candidate = node
                candidate_range = (start, end)
    if candidate is None:
        return None
    # Determine enclosing class by line-range scan (only ClassDef nodes
    # whose range contains the function's first line).
    class_name: str | None = None
    class_range: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", None) or start
        if start <= candidate.lineno <= end:
            if class_range is None or (end - start) < (class_range[1] - class_range[0]):
                class_name = node.name
                class_range = (start, end)
    if class_name:
        return (
            f"{module_qname}.{class_name}.{candidate.name}"
            if module_qname
            else f"{class_name}.{candidate.name}"
        )
    return f"{module_qname}.{candidate.name}" if module_qname else candidate.name


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class RepositoryAnalysisResult:
    """Outcome of the repository-level augmentation pass.

    ``new_findings`` are sinks the per-file scan missed because they
    live in functions that are only reachable transitively (e.g.
    ``layer_two()`` containing ``subprocess.run`` reachable only via
    ``agent_action → layer_one → layer_two``).

    ``augmented_findings`` is a list of (existing_finding_index,
    call_path, certainty) triples so the engine can attach the call
    chain to the existing finding's ``reachability_reason``.
    """

    new_findings: list["Finding"] = field(default_factory=list)
    new_capabilities: list["Capability"] = field(default_factory=list)
    augmented_findings: list[tuple[int, CallPath, AnalysisCertainty]] = field(default_factory=list)
    entrypoint_count: int = 0
    call_graph_nodes: int = 0
    call_graph_edges: int = 0
    effect_summaries_count: int = 0
    incomplete_summaries_count: int = 0
    analysis_error: str | None = None
    transitive_followed_count: int = 0
    transitive_unfollowed_count: int = 0
    local_call_edges: list[dict] = field(default_factory=list)
    local_calls_followed: int = 0
    local_calls_unfollowed: int = 0


def _evaluate_python_callsite_guard(
    index: RepositoryIndex,
    file_rel: str,
    target_line: int,
    effective_guards: list[str],
    *,
    require_explicit_authz_for_caller: bool = False,
) -> tuple[str, str]:
    """Evaluate guard soundness + semantic authority kind around ``file_rel:target_line``.

    Returns ``(status, message)`` where ``status`` is ``"guarded"``, ``"weak"``,
    ``"unbound"``, or ``""``.

    Hostile invariants enforced:
      - ``AUTHENTICATION``, ``VALIDATION``, ``SANITIZATION``, and ``RATE_LIMIT``
        guards NEVER authorize a consequential action across helper boundaries.
      - Wrong-action authorities (``authorize_read`` vs ``refund``) detected by
        ``compare_authority_to_sink`` downgrade ``"guarded"`` to ``"unbound"``.
    """
    if not effective_guards:
        return ("", "")
    ast_info = index.get_ast(file_rel)
    if ast_info is None:
        return ("", "")
    _src, tree = ast_info
    func_node = _find_enclosing_function_node(tree, target_line)
    if func_node is None:
        return ("", "")
    sink_node = _find_call_at_line_in_subtree(func_node, target_line)

    try:
        from actenon_scan.detectors.guards import (
            _build_parent_map,
            _dominates,
            _matches_guard,
            check_guard,
        )
        from actenon_scan.repository.authority_binding import (
            BindingState,
            compare_authority_to_sink,
        )
        from actenon_scan.repository.guard_semantics import (
            GuardKind,
            classify_guard_call,
            classify_guard_name,
        )
    except ImportError:
        return ("", "")

    # Fast per-function pre-check cached on RepositoryIndex: 99%+ of functions in
    # large repositories contain zero guard decorators or guard calls, so skip
    # full-module ``check_guard(tree, ...)`` unless a candidate exists in ``func_node``.
    cand_cache: dict[tuple[str, int], bool] = getattr(index, "_func_guard_cand_cache", None)  # type: ignore[assignment]
    if cand_cache is None:
        cand_cache = {}
        setattr(index, "_func_guard_cand_cache", cand_cache)
    func_key = (file_rel, func_node.lineno)
    has_candidate = cand_cache.get(func_key)
    if has_candidate is None:
        has_candidate = bool(func_node.decorator_list)
        if not has_candidate:
            for sub in ast.walk(func_node):
                if isinstance(sub, ast.Call):
                    cname = _call_name_text(sub)
                    if cname and (
                        _matches_guard(cname, effective_guards)
                        or classify_guard_name(cname) != GuardKind.UNKNOWN_GUARD
                        or "protect" in cname.lower()
                        or "executor" in cname.lower()
                    ):
                        has_candidate = True
                        break
        cand_cache[func_key] = has_candidate
    if not has_candidate:
        return ("", "")

    gres = check_guard(tree, target_line, effective_guards, sink_node=sink_node)
    if not (gres.guarded or gres.weak or gres.unbound):
        return ("", "")

    parent_map = _build_parent_map(func_node)
    module_qname = index._module_qualified_name(file_rel)

    # Check decorators on func_node first if gres matched a guard decorator.
    if gres.guarded and "decorator" in (gres.message or ""):
        for dec in func_node.decorator_list:
            try:
                dec_text = ast.unparse(dec).split("(", 1)[0].strip()
            except Exception:
                dec_text = ""
            if not dec_text:
                continue
            dkind = classify_guard_name(dec_text)
            if dkind in (
                GuardKind.AUTHENTICATION,
                GuardKind.VALIDATION,
                GuardKind.SANITIZATION,
                GuardKind.RATE_LIMIT,
            ):
                return ("", f"decorator '{dec_text}' ({dkind.name}) does NOT authorize action")
            if dkind in (
                GuardKind.AUTHORIZATION,
                GuardKind.POLICY_ENFORCEMENT,
                GuardKind.CAPABILITY_PROOF,
                GuardKind.HUMAN_APPROVAL,
            ) or not require_explicit_authz_for_caller:
                return ("guarded", gres.message)
        return ("", "")

    # Inspect dominating guard calls before target_line.
    has_authorizing_dom = False
    has_wrong_action = False
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        if node is sink_node or getattr(node, "lineno", 0) >= target_line:
            continue
        if _is_inside_nested_function(node, func_node, parent_map):
            continue
        gname = _call_name_text(node)
        if not gname:
            continue
        try:
            if not _dominates(node, target_line, parent_map, func_node):
                continue
        except Exception:
            continue

        classification = classify_guard_call(node)
        if classification.kind in (
            GuardKind.AUTHENTICATION,
            GuardKind.VALIDATION,
            GuardKind.SANITIZATION,
            GuardKind.RATE_LIMIT,
        ):
            continue

        is_custom_configured = any(
            gname.lower() == p.lower() or gname.lower().endswith("." + p.lower())
            for p in effective_guards
        )
        if classification.kind == GuardKind.UNKNOWN_GUARD and (
            require_explicit_authz_for_caller or not is_custom_configured
        ):
            continue

        if sink_node is not None and classification.kind == GuardKind.AUTHORIZATION:
            try:
                binding = compare_authority_to_sink(
                    node, sink_node, func_node, index=index, module_qname=module_qname
                )
                if binding.state == BindingState.UNBOUND:
                    has_wrong_action = True
                    continue
            except Exception:
                pass

        has_authorizing_dom = True

    if gres.guarded:
        if has_authorizing_dom:
            return ("guarded", gres.message)
        if has_wrong_action:
            return ("unbound", "dominating guard action/parameter binding is UNBOUND")
        return ("", "")
    if gres.weak and has_authorizing_dom:
        return ("weak", gres.message)
    if (gres.unbound and has_authorizing_dom) or has_wrong_action:
        return ("unbound", gres.message or "dominating guard parameter binding is UNBOUND")
    return ("", "")


def _compute_unguarded_reachable_nodes(
    index: RepositoryIndex,
    graph,
    ep_qnames: list[str],
    effective_guards: list[str],
    max_depth: int,
) -> set[str]:
    """Return call-graph nodes reachable from ``ep_qnames`` via unguarded call edges."""
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(ep, 0) for ep in ep_qnames]
    edge_guarded_cache: dict[tuple[str, int], bool] = {}

    while queue:
        curr, depth = queue.pop(0)
        if curr in visited:
            continue
        visited.add(curr)
        if depth >= max_depth:
            continue
        for edge in graph.edges_by_caller.get(curr, []):
            if edge.is_unresolved():
                continue
            loc_key = (edge.site.location.file, edge.site.location.line)
            if loc_key not in edge_guarded_cache:
                status, _ = _evaluate_python_callsite_guard(
                    index,
                    edge.site.location.file,
                    edge.site.location.line,
                    effective_guards,
                    require_explicit_authz_for_caller=True,
                )
                edge_guarded_cache[loc_key] = (status == "guarded")
            if edge_guarded_cache[loc_key]:
                continue
            if edge.callee not in visited:
                queue.append((edge.callee, depth + 1))

    return visited


# ---------------------------------------------------------------------------
# Augmentation
# ---------------------------------------------------------------------------


def analyze_repository(
    target: Path | str,
    findings: list["Finding"],
    capabilities: list["Capability"],
    reachability_cfg: dict,
    config: RepositoryAnalysisConfig | None = None,
    rules_sinks: list | None = None,
    files: list[Path] | None = None,
    guard_patterns: list[str] | None = None,
) -> RepositoryAnalysisResult:
    """Run the repository-level augmentation pass.

    See module docstring for the conservative properties.
    """
    cfg = config or RepositoryAnalysisConfig()
    result = RepositoryAnalysisResult()

    if not cfg.enabled:
        return result

    try:
        target_path = Path(target)
        if files is not None:
            index = RepositoryIndex()
            index.root = target_path
            for fp in files:
                try:
                    rel = str(fp.relative_to(target_path)) if target_path.is_dir() else fp.name
                    rel = rel.replace("\\", "/")
                    source = fp.read_text(encoding="utf-8-sig")
                    tree = ast.parse(source, filename=str(fp))
                    index.add_file(rel, source, tree)
                except (UnicodeDecodeError, OSError, SyntaxError):
                    continue
            index.finalize()
        else:
            index = RepositoryIndex.build(target_path)
        result.call_graph_nodes = len(index.symbols)
        graph = build_call_graph(index)
        result.call_graph_edges = len(graph.all_edges)

        # Discover entrypoints
        entrypoints = discover_entrypoints(index, reachability_cfg)
        result.entrypoint_count = len(entrypoints)
        if not entrypoints:
            return result

        effective_guards: list[str]
        if guard_patterns is not None:
            effective_guards = list(guard_patterns)
        else:
            try:
                from actenon_scan.rules.loader import load_default_rules

                effective_guards = list(load_default_rules().guard_patterns)
            except Exception:
                effective_guards = []

        # Transitive reachability
        ep_qnames = [e.qualified_name for e in entrypoints]
        reach = transitive_reachable(graph, ep_qnames, max_depth=cfg.max_depth)
        unguarded_reach = _compute_unguarded_reachable_nodes(
            index, graph, ep_qnames, effective_guards, cfg.max_depth
        )

        unfollowed = 0
        external_call_count = 0
        local_edges: list[dict] = []
        followed_count = 0
        for ep_qname in ep_qnames:
            for edge in graph.edges_by_caller.get(ep_qname, []):
                if edge.is_resolved():
                    followed_count += 1
                elif edge.is_unresolved():
                    callee = edge.callee
                    is_external = (
                        "." in callee
                        and not callee.startswith("self.")
                        and not callee.startswith("cls.")
                        and not callee.startswith("<")
                    )
                    if is_external:
                        external_call_count += 1
                    else:
                        unfollowed += 1
                        local_edges.append({
                            "file": edge.site.location.file,
                            "line": edge.site.location.line,
                            "caller": edge.caller,
                            "callee_text": edge.site.callee_text,
                            "callee_qname": edge.callee,
                            "certainty": edge.certainty.value,
                            "reason": "unresolved_local_call",
                        })
        result.transitive_unfollowed_count = unfollowed
        result.local_call_edges = local_edges
        result.local_calls_followed = followed_count
        result.local_calls_unfollowed = unfollowed

        # Seed effect summaries from per-file findings/capabilities AND
        # independent sink detection.
        direct_sinks = _seed_direct_sinks(
            index, findings, capabilities, rules_sinks=rules_sinks
        )

        # Propagate effects
        propagation = propagate_effects(
            graph,
            direct_sinks=direct_sinks,
            max_iterations=cfg.max_iterations,
        )
        result.effect_summaries_count = len(propagation.summaries)
        result.incomplete_summaries_count = len(propagation.incomplete)

        existing_finding_locs: set[tuple[str, int]] = {
            (f.file, f.line) for f in findings
        }
        existing_cap_by_loc: dict[tuple[str, int], "Capability"] = {
            (c.file, c.line): c for c in capabilities
        }
        emitted_locs: set[tuple[str, int]] = set()

        from actenon_scan.capability import Capability, CapabilityState
        from actenon_scan.engine import Finding as EngineFinding

        for caller_qname, sinks in direct_sinks.items():
            if caller_qname not in reach:
                continue
            path = reach[caller_qname]
            certainty = _path_to_certainty(path)
            if certainty == AnalysisCertainty.UNKNOWN and not cfg.emit_heuristic_new_findings:
                continue
            if certainty == AnalysisCertainty.HEURISTIC and not cfg.emit_heuristic_new_findings:
                continue
            for effect, loc, rule_id in sinks:
                if loc in emitted_locs:
                    continue
                if loc in existing_finding_locs:
                    for i, f in enumerate(findings):
                        if f.file == loc[0] and f.line == loc[1]:
                            result.augmented_findings.append((i, path, certainty))
                            break
                    continue
                if loc in existing_cap_by_loc:
                    cap = existing_cap_by_loc[loc]
                    # If the sink's own function/class was guarded, or every
                    # cross-file path to this helper is also guarded, keep it
                    # suppressed as a GUARD_FOUND capability. Only promote when
                    # the capability was suppressed solely via a same-file
                    # caller guard (`local_helper`) AND an unguarded cross-file
                    # path reaches `caller_qname`.
                    if (
                        getattr(cap, "reachability_source", "") != "local_helper"
                        or caller_qname not in unguarded_reach
                    ):
                        continue

                _src, tree_for_loc = index.get_ast(loc[0]) or (None, None)
                call_text = ""
                if tree_for_loc is not None:
                    for node in ast.walk(tree_for_loc):
                        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == loc[1]:
                            try:
                                call_text = ast.unparse(node)
                            except Exception:
                                call_text = ""
                            break

                callee_guard_status, callee_guard_msg = _evaluate_python_callsite_guard(
                    index, loc[0], loc[1], effective_guards
                )
                category = _effect_to_category(effect)

                if callee_guard_status == "guarded" or caller_qname not in unguarded_reach:
                    gmsg = (
                        callee_guard_msg
                        if callee_guard_status == "guarded"
                        else "all cross-file call paths dominated by authorizing guard"
                    )
                    result.new_capabilities.append(
                        Capability(
                            file=loc[0],
                            line=loc[1],
                            col=0,
                            rule_id=rule_id,
                            category=category,
                            severity="medium",
                            call_text=call_text,
                            state=CapabilityState.GUARD_FOUND,
                            guard_status="guarded",
                            guard_message=gmsg,
                            confidence="high" if certainty == AnalysisCertainty.PROVEN else "medium",
                            reachability_reason=f"transitive:{path.chain_text()}",
                            reachability_source="transitive",
                            tier="production",
                            language="python",
                            snippet_hash="",
                        )
                    )
                    emitted_locs.add(loc)
                    continue

                confidence = "high" if certainty == AnalysisCertainty.PROVEN else "medium"
                severity = "medium"
                rule_id_aug = rule_id
                if certainty == AnalysisCertainty.HEURISTIC:
                    rule_id_aug = f"{rule_id}-REACH-HEURISTIC"
                if callee_guard_status == "weak":
                    rule_id_aug = f"{rule_id_aug}-WEAK"
                    severity = "low"
                elif callee_guard_status == "unbound":
                    rule_id_aug = f"{rule_id_aug}-UNBOUND"
                    severity = "medium"

                new_finding = EngineFinding(
                    file=loc[0],
                    line=loc[1],
                    col=0,
                    rule_id=rule_id_aug,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    description=(
                        f"Transitively agent-reachable sink ({rule_id}) "
                        f"via {path.chain_text()}"
                    ),
                    call_text=call_text,
                    remediation=_remediation_for_effect(effect),
                    snippet_hash="",
                    tier="production",
                    reachability_reason=f"transitive:{path.chain_text()}",
                )
                result.new_findings.append(new_finding)
                emitted_locs.add(loc)

        # Task 5-A2: substrate-module evidence pass on existing AND newly
        # discovered transitive findings/capabilities.
        _augment_with_substrate_evidence(
            index,
            list(findings) + list(result.new_findings),
            list(capabilities) + list(result.new_capabilities),
        )

    except Exception as exc:
        # Never let the augmentation crash the scan.
        import sys
        result.analysis_error = f"{type(exc).__name__}: {exc}"
        print(
            f"actenon-scan: warning: repository analysis failed: {result.analysis_error}",
            file=sys.stderr,
        )

    # Disclosure: the followed count is the number of NEW findings the
    # repo layer added — i.e. sinks in helpers that the per-file scan
    # missed (because the enclosing function isn't directly
    # @tool-decorated) but the repo layer proved transitively reachable
    # from an agent entrypoint. Computed AFTER the new-findings loop so
    # it reflects the final list (including any added during exception
    # recovery, though that path doesn't add findings).
    result.transitive_followed_count = len(result.new_findings)

    return result


def _path_to_certainty(path: CallPath) -> AnalysisCertainty:
    """Convert a CallPath's certainty to an AnalysisCertainty.

    RESOLVED path → PROVEN
    HEURISTIC path → HEURISTIC
    UNRESOLVED path → UNKNOWN
    Truncated path → HEURISTIC (chain is incomplete; reachability
    still holds but the chain evidence is partial)
    """
    cert = path.certainty()
    if cert == ResolutionCertainty.RESOLVED:
        if path.truncated:
            return AnalysisCertainty.HEURISTIC
        return AnalysisCertainty.PROVEN
    if cert == ResolutionCertainty.HEURISTIC:
        return AnalysisCertainty.HEURISTIC
    return AnalysisCertainty.UNKNOWN


def _effect_to_category(effect: EffectType) -> str:
    """Map an EffectType back to a rule category for finding emission."""
    mapping = {
        EffectType.SHELL_EXECUTION: "shell_execution",
        EffectType.CODE_EXECUTION: "code_execution",
        EffectType.FILE_WRITE: "file_mutation",
        EffectType.FILE_DELETE: "data_destruction",
        EffectType.DATA_MUTATION: "database_mutation",
        EffectType.DATA_DELETION: "data_destruction",
        EffectType.IDENTITY_MUTATION: "identity_change",
        EffectType.ACCESS_CONTROL_MUTATION: "access_control_mutation",
        EffectType.MONEY_MUTATION: "payments",
        EffectType.MONEY_REFUND: "payments",
        EffectType.COMMUNICATION_SEND: "communication",
        EffectType.EMAIL_SEND: "communication",
        EffectType.REPOSITORY_MUTATION: "repository_mutation",
        EffectType.DEPLOY_ACTION: "deployment",
        EffectType.CONTAINER_EXECUTION: "deployment",
        EffectType.INFRASTRUCTURE_MUTATION: "deployment",
        EffectType.CREDENTIAL_ACCESS: "credential_access",
        EffectType.NETWORK_EGRESS: "network_egress",
        EffectType.BROWSER_ACTION: "browser_action",
        EffectType.UNKNOWN_EFFECT: "unknown",
    }
    return mapping.get(effect, "unknown")


def _remediation_for_effect(effect: EffectType) -> str:
    """One-line remediation hint for an effect."""
    hints = {
        EffectType.SHELL_EXECUTION: "Avoid passing agent-controlled input to subprocess; use allowlists.",
        EffectType.CODE_EXECUTION: "Do not eval/exec agent-controlled input.",
        EffectType.FILE_WRITE: "Bind file writes to a verified constant path.",
        EffectType.FILE_DELETE: "Bind deletions to a verified constant path.",
        EffectType.DATA_MUTATION: "Require action-bound authorization before DB mutations.",
        EffectType.DATA_DELETION: "Require action-bound authorization before deletions.",
        EffectType.IDENTITY_MUTATION: "Identity mutations require action-bound authorization.",
        EffectType.ACCESS_CONTROL_MUTATION: "Access-control mutations require action-bound authorization.",
        EffectType.MONEY_MUTATION: "Money mutations require action-bound authorization.",
        EffectType.MONEY_REFUND: "Refunds require action-bound authorization matching the refund target.",
        EffectType.COMMUNICATION_SEND: "External comms require action-bound authorization.",
        EffectType.EMAIL_SEND: "External email requires action-bound authorization.",
        EffectType.REPOSITORY_MUTATION: "Repository mutations require action-bound authorization.",
        EffectType.DEPLOY_ACTION: "Deployments require action-bound authorization.",
        EffectType.CONTAINER_EXECUTION: "Container exec requires action-bound authorization.",
        EffectType.INFRASTRUCTURE_MUTATION: "Infra mutations require action-bound authorization.",
        EffectType.CREDENTIAL_ACCESS: "Credential reads require action-bound authorization.",
        EffectType.NETWORK_EGRESS: "Network egress requires action-bound authorization.",
        EffectType.BROWSER_ACTION: "Browser actions require action-bound authorization.",
        EffectType.UNKNOWN_EFFECT: "Verify authority dominates this sink.",
    }
    return hints.get(effect, "Verify authority dominates this sink.")


# ---------------------------------------------------------------------------
# Task 5-A2: substrate-module evidence wiring
# ---------------------------------------------------------------------------
#
# This pass runs AFTER the existing propagate_effects / new-findings loop
# and AUGMENTS each existing per-file finding AND capability with evidence
# from the three substrate modules:
#
#   1. guard_resolution.resolve_guard_call — cross-file guard body
#      inspection. If the guard is RESOLVED cross-file with an ASSERT
#      or PREDICATE style, the finding's reachability_reason gains:
#          [cross-file guard: <qname> ASSERT (raises at line N)]
#
#   2. guard_semantics.classify_guard_name — semantic taxonomy:
#      AUTHENTICATION / AUTHORIZATION / VALIDATION / SANITIZATION /
#      HUMAN_APPROVAL / POLICY_ENFORCEMENT / CAPABILITY_PROOF /
#      RATE_LIMIT / UNKNOWN_GUARD. AUTHENTICATION and VALIDATION (and
#      the other non-action-authorization kinds) MUST be explicitly
#      labelled "does NOT authorize this action" — they CANNOT authorize
#      a specific action (the CRITICAL hostile invariant from the
#      brief: ``authenticate(user)`` does not authorize ``refund``).
#          [guard kind: AUTHORIZATION]
#          [guard kind: AUTHENTICATION — does NOT authorize this action]
#
#   3. authority_binding.compare_authority_to_sink — parameter plumbing
#      comparison; BOUND / UNBOUND / UNKNOWN. The action-label
#      soundness gate runs FIRST inside compare_authority_to_sink, so
#      an ``authorize_read`` authority CANNOT bind to a ``refund`` sink
#      even when parameters match — the action labels differ.
#          [authority binding: BOUND — both args trace back to ...]
#          [authority binding: UNBOUND — authority action 'read'
#           differs from sink action 'refund' ...]
#
# Conservative properties (NON-NEGOTIABLE):
# - This pass ONLY appends evidence to reachability_reason. It NEVER
#   removes, suppresses, or downgrades a finding.
# - Best-effort: any failure (AST parse error, unresolved guard, etc.)
#   is silently skipped per-finding. The repo layer must remain
#   non-fatal.
# - AUTHENTICATION and VALIDATION guards are explicitly labelled
#   "does NOT authorize this action" — never silently treated as
#   authorizing.
#
# The substrate modules now affect the scan's output — every existing
# finding/capability that has a guard nearby gets richer evidence in its
# reachability_reason field.


# Guard kinds that CANNOT authorize a specific action. Their evidence
# must explicitly say "does NOT authorize this action".
_NON_AUTHZ_KINDS = frozenset(
    {
        "AUTHENTICATION",
        "VALIDATION",
        "SANITIZATION",
        "HUMAN_APPROVAL",
        "RATE_LIMIT",
        "UNKNOWN_GUARD",
    }
)


def _augment_with_substrate_evidence(
    index: RepositoryIndex,
    findings: list,
    capabilities: list,
) -> None:
    """Augment per-file findings and capabilities with substrate evidence.

    Best-effort: never raises. See the module docstring above for the
    conservative invariants.
    """
    # Lazy import — keeps the module import side-effect free and silently
    # skips if any substrate module is unavailable (shouldn't happen in
    # normal installs, but the constraint is non-fatal best-effort).
    try:
        from actenon_scan.repository.guard_resolution import (
            resolve_guard_call,
            GuardStyle,
        )
        from actenon_scan.repository.guard_semantics import (
            classify_guard_call,
            GuardKind,
        )
        from actenon_scan.repository.authority_binding import (
            compare_authority_to_sink,
        )
        # The AST-ancestry dominance check is the active path in
        # guards.py — re-use it verbatim (don't wire in cfg.py yet;
        # that's a future slice and we don't want to change behaviour).
        from actenon_scan.detectors.guards import (
            _dominates,
            _build_parent_map,
        )
    except ImportError:
        # Substrate modules not available — best-effort skip.
        return

    # Iterate over BOTH findings AND capabilities. Capabilities with
    # state=GUARD_FOUND are exactly the case where the substrate
    # evidence (cross-file guard body inspection, semantic taxonomy,
    # authority binding) is most informative: the per-file scan
    # already knows a guard call exists, and the substrate modules
    # enrich WHY that guard does (or does NOT) actually authorize
    # the sink.
    for f in list(findings) + list(capabilities):
        try:
            _augment_one_substrate(
                f,
                index,
                resolve_guard_call,
                GuardStyle,
                classify_guard_call,
                GuardKind,
                compare_authority_to_sink,
                _dominates,
                _build_parent_map,
            )
        except Exception:
            # Per-finding best-effort: silently skip on any error.
            # The repo layer must remain non-fatal.
            continue


def _augment_one_substrate(
    f,
    index: RepositoryIndex,
    resolve_guard_call,
    GuardStyle,
    classify_guard_call,
    GuardKind,
    compare_authority_to_sink,
    _dominates,
    _build_parent_map,
) -> None:
    """Augment a single finding/capability with substrate evidence.

    Mutates ``f.reachability_reason`` in place by APPENDING evidence
    strings (never replaces, never removes). See the module docstring
    above for the conservative invariants.
    """
    file_rel = getattr(f, "file", None)
    line = getattr(f, "line", None)
    if not file_rel or line is None:
        return
    ast_info = index.get_ast(file_rel)
    if ast_info is None:
        return
    _src, tree = ast_info

    # Find the enclosing function AST node for this sink line.
    func_node = _find_enclosing_function_node(tree, line)
    if func_node is None:
        return

    # Build the parent map ONCE for the dominance check (mirrors
    # guards.py's _build_parent_map to keep behaviour consistent with
    # the per-file guard analyzer).
    parent_map = _build_parent_map(func_node)

    module_qname = index._module_qualified_name(file_rel)

    # Locate the sink Call node at the finding's line (best-effort).
    sink_node = _find_call_at_line_in_subtree(func_node, line)

    # Walk the function body for guard calls — ast.Call nodes whose
    # callable name classifies as something other than UNKNOWN_GUARD.
    # Skip calls inside nested FunctionDef / AsyncFunctionDef / Lambda
    # — they're not in our function's scope.
    guard_calls: list[tuple] = []  # list of (call_node, guard_name, classification)
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        if _is_inside_nested_function(node, func_node, parent_map):
            continue
        if node is sink_node:
            continue
        classification = classify_guard_call(node)
        if classification.kind == GuardKind.UNKNOWN_GUARD:
            continue
        name = _call_name_text(node)
        if not name:
            continue
        guard_calls.append((node, name, classification))

    if not guard_calls:
        return  # nothing to add

    # For each guard call: cross-file resolution + semantic taxonomy.
    for guard_node, guard_name, classification in guard_calls:
        # --- Cross-file guard resolution ------------------------------
        try:
            resolution = resolve_guard_call(guard_node, module_qname, index)
        except Exception:
            resolution = None

        if (
            resolution is not None
            and resolution.resolved
            and resolution.style in (GuardStyle.ASSERT, GuardStyle.PREDICATE)
        ):
            target_qname = _resolve_qname_for_call(
                index, guard_node, module_qname
            )
            style_name = resolution.style.name  # 'ASSERT' or 'PREDICATE'
            detail = ""
            if resolution.body_inspection is not None:
                lines = resolution.body_inspection.evidence_lines
                if lines:
                    kind_word = (
                        "raises"
                        if resolution.style == GuardStyle.ASSERT
                        else "returns"
                    )
                    detail = (
                        f"{kind_word} at line "
                        + ", ".join(str(ln) for ln in lines)
                    )
            evidence_str = (
                f"[cross-file guard: {target_qname} {style_name}"
                + (f" ({detail})" if detail else "")
                + "]"
            )
            _append_substrate_evidence(f, evidence_str)

        # --- Semantic guard taxonomy ---------------------------------
        kind_name = classification.kind.name  # 'AUTHENTICATION', etc.
        if kind_name in _NON_AUTHZ_KINDS:
            # CRITICAL hostile invariant: AUTHENTICATION and VALIDATION
            # (and other non-action-authorization kinds) MUST be
            # explicitly labelled as "does NOT authorize this action"
            # — never silently treated as authorizing.
            evidence_str = (
                f"[guard kind: {kind_name} — does NOT authorize this action]"
            )
        else:
            evidence_str = f"[guard kind: {kind_name}]"
        _append_substrate_evidence(f, evidence_str)

    # --- Authority/action value binding -----------------------------
    # For each (guard_call, sink_call) pair where the guard dominates
    # the sink (per the existing AST-ancestry check from guards.py),
    # compare parameter binding. Only run for AUTHORIZATION-kind
    # guards (others cannot authorize an action, so binding comparison
    # is moot — the kind evidence already says "does NOT authorize").
    if sink_node is None:
        return

    sink_line = sink_node.lineno
    for guard_node, guard_name, classification in guard_calls:
        # Skip guards that come AFTER the sink (line-number check).
        if guard_node.lineno >= sink_line:
            continue
        # Only run binding comparison for AUTHORIZATION-kind guards.
        # AUTHENTICATION, VALIDATION, etc. cannot authorize — the
        # kind evidence already says so. Binding would be misleading.
        if classification.kind != GuardKind.AUTHORIZATION:
            continue
        # Dominance check via the existing AST-ancestry path in
        # guards.py (don't wire in cfg.py yet — that's a future slice).
        try:
            if not _dominates(guard_node, sink_line, parent_map, func_node):
                continue
        except Exception:
            continue
        try:
            binding = compare_authority_to_sink(
                guard_node,
                sink_node,
                func_node,
                index=index,
                module_qname=module_qname,
            )
        except Exception:
            continue
        state_name = binding.state.name  # 'BOUND', 'UNBOUND', 'UNKNOWN'
        evidence_str = (
            f"[authority binding: {state_name} — {binding.evidence}]"
        )
        _append_substrate_evidence(f, evidence_str)


def _append_substrate_evidence(f, evidence_str: str) -> None:
    """Append substrate evidence to a finding/capability's
    reachability_reason field. De-dups; never replaces or removes."""
    current = getattr(f, "reachability_reason", "") or ""
    if evidence_str in current:
        return
    if current:
        f.reachability_reason = f"{current} {evidence_str}"
    else:
        f.reachability_reason = evidence_str


def _find_enclosing_function_node(
    tree: ast.Module, line: int
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find the innermost FunctionDef / AsyncFunctionDef whose line
    range contains ``line``. Returns None if no enclosing function."""
    candidate: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    candidate_range: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", None) or start
        if start <= line <= end:
            if (
                candidate_range is None
                or (end - start) < (candidate_range[1] - candidate_range[0])
            ):
                candidate = node
                candidate_range = (start, end)
    return candidate


def _find_call_at_line_in_subtree(
    func_node: ast.AST, line: int
) -> ast.Call | None:
    """Find the first ast.Call at the given line within func_node's
    subtree. Best-effort — returns None if no Call matches."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == line:
            return node
    return None


def _is_inside_nested_function(
    node: ast.AST,
    func_node: ast.AST,
    parent_map: dict[int, ast.AST],
) -> bool:
    """True if ``node`` is inside a nested FunctionDef /
    AsyncFunctionDef / Lambda (i.e., not directly in ``func_node``'s
    body but inside an inner function definition)."""
    current = parent_map.get(id(node))
    while current is not None and current is not func_node:
        if isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            return True
        current = parent_map.get(id(current))
    return False


def _call_name_text(call_node: ast.Call) -> str:
    """Best-effort textual callee name from an ast.Call's func.

    ast.Name → id; ast.Attribute → attr; otherwise empty string.
    Mirrors guard_resolution._get_call_name /
    authority_binding._call_name_text.
    """
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _resolve_qname_for_call(
    index: RepositoryIndex, call_node: ast.Call, module_qname: str
) -> str:
    """Re-resolve a guard call's target qname for the cross-file
    evidence string. Falls back to the textual callee if unresolved."""
    try:
        sym, _certainty, qname_attempt = index.resolve_call_target(
            call_node.func, in_module=module_qname
        )
        if sym is not None:
            return sym.qualified_name
        return qname_attempt or _call_name_text(call_node) or "<unknown>"
    except Exception:
        return _call_name_text(call_node) or "<unknown>"
