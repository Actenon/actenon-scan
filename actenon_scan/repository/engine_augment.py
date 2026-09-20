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

    An entrypoint is a function/method decorated with a configured
    ``tool_decorators`` entry (e.g. ``@tool``, ``@mcp.tool()``,
    ``@function_tool``, etc.) or a method of a class subclassing a
    configured ``tool_base_classes`` entry.

    Returns the list of entrypoint Symbols (insertion order).
    """
    tool_decorators = reachability_cfg.get("tool_decorators", [])
    tool_base_classes = reachability_cfg.get("tool_base_classes", [])
    tool_methods = reachability_cfg.get("tool_methods", [])

    entrypoints: list[Symbol] = []
    seen_qnames: set[str] = set()
    for sym in index.symbols:
        if not sym.is_function_like:
            continue
        # Decorator-based detection
        for dec in sym.decorators:
            if _is_tool_decorator(dec, tool_decorators):
                if sym.qualified_name not in seen_qnames:
                    entrypoints.append(sym)
                    seen_qnames.add(sym.qualified_name)
                break
        else:
            # Method-of-tool-base-class detection
            if sym.kind in (SymbolKind.METHOD, SymbolKind.ASYNC_METHOD):
                if sym.name in tool_methods and sym.enclosing_class:
                    # Check whether the enclosing class subclasses a tool base
                    # class. We need to inspect the class def's bases.
                    cls_sym = index.lookup_symbol(sym.enclosing_class)
                    if cls_sym is not None:
                        ast_info = index.get_ast(cls_sym.location.file)
                        if ast_info is not None:
                            _src, tree = ast_info
                            for node in ast.walk(tree):
                                if (
                                    isinstance(node, ast.ClassDef)
                                    and node.name == cls_sym.name
                                ):
                                    for base in node.bases:
                                        try:
                                            base_text = ast.unparse(base)
                                        except Exception:
                                            base_text = ""
                                        if any(
                                            base_text == b
                                            or base_text.endswith("." + b)
                                            for b in tool_base_classes
                                        ):
                                            if sym.qualified_name not in seen_qnames:
                                                entrypoints.append(sym)
                                                seen_qnames.add(sym.qualified_name)
                                            break
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
    augmented_findings: list[tuple[int, CallPath, AnalysisCertainty]] = field(default_factory=list)
    entrypoint_count: int = 0
    call_graph_nodes: int = 0
    call_graph_edges: int = 0
    effect_summaries_count: int = 0
    incomplete_summaries_count: int = 0
    analysis_error: str | None = None


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
) -> RepositoryAnalysisResult:
    """Run the repository-level augmentation pass.

    See module docstring for the conservative properties.

    ``rules_sinks`` is the loaded sink rules list (from
    ``Ruleset.sinks``). When provided, the layer independently runs
    ``detect_sinks`` on every file in the index to catch sinks in
    functions that the per-file scan never flagged because they
    weren't directly agent-reachable.

    ``files`` is the engine's already-filtered Python file list (excludes
    venv/build/test directories). When provided, the index is built
    from this list rather than re-walking the tree — important for
    performance so we don't accidentally parse 1000+ files in .venv.
    """
    cfg = config or RepositoryAnalysisConfig()
    result = RepositoryAnalysisResult()

    if not cfg.enabled:
        return result

    try:
        target_path = Path(target)
        # Build the index. If the engine gave us its filtered file list,
        # use it; otherwise walk the tree (with the standard venv/cache
        # exclusions to avoid parsing 1000s of irrelevant files).
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

        # Transitive reachability
        ep_qnames = [e.qualified_name for e in entrypoints]
        reach = transitive_reachable(graph, ep_qnames, max_depth=cfg.max_depth)

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

        # Find sinks in functions that are reachable but NOT in the
        # existing findings — these are the new transitively-reachable
        # sinks the per-file scan missed.
        existing_sink_locs: set[tuple[str, int]] = set()
        for f in findings + capabilities:  # type: ignore[operator]
            existing_sink_locs.add((f.file, f.line))

        from actenon_scan.engine import Finding as EngineFinding

        # Look at every function's direct sinks (from direct_sinks)
        # and check whether the function is reachable.
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
                if loc in existing_sink_locs:
                    # The per-file scan already caught this sink — augment
                    # the existing finding instead of duplicating it.
                    for i, f in enumerate(findings):
                        if f.file == loc[0] and f.line == loc[1]:
                            result.augmented_findings.append((i, path, certainty))
                            break
                    continue
                # Build a new Finding for this transitively-reachable sink.
                _src, tree_for_loc = index.get_ast(loc[0]) or (None, None)
                call_text = ""
                if tree_for_loc is not None:
                    for node in ast.walk(tree_for_loc):
                        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == loc[1]:
                            try:
                                call_text = ast.unparse(node)[:120]
                            except Exception:
                                call_text = ""
                            break
                confidence = "high" if certainty == AnalysisCertainty.PROVEN else "medium"
                severity = "medium"
                rule_id_aug = rule_id
                if certainty == AnalysisCertainty.HEURISTIC:
                    rule_id_aug = f"{rule_id}-REACH-HEURISTIC"
                category = _effect_to_category(effect)
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

    except Exception as exc:
        # Never let the augmentation crash the scan.
        import sys
        result.analysis_error = f"{type(exc).__name__}: {exc}"
        print(
            f"actenon-scan: warning: repository analysis failed: {result.analysis_error}",
            file=sys.stderr,
        )

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
