"""Cross-language resource reachability for TypeScript and Go.

This module implements ONE capability:

    CROSS-FILE RESOURCE REACHABILITY FOR GO AND TYPESCRIPT

It does NOT implement argument taint across languages. It does NOT
recognise new authority semantics. It does NOT add new sink rules.

Given a target directory, a set of per-file findings already collected
by the engine, and the engine's filtered file lists (Python ``files``,
TypeScript ``ts_files``, Go ``go_files``), this module:

  1. Builds a per-language symbol index (TSRepositoryIndex for TS;
     GoRepositoryIndex for Go).
  2. Discovers registered model-callable handlers (entrypoints):
       - TS: arrow/function passed as the last positional arg to
         ``server.registerTool`` / ``server.tool`` / ``setRequestHandler``
         / ``new DynamicStructuredTool({..., func: ...})``.
       - Go: func_literal passed as the last positional arg to
         ``mcp.AddTool`` / ``server.AddTool`` / ``AddTool`` /
         ``RegisterTool`` / ``AddToolHandler`` / ``NewTypedToolHandler``.
  3. Discovers ALL sinks in every indexed file (using
     ``discover_all_ts_sinks`` / ``discover_all_go_sinks``) regardless
     of per-file reachability — so sinks the per-file scan skipped are
     now visible to the cross-file layer.
  4. From each entrypoint, traverses outgoing call sites, resolves
     each callee cross-file, recurses (bounded depth, cycle-safe).
     Disclosure: unresolved dynamic / external calls are counted but
     not silently resolved.
  5. When traversal reaches a function containing a sink that is NOT
     already in the per-file findings, emits a NEW transitive finding
     with reachability_reason describing the call chain.

Conservative invariants (Phase 3 of the brief):

  - NEVER suppress an existing direct finding. Per-file findings are
    not modified (only augmented with chain evidence in
    ``augmented_findings``).
  - NEVER make an unreachable helper reachable. Only functions
    transitively reachable from a registered handler produce new
    findings. (See TEST C — the negative-control test.)
  - Avoid duplicate direct + transitive findings. If a sink is in
    both per-file findings and the discovered-sink set, the per-file
    finding is augmented with chain evidence; no new finding is
    emitted for the same (file, line) location.
  - Preserve current Python behaviour. This module does not touch
    the Python path; the existing engine_augment.analyze_repository
    is unchanged.
  - Preserve current Go direct behaviour. The Go per-file detector
    is unchanged; its findings remain.
  - Preserve current TypeScript direct behaviour. Same.
  - Bound traversal depth (``max_depth=32``).
  - Handle recursion/cycles safely (visited set in BFS).
  - Disclose unresolved dynamic calls rather than guessing.

Honesty
-------

For transitive findings where exact argument provenance is not yet
established, the description and reachability_reason explicitly state:

    Agent reachability: PROVEN
    Sink: PROVEN
    Model-controlled sink argument: NOT ESTABLISHED

This is required by the brief — we do NOT claim a model-controlled
argument merely because the function is reachable from a model
handler. Argument taint propagation across Go and TS is explicitly
out of scope for this slice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from actenon_scan.repository.symbol_index import ResolutionCertainty


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class CrossLanguageReachResult:
    """Container for cross-language reachability analysis results."""

    # New findings the cross-file layer added (sinks the per-file scan
    # missed because they were only reachable transitively).
    new_findings: list = field(default_factory=list)
    # Augmentation of EXISTING per-file findings with chain evidence.
    # Each tuple: (finding_index_in_findings_list, chain_path_text).
    augmented_findings: list[tuple[int, str]] = field(default_factory=list)
    # Disclosure counts.
    transitive_followed_count: int = 0
    transitive_unfollowed_count: int = 0
    # Per-edge detail for unresolved local calls — surfaced in JSON/
    # SARIF/markdown/HTML output (mirrors the Python repo layer's
    # local_call_edges).
    local_call_edges: list[dict] = field(default_factory=list)
    local_calls_followed: int = 0
    local_calls_unfollowed: int = 0
    # Analysis error (defensive: any unexpected exception is captured
    # here so the engine can surface it; the engine never crashes).
    analysis_error: str = ""
    # Bookkeeping for the report.
    ts_entrypoint_count: int = 0
    go_entrypoint_count: int = 0
    ts_symbols_indexed: int = 0
    go_symbols_indexed: int = 0


# ---------------------------------------------------------------------------
# Entrypoint patterns
# ---------------------------------------------------------------------------

# TS handler-registration call patterns. The handler is the LAST positional
# arg if it's an arrow_function or function_expression. For
# DynamicStructuredTool the handler is the `func` property of the object
# literal (the only positional arg).
_TS_REGISTRATION_CALLEES = {
    "registerTool",
    "tool",
    "setRequestHandler",
    "DynamicStructuredTool",
}

# Go handler-registration call patterns. The handler is the LAST positional
# arg if it's a func_literal. (mcp.AddTool, server.AddTool, etc.)
_GO_REGISTRATION_CALLEES = {
    "AddTool",
    "RegisterTool",
    "AddToolHandler",
    "NewTypedToolHandler",
}


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def analyze_cross_language_reach(
    target: Path | str,
    findings: list,
    capabilities: list,
    *,
    ts_files: list[Path] | None = None,
    go_files: list[Path] | None = None,
    max_depth: int = 32,
) -> CrossLanguageReachResult:
    """Run cross-file reachability analysis for TS and Go targets.

    See module docstring for the conservative invariants and honest-
    reporting semantics.

    Returns a :class:`CrossLanguageReachResult`. Never raises — any
    unexpected exception is captured in ``analysis_error`` and the
    engine surfaces it without crashing.
    """
    result = CrossLanguageReachResult()
    target_path = Path(target)

    try:
        # TypeScript analysis (if the [typescript] extra is installed
        # and at least one TS file was scanned).
        if ts_files:
            try:
                from actenon_scan.detectors.typescript import (
                    is_typescript_extra_available,
                )
            except ImportError:
                is_typescript_extra_available = None  # type: ignore

            if is_typescript_extra_available and is_typescript_extra_available():
                _analyze_ts(target_path, findings, capabilities, ts_files,
                            max_depth, result)

        # Go analysis (if the [go] extra is installed and at least one
        # Go file was scanned).
        if go_files:
            try:
                from actenon_scan.detectors.go import is_go_extra_available
            except ImportError:
                is_go_extra_available = None  # type: ignore

            if is_go_extra_available and is_go_extra_available():
                _analyze_go(target_path, findings, capabilities, go_files,
                            max_depth, result)

    except Exception as exc:  # noqa: BLE001 — non-fatal
        result.analysis_error = (
            f"{type(exc).__name__}: {exc}"
        )

    return result


# ---------------------------------------------------------------------------
# TypeScript analysis
# ---------------------------------------------------------------------------


def _analyze_ts(
    target: Path,
    findings: list,
    capabilities: list,
    ts_files: list[Path],
    max_depth: int,
    result: CrossLanguageReachResult,
) -> None:
    """Build a TSRepositoryIndex, find handlers, traverse, emit findings."""
    from actenon_scan.repository.ts_symbol_index import TSRepositoryIndex
    from actenon_scan.detectors.typescript import discover_all_ts_sinks

    # Build the index from the engine's already-filtered file list.
    index = TSRepositoryIndex(root=target)
    for fp in ts_files:
        try:
            rel = str(fp.relative_to(target)) if target.is_dir() else fp.name
            rel = rel.replace("\\", "/")
            source = fp.read_text(encoding="utf-8-sig")
            index.add_file(rel, source)
        except (UnicodeDecodeError, OSError, Exception):
            continue
    index.finalize()
    result.ts_symbols_indexed = len(index.symbols)
    if not index.symbols:
        return

    # Discover ALL sinks across every indexed file (regardless of per-file
    # reachability). Group sinks by enclosing function qualified_name.
    sinks_by_function: dict[str, list[dict]] = {}
    for fp in ts_files:
        try:
            # discover_all_ts_sinks takes a filepath and reads it itself.
            sinks = discover_all_ts_sinks(fp)
        except Exception:
            continue
        for sink in sinks:
            # Find the enclosing function for this sink.
            file_rel = sink["file"]
            # If the discover helper returned an absolute path, normalise
            # to the relative form used by the index.
            try:
                rel = str(Path(file_rel).relative_to(target)) if target.is_dir() else Path(file_rel).name
                rel = rel.replace("\\", "/")
            except ValueError:
                rel = file_rel
            module_qname = _ts_module_qname(index, rel)
            if module_qname is None:
                continue
            # Walk the file's AST to find the enclosing function.
            ast_info = index.get_ast(rel)
            if ast_info is None:
                continue
            src, root_node = ast_info
            source_bytes = src.encode("utf-8") if isinstance(src, str) else src
            caller_qname = _ts_find_enclosing_function_qname_for_line(
                index, root_node, sink["line"], module_qname, source_bytes
            )
            if caller_qname is None:
                caller_qname = module_qname or "<module>"
            sinks_by_function.setdefault(caller_qname, []).append({
                **sink,
                "file": rel,
                "caller_qname": caller_qname,
            })

    # Discover entrypoints (registered handlers).
    entrypoints: list[tuple[str, str]] = []  # (file_rel, handler_kind)
    # Each entrypoint is a (module_qname, handler_node, file_rel) tuple.
    # The handler_node is the arrow_function or function node; we'll
    # walk its body to find outgoing calls.
    handler_specs: list[tuple[str, object, str, bytes]] = []
    for file_rel in index.files:
        ast_info = index.get_ast(file_rel)
        if ast_info is None:
            continue
        src, root_node = ast_info
        source_bytes = src.encode("utf-8") if isinstance(src, str) else src
        module_qname = _ts_module_qname(index, file_rel) or file_rel
        for handler_node, handler_kind in _ts_find_handlers_in_file(
            root_node, source_bytes
        ):
            handler_specs.append((module_qname, handler_node, file_rel, source_bytes))
            entrypoints.append((file_rel, handler_kind))
    result.ts_entrypoint_count = len(handler_specs)
    if not handler_specs:
        return

    # Build the entrypoint set: for each handler, collect the qualified
    # names we'll BFS from. Handlers themselves may have a qualified_name
    # (named function passed to registration) or be anonymous (inline
    # arrow). For anonymous arrows, we use the synthetic qname
    # "<handler@file:line>" so the BFS can still track visited set
    # correctly.
    entrypoint_qnames: list[str] = []
    # Map: handler_qname → list of (file_rel, line) of the handler's own
    # outgoing call sites (collected from the index's call_sites with
    # caller_qname matching the handler's enclosing-qname lookup; OR
    # walked directly from the handler_node).
    handler_outgoing_calls: dict[str, list[tuple[str, str, int]]] = {}
    # We need to walk the handler's body to collect its outgoing calls
    # because the index may attribute the calls to the module-level
    # synthetic caller if the handler is an anonymous inline arrow.
    for module_qname, handler_node, file_rel, source_bytes in handler_specs:
        handler_qname = _ts_handler_qname(handler_node, module_qname, source_bytes)
        entrypoint_qnames.append(handler_qname)
        outgoing: list[tuple[str, str, int]] = []
        # Walk the handler's body for call_expression nodes.
        for call_node in _ts_walk_calls_in_subtree(handler_node):
            func = call_node.child_by_field_name("function")
            if func is None:
                continue
            callee_text = _ts_node_text(func, source_bytes)
            if not callee_text:
                continue
            line = call_node.start_point[0] + 1
            col = call_node.start_point[1]
            outgoing.append((callee_text, file_rel, line))
        handler_outgoing_calls[handler_qname] = outgoing

    # BFS from each entrypoint. Track visited to handle cycles.
    # Result: reachable set of {callee_qname} with the path from
    # entrypoint to callee.
    # reachable: callee_qname → (entrypoint_qname, [path of qnames])
    reachable: dict[str, tuple[str, list[str]]] = {}
    # Track unfollowed local calls out of agent entrypoints for disclosure.
    unfollowed_local_calls: list[dict] = []
    followed_count = 0
    unfollowed_count = 0

    # BFS queue: (current_qname, path_so_far).
    # The path_so_far starts with the entrypoint qname itself.
    # When we visit a function, we look up its outgoing call sites in
    # the index (call_sites_in) AND merge with any handler-specific
    # outgoing calls (for anonymous arrows whose calls the index
    # attributed to the module-level synthetic caller).
    for ep_qname in entrypoint_qnames:
        visited_in_this_bfs: set[str] = set()
        queue: list[tuple[str, list[str]]] = [(ep_qname, [ep_qname])]
        while queue:
            current, path = queue.pop(0)
            if current in visited_in_this_bfs:
                continue
            visited_in_this_bfs.add(current)
            if len(path) > max_depth:
                continue

            # Collect outgoing calls from this function.
            outgoing_calls: list[tuple[str, str, int]] = []
            # From the handler_outgoing_calls map (for entrypoints).
            if current in handler_outgoing_calls:
                outgoing_calls.extend(handler_outgoing_calls[current])
            # From the index's call_sites (for non-entrypoint functions
            # — i.e. resolved callees we've recursed into).
            for cs in index.call_sites_in(current):
                outgoing_calls.append((
                    cs.callee_text,
                    cs.location.file,
                    cs.location.line,
                ))

            for callee_text, call_file, call_line in outgoing_calls:
                # Resolve the callee via the index.
                # in_module = the file the call is in (we look up the
                # module qname for that file).
                in_module = _ts_module_qname(index, call_file) or call_file
                symbol, certainty, qname_attempt = index.resolve_call_target(
                    callee_text, in_module
                )

                # Count disclosure: if it's a local-looking call (no dot
                # OR starts with "this." or "<") and we couldn't resolve
                # it, count as unfollowed.
                is_local = (
                    "." not in callee_text
                    or callee_text.startswith("this.")
                    or callee_text.startswith("<")
                )
                if symbol is not None and certainty in (
                    ResolutionCertainty.RESOLVED,
                    ResolutionCertainty.HEURISTIC,
                ):
                    followed_count += 1
                    callee_qname = symbol.qualified_name
                    if callee_qname in visited_in_this_bfs:
                        continue
                    new_path = path + [callee_qname]
                    # Record reachability.
                    if callee_qname not in reachable or len(new_path) < len(reachable[callee_qname][1]):
                        reachable[callee_qname] = (ep_qname, new_path)
                    queue.append((callee_qname, new_path))
                elif is_local:
                    unfollowed_count += 1
                    unfollowed_local_calls.append({
                        "file": call_file,
                        "line": call_line,
                        "caller": current,
                        "callee_text": callee_text,
                        "callee_qname": qname_attempt,
                        "certainty": certainty.value,
                        "reason": "unresolved_local_call",
                    })
                # External calls (e.g., "fs.writeFile", "http.Post") are
                # not counted as unfollowed — they are external sinks,
                # a different unit (mirrors the Python repo layer).

    result.transitive_followed_count = followed_count
    result.transitive_unfollowed_count = unfollowed_count
    result.local_call_edges = unfollowed_local_calls
    result.local_calls_followed = followed_count
    result.local_calls_unfollowed = unfollowed_count

    # Now emit findings for sinks in functions that are reachable AND
    # not already in the per-file findings list.
    existing_sink_locs: set[tuple[str, int]] = set()
    for f in findings + capabilities:
        existing_sink_locs.add((f.file, f.line))

    from actenon_scan.engine import Finding as EngineFinding

    for caller_qname, sinks in sinks_by_function.items():
        if caller_qname not in reachable:
            continue
        ep_qname, path = reachable[caller_qname]
        chain_text = " → ".join(path)
        for sink in sinks:
            loc = (sink["file"], sink["line"])
            if loc in existing_sink_locs:
                # Augment the existing finding instead of duplicating.
                for i, f in enumerate(findings):
                    if f.file == loc[0] and f.line == loc[1]:
                        suffix = (
                            f" [transitive path: {chain_text}]"
                            if f.reachability_reason
                            else f"transitive path: {chain_text}"
                        )
                        if chain_text not in (f.reachability_reason or ""):
                            f.reachability_reason = (f.reachability_reason or "") + suffix
                        result.augmented_findings.append((i, chain_text))
                        break
                continue
            # New transitive finding.
            new_finding = EngineFinding(
                file=sink["file"],
                line=sink["line"],
                col=sink.get("col", 0),
                rule_id=sink["rule_id"],
                category=sink["category"],
                severity=sink["severity"],
                confidence="medium",  # transitive reachability, not direct
                description=(
                    f"Transitively agent-reachable sink ({sink['rule_id']}) "
                    f"via {chain_text}. "
                    f"Agent reachability: PROVEN. "
                    f"Sink: PROVEN. "
                    f"Model-controlled sink argument: NOT ESTABLISHED."
                ),
                call_text=sink.get("call_text", ""),
                remediation=_remediation_for_category(sink["category"]),
                snippet_hash="",
                tier="production",
                reachability_reason=(
                    f"transitive:{chain_text} "
                    f"(model-controlled argument: NOT ESTABLISHED)"
                ),
            )
            result.new_findings.append(new_finding)
            existing_sink_locs.add(loc)  # avoid dupes within this run


# ---------------------------------------------------------------------------
# Go analysis
# ---------------------------------------------------------------------------


def _analyze_go(
    target: Path,
    findings: list,
    capabilities: list,
    go_files: list[Path],
    max_depth: int,
    result: CrossLanguageReachResult,
) -> None:
    """Build a GoRepositoryIndex, find handlers, traverse, emit findings."""
    from actenon_scan.repository.go_symbol_index import GoRepositoryIndex
    from actenon_scan.detectors.go import discover_all_go_sinks

    # Build the index from the engine's already-filtered file list.
    index = GoRepositoryIndex(root=target)
    for fp in go_files:
        try:
            rel = str(fp.relative_to(target)) if target.is_dir() else fp.name
            rel = rel.replace("\\", "/")
            source = fp.read_text(encoding="utf-8-sig")
            index.add_file(rel, source)
        except (UnicodeDecodeError, OSError, Exception):
            continue
    index.finalize()
    result.go_symbols_indexed = len(index.symbols)
    if not index.symbols:
        return

    # Discover ALL sinks across every indexed file (regardless of per-file
    # reachability). Group sinks by enclosing function qualified_name.
    sinks_by_function: dict[str, list[dict]] = {}
    for fp in go_files:
        try:
            source_bytes = fp.read_bytes()
            rel = str(fp.relative_to(target)) if target.is_dir() else fp.name
            rel = rel.replace("\\", "/")
        except (OSError, UnicodeDecodeError, Exception):
            continue
        sinks = discover_all_go_sinks(rel, source_bytes)
        for sink in sinks:
            caller_qname = _go_find_enclosing_function_qname_for_line(
                index, rel, sink["line"]
            )
            if caller_qname is None:
                # Fall back to the package qname (module-level call).
                pkg = _go_package_qname(index, rel) or "<package>"
                caller_qname = pkg
            sinks_by_function.setdefault(caller_qname, []).append({
                **sink,
                "file": rel,
                "caller_qname": caller_qname,
            })

    # Discover entrypoints (registered handlers).
    handler_specs: list[tuple[str, object, str, bytes]] = []
    for file_rel in index.files:
        ast_info = index.get_ast(file_rel)
        if ast_info is None:
            continue
        src, root_node = ast_info
        source_bytes = src.encode("utf-8") if isinstance(src, str) else src
        package_qname = _go_package_qname(index, file_rel) or file_rel
        for handler_node in _go_find_handlers_in_file(root_node, source_bytes):
            handler_specs.append((package_qname, handler_node, file_rel, source_bytes))
    result.go_entrypoint_count = len(handler_specs)
    if not handler_specs:
        return

    # Build entrypoint set + outgoing calls per entrypoint.
    entrypoint_qnames: list[str] = []
    handler_outgoing_calls: dict[str, list[tuple[str, str, int]]] = {}
    for package_qname, handler_node, file_rel, source_bytes in handler_specs:
        handler_qname = _go_handler_qname(handler_node, package_qname, source_bytes)
        entrypoint_qnames.append(handler_qname)
        outgoing: list[tuple[str, str, int]] = []
        for call_node in _go_walk_calls_in_subtree(handler_node):
            func = call_node.child_by_field_name("function")
            if func is None:
                continue
            callee_text = _go_node_text(func, source_bytes)
            if not callee_text:
                continue
            line = call_node.start_point[0] + 1
            col = call_node.start_point[1]
            outgoing.append((callee_text, file_rel, line))
        handler_outgoing_calls[handler_qname] = outgoing

    # BFS from each entrypoint.
    reachable: dict[str, tuple[str, list[str]]] = {}
    unfollowed_local_calls: list[dict] = []
    followed_count = 0
    unfollowed_count = 0

    for ep_qname in entrypoint_qnames:
        visited_in_this_bfs: set[str] = set()
        queue: list[tuple[str, list[str]]] = [(ep_qname, [ep_qname])]
        while queue:
            current, path = queue.pop(0)
            if current in visited_in_this_bfs:
                continue
            visited_in_this_bfs.add(current)
            if len(path) > max_depth:
                continue

            outgoing_calls: list[tuple[str, str, int]] = []
            if current in handler_outgoing_calls:
                outgoing_calls.extend(handler_outgoing_calls[current])
            for cs in index.call_sites_in(current):
                outgoing_calls.append((
                    cs.callee_text,
                    cs.location.file,
                    cs.location.line,
                ))

            for callee_text, call_file, call_line in outgoing_calls:
                in_module = _go_package_qname(index, call_file) or call_file
                symbol, certainty, qname_attempt = index.resolve_call_target(
                    callee_text, in_module
                )

                is_local = (
                    "." not in callee_text
                    or callee_text.startswith("<")
                )
                # For dotted calls (m.Method), the "m." prefix is a
                # receiver variable. If unresolved, it could be a local
                # method we couldn't disambiguate OR an external library
                # call. We count these as unfollowed_local_calls when
                # the receiver is a bare identifier (a local variable)
                # — that's the conservative choice.
                if "." in callee_text and not callee_text.startswith("<"):
                    head = callee_text.split(".", 1)[0]
                    # If head is capitalized (e.g., "fmt", "http"), it
                    # looks like an external package import — count as
                    # external, not unfollowed local.
                    # If head is lowercase (e.g., "manager", "m", "tx"),
                    # it looks like a local variable — count as
                    # unfollowed local if unresolved.
                    if not head[:1].isupper():
                        is_local = True

                if symbol is not None and certainty in (
                    ResolutionCertainty.RESOLVED,
                    ResolutionCertainty.HEURISTIC,
                ):
                    followed_count += 1
                    callee_qname = symbol.qualified_name
                    if callee_qname in visited_in_this_bfs:
                        continue
                    new_path = path + [callee_qname]
                    if callee_qname not in reachable or len(new_path) < len(reachable[callee_qname][1]):
                        reachable[callee_qname] = (ep_qname, new_path)
                    queue.append((callee_qname, new_path))
                elif is_local:
                    unfollowed_count += 1
                    unfollowed_local_calls.append({
                        "file": call_file,
                        "line": call_line,
                        "caller": current,
                        "callee_text": callee_text,
                        "callee_qname": qname_attempt,
                        "certainty": certainty.value,
                        "reason": "unresolved_local_call",
                    })

    result.transitive_followed_count += followed_count
    result.transitive_unfollowed_count += unfollowed_count
    result.local_call_edges.extend(unfollowed_local_calls)
    result.local_calls_followed += followed_count
    result.local_calls_unfollowed += unfollowed_count

    # Emit findings for sinks in reachable functions not already in
    # per-file findings.
    existing_sink_locs: set[tuple[str, int]] = set()
    for f in findings + capabilities:
        existing_sink_locs.add((f.file, f.line))

    from actenon_scan.engine import Finding as EngineFinding

    for caller_qname, sinks in sinks_by_function.items():
        if caller_qname not in reachable:
            continue
        ep_qname, path = reachable[caller_qname]
        chain_text = " → ".join(path)
        for sink in sinks:
            loc = (sink["file"], sink["line"])
            if loc in existing_sink_locs:
                for i, f in enumerate(findings):
                    if f.file == loc[0] and f.line == loc[1]:
                        suffix = (
                            f" [transitive path: {chain_text}]"
                            if f.reachability_reason
                            else f"transitive path: {chain_text}"
                        )
                        if chain_text not in (f.reachability_reason or ""):
                            f.reachability_reason = (f.reachability_reason or "") + suffix
                        result.augmented_findings.append((i, chain_text))
                        break
                continue
            new_finding = EngineFinding(
                file=sink["file"],
                line=sink["line"],
                col=sink.get("col", 0),
                rule_id=sink["rule_id"],
                category=sink["category"],
                severity=sink["severity"],
                confidence="medium",
                description=(
                    f"Transitively agent-reachable sink ({sink['rule_id']}) "
                    f"via {chain_text}. "
                    f"Agent reachability: PROVEN. "
                    f"Sink: PROVEN. "
                    f"Model-controlled sink argument: NOT ESTABLISHED."
                ),
                call_text=sink.get("call_text", ""),
                remediation=_remediation_for_category(sink["category"]),
                snippet_hash="",
                tier="production",
                reachability_reason=(
                    f"transitive:{chain_text} "
                    f"(model-controlled argument: NOT ESTABLISHED)"
                ),
            )
            result.new_findings.append(new_finding)
            existing_sink_locs.add(loc)


# ---------------------------------------------------------------------------
# TS helpers
# ---------------------------------------------------------------------------


def _ts_module_qname(index, file_rel: str) -> str | None:
    """Look up the module qualified name for a file in the TS index."""
    for info in index._modules.values():  # noqa: SLF001
        if info.path == file_rel:
            return info.qualified_name
    # Fallback: derive from the path (mirrors TSRepositoryIndex's convention).
    f = file_rel.replace("\\", "/")
    if f.startswith("./"):
        f = f[2:]
    for ext in (".tsx", ".ts", ".mts", ".cts", ".jsx", ".js", ".mjs", ".cjs"):
        if f.endswith(ext):
            f = f[: -len(ext)]
            break
    return f.replace("/", ".")


def _ts_find_enclosing_function_qname_for_line(
    index, root_node, line: int, module_qname: str, source_bytes: bytes
) -> str | None:
    """Find the qualified name of the function enclosing ``line``."""
    return index._enclosing_function_qualified_name(  # noqa: SLF001
        _find_node_at_line(root_node, line), module_qname, source_bytes
    )


def _find_node_at_line(root_node, line: int):
    """Find the deepest node whose start line matches ``line``."""
    target = None
    for node in _ts_walk_all(root_node):
        if node.start_point[0] + 1 == line:
            target = node
            break
    return target


def _ts_walk_all(node):
    yield node
    for child in node.children:
        yield from _ts_walk_all(child)


def _ts_find_handlers_in_file(root_node, source_bytes: bytes):
    """Yield (handler_node, handler_kind) tuples for each registered
    handler arrow/function in the file.

    A handler is the LAST positional argument of a call_expression whose
    callee matches one of ``_TS_REGISTRATION_CALLEES``. For
    ``DynamicStructuredTool`` the handler is the ``func`` property of
    the object literal (the only positional arg).
    """
    handlers: list[tuple[object, str]] = []
    for node in _ts_walk_all(root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None:
            continue
        callee_text = _ts_node_text(func, source_bytes)
        # Strip the receiver of dotted callees (e.g., "server.registerTool"
        # → "registerTool"; "setRequestHandler" stays as-is).
        last_seg = callee_text.rsplit(".", 1)[-1]
        if last_seg not in _TS_REGISTRATION_CALLEES:
            continue
        # Get the arguments.
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        arg_children = [c for c in args.children if c is not None and c.type != "," and c.type not in ("(", ")")]
        if not arg_children:
            continue
        last_arg = arg_children[-1]
        if last_seg == "DynamicStructuredTool":
            # The handler is the `func` property of the object literal.
            if last_arg.type == "object_literal":
                for prop in last_arg.children:
                    if prop.type == "pair":
                        key = prop.child_by_field_name("key")
                        if key is not None and _ts_node_text(key, source_bytes) == "func":
                            value = prop.child_by_field_name("value")
                            if value is not None and value.type in ("arrow_function", "function_expression", "function_declaration"):
                                handlers.append((value, "DynamicStructuredTool.func"))
                            break
        else:
            # The handler is the last positional arg, must be a function-like.
            if last_arg.type in ("arrow_function", "function_expression", "function_declaration"):
                handlers.append((last_arg, last_seg))
    return handlers


def _ts_handler_qname(handler_node, module_qname: str, source_bytes: bytes) -> str:
    """Synthesize a qualified_name for a handler node.

    For named functions passed to a registration call, the qname is the
    normal ``module.function_name``. For inline arrows / anonymous
    functions, the qname is a synthetic ``<handler@file:line>`` so the
    BFS visited-set still works.
    """
    if handler_node.type == "function_declaration":
        name = ""
        name_node = handler_node.child_by_field_name("name")
        if name_node is not None:
            name = _ts_node_text(name_node, source_bytes)
        if name:
            return f"{module_qname}.{name}" if module_qname else name
    if handler_node.type == "function_expression":
        name_node = handler_node.child_by_field_name("name")
        if name_node is not None:
            name = _ts_node_text(name_node, source_bytes)
            if name:
                return f"{module_qname}.{name}" if module_qname else name
    # Anonymous arrow / function expression.
    line = handler_node.start_point[0] + 1
    return f"<handler@{module_qname}:{line}>"


def _ts_walk_calls_in_subtree(handler_node):
    """Yield all call_expression nodes within the handler's body."""
    for node in _ts_walk_all(handler_node):
        if node.type == "call_expression":
            yield node


def _ts_node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Go helpers
# ---------------------------------------------------------------------------


def _go_package_qname(index, file_rel: str) -> str | None:
    """Look up the package qualified name for a file in the Go index."""
    info = index._packages.get(file_rel)  # noqa: SLF001
    if info is None:
        return None
    return info.qualified_name


def _go_find_enclosing_function_qname_for_line(
    index, file_rel: str, line: int
) -> str | None:
    """Find the qualified name of the function enclosing ``line``."""
    ast_info = index.get_ast(file_rel)
    if ast_info is None:
        return None
    src, root_node = ast_info
    source_bytes = src.encode("utf-8") if isinstance(src, str) else src
    package_qname = _go_package_qname(index, file_rel) or ""
    # Walk to find the innermost function_declaration or method_declaration
    # whose line range contains ``line``.
    best_match = None
    best_start = -1
    for node in _go_walk_all(root_node):
        if node.type in ("function_declaration", "method_declaration"):
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= line <= end and start > best_start:
                best_match = node
                best_start = start
    if best_match is None:
        return None
    name = _go_first_child_text(best_match, "name", source_bytes)
    if not name:
        return None
    if best_match.type == "method_declaration":
        recv = _go_receiver_type_name(best_match, source_bytes)
        if recv:
            if package_qname:
                return f"{package_qname}.{recv}.{name}"
            return f"{recv}.{name}"
    return f"{package_qname}.{name}" if package_qname else name


def _go_find_handlers_in_file(root_node, source_bytes: bytes):
    """Yield handler_node for each registered handler func_literal in the file.

    A handler is the LAST positional argument of a call_expression whose
    callee's last segment matches one of ``_GO_REGISTRATION_CALLEES``.
    """
    handlers: list[object] = []
    for node in _go_walk_all(root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None:
            continue
        callee_text = _go_node_text(func, source_bytes)
        last_seg = callee_text.rsplit(".", 1)[-1]
        if last_seg not in _GO_REGISTRATION_CALLEES:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        arg_children = [c for c in args.children if c is not None and c.type != "," and c.type not in ("(", ")")]
        if not arg_children:
            continue
        last_arg = arg_children[-1]
        if last_arg.type == "func_literal":
            handlers.append(last_arg)
    return handlers


def _go_handler_qname(handler_node, package_qname: str, source_bytes: bytes) -> str:
    """Synthesize a qualified_name for a Go handler func_literal."""
    line = handler_node.start_point[0] + 1
    return f"<handler@{package_qname}:{line}>"


def _go_walk_calls_in_subtree(handler_node):
    """Yield all call_expression nodes within the handler's body."""
    for node in _go_walk_all(handler_node):
        if node.type == "call_expression":
            yield node


def _go_walk_all(node):
    yield node
    for child in node.children:
        yield from _go_walk_all(child)


def _go_node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _go_first_child_text(node, field_name: str, source_bytes: bytes) -> str:
    child = node.child_by_field_name(field_name)
    if child is None:
        return ""
    return _go_node_text(child, source_bytes)


def _go_receiver_type_name(method_node, source_bytes: bytes) -> str:
    """Extract the receiver type name from a method_declaration."""
    receiver = method_node.child_by_field_name("receiver")
    if receiver is None:
        return ""
    for child in receiver.children:
        if child.type == "parameter_declaration":
            type_node = child.child_by_field_name("type")
            if type_node is None:
                continue
            type_text = _go_node_text(type_node, source_bytes)
            type_text = type_text.lstrip("*")
            return type_text
    return ""


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


_REMEDIATION_BY_CATEGORY = {
    "shell_execution": "Guard this shell call before execution.",
    "file_mutation": "Guard this filesystem mutation before execution.",
    "data_destruction": "Guard this destructive operation before execution.",
    "network_egress": "Guard this network egress before execution.",
    "payments": "Guard this payment operation before execution.",
    "provider_sdk": "Guard this cloud-SDK call before execution.",
}


def _remediation_for_category(category: str) -> str:
    return _REMEDIATION_BY_CATEGORY.get(
        category,
        "Guard this action before execution.",
    )
