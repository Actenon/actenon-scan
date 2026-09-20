"""Interprocedural call graph with provenance.

A :class:`CallGraph` is built from a :class:`RepositoryIndex`. Each
:class:`CallEdge` records *why* it exists — whether the callee was
resolved via an import binding, a local definition, a heuristic name
match, or remained unresolved. This provenance flows through to
:class:`CallPath` and is emitted in evidence paths so that downstream
reporters can distinguish proven-correct chains from heuristic ones.

The call graph is conservative:

- Unresolved callees produce an explicit
  :data:`ResolutionCertainty.UNRESOLVED` edge — they are *not* silently
  dropped, and they are *not* silently promoted to a heuristic match.
- Recursion and mutual recursion are handled by visited sets and
  strongly-connected-component (SCC) processing. Effects and taint
  propagate to fixed point across SCCs.
- The maximum analysis depth is bounded by ``max_depth``. A path that
  exceeds the depth is truncated with an explicit ``truncated=True``
  marker, not silently cut.

What this module deliberately does NOT do:

- Resolve dynamic dispatch (``getattr``, plugin registries).
- Walk into third-party libraries (the call graph is repository-local).
- Reconstruct dataflow paths (those are in :mod:`repository.taint`).
"""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterator

from actenon_scan.repository.symbol_index import (
    CallSite,
    RepositoryIndex,
    ResolutionCertainty,
    Symbol,
    SymbolKind,
)


# ---------------------------------------------------------------------------
# Edges and paths
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallEdge:
    """A directed edge from caller to callee in the call graph.

    ``caller`` and ``callee`` are qualified names. ``site`` is the
    call-site that gave rise to this edge (location + callee text).
    ``certainty`` is inherited from the symbol resolution step —
    RESOLVED edges always dominate HEURISTIC edges, which dominate
    UNRESOLVED edges.
    """

    caller: str
    callee: str
    certainty: ResolutionCertainty
    site: CallSite

    def is_resolved(self) -> bool:
        return self.certainty == ResolutionCertainty.RESOLVED

    def is_heuristic(self) -> bool:
        return self.certainty == ResolutionCertainty.HEURISTIC

    def is_unresolved(self) -> bool:
        return self.certainty == ResolutionCertainty.UNRESOLVED


@dataclass
class CallPath:
    """A path through the call graph from an entrypoint to a target.

    ``edges`` is ordered from the entrypoint outward. ``truncated`` is
    True if the path hit ``max_depth`` before reaching the target.

    The path is the *evidence* for a finding's reachability claim.
    """

    edges: list[CallEdge] = field(default_factory=list)
    truncated: bool = False

    @property
    def entrypoint(self) -> str:
        return self.edges[0].caller if self.edges else ""

    @property
    def target(self) -> str:
        return self.edges[-1].callee if self.edges else ""

    @property
    def length(self) -> int:
        return len(self.edges)

    def chain_text(self) -> str:
        """Human-readable chain: ``a → b → c → sink``."""
        if not self.edges:
            return ""
        parts: list[str] = [self.edges[0].caller]
        for e in self.edges:
            parts.append(e.callee)
        marker = " … (truncated)" if self.truncated else ""
        return " → ".join(parts) + marker

    def certainty(self) -> ResolutionCertainty:
        """The weakest certainty across all edges.

        A single UNRESOLVED edge makes the whole path UNRESOLVED.
        A single HEURISTIC edge makes the path HEURISTIC unless an
        UNRESOLVED edge is present.
        Otherwise RESOLVED.
        """
        if not self.edges:
            return ResolutionCertainty.UNRESOLVED
        if any(e.is_unresolved() for e in self.edges):
            return ResolutionCertainty.UNRESOLVED
        if any(e.is_heuristic() for e in self.edges):
            return ResolutionCertainty.HEURISTIC
        return ResolutionCertainty.RESOLVED


# ---------------------------------------------------------------------------
# Call graph
# ---------------------------------------------------------------------------


@dataclass
class CallGraph:
    """Adjacency-list call graph over repository symbols.

    ``edges_by_caller`` maps a caller qualified name to the list of
    out-edges. ``edges_by_callee`` is the reverse adjacency list, used
    for backward reachability queries ("who calls this function?").
    """

    edges_by_caller: dict[str, list[CallEdge]] = field(default_factory=lambda: defaultdict(list))
    edges_by_callee: dict[str, list[CallEdge]] = field(default_factory=lambda: defaultdict(list))
    # All edges in insertion order (for stable iteration in tests).
    all_edges: list[CallEdge] = field(default_factory=list)
    # All symbols known to the graph (callers and callees).
    nodes: dict[str, Symbol] = field(default_factory=dict)

    def callers_of(self, callee_qname: str) -> list[str]:
        """All callers of ``callee_qname`` (unique, insertion order)."""
        seen: list[str] = []
        for e in self.edges_by_callee.get(callee_qname, []):
            if e.caller not in seen:
                seen.append(e.caller)
        return seen

    def callees_of(self, caller_qname: str) -> list[str]:
        """All callees of ``caller_qname`` (unique, insertion order)."""
        seen: list[str] = []
        for e in self.edges_by_caller.get(caller_qname, []):
            if e.callee not in seen:
                seen.append(e.callee)
        return seen

    def edge_certainty(self, caller: str, callee: str) -> ResolutionCertainty:
        """The strongest certainty of any edge between caller and callee."""
        best = ResolutionCertainty.UNRESOLVED
        # RESOLVED > HEURISTIC > UNRESOLVED — pick the *strongest* found.
        order = {
            ResolutionCertainty.UNRESOLVED: 0,
            ResolutionCertainty.HEURISTIC: 1,
            ResolutionCertainty.RESOLVED: 2,
        }
        for e in self.edges_by_caller.get(caller, []):
            if e.callee == callee and order[e.certainty] > order[best]:
                best = e.certainty
        return best

    def sccs(self) -> list[list[str]]:
        """Tarjan's algorithm for strongly-connected components.

        Used by effect/taint propagation to detect cycles and process
        them as a unit (fixed-point within the SCC, then propagate out).
        """
        # Iterative Tarjan to avoid Python recursion limits on deep graphs.
        index_counter = [0]
        stack: list[str] = []
        on_stack: set[str] = set()
        indices: dict[str, int] = {}
        lowlinks: dict[str, int] = {}
        result: list[list[str]] = []

        # Build a successor map (callers → callees, deduplicated).
        succ: dict[str, list[str]] = {}
        for caller, edges in self.edges_by_caller.items():
            seen: list[str] = []
            for e in edges:
                if e.callee not in seen:
                    seen.append(e.callee)
            succ[caller] = seen

        # Iterative Tarjan over all nodes (some nodes may only appear as
        # callees, not callers).
        all_nodes: set[str] = set()
        all_nodes.update(self.edges_by_caller.keys())
        all_nodes.update(self.edges_by_callee.keys())
        all_nodes.update(self.nodes.keys())

        for start in sorted(all_nodes):
            if start in indices:
                continue
            work: list[tuple[str, Iterator[str]]] = [(start, iter(succ.get(start, [])))]
            indices[start] = index_counter[0]
            lowlinks[start] = index_counter[0]
            index_counter[0] += 1
            stack.append(start)
            on_stack.add(start)
            while work:
                node, succ_iter = work[-1]
                advanced = False
                for s in succ_iter:
                    if s not in indices:
                        indices[s] = index_counter[0]
                        lowlinks[s] = index_counter[0]
                        index_counter[0] += 1
                        stack.append(s)
                        on_stack.add(s)
                        work.append((s, iter(succ.get(s, []))))
                        advanced = True
                        break
                    elif s in on_stack:
                        lowlinks[node] = min(lowlinks[node], indices[s])
                if advanced:
                    continue
                # Done with `node`
                if lowlinks[node] == indices[node]:
                    scc: list[str] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        scc.append(w)
                        if w == node:
                            break
                    result.append(scc)
                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlinks[parent] = min(lowlinks[parent], lowlinks[node])

        return result


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def build_call_graph(index: RepositoryIndex, *, max_call_args: int = 32) -> CallGraph:
    """Build a call graph by resolving every call site in the index.

    Edges are created for every call site, including unresolved ones
    (with :data:`ResolutionCertainty.UNRESOLVED`). This preserves the
    information that a call *exists* even when we cannot prove its
    target — which is important for hostile analysis (e.g. ``getattr``
    dispatch).

    The caller is always the enclosing function's qualified name. The
    callee is the resolved symbol's qualified name (if resolved) or the
    textual callee (if unresolved).
    """
    g = CallGraph()

    for sym in index.symbols:
        g.nodes[sym.qualified_name] = sym

    for caller_qname, sites in index._call_sites_by_caller.items():
        # Determine the module this caller lives in.
        module_qname = _module_qname_of_caller(caller_qname)
        for site in sites:
            # Re-resolve the callee using the index.
            tree_info = index.get_ast(site.location.file)
            if tree_info is None:
                # File not in index — record an unresolved edge with the
                # textual callee so the call site is not silently lost.
                callee_text = site.callee_text
                edge = CallEdge(
                    caller=caller_qname,
                    callee=callee_text,
                    certainty=ResolutionCertainty.UNRESOLVED,
                    site=site,
                )
                g.edges_by_caller[caller_qname].append(edge)
                g.edges_by_callee[callee_text].append(edge)
                g.all_edges.append(edge)
                continue
            source, tree = tree_info
            # Find the call AST node at the site line/col.
            call_node = _find_call(tree, site.location.line, site.location.col)
            if call_node is None:
                # Site refers to a call we can't relocate — UNRESOLVED.
                edge = CallEdge(
                    caller=caller_qname,
                    callee=site.callee_text,
                    certainty=ResolutionCertainty.UNRESOLVED,
                    site=site,
                )
                g.edges_by_caller[caller_qname].append(edge)
                g.edges_by_callee[site.callee_text].append(edge)
                g.all_edges.append(edge)
                continue
            sym, certainty, qname_attempt = index.resolve_call_target(
                call_node.func, in_module=module_qname
            )
            if sym is not None:
                callee_qname = sym.qualified_name
                g.nodes.setdefault(callee_qname, sym)
            else:
                callee_qname = qname_attempt or site.callee_text
            edge = CallEdge(
                caller=caller_qname,
                callee=callee_qname,
                certainty=certainty,
                site=site,
            )
            g.edges_by_caller[caller_qname].append(edge)
            g.edges_by_callee[callee_qname].append(edge)
            g.all_edges.append(edge)

    return g


def _module_qname_of_caller(caller_qname: str) -> str:
    """Strip the function name (and class) off a caller qualified name
    to get the module qualified name.

    ``pkg.mod.fn`` → ``pkg.mod``
    ``pkg.mod.Class.method`` → ``pkg.mod``

    Best-effort: if the caller is a single-segment name (top-level
    function in a root module), returns that name.
    """
    if "." not in caller_qname:
        return caller_qname
    # Drop the last segment (function name).
    parent = caller_qname.rsplit(".", 1)[0]
    # If there's still a class in there, we can't tell without symbol
    # info — let the index's binding lookup handle it. Returning the
    # package-qualified name is safe.
    return parent


def _find_call(tree: ast.Module, line: int, col: int) -> ast.Call | None:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node, "lineno", None) == line
            and getattr(node, "col_offset", None) == col
        ):
            return node
    return None


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------


def transitive_reachable(
    graph: CallGraph,
    entrypoints: list[str],
    *,
    max_depth: int = 32,
) -> dict[str, CallPath]:
    """Breadth-first reachability from a set of entrypoints.

    Returns a map from every reachable node qualified name to the
    *shortest* path (in edges) from any entrypoint. When multiple
    entrypoints reach a node, the path from the *first* entrypoint
    (in input order) that reached it is returned.

    ``max_depth`` bounds the search depth. A path that exceeds it is
    recorded with ``truncated=True`` so downstream analysis knows the
    reachability claim is incomplete. Soundness is preserved: a
    truncated path still means "this node IS reachable" — we just
    cannot show the complete chain.

    Cycles are handled by a visited set: each node is enqueued at most
    once. We still explore its out-edges even if we've seen it before
    (so that back-edges into the SCC are preserved as evidence), but we
    do not re-enqueue.
    """
    # Queue of (node, path_so_far, depth_so_far)
    queue: deque[tuple[str, CallPath, int]] = deque()
    # Best-known path per node (shortest edge count).
    best: dict[str, CallPath] = {}
    # Visited set — prevents infinite loops on cycles.
    visited: set[str] = set()

    for ep in entrypoints:
        # An entrypoint that doesn't exist in the graph is still
        # recorded as reachable-from-itself with an empty path.
        if ep not in best:
            best[ep] = CallPath()
            queue.append((ep, CallPath(), 0))

    while queue:
        node, path, depth = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        if depth >= max_depth:
            # Mark the existing best path as truncated — node IS
            # reachable, but the chain beyond it is incomplete.
            # Soundness is preserved: the reachability claim stays TRUE.
            if node in best and not best[node].truncated:
                best[node] = CallPath(edges=best[node].edges, truncated=True)
            continue
        for edge in graph.edges_by_caller.get(node, []):
            neighbor = edge.callee
            # A path is truncated if it was already truncated, OR we are
            # about to hit the depth limit and the neighbor still has
            # out-edges (so we cannot prove the chain ended here).
            will_truncate = path.truncated or (
                (depth + 1) >= max_depth
                and bool(graph.edges_by_caller.get(neighbor, []))
            )
            new_path = CallPath(
                edges=path.edges + [edge],
                truncated=will_truncate,
            )
            if neighbor not in best or new_path.length < best[neighbor].length:
                best[neighbor] = new_path
            if neighbor not in visited:
                queue.append((neighbor, new_path, depth + 1))

    return best
