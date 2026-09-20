"""Per-function Control Flow Graph + dominator analysis.

This module builds a lightweight intra-procedural CFG for a single
Python function and computes immediate dominators via the
Cooper-Harvey-Kennedy iterative algorithm. It is the substrate that a
future slice will use to replace the AST-ancestry guard-dominance
heuristic in :mod:`actenon_scan.detectors.guards` with proper
path-sensitive dominance.

This slice is **standalone** — it is not wired into ``guards.py`` or
any other existing module, and the repository package ``__init__.py``
does not re-export it. Future slices will consume :func:`build_cfg`,
:func:`dominators`, and :func:`dominates` directly from this module.

LIMITATIONS
------------
The CFG models a deliberate subset of Python's control flow. Anything
not listed below is modelled linearly (sequential fall-through), which
is sound for dominance of terminators but may be imprecise for guards
nested inside the un-modelled constructs:

- ``try`` / ``except`` / ``finally`` are NOT specially modelled. A
  ``try`` statement is treated as an opaque single node (its ``body``,
  ``handlers``, ``orelse``, and ``finalbody`` are NOT recursed into).
  This is conservative for dominance of code *after* the ``try``: a
  guard inside the ``try`` body that is swallowed by an ``except``
  handler will appear to dominate code after the ``try``. Callers that
  need except-handler soundness should continue to use the AST-ancestry
  dominance check in :mod:`actenon_scan.detectors.guards`.
- ``match`` / ``case`` (Python 3.10+ structural pattern matching) is
  NOT specially modelled. A ``match`` statement is treated as an
  opaque single node (its ``cases`` are NOT recursed into).
- ``with`` blocks are NOT specially modelled. A ``with`` statement is
  treated as an opaque single node (its body is NOT recursed into).
  This loses ``__exit__`` semantics.
- ``break`` and ``continue`` are handled only when they appear at the
  *top level* of a loop body. ``break`` / ``continue`` nested inside
  an ``if`` inside a loop body is treated as a terminator that ends
  the inner ``if``'s path; it does NOT link to the loop's exit or
  header. Top-level break/continue is rare in real code; nested
  break/continue is the common case and is left for a future slice
  to handle correctly.
- The CFG is **intra-procedural**. Nested ``ast.FunctionDef``,
  ``ast.AsyncFunctionDef``, and ``ast.Lambda`` are treated as opaque
  single nodes (their bodies are NOT added to the enclosing
  function's CFG).
- Exceptions raised by callees are not modelled (no interprocedural
  exception analysis).
- Generators and ``yield`` are not specially modelled; a generator
  function's CFG is built as if it were a regular function.
- ``for`` / ``while`` ``else:`` clauses are linearised after the
  loop exit (no break-vs-normal-exit discrimination).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CFGNode:
    """A single basic block in the control flow graph.

    Attributes:
        id: Unique node identifier within the enclosing CFG.
        statements: AST statements that compose this block. Each block
            contains at most one compound-statement header (``If``,
            ``For``, ``While``) or a single simple statement; the first
            statement determines ``start_line``.
        successors: IDs of nodes that control can flow to from this node.
        start_line: Source line of the first statement (0 if empty).
        terminator: ``""`` for normal fall-through, otherwise one of
            ``"return"``, ``"raise"``, ``"break"``, ``"continue"``.
    """

    id: int
    statements: list[ast.stmt] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    start_line: int = 0
    terminator: str = ""


@dataclass
class CFG:
    """A control flow graph for a single function.

    Attributes:
        entry: ID of the entry node (the function's first reachable block).
        nodes: All CFG nodes keyed by ID.
        function_name: Name of the function this CFG represents.
    """

    entry: int
    nodes: dict[int, CFGNode] = field(default_factory=dict)
    function_name: str = ""

    def succ(self, node_id: int) -> list[int]:
        """Return the successor IDs of ``node_id`` (empty if unknown)."""
        node = self.nodes.get(node_id)
        if node is None:
            return []
        return list(node.successors)

    def preds(self, node_id: int) -> list[int]:
        """Return the predecessor IDs of ``node_id``.

        Computed by scanning every node's ``successors`` list. This is
        O(N) per query; the dominator algorithm calls it once per node
        per iteration, so the overall cost is O(N^2 * iterations) —
        acceptable for the function-sized CFGs this module is built for.
        """
        result: list[int] = []
        for nid, node in self.nodes.items():
            if node_id in node.successors:
                result.append(nid)
        return result

    def find_node_containing_line(self, line: int) -> int | None:
        """Return the ID of the node whose statement list covers ``line``.

        Preference order:
          1. A node with a statement whose ``lineno`` exactly equals
             ``line`` (the first such node in insertion order).
          2. A node whose statement line range contains ``line`` (the
             smallest such range wins, breaking ties by insertion order).

        Returns ``None`` if no node covers ``line`` (e.g. the line is in
        a nested function body that was treated as opaque, or the line
        is outside the function entirely).
        """
        exact: list[int] = []
        for nid, node in self.nodes.items():
            for s in node.statements:
                if getattr(s, "lineno", None) == line:
                    exact.append(nid)
                    break
        if exact:
            return exact[0]
        candidates: list[tuple[int, int, int]] = []
        for nid, node in self.nodes.items():
            for s in node.statements:
                start = getattr(s, "lineno", None)
                end = getattr(s, "end_lineno", None) or start
                if start is not None and start <= line <= end:
                    candidates.append((end - start, len(candidates), nid))
                    break
        if candidates:
            candidates.sort()
            return candidates[0][2]
        return None


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build_cfg(func_node) -> CFG:
    """Build a control flow graph for a function definition node.

    Args:
        func_node: An ``ast.FunctionDef``, ``ast.AsyncFunctionDef``,
            or any node with a ``body`` attribute (e.g. an ``ast.Module``
            for a module-level scan).

    Returns:
        A :class:`CFG` with ``entry``, ``nodes``, and successor links
        populated. The function's body is walked statement-by-statement;
        nested function definitions and lambdas are treated as opaque.
    """
    name = getattr(func_node, "name", "")
    cfg = CFG(entry=-1, function_name=name)
    builder = _CFGBuilder(cfg)
    body = list(getattr(func_node, "body", []))
    builder.process_statements(body, [])
    # Defensive: if the function body was empty (no statements at all —
    # not valid Python, but possible with synthetic nodes), ensure there
    # is still an entry node.
    if cfg.entry < 0:
        nid = builder._new_node()
        cfg.entry = nid
    return cfg


# ---------------------------------------------------------------------------
# Dominators (Cooper-Harvey-Kennedy)
# ---------------------------------------------------------------------------


def reverse_postorder(cfg: CFG) -> list[int]:
    """Return the CFG's nodes in reverse post-order from the entry.

    Reverse post-order is the iteration order used by
    Cooper-Harvey-Kennedy for fast convergence of the dominator
    fixed-point. Nodes unreachable from the entry are excluded.
    """
    if not cfg.nodes or cfg.entry not in cfg.nodes:
        return []
    visited: set[int] = set()
    postorder: list[int] = []

    # Iterative DFS to avoid Python recursion-limit issues on wide CFGs.
    stack: list[tuple[int, int]] = [(cfg.entry, 0)]
    visited.add(cfg.entry)
    while stack:
        nid, succ_idx = stack[-1]
        succs = cfg.nodes[nid].successors
        if succ_idx < len(succs):
            stack[-1] = (nid, succ_idx + 1)
            child = succs[succ_idx]
            if child not in visited:
                visited.add(child)
                stack.append((child, 0))
        else:
            stack.pop()
            postorder.append(nid)

    postorder.reverse()
    return postorder


def dominators(cfg: CFG) -> dict[int, int]:
    """Compute immediate dominators using Cooper-Harvey-Kennedy.

    Returns a dict mapping each reachable node ID to its immediate
    dominator's ID. The entry node maps to itself. Unreachable nodes
    (no path from entry) are excluded from the result.

    Reference: K. Cooper, T. Harvey, K. Kennedy, "A Simple, Fast
    Dominance Algorithm" (Rice CS TR-06-338).
    """
    if not cfg.nodes or cfg.entry not in cfg.nodes:
        return {}
    entry = cfg.entry
    rpo = reverse_postorder(cfg)
    rpo_index: dict[int, int] = {nid: i for i, nid in enumerate(rpo)}
    idom: dict[int, int] = {entry: entry}

    def intersect(a: int, b: int) -> int:
        finger1 = a
        finger2 = b
        while finger1 != finger2:
            while rpo_index[finger1] > rpo_index[finger2]:
                finger1 = idom[finger1]
            while rpo_index[finger2] > rpo_index[finger1]:
                finger2 = idom[finger2]
        return finger1

    changed = True
    while changed:
        changed = False
        for nid in rpo:
            if nid == entry:
                continue
            preds = cfg.preds(nid)
            new_idom = -1
            for p in preds:
                if p in idom:
                    new_idom = p
                    break
            if new_idom == -1:
                # No pred has been processed yet — node is currently
                # unreachable on this iteration. Skip; it will either
                # become reachable as idom propagates, or remain
                # unreachable (and be excluded from the result).
                continue
            for p in preds:
                if p == new_idom:
                    continue
                if p in idom:
                    new_idom = intersect(p, new_idom)
            if nid not in idom or idom[nid] != new_idom:
                idom[nid] = new_idom
                changed = True
    return idom


def dominates(
    cfg: CFG,
    doms: dict[int, int],
    dominator_id: int,
    dominated_id: int,
) -> bool:
    """Return True if ``dominator_id`` dominates ``dominated_id``.

    A node D dominates N if every path from the entry to N passes
    through D. This implementation walks the immediate-dominator chain
    from N upward; if it reaches D, returns True. If it reaches the
    entry without finding D, returns False.

    Every node dominates itself (trivially). The entry dominates every
    reachable node. Unreachable nodes return False for any dominator
    query (including self-domination) — they are not in ``doms``.
    """
    if dominator_id not in cfg.nodes or dominated_id not in cfg.nodes:
        return False
    if dominator_id == dominated_id:
        return True
    if dominator_id not in doms or dominated_id not in doms:
        return False
    if dominator_id == cfg.entry:
        # Entry dominates every reachable node.
        return True
    current = dominated_id
    # Bound the walk to len(nodes) + 1 steps to prevent infinite loops
    # on malformed idom maps (defensive — CHK guarantees termination).
    for _ in range(len(cfg.nodes) + 1):
        if current not in doms:
            return False
        parent = doms[current]
        if parent == dominator_id:
            return True
        if parent == current:
            # Self-loop — only the entry self-loops in a well-formed CFG.
            return False
        if parent == cfg.entry:
            # Reached the entry without finding the dominator.
            return False
        current = parent
    return False


# ---------------------------------------------------------------------------
# Internal builder
# ---------------------------------------------------------------------------


# Statement types whose body we DO NOT recurse into (treated as opaque
# single nodes). Documented in the module docstring as LIMITATIONS.
_OPAQUE_TYPES: tuple[type, ...] = (ast.Try, ast.With)
if hasattr(ast, "Match"):
    _OPAQUE_TYPES = _OPAQUE_TYPES + (ast.Match,)


class _CFGBuilder:
    """Internal helper that owns node allocation during construction.

    The builder walks the function body statement-by-statement,
    maintaining a list of "current predecessor node IDs" — the set of
    nodes whose control falls through to the next statement to be
    processed. Branch statements (``If``, ``For``, ``While``) split
    and merge this list; terminators (``Return``, ``Raise``,
    ``Break``, ``Continue``) empty it.
    """

    def __init__(self, cfg: CFG):
        self.cfg = cfg
        self._next_id = 0

    # -- node allocation --------------------------------------------------

    def _new_node(self) -> int:
        nid = self._next_id
        self._next_id += 1
        self.cfg.nodes[nid] = CFGNode(id=nid)
        if self.cfg.entry < 0:
            self.cfg.entry = nid
        return nid

    def _add_stmt_to_new_node(
        self,
        stmt: ast.stmt,
        preds: list[int],
        terminator: str = "",
    ) -> int:
        nid = self._new_node()
        node = self.cfg.nodes[nid]
        node.statements.append(stmt)
        node.start_line = getattr(stmt, "lineno", 0) or 0
        node.terminator = terminator
        for p in preds:
            self.cfg.nodes[p].successors.append(nid)
        return nid

    def _append_simple(self, stmt: ast.stmt, preds: list[int]) -> list[int]:
        """Append a non-terminator simple statement.

        If there is exactly one predecessor node with no statements
        and no terminator, append to it (this is how the entry node
        acquires its first statement, and how loop-exit nodes acquire
        the next sequential statement). Otherwise create a new node
        linked from all current predecessors.
        """
        if len(preds) == 1:
            node = self.cfg.nodes[preds[0]]
            if not node.statements and not node.terminator:
                node.statements.append(stmt)
                node.start_line = getattr(stmt, "lineno", 0) or 0
                return preds
        nid = self._add_stmt_to_new_node(stmt, preds)
        return [nid]

    # -- statement dispatch ----------------------------------------------

    def process_statements(
        self,
        body: list[ast.stmt],
        preds: list[int],
    ) -> list[int]:
        """Process a sequence of statements; return the list of exit node IDs."""
        current = list(preds)
        for stmt in body:
            current = self._process_one(stmt, current)
        return current

    def _process_one(self, stmt: ast.stmt, preds: list[int]) -> list[int]:
        # Nested function definitions are opaque — single node, no
        # recursion into their bodies (their CFGs are built separately).
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return self._append_simple(stmt, preds)
        # Terminators end the path.
        if isinstance(stmt, ast.Return):
            self._add_stmt_to_new_node(stmt, preds, terminator="return")
            return []
        if isinstance(stmt, ast.Raise):
            self._add_stmt_to_new_node(stmt, preds, terminator="raise")
            return []
        if isinstance(stmt, ast.Break):
            # Top-level break in a loop body is intercepted by
            # _process_loop_body. Reaching here means the break is at
            # the top level of the function body (a syntax error in
            # Python) — treat defensively as a terminator.
            self._add_stmt_to_new_node(stmt, preds, terminator="break")
            return []
        if isinstance(stmt, ast.Continue):
            self._add_stmt_to_new_node(stmt, preds, terminator="continue")
            return []
        # Compound: If.
        if isinstance(stmt, ast.If):
            return self._process_if(stmt, preds)
        # Compound: For / While.
        if isinstance(stmt, (ast.For, ast.While)):
            return self._process_loop(stmt, preds)
        # Opaque (LIMITATIONS): try / with / match.
        if isinstance(stmt, _OPAQUE_TYPES):
            return self._append_simple(stmt, preds)
        # Default: simple sequential statement.
        return self._append_simple(stmt, preds)

    def _process_if(self, stmt: ast.If, preds: list[int]) -> list[int]:
        if_node = self._add_stmt_to_new_node(stmt, preds)
        body_exits = self.process_statements(list(stmt.body), [if_node])
        else_exits = self.process_statements(list(stmt.orelse), [if_node])
        if not stmt.orelse:
            # No else — control falls through from the if header directly
            # when the test is false.
            else_exits = [if_node]
        return body_exits + else_exits

    def _process_loop(
        self,
        stmt,  # ast.For | ast.While
        preds: list[int],
    ) -> list[int]:
        header = self._add_stmt_to_new_node(stmt, preds)
        # Loop-exit placeholder. Becomes the after-loop control point.
        # Statements after the loop attach to it via _append_simple.
        exit_id = self._new_node()
        # The loop header has an edge to the exit (loop condition may be
        # false on first iteration, or the loop runs zero times).
        self.cfg.nodes[header].successors.append(exit_id)
        body_exits = self._process_loop_body(
            list(stmt.body), [header], header=header, exit_id=exit_id,
        )
        # Back-edges: each fall-through exit of the body links to the
        # header (the loop iterates again).
        for be in body_exits:
            self.cfg.nodes[be].successors.append(header)
        # If the loop has an else clause (ast.For.orelse / ast.While.orelse),
        # it executes when the loop exits normally (no break). We model
        # this conservatively as: exit → orelse statements → after-orelse.
        after_loop_preds = [exit_id]
        if stmt.orelse:
            after_loop_preds = self.process_statements(
                list(stmt.orelse), [exit_id],
            )
        return after_loop_preds

    def _process_loop_body(
        self,
        body: list[ast.stmt],
        preds: list[int],
        *,
        header: int,
        exit_id: int,
    ) -> list[int]:
        """Process a loop body, routing top-level break/continue.

        ``break`` (at the top level of the body) links to ``exit_id``.
        ``continue`` (at the top level of the body) links to ``header``.
        Both end the path within the body (returning ``[]``).

        Nested ``break`` / ``continue`` (inside an ``if`` inside the
        loop body) is NOT specially handled — it goes through
        :meth:`_process_one` which treats it as a terminator that ends
        the inner ``if``'s path. This is a documented LIMITATION.
        """
        current = list(preds)
        for stmt in body:
            if isinstance(stmt, ast.Break):
                nid = self._add_stmt_to_new_node(
                    stmt, current, terminator="break",
                )
                # break exits the loop.
                self.cfg.nodes[nid].successors.append(exit_id)
                current = []
                continue
            if isinstance(stmt, ast.Continue):
                nid = self._add_stmt_to_new_node(
                    stmt, current, terminator="continue",
                )
                # continue re-enters the loop header.
                self.cfg.nodes[nid].successors.append(header)
                current = []
                continue
            current = self._process_one(stmt, current)
        return current
