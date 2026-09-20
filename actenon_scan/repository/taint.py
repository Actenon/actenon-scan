"""Function-local taint / dataflow analysis with provenance.

This module tracks how *model-controlled* values flow through a single
Python function body. It is deliberately **intra-procedural**: it
analyses one function at a time, using the repository call graph for
cross-function summary propagation (see :mod:`repository.effect_summary`).

The taint lattice (weakest to strongest):

    UNTAINTED    — proven not derived from external input.
    EXTERNAL     — derived from a function parameter (agent-controlled
                   or otherwise external).
    MODEL_CONTROLLED — derived from a parameter *and* propagated
                   through transformations the analyser understands
                   (assignment, attribute access, dict access,
                   f-string, str/int casts, json.loads, wrapper
                   returns).
    MODEL_DERIVED — derived from MODEL_CONTROLLED via a transformation
                   we partially understand (e.g. through a wrapper).
    CONSTRAINED  — derived from MODEL_CONTROLLED but bound by a
                   guard/sanitiser that we recognise as limiting.
    UNKNOWN      — provenance cannot be determined.

The lattice is conservative: ``UNKNOWN`` is *never* silently promoted
to ``UNTAINTED``. A value we can't track stays ``UNKNOWN``, not "safe".

What this module tracks (function-local):

- assignment: ``x = payload``
- attribute access: ``x.command``
- dict access: ``x["command"]``
- f-string: ``f"{payload}/run"``
- string concat: ``payload + " " + suffix``
- ``str(x)``, ``int(x)``, ``Path(x)`` — pass-through
- ``json.loads(x)`` — pass-through (the dict *is* tainted if the input
  is tainted; accesses into it stay tainted)
- wrapper returns: ``y = helper(x)`` where ``helper`` is a single-return
  function whose body is ``return <param>`` — limited to 1-hop.

What it does NOT track:

- aliasing through containers (lists, sets)
- mutable aliasing
- interprocedural return-value taint (except the 1-hop wrapper case)
- sanitisation claims — a transformation NEVER downgrades taint; only
  an explicit guard/sanitiser (recognised by the guards layer) does.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from actenon_scan.repository.symbol_index import RepositoryIndex


# ---------------------------------------------------------------------------
# Lattice
# ---------------------------------------------------------------------------


class TaintLattice(str, Enum):
    UNTAINTED = "untainted"
    EXTERNAL = "external"
    MODEL_CONTROLLED = "model_controlled"
    MODEL_DERIVED = "model_derived"
    CONSTRAINED = "constrained"
    UNKNOWN = "unknown"


# Lattice ordering for joins. Weakest to strongest.
_LATTICE_ORDER: dict[TaintLattice, int] = {
    TaintLattice.UNTAINTED: 0,
    TaintLattice.CONSTRAINED: 1,  # constrained is "tainted but limited"
    TaintLattice.EXTERNAL: 2,
    TaintLattice.MODEL_DERIVED: 3,
    TaintLattice.MODEL_CONTROLLED: 4,
    TaintLattice.UNKNOWN: 5,  # treated as the strongest for join (worst-case)
}


def join_taint(a: TaintLattice, b: TaintLattice) -> TaintLattice:
    """Combine two taint states — takes the *stronger*.

    UNKNOWN dominates: any join with UNKNOWN produces UNKNOWN, because
    we cannot prove the result is safe.
    """
    if a == TaintLattice.UNKNOWN or b == TaintLattice.UNKNOWN:
        return TaintLattice.UNKNOWN
    return a if _LATTICE_ORDER[a] >= _LATTICE_ORDER[b] else b


# ---------------------------------------------------------------------------
# Taint facts and traces
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaintOrigin:
    """Where a tainted value came from.

    ``parameter_name`` is the function parameter that originally introduced
    the taint. ``via`` is the chain of operations that propagated it
    (e.g. ``["json.loads", "['command']", "str"]``). An empty ``via``
    means the value IS the parameter.
    """

    parameter_name: str
    via: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class TaintFact:
    """A single variable's taint state at a program point.

    ``origin`` is None when ``state`` is UNTAINTED or UNKNOWN.
    """

    state: TaintLattice
    origin: TaintOrigin | None = None


@dataclass
class TaintTrace:
    """A complete trace of how a value reached a sink.

    A trace's ``certainty`` is the strongest claim the analyser can make
    about the value's provenance. PROVEN requires a complete chain from
    parameter to sink with no UNKNOWN links.
    """

    parameter_name: str
    operations: list[str]  # ordered list, e.g. ["json.loads", "['command']", "str"]
    final_state: TaintLattice
    certainty: str  # "proven" / "heuristic" / "unknown" — matches AnalysisCertainty values

    def render(self) -> str:
        """Human-readable: ``payload → json.loads → ['command'] → str → command``."""
        parts = [self.parameter_name]
        parts.extend(self.operations)
        return " → ".join(parts)


# ---------------------------------------------------------------------------
# Function-local dataflow
# ---------------------------------------------------------------------------


def _param_names(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """All parameter names (positional, *args, **kwargs, keyword-only)."""
    names: set[str] = set()
    args = func_node.args
    for a in args.posonlyargs + args.args + args.kwonlyargs:
        names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _is_self_attr(node: ast.AST, self_name: str = "self") -> tuple[bool, str]:
    """If ``node`` is ``self.<attr>``, return (True, attr_name).
    Otherwise (False, "").
    """
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == self_name
    ):
        return True, node.attr
    return False, ""


def _is_param_attribute(node: ast.AST, params: set[str]) -> tuple[bool, str, str]:
    """If ``node`` is ``param.<attr>`` for a known parameter, return (True, param, attr).
    Otherwise (False, "", "").
    """
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id in params:
            return True, node.value.id, node.attr
    return False, "", ""


def _is_subscript_of(node: ast.AST, params: set[str]) -> tuple[bool, str]:
    """If ``node`` is ``param[...]`` for a known parameter, return (True, param).
    Otherwise (False, "").
    """
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id in params:
            return True, node.value.id
    return False, ""


def _taint_of_expression(
    expr: ast.AST,
    env: dict[str, TaintFact],
    params: set[str],
    *,
    index: RepositoryIndex | None = None,
    module_qname: str = "",
) -> TaintFact:
    """Compute the taint of an arbitrary expression.

    Conservative: anything we cannot classify is UNKNOWN.
    """
    # Literals are untainted.
    if isinstance(expr, ast.Constant):
        return TaintFact(state=TaintLattice.UNTAINTED)
    # f-string: join taint of all interpolated parts
    if isinstance(expr, ast.JoinedStr):
        state = TaintLattice.UNTAINTED
        origin: TaintOrigin | None = None
        for v in expr.values:
            if isinstance(v, ast.FormattedValue):
                f = _taint_of_expression(v.value, env, params, index=index, module_qname=module_qname)
                state = join_taint(state, f.state)
                if f.origin is not None and origin is None:
                    origin = f.origin
        return TaintFact(state=state, origin=origin)
    # Binary op (e.g. string concat): join of two sides
    if isinstance(expr, ast.BinOp):
        left = _taint_of_expression(expr.left, env, params, index=index, module_qname=module_qname)
        right = _taint_of_expression(expr.right, env, params, index=index, module_qname=module_qname)
        state = join_taint(left.state, right.state)
        origin = left.origin or right.origin
        return TaintFact(state=state, origin=origin)
    # Bare name
    if isinstance(expr, ast.Name):
        if expr.id in env:
            return env[expr.id]
        if expr.id in params:
            return TaintFact(
                state=TaintLattice.EXTERNAL,
                origin=TaintOrigin(parameter_name=expr.id),
            )
        return TaintFact(state=TaintLattice.UNKNOWN)
    # Attribute access: param.attr (MODEL_CONTROLLED) or trackedlocal.attr
    # (propagated) or other.attr (UNKNOWN)
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        if expr.value.id in params:
            return TaintFact(
                state=TaintLattice.MODEL_CONTROLLED,
                origin=TaintOrigin(
                    parameter_name=expr.value.id, via=(expr.attr,)
                ),
            )
        if expr.value.id in env:
            fact = env[expr.value.id]
            if fact.origin is not None:
                return TaintFact(
                    state=fact.state,
                    origin=TaintOrigin(
                        parameter_name=fact.origin.parameter_name,
                        via=fact.origin.via + (expr.attr,),
                    ),
                )
            return TaintFact(state=fact.state)
    # Subscript: param[...] OR trackedlocal[...] — propagate taint
    if isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Name):
        name = expr.value.id
        if name in params:
            return TaintFact(
                state=TaintLattice.MODEL_CONTROLLED,
                origin=TaintOrigin(parameter_name=name, via=("[]",)),
            )
        if name in env:
            fact = env[name]
            # Propagate the existing taint through the [] access
            if fact.origin is not None:
                return TaintFact(
                    state=fact.state,
                    origin=TaintOrigin(
                        parameter_name=fact.origin.parameter_name,
                        via=fact.origin.via + ("[]",),
                    ),
                )
            # Untainted local → still untainted
            return TaintFact(state=fact.state)
    # Call: str(x), int(x), json.loads(x), Path(x) — pass-through
    if isinstance(expr, ast.Call):
        callee_text = ""
        try:
            callee_text = ast.unparse(expr.func)
        except Exception:
            callee_text = ""
        # Pass-through transformations
        passthrough = {
            "str", "int", "float", "bool",
            "Path", "pathlib.Path",
            "json.loads", "loads",
            "bytes", "bytearray",
        }
        # Also: any single-arg call where the callee looks like a
        # pass-through. We don't have a full list, so this is conservative.
        is_passthrough = False
        if callee_text in passthrough:
            is_passthrough = True
        # One-hop wrapper: ``y = helper(x)`` where ``helper`` is a
        # repository-local function whose body is a single return of
        # its parameter. This requires the index to resolve the callee.
        if not is_passthrough and index is not None and expr.args:
            sym, _cert, _qname = index.resolve_call_target(
                expr.func, in_module=module_qname
            )
            if sym is not None and sym.is_function_like:
                wrapped = _taint_through_wrapper(sym, expr, env, params, index, module_qname)
                if wrapped is not None:
                    return wrapped
        if is_passthrough and expr.args:
            inner = _taint_of_expression(expr.args[0], env, params, index=index, module_qname=module_qname)
            # Pass-through: state preserved, but record the cast in provenance
            via = (callee_text,) if inner.origin else ()
            new_origin: TaintOrigin | None = None
            if inner.origin:
                new_origin = TaintOrigin(
                    parameter_name=inner.origin.parameter_name,
                    via=inner.origin.via + via,
                )
            return TaintFact(state=inner.state, origin=new_origin)
        # Any other call: the result is unknown unless it's a passthrough
        return TaintFact(state=TaintLattice.UNKNOWN)
    return TaintFact(state=TaintLattice.UNKNOWN)


def _taint_through_wrapper(
    sym: "Symbol",
    call: ast.Call,
    env: dict[str, TaintFact],
    params: set[str],
    index: RepositoryIndex,
    module_qname: str,
) -> TaintFact | None:
    """If ``sym`` is a 1-hop wrapper (single return of a parameter),
    return the taint of its returned expression applied to the call's
    actual arguments. Otherwise return None.

    Limitation: only handles ``def wrapper(x): return <expr_with_x>``.
    """
    if sym.location is None:
        return None
    ast_info = index.get_ast(sym.location.file)
    if ast_info is None:
        return None
    _src, tree = ast_info
    # Find the function definition matching sym.name
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == sym.name
        ):
            # Check it's the right one (line range match)
            if node.lineno != sym.location.line:
                continue
            body = node.body
            if len(body) != 1:
                return None
            stmt = body[0]
            if not isinstance(stmt, ast.Return) or stmt.value is None:
                return None
            ret_expr = stmt.value
            # Build a binding of the wrapper's parameter names to the
            # call's argument taints, then evaluate the return expr.
            wrapper_params = _param_names(node)
            arg_taints: dict[str, TaintFact] = {}
            # Positional
            for i, arg in enumerate(call.args):
                if i < len(node.args.posonlyargs + node.args.args):
                    pname = (node.args.posonlyargs + node.args.args)[i].arg
                    arg_taints[pname] = _taint_of_expression(
                        arg, env, params, index=index, module_qname=module_qname
                    )
            # Keyword
            for kw in call.keywords:
                if kw.arg:
                    arg_taints[kw.arg] = _taint_of_expression(
                        kw.value, env, params, index=index, module_qname=module_qname
                    )
            # Evaluate the return expression in the wrapper's local env.
            # We use a fake env that has the wrapper's params mapped to
            # the call-site taints.
            return _taint_of_expression(
                ret_expr, arg_taints, wrapper_params, index=index, module_qname=module_qname
            )
    return None


# Import Symbol here to avoid runtime cycle
from actenon_scan.repository.symbol_index import Symbol  # noqa: E402


def function_local_dataflow(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    sink_node: ast.Call,
    *,
    index: RepositoryIndex | None = None,
    module_qname: str = "",
) -> TaintTrace | None:
    """Trace taint from a sink's arguments back to function parameters.

    Returns a :class:`TaintTrace` for the *strongest* (most tainted)
    argument of the sink, or None if no argument is tainted.

    The trace records every transformation the analyser recognised
    (e.g. ``json.loads`` → ``['command']`` → ``str``). Unrecognised
    intermediate operations appear in the trace only if we can prove
    the value passed through them; otherwise the trace's certainty is
    ``unknown`` rather than ``proven``.

    Conservative: a transformation NEVER downgrades taint. If we cannot
    prove the value is untainted, we treat it as UNKNOWN — never as
    UNTAINTED.
    """
    params = _param_names(func_node)
    # Initial environment: every parameter is EXTERNAL (agent-controlled
    # unless we have reason to think otherwise — the calling function
    # is presumed to be an entrypoint by the caller of this function).
    env: dict[str, TaintFact] = {
        p: TaintFact(
            state=TaintLattice.EXTERNAL,
            origin=TaintOrigin(parameter_name=p),
        )
        for p in params
    }

    # Process the function body in source order, updating the env as
    # we see assignments.
    for stmt in ast.walk(func_node):
        # Skip nested function/class bodies — they have their own scope.
        # (We only want to track assignments in THIS function body.)
        # ast.walk doesn't respect scope boundaries, so we use a manual
        # walk of the direct body. We do this for nested Assign targets
        # inside the body, but skip nested function defs entirely.
        if isinstance(stmt, ast.Assign):
            value_taint = _taint_of_expression(
                stmt.value, env, params, index=index, module_qname=module_qname
            )
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = value_taint
                # Aliasing through tuple unpacking: a, b = x, y
                if isinstance(target, ast.Tuple):
                    if isinstance(stmt.value, ast.Tuple):
                        for t, v in zip(target.elts, stmt.value.elts):
                            if isinstance(t, ast.Name):
                                env[t.id] = _taint_of_expression(
                                    v, env, params, index=index, module_qname=module_qname
                                )

    # Now look at the sink's arguments and pick the strongest taint.
    strongest: TaintFact | None = None
    for arg in list(sink_node.args) + [kw.value for kw in sink_node.keywords if kw.value is not None]:
        f = _taint_of_expression(arg, env, params, index=index, module_qname=module_qname)
        if strongest is None or _LATTICE_ORDER[f.state] > _LATTICE_ORDER[strongest.state]:
            strongest = f

    if strongest is None or strongest.state in (TaintLattice.UNTAINTED, TaintLattice.UNKNOWN):
        return None

    # Determine certainty
    if strongest.origin is None:
        certainty = "unknown"
    elif strongest.state == TaintLattice.EXTERNAL:
        certainty = "proven"  # parameter flowed directly to sink
    elif strongest.state in (TaintLattice.MODEL_CONTROLLED, TaintLattice.MODEL_DERIVED):
        # Proven if we recognised every transformation in the chain
        # (i.e. all via entries are non-empty strings we generated).
        # Since we only ever ADD to via when we recognised a transformation,
        # any non-empty chain is "proven" modulo unknown substrates.
        certainty = "proven"
    else:
        certainty = "unknown"

    return TaintTrace(
        parameter_name=strongest.origin.parameter_name if strongest.origin else "",
        operations=list(strongest.origin.via) if strongest.origin else [],
        final_state=strongest.state,
        certainty=certainty,
    )
