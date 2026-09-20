"""Authority-to-action value binding.

Compares the parameters of an authority call (e.g. ``authorize_refund(cust, amt)``)
with the parameters of a sink call (e.g. ``refund(other_cust, other_amt)``).

Returns explicit binding states:

- :data:`BindingState.BOUND` — proven that authority parameters and sink
  parameters trace back to the same value.
- :data:`BindingState.UNBOUND` — proven that they trace back to DIFFERENT
  values.
- :data:`BindingState.UNKNOWN` — cannot prove either way; NEVER silently
  promoted to BOUND.

This is the foundation for Actenon's runtime proof / PCCB mechanisms,
which eventually model execution-bound authority. Static analysis cannot
prove cryptographic verification — but it CAN prove plumbing (same
value flows to both authority-verification and the sink).

Conservative invariants (NON-NEGOTIABLE):

1. **UNKNOWN is NEVER silently promoted to BOUND.** If we cannot prove
   the authority arg and the sink arg trace to the same value, we
   return UNKNOWN — never BOUND. False assurance is worse than a
   reviewable false positive.

2. **Static analysis cannot prove cryptographic verification.** A
   dominating guard that calls ``authorize_refund(...)`` with parameters
   that do NOT bind to the sink's parameters must NOT receive the
   strongest guarded classification.

3. **Constants are explicit.** A constant on one side and a parameter
   on the other is UNBOUND — the authority is for a fixed resource
   while the sink operates on whatever the caller passed.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from actenon_scan.repository.taint import (
    TaintLattice,
    TaintFact,
    TaintOrigin,
    TaintTrace,
    function_local_dataflow,
)
from actenon_scan.repository.symbol_index import RepositoryIndex


# ---------------------------------------------------------------------------
# Binding states
# ---------------------------------------------------------------------------


class BindingState(str, Enum):
    """The outcome of comparing one authority parameter to one sink parameter.

    - ``BOUND``   — proven same value (same function parameter provenance).
    - ``UNBOUND`` — proven different values (different parameters, or
                    constant vs runtime value, or different constant literals).
    - ``UNKNOWN`` — cannot prove either way; NEVER silently promoted to BOUND.
    """

    BOUND = "bound"
    UNBOUND = "unbound"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class BindingResult:
    """One pairwise comparison between an authority arg and a sink arg.

    ``authority_param`` and ``sink_param`` are human-readable labels
    (parameter names, constant reprs, or ``<argN>`` fallbacks) used for
    evidence/diagnostics.

    ``authority_provenance`` / ``sink_provenance`` carry the
    :class:`TaintOrigin` chains (parameter name + via-chain of
    transformations) when both sides are non-constant and the taint
    analysis resolved. They are None for constants or when state is
    UNKNOWN.
    """

    state: BindingState
    authority_param: str
    sink_param: str
    authority_provenance: TaintOrigin | None = None
    sink_provenance: TaintOrigin | None = None
    evidence: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _arg_label(arg: ast.AST, index: int) -> str:
    """Human-readable label for a call argument."""
    if isinstance(arg, ast.Constant):
        return repr(arg.value)
    if isinstance(arg, ast.Name):
        return arg.id
    try:
        return ast.unparse(arg)
    except Exception:
        return f"<arg{index}>"


def _call_name_text(call: ast.Call) -> str | None:
    """Extract the textual callable name from a Call node.

    - ``ast.Call`` with ``func`` = ``ast.Name`` → ``Name.id``
    - ``ast.Call`` with ``func`` = ``ast.Attribute`` → ``Attribute.attr``
      (the attribute name; dotted prefix discarded for taxonomy purposes)
    - Any other form (subscript, call-of-call, lambda) → ``None``
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _arg_taint(
    arg_node: ast.AST,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    index: RepositoryIndex | None = None,
    module_qname: str = "",
) -> TaintFact:
    """Compute the taint of a single argument by running
    :func:`function_local_dataflow` on a 1-arg wrapper call.

    We construct a synthetic :class:`ast.Call` with only ``arg_node`` as
    its sole positional argument and pass it as the ``sink_node`` to
    :func:`function_local_dataflow`. That function returns the
    strongest trace across all sink args — with only one arg, that is
    exactly the trace for the argument we care about.

    If :func:`function_local_dataflow` returns ``None`` (state was
    UNTAINTED or UNKNOWN — both filtered), we conservatively return a
    :class:`TaintFact` with state UNKNOWN and origin None. For
    non-constant arguments, both UNTAINTED (e.g. computed constant
    expressions) and UNKNOWN (e.g. unrecognized calls) mean "we cannot
    prove the value's provenance", so the conservative answer is
    UNKNOWN — never UNTAINTED (which would risk a downstream BOUND).
    """
    fake_call = ast.Call(
        func=ast.Name(id="_authority_binding_probe", ctx=ast.Load()),
        args=[arg_node],
        keywords=[],
    )
    ast.fix_missing_locations(fake_call)
    trace = function_local_dataflow(
        func_node,
        fake_call,
        index=index,
        module_qname=module_qname,
    )
    if trace is None:
        return TaintFact(state=TaintLattice.UNKNOWN)
    return TaintFact(
        state=trace.final_state,
        origin=TaintOrigin(
            parameter_name=trace.parameter_name,
            via=tuple(trace.operations),
        ),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compare_authority_to_sink(
    authority_call: ast.Call,
    sink_call: ast.Call,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    index: RepositoryIndex | None = None,
    module_qname: str = "",
    authority_param_index: int = 0,
    sink_param_index: int = 0,
) -> BindingResult:
    """Compare an authority call's parameter at index ``authority_param_index``
    with the sink call's parameter at index ``sink_param_index``.

    Algorithm:

    0. **Action-label check (soundness gate, runs FIRST):** extract the
       authority's action label via
       :func:`actenon_scan.repository.guard_semantics.extract_action_label`
       and infer the sink's action label via
       :func:`infer_sink_action_label`. If both are extractable AND they
       differ, return UNBOUND immediately — the authority is for a
       *different action* than the sink performs, so even matching
       parameter values do not bind (the canonical hostile case:
       ``authorize_read(cust); refund(cust, amt)``).
    1. Resolve the two argument nodes from the call's positional args.
       If either index is out of range, return UNKNOWN (cannot prove
       anything).
    2. Constants: a constant authority arg bound to a constant sink arg
       with the same literal value → BOUND; different literals → UNBOUND.
    3. One constant, one non-constant → UNBOUND (the authority is for
       a fixed resource, the sink is for whatever the caller passed —
       different values).
    4. Both non-constant: compute taint provenance for each via
       :func:`function_local_dataflow` (with a 1-arg wrapper Call).
    5. If either side is UNKNOWN → UNKNOWN (NEVER silently BOUND).
    6. If both provenances resolve to the same function parameter name
       → BOUND. If they resolve to DIFFERENT function parameters →
       UNBOUND.

    The "provenance chains match" criterion is parameter_name equality
    (not via-chain equality) — recognised pass-through transformations
    (``str(p)``, ``int(p)``, ``json.loads(p)``, etc.) preserve
    parameter_name, so e.g. ``a = str(p); authorize(a); refund(p)``
    is BOUND.
    """
    # --- Soundness gate 0: action-label check ---------------------------
    # If the authority is for a different action than the sink performs,
    # the binding is provably UNBOUND regardless of parameter matching.
    # This is the canonical hostile case from the brief:
    #   authorize_refund(customer_A, 100)
    #   refund(customer_B, 5000)
    # and the more subtle:
    #   authorize_read(cust)
    #   refund(cust, amt)
    # The action-label gate refuses to bind because the authority is
    # for "read" but the sink performs "refund".
    auth_name = _call_name_text(authority_call)
    sink_name = _call_name_text(sink_call)
    if auth_name is not None and sink_name is not None:
        try:
            from actenon_scan.repository.guard_semantics import (
                extract_action_label,
                infer_sink_action_label,
            )
        except ImportError:
            extract_action_label = None  # type: ignore[assignment]
            infer_sink_action_label = None  # type: ignore[assignment]
        if extract_action_label is not None and infer_sink_action_label is not None:
            auth_action = extract_action_label(auth_name)
            sink_action = infer_sink_action_label(sink_name)
            if (
                auth_action is not None
                and sink_action is not None
                and auth_action != sink_action
                # Allow the sink's action label to be a SUFFIX of the
                # authority's (e.g. authority="refund", sink="process_refund"
                # → sink_action_label="refund" after verb strip). The
                # authority's label must contain the sink's label as a
                # word-boundary substring.
                and sink_action not in auth_action
                and auth_action not in sink_action
            ):
                auth_args_peek = list(authority_call.args)
                sink_args_peek = list(sink_call.args)
                auth_label = (
                    _arg_label(auth_args_peek[authority_param_index], authority_param_index)
                    if authority_param_index < len(auth_args_peek)
                    else f"<arg{authority_param_index}>"
                )
                sink_label = (
                    _arg_label(sink_args_peek[sink_param_index], sink_param_index)
                    if sink_param_index < len(sink_args_peek)
                    else f"<arg{sink_param_index}>"
                )
                return BindingResult(
                    state=BindingState.UNBOUND,
                    authority_param=auth_label,
                    sink_param=sink_label,
                    authority_provenance=None,
                    sink_provenance=None,
                    evidence=(
                        f"authority action label '{auth_action}' (from "
                        f"'{auth_name}') differs from sink action label "
                        f"'{sink_action}' (from '{sink_name}') — the "
                        f"authority is for a different action than the "
                        f"sink performs; never BOUND"
                    ),
                )

    auth_args = list(authority_call.args)
    sink_args = list(sink_call.args)

    # Bounds check — out-of-range index → UNKNOWN (cannot prove anything)
    if authority_param_index >= len(auth_args):
        sink_label = (
            _arg_label(sink_args[sink_param_index], sink_param_index)
            if sink_param_index < len(sink_args)
            else f"<arg{sink_param_index}>"
        )
        return BindingResult(
            state=BindingState.UNKNOWN,
            authority_param=f"<arg{authority_param_index}>",
            sink_param=sink_label,
            evidence=(
                f"authority call has only {len(auth_args)} positional "
                f"arg(s); index {authority_param_index} out of range"
            ),
        )
    if sink_param_index >= len(sink_args):
        auth_label = _arg_label(auth_args[authority_param_index], authority_param_index)
        return BindingResult(
            state=BindingState.UNKNOWN,
            authority_param=auth_label,
            sink_param=f"<arg{sink_param_index}>",
            evidence=(
                f"sink call has only {len(sink_args)} positional arg(s); "
                f"index {sink_param_index} out of range"
            ),
        )

    auth_arg = auth_args[authority_param_index]
    sink_arg = sink_args[sink_param_index]

    auth_label = _arg_label(auth_arg, authority_param_index)
    sink_label = _arg_label(sink_arg, sink_param_index)

    auth_is_const = isinstance(auth_arg, ast.Constant)
    sink_is_const = isinstance(sink_arg, ast.Constant)

    # --- Both constants: compare literal values -------------------------
    if auth_is_const and sink_is_const:
        if auth_arg.value == sink_arg.value:
            return BindingResult(
                state=BindingState.BOUND,
                authority_param=auth_label,
                sink_param=sink_label,
                authority_provenance=None,
                sink_provenance=None,
                evidence=f"both are the same constant literal: {auth_arg.value!r}",
            )
        return BindingResult(
            state=BindingState.UNBOUND,
            authority_param=auth_label,
            sink_param=sink_label,
            authority_provenance=None,
            sink_provenance=None,
            evidence=(
                f"different constant literals: {auth_arg.value!r} "
                f"vs {sink_arg.value!r}"
            ),
        )

    # --- One constant, one non-constant: UNBOUND -----------------------
    # The authority is for a fixed resource; the sink operates on whatever
    # the caller passed. Provably different values.
    if auth_is_const and not sink_is_const:
        sink_taint = _arg_taint(
            sink_arg, func_node, index=index, module_qname=module_qname
        )
        return BindingResult(
            state=BindingState.UNBOUND,
            authority_param=auth_label,
            sink_param=sink_label,
            authority_provenance=None,
            sink_provenance=sink_taint.origin,
            evidence=(
                "authority arg is a constant literal, sink arg is a "
                "runtime value — provably different values"
            ),
        )
    if sink_is_const and not auth_is_const:
        auth_taint = _arg_taint(
            auth_arg, func_node, index=index, module_qname=module_qname
        )
        return BindingResult(
            state=BindingState.UNBOUND,
            authority_param=auth_label,
            sink_param=sink_label,
            authority_provenance=auth_taint.origin,
            sink_provenance=None,
            evidence=(
                "authority arg is a runtime value, sink arg is a "
                "constant literal — provably different values"
            ),
        )

    # --- Both non-constant: compute taint provenance for each -----------
    auth_taint = _arg_taint(
        auth_arg, func_node, index=index, module_qname=module_qname
    )
    sink_taint = _arg_taint(
        sink_arg, func_node, index=index, module_qname=module_qname
    )

    # UNKNOWN never silently promoted to BOUND.
    if (
        auth_taint.state == TaintLattice.UNKNOWN
        or sink_taint.state == TaintLattice.UNKNOWN
    ):
        return BindingResult(
            state=BindingState.UNKNOWN,
            authority_param=auth_label,
            sink_param=sink_label,
            authority_provenance=auth_taint.origin,
            sink_provenance=sink_taint.origin,
            evidence=(
                "one or both args have UNKNOWN taint — static analysis "
                "cannot prove plumbing; never silently BOUND"
            ),
        )

    # Defensive: non-UNKNOWN state should always carry an origin. If not,
    # be conservative.
    if auth_taint.origin is None or sink_taint.origin is None:
        return BindingResult(
            state=BindingState.UNKNOWN,
            authority_param=auth_label,
            sink_param=sink_label,
            authority_provenance=auth_taint.origin,
            sink_provenance=sink_taint.origin,
            evidence=(
                "taint state is non-UNKNOWN but origin is missing — "
                "conservative UNKNOWN"
            ),
        )

    # Both provenances resolved. Compare parameter names.
    if auth_taint.origin.parameter_name == sink_taint.origin.parameter_name:
        return BindingResult(
            state=BindingState.BOUND,
            authority_param=auth_label,
            sink_param=sink_label,
            authority_provenance=auth_taint.origin,
            sink_provenance=sink_taint.origin,
            evidence=(
                f"both args trace back to function parameter "
                f"'{auth_taint.origin.parameter_name}'"
            ),
        )
    return BindingResult(
        state=BindingState.UNBOUND,
        authority_param=auth_label,
        sink_param=sink_label,
        authority_provenance=auth_taint.origin,
        sink_provenance=sink_taint.origin,
        evidence=(
            f"authority traces to parameter "
            f"'{auth_taint.origin.parameter_name}', sink traces to "
            f"parameter '{sink_taint.origin.parameter_name}' — "
            f"provably different values"
        ),
    )


def compare_all_authority_to_sink_params(
    authority_call: ast.Call,
    sink_call: ast.Call,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    index: RepositoryIndex | None = None,
    module_qname: str = "",
) -> list[BindingResult]:
    """Compare ALL positional parameters pairwise.

    Returns one :class:`BindingResult` per index pair (``authority.args[i]``
    vs ``sink.args[i]``), for ``i`` in ``range(min(len(auth), len(sink)))``.

    The overall binding state is obtained by passing the list to
    :func:`overall_binding_state` — worst-case aggregation: UNBOUND
    dominates UNKNOWN dominates BOUND. If any pair is UNBOUND, the
    whole binding is UNBOUND.
    """
    n_auth = len(authority_call.args)
    n_sink = len(sink_call.args)
    n = min(n_auth, n_sink)
    results: list[BindingResult] = []
    for i in range(n):
        results.append(
            compare_authority_to_sink(
                authority_call,
                sink_call,
                func_node,
                index=index,
                module_qname=module_qname,
                authority_param_index=i,
                sink_param_index=i,
            )
        )
    return results


def overall_binding_state(results: list[BindingResult]) -> BindingState:
    """Worst-case aggregation: UNBOUND dominates UNKNOWN dominates BOUND.

    - Empty list → UNKNOWN (conservative: nothing has been proven).
    - If any result is UNBOUND → UNBOUND (one provably-mismatched pair
      taints the whole binding).
    - Else if any result is UNKNOWN → UNKNOWN (cannot prove; never
      silently BOUND).
    - Else (all BOUND) → BOUND.
    """
    if not results:
        return BindingState.UNKNOWN
    states = [r.state for r in results]
    if BindingState.UNBOUND in states:
        return BindingState.UNBOUND
    if BindingState.UNKNOWN in states:
        return BindingState.UNKNOWN
    return BindingState.BOUND
