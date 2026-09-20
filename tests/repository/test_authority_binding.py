"""Tests for authority/action value binding (Objective 8).

Verifies that authority-call parameters are correctly compared to sink
parameters using the existing taint provenance layer:

- :data:`BindingState.BOUND`   — both trace back to the same function
  parameter (plumbing proof).
- :data:`BindingState.UNBOUND` — provably different (different function
  parameters, or constant vs parameter, or different constant literals).
- :data:`BindingState.UNKNOWN` — cannot prove either way; NEVER silently
  promoted to BOUND.

Critical invariants pinned by these tests:

- An unrecognized transform on either side → UNKNOWN (NEVER BOUND).
- Constants vs parameters → UNBOUND (different values).
- Static analysis cannot prove cryptographic verification — UNKNOWN.
- Overall aggregation: UNBOUND dominates UNKNOWN dominates BOUND.
"""
from __future__ import annotations

import ast
import unittest

from actenon_scan.repository.authority_binding import (
    BindingResult,
    BindingState,
    compare_all_authority_to_sink_params,
    compare_authority_to_sink,
    overall_binding_state,
)


def _parse_func_and_calls(
    src: str,
    auth_name: str = "authorize",
    sink_name: str = "refund",
) -> tuple:
    """Parse ``src`` and return ``(func_node, auth_call, sink_call)``.

    Finds the first top-level FunctionDef and the first Call nodes whose
    callee name matches ``auth_name`` / ``sink_name`` (matched via
    ``ast.unparse(call.func)`` so attribute callees also work).
    """
    tree = ast.parse(src)
    func_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_node = node
            break
    assert func_node is not None, "no FunctionDef found in src"

    auth_call: ast.Call | None = None
    sink_call: ast.Call | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        try:
            fname = ast.unparse(node.func)
        except Exception:
            continue
        if fname == auth_name and auth_call is None:
            auth_call = node
        elif fname == sink_name and sink_call is None:
            sink_call = node
    assert auth_call is not None, f"no call to {auth_name!r} found in src"
    assert sink_call is not None, f"no call to {sink_name!r} found in src"
    return func_node, auth_call, sink_call


class AuthorityBindingTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # 1. Same parameter → BOUND
    # ------------------------------------------------------------------
    def test_same_parameter_bound(self) -> None:
        src = (
            "def f(cust):\n"
            "    authorize(cust)\n"
            "    refund(cust)\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        result = compare_authority_to_sink(auth, sink, func)
        self.assertEqual(
            result.state, BindingState.BOUND,
            f"expected BOUND, got {result.state!r}: {result.evidence}",
        )
        self.assertEqual(result.authority_param, "cust")
        self.assertEqual(result.sink_param, "cust")
        # Both provenances should resolve to the same parameter
        self.assertIsNotNone(result.authority_provenance)
        self.assertIsNotNone(result.sink_provenance)
        self.assertEqual(result.authority_provenance.parameter_name, "cust")
        self.assertEqual(result.sink_provenance.parameter_name, "cust")

    # ------------------------------------------------------------------
    # 2. Different parameters → UNBOUND
    # ------------------------------------------------------------------
    def test_different_parameters_unbound(self) -> None:
        src = (
            "def f(cust_a, cust_b):\n"
            "    authorize(cust_a)\n"
            "    refund(cust_b)\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        result = compare_authority_to_sink(auth, sink, func)
        self.assertEqual(
            result.state, BindingState.UNBOUND,
            f"expected UNBOUND, got {result.state!r}: {result.evidence}",
        )
        # Provenance must show different parameter names
        self.assertIsNotNone(result.authority_provenance)
        self.assertIsNotNone(result.sink_provenance)
        self.assertEqual(result.authority_provenance.parameter_name, "cust_a")
        self.assertEqual(result.sink_provenance.parameter_name, "cust_b")

    # ------------------------------------------------------------------
    # 3. Authority is a constant, sink is a parameter → UNBOUND
    # ------------------------------------------------------------------
    def test_authority_constant_sink_parameter_unbound(self) -> None:
        src = (
            "def f(cust):\n"
            "    authorize('admin')\n"
            "    refund(cust)\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        result = compare_authority_to_sink(auth, sink, func)
        self.assertEqual(
            result.state, BindingState.UNBOUND,
            f"expected UNBOUND, got {result.state!r}: {result.evidence}",
        )
        # Authority side has no provenance (it's a constant)
        self.assertIsNone(result.authority_provenance)

    # ------------------------------------------------------------------
    # 4. Authority is a parameter, sink is a constant → UNBOUND
    # ------------------------------------------------------------------
    def test_authority_parameter_sink_constant_unbound(self) -> None:
        src = (
            "def f(cust):\n"
            "    authorize(cust)\n"
            "    refund('admin')\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        result = compare_authority_to_sink(auth, sink, func)
        self.assertEqual(
            result.state, BindingState.UNBOUND,
            f"expected UNBOUND, got {result.state!r}: {result.evidence}",
        )
        # Sink side has no provenance (it's a constant)
        self.assertIsNone(result.sink_provenance)

    # ------------------------------------------------------------------
    # 5. Same constant literal → BOUND
    # ------------------------------------------------------------------
    def test_same_constant_bound(self) -> None:
        src = (
            "def f():\n"
            "    authorize('admin')\n"
            "    refund('admin')\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        result = compare_authority_to_sink(auth, sink, func)
        self.assertEqual(
            result.state, BindingState.BOUND,
            f"expected BOUND, got {result.state!r}: {result.evidence}",
        )
        self.assertIsNone(result.authority_provenance)
        self.assertIsNone(result.sink_provenance)

    # ------------------------------------------------------------------
    # 6. Different constant literals → UNBOUND
    # ------------------------------------------------------------------
    def test_different_constants_unbound(self) -> None:
        src = (
            "def f():\n"
            "    authorize('admin')\n"
            "    refund('user')\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        result = compare_authority_to_sink(auth, sink, func)
        self.assertEqual(
            result.state, BindingState.UNBOUND,
            f"expected UNBOUND, got {result.state!r}: {result.evidence}",
        )

    # ------------------------------------------------------------------
    # 7. Params swapped → UNBOUND for the first pair
    # ------------------------------------------------------------------
    def test_authority_first_param_sink_second_param_unbound(self) -> None:
        src = (
            "def f(cust, amt):\n"
            "    authorize(cust, amt)\n"
            "    refund(amt, cust)\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        result = compare_authority_to_sink(
            auth, sink, func,
            authority_param_index=0,
            sink_param_index=0,
        )
        self.assertEqual(
            result.state, BindingState.UNBOUND,
            f"expected UNBOUND for first pair, got {result.state!r}: "
            f"{result.evidence}",
        )
        self.assertEqual(result.authority_provenance.parameter_name, "cust")
        self.assertEqual(result.sink_provenance.parameter_name, "amt")

    # ------------------------------------------------------------------
    # 8. Authority arg is an unrecognized call → UNKNOWN (NEVER BOUND)
    # ------------------------------------------------------------------
    def test_unknown_authority_never_silently_bound(self) -> None:
        src = (
            "def f(cust):\n"
            "    authorize(get_dynamic_thing())\n"
            "    refund(cust)\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        result = compare_authority_to_sink(auth, sink, func)
        self.assertEqual(
            result.state, BindingState.UNKNOWN,
            f"expected UNKNOWN, got {result.state!r}: {result.evidence}",
        )
        # Critical invariant: UNKNOWN is NEVER silently promoted to BOUND
        self.assertNotEqual(result.state, BindingState.BOUND)

    # ------------------------------------------------------------------
    # 9. Overall binding state: UNBOUND dominates UNKNOWN and BOUND
    # ------------------------------------------------------------------
    def test_overall_binding_state_unbound_dominates(self) -> None:
        results = [
            BindingResult(
                state=BindingState.BOUND,
                authority_param="a", sink_param="a",
                evidence="",
            ),
            BindingResult(
                state=BindingState.UNBOUND,
                authority_param="b", sink_param="c",
                evidence="",
            ),
            BindingResult(
                state=BindingState.UNKNOWN,
                authority_param="d", sink_param="e",
                evidence="",
            ),
        ]
        self.assertEqual(overall_binding_state(results), BindingState.UNBOUND)

    # ------------------------------------------------------------------
    # 10. Overall binding state: UNKNOWN dominates BOUND (NOT BOUND)
    # ------------------------------------------------------------------
    def test_overall_binding_state_unknown_dominates_bound(self) -> None:
        results = [
            BindingResult(
                state=BindingState.BOUND,
                authority_param="a", sink_param="a",
                evidence="",
            ),
            BindingResult(
                state=BindingState.UNKNOWN,
                authority_param="d", sink_param="e",
                evidence="",
            ),
        ]
        overall = overall_binding_state(results)
        self.assertEqual(overall, BindingState.UNKNOWN)
        # Critical invariant: NEVER BOUND when any pair is UNKNOWN
        self.assertNotEqual(overall, BindingState.BOUND)

    # ------------------------------------------------------------------
    # 11. Provenance chain mismatch:
    #     - unrecognized transform → UNKNOWN (NEVER silently BOUND)
    #     - recognized passthrough (str(p)) → BOUND (parameter_name match)
    # ------------------------------------------------------------------
    def test_provenance_chain_mismatch_unbound(self) -> None:
        # Case A: unrecognized transform → UNKNOWN (NEVER BOUND)
        src_a = (
            "def f(p):\n"
            "    a = transform(p)\n"
            "    authorize(a)\n"
            "    refund(p)\n"
        )
        func_a, auth_a, sink_a = _parse_func_and_calls(src_a)
        result_a = compare_authority_to_sink(auth_a, sink_a, func_a)
        self.assertEqual(
            result_a.state, BindingState.UNKNOWN,
            f"unrecognized transform: expected UNKNOWN, got "
            f"{result_a.state!r}: {result_a.evidence}",
        )
        self.assertNotEqual(
            result_a.state, BindingState.BOUND,
            "UNKNOWN must NEVER be silently promoted to BOUND",
        )

        # Case B: recognized passthrough str(p) → BOUND (parameter_name
        # both = 'p'). The via-chains mismatch ([str] vs []) but the
        # parameter_name matches, so it's BOUND.
        src_b = (
            "def f(p):\n"
            "    a = str(p)\n"
            "    authorize(a)\n"
            "    refund(p)\n"
        )
        func_b, auth_b, sink_b = _parse_func_and_calls(src_b)
        result_b = compare_authority_to_sink(auth_b, sink_b, func_b)
        self.assertEqual(
            result_b.state, BindingState.BOUND,
            f"recognized passthrough str(p): expected BOUND, got "
            f"{result_b.state!r}: {result_b.evidence}",
        )
        self.assertIsNotNone(result_b.authority_provenance)
        self.assertIsNotNone(result_b.sink_provenance)
        self.assertEqual(result_b.authority_provenance.parameter_name, "p")
        self.assertEqual(result_b.sink_provenance.parameter_name, "p")
        # The via-chains differ (str on authority, none on sink) but
        # parameter_name matches — that is the criterion for BOUND.
        self.assertIn("str", result_b.authority_provenance.via)
        self.assertEqual(result_b.sink_provenance.via, ())

    # ------------------------------------------------------------------
    # 12. Two-parameter match: both pairs BOUND → overall BOUND
    # ------------------------------------------------------------------
    def test_two_param_match_bound(self) -> None:
        src = (
            "def f(cust, amt):\n"
            "    authorize(cust, amt)\n"
            "    refund(cust, amt)\n"
        )
        func, auth, sink = _parse_func_and_calls(src)
        results = compare_all_authority_to_sink_params(auth, sink, func)
        self.assertEqual(len(results), 2)
        for i, r in enumerate(results):
            self.assertEqual(
                r.state, BindingState.BOUND,
                f"pair {i}: expected BOUND, got {r.state!r}: {r.evidence}",
            )
        self.assertEqual(
            overall_binding_state(results), BindingState.BOUND,
        )


if __name__ == "__main__":
    unittest.main()
