"""Regression tests for argument-sensitive sink semantics (Phase 3).

These tests verify that Actenon can distinguish WHAT the model controls
within a sink's arguments, not merely WHETHER any argument is tainted.

Cases:
  A. constant HTTP URL + model-controlled JSON body
  B. model-controlled HTTP URL
  C. constant parameterised SQL + controlled bound parameter
  D. model-controlled SQL text
  E. HTTP route externally callable but not proven model-callable
  F. genuine @tool model entrypoint

These tests are expected to FAIL before the implementation change
(Phase 4), because _is_tainted does not handle ast.Tuple or ast.Dict.
"""

from __future__ import annotations

import ast
import unittest

from actenon_scan.detectors.sinks import _is_tainted


class TaintContainerHandlingTests(unittest.TestCase):
    """Tests that _is_tainted correctly detects taint inside containers
    (Tuple, Dict, List) — the core defect causing the DeepAgents
    precision failures."""

    def test_taint_inside_tuple(self):
        """_is_tainted must check inside ast.Tuple.

        Case C: conn.execute("UPDATE ... WHERE id = ?", (run_id,))
        The bound parameter (run_id,) is a Tuple containing a tainted Name.
        """
        source = "(run_id,)"
        node = ast.parse(source, mode="eval").body
        params = {"run_id"}
        self.assertTrue(
            _is_tainted(node, params),
            "_is_tainted must detect taint inside ast.Tuple — "
            "this is the SQL bound-parameter defect."
        )

    def test_taint_inside_dict(self):
        """_is_tainted must check inside ast.Dict.

        Case A: client.post(url, json={"query": query})
        The json= kwarg value is a Dict containing a tainted Name.
        """
        source = "{'query': query, 'max_results': 5}"
        node = ast.parse(source, mode="eval").body
        params = {"query"}
        self.assertTrue(
            _is_tainted(node, params),
            "_is_tainted must detect taint inside ast.Dict — "
            "this is the HTTP JSON body defect."
        )

    def test_taint_inside_list(self):
        """_is_tainted must check inside ast.List."""
        source = "[run_id, 5]"
        node = ast.parse(source, mode="eval").body
        params = {"run_id"}
        self.assertTrue(
            _is_tainted(node, params),
            "_is_tainted must detect taint inside ast.List."
        )

    def test_constant_tuple_not_tainted(self):
        """A tuple of constants is NOT tainted."""
        source = "(5, 'hello')"
        node = ast.parse(source, mode="eval").body
        params = {"run_id"}
        self.assertFalse(_is_tainted(node, params))

    def test_constant_dict_not_tainted(self):
        """A dict of constants is NOT tainted."""
        source = "{'key': 'value', 'max': 5}"
        node = ast.parse(source, mode="eval").body
        params = {"run_id"}
        self.assertFalse(_is_tainted(node, params))

    def test_nested_taint_in_dict_inside_tuple(self):
        """Taint propagates through nested containers."""
        source = "({'query': query}, 5)"
        node = ast.parse(source, mode="eval").body
        params = {"query"}
        self.assertTrue(_is_tainted(node, params))


class EntrypointWordingTests(unittest.TestCase):
    """Tests that the pretty output distinguishes resource_boundary
    (HTTP route) from tool_decorator (model-callable)."""

    def test_resource_boundary_not_called_agent_entry_point(self):
        """Case E: @app.post is an HTTP route, not a model-callable
        entrypoint. The blast radius output must not say 'agent entry point'
        for resource_boundary signals."""
        from actenon_scan.report.pretty import _decorator_or_function
        from actenon_scan.engine import Finding

        f = Finding(
            file="routes.py", line=10, col=0,
            rule_id="DATABASE-MUTATE", category="database_mutation",
            severity="high", confidence="high",
            description="test", call_text="conn.execute(sql)",
            remediation="test", reachability_reason="resource_boundary",
        )
        label = _decorator_or_function(f)
        self.assertNotIn(
            "agent entry point", label.lower(),
            f"resource_boundary findings must not say 'agent entry point' — "
            f"they are HTTP routes, not model-callable entrypoints. Got: {label}"
        )


class ExtractParamsTests(unittest.TestCase):
    """Tests that _extract_params does not report string literals as
    model-controlled inputs."""

    def test_sql_literal_not_reported_as_model_controlled(self):
        """Case C: the SQL string literal must NOT appear in
        'Model-controlled inputs' — only the bound parameter run_id should."""
        from actenon_scan.report.pretty import _extract_params
        from actenon_scan.engine import Finding

        f = Finding(
            file="sql_tool.py", line=9, col=0,
            rule_id="DATABASE-MUTATE", category="database_mutation",
            severity="high", confidence="high",
            description="test",
            call_text='conn.execute("UPDATE runs SET status = ? WHERE run_id = ?", (run_id,))',
            remediation="test",
        )
        params = _extract_params(f)
        self.assertNotIn(
            "UPDATE", str(params),
            f"SQL string literal must not appear as a model-controlled input. "
            f"Got: {params}"
        )


if __name__ == "__main__":
    unittest.main()
