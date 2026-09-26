"""Adversarial tests for argument-sensitive sink semantics (Phase 6).

Try to break the new implementation with cases that combine
containers, wrappers, and partial constant/controlled inputs.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from actenon_scan.detectors.sinks import _is_tainted
from actenon_scan.engine import scan_path


def _scan(source: str, *, resource_boundary=True):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "handler.py"
        p.write_text(source)
        return scan_path(Path(td), cache=None, resource_boundary=resource_boundary)


class AdversarialContainerTests(unittest.TestCase):
    """Container taint propagation — adversarial cases."""

    def test_url_assembled_from_constant_plus_controlled_fragment(self):
        """URL = "https://api.vendor.com/" + path — the path is controlled."""
        node = ast.parse('"https://api.vendor.com/" + path', mode='eval').body
        self.assertTrue(_is_tainted(node, {"path"}))

    def test_nested_json_model_data(self):
        """json={"outer": {"inner": query, "const": 5}} — nested dict."""
        source = "{'outer': {'inner': query, 'const': 5}}"
        node = ast.parse(source, mode='eval').body
        self.assertTrue(_is_tainted(node, {"query"}))

    def test_controlled_headers(self):
        """headers={"Authorization": token} — token is controlled."""
        source = "{'Authorization': token}"
        node = ast.parse(source, mode='eval').body
        self.assertTrue(_is_tainted(node, {"token"}))

    def test_sql_concatenation(self):
        """SQL = "SELECT * FROM " + table — table is controlled."""
        node = ast.parse('"SELECT * FROM " + table', mode='eval').body
        self.assertTrue(_is_tainted(node, {"table"}))

    def test_parameterised_sql_with_tainted_tuple(self):
        """execute("UPDATE ... WHERE id = ?", (user_id,)) — tuple is tainted."""
        source = '(user_id,)'
        node = ast.parse(source, mode='eval').body
        self.assertTrue(_is_tainted(node, {"user_id"}))

    def test_constant_sql_with_constant_params_not_tainted(self):
        """execute("UPDATE ... WHERE id = ?", (5,)) — all constant."""
        source = '(5, "hello")'
        node = ast.parse(source, mode='eval').body
        self.assertFalse(_is_tainted(node, {"user_id"}))

    def test_wrapper_function_around_http(self):
        """A wrapper that receives the URL and calls requests.post."""
        source = '''
from langchain.tools import tool
import requests

def _do_post(url, **kwargs):
    return requests.post(url, **kwargs)

@tool
def fetch(url: str):
    _do_post(url, json={"query": "const"})
'''
        result = _scan(source)
        # The wrapper itself is not a sink — the sink is inside _do_post.
        # The @tool function fetch() calls _do_post with url (controlled).
        # The scanner should find the sink in _do_post, and if the
        # repository layer follows the call, escalate to HIGH.
        # But _do_post is module-level — module-level reachability
        # should follow it (follow_local_calls_depth_1).
        findings = [(f.rule_id, f.severity) for f in result.findings]
        # At minimum, NET-EGRESS should fire (the URL is controlled)
        self.assertTrue(
            any(r == "NET-EGRESS" for r, _ in findings),
            f"Expected NET-EGRESS finding for wrapper HTTP. Got: {findings}"
        )

    def test_wrapper_function_around_db(self):
        """A wrapper that receives the query and calls conn.execute."""
        source = '''
from langchain.tools import tool
import sqlite3

def _do_execute(conn, query, params=()):
    conn.execute(query, params)

@tool
def run_query(query: str):
    conn = sqlite3.connect("data.db")
    _do_execute(conn, query)
'''
        result = _scan(source)
        findings = [(f.rule_id, f.severity) for f in result.findings]
        # The @tool function calls _do_execute with query (controlled).
        # The sink is conn.execute(query) inside _do_execute.
        self.assertTrue(
            any("SQL" in r or "DATABASE" in r for r, _ in findings),
            f"Expected SQL/DATABASE finding for wrapper DB. Got: {findings}"
        )

    def test_constant_url_with_controlled_body_not_high(self):
        """requests.post("https://api.vendor.com", json={"q": query})
        — URL is constant, body is controlled. Must NOT escalate to HIGH."""
        source = '''
from langchain.tools import tool
import requests

@tool
def search(query: str):
    requests.post("https://api.vendor.com/search", json={"query": query})
'''
        result = _scan(source)
        for f in result.findings:
            if f.rule_id == "NET-EGRESS":
                self.assertNotEqual(
                    f.severity, "high",
                    f"Constant URL + controlled body must NOT escalate to HIGH. "
                    f"Got: {f.severity}"
                )

    def test_controlled_url_escalates_to_high(self):
        """requests.post(url, json={"q": "const"})
        — URL is controlled, body is constant. MUST escalate to HIGH."""
        source = '''
from langchain.tools import tool
import requests

@tool
def fetch(url: str):
    requests.post(url, json={"query": "constant"})
'''
        result = _scan(source)
        found_high = False
        for f in result.findings:
            if f.rule_id == "NET-EGRESS" and f.severity == "high":
                found_high = True
        self.assertTrue(
            found_high,
            f"Controlled URL must escalate NET-EGRESS to HIGH. "
            f"Findings: {[(f.rule_id, f.severity) for f in result.findings]}"
        )


if __name__ == "__main__":
    unittest.main()
