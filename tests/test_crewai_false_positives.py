"""Regression tests for crewAI false-positive patterns.

These tests reproduce the false positives found when scanning the crewAI
repo with v0.1.7, where 52 findings in 28 files were mostly false positives
from three causes:
  1. Substring matching in _match_attr_call ("db" in "sandbox.delete" → True)
  2. Prefix matching in _match_attr_call ("session".startswith("s") → True)
  3. Reachability giving MEDIUM confidence to sinks in non-tool functions
     just because the module imports an agent framework
  4. "query" in DATABASE-ORM-MUTATE module_patterns matching API client calls
"""

import ast
import unittest

from actenon_scan.detectors.reachability import detect_reachability
from actenon_scan.detectors.sinks import detect_sinks
from actenon_scan.rules.loader import load_rules


RULESET = load_rules()


def _has_finding(source: str) -> bool:
    """Parse source, detect sinks, and return True if any sink is agent-reachable."""
    tree = ast.parse(source)
    sinks = detect_sinks(tree, "test.py", RULESET.sinks)
    for sf in sinks:
        reach = detect_reachability(tree, sf.line, RULESET.reachability)
        if reach.confidence != "none":
            return True
    return False


class CrewAIFalsePositiveTests(unittest.TestCase):
    """Calls that were false positives in the crewAI scan must NOT be flagged."""

    def test_sandbox_delete_not_flagged(self):
        """sandbox.delete() must not match DATABASE-ORM-MUTATE.

        v0.1.7 bug: 'db' in 'sandbox.delete' → True (substring match).
        v0.1.8 fix: exact segment matching — 'sandbox' != 'db'.
        """
        source = (
            'from crewai import Tool\n'
            '@Tool("x", "y")\n'
            'def f():\n'
            '    sandbox.delete(timeout=1)\n'
        )
        self.assertFalse(_has_finding(source), "sandbox.delete() should not be flagged")

    def test_sandbox_cls_create_not_flagged(self):
        """sandbox_cls.create() must not match DATABASE-ORM-MUTATE.

        v0.1.7 bug: 'db' in 'sandbox_cls.create' → True (substring).
        """
        source = (
            'from crewai import Tool\n'
            '@Tool("x", "y")\n'
            'def f():\n'
            '    sandbox_cls.create(**kw)\n'
        )
        self.assertFalse(_has_finding(source), "sandbox_cls.create() should not be flagged")

    def test_api_client_query_create_not_flagged(self):
        """self.contextual_client.agents.query.create() must not match DATABASE-ORM-MUTATE.

        v0.1.7 bug: 'query' in the attribute chain matched the 'query' module_pattern.
        v0.1.8 fix: 'query' removed from DATABASE-ORM-MUTATE module_patterns.
        """
        source = (
            'from crewai import Tool\n'
            '@Tool("x", "y")\n'
            'def f():\n'
            '    self.contextual_client.agents.query.create(agent_id=a, messages=[])\n'
        )
        self.assertFalse(_has_finding(source), "API client query.create() should not be flagged")

    def test_s_save_not_flagged(self):
        """s.save() must not match DATABASE-ORM-MUTATE.

        v0.1.7 bug: 'session'.startswith('s') → True (prefix match).
        v0.1.8 fix: exact segment matching — 's' != 'session'.
        """
        source = (
            'from crewai import Tool\n'
            '@Tool("x", "y")\n'
            'def f():\n'
            '    s.save([_rec(content="x")])\n'
        )
        self.assertFalse(_has_finding(source), "s.save() should not be flagged")

    def test_os_remove_in_non_tool_function_not_flagged(self):
        """os.remove() in a non-tool function must not be flagged, even if the
        module imports an agent framework.

        v0.1.7 bug: 'agent_framework_import' gave MEDIUM confidence to ALL sinks
        in modules that import an agent framework — including internal functions.
        v0.1.8 fix: MEDIUM confidence only applies to module-level sinks, not
        sinks inside non-tool functions.
        """
        source = (
            'from crewai import Agent\n'
            'import os\n'
            'def cleanup(path):\n'
            '    os.remove(path)\n'
        )
        self.assertFalse(_has_finding(source), "os.remove() in non-tool function should not be flagged")

    def test_shutil_rmtree_in_non_tool_function_not_flagged(self):
        """shutil.rmtree() in a non-tool function must not be flagged."""
        source = (
            'import shutil\n'
            'def cleanup(path):\n'
            '    shutil.rmtree(path)\n'
        )
        self.assertFalse(_has_finding(source), "shutil.rmtree() in non-tool function should not be flagged")

    def test_os_unlink_in_non_tool_function_not_flagged(self):
        """os.unlink() in a non-tool function must not be flagged."""
        source = (
            'import os\n'
            'def cleanup(tmp):\n'
            '    os.unlink(tmp)\n'
        )
        self.assertFalse(_has_finding(source), "os.unlink() in non-tool function should not be flagged")

    def test_nested_test_file_excluded(self):
        """Test files in nested directories (tests/rag/test_csv_loader.py) must
        be excluded by default.

        v0.1.7 bug: glob pattern '*/tests/test_*.py' didn't match
        'tests/rag/test_csv_loader.py' (extra 'rag/' directory level).
        v0.1.8 fix: use '**/test_*.py' patterns that match at any depth.
        """
        import tempfile
        from pathlib import Path
        from actenon_scan.engine import scan_path

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Create a nested test file that should be excluded
            nested = tmp_path / "lib" / "crewai-tools" / "tests" / "rag"
            nested.mkdir(parents=True)
            (nested / "test_csv_loader.py").write_text(
                'import os\n'
                'from langchain.tools import tool\n'
                '@tool\n'
                'def test_thing():\n'
                '    os.remove("x")\n'
            )
            # Create a real source file that should be scanned
            (tmp_path / "real_tool.py").write_text(
                'from langchain.tools import tool\n'
                'import stripe\n'
                '@tool\n'
                'def refund(pid, amt):\n'
                '    return stripe.Refund.create(payment_intent=pid, amount=amt)\n'
            )

            result = scan_path(tmp_path)

            self.assertEqual(result.files_scanned, 1, "should only scan real_tool.py")
            for f in result.findings:
                self.assertNotIn("test_csv_loader", f.file, "test_csv_loader.py should be excluded")


class RealFindingTests(unittest.TestCase):
    """Real findings must still be detected after the false-positive fixes."""

    def test_os_remove_in_tool_function_flagged(self):
        """os.remove() inside a @tool function must still be flagged."""
        source = (
            'from langchain.tools import tool\n'
            'import os\n'
            '@tool\n'
            'def delete_file(path):\n'
            '    os.remove(path)\n'
        )
        self.assertTrue(_has_finding(source), "os.remove() in @tool should be flagged")

    def test_stripe_refund_in_tool_function_flagged(self):
        """stripe.Refund.create() inside a @tool function must still be flagged."""
        source = (
            'from langchain.tools import tool\n'
            'import stripe\n'
            '@tool\n'
            'def refund(pid, amt):\n'
            '    return stripe.Refund.create(payment_intent=pid, amount=amt)\n'
        )
        self.assertTrue(_has_finding(source), "stripe.Refund.create() in @tool should be flagged")

    def test_pathlib_unlink_in_tool_function_flagged(self):
        """p.unlink() inside a @tool function must still be flagged.

        This requires variable-type tracking: p = Path(...) → p is a Path.
        """
        source = (
            'from langchain.tools import tool\n'
            'from pathlib import Path\n'
            '@tool\n'
            'def delete_config(config_path):\n'
            '    p = Path(config_path)\n'
            '    p.unlink()\n'
        )
        self.assertTrue(_has_finding(source), "p.unlink() in @tool should be flagged")

    def test_session_delete_in_tool_function_flagged(self):
        """session.delete() inside a @tool function must still be flagged as ORM mutation."""
        source = (
            'from langchain.tools import tool\n'
            '@tool\n'
            'def remove_member(session, member):\n'
            '    session.delete(member)\n'
        )
        self.assertTrue(_has_finding(source), "session.delete() in @tool should be flagged")

    def test_crewai_tool_decorator_recognized(self):
        """CrewAI's @Tool(...) decorator must be recognized as a tool boundary."""
        source = (
            'from crewai import Tool\n'
            'import os\n'
            '@Tool("Delete", "Deletes a file")\n'
            'def delete_file(path):\n'
            '    os.remove(path)\n'
        )
        self.assertTrue(_has_finding(source), "@Tool(...) decorated function should be flagged")

    def test_openai_agent_tool_decorator_recognized(self):
        """OpenAI's @Agent.tool(...) decorator must be recognized as a tool boundary."""
        source = (
            'from openai import Agent\n'
            'import os\n'
            '@Agent.tool("Delete", "Deletes a file")\n'
            'def delete_file(path):\n'
            '    os.remove(path)\n'
        )
        self.assertTrue(_has_finding(source), "@Agent.tool(...) decorated function should be flagged")


if __name__ == "__main__":
    unittest.main()
