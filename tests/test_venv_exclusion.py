"""Regression test: scanner must ignore virtual envs, build dirs, and dependency dirs.

Reproduces the OpenHands adoption bug where `actenon-scan scan .` on a
project with a venv at ./.actenon-env/ found the scanner's OWN test
fixtures (shipped in the wheel) as false positives, drowning out the
real findings.

The fix: default exclude patterns for .venv/, venv/, .actenon-env/,
node_modules/, __pycache__/, build/, dist/, .eggs/, *.egg-info/,
.pytest_cache/, .ruff_cache/, .mypy_cache/, **/tests/fixtures/**, etc.
"""

import unittest
from pathlib import Path

from actenon_scan.engine import scan_path


class VenvExclusionTests(unittest.TestCase):
    """Virtual envs, build dirs, and dependency dirs must be ignored by default."""

    def test_ignores_actenon_env_directory(self):
        """The .actenon-env/ directory (used in the OpenHands repro) must be ignored."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Real source file — should be scanned
            (tmp_path / "app_tool.py").write_text(
                "from langchain.tools import tool\n"
                "import stripe\n"
                "@tool\n"
                "def refund(pid, amt):\n"
                "    return stripe.Refund.create(payment_intent=pid, amount=amt)\n"
            )
            # Venv directory with a .py file — should be ignored
            (tmp_path / ".actenon-env").mkdir(parents=True)
            (tmp_path / ".actenon-env" / "lib").mkdir(parents=True)
            (tmp_path / ".actenon-env" / "lib" / "vulnerable.py").write_text(
                "import os\n"
                "def delete(p):\n"
                "    return os.remove(p)\n"
            )

            result = scan_path(tmp_path)

            self.assertEqual(result.files_scanned, 1, "should only scan the real app_tool.py")
            scanned_files = [f.file for f in result.findings]
            self.assertTrue(
                all(".actenon-env" not in f for f in scanned_files),
                f"should not scan .actenon-env/ files, got: {scanned_files}",
            )

    def test_ignores_standard_venv_directories(self):
        """All common venv directory names must be ignored."""
        import tempfile

        venv_names = [".venv", "venv", "env", ".env", ".tox"]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "real_tool.py").write_text(
                "from langchain.tools import tool\n"
                "import stripe\n"
                "@tool\n"
                "def refund(pid, amt):\n"
                "    return stripe.Refund.create(payment_intent=pid, amount=amt)\n"
            )
            for venv in venv_names:
                (tmp_path / venv).mkdir(parents=True)
                (tmp_path / venv / "fake.py").write_text(
                    "import os\n"
                    "def delete(p):\n"
                    "    return os.remove(p)\n"
                )

            result = scan_path(tmp_path)

            self.assertEqual(result.files_scanned, 1, "should only scan real_tool.py")
            for f in result.findings:
                for venv in venv_names:
                    self.assertNotIn(venv, f.file, f"should not scan {venv}/ files")

    def test_ignores_node_modules_and_build_dirs(self):
        """node_modules/, build/, dist/, target/ must be ignored."""
        import tempfile

        dirs = ["node_modules", "build", "dist", "target", ".eggs"]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "real_tool.py").write_text(
                "from langchain.tools import tool\n"
                "import stripe\n"
                "@tool\n"
                "def refund(pid, amt):\n"
                "    return stripe.Refund.create(payment_intent=pid, amount=amt)\n"
            )
            for d in dirs:
                (tmp_path / d).mkdir(parents=True)
                (tmp_path / d / "fake.py").write_text(
                    "import os\n"
                    "def delete(p):\n"
                    "    return os.remove(p)\n"
                )

            result = scan_path(tmp_path)

            self.assertEqual(result.files_scanned, 1, "should only scan real_tool.py")

    def test_ignores_pycache_and_cache_dirs(self):
        """__pycache__/, .pytest_cache/, .ruff_cache/, .mypy_cache/ must be ignored."""
        import tempfile

        dirs = ["__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "real_tool.py").write_text(
                "from langchain.tools import tool\n"
                "import stripe\n"
                "@tool\n"
                "def refund(pid, amt):\n"
                "    return stripe.Refund.create(payment_intent=pid, amount=amt)\n"
            )
            for d in dirs:
                (tmp_path / d).mkdir(parents=True)
                (tmp_path / d / "fake.py").write_text(
                    "import os\n"
                    "def delete(p):\n"
                    "    return os.remove(p)\n"
                )

            result = scan_path(tmp_path)

            self.assertEqual(result.files_scanned, 1, "should only scan real_tool.py")

    def test_ignores_tests_fixtures_directory(self):
        """**/tests/fixtures/** must be ignored (scanner's own fixtures)."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "real_tool.py").write_text(
                "from langchain.tools import tool\n"
                "import stripe\n"
                "@tool\n"
                "def refund(pid, amt):\n"
                "    return stripe.Refund.create(payment_intent=pid, amount=amt)\n"
            )
            # Simulate the scanner's own shipped fixtures
            fixtures = tmp_path / "tests" / "fixtures" / "vulnerable"
            fixtures.mkdir(parents=True)
            (fixtures / "refund_tool.py").write_text(
                "import stripe\n"
                "def refund(payment_id, amount):\n"
                "    return stripe.Refund.create(payment_intent=payment_id, amount=amount)\n"
            )

            result = scan_path(tmp_path)

            self.assertEqual(result.files_scanned, 1, "should only scan real_tool.py")
            for f in result.findings:
                self.assertNotIn("tests/fixtures", f.file, "should not scan tests/fixtures/")

    def test_real_finding_still_detected(self):
        """A real finding in a normal source file must still be detected."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "real_tool.py").write_text(
                "from langchain.tools import tool\n"
                "import stripe\n"
                "@tool\n"
                "def refund(pid, amt):\n"
                "    return stripe.Refund.create(payment_intent=pid, amount=amt)\n"
            )

            result = scan_path(tmp_path)

            self.assertEqual(result.files_scanned, 1)
            self.assertTrue(any(f.rule_id == "PAY-STRIPE-REFUND" for f in result.findings))


if __name__ == "__main__":
    unittest.main()
