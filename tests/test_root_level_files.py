"""Regression test: scanning a directory must include files at the directory root.

This blocks a class of bug where `actenon-scan scan .` on a flat repo (or
any repo with .py files at the directory root) silently skipped root-level
files and reported "Scanned 0 file(s)" — the headline command in the README.

The bug was present in published v0.1.0 and fixed in v0.1.4+.
"""

import unittest
from pathlib import Path

from actenon_scan.engine import scan_path


class RootLevelFileScanningTests(unittest.TestCase):
    """Files at the target directory's root must be scanned, not just files
    inside subdirectories."""

    def test_scans_files_at_target_root(self):
        """A @tool-decorated Stripe refund at the directory root must produce
        a PAY-STRIPE-REFUND finding.

        Reproduces the exact scenario from the README: a developer puts a
        file at their repo root, runs `actenon-scan scan .`, and expects
        the advertised finding to fire.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "root_tool.py").write_text(
                "from langchain.tools import tool\n"
                "import stripe\n"
                "@tool\n"
                "def refund(pid: str, amt: int) -> str:\n"
                "    'refund'\n"
                "    return stripe.Refund.create(payment_intent=pid, amount=amt)\n"
            )

            result = scan_path(tmp_path)

            self.assertGreaterEqual(
                result.files_scanned,
                1,
                "scan_path on a directory must include files at the directory root. "
                f"Got files_scanned={result.files_scanned}.",
            )
            self.assertTrue(
                any(f.rule_id == "PAY-STRIPE-REFUND" for f in result.findings),
                f"Expected PAY-STRIPE-REFUND finding from root_tool.py. "
                f"Got findings: {[f.rule_id for f in result.findings]}.",
            )

    def test_scans_both_root_and_subdirectory_files(self):
        """Both root-level files and files in subdirectories must be scanned."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "root_tool.py").write_text(
                "import stripe\n"
                "def refund_root(pid, amt):\n"
                "    return stripe.Refund.create(payment_intent=pid, amount=amt)\n"
            )
            (tmp_path / "sub").mkdir()
            (tmp_path / "sub" / "child_tool.py").write_text(
                "import os\n"
                "def delete_root(p):\n"
                "    return os.remove(p)\n"
            )

            result = scan_path(tmp_path)

            self.assertGreaterEqual(
                result.files_scanned,
                2,
                f"Both root and subdir files must be scanned. "
                f"Got files_scanned={result.files_scanned}.",
            )


if __name__ == "__main__":
    unittest.main()
