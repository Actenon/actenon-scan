"""Regression tests for file collection and file-deletion detection."""

import unittest
from pathlib import Path

from actenon_scan.engine import scan_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class FileCollectionTests(unittest.TestCase):
    """Blocker 1: scan . on a directory must find files without --include."""

    def test_scan_directory_finds_files_without_include_flag(self):
        """The headline command `actenon-scan scan .` must find .py files
        without requiring the user to pass --include.
        """
        result = scan_path(FIXTURES / "vulnerable")
        self.assertGreater(
            result.files_scanned,
            0,
            "scan_path on a directory must find .py files without --include. "
            f"Got files_scanned={result.files_scanned}.",
        )

    def test_scan_directory_finds_all_py_files(self):
        """All .py files in the vulnerable fixtures directory should be found."""
        vuln_dir = FIXTURES / "vulnerable"
        py_count = len(list(vuln_dir.rglob("*.py")))
        result = scan_path(vuln_dir)
        self.assertEqual(
            result.files_scanned,
            py_count,
            f"Should scan all {py_count} .py files, got {result.files_scanned}.",
        )


class FileDeletionSinkTests(unittest.TestCase):
    """Blocker 2: os.remove, shutil.rmtree, pathlib.Path.unlink must be detected."""

    def test_os_remove_in_agent_tool_flagged(self):
        """os.remove() in an @server.tool must be flagged as data_destruction."""
        result = scan_path(FIXTURES / "vulnerable" / "delete_files_os.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertGreater(
            len(findings),
            0,
            "delete_files_os.py should flag os.remove and shutil.rmtree",
        )
        self.assertTrue(
            any(f.category == "data_destruction" for f in findings),
            "Findings should include data_destruction category",
        )

    def test_shutil_rmtree_flagged(self):
        """shutil.rmtree() in an agent tool must be flagged."""
        result = scan_path(FIXTURES / "vulnerable" / "delete_files_os.py")
        findings = [f for f in result.findings if not f.suppressed]
        # Should have at least 2 findings (os.remove + shutil.rmtree)
        self.assertGreaterEqual(
            len(findings),
            2,
            "delete_files_os.py should flag both os.remove and shutil.rmtree",
        )

    def test_pathlib_unlink_flagged(self):
        """pathlib.Path.unlink() in an agent tool must be flagged."""
        result = scan_path(FIXTURES / "vulnerable" / "delete_pathlib.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertGreater(
            len(findings),
            0,
            "delete_pathlib.py should flag pathlib.Path.unlink",
        )
        self.assertTrue(
            any(f.category == "data_destruction" for f in findings),
            "Findings should include data_destruction category",
        )


if __name__ == "__main__":
    unittest.main()
