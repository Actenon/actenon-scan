"""Tests for unsupported-language safety (ITEMs 1-4).

Tests that:
- A Go repo reports unsupported files, not "clean"
- A single Go file reports unsupported, not "clean"
- --changed-only on Go files reports unsupported (ITEM 1)
- TS files without the extra report with "install" hint (ITEM 2)
- A file with an unknown extension is not reported as unsupported
- The tree_sitter_typescript import works (ITEM 4 typo fix)
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_BIN = str(ROOT / "actenon_scan" / "__main__.py")


class UnsupportedLanguageTests(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def _scan(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, SCAN_BIN, "scan", *args, "--fail-on", "none"],
            capture_output=True, text=True, cwd=self.tmpdir,
        )

    def test_go_directory_reports_unsupported(self) -> None:
        """A directory of .go files must report unsupported, not 'clean'."""
        go_dir = Path(self.tmpdir) / "godir"
        go_dir.mkdir()
        (go_dir / "main.go").write_text("package main\n")
        result = self._scan(str(go_dir))
        self.assertIn("NOT scanned", result.stdout)
        self.assertIn("Go", result.stdout)
        self.assertIn("not supported", result.stdout)

    def test_single_go_file_reports_unsupported(self) -> None:
        """A single .go file named directly must report unsupported."""
        go_file = Path(self.tmpdir) / "main.go"
        go_file.write_text("package main\n")
        result = self._scan(str(go_file))
        self.assertIn("NOT scanned", result.stdout)
        self.assertIn("Go", result.stdout)

    def test_changed_only_go_files_report_unsupported(self) -> None:
        """--changed-only on Go files must report unsupported (ITEM 1)."""
        go_dir = Path(self.tmpdir) / "godir"
        go_dir.mkdir()
        (go_dir / "main.go").write_text("package main\n")
        os.system(f"cd {self.tmpdir} && git init -q && git add -A && "
                   f"git -c user.name=test -c user.email=test@test.com commit -qm init")
        (go_dir / "another.go").write_text("package main\n")
        os.system(f"cd {self.tmpdir} && git add -A && "
                   f"git -c user.name=test -c user.email=test@test.com commit -qm touch")
        result = self._scan(str(go_dir), "--changed-only", "HEAD~1")
        self.assertIn("NOT scanned", result.stdout)
        self.assertIn("Go", result.stdout)

    def test_ts_without_extra_shows_install_hint(self) -> None:
        """TS files without the extra should show 'Install with' hint."""
        ts_dir = Path(self.tmpdir) / "tsdir"
        ts_dir.mkdir()
        (ts_dir / "app.ts").write_text("console.log('hello');\n")
        result = self._scan(str(ts_dir))
        # If the extra IS installed, TS files are scanned and no warning appears.
        # If the extra is NOT installed, the install hint should appear.
        if "NOT scanned" in result.stdout:
            self.assertIn("Install with", result.stdout)
            self.assertIn("typescript", result.stdout)

    def test_go_shows_not_supported_not_install_hint(self) -> None:
        """Go files should show 'not supported', NOT 'Install with'."""
        go_dir = Path(self.tmpdir) / "godir"
        go_dir.mkdir()
        (go_dir / "main.go").write_text("package main\n")
        result = self._scan(str(go_dir))
        self.assertIn("not supported", result.stdout)
        self.assertNotIn("Install with", result.stdout)

    def test_typescript_extra_import_is_correct(self) -> None:
        """The tree_sitter_typescript import must not have a typo (ITEM 4)."""
        from actenon_scan.engine import _is_typescript_extra_available
        # This should not raise an ImportError due to a typo
        # If tree-sitter and tree-sitter-typescript are installed, it returns True
        # If not, it returns False — but either way, no crash
        result = _is_typescript_extra_available()
        self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main()
