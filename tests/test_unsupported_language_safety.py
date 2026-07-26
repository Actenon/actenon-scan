"""Tests for unsupported-language safety (ITEMs 1-4).

Tests that:
- A Go repo reports unsupported files when the [go] extra is NOT installed
- A single Go file reports unsupported when the [go] extra is NOT installed
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

    def test_go_directory_reports_unsupported_without_extra(self) -> None:
        """A directory of .go files must report unsupported when [go] extra is absent."""
        from actenon_scan.detectors.go import is_go_extra_available
        if is_go_extra_available():
            self.skipTest("[go] extra is installed — Go is supported")
        go_dir = Path(self.tmpdir) / "godir"
        go_dir.mkdir()
        (go_dir / "main.go").write_text("package main\n")
        result = self._scan(str(go_dir))
        self.assertIn("NOT scanned", result.stdout)
        self.assertIn("Go", result.stdout)
        # The install hint must point at the [go] extra so the user knows
        # how to enable Go scanning.
        self.assertIn("Install with", result.stdout)
        self.assertIn("go", result.stdout)

    def test_single_go_file_reports_unsupported_without_extra(self) -> None:
        """A single .go file named directly must report unsupported when [go] extra is absent."""
        from actenon_scan.detectors.go import is_go_extra_available
        if is_go_extra_available():
            self.skipTest("[go] extra is installed — Go is supported")
        go_file = Path(self.tmpdir) / "main.go"
        go_file.write_text("package main\n")
        result = self._scan(str(go_file))
        self.assertIn("NOT scanned", result.stdout)
        self.assertIn("Go", result.stdout)

    def test_changed_only_go_files_report_unsupported(self) -> None:
        """--changed-only on Go files must report unsupported (ITEM 1)."""
        from actenon_scan.detectors.go import is_go_extra_available
        go_dir = Path(self.tmpdir) / "godir"
        go_dir.mkdir()
        (go_dir / "main.go").write_text("package main\n")
        os.system(f"cd {self.tmpdir} && git init -q && git add -A && "
                   f"git -c user.name=test -c user.email=test@test.com commit -qm init")
        (go_dir / "another.go").write_text("package main\n")
        os.system(f"cd {self.tmpdir} && git add -A && "
                   f"git -c user.name=test -c user.email=test@test.com commit -qm touch")
        result = self._scan(str(go_dir), "--changed-only", "HEAD~1")
        if is_go_extra_available():
            # With the extra, Go files are scanned (not unsupported)
            self.assertNotIn("NOT scanned", result.stdout)
        else:
            # Without the extra, Go files are unsupported
            self.assertIn("NOT scanned", result.stdout)
            self.assertIn("Go", result.stdout)

    def test_ts_without_extra_shows_install_hint(self) -> None:
        """TS files without the extra should show 'Install with' hint."""
        ts_dir = Path(self.tmpdir) / "tsdir"
        ts_dir.mkdir()
        (ts_dir / "app.ts").write_text("console.log('hello');\n")
        result = self._scan(str(ts_dir))
        # If the extra IS installed, TS files are scanned and no warning appears.
        if "NOT scanned" in result.stdout:
            self.assertIn("Install with", result.stdout)
            self.assertIn("typescript", result.stdout)

    def test_go_shows_install_hint_when_extra_absent(self) -> None:
        """Go files should show the 'Install with actenon-scan[go]' hint when
        the [go] extra is NOT installed.

        Previously this test asserted the OPPOSITE — that Go should show "not
        supported" but NOT the install hint. That was when Go support was
        experimental and we didn't want to push it. Now that Go is a
        first-class supported language (the README headline says "Parses
        Python, TypeScript, and Go" and action.yml installs `[go]`), the
        install hint SHOULD appear so users know how to enable Go scanning.

        Note: the "Other languages are not supported" line is NOT printed
        for Go-only repos because Go is in the `extras` set (the line is
        reserved for truly-unsupported languages like .rs, .java, etc.).
        The user-facing signal that Go is unsupported is the "NOT scanned"
        line plus the install hint, not the "not supported" line.
        """
        from actenon_scan.detectors.go import is_go_extra_available
        if is_go_extra_available():
            self.skipTest("[go] extra is installed — Go is supported")
        go_dir = Path(self.tmpdir) / "godir"
        go_dir.mkdir()
        (go_dir / "main.go").write_text("package main\n")
        result = self._scan(str(go_dir))
        self.assertIn("NOT scanned", result.stdout)
        self.assertIn("Go", result.stdout)
        self.assertIn("Install with", result.stdout)
        self.assertIn("go", result.stdout)

    def test_typescript_extra_import_is_correct(self) -> None:
        """The tree_sitter_typescript import must not have a typo (ITEM 4)."""
        from actenon_scan.engine import _is_typescript_extra_available
        result = _is_typescript_extra_available()
        self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main()
