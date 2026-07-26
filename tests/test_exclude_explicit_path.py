"""Regression tests for the exclude/explicit-path distinction.

The exclude fix (PR #50) applies exclude globs to --changed-only's
explicit_files. This is correct for the git-diff-derived file list.
But user-named files reach the engine via _collect_files, which returns
single files unfiltered.

These two code paths don't touch each other today, but anyone
consolidating them into one helper could reintroduce the bug silently.
These tests assert the distinction at the CLI surface so the assertion
survives a refactor of the internals.
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


class ExcludeExplicitPathTests(unittest.TestCase):
    """Exclude globs must filter --changed-only files but NOT user-named files."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        # Create a file that matches an exclude glob
        self.excluded_dir = Path(self.tmpdir) / "tests" / "benchmark"
        self.excluded_dir.mkdir(parents=True, exist_ok=True)
        self.excluded_file = self.excluded_dir / "vulnerable.py"
        self.excluded_file.write_text(
            "from mcp import tool\n"
            "\n"
            "@tool()\n"
            "def run_cmd(cmd: str) -> str:\n"
            "    import subprocess\n"
            "    return subprocess.run(cmd, shell=True).stdout.decode()\n"
        )
        # Create an .actenon-scan.json that excludes tests/benchmark/**
        self.config = Path(self.tmpdir) / ".actenon-scan.json"
        self.config.write_text(
            '{"exclude": ["tests/benchmark/**"]}'
        )
        # Initialize a git repo so --changed-only works
        os.system(f"cd {self.tmpdir} && git init -q && git add -A && "
                   f"git -c user.name=test -c user.email=test@test.com commit -qm init")

    def test_excluded_file_via_changed_only_is_skipped(self) -> None:
        """A file matching an exclude glob, reached via --changed-only, is skipped."""
        # Touch the file so it shows in git diff
        os.system(f"cd {self.tmpdir} && git add -A && "
                   f"git -c user.name=test -c user.email=test@test.com commit -qm touch")

        result = subprocess.run(
            [sys.executable, SCAN_BIN, "scan", ".",
             "--changed-only", "HEAD~1", "--fail-on", "none"],
            capture_output=True, text=True, cwd=self.tmpdir,
        )
        # The file should be excluded — no findings
        self.assertNotIn("Your agent can reach", result.stdout,
                         "Excluded file was scanned via --changed-only — exclude globs not applied")

    def test_excluded_file_named_directly_is_scanned(self) -> None:
        """The same file named directly on the command line IS scanned."""
        result = subprocess.run(
            [sys.executable, SCAN_BIN, "scan",
             str(self.excluded_file), "--fail-on", "none"],
            capture_output=True, text=True, cwd=self.tmpdir,
        )
        # The file should be scanned — at least one finding
        self.assertIn("consequential action", result.stdout,
                      "User-named file was NOT scanned — exclude globs over-applied")


if __name__ == "__main__":
    unittest.main()
