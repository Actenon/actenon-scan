"""The parallel scan must return exactly what the serial scan returns.

A faster scanner that finds different things is not a faster scanner, it is
a different scanner. This locks the equivalence so the parallel path cannot
drift from the serial one.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon_scan.engine import scan_path, scan_path_parallel

TOOL_FILE = (
    "from langchain.tools import tool\n"
    "import subprocess\n"
    "@tool\n"
    "def run_{n}(cmd: str):\n"
    "    return subprocess.run(cmd, shell=True)\n"
)
INERT_FILE = "class Plain{n}:\n    pass\n"


def _key(result):
    return sorted(
        (f.file, f.line, f.rule_id, f.severity, f.suppressed) for f in result.findings
    )


class ParallelEquivalenceTests(unittest.TestCase):
    def _repo(self, tmp: str, n_tool: int, n_inert: int) -> Path:
        root = Path(tmp)
        for i in range(n_tool):
            (root / f"tool_{i}.py").write_text(TOOL_FILE.format(n=i))
        for i in range(n_inert):
            (root / f"inert_{i}.py").write_text(INERT_FILE.format(n=i))
        return root

    def test_parallel_matches_serial_above_the_shard_threshold(self) -> None:
        # Needs to exceed the 200-file floor where parallelism kicks in.
        with TemporaryDirectory() as tmp:
            root = self._repo(tmp, n_tool=60, n_inert=200)
            serial = scan_path(root)
            parallel = scan_path_parallel(root, jobs=4)
        self.assertEqual(_key(serial), _key(parallel))
        self.assertEqual(serial.files_scanned, parallel.files_scanned)
        self.assertGreater(len([f for f in serial.findings if not f.suppressed]), 0)

    def test_jobs_of_one_is_the_serial_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = self._repo(tmp, n_tool=5, n_inert=5)
            self.assertEqual(_key(scan_path(root)), _key(scan_path_parallel(root, jobs=1)))

    def test_small_repo_falls_back_to_serial(self) -> None:
        # Under the threshold the parallel entry point must still be correct.
        with TemporaryDirectory() as tmp:
            root = self._repo(tmp, n_tool=3, n_inert=3)
            self.assertEqual(_key(scan_path(root)), _key(scan_path_parallel(root, jobs=8)))


if __name__ == "__main__":
    unittest.main()
