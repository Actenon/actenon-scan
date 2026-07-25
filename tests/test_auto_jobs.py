"""auto_jobs must never choose parallelism where it was measured to lose.

Parallel-by-default was ~10% SLOWER than serial on 2-4 core CI runners while
being ~2.5x faster on a 10-core host. The discriminator is core count, not
file count, so these tests pin the core gate as well as the file floor.
"""

from __future__ import annotations

import unittest

from actenon_scan.engine import (
    MIN_CORES_FOR_AUTO_PARALLEL,
    MIN_FILES_FOR_AUTO_PARALLEL,
    auto_jobs,
)


class AutoJobsTests(unittest.TestCase):
    def test_low_core_machines_never_auto_parallelise(self) -> None:
        # The measured regression: 2-4 cores, large repo, parallel loses.
        for cores in (1, 2, 3, 4):
            with self.subTest(cores=cores):
                self.assertEqual(1, auto_jobs(5000, cores))

    def test_unmeasured_core_range_defaults_to_serial(self) -> None:
        # 5-7 cores was never measured. Ambiguity resolves to the mode that
        # is never slower, not to the one that might be faster.
        for cores in range(5, MIN_CORES_FOR_AUTO_PARALLEL):
            with self.subTest(cores=cores):
                self.assertEqual(1, auto_jobs(5000, cores))

    def test_small_repos_stay_serial_even_on_many_cores(self) -> None:
        for files in (0, 50, 120, MIN_FILES_FOR_AUTO_PARALLEL - 1):
            with self.subTest(files=files):
                self.assertEqual(1, auto_jobs(files, 32))

    def test_large_repo_on_many_cores_parallelises(self) -> None:
        self.assertGreater(auto_jobs(2000, 10), 1)

    def test_never_uses_every_core(self) -> None:
        # One core is left for the parent, which does the ancillary passes.
        for cores in (8, 10, 16, 64):
            with self.subTest(cores=cores):
                self.assertLessEqual(auto_jobs(10000, cores), cores - 1)


if __name__ == "__main__":
    unittest.main()
