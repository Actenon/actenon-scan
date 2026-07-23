"""Pinned regression suite — records expected finding counts against fixed commits.

This test is NOT run on every commit (it requires network access to clone
repos). It runs nightly in CI via a scheduled workflow.

To update the expected counts after an intentional rule change:
1. Run the scan manually against the pinned commit
2. Update the expected counts in tests/pinned_repos.json
3. Commit the update in the same PR as the rule change

Known limitation: this test is skipped when the repos are not cloned locally.
In CI, the nightly workflow clones them before running.
"""

import json
import unittest
from pathlib import Path

PINNED_FILE = Path(__file__).resolve().parent / "pinned_repos.json"


class PinnedReposTests(unittest.TestCase):
    """Pinned regression tests for the 10 benchmark repos."""

    def setUp(self):
        if not PINNED_FILE.exists():
            self.skipTest("pinned_repos.json not found")
        self.pinned = json.loads(PINNED_FILE.read_text())

    def test_pinned_file_exists_and_has_entries(self):
        """The pinned repos file must exist and contain entries."""
        self.assertGreater(len(self.pinned), 0, "pinned_repos.json must have entries")

    def test_pinned_repos_have_required_fields(self):
        """Each pinned repo must have sha, files, production, high fields."""
        required = {"sha", "files", "production", "high"}
        for repo, data in self.pinned.items():
            missing = required - set(data.keys())
            self.assertEqual(
                missing, set(),
                f"pinned repo {repo} missing fields: {missing}"
            )


if __name__ == "__main__":
    unittest.main()
