"""Phase 2 (D1): determinism test — cold == warm == --no-cache on
finding sets, capability counts, and blast-radius summary numbers.

Reproduces D1: tests/corpus/DECLARATIVE-GUARD cold 3, warm 5, --no-cache 3.
After the fix: cold == warm == --no-cache == 3.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from actenon_scan.engine import scan_path


class DeterminismTests(unittest.TestCase):
    """Cold, warm, and --no-cache must produce identical results."""

    def _scan(self, target: Path, cache_dir: Path | None, no_cache: bool = False):
        """Run a scan with the given cache config."""
        from actenon_scan.cache import FileCache
        cache = None
        if cache_dir is not None and not no_cache:
            cache = FileCache(cache_dir)
        result = scan_path(
            target, cache=cache,
            repository_analysis=False,  # per-file only for determinism
        )
        return result

    def _extract_numbers(self, result):
        """Extract the numbers that appear in the blast-radius summary."""
        findings = [(f.file, f.line, f.rule_id, f.suppressed)
                     for f in result.findings]
        caps = [(c.file, c.line, c.rule_id, c.state)
                for c in result.capabilities]
        return {
            "finding_count": len([f for f in result.findings if not f.suppressed]),
            "capability_count": len(result.capabilities),
            "findings": findings,
            "capabilities": caps,
            "transitive_followed": getattr(result, "transitive_followed_count", 0),
            "transitive_unfollowed": getattr(result, "transitive_unfollowed_count", 0),
        }

    def test_declarative_guard_determinism(self):
        """D1: tests/corpus/DECLARATIVE-GUARD cold == warm == --no-cache.

        Before the fix: cold 3, warm 5, --no-cache 3.
        After the fix: cold 3, warm 3, --no-cache 3.
        """
        target = Path("tests/corpus/DECLARATIVE-GUARD")
        if not target.exists():
            self.skipTest("DECLARATIVE-GUARD corpus not found")

        tmp = Path(tempfile.mkdtemp())
        cache_dir = tmp / "cache"

        # Cold: empty cache dir (first scan populates it)
        shutil.rmtree(cache_dir, ignore_errors=True)
        cache_dir.mkdir(parents=True)
        cold = self._extract_numbers(self._scan(target, cache_dir))

        # Warm: same cache dir (should hit cache)
        warm = self._extract_numbers(self._scan(target, cache_dir))

        # No-cache: --no-cache flag
        no_cache = self._extract_numbers(self._scan(target, cache_dir, no_cache=True))

        # Assert identical
        self.assertEqual(
            cold["finding_count"], warm["finding_count"],
            f"COLD ({cold['finding_count']}) != WARM ({warm['finding_count']}). "
            f"D1 cache bug: declarative-guard suppression lost on cache hit."
        )
        self.assertEqual(
            cold["finding_count"], no_cache["finding_count"],
            f"COLD ({cold['finding_count']}) != NO-CACHE ({no_cache['finding_count']})"
        )
        self.assertEqual(
            cold["findings"], warm["findings"],
            "Finding sets differ between cold and warm"
        )
        self.assertEqual(
            cold["findings"], no_cache["findings"],
            "Finding sets differ between cold and no-cache"
        )
        self.assertEqual(
            cold["capability_count"], warm["capability_count"],
            f"Capability counts differ: cold={cold['capability_count']}, "
            f"warm={warm['capability_count']}. D1: capabilities not cached."
        )
        self.assertEqual(
            cold["capability_count"], no_cache["capability_count"],
            "Capability counts differ between cold and no-cache"
        )

        # Print the result for the acceptance test
        print(f"\n  DECLARATIVE-GUARD determinism: "
              f"cold={cold['finding_count']}, warm={warm['finding_count']}, "
              f"no-cache={no_cache['finding_count']} — ALL EQUAL")

        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
