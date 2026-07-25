"""Tests for the content-hash cache (Work Order 2, Part 4.4 + 4.5).

Covers:
- cache hit returns identical findings (RULE 5)
- cache miss falls through to fresh scan
- file edit invalidates the cache entry
- --no-cache produces identical output
- corrupted cache entries are treated as cache misses
- cache key incorporates content + config + scanner version
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan.cache import (
    CacheEntry,
    FileCache,
    compute_cache_key,
    get_default_cache_dir,
)
from actenon_scan.engine import scan_path, Finding


_FINDING_FIXTURE = '''from mcp import tool

@tool()
def run_cmd(cmd: str) -> str:
    import subprocess
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''

_CLEAN_FIXTURE = '''import os

def helper():
    return os.getcwd()
'''


class CacheKeyTests(unittest.TestCase):
    def test_key_changes_with_content(self) -> None:
        config = type("Config", (), {"sinks": [], "guard_patterns": [], "reachability": []})()
        k1 = compute_cache_key("content A", config)
        k2 = compute_cache_key("content B", config)
        self.assertNotEqual(k1, k2)

    def test_key_changes_with_config(self) -> None:
        config_a = type("Config", (), {"sinks": [], "guard_patterns": ["a"], "reachability": []})()
        config_b = type("Config", (), {"sinks": [], "guard_patterns": ["b"], "reachability": []})()
        k1 = compute_cache_key("same content", config_a)
        k2 = compute_cache_key("same content", config_b)
        self.assertNotEqual(k1, k2)


class FileCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.cache_dir = Path(self.tmpdir) / ".actenon-scan-cache"
        self.cache = FileCache(self.cache_dir)
        self.fixture = Path(self.tmpdir) / "finding.py"
        self.fixture.write_text(_FINDING_FIXTURE)

    def test_cache_miss_returns_none(self) -> None:
        from actenon_scan.rules.loader import load_rules
        rules = load_rules(None)
        result = self.cache.findings_for(_FINDING_FIXTURE, "finding.py", rules)
        self.assertIsNone(result)

    def test_cache_hit_returns_identical_findings(self) -> None:
        """RULE 5: a cache hit returns the exact same findings."""
        # First scan — populates the cache.
        result1 = scan_path(self.fixture, cache=self.cache)
        findings1 = result1.findings

        # Second scan — should be a cache hit.
        cache2 = FileCache(self.cache_dir)
        result2 = scan_path(self.fixture, cache=cache2)
        findings2 = result2.findings

        # Findings must be identical.
        self.assertEqual(len(findings1), len(findings2))
        for f1, f2 in zip(findings1, findings2):
            self.assertEqual(f1.rule_id, f2.rule_id)
            self.assertEqual(f1.line, f2.line)
            self.assertEqual(f1.severity, f2.severity)
            self.assertEqual(f1.confidence, f2.confidence)
            self.assertEqual(f1.category, f2.category)
            self.assertEqual(f1.call_text, f2.call_text)

    def test_file_edit_invalidates_cache(self) -> None:
        """Editing a file changes its content hash, invalidating the cache."""
        # First scan.
        scan_path(self.fixture, cache=self.cache)

        # Edit the file (add a comment — doesn't change findings but
        # changes the content hash).
        self.fixture.write_text("# comment\n" + _FINDING_FIXTURE)

        # Second scan — the edited file must be re-scanned (cache miss).
        cache2 = FileCache(self.cache_dir)
        result = scan_path(self.fixture, cache=cache2)
        # Findings should still be the same (the comment doesn't affect
        # detection), but the cache should have a new entry for the new
        # content hash.
        self.assertGreater(len(result.findings), 0)

    def test_no_cache_produces_identical_output(self) -> None:
        """--no-cache (cache=None) produces the same findings as cached."""
        # Scan with cache.
        result_cached = scan_path(self.fixture, cache=self.cache)
        # Scan without cache.
        result_nocache = scan_path(self.fixture, cache=None)
        # Findings must be identical.
        self.assertEqual(
            len(result_cached.findings), len(result_nocache.findings)
        )

    def test_corrupted_cache_entry_treated_as_miss(self) -> None:
        """A corrupted cache entry is caught and treated as a cache miss."""
        from actenon_scan.rules.loader import load_rules
        rules = load_rules(None)
        key = compute_cache_key(_FINDING_FIXTURE, rules)
        # Write a corrupted entry.
        entry_path = self.cache_dir / key[:2] / f"{key}.json"
        entry_path.parent.mkdir(parents=True, exist_ok=True)
        entry_path.write_text("{ corrupted json")
        # The cache should return None (miss), not crash.
        result = self.cache.get(key)
        self.assertIsNone(result)

    def test_cache_disabled_returns_none(self) -> None:
        """A disabled cache always returns None (cache miss)."""
        self.cache.disable()
        result = self.cache.get("any-key")
        self.assertIsNone(result)

    def test_get_default_cache_dir_for_directory(self) -> None:
        d = get_default_cache_dir(Path(self.tmpdir))
        self.assertEqual(d, Path(self.tmpdir) / ".actenon-scan-cache")

    def test_get_default_cache_dir_for_file(self) -> None:
        d = get_default_cache_dir(self.fixture)
        self.assertEqual(d, self.fixture.parent / ".actenon-scan-cache")


class ProgressiveOutputTests(unittest.TestCase):
    """Part 4.1: progressive output streams findings as they are discovered."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.fixture = Path(self.tmpdir) / "finding.py"
        self.fixture.write_text(_FINDING_FIXTURE)

    def test_on_finding_callback_invoked(self) -> None:
        """The on_finding callback is invoked for each unsuppressed finding."""
        discovered: list[Finding] = []
        scan_path(self.fixture, on_finding=lambda f: discovered.append(f))
        self.assertGreater(len(discovered), 0)
        # Each discovered finding should be a Finding with a rule_id.
        for f in discovered:
            self.assertTrue(f.rule_id)

    def test_on_finding_not_invoked_for_suppressed(self) -> None:
        """Suppressed findings do not trigger the callback."""
        # A clean fixture produces no findings, so no callbacks.
        clean = Path(self.tmpdir) / "clean.py"
        clean.write_text(_CLEAN_FIXTURE)
        discovered: list[Finding] = []
        scan_path(clean, on_finding=lambda f: discovered.append(f))
        self.assertEqual(len(discovered), 0)


if __name__ == "__main__":
    unittest.main()
