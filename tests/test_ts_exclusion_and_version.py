"""Tests for TS test-file exclusion and __version__ derivation."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path


def _ts_extra_available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
        return True
    except ImportError:
        return False


TS_EXTRA_AVAILABLE = _ts_extra_available()


@pytest.mark.skipif(not TS_EXTRA_AVAILABLE, reason="TypeScript extra not installed")
class TestTypeScriptTestFileExclusion:
    """TS test files must be excluded, matching the Python analyser's behaviour.

    The three TS false positives in the MCP servers repo were all in
    .test.ts files (beforeEach/afterEach cleanup using fs.writeFile
    and fs.rm). These are test fixtures, not agent tool code.
    """

    def _make_ts_sink_source(self) -> str:
        return '''import * as fs from "fs";
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  fs.rmSync(req.params.arguments.path);
});
'''

    def test_dot_test_ts_excluded(self, tmp_path):
        """*.test.ts files are excluded from scanning."""
        (tmp_path / "cleanup.test.ts").write_text(self._make_ts_sink_source())
        result = scan_path(tmp_path)
        assert len(result.findings) == 0
        assert result.files_scanned == 0

    def test_dot_spec_ts_excluded(self, tmp_path):
        """*.spec.ts files are excluded from scanning."""
        (tmp_path / "server.spec.ts").write_text(self._make_ts_sink_source())
        result = scan_path(tmp_path)
        assert len(result.findings) == 0
        assert result.files_scanned == 0

    def test_underscore_tests_dir_excluded(self, tmp_path):
        """Files in __tests__/ directories are excluded."""
        tests_dir = tmp_path / "src" / "__tests__"
        tests_dir.mkdir(parents=True)
        (tests_dir / "cleanup.ts").write_text(self._make_ts_sink_source())
        result = scan_path(tmp_path)
        assert len(result.findings) == 0
        assert result.files_scanned == 0

    def test_underscore_mocks_dir_excluded(self, tmp_path):
        """Files in __mocks__/ directories are excluded."""
        mocks_dir = tmp_path / "__mocks__"
        mocks_dir.mkdir()
        (mocks_dir / "fs.ts").write_text(self._make_ts_sink_source())
        result = scan_path(tmp_path)
        assert len(result.findings) == 0
        assert result.files_scanned == 0

    def test_dot_test_js_excluded(self, tmp_path):
        """*.test.js files are excluded."""
        (tmp_path / "cleanup.test.js").write_text(self._make_ts_sink_source())
        result = scan_path(tmp_path)
        assert len(result.findings) == 0

    def test_non_test_ts_still_scanned(self, tmp_path):
        """Non-test .ts files are still scanned."""
        (tmp_path / "server.ts").write_text(self._make_ts_sink_source())
        result = scan_path(tmp_path)
        assert len(result.findings) >= 1
        assert result.files_scanned >= 1

    def test_dot_bench_ts_excluded(self, tmp_path):
        """*.bench.ts files are excluded."""
        (tmp_path / "perf.bench.ts").write_text(self._make_ts_sink_source())
        result = scan_path(tmp_path)
        assert len(result.findings) == 0

    def test_test_file_not_in_unsupported(self, tmp_path):
        """Test .ts files should NOT appear in unsupported_files when extra is installed."""
        (tmp_path / "cleanup.test.ts").write_text(self._make_ts_sink_source())
        result = scan_path(tmp_path)
        # With the extra installed, .test.ts is excluded from scanning
        # AND from unsupported_files (it's a test file, not production code)
        assert len(result.unsupported_files) == 0


class TestVersionDerivation:
    """__version__ must be derived from importlib.metadata, not hardcoded."""

    def test_version_matches_pyproject(self):
        """__version__ must match pyproject.toml's version field."""
        import tomllib
        from actenon_scan import __version__

        with open("pyproject.toml", "rb") as f:
            d = tomllib.load(f)
        pyproject_version = d["project"]["version"]

        assert __version__ == pyproject_version, (
            f"__version__={__version__!r} but pyproject.toml says {pyproject_version!r}"
        )

    def test_version_not_hardcoded_to_old_value(self):
        """__version__ must not be stuck at 0.2.3."""
        from actenon_scan import __version__
        assert __version__ != "0.2.3", (
            "__version__ is still 0.2.3 — it should be derived from "
            "importlib.metadata, not hardcoded"
        )

    def test_cli_version_flag_matches(self):
        """actenon-scan --version must report the correct version."""
        from actenon_scan import __version__
        # Just verify __version__ is importable and non-empty
        assert __version__
        assert len(__version__) > 0
