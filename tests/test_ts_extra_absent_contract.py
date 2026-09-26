"""Regression test for the packaging/API-contract regression on PR #95.

Background:
  The cross-language reachability slice (commit 9c4a01d) changed
  ``_scan_typescript_files`` from a 3-tuple to a 4-tuple so the engine
  could pass the scanned TS file list to the cross-language reachability
  layer. Two early-return paths inside the function (ImportError and
  ``is_typescript_extra_available() == False``) were left as 3-tuples,
  crashing the engine with ``ValueError: not enough values to unpack``
  when the TypeScript optional dependency was absent (base install /
  built wheel without extras).

This regression test pins the contract: ``_scan_typescript_files`` MUST
return exactly four values on EVERY return path, and the fourth value
on fallback paths MUST be the empty list ``[]`` — never fabricated data.

The test runs in ANY environment (with or without the TS extra installed)
because it patches ``is_typescript_extra_available`` to return False,
simulating the base-install scenario that PR #95's CI reproduced.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from actenon_scan.engine import _scan_typescript_files, scan_path


class TestScanTypescriptFilesContractWhenExtraAbsent(unittest.TestCase):
    """The function MUST return a 4-tuple on every return path,
    including the ImportError and extra-unavailable fallbacks.

    This pins the regression in PR #95 where the fallback paths
    returned a 3-tuple, crashing scan_path on the base-install CI.
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        # A directory containing a single .ts file the engine should
        # report as unsupported (since we patch is_typescript_extra_available
        # to return False, simulating the base install).
        (Path(self.tmpdir) / "server.ts").write_text(
            'export function noop() { return 1; }\n'
        )

    def test_import_error_path_returns_four_values(self) -> None:
        """Patch ``is_typescript_extra_available`` AND make the import
        itself raise ImportError. This exercises the FIRST early-return
        path inside _scan_typescript_files.
        """
        with mock.patch("actenon_scan.engine.is_typescript_extra_available", return_value=False, create=True):
            # Make the inner import inside _scan_typescript_files fail by
            # patching the detector module to raise ImportError on access.
            import sys
            real_module = sys.modules.get("actenon_scan.detectors.typescript")
            if real_module is not None:
                # Inject a fake module that raises ImportError on attribute
                # access — the function's try/except catches this and returns
                # the 3-tuple (now 4-tuple after the fix).
                class _RaisingModule:
                    def __getattr__(self, name):
                        raise ImportError(f"simulated: {name} not available")

                sys.modules["actenon_scan.detectors.typescript"] = _RaisingModule()
                try:
                    result = _scan_typescript_files(
                        Path(self.tmpdir), None, None,
                    )
                finally:
                    if real_module is not None:
                        sys.modules["actenon_scan.detectors.typescript"] = real_module
        # The contract: exactly 4 values, all empty.
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 4, (
            f"_scan_typescript_files returned {len(result)} values on the "
            f"ImportError fallback path; expected exactly 4. "
            f"Got: {result!r}"
        ))
        findings, scanned, errors, files_list = result
        self.assertEqual(findings, [], "findings must be empty when TS extra is absent")
        self.assertEqual(scanned, 0, "scanned count must be 0 when TS extra is absent")
        self.assertEqual(errors, [], "errors must be empty when TS extra is absent")
        self.assertEqual(files_list, [], (
            "files_list MUST be the empty list on the ImportError fallback "
            "path — never None, never fabricated data. Got: "
            f"{files_list!r}"
        ))

    def test_extra_unavailable_path_returns_four_values(self) -> None:
        """Patch ``is_typescript_extra_available`` to return False WITHOUT
        touching the import (it succeeds). This exercises the SECOND
        early-return path inside _scan_typescript_files.
        """
        from actenon_scan.detectors import typescript as ts_module
        with mock.patch.object(ts_module, "is_typescript_extra_available", return_value=False):
            result = _scan_typescript_files(
                Path(self.tmpdir), None, None,
            )
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 4, (
            f"_scan_typescript_files returned {len(result)} values on the "
            f"extra-unavailable fallback path; expected exactly 4. "
            f"Got: {result!r}"
        ))
        findings, scanned, errors, files_list = result
        self.assertEqual(findings, [])
        self.assertEqual(scanned, 0)
        self.assertEqual(errors, [])
        self.assertEqual(files_list, [], (
            "files_list MUST be the empty list on the extra-unavailable "
            "fallback path. Got: "
            f"{files_list!r}"
        ))

    def test_scan_path_does_not_crash_when_ts_extra_absent(self) -> None:
        """scan_path on a directory containing a .ts file MUST NOT crash
        when the TS extra is unavailable (the regression on PR #95 caused
        a ValueError: not enough values to unpack here).
        """
        # Patch BOTH the engine's private availability check (used by
        # _collect_unsupported_files to decide whether .ts files are
        # unsupported) AND the detector module's check (used by
        # _scan_typescript_files to decide whether to scan). When the
        # TS extra is truly absent, BOTH return False.
        from actenon_scan.detectors import typescript as ts_module
        from actenon_scan import engine as engine_module
        with mock.patch.object(ts_module, "is_typescript_extra_available", return_value=False), \
             mock.patch.object(engine_module, "_is_typescript_extra_available", return_value=False):
            # scan_path should run cleanly and report the .ts file as
            # unsupported (since the parser isn't available).
            result = scan_path(self.tmpdir, cache=None)
        # No findings (the .ts file was not scanned, so no sink match).
        self.assertEqual(
            len(result.findings), 0,
            f"Expected 0 findings when TS extra absent; got {result.findings}",
        )
        # The .ts file MUST appear in unsupported_files with the
        # "TypeScript" language tag (the existing pre-PR behaviour).
        self.assertGreater(
            len(result.unsupported_files), 0,
            "The .ts file MUST be reported as unsupported when the TS extra "
            "is absent — the regression on PR #95 silenced this safety surface.",
        )
        # Find the TS entry in unsupported_files.
        ts_unsupported = [
            (f, l) for f, l in result.unsupported_files
            if f.endswith(".ts")
        ]
        self.assertEqual(
            len(ts_unsupported), 1,
            f"Expected exactly 1 .ts file in unsupported_files; got "
            f"{ts_unsupported}",
        )
        _file, lang = ts_unsupported[0]
        self.assertEqual(lang, "TypeScript")

    def test_repository_analysis_not_fabricated_when_ts_extra_absent(self) -> None:
        """When the TS extra is absent, scan_path MUST NOT fabricate TS
        analysis. Concretely:
          - repository_analysis_enabled MUST be False (no Python files,
            no TS files were parsed, no Go files either).
          - local_call_edges MUST be empty (no cross-language edges
            were collected because the cross-language layer was gated
            on ts_files_scanned being non-empty).
          - transitive_followed_count / transitive_unfollowed_count
            MUST be 0.
        """
        from actenon_scan.detectors import typescript as ts_module
        from actenon_scan import engine as engine_module
        with mock.patch.object(ts_module, "is_typescript_extra_available", return_value=False), \
             mock.patch.object(engine_module, "_is_typescript_extra_available", return_value=False):
            result = scan_path(self.tmpdir, cache=None)
        self.assertFalse(
            result.repository_analysis_enabled,
            "repository_analysis_enabled MUST be False when no Python/TS/Go "
            "files were scanned — the cross-language layer must NOT silently "
            "fabricate TS analysis. Got: "
            f"{result.repository_analysis_enabled}",
        )
        self.assertEqual(
            result.transitive_followed_count, 0,
            "transitive_followed_count MUST be 0 when no TS/Go files were "
            "scanned — no cross-language edges were followed.",
        )
        self.assertEqual(
            result.transitive_unfollowed_count, 0,
            "transitive_unfollowed_count MUST be 0 when no TS/Go files were "
            "scanned.",
        )
        self.assertEqual(
            result.local_call_edges, [],
            "local_call_edges MUST be empty when no cross-language analysis "
            "ran — the empty file list MUST NOT produce fabricated edges.",
        )


if __name__ == "__main__":
    unittest.main()
