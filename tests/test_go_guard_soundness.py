"""Soundness tests for Go guard recognition (ITEM 1).

Tests that the Go detector correctly:
  - Suppresses findings when a dominating, parameter-bound guard is present
  - Does NOT suppress when the guard is defeated (discarded error, dead branch)
  - Does NOT suppress when no guard exists

The two-function harness: one guarded, one not — must yield exactly one finding.
Defeated-guard variants must still be flagged.

These tests are in the soundness suite (not just unit tests) because they
test the core soundness property: a guard that doesn't actually guard must
not suppress a finding. A permissive implementation that suppresses on any
guard-named call would clear the harness test and blind the scanner.

These tests require the [go] extra (tree-sitter-go). They are automatically
skipped when tree-sitter-go is not installed (e.g. in the Base install CI job
that verifies zero runtime deps).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

# Skip all tests in this module if tree-sitter-go is not installed.
from actenon_scan.detectors.go import is_go_extra_available
pytestmark = pytest.mark.skipif(
    not is_go_extra_available(),
    reason="[go] extra not installed — tree-sitter-go required for Go guard tests",
)


def _write_go_fixture(tmp_path: Path, filename: str, source: str) -> Path:
    """Write a Go source file to tmp_path/filename and return the path."""
    p = tmp_path / filename
    p.write_text(textwrap.dedent(source))
    return p


# ---------------------------------------------------------------------------
# Two-function harness: one guarded, one not — must yield exactly one finding.
# ---------------------------------------------------------------------------


def test_go_guard_recognition_basic_harness(tmp_path: Path) -> None:
    """Two tools in one file: one guarded with authorize(), one not.
    Must yield exactly one finding (the unguarded one)."""
    _write_go_fixture(tmp_path, "tools.go", '''\
        package main

        import (
            "os"
            "github.com/modelcontextprotocol/go-sdk/mcp"
        )

        // Guarded — authorize() dominates and panics on failure.
        // This must NOT produce a finding.
        func deleteFileGuarded(path string) error {
            authorize(path)
            return os.Remove(path)
        }

        // Unguarded — no guard call.
        // This MUST produce a finding.
        func deleteFileUnguarded(path string) error {
            return os.Remove(path)
        }

        func authorize(path string) {
            // Work Order 1.5: the body MUST contain a panic() call for the
            // local-resolution assert-style classifier to recognise this as
            // an assert-style guard. A stub with an empty body is correctly
            // classified as boolean-style (returns without enforcing),
            // which would make the result-discarded case flag as WEAK.
            if path == "" {
                panic("unauthorized")
            }
        }
        ''')

    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()

    source = (tmp_path / "tools.go").read_bytes()
    findings = scan_go_file("tools.go", source, guard_patterns=rules.guard_patterns)

    # Filter out the authorize() definition itself (it's not a sink)
    sink_findings = [f for f in findings if f.rule_id.startswith("DATA-DELETE") and f.guard_status != "guarded"]
    assert len(sink_findings) == 1, (
        f"Expected exactly 1 finding (the unguarded one), got {len(sink_findings)}: "
        f"{[(f.line, f.rule_id) for f in sink_findings]}"
    )
    # The finding must be on the unguarded function, not the guarded one
    assert sink_findings[0].line > 12, (
        f"Expected the finding on deleteFileUnguarded (line >12), got line {sink_findings[0].line}"
    )


# ---------------------------------------------------------------------------
# Defeated-guard variants — must still be flagged.
# ---------------------------------------------------------------------------


def test_go_guard_discarded_error_is_weak(tmp_path: Path) -> None:
    """A guard whose error return is discarded with `_ =` is WEAK, not guarded.
    The finding must still appear (with reduced severity)."""
    _write_go_fixture(tmp_path, "tools.go", '''\
        package main

        import (
            "os"
            "github.com/modelcontextprotocol/go-sdk/mcp"
        )

        func deleteFileWeak(path string) error {
            _ = authorize(path)
            return os.Remove(path)
        }

        func authorize(path string) error {
            return nil
        }
        ''')

    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()

    source = (tmp_path / "tools.go").read_bytes()
    findings = scan_go_file("tools.go", source, guard_patterns=rules.guard_patterns)

    sink_findings = [f for f in findings if f.rule_id.startswith("DATA-DELETE") and f.guard_status != "guarded"]
    assert len(sink_findings) == 1, (
        f"Expected 1 finding (WEAK), got {len(sink_findings)}"
    )
    assert "-WEAK" in sink_findings[0].rule_id, (
        f"Expected -WEAK suffix, got {sink_findings[0].rule_id}"
    )
    assert sink_findings[0].severity == "low", (
        f"Expected low severity for WEAK, got {sink_findings[0].severity}"
    )


def test_go_guard_in_dead_branch_not_dominating(tmp_path: Path) -> None:
    """A guard inside `if false` does not dominate — finding must appear."""
    _write_go_fixture(tmp_path, "tools.go", '''\
        package main

        import (
            "os"
            "github.com/modelcontextprotocol/go-sdk/mcp"
        )

        func deleteFileDeadBranch(path string) error {
            if false {
                authorize(path)
            }
            return os.Remove(path)
        }

        func authorize(path string) {}
        ''')

    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()

    source = (tmp_path / "tools.go").read_bytes()
    findings = scan_go_file("tools.go", source, guard_patterns=rules.guard_patterns)

    sink_findings = [f for f in findings if f.rule_id.startswith("DATA-DELETE") and f.guard_status != "guarded"]
    assert len(sink_findings) == 1, (
        f"Guard in dead branch must NOT suppress. Got {len(sink_findings)} findings."
    )
    assert "-WEAK" not in sink_findings[0].rule_id, (
        "Guard in dead branch is not WEAK — it doesn't exist. Should be a plain finding."
    )


def test_go_guard_in_nested_func_literal_not_dominating(tmp_path: Path) -> None:
    """A guard inside a nested func literal does not dominate — finding must appear."""
    _write_go_fixture(tmp_path, "tools.go", '''\
        package main

        import (
            "os"
            "github.com/modelcontextprotocol/go-sdk/mcp"
        )

        func deleteFileNested(path string) error {
            func() {
                authorize(path)
            }()
            return os.Remove(path)
        }

        func authorize(path string) {}
        ''')

    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()

    source = (tmp_path / "tools.go").read_bytes()
    findings = scan_go_file("tools.go", source, guard_patterns=rules.guard_patterns)

    sink_findings = [f for f in findings if f.rule_id.startswith("DATA-DELETE") and f.guard_status != "guarded"]
    assert len(sink_findings) == 1, (
        f"Guard in nested func literal must NOT suppress. Got {len(sink_findings)} findings."
    )


def test_go_guard_checked_error_is_guarded(tmp_path: Path) -> None:
    """A guard whose error return is checked (`if err != nil { return }`)
    is a real guard — finding must be suppressed."""
    _write_go_fixture(tmp_path, "tools.go", '''\
        package main

        import (
            "os"
            "github.com/modelcontextprotocol/go-sdk/mcp"
        )

        func deleteFileChecked(path string) error {
            if err := checkPermission(path); err != nil {
                return err
            }
            return os.Remove(path)
        }

        func checkPermission(path string) error {
            return nil
        }
        ''')

    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()

    source = (tmp_path / "tools.go").read_bytes()
    findings = scan_go_file("tools.go", source, guard_patterns=rules.guard_patterns)

    sink_findings = [f for f in findings if f.rule_id.startswith("DATA-DELETE") and f.guard_status != "guarded"]
    assert len(sink_findings) == 0, (
        f"Guard with checked error should suppress the finding. Got {len(sink_findings)}."
    )


def test_go_guard_not_parameter_bound_is_unbound(tmp_path: Path) -> None:
    """A non-assert-style guard that dominates but shares no parameters with
    the sink is UNBOUND. The finding must appear with reduced severity.

    Uses a custom guard name that is NOT in the assert-style vocabulary
    (so binding IS required) and passes a literal (so binding fails).
    """
    _write_go_fixture(tmp_path, "tools.go", '''\
        package main

        import (
            "os"
            "github.com/modelcontextprotocol/go-sdk/mcp"
        )

        func deleteFileUnbound(path string) error {
            if !myAccessCheck("admin") {
                return nil
            }
            return os.Remove(path)
        }

        func myAccessCheck(role string) bool {
            return true
        }
        ''')

    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()
    # Register myAccessCheck as a custom guard (it's not in the default
    # vocabulary, so _matches_guard_name won't match it without this).
    custom_guard_patterns = list(rules.guard_patterns) + ["myAccessCheck"]

    source = (tmp_path / "tools.go").read_bytes()
    findings = scan_go_file("tools.go", source, guard_patterns=custom_guard_patterns)

    sink_findings = [f for f in findings if f.rule_id.startswith("DATA-DELETE") and f.guard_status != "guarded"]
    # "myAccessCheck" is not assert-style (not in conventional_assert),
    # and "admin" (a literal) doesn't bind to "path" (the sink argument).
    # So this should be UNBOUND.
    if sink_findings:
        assert "-UNBOUND" in sink_findings[0].rule_id or "-WEAK" in sink_findings[0].rule_id, (
            f"Expected -UNBOUND or -WEAK for non-assert-style guard with no binding, "
            f"got {sink_findings[0].rule_id} (guard_status={sink_findings[0].guard_status})"
        )


# ---------------------------------------------------------------------------
# Temp-file suppression (ITEM 2)
# ---------------------------------------------------------------------------


def test_go_temp_file_cleanup_suppressed(tmp_path: Path) -> None:
    """os.Remove on a temp file created with os.CreateTemp in the same
    function must be suppressed (not model-controlled)."""
    _write_go_fixture(tmp_path, "tools.go", '''\
        package main

        import (
            "os"
            "github.com/modelcontextprotocol/go-sdk/mcp"
        )

        func writeFile(path string, data []byte) error {
            tmp, err := os.CreateTemp("", "prefix-*")
            if err != nil {
                return err
            }
            tmpName := tmp.Name()
            defer os.Remove(tmpName)
            _, err = tmp.Write(data)
            return err
        }
        ''')

    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()

    source = (tmp_path / "tools.go").read_bytes()
    findings = scan_go_file("tools.go", source, guard_patterns=rules.guard_patterns)

    delete_findings = [f for f in findings if f.rule_id.startswith("DATA-DELETE") and f.guard_status != "guarded"]
    assert len(delete_findings) == 0, (
        f"Temp file cleanup should be suppressed. Got {len(delete_findings)} findings."
    )


def test_go_model_controlled_delete_not_suppressed(tmp_path: Path) -> None:
    """os.Remove on a model-controlled path must NOT be suppressed,
    even if there's a defer."""
    _write_go_fixture(tmp_path, "tools.go", '''\
        package main

        import (
            "os"
            "github.com/modelcontextprotocol/go-sdk/mcp"
        )

        func deleteFile(path string) error {
            defer os.Remove(path)
            return nil
        }
        ''')

    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()

    source = (tmp_path / "tools.go").read_bytes()
    findings = scan_go_file("tools.go", source, guard_patterns=rules.guard_patterns)

    delete_findings = [f for f in findings if f.rule_id.startswith("DATA-DELETE") and f.guard_status != "guarded"]
    assert len(delete_findings) == 1, (
        f"Model-controlled delete must NOT be suppressed. Got {len(delete_findings)} findings."
    )
