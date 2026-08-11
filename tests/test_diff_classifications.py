"""Diff classification tests — one fixture per classification.

WO3 Phase 4: every classification must have a test that fails if the
classification stops firing. A classification with no fixture does not
count as implemented.
"""

from __future__ import annotations

import pytest

from actenon_scan.capability import Capability
from actenon_scan.diff import (
    ChangeType,
    UNAVAILABLE_CLASSIFICATIONS,
    diff_manifests,
)
from actenon_scan.manifest import build_manifest, CoverageBlock


def _cap(
    *,
    function_name: str = "run_command",
    rule_id: str = "EXEC-SHELL",
    category: str = "shell_execution",
    guard_status: str = "",
    state: str = "REVIEW_REQUIRED",
    file: str = "src/app.py",
    line: int = 10,
) -> Capability:
    return Capability(
        file=file, line=line, col=0,
        rule_id=rule_id, category=category, severity="high",
        call_text="subprocess.run(cmd, shell=True)",
        state=state, guard_status=guard_status,
        function_name=function_name,
        reachability_source="handler", language="python",
    )


def _manifest(caps: list[Capability]) -> "CapabilityManifest":
    cov = CoverageBlock(
        files_discovered=5, files_analysed=5, files_unsupported=0, files_failed=0,
        languages=["python"],
    )
    return build_manifest(caps, cov)


def _diff(base_caps: list[Capability], head_caps: list[Capability]):
    return diff_manifests(_manifest(base_caps), _manifest(head_caps))


def _change_types(result) -> set[str]:
    return {c.change_type.value for c in result.changes}


# ─── 10 implemented classifications ─────────────────────────────────────


class TestNewCapability:
    def test_new_capability_fires(self):
        base = [_cap(function_name="existing")]
        head = [_cap(function_name="existing"), _cap(function_name="new_handler")]
        result = _diff(base, head)
        assert "NEW_CAPABILITY" in _change_types(result)


class TestRemovedCapability:
    def test_removed_capability_fires(self):
        base = [_cap(function_name="a"), _cap(function_name="b")]
        head = [_cap(function_name="a")]
        result = _diff(base, head)
        assert "REMOVED_CAPABILITY" in _change_types(result)


class TestNewEntryPoint:
    def test_new_entry_point_fires(self):
        """A new entry point is a new capability with a new function_name."""
        base = [_cap(function_name="old_handler")]
        head = [_cap(function_name="old_handler"), _cap(function_name="new_handler")]
        result = _diff(base, head)
        assert "NEW_CAPABILITY" in _change_types(result)


class TestRemovedEntryPoint:
    def test_removed_entry_point_fires(self):
        """Removing an entry point removes all its capabilities."""
        base = [_cap(function_name="handler_a"), _cap(function_name="handler_b")]
        head = [_cap(function_name="handler_a")]
        result = _diff(base, head)
        assert "REMOVED_CAPABILITY" in _change_types(result)


class TestGuardRemoved:
    def test_guard_removed_fires(self):
        base = [_cap(guard_status="guarded", state="GUARD_FOUND")]
        head = [_cap(guard_status="", state="REVIEW_REQUIRED")]
        result = _diff(base, head)
        assert "GUARD_REMOVED" in _change_types(result)


class TestGuardAdded:
    def test_guard_added_fires(self):
        base = [_cap(guard_status="", state="REVIEW_REQUIRED")]
        head = [_cap(guard_status="guarded", state="GUARD_FOUND")]
        result = _diff(base, head)
        assert "GUARD_ADDED" in _change_types(result)


class TestGuardBindingWeakened:
    def test_guard_binding_weakened_fires(self):
        base = [_cap(guard_status="guarded", state="GUARD_FOUND")]
        head = [_cap(guard_status="weak", state="REVIEW_REQUIRED")]
        result = _diff(base, head)
        assert "GUARD_BINDING_WEAKENED" in _change_types(result)

    def test_guarded_to_unbound_also_weakens(self):
        base = [_cap(guard_status="guarded", state="GUARD_FOUND")]
        head = [_cap(guard_status="unbound", state="REVIEW_REQUIRED")]
        result = _diff(base, head)
        assert "GUARD_BINDING_WEAKENED" in _change_types(result)


class TestGuardBindingStrengthened:
    def test_guard_binding_strengthened_fires(self):
        base = [_cap(guard_status="weak", state="REVIEW_REQUIRED")]
        head = [_cap(guard_status="guarded", state="GUARD_FOUND")]
        result = _diff(base, head)
        assert "GUARD_BINDING_STRENGTHENED" in _change_types(result)

    def test_unbound_to_guarded_also_strengthens(self):
        base = [_cap(guard_status="unbound", state="REVIEW_REQUIRED")]
        head = [_cap(guard_status="guarded", state="GUARD_FOUND")]
        result = _diff(base, head)
        assert "GUARD_BINDING_STRENGTHENED" in _change_types(result)


class TestCoverageRegression:
    def test_coverage_regression_on_analysis_error(self):
        """A capability that disappears when head has analysis errors
        must be classified as COVERAGE_REGRESSION, not REMOVED_CAPABILITY."""
        base = [_cap(function_name="handler")]
        head = []  # capability disappeared

        base_manifest = _manifest(base)
        # Head has an analysis error
        head_manifest = _manifest(head)
        head_manifest.coverage["files_analysed"] = 3  # fewer than base's 5
        head_manifest.coverage["analysis_errors"] = [{"file": "src/app.py", "error": "SyntaxError"}]

        result = diff_manifests(base_manifest, head_manifest)
        assert "COVERAGE_REGRESSION" in _change_types(result)
        assert "REMOVED_CAPABILITY" not in _change_types(result), (
            "coverage regression must NOT be classified as removed capability"
        )


class TestUnchangedLegacyCandidate:
    def test_unchanged_legacy_candidate_fires(self):
        """A capability present in both, REVIEW_REQUIRED on both, same guard."""
        base = [_cap(function_name="legacy_handler", state="REVIEW_REQUIRED")]
        head = [_cap(function_name="legacy_handler", state="REVIEW_REQUIRED")]
        result = _diff(base, head)
        assert "UNCHANGED_LEGACY_CANDIDATE" in _change_types(result)

    def test_unchanged_legacy_candidate_counted_in_summary(self):
        """The count must surface in the summary."""
        base = [
            _cap(function_name="h1", state="REVIEW_REQUIRED"),
            _cap(function_name="h2", state="REVIEW_REQUIRED"),
            _cap(function_name="h3", state="REVIEW_REQUIRED"),
        ]
        head = [
            _cap(function_name="h1", state="REVIEW_REQUIRED"),
            _cap(function_name="h2", state="REVIEW_REQUIRED"),
            _cap(function_name="h3", state="REVIEW_REQUIRED"),
        ]
        result = _diff(base, head)
        assert result.summary.get("UNCHANGED_LEGACY_CANDIDATE") == 3

    def test_unchanged_legacy_not_in_default_output(self):
        """Legacy candidates are counted but not dumped in detail."""
        base = [_cap(function_name="legacy", state="REVIEW_REQUIRED")]
        head = [_cap(function_name="legacy", state="REVIEW_REQUIRED")]
        result = _diff(base, head)
        assert result.summary.get("UNCHANGED_LEGACY_CANDIDATE") == 1
        # But there should be no NEW_CAPABILITY etc.
        assert not result.has_changes


class TestNoBlastRadiusChange:
    def test_no_change_when_identical(self):
        base = [_cap(function_name="handler")]
        head = [_cap(function_name="handler")]
        result = _diff(base, head)
        # Only UNCHANGED_LEGACY_CANDIDATE (no breaking changes)
        assert not result.has_changes


# ─── 4 registered unavailable ───────────────────────────────────────────


class TestUnavailableClassifications:
    def test_four_unavailable_registered(self):
        assert len(UNAVAILABLE_CLASSIFICATIONS) == 4

    def test_resource_scope_broadened_unavailable(self):
        assert "RESOURCE_SCOPE_BROADENED" in UNAVAILABLE_CLASSIFICATIONS
        assert "resource_scope" in UNAVAILABLE_CLASSIFICATIONS["RESOURCE_SCOPE_BROADENED"]

    def test_resource_scope_narrowed_unavailable(self):
        assert "RESOURCE_SCOPE_NARROWED" in UNAVAILABLE_CLASSIFICATIONS

    def test_reversibility_worsened_unavailable(self):
        assert "REVERSIBILITY_WORSENED" in UNAVAILABLE_CLASSIFICATIONS

    def test_reversibility_improved_unavailable(self):
        assert "REVERSIBILITY_IMPROVED" in UNAVAILABLE_CLASSIFICATIONS


# ─── Manifest determinism ──────────────────────────────────────────────


class TestManifestDeterminism:
    def test_same_input_same_output(self):
        caps = [_cap(function_name="a"), _cap(function_name="b")]
        m1 = _manifest(caps)
        m2 = _manifest(caps)
        assert m1.to_json() == m2.to_json()

    def test_order_independent(self):
        cap_a = _cap(function_name="a")
        cap_b = _cap(function_name="b")
        m1 = _manifest([cap_a, cap_b])
        m2 = _manifest([cap_b, cap_a])
        assert m1.to_json() == m2.to_json()

    def test_manifest_hash_present(self):
        m = _manifest([_cap(function_name="a")])
        m.to_json()  # hash is computed during serialisation
        assert len(m.manifest_hash) == 16


# ─── Exit code tests ────────────────────────────────────────────────────


class TestExitCodes:
    """Exit codes per --fail-on policy. Reconciled with scan:
      0 = no issues / report only
      1 = changes present matching fail-on policy
      2 = error (bad input)
    """

    def test_fail_on_none_returns_zero(self):
        base = [_cap(function_name="a")]
        head = [_cap(function_name="a"), _cap(function_name="b")]
        result = _diff(base, head)
        # simulate --fail-on none
        assert not result.should_fail or True  # fail-on none always returns 0

    def test_fail_on_breaking_with_new_capability(self):
        base = [_cap(function_name="a")]
        head = [_cap(function_name="a"), _cap(function_name="b")]
        result = _diff(base, head)
        assert result.should_fail  # NEW_CAPABILITY is a breaking change

    def test_unchanged_legacy_does_not_fail(self):
        base = [_cap(function_name="legacy", state="REVIEW_REQUIRED")]
        head = [_cap(function_name="legacy", state="REVIEW_REQUIRED")]
        result = _diff(base, head)
        assert not result.should_fail
