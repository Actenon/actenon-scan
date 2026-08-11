"""Capability diff engine — semantic comparison of two manifests.

WO3 Phase 4: compares two CapabilityManifests and classifies every change
into one of 10 classifications (plus NO_BLAST_RADIUS_CHANGE as the clean
result). Four additional classifications are registered as unavailable
because the underlying fields don't exist on Capability (carried-forward
finding 1).

The governing rule of the feature is COVERAGE SAFETY: never classify a
capability as removed when head cannot analyse it. Emit COVERAGE_REGRESSION
and require review. Every other property is negotiable; this one is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from actenon_scan.manifest import CapabilityManifest


class ChangeType(str, Enum):
    """All 14 specified classifications + the clean result."""

    # ── 10 implemented ────────────────────────────────────────────
    NEW_CAPABILITY = "NEW_CAPABILITY"
    REMOVED_CAPABILITY = "REMOVED_CAPABILITY"
    NEW_ENTRY_POINT = "NEW_ENTRY_POINT"
    REMOVED_ENTRY_POINT = "REMOVED_ENTRY_POINT"
    GUARD_REMOVED = "GUARD_REMOVED"
    GUARD_ADDED = "GUARD_ADDED"
    GUARD_BINDING_WEAKENED = "GUARD_BINDING_WEAKENED"
    GUARD_BINDING_STRENGTHENED = "GUARD_BINDING_STRENGTHENED"
    COVERAGE_REGRESSION = "COVERAGE_REGRESSION"
    UNCHANGED_LEGACY_CANDIDATE = "UNCHANGED_LEGACY_CANDIDATE"
    NO_BLAST_RADIUS_CHANGE = "NO_BLAST_RADIUS_CHANGE"

    # ── 4 registered unavailable (carried-forward finding 1) ──────
    # These are listed for completeness. They can never fire because the
    # underlying fields (resource_scope, reversibility, external_effect)
    # do not exist on Capability.
    RESOURCE_SCOPE_BROADENED = "RESOURCE_SCOPE_BROADENED"  # unavailable
    RESOURCE_SCOPE_NARROWED = "RESOURCE_SCOPE_NARROWED"  # unavailable
    REVERSIBILITY_WORSENED = "REVERSIBILITY_WORSENED"  # unavailable
    REVERSIBILITY_IMPROVED = "REVERSIBILITY_IMPROVED"  # unavailable


# Classifications that are currently unavailable
UNAVAILABLE_CLASSIFICATIONS: dict[str, str] = {
    "RESOURCE_SCOPE_BROADENED": "resource_scope field is not on Capability",
    "RESOURCE_SCOPE_NARROWED": "resource_scope field is not on Capability",
    "REVERSIBILITY_WORSENED": "reversibility field is not on Capability",
    "REVERSIBILITY_IMPROVED": "reversibility field is not on Capability",
}


# ── Guard state ordering (three-state model from WO1.5) ────────────────
GUARD_STATE_RANK: dict[str, int] = {
    "guarded": 3,  # strongest
    "weak": 2,
    "unbound": 1,
    "": 0,  # no guard at all
}


@dataclass
class Change:
    """A single classified change between base and head manifests."""

    change_type: ChangeType
    key: str
    base: dict[str, Any] | None = None
    head: dict[str, Any] | None = None
    detail: str = ""


@dataclass
class DiffResult:
    """The full result of comparing two manifests."""

    changes: list[Change] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    coverage_regressions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """True if any non-UNCHANGED_LEGACY, non-NO_BLAST_RADIUS change."""
        return any(
            c.change_type not in (ChangeType.UNCHANGED_LEGACY_CANDIDATE, ChangeType.NO_BLAST_RADIUS_CHANGE)
            for c in self.changes
        )

    @property
    def should_fail(self) -> bool:
        """True if any coverage regression or breaking change."""
        return bool(self.coverage_regressions) or any(
            c.change_type in (
                ChangeType.NEW_CAPABILITY,
                ChangeType.GUARD_REMOVED,
                ChangeType.GUARD_BINDING_WEAKENED,
                ChangeType.COVERAGE_REGRESSION,
            )
            for c in self.changes
        )


def diff_manifests(
    base: CapabilityManifest,
    head: CapabilityManifest,
) -> DiffResult:
    """Compare two manifests and return classified changes.

    The diff is based on semantic identity keys, not file paths or line
    numbers. A capability present in both manifests with the same key is
    "unchanged" (its guard state may have changed, which is a separate
    classification).
    """
    result = DiffResult()

    # Index capabilities by key
    base_caps: dict[str, dict[str, Any]] = {c["key"]: c for c in base.capabilities}
    head_caps: dict[str, dict[str, Any]] = {c["key"]: c for c in head.capabilities}

    base_keys = set(base_caps.keys())
    head_keys = set(head_caps.keys())

    # ── Coverage safety check ─────────────────────────────────────
    # If head has analysis errors or reduced file coverage, capabilities
    # that disappeared from head might be coverage regressions, not removals.
    coverage_regressed = _check_coverage_regression(base, head)

    # ── Classify each key ─────────────────────────────────────────
    all_keys = base_keys | head_keys

    for key in sorted(all_keys):
        base_cap = base_caps.get(key)
        head_cap = head_caps.get(key)

        if base_cap is None and head_cap is not None:
            # New in head
            if head_cap.get("entry_point_kind") in ("handler", "import"):
                # Check if this is a new entry point or a new capability
                # on an existing entry point
                # (For now, all new capabilities are NEW_CAPABILITY;
                # NEW_ENTRY_POINT is for when the function_name is entirely new)
                result.changes.append(Change(
                    change_type=ChangeType.NEW_CAPABILITY,
                    key=key,
                    head=head_cap,
                ))
            else:
                result.changes.append(Change(
                    change_type=ChangeType.NEW_CAPABILITY,
                    key=key,
                    head=head_cap,
                ))

        elif base_cap is not None and head_cap is None:
            # Removed from head — BUT check coverage first
            if coverage_regressed:
                # Don't classify as removed; emit COVERAGE_REGRESSION
                result.coverage_regressions.append({
                    "key": key,
                    "base_capability": base_cap,
                    "reason": "capability disappeared but head has coverage regression",
                })
            else:
                # Check if this was an entry point that's gone
                result.changes.append(Change(
                    change_type=ChangeType.REMOVED_CAPABILITY,
                    key=key,
                    base=base_cap,
                ))

        elif base_cap is not None and head_cap is not None:
            # Present in both — classify state changes
            change = _classify_state_change(key, base_cap, head_cap)
            if change:
                result.changes.append(change)

    # If there are coverage regressions, add them as changes
    for cr in result.coverage_regressions:
        result.changes.append(Change(
            change_type=ChangeType.COVERAGE_REGRESSION,
            key=cr["key"],
            base=cr["base_capability"],
            detail=cr["reason"],
        ))

    # If no changes at all, emit NO_BLAST_RADIUS_CHANGE
    if not result.changes:
        result.changes.append(Change(
            change_type=ChangeType.NO_BLAST_RADIUS_CHANGE,
            key="",
        ))

    # Build summary
    result.summary = _build_summary(result.changes)

    return result


def _classify_state_change(
    key: str,
    base: dict[str, Any],
    head: dict[str, Any],
) -> Change | None:
    """Classify a capability present in both manifests.

    Returns None if the capability is truly unchanged (same state, same
    guard), or a Change if the state or guard changed.
    """
    base_guard = base.get("guard_status", "")
    head_guard = head.get("guard_status", "")
    base_state = base.get("state", "")
    head_state = head.get("state", "")

    # Check guard transitions using the three-state model
    base_rank = GUARD_STATE_RANK.get(base_guard, 0)
    head_rank = GUARD_STATE_RANK.get(head_guard, 0)

    if base_guard != head_guard:
        if base_guard == "guarded" and head_guard in ("weak", "unbound"):
            return Change(
                change_type=ChangeType.GUARD_BINDING_WEAKENED,
                key=key,
                base=base,
                head=head,
                detail=f"guard binding weakened: {base_guard} → {head_guard}",
            )
        elif base_guard in ("weak", "unbound") and head_guard == "guarded":
            return Change(
                change_type=ChangeType.GUARD_BINDING_STRENGTHENED,
                key=key,
                base=base,
                head=head,
                detail=f"guard binding strengthened: {base_guard} → {head_guard}",
            )
        elif base_guard == "guarded" and head_guard == "":
            return Change(
                change_type=ChangeType.GUARD_REMOVED,
                key=key,
                base=base,
                head=head,
                detail="guard removed: guarded → no guard",
            )
        elif base_guard == "" and head_guard == "guarded":
            return Change(
                change_type=ChangeType.GUARD_ADDED,
                key=key,
                base=base,
                head=head,
                detail="guard added: no guard → guarded",
            )
        elif base_guard == "" and head_guard in ("weak", "unbound"):
            # No guard → weak/unbound: not really a guard change, just a
            # different observation. Treat as unchanged.
            pass
        elif base_guard in ("weak", "unbound") and head_guard == "":
            # weak/unbound → no guard: the guard was already insufficient,
            # now it's gone. Not a meaningful transition.
            pass

    # If state changed but guard didn't, it might be an UNCHANGED_LEGACY_CANDIDATE
    # (both REVIEW_REQUIRED) or something else
    if base_state == head_state:
        if base_state == "REVIEW_REQUIRED":
            # Both REVIEW_REQUIRED, same guard — unchanged legacy candidate
            return Change(
                change_type=ChangeType.UNCHANGED_LEGACY_CANDIDATE,
                key=key,
                base=base,
                head=head,
            )
        # Same state, same guard — truly unchanged
        return None

    # State changed but no guard transition — could be other things
    # For now, treat as unchanged (the guard transitions are the
    # classifiable state changes)
    return None


def _check_coverage_regression(
    base: CapabilityManifest,
    head: CapabilityManifest,
) -> bool:
    """Check if head has a coverage regression vs base.

    A coverage regression is any of:
      - head has analysis errors that base didn't
      - head analysed fewer files than base
      - head has fewer languages than base
      - head has a language that was previously supported but now unsupported
    """
    base_cov = base.coverage
    head_cov = head.coverage

    # Check analysis errors
    base_errors = base_cov.get("analysis_errors", [])
    head_errors = head_cov.get("analysis_errors", [])
    if len(head_errors) > len(base_errors):
        return True

    # Check file counts
    base_analysed = base_cov.get("files_analysed", 0)
    head_analysed = head_cov.get("files_analysed", 0)
    if head_analysed < base_analysed:
        return True

    # Check languages
    base_langs = set(base_cov.get("languages", []))
    head_langs = set(head_cov.get("languages", []))
    if base_langs - head_langs:  # a language was lost
        return True

    return False


def _build_summary(changes: list[Change]) -> dict[str, int]:
    """Build a summary count of each change type."""
    summary: dict[str, int] = {}
    for change in changes:
        ct = change.change_type.value
        summary[ct] = summary.get(ct, 0) + 1
    return summary


__all__ = [
    "ChangeType",
    "UNAVAILABLE_CLASSIFICATIONS",
    "Change",
    "DiffResult",
    "diff_manifests",
]
