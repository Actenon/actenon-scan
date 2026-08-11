"""Capability semantic identity — stable keys for diff and manifest.

WO3: the identity key is what makes a capability the "same" capability
across two scans. It is based on what the agent can do (function name +
sink family), not where the code lives (file path, line number).

Key fields (see docs/IDENTITY_DESIGN.md for the full rationale):
  - language
  - entry_point_kind (handler / import / module)
  - function_name (bare name)
  - sink_family (rule_id)
  - resource_type (category)

Guard state is NOT part of the key — it's comparable state. A capability
moving from GUARD_FOUND → REVIEW_REQUIRED reads as a state change, not a
swap.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from actenon_scan.capability import Capability


@dataclass(frozen=True)
class CapabilityKey:
    """Stable identity key for a capability.

    Two capabilities with the same key are the "same" capability,
    regardless of file path, line number, or guard state.
    """

    language: str
    entry_point_kind: str
    function_name: str
    sink_family: str
    resource_type: str

    def __str__(self) -> str:
        return (
            f"{self.language}:{self.entry_point_kind}:"
            f"{self.function_name}:{self.sink_family}:{self.resource_type}"
        )


def capability_to_key(cap: Capability) -> CapabilityKey:
    """Derive a stable identity key from a Capability.

    The key is deliberately independent of:
      - file path (evidence, not identity — see IDENTITY_DESIGN.md)
      - line number (changes on any edit)
      - guard state (comparable state, not identity)
      - call text (changes on parameter rename)
      - snippet hash (changes on whitespace)

    This means a function moved between files, or a guard added/removed,
    produces the same key — the diff engine can then classify the state
    change rather than reporting a spurious removal+addition.
    """
    # entry_point_kind: normalise reachability_source to handler/import/module
    kind = cap.reachability_source or "module"
    if kind not in ("handler", "import", "module"):
        kind = "module"  # unknown → module-level

    return CapabilityKey(
        language=cap.language,
        entry_point_kind=kind,
        function_name=cap.function_name or "<module>",
        sink_family=cap.rule_id.split("-")[0] if cap.rule_id else "",
        resource_type=cap.category,
    )


def capabilities_by_key(
    capabilities: list[Capability],
) -> dict[CapabilityKey, list[Capability]]:
    """Group capabilities by their identity key.

    Returns a dict mapping each key to the list of capabilities that share
    it. Most keys will have exactly one capability. Keys with multiple
    capabilities indicate name collisions (documented limitation — see
    IDENTITY_DESIGN.md).
    """
    result: dict[CapabilityKey, list[Capability]] = {}
    for cap in capabilities:
        key = capability_to_key(cap)
        result.setdefault(key, []).append(cap)
    return result


__all__ = [
    "CapabilityKey",
    "capability_to_key",
    "capabilities_by_key",
]
