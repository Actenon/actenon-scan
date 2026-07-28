"""Capability model — enumerates all consequential capabilities, not just findings.

Work Order 2, Phase 2: the scanner currently discards guarded sinks and
only emits findings for unguarded ones. The capability model records
every consequential sink with its guard state, so a repository can see
what its agent can do — and be told when a change grants it a new power.

States (observational, never asserting safety):
  GUARD_FOUND        a recognised guard dominates the analysed path
  REVIEW_REQUIRED    no recognised guard found on the analysed path
  ACCEPTED_DECISION  a human adjudicated this (future, not implemented)
  NOT_ANALYSED       coverage gap, parse failure, unsupported construct

No state name asserts safety, correctness, or absence of vulnerability.
"Guard found" is the same information as "guarded" but carries no claim.
The scanner establishes that a recognised guard dominates the path, not
that the guard is correct.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


CapabilityState = Literal["GUARD_FOUND", "REVIEW_REQUIRED", "ACCEPTED_DECISION", "NOT_ANALYSED"]


@dataclass
class Capability:
    """A consequential capability of an agent in a repository.

    Unlike a Finding (which is only emitted when review is required),
    a Capability records every consequential sink with its guard state.

    Attributes:
        file: Source file path (relative to scan target).
        line: 1-indexed line number of the sink call.
        col: 1-indexed column of the sink call.
        rule_id: The sink rule that matched (e.g. EXEC-SHELL).
        category: Consequence category (e.g. shell_execution).
        severity: The sink's base severity (high/medium/low).
        call_text: The source text of the sink call.
        state: The capability state (GUARD_FOUND / REVIEW_REQUIRED / etc.).
        guard_status: Raw guard analysis result ("guarded"/"weak"/"unbound"/"").
        guard_message: Human-readable guard analysis explanation.
        confidence: Reachability confidence (high/medium/none).
        reachability_reason: Why this is reachable (e.g. "tool_decorator").
        reachability_source: "handler" (registered tool handler) or
            "import" (file imports a framework) — distinguishes the two
            reachability paths so issue #81 can be resolved later.
        tier: "production" or "example".
        language: "python", "typescript", or "go".
        snippet_hash: Content hash for stable identity.
    """
    file: str
    line: int
    col: int
    rule_id: str
    category: str
    severity: str
    call_text: str
    state: CapabilityState
    guard_status: str = ""
    guard_message: str = ""
    confidence: str = "high"
    reachability_reason: str = ""
    reachability_source: str = ""  # "handler" or "import"
    tier: str = "production"
    language: str = "python"
    snippet_hash: str = ""


@dataclass
class CapabilitySummary:
    """Aggregated counts of capabilities by state."""
    total: int = 0
    guard_found: int = 0
    review_required: int = 0
    accepted_decision: int = 0
    not_analysed: int = 0

    def add(self, cap: Capability) -> None:
        self.total += 1
        if cap.state == "GUARD_FOUND":
            self.guard_found += 1
        elif cap.state == "REVIEW_REQUIRED":
            self.review_required += 1
        elif cap.state == "ACCEPTED_DECISION":
            self.accepted_decision += 1
        elif cap.state == "NOT_ANALYSED":
            self.not_analysed += 1


def guard_status_to_capability_state(
    guard_status: str,
    is_reachable: bool,
) -> CapabilityState:
    """Map the detector's guard_status to a capability state.

    - guard_status="guarded" → GUARD_FOUND
    - guard_status="weak" → REVIEW_REQUIRED (guard exists but is imperfect)
    - guard_status="unbound" → REVIEW_REQUIRED (guard exists but is not bound)
    - guard_status="" (no guard) → REVIEW_REQUIRED
    - not reachable → NOT_ANALYSED (shouldn't normally appear — the detector
      filters non-reachable sinks before this point, but defensive)
    """
    if not is_reachable:
        return "NOT_ANALYSED"
    if guard_status == "guarded":
        return "GUARD_FOUND"
    # weak, unbound, and no-guard all require review
    return "REVIEW_REQUIRED"
