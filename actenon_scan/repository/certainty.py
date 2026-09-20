"""Explicit analysis-certainty levels.

Every analysis claim in this package is annotated with one of these
levels. The rule is strict:

- :data:`PROVEN` requires evidence sufficient to make the claim.
  Reachability PROVEN = the call path is fully RESOLVED with no
  heuristic edges.
- :data:`STRONG` is reserved for claims with strong evidence but a
  single weak link.
- :data:`HEURISTIC` means the claim rests on a name-pattern or
  single-candidate match.
- :data:`UNKNOWN` means we have no evidence — and the claim is NOT
  promoted to a stronger level.
- :data:`UNSUPPORTED` means the feature isn't implemented for this
  language/case (e.g. CFG for TS).
- :data:`ANALYSIS_ERROR` means we tried to analyse but failed. Distinct
  from UNKNOWN (we don't know) and UNSUPPORTED (we don't do this).

Nothing labelled ``unknown`` is ever silently treated as ``safe``.
"""

from __future__ import annotations

from enum import Enum


class AnalysisCertainty(str, Enum):
    PROVEN = "proven"
    STRONG = "strong"
    HEURISTIC = "heuristic"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    ANALYSIS_ERROR = "analysis_error"


# Ordering from weakest to strongest. Used by :func:`combine_certainty`
# to take the *weakest* link in a chain.
CERTAINTY_ORDER: dict[AnalysisCertainty, int] = {
    AnalysisCertainty.ANALYSIS_ERROR: -1,  # errors dominate (lowest)
    AnalysisCertainty.UNSUPPORTED: 0,
    AnalysisCertainty.UNKNOWN: 1,
    AnalysisCertainty.HEURISTIC: 2,
    AnalysisCertainty.STRONG: 3,
    AnalysisCertainty.PROVEN: 4,
}


def combine_certainty(*levels: AnalysisCertainty) -> AnalysisCertainty:
    """Return the *weakest* of the input certainties.

    A chain is only as strong as its weakest link. ``ANALYSIS_ERROR``
    dominates (returns ANALYSIS_ERROR) because an error in the chain
    means we cannot trust the conclusion.
    """
    if not levels:
        return AnalysisCertainty.UNKNOWN
    # ANALYSIS_ERROR dominates — it's distinct from UNKNOWN (we don't
    # know) because the analysis itself failed.
    if any(l == AnalysisCertainty.ANALYSIS_ERROR for l in levels):
        return AnalysisCertainty.ANALYSIS_ERROR
    # Otherwise, take the weakest (lowest order).
    return min(levels, key=lambda l: CERTAINTY_ORDER[l])
