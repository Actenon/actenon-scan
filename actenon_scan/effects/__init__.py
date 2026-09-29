"""AREF-002 M0: the effect-claim data model.

This package is the foundational data model of AREF-002
(``specs/AREF-002/``): ``EffectClaim``, ``EvidencePacket``, ``EffectReceipt``,
``CoverageLedger``, and the closed proof-state and verdict vocabularies.

It is deliberately inert. It performs no evidence acquisition and no
dependency descent, knows no SDK, reads no sink rule, and is imported by no
existing module, so introducing it changes no finding, severity or authority
decision. Sink-rule matches can appear here only as evidence packets.
"""

from __future__ import annotations

from actenon_scan.effects._codec import EffectModelError
from actenon_scan.effects.claim import (
    ABSENT,
    Acquisition,
    ArgumentShape,
    Authority,
    Closure,
    Condition,
    Contradiction,
    Control,
    Descriptors,
    EffectClaim,
    FrontierEntry,
    Genesis,
    ImplementationCandidate,
    Invocation,
    ObligationStates,
    Priority,
    Target,
    TargetCoordinate,
    aggregate_claim_states,
    aggregate_obligation,
)
from actenon_scan.effects.evidence import (
    AcquisitionCost,
    EvidenceAssertion,
    EvidencePacket,
    ProbeOutcome,
    SourceLocator,
    VerbatimExtract,
)
from actenon_scan.effects.ledger import (
    AnalysisErrorCounts,
    Budgets,
    CapabilityCounts,
    ClaimCounts,
    ContradictionCounts,
    CounterEvidenceCounts,
    CoverageLedger,
    EvidenceCounts,
    FrontierCounts,
    Interpretation,
    InvocationCounts,
    PerformanceCounts,
)
from actenon_scan.effects.receipt import (
    Answers,
    ContradictionsAnswer,
    EffectAnswer,
    EffectReceipt,
    ImplementationAnswer,
    ObligationAnswer,
    RenderingConstraints,
    UnknownsAnswer,
)
from actenon_scan.effects.vocabulary import (
    BLOCKING_PROBE_IDS,
    NECESSARY_OBLIGATIONS,
    PROBE_REGISTRY,
    RULE_MATCH_ADMISSIBILITY,
    SCHEMA_VERSION,
    TIER_CAN_SETTLE,
    Admissibility,
    AssertionPredicate,
    BudgetName,
    CandidateKind,
    ConditionKind,
    ContradictionResolution,
    EffectClass,
    InertnessBlocker,
    LadderTier,
    Language,
    Obligation,
    PacketKind,
    Polarity,
    ProbeClass,
    ProbeResult,
    ProbeSpec,
    ProofState,
    RuleMatchType,
    SelectionState,
    StopReason,
    Strength,
    TargetScope,
    Verdict,
    VersionResolution,
)

from types import ModuleType as _ModuleType

__all__ = sorted(
    name for name, value in globals().items()
    if not name.startswith("_") and name != "annotations" and not isinstance(value, _ModuleType)
)
