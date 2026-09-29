"""CoverageLedger: the first-class account of what the claim layer did and did not do.

Frozen by ``specs/AREF-002/coverage_ledger.schema.json`` and AREF-002.md
section 10. The ledger exists so that "0 PROVEN_EFFECT" can never be rendered
as "safe". It keeps five populations apart that a naive summary would merge:
proven effects, established absences (NO_EFFECT), unresolved claims (ABSTAIN),
analysis failures (ANALYSIS_ERROR) and claims that were never investigated.
Only NO_EFFECT is ever a negative result.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from actenon_scan.effects import _codec as c
from actenon_scan.effects.claim import EffectClaim
from actenon_scan.effects.vocabulary import (
    FRONTIER_REASONS,
    NECESSARY_OBLIGATIONS,
    PROBE_REGISTRY,
    SCHEMA_VERSION,
    Admissibility,
    BudgetName,
    ContradictionResolution,
    EffectClass,
    LadderTier,
    Language,
    Obligation,
    ProbeClass,
    ProbeResult,
    ProofState,
    StopReason,
    Verdict,
)


def _key(cls):
    return lambda value, where: c.enum_value(cls, value, where)


def _evidence_tier_key(value, where):
    tier = c.enum_value(LadderTier, value, where)
    if tier is LadderTier.L8:
        raise c.fail(where, "L8 is not an evidence tier")
    return tier


def _probe_key(value, where):
    if value not in PROBE_REGISTRY:
        raise c.fail(where, f"{value!r} is not a registered probe")
    return value


def _free_key(value, where):
    return c.text(value, where)


def _counts(value, where, key_check):
    return c.frozen_counts(value, where, key_check)


def _optional_counts(value, where, key_check):
    return None if value is None else _counts(value, where, key_check)


def _total(counts: Mapping | None) -> int:
    return 0 if counts is None else sum(counts.values())


def _check_partition(counts: Mapping | None, total: int, where: str) -> None:
    if counts is not None and _total(counts) != total:
        raise c.fail(where, f"breakdown sums to {_total(counts)}, not {total}")


def _check_within(counts: Mapping | None, total: int, where: str) -> None:
    if counts is not None and _total(counts) > total:
        raise c.fail(where, f"breakdown sums to {_total(counts)}, more than {total}")


def _emit(out: dict, key: str, counts: Mapping | None, order=None) -> None:
    if counts is not None:
        out[key] = c.counts_to_dict(counts, order)


@dataclass(frozen=True)
class Budgets:
    """Budget configuration. The defaults are AREF-002's frozen defaults."""

    max_ladder_tier: LadderTier = LadderTier.L7
    max_dependency_hops: int = 6
    max_files_opened: int = 4000
    max_bytes_read: int = 268435456
    max_wall_ms_per_claim: int = 2000
    max_claims_investigated: int = 5000
    max_implementation_candidates: int = 8

    _INTS = ("max_dependency_hops", "max_files_opened", "max_bytes_read", "max_wall_ms_per_claim",
             "max_claims_investigated", "max_implementation_candidates")

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_ladder_tier", _evidence_tier_key(self.max_ladder_tier, "budgets.max_ladder_tier"))
        for name in self._INTS:
            c.integer(getattr(self, name), f"budgets.{name}", 1 if name == "max_implementation_candidates" else 0)

    def to_dict(self) -> dict:
        return {"max_ladder_tier": self.max_ladder_tier.value, **{n: getattr(self, n) for n in self._INTS}}

    @classmethod
    def from_dict(cls, data: Any, where: str = "budgets") -> "Budgets":
        r = c.Reader(data, where, ("max_ladder_tier",) + cls._INTS)
        return cls(max_ladder_tier=r.get("max_ladder_tier"), **{n: r.get(n) for n in cls._INTS})


@dataclass(frozen=True)
class CapabilityCounts:
    discovered: int
    by_language: Mapping | None = None

    def __post_init__(self) -> None:
        c.integer(self.discovered, "capabilities.discovered")
        object.__setattr__(self, "by_language", _optional_counts(self.by_language, "capabilities.by_language", _key(Language)))
        _check_partition(self.by_language, self.discovered, "capabilities.by_language")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"discovered": self.discovered}
        _emit(out, "by_language", self.by_language)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "capabilities") -> "CapabilityCounts":
        r = c.Reader(data, where, ("discovered",), ("by_language",))
        return cls(discovered=r.get("discovered"), by_language=r.get("by_language"))


@dataclass(frozen=True)
class InvocationCounts:
    enumerated: int
    with_matching_sink_rule: int | None = None
    without_matching_sink_rule: int | None = None
    by_language: Mapping | None = None

    def __post_init__(self) -> None:
        w = "invocations"
        c.integer(self.enumerated, f"{w}.enumerated")
        c.optional_integer(self.with_matching_sink_rule, f"{w}.with_matching_sink_rule")
        c.optional_integer(self.without_matching_sink_rule, f"{w}.without_matching_sink_rule")
        object.__setattr__(self, "by_language", _optional_counts(self.by_language, f"{w}.by_language", _key(Language)))
        _check_partition(self.by_language, self.enumerated, f"{w}.by_language")
        for name in ("with_matching_sink_rule", "without_matching_sink_rule"):
            if (getattr(self, name) or 0) > self.enumerated:
                raise c.fail(w, f"{name} exceeds the invocations enumerated")
        if self.with_matching_sink_rule is not None and self.without_matching_sink_rule is not None \
                and self.with_matching_sink_rule + self.without_matching_sink_rule != self.enumerated:
            raise c.fail(w, "with and without a matching sink rule must partition the enumerated invocations")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"enumerated": self.enumerated}
        c.put(out, "with_matching_sink_rule", self.with_matching_sink_rule)
        c.put(out, "without_matching_sink_rule", self.without_matching_sink_rule)
        _emit(out, "by_language", self.by_language)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "invocations") -> "InvocationCounts":
        r = c.Reader(data, where, ("enumerated",), ("with_matching_sink_rule", "without_matching_sink_rule", "by_language"))
        return cls(enumerated=r.get("enumerated"), with_matching_sink_rule=r.get("with_matching_sink_rule"),
                   without_matching_sink_rule=r.get("without_matching_sink_rule"), by_language=r.get("by_language"))


@dataclass(frozen=True)
class ClaimCounts:
    instantiated: int
    investigated: int
    not_investigated: int
    scheduled: int | None = None
    instantiated_without_any_rule_match: int | None = None
    by_language: Mapping | None = None

    def __post_init__(self) -> None:
        w = "claims"
        for name in ("instantiated", "investigated", "not_investigated"):
            c.integer(getattr(self, name), f"{w}.{name}")
        c.optional_integer(self.scheduled, f"{w}.scheduled")
        c.optional_integer(self.instantiated_without_any_rule_match, f"{w}.instantiated_without_any_rule_match")
        object.__setattr__(self, "by_language", _optional_counts(self.by_language, f"{w}.by_language", _key(Language)))
        if self.investigated + self.not_investigated != self.instantiated:
            raise c.fail(w, "every instantiated claim is either investigated or not investigated")
        for name in ("scheduled", "instantiated_without_any_rule_match"):
            if (getattr(self, name) or 0) > self.instantiated:
                raise c.fail(w, f"{name} exceeds the claims instantiated")
        if self.scheduled is not None and self.scheduled < self.investigated:
            raise c.fail(w, "a claim cannot be investigated without being scheduled")
        _check_partition(self.by_language, self.instantiated, f"{w}.by_language")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"instantiated": self.instantiated}
        c.put(out, "scheduled", self.scheduled)
        out["investigated"] = self.investigated
        out["not_investigated"] = self.not_investigated
        c.put(out, "instantiated_without_any_rule_match", self.instantiated_without_any_rule_match)
        _emit(out, "by_language", self.by_language)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "claims") -> "ClaimCounts":
        r = c.Reader(data, where, ("instantiated", "investigated", "not_investigated"),
                     ("scheduled", "instantiated_without_any_rule_match", "by_language"))
        return cls(**{k: r.get(k) for k in ("instantiated", "investigated", "not_investigated", "scheduled",
                                            "instantiated_without_any_rule_match", "by_language")})


@dataclass(frozen=True)
class FrontierCounts:
    total: int
    by_tier: Mapping
    by_reason: Mapping

    def __post_init__(self) -> None:
        c.integer(self.total, "frontier.total")
        object.__setattr__(self, "by_tier", _counts(self.by_tier, "frontier.by_tier", _evidence_tier_key))
        object.__setattr__(self, "by_reason", _counts(self.by_reason, "frontier.by_reason", _frontier_reason_key))
        _check_within(self.by_tier, self.total, "frontier.by_tier")
        _check_within(self.by_reason, self.total, "frontier.by_reason")

    def to_dict(self) -> dict:
        return {"total": self.total, "by_tier": c.counts_to_dict(self.by_tier, LadderTier),
                "by_reason": c.counts_to_dict(self.by_reason, StopReason)}

    @classmethod
    def from_dict(cls, data: Any, where: str = "frontier") -> "FrontierCounts":
        r = c.Reader(data, where, ("total", "by_tier", "by_reason"))
        return cls(total=r.get("total"), by_tier=r.get("by_tier"), by_reason=r.get("by_reason"))


def _frontier_reason_key(value, where):
    reason = c.enum_value(StopReason, value, where)
    if reason not in FRONTIER_REASONS:
        raise c.fail(where, f"{reason.value} is not a reason an edge is left unopened")
    return reason


@dataclass(frozen=True)
class ContradictionCounts:
    total: int | None = None
    unresolved: int | None = None
    resolved_by_implementation_precedence: int | None = None
    by_obligation: Mapping | None = None

    def __post_init__(self) -> None:
        w = "contradictions"
        for name in ("total", "unresolved", "resolved_by_implementation_precedence"):
            c.optional_integer(getattr(self, name), f"{w}.{name}")
        object.__setattr__(self, "by_obligation", _optional_counts(self.by_obligation, f"{w}.by_obligation", _key(Obligation)))
        if None not in (self.total, self.unresolved, self.resolved_by_implementation_precedence) and \
                self.unresolved + self.resolved_by_implementation_precedence != self.total:
            raise c.fail(w, "every contradiction is either unresolved or resolved by precedence")
        if self.total is not None:
            _check_partition(self.by_obligation, self.total, f"{w}.by_obligation")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        for name in ("total", "unresolved", "resolved_by_implementation_precedence"):
            c.put(out, name, getattr(self, name))
        _emit(out, "by_obligation", self.by_obligation, Obligation)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "contradictions") -> "ContradictionCounts":
        keys = ("total", "unresolved", "resolved_by_implementation_precedence", "by_obligation")
        r = c.Reader(data, where, (), keys)
        return cls(**{k: r.get(k) for k in keys})


@dataclass(frozen=True)
class CounterEvidenceCounts:
    """``blocking_probes_executed`` counts recorded BLOCKING outcomes, of which some may be INCOMPLETE."""

    blocking_probes_executed: int | None = None
    blocking_probes_incomplete: int | None = None
    by_probe_id: Mapping | None = None

    def __post_init__(self) -> None:
        w = "counter_evidence"
        c.optional_integer(self.blocking_probes_executed, f"{w}.blocking_probes_executed")
        c.optional_integer(self.blocking_probes_incomplete, f"{w}.blocking_probes_incomplete")
        object.__setattr__(self, "by_probe_id", _optional_counts(self.by_probe_id, f"{w}.by_probe_id", _probe_key))
        if None not in (self.blocking_probes_executed, self.blocking_probes_incomplete) and \
                self.blocking_probes_incomplete > self.blocking_probes_executed:
            raise c.fail(w, "more BLOCKING probes incomplete than executed")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        c.put(out, "blocking_probes_executed", self.blocking_probes_executed)
        c.put(out, "blocking_probes_incomplete", self.blocking_probes_incomplete)
        _emit(out, "by_probe_id", self.by_probe_id, tuple(PROBE_REGISTRY))
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "counter_evidence") -> "CounterEvidenceCounts":
        keys = ("blocking_probes_executed", "blocking_probes_incomplete", "by_probe_id")
        r = c.Reader(data, where, (), keys)
        return cls(**{k: r.get(k) for k in keys})


@dataclass(frozen=True)
class EvidenceCounts:
    """Fidelity figures exist only when fidelity was actually checked."""

    packets_total: int | None = None
    probative: int | None = None
    hypothesis_only: int | None = None
    by_tier: Mapping | None = None
    fidelity_checked: int | None = None
    fidelity_failures: int | None = None

    def __post_init__(self) -> None:
        w = "evidence"
        for name in ("packets_total", "probative", "hypothesis_only", "fidelity_checked", "fidelity_failures"):
            c.optional_integer(getattr(self, name), f"{w}.{name}")
        object.__setattr__(self, "by_tier", _optional_counts(self.by_tier, f"{w}.by_tier", _evidence_tier_key))
        if self.packets_total is not None:
            if None not in (self.probative, self.hypothesis_only) and \
                    self.probative + self.hypothesis_only != self.packets_total:
                raise c.fail(w, "every packet is either PROBATIVE or HYPOTHESIS_ONLY")
            _check_partition(self.by_tier, self.packets_total, f"{w}.by_tier")
            if (self.fidelity_checked or 0) > self.packets_total:
                raise c.fail(w, "more packets fidelity-checked than exist")
        if self.fidelity_failures is not None:
            if self.fidelity_checked is None:
                raise c.fail(w, "fidelity failures cannot be reported when fidelity was not checked")
            if self.fidelity_failures > self.fidelity_checked:
                raise c.fail(w, "more fidelity failures than packets checked")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        for name in ("packets_total", "probative", "hypothesis_only"):
            c.put(out, name, getattr(self, name))
        _emit(out, "by_tier", self.by_tier, LadderTier)
        c.put(out, "fidelity_checked", self.fidelity_checked)
        c.put(out, "fidelity_failures", self.fidelity_failures)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "evidence") -> "EvidenceCounts":
        keys = ("packets_total", "probative", "hypothesis_only", "by_tier", "fidelity_checked", "fidelity_failures")
        r = c.Reader(data, where, (), keys)
        return cls(**{k: r.get(k) for k in keys})


@dataclass(frozen=True)
class AnalysisErrorCounts:
    total: int
    by_obligation: Mapping | None = None
    by_cause: Mapping | None = None

    def __post_init__(self) -> None:
        c.integer(self.total, "analysis_errors.total")
        object.__setattr__(self, "by_obligation", _optional_counts(
            self.by_obligation, "analysis_errors.by_obligation", _key(Obligation)))
        object.__setattr__(self, "by_cause", _optional_counts(self.by_cause, "analysis_errors.by_cause", _free_key))

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"total": self.total}
        _emit(out, "by_obligation", self.by_obligation, Obligation)
        _emit(out, "by_cause", self.by_cause)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "analysis_errors") -> "AnalysisErrorCounts":
        r = c.Reader(data, where, ("total",), ("by_obligation", "by_cause"))
        return cls(total=r.get("total"), by_obligation=r.get("by_obligation"), by_cause=r.get("by_cause"))


@dataclass(frozen=True)
class PerformanceCounts:
    wall_ms_total: int | None = None
    claims_hitting_wall_budget: int | None = None
    artefacts_opened: int | None = None
    bytes_read: int | None = None
    cache_hit_rate: float | None = None
    marginal_wall_ms_by_tier: Mapping | None = None

    _INTS = ("wall_ms_total", "claims_hitting_wall_budget", "artefacts_opened", "bytes_read")

    def __post_init__(self) -> None:
        for name in self._INTS:
            c.optional_integer(getattr(self, name), f"performance.{name}")
        if self.cache_hit_rate is not None:
            c.number(self.cache_hit_rate, "performance.cache_hit_rate", 0, 1)
        object.__setattr__(self, "marginal_wall_ms_by_tier", _optional_counts(
            self.marginal_wall_ms_by_tier, "performance.marginal_wall_ms_by_tier", _key(LadderTier)))

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        for name in self._INTS + ("cache_hit_rate",):
            c.put(out, name, getattr(self, name))
        _emit(out, "marginal_wall_ms_by_tier", self.marginal_wall_ms_by_tier, LadderTier)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "performance") -> "PerformanceCounts":
        keys = cls._INTS + ("cache_hit_rate", "marginal_wall_ms_by_tier")
        r = c.Reader(data, where, (), keys)
        return cls(**{k: r.get(k) for k in keys})


@dataclass(frozen=True)
class Interpretation:
    """The three literal statements are not configurable; only the prose is."""

    statement: str
    abstained_claims_are_not_negative_results: bool = True
    uninvestigated_claims_are_not_negative_results: bool = True
    zero_proven_effect_does_not_mean_safe: bool = True

    _FLAGS = ("abstained_claims_are_not_negative_results", "uninvestigated_claims_are_not_negative_results",
              "zero_proven_effect_does_not_mean_safe")

    def __post_init__(self) -> None:
        c.text(self.statement, "interpretation.statement")
        for flag in self._FLAGS:
            if getattr(self, flag) is not True:
                raise c.fail(f"interpretation.{flag}", "is a required literal statement and must be true")

    def to_dict(self) -> dict:
        return {**{f: True for f in self._FLAGS}, "statement": self.statement}

    @classmethod
    def from_dict(cls, data: Any, where: str = "interpretation") -> "Interpretation":
        r = c.Reader(data, where, cls._FLAGS + ("statement",))
        return cls(statement=r.get("statement"), **{f: r.get(f) for f in cls._FLAGS})


_STATE_ORDER = tuple(ProofState)


@dataclass(frozen=True)
class CoverageLedger:
    enabled_effect_classes: tuple[EffectClass, ...]
    budgets: Budgets
    capabilities: CapabilityCounts
    invocations: InvocationCounts
    claims: ClaimCounts
    verdict_distribution: Mapping
    obligation_state_distribution: Mapping
    highest_tier_reached_histogram: Mapping
    stop_reason_histogram: Mapping
    budget_exhaustion: Mapping
    frontier: FrontierCounts
    analysis_errors: AnalysisErrorCounts
    interpretation: Interpretation
    priority_policy_id: str | None = None
    contradictions: ContradictionCounts | None = None
    counter_evidence: CounterEvidenceCounts | None = None
    evidence: EvidenceCounts | None = None
    performance: PerformanceCounts | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        w = "ledger"
        if self.schema_version != SCHEMA_VERSION:
            raise c.fail(w, f"schema_version must be {SCHEMA_VERSION}")
        classes = c.enum_tuple(EffectClass, self.enabled_effect_classes, f"{w}.enabled_effect_classes")
        if not classes:
            raise c.fail(w, "at least one effect class is enabled")
        object.__setattr__(self, "enabled_effect_classes", classes)
        for name, cls in (("budgets", Budgets), ("capabilities", CapabilityCounts), ("invocations", InvocationCounts),
                          ("claims", ClaimCounts), ("frontier", FrontierCounts),
                          ("analysis_errors", AnalysisErrorCounts), ("interpretation", Interpretation)):
            c.instance(cls, getattr(self, name), f"{w}.{name}")
        for name, cls in (("contradictions", ContradictionCounts), ("counter_evidence", CounterEvidenceCounts),
                          ("evidence", EvidenceCounts), ("performance", PerformanceCounts)):
            c.optional_instance(cls, getattr(self, name), f"{w}.{name}")
        c.optional_text(self.priority_policy_id, f"{w}.priority_policy_id")

        verdicts = _counts(self.verdict_distribution, f"{w}.verdict_distribution", _key(Verdict))
        if set(verdicts) != set(Verdict):
            raise c.fail(w, "verdict_distribution reports all four verdicts")
        object.__setattr__(self, "verdict_distribution", verdicts)

        if not isinstance(self.obligation_state_distribution, Mapping):
            raise c.fail(w, "obligation_state_distribution must be a mapping")
        dist = {}
        for raw, counts in self.obligation_state_distribution.items():
            o = c.enum_value(Obligation, raw, f"{w}.obligation_state_distribution key")
            per = _counts(counts, f"{w}.obligation_state_distribution[{o.value}]", _key(ProofState))
            if set(per) != set(ProofState):
                raise c.fail(w, f"{o.value} must count all five proof states separately")
            dist[o] = per
        if set(dist) != set(Obligation):
            raise c.fail(w, "obligation_state_distribution covers all five obligations")
        object.__setattr__(self, "obligation_state_distribution", MappingProxyType(dist))

        object.__setattr__(self, "highest_tier_reached_histogram", _counts(
            self.highest_tier_reached_histogram, f"{w}.highest_tier_reached_histogram", _key(LadderTier)))
        object.__setattr__(self, "stop_reason_histogram", _counts(
            self.stop_reason_histogram, f"{w}.stop_reason_histogram", _key(StopReason)))
        object.__setattr__(self, "budget_exhaustion", _counts(
            self.budget_exhaustion, f"{w}.budget_exhaustion", _key(BudgetName)))
        self._check_arithmetic(w)

    def _check_arithmetic(self, w: str) -> None:
        claims = self.claims
        if claims.instantiated > self.invocations.enumerated * len(self.enabled_effect_classes):
            raise c.fail(w, "more claims instantiated than invocations enumerated for the enabled classes")
        if _total(self.verdict_distribution) != claims.investigated:
            raise c.fail(w, "verdict_distribution counts investigated claims only, and all of them")
        for o, per in self.obligation_state_distribution.items():
            if _total(per) != claims.investigated:
                raise c.fail(w, f"{o.value} state counts must sum to the claims investigated")
        _check_partition(self.highest_tier_reached_histogram, claims.instantiated,
                         f"{w}.highest_tier_reached_histogram")
        _check_partition(self.stop_reason_histogram, claims.instantiated, f"{w}.stop_reason_histogram")
        if self.stop_reason_histogram.get(StopReason.CLAIM_NOT_INVESTIGATED, 0) != claims.not_investigated:
            raise c.fail(w, "every uninvestigated claim, and only those, stop with CLAIM_NOT_INVESTIGATED")
        if self.analysis_errors.total < self.verdict_distribution[Verdict.ANALYSIS_ERROR]:
            raise c.fail(w, "every ANALYSIS_ERROR claim is counted as an analysis error")
        self._check_verdicts_against_states(w)
        if claims.instantiated_without_any_rule_match is not None \
                and self.invocations.without_matching_sink_rule is not None \
                and claims.instantiated_without_any_rule_match > \
                self.invocations.without_matching_sink_rule * len(self.enabled_effect_classes):
            raise c.fail(w, "more rule-free claims than rule-free invocations")

    def _check_verdicts_against_states(self, w: str) -> None:
        """Bounds the verdict function imposes on the state counts of the same investigated claims."""
        verdicts = self.verdict_distribution
        dist = self.obligation_state_distribution
        necessary = set(Obligation)
        for effect_class in self.enabled_effect_classes:
            necessary &= set(NECESSARY_OBLIGATIONS[effect_class])
        if not necessary:
            return
        errors = [dist[o][ProofState.ERROR] for o in necessary]
        if max(errors) > verdicts[Verdict.ANALYSIS_ERROR]:
            raise c.fail(w, "an ERROR on a necessary obligation makes the claim ANALYSIS_ERROR, never another verdict")
        if len(necessary) == len(Obligation) and verdicts[Verdict.ANALYSIS_ERROR] > sum(errors):
            raise c.fail(w, "an ANALYSIS_ERROR claim has an ERROR on a necessary obligation")
        if verdicts[Verdict.PROVEN_EFFECT] > min(dist[o][ProofState.SUPPORTED] for o in necessary):
            raise c.fail(w, "a PROVEN_EFFECT claim has every necessary obligation SUPPORTED")
        if len(necessary) == len(Obligation) and verdicts[Verdict.NO_EFFECT] > sum(
                dist[o][ProofState.REFUTED] for o in necessary if o is not Obligation.IMPLEMENTATION):
            raise c.fail(w, "a NO_EFFECT claim has a REFUTED obligation")
        settled = verdicts[Verdict.PROVEN_EFFECT] + verdicts[Verdict.NO_EFFECT]
        for o in necessary:
            if dist[o][ProofState.CONFLICTING] + settled > self.claims.investigated:
                raise c.fail(w, f"a claim with {o.value} CONFLICTING is neither PROVEN_EFFECT nor NO_EFFECT")

    # -- the distinctions the ledger exists to keep

    @property
    def proven_effect(self) -> int:
        return self.verdict_distribution[Verdict.PROVEN_EFFECT]

    @property
    def no_effect(self) -> int:
        return self.verdict_distribution[Verdict.NO_EFFECT]

    @property
    def abstained(self) -> int:
        return self.verdict_distribution[Verdict.ABSTAIN]

    @property
    def analysis_error(self) -> int:
        return self.verdict_distribution[Verdict.ANALYSIS_ERROR]

    @property
    def not_investigated(self) -> int:
        return self.claims.not_investigated

    @property
    def unresolved(self) -> int:
        """Claims whose effect is neither established nor excluded: ABSTAIN plus never investigated."""
        return self.abstained + self.not_investigated

    @property
    def negative_results(self) -> int:
        """Only NO_EFFECT is a negative result. Nothing else is ever counted here."""
        return self.no_effect

    # -- construction from claims

    @classmethod
    def from_claims(cls, claims: Iterable[EffectClaim], *, capabilities_discovered: int,
                    invocations_enumerated: int, budgets: Budgets | None = None,
                    enabled_effect_classes: Iterable[EffectClass] = (EffectClass.EXTERNAL_PERSISTENT_STATE_EFFECT,),
                    priority_policy_id: str | None = None) -> "CoverageLedger":
        claims = c.typed_tuple(EffectClaim, claims, "claims")
        enabled = c.enum_tuple(EffectClass, enabled_effect_classes, "enabled_effect_classes")
        c.unique(claims, "claims", key=lambda k: k.claim_id)
        c.unique(claims, "claims", key=lambda k: k.identity)
        for k in claims:
            if k.effect_class not in enabled:
                raise c.fail("claims", f"claim {k.claim_id!r} is for a class that is not enabled")

        investigated = [k for k in claims if k.was_investigated]
        verdicts = {v: 0 for v in Verdict}
        states = {o: {s: 0 for s in ProofState} for o in Obligation}
        for k in investigated:
            verdicts[k.verdict] += 1
            for o, s in k.obligations.items():
                states[o][s] += 1

        tiers: dict = {}
        stops: dict = {}
        budgets_hit: dict = {}
        frontier_tiers: dict = {}
        frontier_reasons: dict = {}
        for k in claims:
            acq = k.acquisition
            tiers[acq.highest_tier_reached] = tiers.get(acq.highest_tier_reached, 0) + 1
            stops[acq.stop_reason] = stops.get(acq.stop_reason, 0) + 1
            for b in acq.budget_exhausted:
                budgets_hit[b] = budgets_hit.get(b, 0) + 1
            for entry in acq.frontier or ():
                frontier_tiers[entry.would_reach_tier] = frontier_tiers.get(entry.would_reach_tier, 0) + 1
                frontier_reasons[entry.reason] = frontier_reasons.get(entry.reason, 0) + 1

        errored = [k for k in claims if k.verdict is Verdict.ANALYSIS_ERROR]
        error_obligations: dict = {}
        for k in errored:
            for o, s in k.obligations.items():
                if s is ProofState.ERROR:
                    error_obligations[o] = error_obligations.get(o, 0) + 1

        records = [x for k in claims for x in k.contradictions]
        by_obligation: dict = {}
        for x in records:
            by_obligation[x.obligation] = by_obligation.get(x.obligation, 0) + 1
        blocking = [o for k in claims for o in k.probe_outcomes if o.probe_class is ProbeClass.BLOCKING]
        by_probe: dict = {}
        for k in claims:
            for o in k.probe_outcomes:
                by_probe[o.probe_id] = by_probe.get(o.probe_id, 0) + 1
        packets = [p for k in claims for p in k.evidence_packets]
        packet_tiers: dict = {}
        for p in packets:
            packet_tiers[p.tier] = packet_tiers.get(p.tier, 0) + 1

        rule_free = sum(1 for k in claims if not k.invocation.matched_rule_ids
                        and not any(p.is_rule_derived for p in k.evidence_packets))
        ledger_counts = dict(
            claims=ClaimCounts(instantiated=len(claims), investigated=len(investigated),
                               not_investigated=len(claims) - len(investigated),
                               instantiated_without_any_rule_match=rule_free),
            verdict_distribution=verdicts,
        )
        return cls(
            enabled_effect_classes=enabled,
            budgets=budgets if budgets is not None else Budgets(),
            priority_policy_id=priority_policy_id,
            capabilities=CapabilityCounts(discovered=capabilities_discovered),
            invocations=InvocationCounts(enumerated=invocations_enumerated),
            obligation_state_distribution=states,
            highest_tier_reached_histogram=tiers,
            stop_reason_histogram=stops,
            budget_exhaustion=budgets_hit,
            frontier=FrontierCounts(total=sum(k.acquisition.frontier_size for k in claims),
                                    by_tier=frontier_tiers, by_reason=frontier_reasons),
            contradictions=ContradictionCounts(
                total=len(records),
                unresolved=sum(1 for x in records if x.resolution is ContradictionResolution.UNRESOLVED),
                resolved_by_implementation_precedence=sum(
                    1 for x in records if x.resolution is ContradictionResolution.RESOLVED_IMPLEMENTATION_PRECEDENCE),
                by_obligation=by_obligation),
            counter_evidence=CounterEvidenceCounts(
                blocking_probes_executed=len(blocking),
                blocking_probes_incomplete=sum(1 for o in blocking if o.outcome is ProbeResult.INCOMPLETE),
                by_probe_id=by_probe),
            evidence=EvidenceCounts(
                packets_total=len(packets),
                probative=sum(1 for p in packets if p.admissibility is Admissibility.PROBATIVE),
                hypothesis_only=sum(1 for p in packets if p.admissibility is Admissibility.HYPOTHESIS_ONLY),
                by_tier=packet_tiers),
            analysis_errors=AnalysisErrorCounts(total=len(errored), by_obligation=error_obligations),
            interpretation=Interpretation(statement=_statement(verdicts, len(claims) - len(investigated),
                                                               sum(k.acquisition.frontier_size for k in claims))),
            **ledger_counts,
        )

    # -- serialisation

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "enabled_effect_classes": [e.value for e in self.enabled_effect_classes],
            "budgets": self.budgets.to_dict(),
        }
        c.put(out, "priority_policy_id", self.priority_policy_id)
        out.update({
            "capabilities": self.capabilities.to_dict(),
            "invocations": self.invocations.to_dict(),
            "claims": self.claims.to_dict(),
            "verdict_distribution": c.counts_to_dict(self.verdict_distribution, Verdict),
            "obligation_state_distribution": {
                o.value: c.counts_to_dict(self.obligation_state_distribution[o], _STATE_ORDER) for o in Obligation},
            "highest_tier_reached_histogram": c.counts_to_dict(self.highest_tier_reached_histogram, LadderTier),
            "stop_reason_histogram": c.counts_to_dict(self.stop_reason_histogram, StopReason),
            "budget_exhaustion": c.counts_to_dict(self.budget_exhaustion, BudgetName),
            "frontier": self.frontier.to_dict(),
        })
        for name in ("contradictions", "counter_evidence", "evidence"):
            c.put(out, name, getattr(self, name) and getattr(self, name).to_dict())
        out["analysis_errors"] = self.analysis_errors.to_dict()
        c.put(out, "performance", self.performance and self.performance.to_dict())
        out["interpretation"] = self.interpretation.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "ledger") -> "CoverageLedger":
        required = ("schema_version", "enabled_effect_classes", "budgets", "capabilities", "invocations", "claims",
                    "verdict_distribution", "obligation_state_distribution", "highest_tier_reached_histogram",
                    "stop_reason_histogram", "budget_exhaustion", "frontier", "analysis_errors", "interpretation")
        optional = ("priority_policy_id", "contradictions", "counter_evidence", "evidence", "performance")
        r = c.Reader(data, where, required, optional)
        sections = {"budgets": Budgets, "capabilities": CapabilityCounts, "invocations": InvocationCounts,
                    "claims": ClaimCounts, "frontier": FrontierCounts, "analysis_errors": AnalysisErrorCounts,
                    "interpretation": Interpretation, "contradictions": ContradictionCounts,
                    "counter_evidence": CounterEvidenceCounts, "evidence": EvidenceCounts,
                    "performance": PerformanceCounts}
        parsed = {name: section.from_dict(r.get(name), r.at(name))
                  for name, section in sections.items() if name in r}
        obligation_dist = r.get("obligation_state_distribution")
        c.Reader(obligation_dist, r.at("obligation_state_distribution"), tuple(o.value for o in Obligation))
        return cls(
            schema_version=r.get("schema_version"),
            enabled_effect_classes=r.get("enabled_effect_classes"),
            priority_policy_id=r.get("priority_policy_id"),
            verdict_distribution=_exact_keys(r.get("verdict_distribution"), r.at("verdict_distribution"),
                                             [v.value for v in Verdict]),
            obligation_state_distribution={
                k: _exact_keys(v, f"{r.at('obligation_state_distribution')}.{k}", [s.value for s in ProofState])
                for k, v in obligation_dist.items()},
            highest_tier_reached_histogram=r.get("highest_tier_reached_histogram"),
            stop_reason_histogram=r.get("stop_reason_histogram"),
            budget_exhaustion=r.get("budget_exhaustion"),
            **parsed,
        )


def _exact_keys(data: Any, where: str, keys: list) -> Mapping:
    c.Reader(data, where, keys)
    return data


def _statement(verdicts: dict, not_investigated: int, frontier_total: int) -> str:
    return (f"{verdicts[Verdict.PROVEN_EFFECT]} PROVEN_EFFECT, {verdicts[Verdict.NO_EFFECT]} NO_EFFECT, "
            f"{verdicts[Verdict.ABSTAIN]} ABSTAIN, {verdicts[Verdict.ANALYSIS_ERROR]} ANALYSIS_ERROR; "
            f"{not_investigated} claims were never investigated and {frontier_total} descent edges were "
            "identified and not opened. Abstained and uninvestigated claims are not negative results, and an "
            "analysis error is not a result. Zero PROVEN_EFFECT does not mean this repository is safe or free "
            f"of effects; only the {verdicts[Verdict.NO_EFFECT]} NO_EFFECT claims establish an absence, and only "
            "for their own invocation.")
