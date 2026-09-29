"""The EffectClaim and everything it owns.

Frozen by AREF-002 as amended by ``specs/AREF-002A/`` and the budget-only
``specs/AREF-002B/`` profile; sections 4 to 9 of
``specs/AREF-002/proof_obligations.md`` and ``effect_claim.schema.json``.

An ``EffectClaim`` exists because inertness was not established for an
invocation. Nothing in this module requires, accepts as a basis, or derives
identity from a sink rule or a finding: ``matched_rule_ids`` is provenance only
and may be empty.

Implementation candidates are a set. The claim holds them as a ``frozenset``
and offers no positional access; a selected candidate exists only under
``SINGLE_ESTABLISHED``.
"""

from __future__ import annotations

from collections.abc import Mapping

from dataclasses import dataclass
from typing import Any, Iterable

from actenon_scan.effects import _codec as c
from actenon_scan.effects.evidence import (
    EvidencePacket,
    ProbeOutcome,
    SourceLocator,
    VerbatimExtract,
    check_packet_set,
    check_probe_set,
)
from actenon_scan.effects.vocabulary import (
    BLOCKING_PROBE_IDS,
    ESTABLISHED_SELECTIONS,
    EVIDENCE_OBLIGATIONS,
    FRONTIER_REASONS,
    GENESIS_BASIS,
    NECESSARY_OBLIGATIONS,
    OPAQUE_CANDIDATE_KINDS,
    RESOLVED_CANDIDATE_KINDS,
    SCHEMA_VERSION,
    UNCERTAINTY_PREDICATES,
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
    ProofState,
    SelectionState,
    StopReason,
    TargetScope,
    Verdict,
)
from actenon_scan.repository.symbol_index import ResolutionCertainty
from actenon_scan.repository.taint import TaintLattice

_S, _R, _U, _C, _E = (ProofState.SUPPORTED, ProofState.REFUTED, ProofState.UNKNOWN,
                      ProofState.CONFLICTING, ProofState.ERROR)


def _ids(value: Any, where: str, *, non_empty: bool = False) -> tuple[str, ...]:
    items = tuple(c.identifier(v, where) for v in c.sequence(value, where))
    if non_empty and not items:
        raise c.fail(where, "must not be empty")
    return c.unique(items, where)


@dataclass(frozen=True)
class ObligationStates:
    implementation: ProofState
    activation: ProofState
    boundary: ProofState
    operation: ProofState
    persistence: ProofState

    def __post_init__(self) -> None:
        for o in Obligation:
            name = o.value.lower()
            object.__setattr__(self, name, c.enum_value(ProofState, getattr(self, name), f"obligations.{o.value}"))

    def __getitem__(self, obligation: Obligation) -> ProofState:
        return getattr(self, c.enum_value(Obligation, obligation, "obligation").value.lower())

    def items(self) -> tuple[tuple[Obligation, ProofState], ...]:
        return tuple((o, self[o]) for o in Obligation)

    @classmethod
    def from_mapping(cls, states: dict) -> "ObligationStates":
        return cls(**{o.value.lower(): states[o] for o in Obligation})

    def to_dict(self) -> dict:
        return {o.value: s.value for o, s in self.items()}

    @classmethod
    def from_dict(cls, data: Any, where: str = "obligations") -> "ObligationStates":
        r = c.Reader(data, where, tuple(o.value for o in Obligation))
        return cls(**{o.value.lower(): r.get(o.value) for o in Obligation})


def aggregate_obligation(states: Iterable[ProofState]) -> ProofState:
    """Claim-level state of one evidence obligation across candidates.

    Identical per-candidate states pass through. Disagreement is ``UNKNOWN``
    (inter-candidate divergence is not a contradiction), except that an
    ``ERROR`` on any candidate is never hidden behind ``UNKNOWN`` and a
    ``CONFLICTING`` candidate never collapses to ``UNKNOWN``. The result
    depends only on the set of states, never on candidate order.
    """
    distinct = frozenset(c.enum_value(ProofState, s, "state") for s in states)
    if not distinct:
        raise c.EffectModelError("cannot aggregate over zero candidates")
    if len(distinct) == 1:
        return next(iter(distinct))
    if _E in distinct:
        return _E
    if _C in distinct:
        return _C
    return _U


def aggregate_claim_states(selection_state: SelectionState,
                           candidate_states: Iterable[ObligationStates]) -> ObligationStates:
    selection_state = c.enum_value(SelectionState, selection_state, "selection_state")
    per_candidate = tuple(candidate_states)
    states = {}
    for o in Obligation:
        states[o] = aggregate_obligation(s[o] for s in per_candidate)
    return ObligationStates.from_mapping(states)


@dataclass(frozen=True)
class ImplementationCandidate:
    candidate_id: str
    kind: CandidateKind
    obligations: ObligationStates | None = None
    symbol: str | None = None
    locator: SourceLocator | None = None
    resolved_at_tier: LadderTier | None = None

    def __post_init__(self) -> None:
        w = f"candidate {self.candidate_id!r}"
        c.identifier(self.candidate_id, f"{w}.candidate_id")
        object.__setattr__(self, "kind", c.enum_value(CandidateKind, self.kind, f"{w}.kind"))
        c.optional_instance(ObligationStates, self.obligations, f"{w}.obligations")
        c.optional_text(self.symbol, f"{w}.symbol")
        c.optional_instance(SourceLocator, self.locator, f"{w}.locator")
        object.__setattr__(self, "resolved_at_tier", c.optional_enum(
            LadderTier, self.resolved_at_tier, f"{w}.resolved_at_tier"))
        if self.resolved_at_tier is LadderTier.L8:
            raise c.fail(w, "L8 is not a tier at which anything resolves")
        if self.obligations is not None and self.obligations.implementation is _R:
            raise c.fail(w, "IMPLEMENTATION is never REFUTED")
        if self.obligations is not None and self.kind in OPAQUE_CANDIDATE_KINDS and self.obligations.implementation not in (_U, _E):
            raise c.fail(w, "opaque/unresolved identity cannot be implementation-supported")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"candidate_id": self.candidate_id, "kind": self.kind.value}
        c.put(out, "symbol", self.symbol)
        c.put(out, "locator", self.locator and self.locator.to_dict())
        c.put(out, "obligations", self.obligations and self.obligations.to_dict())
        c.put(out, "resolved_at_tier", self.resolved_at_tier and self.resolved_at_tier.value)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "candidate") -> "ImplementationCandidate":
        r = c.Reader(data, where, ("candidate_id", "kind"),
                     ("symbol", "locator", "obligations", "resolved_at_tier"))
        return cls(
            candidate_id=r.get("candidate_id"),
            kind=r.get("kind"),
            obligations=None if "obligations" not in r else ObligationStates.from_dict(
                r.get("obligations"), r.at("obligations")),
            symbol=r.get("symbol"),
            locator=None if "locator" not in r else SourceLocator.from_dict(r.get("locator"), r.at("locator")),
            resolved_at_tier=r.get("resolved_at_tier"),
        )


def candidate_set(value: Any, where: str) -> frozenset:
    items = c.typed_tuple(ImplementationCandidate, value, where)
    if not items:
        raise c.fail(where, "at least one implementation candidate always exists")
    c.unique(items, where, key=lambda cand: cand.candidate_id)
    return frozenset(items)


def sorted_candidates(candidates: frozenset) -> list:
    return [cand.to_dict() for cand in sorted(candidates, key=lambda cand: cand.candidate_id)]


def check_selection_cardinality(selection: SelectionState, candidates: frozenset, where: str) -> None:
    n = len(candidates)
    if selection is SelectionState.SINGLE_ESTABLISHED and n != 1:
        raise c.fail(where, f"SINGLE_ESTABLISHED requires exactly one candidate, found {n}")
    if selection in (SelectionState.AGREEMENT_INVARIANT, SelectionState.UNRESOLVED_DIVERGENT) and n < 2:
        raise c.fail(where, f"{selection.value} requires several candidates, found {n}")


# ---------------------------------------------------------------- descriptors


@dataclass(frozen=True)
class TargetCoordinate:
    field: str
    resolution: ResolutionCertainty
    value: str | None = None

    def __post_init__(self) -> None:
        c.text(self.field, "target.coordinate.field", min_length=0)
        object.__setattr__(self, "resolution", c.enum_value(
            ResolutionCertainty, self.resolution, "target.coordinate.resolution"))
        c.optional_text(self.value, "target.coordinate.value")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"field": self.field}
        c.put(out, "value", self.value)
        out["resolution"] = self.resolution.value
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "TargetCoordinate":
        r = c.Reader(data, where, ("field", "resolution"), ("value",))
        return cls(field=r.get("field"), resolution=r.get("resolution"), value=r.get("value"))


@dataclass(frozen=True)
class Target:
    coordinates: tuple[TargetCoordinate, ...]
    scope: TargetScope

    def __post_init__(self) -> None:
        object.__setattr__(self, "coordinates", c.typed_tuple(TargetCoordinate, self.coordinates, "target.coordinates"))
        object.__setattr__(self, "scope", c.enum_value(TargetScope, self.scope, "target.scope"))

    def to_dict(self) -> dict:
        return {"coordinates": [x.to_dict() for x in self.coordinates], "scope": self.scope.value}

    @classmethod
    def from_dict(cls, data: Any, where: str = "target") -> "Target":
        r = c.Reader(data, where, ("coordinates", "scope"))
        coords = c.sequence(r.get("coordinates"), r.at("coordinates"))
        return cls(coordinates=tuple(TargetCoordinate.from_dict(x, f"{r.at('coordinates')}[{i}]")
                                     for i, x in enumerate(coords)),
                   scope=r.get("scope"))


@dataclass(frozen=True)
class Control:
    """Three independent proof states. Never an obligation; never gates a verdict."""

    trigger_control: ProofState
    target_control: ProofState
    content_control: ProofState
    taint: TaintLattice | None = None

    def __post_init__(self) -> None:
        for name in ("trigger_control", "target_control", "content_control"):
            object.__setattr__(self, name, c.enum_value(ProofState, getattr(self, name), f"control.{name}"))
        object.__setattr__(self, "taint", c.optional_enum(TaintLattice, self.taint, "control.taint"))

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "TRIGGER_CONTROL": self.trigger_control.value,
            "TARGET_CONTROL": self.target_control.value,
            "CONTENT_CONTROL": self.content_control.value,
        }
        c.put(out, "taint", self.taint and self.taint.value)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "control") -> "Control":
        r = c.Reader(data, where, ("TRIGGER_CONTROL", "TARGET_CONTROL", "CONTENT_CONTROL"), ("taint",))
        return cls(trigger_control=r.get("TRIGGER_CONTROL"), target_control=r.get("TARGET_CONTROL"),
                   content_control=r.get("CONTENT_CONTROL"), taint=r.get("taint"))


@dataclass(frozen=True)
class Authority:
    """Recorded, never an obligation: present or absent, it changes no verdict."""

    state: ProofState
    mechanism: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", c.enum_value(ProofState, self.state, "authority.state"))
        c.optional_text(self.mechanism, "authority.mechanism")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"state": self.state.value}
        c.put(out, "mechanism", self.mechanism)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "authority") -> "Authority":
        r = c.Reader(data, where, ("state",), ("mechanism",))
        return cls(state=r.get("state"), mechanism=r.get("mechanism"))


@dataclass(frozen=True)
class Condition:
    kind: ConditionKind
    expression: str
    locator: SourceLocator | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", c.enum_value(ConditionKind, self.kind, "condition.kind"))
        c.text(self.expression, "condition.expression", min_length=0)
        c.optional_instance(SourceLocator, self.locator, "condition.locator")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"kind": self.kind.value, "expression": self.expression}
        c.put(out, "locator", self.locator and self.locator.to_dict())
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "Condition":
        r = c.Reader(data, where, ("kind", "expression"), ("locator",))
        return cls(kind=r.get("kind"), expression=r.get("expression"),
                   locator=None if "locator" not in r else SourceLocator.from_dict(r.get("locator"), r.at("locator")))


@dataclass(frozen=True)
class Descriptors:
    target: Target
    control: Control
    authority: Authority
    conditions: tuple[Condition, ...] = ()

    def __post_init__(self) -> None:
        c.instance(Target, self.target, "descriptors.target")
        c.instance(Control, self.control, "descriptors.control")
        c.instance(Authority, self.authority, "descriptors.authority")
        object.__setattr__(self, "conditions", c.typed_tuple(Condition, self.conditions, "descriptors.conditions"))

    def to_dict(self) -> dict:
        return {"target": self.target.to_dict(), "control": self.control.to_dict(),
                "authority": self.authority.to_dict(),
                "conditions": [x.to_dict() for x in self.conditions]}

    @classmethod
    def from_dict(cls, data: Any, where: str = "descriptors") -> "Descriptors":
        r = c.Reader(data, where, ("target", "control", "authority", "conditions"))
        conds = c.sequence(r.get("conditions"), r.at("conditions"))
        return cls(target=Target.from_dict(r.get("target"), r.at("target")),
                   control=Control.from_dict(r.get("control"), r.at("control")),
                   authority=Authority.from_dict(r.get("authority"), r.at("authority")),
                   conditions=tuple(Condition.from_dict(x, f"{r.at('conditions')}[{i}]")
                                    for i, x in enumerate(conds)))


# ----------------------------------------------------------------- invocation


class _Absent:
    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = _Absent()


@dataclass(frozen=True)
class ArgumentShape:
    position: int | str
    literal: Any = ABSENT
    taint: TaintLattice | None = None

    def __post_init__(self) -> None:
        if type(self.position) is int:
            c.integer(self.position, "argument.position")
        else:
            c.text(self.position, "argument.position")
        if self.literal is not ABSENT and self.literal is not None and type(self.literal) not in (str, int, float, bool):
            raise c.fail("argument.literal", f"a {type(self.literal).__name__} is not a JSON scalar")
        object.__setattr__(self, "taint", c.optional_enum(TaintLattice, self.taint, "argument.taint"))

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"position": self.position}
        if self.literal is not ABSENT:
            out["literal"] = self.literal
        c.put(out, "taint", self.taint and self.taint.value)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "ArgumentShape":
        r = c.Reader(data, where, ("position",), ("literal", "taint"))
        return cls(position=r.get("position"), literal=r.raw("literal", ABSENT), taint=r.get("taint"))


@dataclass(frozen=True)
class Invocation:
    """The call site. ``matched_rule_ids`` is provenance only and may be empty."""

    locator: SourceLocator
    callee_expression: str
    language: Language
    matched_rule_ids: tuple[str, ...] = ()
    argument_shape: tuple[ArgumentShape, ...] = ()

    def __post_init__(self) -> None:
        c.instance(SourceLocator, self.locator, "invocation.locator")
        c.text(self.callee_expression, "invocation.callee_expression")
        object.__setattr__(self, "language", c.enum_value(Language, self.language, "invocation.language"))
        rules = tuple(c.text(r, "invocation.matched_rule_ids", min_length=0)
                      for r in c.sequence(self.matched_rule_ids, "invocation.matched_rule_ids"))
        object.__setattr__(self, "matched_rule_ids", c.unique(rules, "invocation.matched_rule_ids"))
        object.__setattr__(self, "argument_shape", c.typed_tuple(
            ArgumentShape, self.argument_shape, "invocation.argument_shape"))

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"locator": self.locator.to_dict(),
                               "callee_expression": self.callee_expression,
                               "language": self.language.value}
        if self.argument_shape:
            out["argument_shape"] = [a.to_dict() for a in self.argument_shape]
        out["matched_rule_ids"] = list(self.matched_rule_ids)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "invocation") -> "Invocation":
        r = c.Reader(data, where, ("locator", "callee_expression", "language"),
                     ("argument_shape", "matched_rule_ids"))
        shape = c.sequence(r.get("argument_shape", ()), r.at("argument_shape"))
        return cls(locator=SourceLocator.from_dict(r.get("locator"), r.at("locator")),
                   callee_expression=r.get("callee_expression"),
                   language=r.get("language"),
                   matched_rule_ids=r.get("matched_rule_ids", ()),
                   argument_shape=tuple(ArgumentShape.from_dict(a, f"{r.at('argument_shape')}[{i}]")
                                        for i, a in enumerate(shape)))


@dataclass(frozen=True)
class Genesis:
    """Why the claim exists. The only legal basis is non-refutation of inertness."""

    inertness_blockers: tuple[InertnessBlocker, ...] = ()
    basis: str = GENESIS_BASIS
    inertness_established: bool = False

    def __post_init__(self) -> None:
        if self.basis != GENESIS_BASIS or type(self.basis) is not str:
            raise c.fail("genesis.basis", f"the only legal basis is {GENESIS_BASIS}; a rule match is never a basis")
        if self.inertness_established is not False:
            raise c.fail("genesis.inertness_established", "an emitted claim never has established inertness")
        object.__setattr__(self, "inertness_blockers", c.enum_tuple(
            InertnessBlocker, self.inertness_blockers, "genesis.inertness_blockers"))

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"basis": self.basis, "inertness_established": False}
        if self.inertness_blockers:
            out["inertness_blockers"] = [b.value for b in self.inertness_blockers]
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "genesis") -> "Genesis":
        r = c.Reader(data, where, ("basis", "inertness_established"), ("inertness_blockers",))
        return cls(inertness_blockers=r.get("inertness_blockers", ()), basis=r.get("basis"),
                   inertness_established=r.get("inertness_established"))


# ---------------------------------------------------------------- acquisition


@dataclass(frozen=True)
class FrontierEntry:
    """A relevant descent edge that was not opened."""

    origin: SourceLocator
    would_reach_tier: LadderTier
    reason: StopReason
    target_symbol: str | None = None
    target_package: str | None = None
    might_settle: tuple[Obligation, ...] = ()
    budget_name: BudgetName | None = None

    def __post_init__(self) -> None:
        w = "frontier entry"
        c.instance(SourceLocator, self.origin, f"{w}.origin")
        object.__setattr__(self, "would_reach_tier", c.enum_value(LadderTier, self.would_reach_tier, f"{w}.would_reach_tier"))
        object.__setattr__(self, "reason", c.enum_value(StopReason, self.reason, f"{w}.reason"))
        c.optional_text(self.target_symbol, f"{w}.target_symbol")
        c.optional_text(self.target_package, f"{w}.target_package")
        object.__setattr__(self, "might_settle", c.enum_tuple(Obligation, self.might_settle, f"{w}.might_settle"))
        object.__setattr__(self, "budget_name", c.optional_enum(BudgetName, self.budget_name, f"{w}.budget_name"))
        if self.would_reach_tier is LadderTier.L8:
            raise c.fail(w, "L8 is not a tier an edge can reach")
        if self.reason not in FRONTIER_REASONS:
            raise c.fail(w, f"{self.reason.value} is not a reason an edge is left unopened")
        if (self.reason is StopReason.BUDGET_EXHAUSTED) != (self.budget_name is not None):
            raise c.fail(w, "a budget name is recorded exactly when the reason is BUDGET_EXHAUSTED")

    def is_relevant_to(self, obligation: Obligation) -> bool:
        """An entry that does not say what it might settle is relevant to everything."""
        return not self.might_settle or obligation in self.might_settle

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"origin": self.origin.to_dict()}
        c.put(out, "target_symbol", self.target_symbol)
        c.put(out, "target_package", self.target_package)
        out["would_reach_tier"] = self.would_reach_tier.value
        if self.might_settle:
            out["might_settle"] = [o.value for o in self.might_settle]
        out["reason"] = self.reason.value
        c.put(out, "budget_name", self.budget_name and self.budget_name.value)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "frontier entry") -> "FrontierEntry":
        r = c.Reader(data, where, ("origin", "would_reach_tier", "reason"),
                     ("target_symbol", "target_package", "might_settle", "budget_name"))
        return cls(origin=SourceLocator.from_dict(r.get("origin"), r.at("origin")),
                   would_reach_tier=r.get("would_reach_tier"), reason=r.get("reason"),
                   target_symbol=r.get("target_symbol"), target_package=r.get("target_package"),
                   might_settle=r.get("might_settle", ()), budget_name=r.get("budget_name"))


@dataclass(frozen=True)
class BudgetExclusion:
    """Supplied scoped exclusion witness; M0 does not verify its source truth."""

    budget_name: BudgetName
    frontier_indices: tuple[int, ...]
    locator: SourceLocator
    extract: VerbatimExtract

    def __post_init__(self) -> None:
        w = "budget exclusion"
        object.__setattr__(self, "budget_name", c.enum_value(BudgetName, self.budget_name, f"{w}.budget_name"))
        indices = tuple(c.integer(i, f"{w}.frontier_indices")
                        for i in c.sequence(self.frontier_indices, f"{w}.frontier_indices"))
        object.__setattr__(self, "frontier_indices", c.unique(indices, f"{w}.frontier_indices"))
        c.instance(SourceLocator, self.locator, f"{w}.locator")
        c.instance(VerbatimExtract, self.extract, f"{w}.extract")
        if not self.extract.text.strip() or self.extract.truncated:
            raise c.fail(w, "source extract must be nonempty and untruncated")

    def to_dict(self) -> dict:
        return {"budget_name": self.budget_name.value, "frontier_indices": list(self.frontier_indices),
                "locator": self.locator.to_dict(), "extract": self.extract.to_dict()}

    @classmethod
    def from_dict(cls, data: Any, where: str = "budget exclusion") -> "BudgetExclusion":
        r = c.Reader(data, where, ("budget_name", "frontier_indices", "locator", "extract"))
        return cls(budget_name=r.get("budget_name"), frontier_indices=r.get("frontier_indices"),
                   locator=SourceLocator.from_dict(r.get("locator"), r.at("locator")),
                   extract=VerbatimExtract.from_dict(r.get("extract"), r.at("extract")))


@dataclass(frozen=True)
class BudgetProvenance:
    """Source/edge/refutation links backing exclusion of recorded exhaustion."""

    refuted_obligation: Obligation
    refutation_packet_ids: tuple[str, ...]
    exclusions: tuple[BudgetExclusion, ...]

    def __post_init__(self) -> None:
        w = "budget provenance"
        object.__setattr__(self, "refuted_obligation", c.enum_value(
            Obligation, self.refuted_obligation, f"{w}.refuted_obligation"))
        if self.refuted_obligation is Obligation.IMPLEMENTATION:
            raise c.fail(w, "IMPLEMENTATION cannot be the refutation")
        object.__setattr__(self, "refutation_packet_ids", _ids(
            self.refutation_packet_ids, f"{w}.refutation_packet_ids", non_empty=True))
        exclusions = c.typed_tuple(BudgetExclusion, self.exclusions, f"{w}.exclusions")
        if not exclusions:
            raise c.fail(w, "exclusions must cover every exhausted budget")
        object.__setattr__(self, "exclusions", c.unique(
            exclusions, f"{w}.exclusions", key=lambda x: x.budget_name))

    def to_dict(self) -> dict:
        return {"refuted_obligation": self.refuted_obligation.value,
                "refutation_packet_ids": list(self.refutation_packet_ids),
                "exclusions": [x.to_dict() for x in self.exclusions]}

    @classmethod
    def from_dict(cls, data: Any, where: str = "budget provenance") -> "BudgetProvenance":
        r = c.Reader(data, where, ("refuted_obligation", "refutation_packet_ids", "exclusions"))
        exclusions = tuple(BudgetExclusion.from_dict(x, f"{r.at('exclusions')}[{i}]")
                           for i, x in enumerate(c.sequence(r.get("exclusions"), r.at("exclusions"))))
        return cls(refuted_obligation=r.get("refuted_obligation"),
                   refutation_packet_ids=r.get("refutation_packet_ids"), exclusions=exclusions)


@dataclass(frozen=True)
class Acquisition:
    """How far acquisition got and why it stopped.

    ``frontier`` is ``None`` when the entries were not enumerated in this
    record; ``frontier_size`` is always the true total.
    """

    highest_tier_reached: LadderTier
    stop_reason: StopReason
    tiers_attempted: tuple[LadderTier, ...]
    unresolved_obligations: tuple[Obligation, ...]
    frontier_size: int
    frontier: tuple[FrontierEntry, ...] | None = None
    frontier_truncated: bool | None = None
    budget_exhausted: tuple[BudgetName, ...] = ()
    hops_followed: int | None = None
    hops_declined: int | None = None
    budget_provenance: BudgetProvenance | None = None

    def __post_init__(self) -> None:
        w = "acquisition"
        object.__setattr__(self, "highest_tier_reached", c.enum_value(
            LadderTier, self.highest_tier_reached, f"{w}.highest_tier_reached"))
        object.__setattr__(self, "stop_reason", c.enum_value(StopReason, self.stop_reason, f"{w}.stop_reason"))
        tiers = c.enum_tuple(LadderTier, self.tiers_attempted, f"{w}.tiers_attempted")
        if LadderTier.L8 in tiers:
            raise c.fail(w, "L8 is not a tier that can be attempted")
        object.__setattr__(self, "tiers_attempted", tiers)
        object.__setattr__(self, "unresolved_obligations", c.enum_tuple(
            Obligation, self.unresolved_obligations, f"{w}.unresolved_obligations"))
        c.integer(self.frontier_size, f"{w}.frontier_size")
        if self.frontier is not None:
            object.__setattr__(self, "frontier", c.typed_tuple(FrontierEntry, self.frontier, f"{w}.frontier"))
        c.optional_boolean(self.frontier_truncated, f"{w}.frontier_truncated")
        object.__setattr__(self, "budget_exhausted", c.enum_tuple(
            BudgetName, self.budget_exhausted, f"{w}.budget_exhausted"))
        c.optional_integer(self.hops_followed, f"{w}.hops_followed")
        c.optional_integer(self.hops_declined, f"{w}.hops_declined")
        c.optional_instance(BudgetProvenance, self.budget_provenance, f"{w}.budget_provenance")
        if self.budget_provenance is not None:
            if not self.budget_exhausted:
                raise c.fail(w, "budget provenance without recorded exhaustion")
            if {x.budget_name for x in self.budget_provenance.exclusions} != set(self.budget_exhausted):
                raise c.fail(w, "budget exclusions must cover exactly every exhausted budget")
            for x in self.budget_provenance.exclusions:
                expected = {i for i, edge in enumerate(self.frontier or ())
                            if edge.reason is StopReason.BUDGET_EXHAUSTED and edge.budget_name is x.budget_name}
                if set(x.frontier_indices) != expected:
                    raise c.fail(w, "budget exclusion must cover exactly its exhausted frontier indices")

        if self.frontier is None:
            if self.frontier_truncated is not None:
                raise c.fail(w, "frontier_truncated without an enumerated frontier")
        else:
            listed = len(self.frontier)
            if listed > self.frontier_size:
                raise c.fail(w, f"{listed} frontier entries listed but frontier_size is {self.frontier_size}")
            if listed < self.frontier_size and self.frontier_truncated is not True:
                raise c.fail(w, "a frontier listing fewer entries than its size must be marked truncated")
            if self.frontier_truncated and listed == self.frontier_size:
                raise c.fail(w, "a complete frontier is not truncated")
            for entry in self.frontier:
                if entry.budget_name is not None and entry.budget_name not in self.budget_exhausted:
                    raise c.fail(w, f"frontier entry blames budget {entry.budget_name.value}, "
                                    "which is not recorded as exhausted")
        if self.stop_reason is StopReason.BUDGET_EXHAUSTED and not self.budget_exhausted:
            raise c.fail(w, "BUDGET_EXHAUSTED must name the exhausted budget")
        if not tiers:
            if self.stop_reason is not StopReason.CLAIM_NOT_INVESTIGATED:
                raise c.fail(w, "an investigated claim attempted at least one tier")
            if self.highest_tier_reached is not LadderTier.L0:
                raise c.fail(w, "a claim that attempted no tier reached only L0")
        else:
            if self.stop_reason is StopReason.CLAIM_NOT_INVESTIGATED:
                raise c.fail(w, "an uninvestigated claim attempted no tier")
            top = max(tiers, key=lambda t: t.position)
            if self.highest_tier_reached not in (top, LadderTier.L8):
                raise c.fail(w, f"highest_tier_reached {self.highest_tier_reached.value} does not match "
                                f"the highest tier attempted, {top.value}")

    @property
    def frontier_enumerated_completely(self) -> bool:
        return (self.frontier is not None and not self.frontier_truncated
                and len(self.frontier) == self.frontier_size)

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "highest_tier_reached": self.highest_tier_reached.value,
            "stop_reason": self.stop_reason.value,
            "tiers_attempted": [t.value for t in self.tiers_attempted],
            "unresolved_obligations": [o.value for o in self.unresolved_obligations],
        }
        if self.budget_exhausted:
            out["budget_exhausted"] = [b.value for b in self.budget_exhausted]
        if self.budget_provenance is not None:
            out["budget_provenance"] = self.budget_provenance.to_dict()
        c.put(out, "hops_followed", self.hops_followed)
        c.put(out, "hops_declined", self.hops_declined)
        out["frontier_size"] = self.frontier_size
        if self.frontier is not None:
            out["frontier"] = [e.to_dict() for e in self.frontier]
        c.put(out, "frontier_truncated", self.frontier_truncated)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "acquisition") -> "Acquisition":
        r = c.Reader(data, where, (
            "highest_tier_reached", "stop_reason", "tiers_attempted",
            "unresolved_obligations", "frontier_size"),
            ("budget_exhausted", "hops_followed", "hops_declined", "frontier", "frontier_truncated", "budget_provenance"))
        frontier = None
        if "frontier" in r:
            entries = c.sequence(r.get("frontier"), r.at("frontier"))
            frontier = tuple(FrontierEntry.from_dict(e, f"{r.at('frontier')}[{i}]") for i, e in enumerate(entries))
        return cls(highest_tier_reached=r.get("highest_tier_reached"), stop_reason=r.get("stop_reason"),
                   tiers_attempted=r.get("tiers_attempted"),
                   unresolved_obligations=r.get("unresolved_obligations"),
                   frontier_size=r.get("frontier_size"), frontier=frontier,
                   frontier_truncated=r.get("frontier_truncated"),
                   budget_exhausted=r.get("budget_exhausted", ()),
                   budget_provenance=None if "budget_provenance" not in r else BudgetProvenance.from_dict(
                       r.get("budget_provenance"), r.at("budget_provenance")),
                   hops_followed=r.get("hops_followed"), hops_declined=r.get("hops_declined"))


# ------------------------------------------------- closure, contradiction, etc.


_CLOSURE_FLAGS = (
    "C1_no_opaque_or_dynamic_candidate",
    "C2_refuted_for_every_candidate",
    "C3_no_conflicting_obligation",
    "C4_no_budget_exhausted_on_contributing_path",
    "C5_relevant_frontier_empty",
    "C6_no_error_on_necessary_obligation",
)


@dataclass(frozen=True)
class Closure:
    """C1 to C6 for NO_EFFECT. Every flag is literally true or the object is illegal."""

    refuted_obligation: Obligation
    C1_no_opaque_or_dynamic_candidate: bool = True
    C2_refuted_for_every_candidate: bool = True
    C3_no_conflicting_obligation: bool = True
    C4_no_budget_exhausted_on_contributing_path: bool = True
    C5_relevant_frontier_empty: bool = True
    C6_no_error_on_necessary_obligation: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "refuted_obligation", c.enum_value(
            Obligation, self.refuted_obligation, "closure.refuted_obligation"))
        for flag in _CLOSURE_FLAGS:
            if getattr(self, flag) is not True:
                raise c.fail(f"closure.{flag}", "must be true; if any closure condition fails the verdict is ABSTAIN")

    def to_dict(self) -> dict:
        return {"refuted_obligation": self.refuted_obligation.value, **{f: True for f in _CLOSURE_FLAGS}}

    @classmethod
    def from_dict(cls, data: Any, where: str = "closure") -> "Closure":
        r = c.Reader(data, where, ("refuted_obligation",) + _CLOSURE_FLAGS)
        return cls(refuted_obligation=r.get("refuted_obligation"), **{f: r.get(f) for f in _CLOSURE_FLAGS})


@dataclass(frozen=True)
class PrecedencePath:
    packet_id: str
    binding_packet_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        c.identifier(self.packet_id, "precedence.packet_id")
        object.__setattr__(self, "binding_packet_ids", tuple(c.identifier(x, "precedence.binding_packet_ids")
                           for x in c.sequence(self.binding_packet_ids, "precedence.binding_packet_ids")))

    def to_dict(self) -> dict:
        return {"packet_id": self.packet_id, "binding_packet_ids": list(self.binding_packet_ids)}

    @classmethod
    def from_dict(cls, data: Any, where: str = "precedence path") -> "PrecedencePath":
        r = c.Reader(data, where, ("packet_id", "binding_packet_ids"))
        return cls(r.get("packet_id"), r.get("binding_packet_ids"))


@dataclass(frozen=True)
class ImplementationPrecedence:
    selection_packet_id: str
    winning_paths: tuple[PrecedencePath, ...]

    def __post_init__(self) -> None:
        c.identifier(self.selection_packet_id, "precedence.selection_packet_id")
        paths = c.typed_tuple(PrecedencePath, self.winning_paths, "precedence.winning_paths")
        if not paths:
            raise c.fail("precedence", "every winner requires a body derivation")
        c.unique(paths, "precedence.winning_paths", key=lambda p: p.packet_id)
        object.__setattr__(self, "winning_paths", paths)

    def to_dict(self) -> dict:
        return {"selection_packet_id": self.selection_packet_id,
                "winning_paths": [p.to_dict() for p in self.winning_paths]}

    @classmethod
    def from_dict(cls, data: Any, where: str = "precedence") -> "ImplementationPrecedence":
        r = c.Reader(data, where, ("selection_packet_id", "winning_paths"))
        return cls(r.get("selection_packet_id"), tuple(PrecedencePath.from_dict(p)
                   for p in c.sequence(r.get("winning_paths"), r.at("winning_paths"))))


@dataclass(frozen=True)
class Contradiction:
    """Opposing PROBATIVE packets on one obligation for one candidate."""

    obligation: Obligation
    implementation_candidate_id: str
    positive_packet_ids: tuple[str, ...]
    negative_packet_ids: tuple[str, ...]
    resolution: ContradictionResolution
    overridden_packet_ids: tuple[str, ...] = ()
    precedence: ImplementationPrecedence | None = None

    def __post_init__(self) -> None:
        w = "contradiction"
        object.__setattr__(self, "obligation", c.enum_value(Obligation, self.obligation, f"{w}.obligation"))
        c.identifier(self.implementation_candidate_id, f"{w}.implementation_candidate_id")
        object.__setattr__(self, "positive_packet_ids", _ids(self.positive_packet_ids, f"{w}.positive_packet_ids", non_empty=True))
        object.__setattr__(self, "negative_packet_ids", _ids(self.negative_packet_ids, f"{w}.negative_packet_ids", non_empty=True))
        object.__setattr__(self, "resolution", c.enum_value(ContradictionResolution, self.resolution, f"{w}.resolution"))
        object.__setattr__(self, "overridden_packet_ids", _ids(self.overridden_packet_ids, f"{w}.overridden_packet_ids"))
        if self.obligation is Obligation.IMPLEMENTATION:
            raise c.fail(w, "IMPLEMENTATION is settled by selection, not by opposing packets")
        if set(self.positive_packet_ids) & set(self.negative_packet_ids):
            raise c.fail(w, "a packet cannot be on both sides")
        overridden = set(self.overridden_packet_ids)
        if self.resolution is ContradictionResolution.UNRESOLVED:
            if overridden:
                raise c.fail(w, "an unresolved contradiction overrides nothing")
            if self.precedence is not None:
                raise c.fail(w, "an unresolved contradiction has no precedence resolution")
        elif overridden not in (set(self.positive_packet_ids), set(self.negative_packet_ids)):
            raise c.fail(w, "a resolution overrides exactly one whole side, and says which")
        else:
            c.instance(ImplementationPrecedence, self.precedence, "contradiction.precedence")

    @property
    def winning_polarity(self) -> Polarity | None:
        if self.resolution is ContradictionResolution.UNRESOLVED:
            return None
        if set(self.overridden_packet_ids) == set(self.negative_packet_ids):
            return Polarity.POSITIVE
        return Polarity.NEGATIVE

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "obligation": self.obligation.value,
            "implementation_candidate_id": self.implementation_candidate_id,
            "positive_packet_ids": list(self.positive_packet_ids),
            "negative_packet_ids": list(self.negative_packet_ids),
            "resolution": self.resolution.value,
        }
        if self.overridden_packet_ids:
            out["overridden_packet_ids"] = list(self.overridden_packet_ids)
        c.put(out, "precedence", self.precedence and self.precedence.to_dict())
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "contradiction") -> "Contradiction":
        r = c.Reader(data, where, ("obligation", "implementation_candidate_id", "positive_packet_ids",
                                   "negative_packet_ids", "resolution"), ("overridden_packet_ids", "precedence"))
        return cls(obligation=r.get("obligation"),
                   implementation_candidate_id=r.get("implementation_candidate_id"),
                   positive_packet_ids=r.get("positive_packet_ids"),
                   negative_packet_ids=r.get("negative_packet_ids"),
                   resolution=r.get("resolution"),
                   overridden_packet_ids=r.get("overridden_packet_ids", ()),
                   precedence=None if "precedence" not in r else ImplementationPrecedence.from_dict(r.get("precedence")))


def check_contradictions(contradictions: tuple, packets_by_id: dict, candidates: frozenset,
                         selection: SelectionState, where: str, *, invocation_id: str,
                         invocation_locator: SourceLocator) -> dict:
    """Structural checks shared by claims and receipts. Returns (obligation, candidate) -> record."""
    by_candidate = {cand.candidate_id: cand for cand in candidates}
    by_key: dict = {}
    for k in contradictions:
        key = (k.obligation, k.implementation_candidate_id)
        if key in by_key:
            raise c.fail(where, f"two contradiction records for {k.obligation.value} on {key[1]!r}")
        cand = by_candidate.get(k.implementation_candidate_id)
        if cand is None:
            raise c.fail(where, f"contradiction names unknown candidate {key[1]!r}")
        for ids, polarity in ((k.positive_packet_ids, Polarity.POSITIVE), (k.negative_packet_ids, Polarity.NEGATIVE)):
            for pid in ids:
                p = packets_by_id.get(pid)
                if p is None:
                    raise c.fail(where, f"contradiction cites unknown packet {pid!r}; evidence is never discarded")
                if (p.obligation, p.implementation_candidate_id, p.polarity) != (k.obligation, key[1], polarity) \
                        or not p.is_probative or p.assertion.predicate in UNCERTAINTY_PREDICATES:
                    raise c.fail(where, f"packet {pid!r} is not {polarity.value} PROBATIVE evidence on "
                                        f"{k.obligation.value} for {key[1]!r}")
        if k.resolution is ContradictionResolution.RESOLVED_IMPLEMENTATION_PRECEDENCE:
            _check_precedence(k, cand, selection, packets_by_id, where, invocation_id, invocation_locator)
        by_key[key] = k
    return by_key


_BODY_KINDS = frozenset({PacketKind.LOCAL_FUNCTION_BODY, PacketKind.WRAPPER_CHAIN_BODY, PacketKind.DEPENDENCY_SOURCE_BODY})
_CONTRACT_KINDS = frozenset({PacketKind.OPENAPI_OPERATION, PacketKind.PROTOBUF_SERVICE_METHOD,
    PacketKind.GRAPHQL_SCHEMA_FIELD, PacketKind.JSON_SCHEMA_NODE, PacketKind.SDK_OPERATION_METADATA,
    PacketKind.COMMAND_SPECIFICATION})


def _binding_matches(packet, candidate_id, invocation_id, relation, source, target=None):
    b = packet.binding if packet is not None else None
    return (b is not None and packet.is_probative and packet.obligation is Obligation.IMPLEMENTATION
            and packet.implementation_candidate_id == candidate_id and b.invocation_id == invocation_id
            and b.relation == relation and b.source == source and (target is None or b.target == target))


def _contains(body: SourceLocator, evidence: SourceLocator) -> bool:
    return (all(getattr(body, k) == getattr(evidence, k) for k in ("path", "package", "version", "version_resolution"))
            and body.start_line <= evidence.start_line <= evidence.end_line <= body.end_line
            and (body.start_column is None or evidence.start_line != body.start_line
                 or (evidence.start_column is not None and evidence.start_column >= body.start_column))
            and (body.end_column is None or evidence.end_line != body.end_line
                 or (evidence.end_column is not None and evidence.end_column <= body.end_column)))


def _check_precedence(k: Contradiction, cand: ImplementationCandidate, selection: SelectionState,
                      packets_by_id: dict, where: str, invocation_id: str,
                      invocation_locator: SourceLocator) -> None:
    if selection is not SelectionState.SINGLE_ESTABLISHED:
        raise c.fail(where, "resolved-implementation precedence applies only under SINGLE_ESTABLISHED")
    if cand.kind not in RESOLVED_CANDIDATE_KINDS or cand.locator is None:
        raise c.fail(where, f"precedence needs a resolved body; candidate is {cand.kind.value}")
    proof = k.precedence
    if not _binding_matches(packets_by_id.get(proof.selection_packet_id), cand.candidate_id,
                            invocation_id, "SELECTED_TARGET", invocation_locator, cand.locator):
        raise c.fail(where, "precedence requires selected-body binding provenance")
    overridden = set(k.overridden_packet_ids)
    winners = [pid for pid in k.positive_packet_ids + k.negative_packet_ids if pid not in overridden]
    if {p.packet_id for p in proof.winning_paths} != set(winners):
        raise c.fail(where, "precedence requires a path for every winning packet")
    for path in proof.winning_paths:
        winner = packets_by_id[path.packet_id]
        if winner.kind not in _BODY_KINDS:
            raise c.fail(where, "tier/package provenance is not selected-body evidence")
        body = cand.locator
        for pid in path.binding_packet_ids:
            edge = packets_by_id.get(pid)
            if not _binding_matches(edge, cand.candidate_id, invocation_id, "RESOLVED_CALL", body):
                raise c.fail(where, "precedence body derivation requires resolved-call binding provenance")
            body = edge.binding.target
        if not _contains(body, winner.locator):
            raise c.fail(where, "winning evidence is outside the selected/linked body source")
    for pid in k.overridden_packet_ids:
        if packets_by_id[pid].tier is not LadderTier.L6 or packets_by_id[pid].kind not in _CONTRACT_KINDS:
            raise c.fail(where, f"only contract-declared evidence can be overridden; {pid!r} is "
                                f"{packets_by_id[pid].tier.value}")


@dataclass(frozen=True)
class Priority:
    """Investigation order only. Never changes a verdict."""

    rank: int
    policy_id: str
    hypothesis_signals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        c.integer(self.rank, "priority.rank")
        c.text(self.policy_id, "priority.policy_id", min_length=0)
        signals = tuple(c.text(s, "priority.hypothesis_signals", min_length=0)
                        for s in c.sequence(self.hypothesis_signals, "priority.hypothesis_signals"))
        object.__setattr__(self, "hypothesis_signals", signals)

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"rank": self.rank, "policy_id": self.policy_id}
        if self.hypothesis_signals:
            out["hypothesis_signals"] = list(self.hypothesis_signals)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "priority") -> "Priority":
        r = c.Reader(data, where, ("rank", "policy_id"), ("hypothesis_signals",))
        return cls(rank=r.get("rank"), policy_id=r.get("policy_id"),
                   hypothesis_signals=r.get("hypothesis_signals", ()))


# ------------------------------------------------------------------ the claim


@dataclass(frozen=True)
class EffectClaim:
    """One invocation, one effect class, a set of implementations and an evidentiary record.

    Identity is ``(capability_id, invocation_id, effect_class)``. No rule id
    participates in identity or existence.
    """

    claim_id: str
    capability_id: str
    invocation_id: str
    effect_class: EffectClass
    invocation: Invocation
    genesis: Genesis
    implementation_candidates: frozenset
    selection_state: SelectionState
    obligations: ObligationStates
    descriptors: Descriptors
    acquisition: Acquisition
    verdict: Verdict
    evidence_packets: tuple[EvidencePacket, ...] = ()
    probe_outcomes: tuple[ProbeOutcome, ...] = ()
    contradictions: tuple[Contradiction, ...] = ()
    closure: Closure | None = None
    verdict_rationale: str | None = None
    priority: Priority | None = None
    receipt_id: str | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        w = f"claim {self.claim_id!r}"
        if self.schema_version != SCHEMA_VERSION:
            raise c.fail(w, f"schema_version must be {SCHEMA_VERSION}")
        for name in ("claim_id", "capability_id", "invocation_id"):
            c.identifier(getattr(self, name), f"{w}.{name}")
        c.optional_identifier(self.receipt_id, f"{w}.receipt_id")
        object.__setattr__(self, "effect_class", c.enum_value(EffectClass, self.effect_class, f"{w}.effect_class"))
        object.__setattr__(self, "selection_state", c.enum_value(SelectionState, self.selection_state, f"{w}.selection_state"))
        object.__setattr__(self, "verdict", c.enum_value(Verdict, self.verdict, f"{w}.verdict"))
        c.instance(Invocation, self.invocation, f"{w}.invocation")
        c.instance(Genesis, self.genesis, f"{w}.genesis")
        c.instance(ObligationStates, self.obligations, f"{w}.obligations")
        c.instance(Descriptors, self.descriptors, f"{w}.descriptors")
        c.instance(Acquisition, self.acquisition, f"{w}.acquisition")
        c.optional_instance(Closure, self.closure, f"{w}.closure")
        c.optional_instance(Priority, self.priority, f"{w}.priority")
        c.optional_text(self.verdict_rationale, f"{w}.verdict_rationale")
        object.__setattr__(self, "implementation_candidates",
                           candidate_set(self.implementation_candidates, f"{w}.implementation_candidates"))
        object.__setattr__(self, "evidence_packets", c.typed_tuple(EvidencePacket, self.evidence_packets, f"{w}.evidence_packets"))
        object.__setattr__(self, "probe_outcomes", c.typed_tuple(ProbeOutcome, self.probe_outcomes, f"{w}.probe_outcomes"))
        object.__setattr__(self, "contradictions", c.typed_tuple(Contradiction, self.contradictions, f"{w}.contradictions"))
        _validate_claim(self, w)

    # -- read-only views; there is deliberately no positional candidate access

    @property
    def identity(self) -> tuple[str, str, EffectClass]:
        return (self.capability_id, self.invocation_id, self.effect_class)

    @property
    def candidate_ids(self) -> frozenset:
        return frozenset(cand.candidate_id for cand in self.implementation_candidates)

    def candidate(self, candidate_id: str) -> ImplementationCandidate:
        for cand in self.implementation_candidates:
            if cand.candidate_id == candidate_id:
                return cand
        raise KeyError(candidate_id)

    def selected_candidate(self) -> ImplementationCandidate | None:
        """The candidate that runs, when and only when selection is SINGLE_ESTABLISHED."""
        if self.selection_state is not SelectionState.SINGLE_ESTABLISHED:
            return None
        (only,) = self.implementation_candidates
        return only

    def candidate_states(self, candidate_id: str) -> ObligationStates:
        cand = self.candidate(candidate_id)
        return cand.obligations if cand.obligations is not None else self.obligations

    def packets_for(self, obligation: Obligation, candidate_id: str | None = None) -> tuple[EvidencePacket, ...]:
        return tuple(p for p in self.evidence_packets if p.obligation is obligation
                     and (candidate_id is None or p.implementation_candidate_id == candidate_id))

    @property
    def necessary_obligations(self) -> tuple[Obligation, ...]:
        return NECESSARY_OBLIGATIONS[self.effect_class]

    @property
    def was_investigated(self) -> bool:
        return self.acquisition.stop_reason is not StopReason.CLAIM_NOT_INVESTIGATED

    @property
    def overridden_packet_ids(self) -> frozenset:
        return frozenset(pid for k in self.contradictions for pid in k.overridden_packet_ids)

    # -- serialisation

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "capability_id": self.capability_id,
            "invocation_id": self.invocation_id,
            "effect_class": self.effect_class.value,
            "invocation": self.invocation.to_dict(),
            "genesis": self.genesis.to_dict(),
            "implementation_candidates": sorted_candidates(self.implementation_candidates),
            "selection_state": self.selection_state.value,
            "obligations": self.obligations.to_dict(),
            "descriptors": self.descriptors.to_dict(),
            "evidence_packets": [p.to_dict() for p in self.evidence_packets],
            "probe_outcomes": [o.to_dict() for o in self.probe_outcomes],
            "contradictions": [k.to_dict() for k in self.contradictions],
        }
        c.put(out, "closure", self.closure and self.closure.to_dict())
        out["acquisition"] = self.acquisition.to_dict()
        out["verdict"] = self.verdict.value
        c.put(out, "verdict_rationale", self.verdict_rationale)
        c.put(out, "priority", self.priority and self.priority.to_dict())
        c.put(out, "receipt_id", self.receipt_id)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "claim") -> "EffectClaim":
        if isinstance(data, Mapping) and "schema_version" in data and data["schema_version"] != SCHEMA_VERSION:
            raise c.fail(where, f"schema_version must be {SCHEMA_VERSION}; historical records are not migrated")
        r = c.Reader(data, where, (
            "schema_version", "claim_id", "capability_id", "invocation_id", "effect_class",
            "invocation", "genesis", "implementation_candidates", "selection_state", "obligations",
            "descriptors", "evidence_packets", "probe_outcomes", "acquisition", "verdict"),
            ("contradictions", "closure", "verdict_rationale", "priority", "receipt_id"))

        def many(key, parse):
            items = c.sequence(r.get(key, ()), r.at(key))
            return tuple(parse(item, f"{r.at(key)}[{i}]") for i, item in enumerate(items))

        return cls(
            schema_version=r.get("schema_version"),
            claim_id=r.get("claim_id"),
            capability_id=r.get("capability_id"),
            invocation_id=r.get("invocation_id"),
            effect_class=r.get("effect_class"),
            invocation=Invocation.from_dict(r.get("invocation"), r.at("invocation")),
            genesis=Genesis.from_dict(r.get("genesis"), r.at("genesis")),
            implementation_candidates=many("implementation_candidates", ImplementationCandidate.from_dict),
            selection_state=r.get("selection_state"),
            obligations=ObligationStates.from_dict(r.get("obligations"), r.at("obligations")),
            descriptors=Descriptors.from_dict(r.get("descriptors"), r.at("descriptors")),
            evidence_packets=many("evidence_packets", EvidencePacket.from_dict),
            probe_outcomes=many("probe_outcomes", ProbeOutcome.from_dict),
            contradictions=many("contradictions", Contradiction.from_dict),
            closure=None if "closure" not in r else Closure.from_dict(r.get("closure"), r.at("closure")),
            acquisition=Acquisition.from_dict(r.get("acquisition"), r.at("acquisition")),
            verdict=r.get("verdict"),
            verdict_rationale=r.get("verdict_rationale"),
            priority=None if "priority" not in r else Priority.from_dict(r.get("priority"), r.at("priority")),
            receipt_id=r.get("receipt_id"),
        )


# ------------------------------------------------------------- claim checking


def _validate_claim(claim: EffectClaim, w: str) -> None:
    candidates = claim.implementation_candidates
    selection = claim.selection_state
    check_selection_cardinality(selection, candidates, w)
    if any(cand.obligations is None for cand in candidates) and not (
            len(candidates) == 1 and selection is SelectionState.SINGLE_ESTABLISHED):
        raise c.fail(w, "every candidate carries its own obligation states except the unique established shorthand")
    effective = {cand.candidate_id: claim.candidate_states(cand.candidate_id) for cand in candidates}
    check_candidate_states(selection, effective, claim.obligations, w)
    packets = check_packet_set(claim.evidence_packets, claim.candidate_ids, w)
    probes = check_probe_set(claim.probe_outcomes, packets, w)
    records = check_contradictions(claim.contradictions, packets, candidates, selection, w,
                                  invocation_id=claim.invocation_id, invocation_locator=claim.invocation.locator)
    check_states_against_packets(claim.evidence_packets, effective, records, w,
                                candidates=candidates, invocation_id=claim.invocation_id,
                                invocation_locator=claim.invocation.locator)
    impl = [states.implementation for states in effective.values()]
    if _E in impl:
        expected = SelectionState.SELECTION_ERROR
    elif any(state is not _S for state in impl):
        expected = SelectionState.UNRESOLVED_IDENTITY
    elif len(candidates) == 1:
        (only,) = candidates
        selected = any(_binding_matches(p, only.candidate_id, claim.invocation_id,
                       "SELECTED_TARGET", claim.invocation.locator, only.locator) for p in claim.evidence_packets)
        expected = SelectionState.SINGLE_ESTABLISHED if selected else SelectionState.UNRESOLVED_IDENTITY
    elif all(len({states[o] for states in effective.values()}) == 1 for o in EVIDENCE_OBLIGATIONS):
        expected = SelectionState.AGREEMENT_INVARIANT
    else:
        expected = SelectionState.UNRESOLVED_DIVERGENT
    if selection is not expected:
        raise c.fail(w, f"selection requires {expected.value}, not {selection.value}; labels are not evidence")
    _check_acquisition(claim, packets, w)
    _check_budget_provenance(claim, w)
    _check_verdict(claim, effective, probes, w)


def check_candidate_states(selection: SelectionState, effective: dict, states: ObligationStates, w: str) -> None:
    expected = aggregate_claim_states(selection, effective.values())
    for o in Obligation:
        if states[o] is not expected[o]:
            raise c.fail(w, f"claim-level {o.value} is {states[o].value} but candidates aggregate to {expected[o].value}")


def check_states_against_packets(packets: tuple, effective: dict, records: dict, w: str, *,
                                candidates: frozenset, invocation_id: str, invocation_locator: SourceLocator) -> None:
    """Typed facts, not selection labels, determine every candidate obligation."""
    by_candidate = {cand.candidate_id: cand for cand in candidates}
    for cand_id, cand_states in effective.items():
        cand = by_candidate[cand_id]
        if cand.kind in OPAQUE_CANDIDATE_KINDS and cand_states.implementation not in (_U, _E):
            raise c.fail(w, "opaque/unresolved identity cannot be implementation-supported")
        for o in Obligation:
            state = cand_states[o]
            where = f"{w}: {o.value} for {cand_id!r}"
            probative = [p for p in packets if p.obligation is o and p.implementation_candidate_id == cand_id and p.is_probative]
            uncertain = any(p.assertion.predicate in UNCERTAINTY_PREDICATES for p in probative)
            directional = [p for p in probative if p.assertion.predicate not in UNCERTAINTY_PREDICATES]
            if o is Obligation.IMPLEMENTATION:
                directional = [p for p in directional if cand.locator is not None and any(
                    _binding_matches(p, cand_id, invocation_id, rel, invocation_locator, cand.locator)
                    for rel in ("SELECTED_TARGET", "POSSIBLE_TARGET"))]
            pos = {p.packet_id for p in directional if p.polarity is Polarity.POSITIVE}
            neg = {p.packet_id for p in directional if p.polarity is Polarity.NEGATIVE}
            record = records.get((o, cand_id))
            if pos and neg:
                if record is None or (set(record.positive_packet_ids), set(record.negative_packet_ids)) != (pos, neg):
                    raise c.fail(where, "contradiction must cite every opposing PROBATIVE packet")
            elif record is not None:
                raise c.fail(where, "a contradiction record needs opposing evidence")
            winner = record.winning_polarity if record is not None else None
            if state is _E:
                expected = _E
            elif pos and neg and winner is None:
                expected = _C
            elif uncertain:
                expected = _U
            elif winner is not None:
                expected = _S if winner is Polarity.POSITIVE else _R
            elif pos:
                expected = _S
            elif neg:
                expected = _R
            else:
                expected = _U
            if state is not expected:
                raise c.fail(where, f"PROBATIVE evidence requires {expected.value}, recorded {state.value}")


def _check_acquisition(claim: EffectClaim, packets: dict, w: str) -> None:
    acq = claim.acquisition
    states = claim.obligations
    necessary = claim.necessary_obligations
    for o in acq.unresolved_obligations:
        if o not in necessary:
            raise c.fail(w, f"{o.value} is not a necessary obligation of {claim.effect_class.value}")
        if states[o] in (_S, _R):
            raise c.fail(w, f"{o.value} is {states[o].value} and cannot be listed as unresolved")
    for o in necessary:
        if states[o] in (_U, _C) and o not in acq.unresolved_obligations:
            raise c.fail(w, f"{o.value} is UNKNOWN and must be listed as unresolved")
    if acq.stop_reason is StopReason.SETTLED and any(states[o] in (_U, _E) for o in necessary):
        raise c.fail(w, "SETTLED means every necessary obligation is SUPPORTED, REFUTED or CONFLICTING")
    attempted = set(acq.tiers_attempted)
    for p in packets.values():
        if p.tier not in attempted:
            raise c.fail(w, f"packet {p.packet_id!r} came from tier {p.tier.value}, which was not attempted")
    if not claim.was_investigated:
        if claim.evidence_packets or claim.probe_outcomes or claim.contradictions:
            raise c.fail(w, "an uninvestigated claim has no evidence, probes or contradictions")
        if claim.verdict is not Verdict.ABSTAIN:
            raise c.fail(w, "an uninvestigated claim can only ABSTAIN; it is never a negative result")


def _check_budget_provenance(claim: EffectClaim, w: str) -> None:
    """Validate supplied provenance links on any verdict; never infer witness truth."""
    proof = claim.acquisition.budget_provenance
    if proof is None:
        return
    o = proof.refuted_obligation
    if claim.closure is not None and claim.closure.refuted_obligation is not o:
        raise c.fail(w, "budget provenance must link to the same closure refutation")
    settling = [p for p in claim.packets_for(o) if p.polarity is Polarity.NEGATIVE
                and p.is_probative and p.packet_id not in claim.overridden_packet_ids
                and p.assertion.predicate not in UNCERTAINTY_PREDICATES]
    if set(proof.refutation_packet_ids) != {p.packet_id for p in settling}:
        raise c.fail(w, "budget provenance must cite exactly the retained settling-negative refutation packets")
    if {p.implementation_candidate_id for p in settling} != claim.candidate_ids:
        raise c.fail(w, "budget provenance must cover the refutation for every candidate")


def _check_verdict(claim: EffectClaim, effective: dict, probes: dict, w: str) -> None:
    """The recorded verdict must be the one the frozen verdict function yields."""
    states = claim.obligations
    necessary = claim.necessary_obligations
    verdict = claim.verdict

    if any(states[o] is _E for o in necessary):
        if verdict is not Verdict.ANALYSIS_ERROR:
            raise c.fail(w, f"an ERROR on a necessary obligation is ANALYSIS_ERROR, never {verdict.value}")
    elif verdict is Verdict.ANALYSIS_ERROR:
        raise c.fail(w, "ANALYSIS_ERROR requires an ERROR on a necessary obligation")

    if verdict is not Verdict.ANALYSIS_ERROR:
        proven_blockers = _proven_effect_blockers(claim, probes)
        if verdict is Verdict.PROVEN_EFFECT and proven_blockers:
            raise c.fail(w, "PROVEN_EFFECT is not established: " + "; ".join(proven_blockers))
        if verdict is not Verdict.PROVEN_EFFECT and not proven_blockers:
            raise c.fail(w, f"every PROVEN_EFFECT condition holds, so {verdict.value} is not the verdict")

    if verdict is Verdict.NO_EFFECT:
        _check_closure(claim, effective, w)
    elif claim.closure is not None:
        raise c.fail(w, "a closure record is only legal on a NO_EFFECT claim")


def _proven_effect_blockers(claim: EffectClaim, probes: dict) -> list[str]:
    reasons = []
    if claim.selection_state not in ESTABLISHED_SELECTIONS:
        reasons.append(f"selection is {claim.selection_state.value}")
    for o in claim.necessary_obligations:
        if claim.obligations[o] is not _S:
            reasons.append(f"{o.value} is {claim.obligations[o].value}")
    for pid in BLOCKING_PROBE_IDS:
        outcome = probes.get(pid)
        if outcome is None:
            reasons.append(f"BLOCKING probe {pid} was not executed")
        elif not outcome.completed:
            reasons.append(f"BLOCKING probe {pid} is INCOMPLETE")

    return reasons


def _check_closure(claim: EffectClaim, effective: dict, w: str) -> None:
    closure = claim.closure
    if closure is None:
        raise c.fail(w, "NO_EFFECT requires an established closure C1 to C6")
    o = closure.refuted_obligation
    if o is Obligation.IMPLEMENTATION or o not in claim.necessary_obligations:
        raise c.fail(w, f"{o.value} cannot be the refuted necessary obligation")
    if claim.obligations[o] is not _R:
        raise c.fail(w, f"closure names {o.value}, which is {claim.obligations[o].value}, not REFUTED")
    if any(cand.kind in OPAQUE_CANDIDATE_KINDS for cand in claim.implementation_candidates):
        raise c.fail(w, "C1 fails: a negative cannot be proved about code that was never obtained")
    if any(states[o] is not _R for states in effective.values()):
        raise c.fail(w, "C2 fails: the refutation must hold for every candidate")
    if any(claim.obligations[x] is _C for x in claim.necessary_obligations) or any(
            k.resolution is ContradictionResolution.UNRESOLVED for k in claim.contradictions):
        raise c.fail(w, "C3 fails: a necessary obligation is CONFLICTING")
    acq = claim.acquisition
    if acq.budget_exhausted and acq.budget_provenance is None:
        raise c.fail(w, "C4 requires budget exclusion provenance for recorded exhaustion")
    if not acq.frontier_enumerated_completely:
        raise c.fail(w, "C5 cannot be established without the complete frontier")
    if any(entry.is_relevant_to(o) for entry in acq.frontier):
        raise c.fail(w, f"C5 fails: an unopened edge might settle {o.value}")
