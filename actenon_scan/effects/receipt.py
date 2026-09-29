"""EffectReceipt: the auditable artefact for every verdict, including ABSTAIN.

Frozen by ``specs/AREF-002/effect_receipt.schema.json``. A receipt answers all
eleven questions, carries every packet the verdict rests on (including
overridden and negative packets) and every probe outcome, and never licenses
rendering the result as "safe".
"""

from __future__ import annotations

from collections.abc import Mapping

from dataclasses import dataclass
from typing import Any

from actenon_scan.effects import _codec as c
from actenon_scan.effects.claim import (
    Acquisition,
    Authority,
    Contradiction,
    Control,
    Closure,
    EffectClaim,
    FrontierEntry,
    ImplementationCandidate,
    Target,
    candidate_set,
    check_selection_cardinality,
    _validate_claim,
    sorted_candidates,
)
from actenon_scan.effects.evidence import EvidencePacket, ProbeOutcome
from actenon_scan.effects.vocabulary import (
    BLOCKING_PROBE_IDS,
    EVIDENCE_OBLIGATIONS,
    PROBE_REGISTRY,
    RECEIPT_ANSWER_KEYS,
    SCHEMA_VERSION,
    UNCERTAINTY_PREDICATES,
    BudgetName,
    EffectClass,
    LadderTier,
    Obligation,
    Polarity,
    ProbeClass,
    ProbeResult,
    ProofState,
    SelectionState,
    StopReason,
    Verdict,
)

_S, _R, _U, _C, _E = (ProofState.SUPPORTED, ProofState.REFUTED, ProofState.UNKNOWN,
                      ProofState.CONFLICTING, ProofState.ERROR)


@dataclass(frozen=True)
class EffectAnswer:
    effect_class: EffectClass
    verdict: Verdict
    statement: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "effect_class", c.enum_value(EffectClass, self.effect_class, "answers.effect.effect_class"))
        object.__setattr__(self, "verdict", c.enum_value(Verdict, self.verdict, "answers.effect.verdict"))
        c.text(self.statement, "answers.effect.statement")

    def to_dict(self) -> dict:
        return {"effect_class": self.effect_class.value, "verdict": self.verdict.value, "statement": self.statement}

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "EffectAnswer":
        r = c.Reader(data, where, ("effect_class", "verdict", "statement"))
        return cls(effect_class=r.get("effect_class"), verdict=r.get("verdict"), statement=r.get("statement"))


@dataclass(frozen=True)
class ImplementationAnswer:
    selection_state: SelectionState
    candidates: frozenset
    selected_candidate_id: str | None = None

    def __post_init__(self) -> None:
        w = "answers.implementation"
        object.__setattr__(self, "selection_state", c.enum_value(SelectionState, self.selection_state, f"{w}.selection_state"))
        object.__setattr__(self, "candidates", candidate_set(self.candidates, f"{w}.candidates"))
        c.optional_identifier(self.selected_candidate_id, f"{w}.selected_candidate_id")
        check_selection_cardinality(self.selection_state, self.candidates, w)
        if self.selected_candidate_id is not None:
            if self.selection_state is not SelectionState.SINGLE_ESTABLISHED:
                raise c.fail(w, f"no candidate is selected under {self.selection_state.value}")
            (only,) = self.candidates
            if only.candidate_id != self.selected_candidate_id:
                raise c.fail(w, "the selected candidate is not the established candidate")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"selection_state": self.selection_state.value,
                               "candidates": sorted_candidates(self.candidates)}
        c.put(out, "selected_candidate_id", self.selected_candidate_id)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "ImplementationAnswer":
        r = c.Reader(data, where, ("selection_state", "candidates"), ("selected_candidate_id",))
        items = c.sequence(r.get("candidates"), r.at("candidates"))
        return cls(selection_state=r.get("selection_state"),
                   candidates=tuple(ImplementationCandidate.from_dict(x, f"{r.at('candidates')}[{i}]")
                                    for i, x in enumerate(items)),
                   selected_candidate_id=r.get("selected_candidate_id"))


@dataclass(frozen=True)
class ObligationAnswer:
    state: ProofState
    settled_by_packet_ids: tuple[str, ...] = ()
    mechanism: str | None = None
    settled_at_tier: LadderTier | None = None
    error_detail: str | None = None

    def __post_init__(self) -> None:
        w = "obligation answer"
        object.__setattr__(self, "state", c.enum_value(ProofState, self.state, f"{w}.state"))
        ids = tuple(c.identifier(x, f"{w}.settled_by_packet_ids")
                    for x in c.sequence(self.settled_by_packet_ids, f"{w}.settled_by_packet_ids"))
        object.__setattr__(self, "settled_by_packet_ids", c.unique(ids, f"{w}.settled_by_packet_ids"))
        c.optional_text(self.mechanism, f"{w}.mechanism")
        object.__setattr__(self, "settled_at_tier", c.optional_enum(LadderTier, self.settled_at_tier, f"{w}.settled_at_tier"))
        c.optional_text(self.error_detail, f"{w}.error_detail")
        if self.state is _U and self.settled_by_packet_ids:
            raise c.fail(w, "an UNKNOWN obligation cannot have been settled by anything")
        if self.state in (_S, _R) and not self.settled_by_packet_ids:
            raise c.fail(w, f"a {self.state.value} obligation must name the PROBATIVE packets that settled it")
        if self.state in (_U, _E) and self.mechanism is not None:
            raise c.fail(w, f"no mechanism is established for a {self.state.value} obligation")
        if self.error_detail is not None and self.state is not _E:
            raise c.fail(w, "error_detail belongs to an ERROR obligation only")
        if self.settled_at_tier is not None and self.state not in (_S, _R):
            raise c.fail(w, f"a {self.state.value} obligation was not settled at any tier")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"state": self.state.value}
        c.put(out, "mechanism", self.mechanism)
        out["settled_by_packet_ids"] = list(self.settled_by_packet_ids)
        c.put(out, "settled_at_tier", self.settled_at_tier and self.settled_at_tier.value)
        c.put(out, "error_detail", self.error_detail)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "ObligationAnswer":
        r = c.Reader(data, where, ("state", "settled_by_packet_ids"), ("mechanism", "settled_at_tier", "error_detail"))
        return cls(state=r.get("state"), settled_by_packet_ids=r.get("settled_by_packet_ids"),
                   mechanism=r.get("mechanism"), settled_at_tier=r.get("settled_at_tier"),
                   error_detail=r.get("error_detail"))


@dataclass(frozen=True)
class ContradictionsAnswer:
    contradictions: tuple[Contradiction, ...]
    counter_evidence_found: tuple[ProbeOutcome, ...]
    blocking_probes_incomplete: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        w = "answers.contradictions"
        object.__setattr__(self, "contradictions", c.typed_tuple(Contradiction, self.contradictions, f"{w}.contradictions"))
        object.__setattr__(self, "counter_evidence_found", c.typed_tuple(
            ProbeOutcome, self.counter_evidence_found, f"{w}.counter_evidence_found"))
        if self.blocking_probes_incomplete is not None:
            ids = tuple(c.text(x, f"{w}.blocking_probes_incomplete")
                        for x in c.sequence(self.blocking_probes_incomplete, f"{w}.blocking_probes_incomplete"))
            object.__setattr__(self, "blocking_probes_incomplete", c.unique(ids, f"{w}.blocking_probes_incomplete"))
            for pid in ids:
                spec = PROBE_REGISTRY.get(pid)
                if spec is None or spec.probe_class is not ProbeClass.BLOCKING:
                    raise c.fail(w, f"{pid!r} is not a registered BLOCKING probe")
        for o in self.counter_evidence_found:
            if o.outcome is not ProbeResult.FOUND:
                raise c.fail(w, f"probe {o.probe_id} is {o.outcome.value}, which is not counter-evidence found")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"contradictions": [k.to_dict() for k in self.contradictions],
                               "counter_evidence_found": [o.to_dict() for o in self.counter_evidence_found]}
        if self.blocking_probes_incomplete is not None:
            out["blocking_probes_incomplete"] = list(self.blocking_probes_incomplete)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "ContradictionsAnswer":
        r = c.Reader(data, where, ("contradictions", "counter_evidence_found"), ("blocking_probes_incomplete",))
        ks = c.sequence(r.get("contradictions"), r.at("contradictions"))
        found = c.sequence(r.get("counter_evidence_found"), r.at("counter_evidence_found"))
        return cls(contradictions=tuple(Contradiction.from_dict(k, f"{r.at('contradictions')}[{i}]") for i, k in enumerate(ks)),
                   counter_evidence_found=tuple(ProbeOutcome.from_dict(o, f"{r.at('counter_evidence_found')}[{i}]")
                                                for i, o in enumerate(found)),
                   blocking_probes_incomplete=r.get("blocking_probes_incomplete"))


@dataclass(frozen=True)
class UnknownsAnswer:
    unresolved_obligations: tuple[Obligation, ...]
    highest_tier_reached: LadderTier
    stop_reason: StopReason
    frontier_size: int
    budget_exhausted: tuple[BudgetName, ...] | None = None
    frontier: tuple[FrontierEntry, ...] | None = None

    def __post_init__(self) -> None:
        w = "answers.unknowns"
        object.__setattr__(self, "unresolved_obligations", c.enum_tuple(
            Obligation, self.unresolved_obligations, f"{w}.unresolved_obligations"))
        object.__setattr__(self, "highest_tier_reached", c.enum_value(LadderTier, self.highest_tier_reached, f"{w}.highest_tier_reached"))
        object.__setattr__(self, "stop_reason", c.enum_value(StopReason, self.stop_reason, f"{w}.stop_reason"))
        c.integer(self.frontier_size, f"{w}.frontier_size")
        if self.budget_exhausted is not None:
            object.__setattr__(self, "budget_exhausted", c.enum_tuple(BudgetName, self.budget_exhausted, f"{w}.budget_exhausted"))
        if self.frontier is not None:
            object.__setattr__(self, "frontier", c.typed_tuple(FrontierEntry, self.frontier, f"{w}.frontier"))
            if len(self.frontier) > self.frontier_size:
                raise c.fail(w, "more frontier entries listed than frontier_size")

    @classmethod
    def from_acquisition(cls, acq: Acquisition) -> "UnknownsAnswer":
        return cls(unresolved_obligations=acq.unresolved_obligations,
                   highest_tier_reached=acq.highest_tier_reached, stop_reason=acq.stop_reason,
                   frontier_size=acq.frontier_size, budget_exhausted=acq.budget_exhausted or None,
                   frontier=acq.frontier)

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"unresolved_obligations": [o.value for o in self.unresolved_obligations],
                               "highest_tier_reached": self.highest_tier_reached.value,
                               "stop_reason": self.stop_reason.value}
        if self.budget_exhausted is not None:
            out["budget_exhausted"] = [b.value for b in self.budget_exhausted]
        out["frontier_size"] = self.frontier_size
        if self.frontier is not None:
            out["frontier"] = [e.to_dict() for e in self.frontier]
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "UnknownsAnswer":
        r = c.Reader(data, where, ("unresolved_obligations", "highest_tier_reached", "stop_reason", "frontier_size"),
                     ("budget_exhausted", "frontier"))
        frontier = None
        if "frontier" in r:
            entries = c.sequence(r.get("frontier"), r.at("frontier"))
            frontier = tuple(FrontierEntry.from_dict(e, f"{r.at('frontier')}[{i}]") for i, e in enumerate(entries))
        return cls(unresolved_obligations=r.get("unresolved_obligations"),
                   highest_tier_reached=r.get("highest_tier_reached"), stop_reason=r.get("stop_reason"),
                   frontier_size=r.get("frontier_size"), budget_exhausted=r.get("budget_exhausted"),
                   frontier=frontier)


@dataclass(frozen=True)
class Answers:
    """The eleven questions of requirement 16. Every key is always present."""

    effect: EffectAnswer
    implementation: ImplementationAnswer
    resource: Target
    activation: ObligationAnswer
    boundary: ObligationAnswer
    operation: ObligationAnswer
    persistence: ObligationAnswer
    control: Control
    authority: Authority
    contradictions: ContradictionsAnswer
    unknowns: UnknownsAnswer

    _TYPES = {
        "effect": EffectAnswer, "implementation": ImplementationAnswer, "resource": Target,
        "activation": ObligationAnswer, "boundary": ObligationAnswer, "operation": ObligationAnswer,
        "persistence": ObligationAnswer, "control": Control, "authority": Authority,
        "contradictions": ContradictionsAnswer, "unknowns": UnknownsAnswer,
    }

    def __post_init__(self) -> None:
        for key in RECEIPT_ANSWER_KEYS:
            c.instance(self._TYPES[key], getattr(self, key), f"answers.{key}")

    def obligation(self, obligation: Obligation) -> ObligationAnswer:
        if obligation is Obligation.IMPLEMENTATION:
            raise KeyError("IMPLEMENTATION is answered by the implementation selection")
        return getattr(self, obligation.value.lower())

    def to_dict(self) -> dict:
        return {key: getattr(self, key).to_dict() for key in RECEIPT_ANSWER_KEYS}

    @classmethod
    def from_dict(cls, data: Any, where: str = "answers") -> "Answers":
        r = c.Reader(data, where, RECEIPT_ANSWER_KEYS)
        return cls(**{key: cls._TYPES[key].from_dict(r.get(key), r.at(key)) for key in RECEIPT_ANSWER_KEYS})


@dataclass(frozen=True)
class RenderingConstraints:
    is_negative_result: bool
    may_render_as_safe: bool = False

    def __post_init__(self) -> None:
        c.boolean(self.is_negative_result, "rendering_constraints.is_negative_result")
        if self.may_render_as_safe is not False:
            raise c.fail("rendering_constraints.may_render_as_safe", "no receipt licenses a safety claim")

    def to_dict(self) -> dict:
        return {"is_negative_result": self.is_negative_result, "may_render_as_safe": False}

    @classmethod
    def from_dict(cls, data: Any, where: str = "rendering_constraints") -> "RenderingConstraints":
        r = c.Reader(data, where, ("is_negative_result", "may_render_as_safe"))
        return cls(is_negative_result=r.get("is_negative_result"), may_render_as_safe=r.get("may_render_as_safe"))


def _statement(claim: EffectClaim) -> str:
    cls = claim.effect_class.value
    if claim.verdict is Verdict.PROVEN_EFFECT:
        return (f"This invocation produces an effect of class {cls}: every necessary obligation is SUPPORTED "
                "by PROBATIVE evidence and every BLOCKING counter-evidence probe completed without finding "
                "counter-evidence.")
    if claim.verdict is Verdict.NO_EFFECT:
        return (f"This invocation produces no effect of class {cls}: "
                f"{claim.closure.refuted_obligation.value} is REFUTED by PROBATIVE evidence for every "
                "implementation candidate under closure C1 to C6. This says nothing about the safety of "
                "the surrounding code.")
    if claim.verdict is Verdict.ANALYSIS_ERROR:
        failed = ", ".join(o.value for o, s in claim.obligations.items() if s is _E)
        return f"The analysis failed on {failed}. This is an analysis error, not a result of any kind."
    if not claim.was_investigated:
        return (f"This invocation may produce an effect of class {cls}. The claim was never investigated; "
                "this is not a negative result.")
    return (f"This invocation may produce an effect of class {cls}. Neither the effect nor its absence was "
            "established; the unknowns answer records what was not reached.")


def _settling_ids(claim: EffectClaim, obligation: Obligation) -> tuple[str, ...]:
    state = claim.obligations[obligation]
    if state in (_U, _E):
        return ()
    wanted = {_S: {Polarity.POSITIVE}, _R: {Polarity.NEGATIVE},
              _C: {Polarity.POSITIVE, Polarity.NEGATIVE}}[state]
    overridden = claim.overridden_packet_ids
    return tuple(p.packet_id for p in claim.packets_for(obligation)
                 if p.is_probative and p.polarity in wanted and p.packet_id not in overridden
                 and p.assertion.predicate not in UNCERTAINTY_PREDICATES)


def _incomplete_blocking(outcomes: tuple) -> tuple[str, ...]:
    """BLOCKING probes that did not complete. Never-executed counts as incomplete, never as NOT_FOUND."""
    completed = {o.probe_id for o in outcomes if o.completed}
    return tuple(pid for pid in BLOCKING_PROBE_IDS if pid not in completed)


@dataclass(frozen=True)
class EffectReceipt:
    receipt_id: str
    claim_id: str
    capability_id: str
    invocation_id: str
    effect_class: EffectClass
    verdict: Verdict
    answers: Answers
    evidence_packets: tuple[EvidencePacket, ...]
    probe_outcomes: tuple[ProbeOutcome, ...]
    acquisition: Acquisition
    claim_snapshot: EffectClaim
    closure: Closure | None = None
    rendering_constraints: RenderingConstraints | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        w = f"receipt {self.receipt_id!r}"
        if self.schema_version != SCHEMA_VERSION:
            raise c.fail(w, f"schema_version must be {SCHEMA_VERSION}")
        for name in ("receipt_id", "claim_id", "capability_id", "invocation_id"):
            c.identifier(getattr(self, name), f"{w}.{name}")
        object.__setattr__(self, "effect_class", c.enum_value(EffectClass, self.effect_class, f"{w}.effect_class"))
        object.__setattr__(self, "verdict", c.enum_value(Verdict, self.verdict, f"{w}.verdict"))
        c.instance(Answers, self.answers, f"{w}.answers")
        c.instance(Acquisition, self.acquisition, f"{w}.acquisition")
        c.instance(EffectClaim, self.claim_snapshot, f"{w}.claim_snapshot")
        c.optional_instance(Closure, self.closure, f"{w}.closure")
        c.optional_instance(RenderingConstraints, self.rendering_constraints, f"{w}.rendering_constraints")
        object.__setattr__(self, "evidence_packets", c.typed_tuple(EvidencePacket, self.evidence_packets, f"{w}.evidence_packets"))
        object.__setattr__(self, "probe_outcomes", c.typed_tuple(ProbeOutcome, self.probe_outcomes, f"{w}.probe_outcomes"))
        _validate_receipt(self, w)

    @classmethod
    def from_claim(cls, claim: EffectClaim, receipt_id: str | None = None) -> "EffectReceipt":
        c.instance(EffectClaim, claim, "claim")
        if receipt_id is None:
            receipt_id = claim.receipt_id
        if receipt_id is None:
            raise c.EffectModelError("a receipt needs a receipt_id")
        if claim.receipt_id is not None and claim.receipt_id != receipt_id:
            raise c.EffectModelError(f"claim {claim.claim_id!r} names receipt {claim.receipt_id!r}, not {receipt_id!r}")
        selected = claim.selected_candidate()
        answers = Answers(
            effect=EffectAnswer(claim.effect_class, claim.verdict, _statement(claim)),
            implementation=ImplementationAnswer(
                claim.selection_state, claim.implementation_candidates,
                selected.candidate_id if selected is not None else None),
            resource=claim.descriptors.target,
            **{o.value.lower(): ObligationAnswer(claim.obligations[o], _settling_ids(claim, o))
               for o in EVIDENCE_OBLIGATIONS},
            control=claim.descriptors.control,
            authority=claim.descriptors.authority,
            contradictions=ContradictionsAnswer(
                contradictions=claim.contradictions,
                counter_evidence_found=tuple(o for o in claim.probe_outcomes if o.outcome is ProbeResult.FOUND),
                blocking_probes_incomplete=_incomplete_blocking(claim.probe_outcomes)),
            unknowns=UnknownsAnswer.from_acquisition(claim.acquisition),
        )
        return cls(receipt_id=receipt_id, claim_id=claim.claim_id, capability_id=claim.capability_id,
                   invocation_id=claim.invocation_id, effect_class=claim.effect_class, verdict=claim.verdict,
                   answers=answers, evidence_packets=claim.evidence_packets,
                   probe_outcomes=claim.probe_outcomes, acquisition=claim.acquisition,
                   claim_snapshot=claim, closure=claim.closure,
                   rendering_constraints=RenderingConstraints(claim.verdict is Verdict.NO_EFFECT))

    @property
    def is_negative_result(self) -> bool:
        return self.verdict is Verdict.NO_EFFECT

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "capability_id": self.capability_id,
            "invocation_id": self.invocation_id,
            "effect_class": self.effect_class.value,
            "verdict": self.verdict.value,
            "answers": self.answers.to_dict(),
            "evidence_packets": [p.to_dict() for p in self.evidence_packets],
            "probe_outcomes": [o.to_dict() for o in self.probe_outcomes],
            "acquisition": self.acquisition.to_dict(),
            "claim_snapshot": self.claim_snapshot.to_dict(),
        }
        c.put(out, "closure", self.closure and self.closure.to_dict())
        c.put(out, "rendering_constraints", self.rendering_constraints and self.rendering_constraints.to_dict())
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "receipt") -> "EffectReceipt":
        if isinstance(data, Mapping) and "schema_version" in data and data["schema_version"] != SCHEMA_VERSION:
            raise c.fail(where, f"schema_version must be {SCHEMA_VERSION}; historical records are not migrated")
        r = c.Reader(data, where, ("schema_version", "receipt_id", "claim_id", "capability_id", "invocation_id",
                                   "effect_class", "verdict", "answers", "evidence_packets", "probe_outcomes",
                                   "acquisition", "claim_snapshot"), ("rendering_constraints", "closure"))
        packets = c.sequence(r.get("evidence_packets"), r.at("evidence_packets"))
        outcomes = c.sequence(r.get("probe_outcomes"), r.at("probe_outcomes"))
        return cls(
            schema_version=r.get("schema_version"), receipt_id=r.get("receipt_id"), claim_id=r.get("claim_id"),
            capability_id=r.get("capability_id"), invocation_id=r.get("invocation_id"),
            effect_class=r.get("effect_class"), verdict=r.get("verdict"),
            answers=Answers.from_dict(r.get("answers"), r.at("answers")),
            evidence_packets=tuple(EvidencePacket.from_dict(p, f"{r.at('evidence_packets')}[{i}]") for i, p in enumerate(packets)),
            probe_outcomes=tuple(ProbeOutcome.from_dict(o, f"{r.at('probe_outcomes')}[{i}]") for i, o in enumerate(outcomes)),
            acquisition=Acquisition.from_dict(r.get("acquisition"), r.at("acquisition")),
            claim_snapshot=EffectClaim.from_dict(r.get("claim_snapshot"), r.at("claim_snapshot")),
            closure=None if "closure" not in r else Closure.from_dict(r.get("closure"), r.at("closure")),
            rendering_constraints=None if "rendering_constraints" not in r else RenderingConstraints.from_dict(
                r.get("rendering_constraints"), r.at("rendering_constraints")),
        )


def _validate_receipt(receipt: EffectReceipt, w: str) -> None:
    claim = receipt.claim_snapshot
    _validate_claim(claim, w + ".claim_snapshot")
    for field in ("claim_id", "capability_id", "invocation_id", "effect_class", "verdict",
                  "evidence_packets", "probe_outcomes", "acquisition", "closure"):
        if getattr(receipt, field) != getattr(claim, field):
            raise c.fail(w, f"receipt {field} disagrees with underlying claim")
    answers = receipt.answers
    if (answers.effect.effect_class, answers.effect.verdict) != (claim.effect_class, claim.verdict):
        raise c.fail(w, "effect answer disagrees with underlying claim")
    impl = answers.implementation
    selected = claim.selected_candidate()
    if (impl.selection_state, impl.candidates, impl.selected_candidate_id) != (
            claim.selection_state, claim.implementation_candidates, selected.candidate_id if selected else None):
        raise c.fail(w, "implementation answer disagrees with underlying claim")
    for field, descriptor in (("resource", "target"), ("control", "control"), ("authority", "authority")):
        if getattr(answers, field) != getattr(claim.descriptors, descriptor):
            raise c.fail(w, f"{field} answer disagrees with underlying claim")
    packets = {p.packet_id: p for p in claim.evidence_packets}
    for o in EVIDENCE_OBLIGATIONS:
        answer = answers.obligation(o)
        if answer.state is not claim.obligations[o] or set(answer.settled_by_packet_ids) != set(_settling_ids(claim, o)):
            raise c.fail(w, f"{o.value} answer/settling packets disagree with underlying claim")
        _check_answer_packets(answer, o, packets, w)
    contradictions = answers.contradictions
    if contradictions.contradictions != claim.contradictions:
        raise c.fail(w, "contradictions differ from underlying claim")
    if contradictions.counter_evidence_found != tuple(o for o in claim.probe_outcomes if o.outcome is ProbeResult.FOUND):
        raise c.fail(w, "counter_evidence_found must report exactly the found probes")
    if set(contradictions.blocking_probes_incomplete or ()) != set(_incomplete_blocking(claim.probe_outcomes)):
        raise c.fail(w, "missing/incomplete BLOCKING probes must be reported")
    unknowns = answers.unknowns.to_dict()
    acquisition = claim.acquisition.to_dict()
    for key, value in unknowns.items():
        if value != acquisition.get(key):
            raise c.fail(w, f"unknowns {key} disagrees with acquisition record")
    rc = receipt.rendering_constraints
    if rc is not None and rc.is_negative_result != (claim.verdict is Verdict.NO_EFFECT):
        raise c.fail(w, "only NO_EFFECT is a negative result")


def _check_answer_packets(answer: ObligationAnswer, obligation: Obligation, packets: dict, w: str) -> None:
    cited = []
    for pid in answer.settled_by_packet_ids:
        p = packets.get(pid)
        if p is None:
            raise c.fail(w, f"cites packet {pid!r}, which the receipt does not carry")
        if p.obligation is not obligation or not p.is_probative \
                or p.assertion.predicate in UNCERTAINTY_PREDICATES:
            raise c.fail(w, f"packet {pid!r} is not PROBATIVE settling evidence on {obligation.value}")
        cited.append(p)
    polarities = {p.polarity for p in cited}
    if answer.state is _S and polarities != {Polarity.POSITIVE}:
        raise c.fail(w, "SUPPORTED rests on POSITIVE packets only")
    if answer.state is _R and polarities != {Polarity.NEGATIVE}:
        raise c.fail(w, "REFUTED rests on NEGATIVE packets only")
    if answer.state is _C and polarities != {Polarity.POSITIVE, Polarity.NEGATIVE}:
        raise c.fail(w, "CONFLICTING cites the PROBATIVE packets on both sides")
    if answer.settled_at_tier is not None and answer.settled_at_tier not in {p.tier for p in cited}:
        raise c.fail(w, "settled_at_tier is not the tier of any settling packet")
