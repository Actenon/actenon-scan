"""Valid baseline objects for the AREF-002 M0 tests.

Every adversarial test starts from one of these and changes exactly one thing,
so that a rejection can only be caused by that change.
"""

from __future__ import annotations

import dataclasses

from actenon_scan.effects import (
    Acquisition,
    AcquisitionCost,
    Admissibility,
    AssertionPredicate,
    Authority,
    CandidateKind,
    Closure,
    Contradiction,
    ContradictionResolution,
    Control,
    Descriptors,
    EffectClaim,
    EffectClass,
    EvidenceAssertion,
    EvidencePacket,
    FrontierEntry,
    Genesis,
    ImplementationCandidate,
    InertnessBlocker,
    Invocation,
    Language,
    LadderTier,
    Obligation,
    ObligationStates,
    PacketKind,
    Polarity,
    PROBE_REGISTRY,
    ProbeClass,
    ProbeOutcome,
    ProbeResult,
    ProofState,
    SelectionState,
    SourceLocator,
    StopReason,
    Strength,
    Target,
    TargetScope,
    VerbatimExtract,
    Verdict,
    aggregate_claim_states,
)
from actenon_scan.effects.vocabulary import EVIDENCE_OBLIGATIONS

S = ProofState.SUPPORTED
R = ProofState.REFUTED
U = ProofState.UNKNOWN
C = ProofState.CONFLICTING
E = ProofState.ERROR

SITE = SourceLocator(path="src/tools/zones.ts", start_line=57, end_line=57)

POSITIVE_PREDICATE = {
    Obligation.IMPLEMENTATION: AssertionPredicate.IMPLEMENTATION_IS,
    Obligation.ACTIVATION: AssertionPredicate.INVOCATION_EXECUTES,
    Obligation.BOUNDARY: AssertionPredicate.EGRESS_MECHANISM_IS,
    Obligation.OPERATION: AssertionPredicate.OPERATION_IS_MUTATION,
    Obligation.PERSISTENCE: AssertionPredicate.STATE_IS_DURABLY_COMMITTED,
}
NEGATIVE_PREDICATE = {
    Obligation.ACTIVATION: AssertionPredicate.INVOCATION_DOES_NOT_EXECUTE,
    Obligation.BOUNDARY: AssertionPredicate.TERMINATES_IN_PROCESS_STATE,
    Obligation.OPERATION: AssertionPredicate.OPERATION_IS_OBSERVATION,
    Obligation.PERSISTENCE: AssertionPredicate.STATE_IS_GUARANTEED_ROLLED_BACK,
}


def states(implementation=S, activation=U, boundary=U, operation=U, persistence=U):
    return ObligationStates(
        implementation=implementation,
        activation=activation,
        boundary=boundary,
        operation=operation,
        persistence=persistence,
    )


def packet(
    packet_id: str,
    obligation: Obligation,
    *,
    polarity: Polarity = Polarity.POSITIVE,
    candidate_id: str = "cand-1",
    tier: LadderTier = LadderTier.L1,
    kind: PacketKind = PacketKind.LOCAL_FUNCTION_BODY,
    admissibility: Admissibility = Admissibility.PROBATIVE,
    locator: SourceLocator | None = None,
    text: str = "    self._table.put_item(Item=item)",
    **extra,
) -> EvidencePacket:
    if polarity is Polarity.POSITIVE:
        predicate = POSITIVE_PREDICATE[obligation]
    else:
        predicate = NEGATIVE_PREDICATE[obligation]
    return EvidencePacket(
        packet_id=packet_id,
        tier=tier,
        kind=kind,
        locator=locator or SourceLocator(path="src/store.py", start_line=10, end_line=10),
        assertion=EvidenceAssertion(predicate=predicate),
        polarity=polarity,
        obligation=obligation,
        implementation_candidate_id=candidate_id,
        admissibility=admissibility,
        strength=Strength.STRONG,
        acquisition_cost=AcquisitionCost(hops=1, bytes_read=64),
        extract=VerbatimExtract(text=text),
        **extra,
    )


def candidate(candidate_id="cand-1", kind=CandidateKind.OPAQUE_EXTERNAL, obligations=None):
    return ImplementationCandidate(candidate_id=candidate_id, kind=kind, obligations=obligations)


def descriptors() -> Descriptors:
    return Descriptors(
        target=Target(coordinates=(), scope=TargetScope.UNKNOWN),
        control=Control(trigger_control=S, target_control=U, content_control=U),
        authority=Authority(state=U),
        conditions=(),
    )


def invocation(matched_rule_ids=()) -> Invocation:
    return Invocation(
        locator=SITE,
        callee_expression="client.zones.settings.edit",
        language=Language.TYPESCRIPT,
        matched_rule_ids=matched_rule_ids,
    )


def abstain_acquisition(unresolved=(Obligation.ACTIVATION, Obligation.BOUNDARY,
                                    Obligation.OPERATION, Obligation.PERSISTENCE)):
    return Acquisition(
        highest_tier_reached=LadderTier.L4,
        stop_reason=StopReason.TIER_UNAVAILABLE,
        tiers_attempted=(LadderTier.L0, LadderTier.L1, LadderTier.L2,
                         LadderTier.L3, LadderTier.L4),
        unresolved_obligations=unresolved,
        frontier_size=1,
        frontier=(
            FrontierEntry(
                origin=SITE,
                would_reach_tier=LadderTier.L5,
                reason=StopReason.TIER_UNAVAILABLE,
                target_package="example-sdk",
                might_settle=(Obligation.BOUNDARY, Obligation.OPERATION,
                              Obligation.PERSISTENCE),
            ),
        ),
        frontier_truncated=False,
    )


def settled_acquisition(unresolved=()):
    return Acquisition(
        highest_tier_reached=LadderTier.L7,
        stop_reason=StopReason.SETTLED,
        tiers_attempted=tuple(LadderTier.evidence_tiers()),
        unresolved_obligations=unresolved,
        frontier_size=0,
        frontier=(),
        frontier_truncated=False,
    )


def unfamiliar_sdk_claim(**overrides) -> EffectClaim:
    """AREF-002.md section 13: an unseen SDK call, no sink rule, verdict ABSTAIN."""
    fields = dict(
        claim_id="claim-0001",
        capability_id="cap-zones-settings-tool",
        invocation_id="inv-src-tools-zones.ts-L57C11",
        effect_class=EffectClass.EXTERNAL_PERSISTENT_STATE_EFFECT,
        invocation=invocation(),
        genesis=Genesis(inertness_blockers=(InertnessBlocker.OPAQUE_EXTERNAL_CANDIDATE,)),
        implementation_candidates=[candidate()],
        selection_state=SelectionState.SINGLE_ESTABLISHED,
        obligations=states(),
        descriptors=descriptors(),
        acquisition=abstain_acquisition(),
        verdict=Verdict.ABSTAIN,
    )
    fields.update(overrides)
    return EffectClaim(**fields)


def all_blocking_probes_complete(result=ProbeResult.NOT_FOUND):
    return tuple(
        ProbeOutcome(probe_id=pid, obligation=entry.obligation,
                     probe_class=ProbeClass.BLOCKING, outcome=result)
        for pid, entry in sorted(PROBE_REGISTRY.items())
        if entry.probe_class is ProbeClass.BLOCKING
    )


def supporting_packets(candidate_id="cand-1", prefix="pkt", skip=()):
    return tuple(
        packet(f"{prefix}-{o.value.lower()}", o, candidate_id=candidate_id)
        for o in (Obligation.ACTIVATION, Obligation.BOUNDARY,
                  Obligation.OPERATION, Obligation.PERSISTENCE)
        if o not in skip
    )


def proven_claim(**overrides) -> EffectClaim:
    fields = dict(
        implementation_candidates=[
            candidate(kind=CandidateKind.RESOLVED_DEPENDENCY_SOURCE)
        ],
        obligations=states(S, S, S, S, S),
        evidence_packets=supporting_packets(),
        probe_outcomes=all_blocking_probes_complete(),
        acquisition=settled_acquisition(),
        verdict=Verdict.PROVEN_EFFECT,
    )
    fields.update(overrides)
    return unfamiliar_sdk_claim(**fields)


def rolled_back_packet(candidate_id="cand-1", packet_id="pkt-rollback"):
    return packet(packet_id, Obligation.PERSISTENCE, polarity=Polarity.NEGATIVE,
                  candidate_id=candidate_id,
                  text="    finally:\n        tx.rollback()")


def full_closure(refuted=Obligation.PERSISTENCE) -> Closure:
    return Closure(refuted_obligation=refuted)


def no_effect_claim(**overrides) -> EffectClaim:
    fields = dict(
        implementation_candidates=[candidate(kind=CandidateKind.RESOLVED_LOCAL)],
        obligations=states(S, S, S, S, R),
        evidence_packets=supporting_packets(skip=(Obligation.PERSISTENCE,))
        + (rolled_back_packet(),),
        probe_outcomes=all_blocking_probes_complete(),
        acquisition=settled_acquisition(),
        verdict=Verdict.NO_EFFECT,
        closure=full_closure(),
    )
    fields.update(overrides)
    return unfamiliar_sdk_claim(**fields)


def conflicting_claim(**overrides) -> EffectClaim:
    """Requirement 14: contract says READ, implementation says MUTATE."""
    contract_read = packet("pkt-contract", Obligation.OPERATION,
                           polarity=Polarity.NEGATIVE, tier=LadderTier.L6,
                           kind=PacketKind.OPENAPI_OPERATION,
                           locator=SourceLocator(path="openapi.json", start_line=4,
                                                 end_line=4, package="svc",
                                                 version="1.0.0",
                                                 version_resolution=_lockfile()),
                           text='"x-effect": "read-only"')
    body_mutate = packet("pkt-body", Obligation.OPERATION, tier=LadderTier.L1,
                         text="    cur.execute('UPDATE t SET v = 1')")
    fields = dict(
        implementation_candidates=[candidate(kind=CandidateKind.RESOLVED_LOCAL)],
        obligations=states(S, U, U, C, U),
        evidence_packets=(contract_read, body_mutate),
        contradictions=(
            Contradiction(
                obligation=Obligation.OPERATION,
                implementation_candidate_id="cand-1",
                positive_packet_ids=("pkt-body",),
                negative_packet_ids=("pkt-contract",),
                resolution=ContradictionResolution.UNRESOLVED,
            ),
        ),
        acquisition=Acquisition(
            highest_tier_reached=LadderTier.L6,
            stop_reason=StopReason.NO_FURTHER_TIER,
            tiers_attempted=(LadderTier.L0, LadderTier.L1, LadderTier.L6),
            unresolved_obligations=(Obligation.ACTIVATION, Obligation.BOUNDARY,
                                    Obligation.PERSISTENCE),
            frontier_size=0,
            frontier=(),
        ),
        verdict=Verdict.ABSTAIN,
    )
    fields.update(overrides)
    return unfamiliar_sdk_claim(**fields)


def error_claim(**overrides) -> EffectClaim:
    fields = dict(
        obligations=states(S, U, E, U, U),
        acquisition=Acquisition(
            highest_tier_reached=LadderTier.L1,
            stop_reason=StopReason.ACQUISITION_ERROR,
            tiers_attempted=(LadderTier.L0, LadderTier.L1),
            unresolved_obligations=(Obligation.ACTIVATION, Obligation.OPERATION,
                                    Obligation.PERSISTENCE),
            frontier_size=0,
            frontier=(),
        ),
        verdict=Verdict.ANALYSIS_ERROR,
    )
    fields.update(overrides)
    return unfamiliar_sdk_claim(**fields)


def not_investigated_claim(claim_id="claim-ni", invocation_id="inv-ni") -> EffectClaim:
    return unfamiliar_sdk_claim(
        claim_id=claim_id,
        invocation_id=invocation_id,
        acquisition=Acquisition(
            highest_tier_reached=LadderTier.L0,
            stop_reason=StopReason.CLAIM_NOT_INVESTIGATED,
            tiers_attempted=(),
            unresolved_obligations=(Obligation.ACTIVATION, Obligation.BOUNDARY,
                                    Obligation.OPERATION, Obligation.PERSISTENCE),
            frontier_size=0,
            frontier=(),
        ),
    )


def evidence_for(cid: str, o: Obligation, state: ProofState):
    stem = f"p-{cid}-{o.value.lower()}"
    pos = packet(f"{stem}-pos", o, candidate_id=cid)
    neg = packet(f"{stem}-neg", o, candidate_id=cid, polarity=Polarity.NEGATIVE)
    if state is S:
        return [pos], []
    if state is R:
        return [neg], []
    if state is C:
        return [pos, neg], [Contradiction(o, cid, (pos.packet_id,), (neg.packet_id,),
                                          ContradictionResolution.UNRESOLVED)]
    return [], []


def multi_claim(selection, per_candidate, *, kinds=None, claim_states=None, verdict=None,
                probes=(), acquisition=None, **overrides):
    """A claim over several candidates, each with evidence matching its states."""
    cands, packets, records = [], [], []
    for i, cand_states in enumerate(per_candidate):
        cid = f"cand-{i + 1}"
        full = states(S, **{o.value.lower(): cand_states.get(o, U) for o in EVIDENCE_OBLIGATIONS})
        kind = kinds[i] if kinds else CandidateKind.RESOLVED_LOCAL
        cands.append(candidate(cid, kind, full))
        for o in EVIDENCE_OBLIGATIONS:
            ps, ks = evidence_for(cid, o, full[o])
            packets += ps
            records += ks
    if claim_states is None:
        claim_states = aggregate_claim_states(selection, [c_.obligations for c_ in cands])
    if acquisition is None:
        acquisition = Acquisition(
            highest_tier_reached=LadderTier.L1, stop_reason=StopReason.NO_FURTHER_TIER,
            tiers_attempted=(LadderTier.L0, LadderTier.L1),
            unresolved_obligations=tuple(o for o, s in claim_states.items() if s is U),
            frontier_size=0, frontier=())
    if verdict is None:
        verdict = Verdict.ANALYSIS_ERROR if E in dict(claim_states.items()).values() else Verdict.ABSTAIN
    return unfamiliar_sdk_claim(
        implementation_candidates=cands, selection_state=selection, obligations=claim_states,
        evidence_packets=tuple(packets), contradictions=tuple(records), probe_outcomes=probes,
        acquisition=acquisition, verdict=verdict, **overrides)


def resolved_claim(**overrides):
    base = conflicting_claim()
    record = dataclasses.replace(base.contradictions[0],
                                 resolution=ContradictionResolution.RESOLVED_IMPLEMENTATION_PRECEDENCE,
                                 overridden_packet_ids=("pkt-contract",))
    fields = dict(obligations=states(S, U, U, S, U), contradictions=(record,))
    fields.update(overrides)
    return dataclasses.replace(base, **fields)


def _lockfile():
    from actenon_scan.effects import VersionResolution
    return VersionResolution.LOCKFILE
