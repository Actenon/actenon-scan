"""M0: EffectClaim.

Covers required M0 tests 1 to 7: a claim with zero sink rules; set-valued
implementations; no silent collapse to a first candidate; UNKNOWN never
becoming REFUTED; CONFLICTING surviving aggregation; ERROR never becoming
ABSTAIN; and SUPPORTED always resting on evidence provenance. Every test
starts from a valid baseline and changes one thing.
"""

from __future__ import annotations

import dataclasses
import inspect
import itertools
import json

import pytest

from actenon_scan.effects import (
    Admissibility,
    AssertionPredicate,
    Authority,
    BudgetName,
    CandidateKind,
    Closure,
    Contradiction,
    ContradictionResolution,
    ImplementationPrecedence,
    PrecedencePath,
    Control,
    Descriptors,
    EffectClaim,
    EffectModelError,
    EvidenceAssertion,
    FrontierEntry,
    Genesis,
    Invocation,
    LadderTier,
    Language,
    Obligation,
    PacketKind,
    Polarity,
    ProbeClass,
    ProbeOutcome,
    ProbeResult,
    ProofState,
    SelectionState,
    SourceLocator,
    StopReason,
    Target,
    TargetScope,
    Verdict,
    aggregate_obligation,
)
from actenon_scan.effects.vocabulary import EVIDENCE_OBLIGATIONS

from ._builders import (
    SITE,
    C,
    E,
    R,
    S,
    U,
    abstain_acquisition,
    all_blocking_probes_complete,
    candidate,
    conflicting_claim,
    descriptors,
    error_claim,
    invocation,
    multi_claim,
    no_effect_claim,
    not_investigated_claim,
    packet,
    proven_claim,
    resolved_claim,
    rolled_back_packet,
    settled_acquisition,
    states,
    unfamiliar_sdk_claim,
)
from ._spec import example, amended_example

ALL_STATES = tuple(ProofState)


def replace(claim: EffectClaim, **changes) -> EffectClaim:
    return dataclasses.replace(claim, **changes)


def with_states(claim_states: dict):
    return states(**{o.value.lower(): s for o, s in claim_states.items()})


# ============================================ 1. a claim with zero sink rules


def test_1_claim_exists_with_zero_matched_rules():
    claim = unfamiliar_sdk_claim()
    assert claim.invocation.matched_rule_ids == ()
    assert not any(p.is_rule_derived for p in claim.evidence_packets)
    assert claim.verdict is Verdict.ABSTAIN
    assert all(claim.obligations[o] is U for o in EVIDENCE_OBLIGATIONS)


def test_1_zero_rule_claim_can_reach_every_verdict():
    for claim in (proven_claim(), no_effect_claim(), unfamiliar_sdk_claim(), error_claim()):
        assert claim.invocation.matched_rule_ids == ()
        assert not any(p.is_rule_derived for p in claim.evidence_packets)
    assert {k.verdict for k in (proven_claim(), no_effect_claim(), unfamiliar_sdk_claim(), error_claim())} \
        == set(Verdict)


def test_1_frozen_rule_free_examples_load():
    for name in ("valid_opaque_abstain", "valid_proven"):
        claim = EffectClaim.from_dict(amended_example(name))
        assert claim.invocation.matched_rule_ids == ()


def test_1_rules_change_neither_existence_nor_identity():
    without = unfamiliar_sdk_claim()
    with_rules = unfamiliar_sdk_claim(invocation=invocation(matched_rule_ids=("DB-WRITE", "HTTP-POST")))
    assert without.identity == with_rules.identity
    assert "rule" not in "".join(str(x) for x in without.identity).lower()
    assert with_rules.verdict is without.verdict


def test_1_no_constructor_requires_a_rule_or_a_finding():
    for cls in (EffectClaim, Invocation, Genesis):
        for name, param in inspect.signature(cls).parameters.items():
            text = f"{name} {param.annotation}".lower()
            assert "finding" not in text
            if "rule" in text:
                assert param.default is not inspect.Parameter.empty, f"{cls.__name__}.{name} is required"


@pytest.mark.parametrize("basis", ["SINK_RULE_MATCH", "RULE_HIT", "non_refutation_of_inertness", ""])
def test_1_a_rule_is_never_the_basis_of_a_claim(basis):
    with pytest.raises(EffectModelError, match="basis"):
        Genesis(basis=basis)


def test_1_an_emitted_claim_never_has_established_inertness():
    for value in (True, None, 0, "false"):
        with pytest.raises(EffectModelError):
            Genesis(inertness_established=value)


# ================================= 2. multiple implementations are retained


def test_2_three_candidates_are_all_retained_through_serialisation():
    claim = multi_claim(SelectionState.UNRESOLVED_DIVERGENT,
                        [{Obligation.OPERATION: S}, {Obligation.OPERATION: R}, {}])
    assert claim.candidate_ids == {"cand-1", "cand-2", "cand-3"}
    again = EffectClaim.from_dict(json.loads(json.dumps(claim.to_dict())))
    assert again == claim
    assert again.candidate_ids == claim.candidate_ids
    for cid in claim.candidate_ids:
        assert again.candidate_states(cid) == claim.candidate_states(cid)
        assert again.packets_for(Obligation.OPERATION, cid) == claim.packets_for(Obligation.OPERATION, cid)


def test_2_agreeing_candidates_support_a_proven_effect_without_selecting_one():
    full = {o: S for o in EVIDENCE_OBLIGATIONS}
    claim = multi_claim(SelectionState.AGREEMENT_INVARIANT, [full, full, full],
                        probes=all_blocking_probes_complete(), verdict=Verdict.PROVEN_EFFECT)
    assert len(claim.implementation_candidates) == 3
    assert claim.selected_candidate() is None
    assert len(claim.evidence_packets) == 15


def test_2_an_opaque_candidate_is_a_first_class_candidate():
    claim = multi_claim(SelectionState.UNRESOLVED_IDENTITY, [{Obligation.OPERATION: S}, {}],
                        kinds=[CandidateKind.RESOLVED_LOCAL, CandidateKind.OPAQUE_EXTERNAL])
    assert {c_.kind for c_ in claim.implementation_candidates} == {CandidateKind.RESOLVED_LOCAL,
                                                                   CandidateKind.OPAQUE_EXTERNAL}


def test_2_duplicate_candidates_are_rejected_not_deduplicated():
    same = candidate("cand-1")
    with pytest.raises(EffectModelError, match="duplicate"):
        unfamiliar_sdk_claim(implementation_candidates=[same, same])
    with pytest.raises(EffectModelError, match="duplicate"):
        unfamiliar_sdk_claim(implementation_candidates=[candidate("cand-1"),
                                                        candidate("cand-1", CandidateKind.RESOLVED_LOCAL)])


def test_2_a_claim_always_has_at_least_one_candidate():
    with pytest.raises(EffectModelError, match="at least one"):
        unfamiliar_sdk_claim(implementation_candidates=[])


def test_2_several_candidates_each_carry_their_own_states():
    with pytest.raises(EffectModelError, match="its own obligation states"):
        unfamiliar_sdk_claim(implementation_candidates=[candidate("cand-1"), candidate("cand-2")],
                             selection_state=SelectionState.UNRESOLVED_DIVERGENT,
                             obligations=states(U))


# ============================== 3. no silent collapse to the first candidate


def test_3_there_is_no_first_candidate():
    claim = multi_claim(SelectionState.UNRESOLVED_DIVERGENT, [{Obligation.OPERATION: S}, {Obligation.OPERATION: R}])
    assert isinstance(claim.implementation_candidates, frozenset)
    with pytest.raises(TypeError):
        claim.implementation_candidates[0]
    assert claim.selected_candidate() is None


@pytest.mark.parametrize("pick", [S, R])
def test_3_divergent_claim_cannot_take_any_one_candidates_state(pick):
    good = multi_claim(SelectionState.UNRESOLVED_DIVERGENT, [{Obligation.OPERATION: S}, {Obligation.OPERATION: R}])
    assert good.obligations.operation is U
    collapsed = dict(good.obligations.items())
    collapsed[Obligation.OPERATION] = pick
    with pytest.raises(EffectModelError, match="aggregate"):
        replace(good, obligations=with_states(collapsed),
                acquisition=dataclasses.replace(good.acquisition, unresolved_obligations=(Obligation.IMPLEMENTATION,)))


def test_3_candidate_order_never_matters():
    per = [{Obligation.OPERATION: S, Obligation.BOUNDARY: S}, {Obligation.OPERATION: R}, {Obligation.BOUNDARY: C}]
    base = multi_claim(SelectionState.UNRESOLVED_DIVERGENT, per)
    for order in itertools.permutations(base.implementation_candidates):
        other = replace(base, implementation_candidates=list(order))
        assert other == base
        assert other.to_dict() == base.to_dict()


@pytest.mark.parametrize("n", [1, 2, 3, 4])
def test_3_aggregation_is_invariant_under_every_permutation(n):
    for combo in itertools.product(ALL_STATES, repeat=n):
        results = {aggregate_obligation(order) for order in itertools.permutations(combo)}
        assert len(results) == 1


def test_3_single_established_means_exactly_one_candidate():
    with pytest.raises(EffectModelError, match="exactly one"):
        multi_claim(SelectionState.SINGLE_ESTABLISHED, [{Obligation.OPERATION: S}, {Obligation.OPERATION: S}],
                    claim_states=states(S, U, U, S, U))


def test_3_agreement_and_divergence_are_checked_not_asserted():
    with pytest.raises(EffectModelError, match="selection requires UNRESOLVED_DIVERGENT"):
        multi_claim(SelectionState.AGREEMENT_INVARIANT, [{Obligation.OPERATION: S}, {Obligation.OPERATION: R}],
                    claim_states=states(S, U, U, U, U))
    with pytest.raises(EffectModelError, match="selection requires AGREEMENT_INVARIANT"):
        multi_claim(SelectionState.UNRESOLVED_DIVERGENT, [{Obligation.OPERATION: S}, {Obligation.OPERATION: S}])
    with pytest.raises(EffectModelError, match="several candidates"):
        unfamiliar_sdk_claim(selection_state=SelectionState.AGREEMENT_INVARIANT)


def test_3_one_inert_candidate_does_not_make_the_site_inert():
    """C2: refuted for the first candidate only is not NO_EFFECT."""
    per = [{**{o: S for o in EVIDENCE_OBLIGATIONS}, Obligation.PERSISTENCE: R},
           {o: S for o in EVIDENCE_OBLIGATIONS}]
    claim = multi_claim(SelectionState.UNRESOLVED_DIVERGENT, per, probes=all_blocking_probes_complete())
    assert claim.obligations.persistence is U
    with pytest.raises(EffectModelError):
        replace(claim, verdict=Verdict.NO_EFFECT, closure=Closure(Obligation.PERSISTENCE))


# ===================================== 4. UNKNOWN never becomes REFUTED


def test_4_unknown_survives_json_round_trip():
    claim = unfamiliar_sdk_claim()
    wire = json.loads(json.dumps(claim.to_dict()))
    assert wire["obligations"]["PERSISTENCE"] == "UNKNOWN"
    again = EffectClaim.from_dict(wire)
    assert again.obligations.persistence is U
    assert again == claim


@pytest.mark.parametrize("mutate", [
    lambda d: d["obligations"].pop("PERSISTENCE"),
    lambda d: d["obligations"].update(PERSISTENCE=None),
    lambda d: d["obligations"].update(PERSISTENCE="unknown"),
    lambda d: d["obligations"].update(PERSISTENCE=""),
    lambda d: d["obligations"].update(PERSISTENCE=False),
    lambda d: d["implementation_candidates"][0].update(obligations={"IMPLEMENTATION": "SUPPORTED"}),
])
def test_4_a_missing_or_malformed_state_is_an_error_not_a_default(mutate):
    d = unfamiliar_sdk_claim().to_dict()
    mutate(d)
    with pytest.raises(EffectModelError):
        EffectClaim.from_dict(d)


def test_4_rewriting_unknown_as_refuted_on_the_wire_is_rejected():
    d = unfamiliar_sdk_claim().to_dict()
    d["obligations"]["PERSISTENCE"] = "REFUTED"
    with pytest.raises(EffectModelError):
        EffectClaim.from_dict(d)
    d["acquisition"]["unresolved_obligations"].remove("PERSISTENCE")
    with pytest.raises(EffectModelError, match="REFUTED"):
        EffectClaim.from_dict(d)


def test_4_aggregation_never_produces_refuted_from_unknown():
    assert aggregate_obligation([U, R]) is U
    assert aggregate_obligation([R, U, R]) is U
    assert aggregate_obligation([R, R]) is R
    for combo in itertools.product(ALL_STATES, repeat=3):
        if R in combo and set(combo) != {R}:
            assert aggregate_obligation(combo) is not R


def test_4_refuted_requires_probative_negative_evidence():
    base = no_effect_claim()
    with pytest.raises(EffectModelError, match="evidence requires UNKNOWN, recorded REFUTED"):
        replace(base, evidence_packets=tuple(p for p in base.evidence_packets
                                             if p.obligation is not Obligation.PERSISTENCE))
    hypothesis = dataclasses.replace(rolled_back_packet(), admissibility=Admissibility.HYPOTHESIS_ONLY)
    with pytest.raises(EffectModelError, match="evidence requires UNKNOWN, recorded REFUTED"):
        replace(base, evidence_packets=tuple(p for p in base.evidence_packets
                                             if p.obligation is not Obligation.PERSISTENCE) + (hypothesis,))


def test_4_no_effect_is_impossible_from_an_unknown_obligation():
    claim = unfamiliar_sdk_claim()
    with pytest.raises(EffectModelError):
        replace(claim, verdict=Verdict.NO_EFFECT, closure=Closure(Obligation.PERSISTENCE))


def test_4_an_uninvestigated_claim_is_never_a_negative():
    claim = not_investigated_claim()
    assert claim.verdict is Verdict.ABSTAIN and not claim.was_investigated
    with pytest.raises(EffectModelError):
        replace(claim, verdict=Verdict.NO_EFFECT, closure=Closure(Obligation.PERSISTENCE))


# ===================================== 5. CONFLICTING survives aggregation


def test_5_conflicting_survives_round_trip():
    claim = conflicting_claim()
    assert claim.obligations.operation is C
    again = EffectClaim.from_dict(json.loads(json.dumps(claim.to_dict())))
    assert again.obligations.operation is C
    assert again.contradictions == claim.contradictions


@pytest.mark.parametrize("others", [(S,), (U,), (R,), (S, U), (R, S, U), (C,)])
def test_5_conflicting_never_collapses_when_aggregated(others):
    assert aggregate_obligation((C,) + others) is C


def test_5_divergent_claim_with_a_conflicting_candidate_is_conflicting():
    claim = multi_claim(SelectionState.UNRESOLVED_DIVERGENT, [{Obligation.OPERATION: C}, {Obligation.OPERATION: S}])
    assert claim.obligations.operation is C
    flattened = dict(claim.obligations.items())
    flattened[Obligation.OPERATION] = U
    with pytest.raises(EffectModelError, match="aggregate"):
        replace(claim, obligations=with_states(flattened),
                acquisition=dataclasses.replace(claim.acquisition, unresolved_obligations=tuple(
                    o for o, s in flattened.items() if s is U)))


def test_5_inter_candidate_divergence_is_not_a_contradiction():
    assert aggregate_obligation([S, R]) is U
    claim = multi_claim(SelectionState.UNRESOLVED_DIVERGENT, [{Obligation.OPERATION: S}, {Obligation.OPERATION: R}])
    manufactured = dict(claim.obligations.items())
    manufactured[Obligation.OPERATION] = C
    with pytest.raises(EffectModelError):
        replace(claim, obligations=with_states(manufactured))
    cross = Contradiction(Obligation.OPERATION, "cand-1", ("p-cand-1-operation-pos",),
                          ("p-cand-2-operation-neg",), ContradictionResolution.UNRESOLVED)
    with pytest.raises(EffectModelError, match="not NEGATIVE PROBATIVE evidence"):
        replace(claim, contradictions=(cross,))


@pytest.mark.parametrize("state", [S, R, U])
def test_5_conflicting_cannot_be_rewritten_without_a_precedence_rule(state):
    base = conflicting_claim()
    rewritten = states(S, U, U, state, U)
    unresolved = tuple(o for o, s in rewritten.items() if s is U)
    with pytest.raises(EffectModelError):
        replace(base, obligations=rewritten,
                implementation_candidates=[candidate(kind=CandidateKind.RESOLVED_LOCAL)],
                acquisition=dataclasses.replace(base.acquisition, unresolved_obligations=unresolved))


def test_5_conflicting_requires_its_contradiction_record():
    with pytest.raises(EffectModelError, match="contradiction must cite every opposing"):
        replace(conflicting_claim(), contradictions=())


def test_5_conflicting_blocks_both_decisive_verdicts():
    base = conflicting_claim()
    with pytest.raises(EffectModelError):
        replace(base, verdict=Verdict.PROVEN_EFFECT)
    with pytest.raises(EffectModelError):
        replace(base, verdict=Verdict.NO_EFFECT, closure=Closure(Obligation.OPERATION))


def test_5_the_one_admissible_precedence_rule_keeps_the_overridden_packet():
    claim = resolved_claim()
    assert claim.obligations.operation is S
    assert "pkt-contract" in {p.packet_id for p in claim.evidence_packets}
    assert claim.overridden_packet_ids == {"pkt-contract"}


def test_5_precedence_cannot_drop_the_overridden_packet():
    claim = resolved_claim()
    with pytest.raises(EffectModelError, match="unknown packet"):
        replace(claim, evidence_packets=tuple(p for p in claim.evidence_packets if p.packet_id != "pkt-contract"))


def test_5_precedence_requires_single_established_resolved_body():
    with pytest.raises(EffectModelError, match="resolved body"):
        resolved_claim(implementation_candidates=[candidate(kind=CandidateKind.CONTRACT_DECLARED)])
    base = conflicting_claim()
    record = dataclasses.replace(base.contradictions[0],
                                 resolution=ContradictionResolution.RESOLVED_IMPLEMENTATION_PRECEDENCE,
                                 overridden_packet_ids=("pkt-body",),
                                 precedence=ImplementationPrecedence("pkt-implementation", (PrecedencePath("pkt-contract"),)))
    with pytest.raises(EffectModelError):
        replace(base, obligations=states(S, U, U, R, U), contradictions=(record,))


def test_5_precedence_does_not_apply_under_agreement():
    full = {o: S for o in EVIDENCE_OBLIGATIONS}
    claim = multi_claim(SelectionState.AGREEMENT_INVARIANT, [full, full])
    contract = packet("pkt-c", Obligation.OPERATION, polarity=Polarity.NEGATIVE, candidate_id="cand-1",
                      tier=LadderTier.L6, kind=PacketKind.OPENAPI_OPERATION,
                      locator=SourceLocator(path="api.json", start_line=1, end_line=1, package="svc",
                                            version="1", version_resolution="LOCKFILE"))
    record = Contradiction(Obligation.OPERATION, "cand-1", ("p-cand-1-operation-pos",), ("pkt-c",),
                           ContradictionResolution.RESOLVED_IMPLEMENTATION_PRECEDENCE, ("pkt-c",),
                           ImplementationPrecedence("p-cand-1-implementation-pos",
                                                    (PrecedencePath("p-cand-1-operation-pos"),)))
    with pytest.raises(EffectModelError, match="only under SINGLE_ESTABLISHED"):
        replace(claim, evidence_packets=claim.evidence_packets + (contract,), contradictions=(record,),
                acquisition=dataclasses.replace(claim.acquisition, tiers_attempted=(
                    LadderTier.L0, LadderTier.L1, LadderTier.L6), highest_tier_reached=LadderTier.L6))


# ========================================== 6. ERROR never becomes ABSTAIN


@pytest.mark.parametrize("verdict", [Verdict.ABSTAIN, Verdict.NO_EFFECT, Verdict.PROVEN_EFFECT])
def test_6_error_cannot_be_reported_as_any_other_verdict(verdict):
    closure = Closure(Obligation.PERSISTENCE) if verdict is Verdict.NO_EFFECT else None
    with pytest.raises(EffectModelError, match="ANALYSIS_ERROR"):
        error_claim(verdict=verdict, closure=closure)


def test_6_analysis_error_requires_an_error():
    with pytest.raises(EffectModelError, match="requires an ERROR"):
        unfamiliar_sdk_claim(verdict=Verdict.ANALYSIS_ERROR)


def test_6_error_outranks_every_other_state_in_aggregation():
    for others in itertools.product(ALL_STATES, repeat=2):
        assert aggregate_obligation((E,) + others) is E


def test_6_error_survives_round_trip():
    claim = error_claim()
    again = EffectClaim.from_dict(json.loads(json.dumps(claim.to_dict())))
    assert again.obligations.boundary is E
    assert again.verdict is Verdict.ANALYSIS_ERROR


def test_6_selection_error_is_an_analysis_error():
    claim = unfamiliar_sdk_claim(implementation_candidates=[candidate(obligations=states(E))],
                                 selection_state=SelectionState.SELECTION_ERROR, obligations=states(E),
                                 verdict=Verdict.ANALYSIS_ERROR)
    assert claim.obligations.implementation is E
    with pytest.raises(EffectModelError, match="ANALYSIS_ERROR"):
        replace(claim, verdict=Verdict.ABSTAIN)
    with pytest.raises(EffectModelError, match="IMPLEMENTATION is UNKNOWN but candidates aggregate to ERROR"):
        replace(claim, obligations=states(U))


def test_6_error_on_one_candidate_is_not_hidden_by_divergence():
    claim = multi_claim(SelectionState.UNRESOLVED_DIVERGENT, [{Obligation.BOUNDARY: E}, {Obligation.BOUNDARY: S}])
    assert claim.obligations.boundary is E
    assert claim.verdict is Verdict.ANALYSIS_ERROR


def test_6_implementation_is_never_refuted():
    with pytest.raises(EffectModelError):
        unfamiliar_sdk_claim(obligations=states(R))
    with pytest.raises(EffectModelError, match="never REFUTED"):
        candidate(obligations=states(R))


# ================================ 7. SUPPORTED requires evidence provenance


@pytest.mark.parametrize("obligation", EVIDENCE_OBLIGATIONS)
def test_7_supported_without_any_packet_is_rejected(obligation):
    base = proven_claim()
    with pytest.raises(EffectModelError, match="evidence requires UNKNOWN, recorded SUPPORTED"):
        replace(base, evidence_packets=tuple(p for p in base.evidence_packets if p.obligation is not obligation))


@pytest.mark.parametrize("obligation", EVIDENCE_OBLIGATIONS)
def test_7_hypothesis_only_evidence_cannot_support(obligation):
    base = proven_claim()
    weakened = tuple(dataclasses.replace(p, admissibility=Admissibility.HYPOTHESIS_ONLY)
                     if p.obligation is obligation else p for p in base.evidence_packets)
    with pytest.raises(EffectModelError, match="evidence requires UNKNOWN, recorded SUPPORTED"):
        replace(base, evidence_packets=weakened)


def test_7_evidence_for_another_candidate_cannot_support():
    full = {o: S for o in EVIDENCE_OBLIGATIONS}
    claim = multi_claim(SelectionState.AGREEMENT_INVARIANT, [full, full],
                        probes=all_blocking_probes_complete(), verdict=Verdict.PROVEN_EFFECT)
    borrowed = tuple(dataclasses.replace(p, implementation_candidate_id="cand-1")
                     if p.implementation_candidate_id == "cand-2" and p.obligation is Obligation.OPERATION else p
                     for p in claim.evidence_packets)
    with pytest.raises(EffectModelError, match="for 'cand-2'"):
        replace(claim, evidence_packets=borrowed)


def test_7_packets_must_belong_to_a_known_candidate():
    base = proven_claim()
    stray = packet("pkt-stray", Obligation.BOUNDARY, candidate_id="cand-ghost")
    with pytest.raises(EffectModelError, match="unknown candidate"):
        replace(base, evidence_packets=base.evidence_packets + (stray,))


def test_7_packet_ids_are_unique():
    base = proven_claim()
    with pytest.raises(EffectModelError, match="duplicate packet id"):
        replace(base, evidence_packets=base.evidence_packets + (base.evidence_packets[0],))


def test_7_evidence_cannot_come_from_a_tier_that_was_not_attempted():
    base = proven_claim()
    with pytest.raises(EffectModelError, match="not attempted"):
        replace(base, acquisition=dataclasses.replace(
            base.acquisition, tiers_attempted=(LadderTier.L0, LadderTier.L7)))


def test_7_unknown_with_probative_evidence_discards_evidence_and_is_rejected():
    base = unfamiliar_sdk_claim()
    with pytest.raises(EffectModelError, match="evidence requires SUPPORTED, recorded UNKNOWN"):
        replace(base, evidence_packets=(packet("pkt-1", Obligation.BOUNDARY),))


def test_7_an_undetermined_commit_never_supports_persistence():
    base = proven_claim()
    undetermined = dataclasses.replace(
        packet("pkt-undetermined", Obligation.PERSISTENCE),
        assertion=EvidenceAssertion(AssertionPredicate.COMMIT_OUTCOME_UNDETERMINED),
        polarity=Polarity.NEGATIVE)
    only_undetermined = tuple(p for p in base.evidence_packets if p.obligation is not Obligation.PERSISTENCE)
    with pytest.raises(EffectModelError, match="evidence requires UNKNOWN, recorded SUPPORTED"):
        replace(base, evidence_packets=only_undetermined + (undetermined,))
    with pytest.raises(EffectModelError, match="evidence requires UNKNOWN, recorded SUPPORTED"):
        replace(base, evidence_packets=base.evidence_packets + (undetermined,))


def test_7_cp_per_05_found_keeps_persistence_unknown():
    base = proven_claim()
    finding = packet("pkt-per05", Obligation.PERSISTENCE, polarity=Polarity.NEGATIVE,
                     admissibility=Admissibility.HYPOTHESIS_ONLY, kind=PacketKind.COUNTER_EVIDENCE_PROBE)
    probes = tuple(ProbeOutcome(o.probe_id, o.obligation, o.probe_class, ProbeResult.FOUND, packet_ids=("pkt-per05",))
                   if o.probe_id == "CP-PER-05" else o for o in base.probe_outcomes)
    with pytest.raises(EffectModelError, match="typed uncertainty assertion"):
        replace(base, evidence_packets=base.evidence_packets + (finding,), probe_outcomes=probes)


def test_7_every_settled_state_in_a_valid_claim_cites_located_verbatim_evidence():
    for claim in (proven_claim(), no_effect_claim(), resolved_claim()):
        for cid in claim.candidate_ids:
            for o in EVIDENCE_OBLIGATIONS:
                state = claim.candidate_states(cid)[o]
                if state in (S, R):
                    want = Polarity.POSITIVE if state is S else Polarity.NEGATIVE
                    cited = [p for p in claim.packets_for(o, cid) if p.is_probative and p.polarity is want]
                    assert cited
                    assert all(p.locator.path and p.extract.verbatim and p.extract.text for p in cited)


# ============================================== verdict function and closure


def test_proven_effect_requires_every_blocking_probe_to_complete():
    base = proven_claim()
    missing = tuple(o for o in base.probe_outcomes if o.probe_id != "CP-PER-03")
    with pytest.raises(EffectModelError, match="CP-PER-03 was not executed"):
        replace(base, probe_outcomes=missing)
    incomplete = tuple(ProbeOutcome(o.probe_id, o.obligation, o.probe_class, ProbeResult.INCOMPLETE,
                                    incomplete_reason=StopReason.BUDGET_EXHAUSTED)
                       if o.probe_id == "CP-OPR-01" else o for o in base.probe_outcomes)
    with pytest.raises(EffectModelError, match="CP-OPR-01 is INCOMPLETE"):
        replace(base, probe_outcomes=incomplete)
    assert replace(base, probe_outcomes=missing, verdict=Verdict.ABSTAIN).verdict is Verdict.ABSTAIN


def test_proven_effect_requires_that_no_blocking_probe_found_counter_evidence():
    # A found PROBATIVE refutation vetoes through contradiction, never by FOUND alone.
    base = proven_claim()
    negative = packet("boundary-local", Obligation.BOUNDARY, polarity=Polarity.NEGATIVE)
    found = tuple(ProbeOutcome(o.probe_id, o.obligation, o.probe_class, ProbeResult.FOUND,
                              packet_ids=(negative.packet_id,)) if o.probe_id == "CP-BND-01" else o
                  for o in base.probe_outcomes)
    with pytest.raises(EffectModelError, match="contradiction must cite every opposing"):
        replace(base, probe_outcomes=found, evidence_packets=base.evidence_packets+(negative,))
    record = Contradiction(Obligation.BOUNDARY, "cand-1", ("pkt-boundary",), (negative.packet_id,),
                           ContradictionResolution.UNRESOLVED)
    claim = replace(base, probe_outcomes=found, evidence_packets=base.evidence_packets+(negative,),
                    contradictions=(record,), obligations=states(S,S,C,S,S), verdict=Verdict.ABSTAIN,
                    acquisition=dataclasses.replace(base.acquisition, unresolved_obligations=(Obligation.BOUNDARY,)))
    assert claim.obligations.boundary is C
    assert claim.verdict is Verdict.ABSTAIN


def test_advisory_probes_do_not_gate_proven_effect():
    base = proven_claim()
    advisory = ProbeOutcome("CP-ACT-03", Obligation.ACTIVATION, ProbeClass.ADVISORY, ProbeResult.INCOMPLETE,
                            incomplete_reason=StopReason.TIER_UNAVAILABLE)
    assert replace(base, probe_outcomes=base.probe_outcomes + (advisory,)).verdict is Verdict.PROVEN_EFFECT
    hypothesis = packet("advisory-hyp", Obligation.ACTIVATION, admissibility=Admissibility.HYPOTHESIS_ONLY)
    advisory_found = ProbeOutcome("CP-ACT-03", Obligation.ACTIVATION, ProbeClass.ADVISORY, ProbeResult.FOUND,
                                  packet_ids=("advisory-hyp",))
    assert replace(base, evidence_packets=base.evidence_packets+(hypothesis,), probe_outcomes=base.probe_outcomes + (advisory_found,)).verdict is Verdict.PROVEN_EFFECT


def test_the_verdict_function_leaves_no_freedom_to_under_claim():
    with pytest.raises(EffectModelError, match="every PROVEN_EFFECT condition holds"):
        replace(proven_claim(), verdict=Verdict.ABSTAIN)


def test_boundary_alone_never_proves_an_effect():
    base = proven_claim()
    with pytest.raises(EffectModelError):
        replace(base, obligations=states(S, S, S, U, S),
                evidence_packets=tuple(p for p in base.evidence_packets if p.obligation is not Obligation.OPERATION))


@pytest.mark.parametrize("control, authority", [
    (Control(S, R, S), Authority(U)),
    (Control(U, U, U), Authority(R)),
    (Control(E, E, E), Authority(E)),
])
def test_descriptors_never_gate_the_verdict(control, authority):
    d = Descriptors(target=Target((), TargetScope.UNKNOWN), control=control, authority=authority)
    assert proven_claim(descriptors=d).verdict is Verdict.PROVEN_EFFECT


def test_no_effect_requires_closure():
    with pytest.raises(EffectModelError, match="requires an established closure"):
        no_effect_claim(closure=None)


def test_frozen_invalid_claim_is_rejected_at_every_layer_it_violates():
    # Historical 0.1.0 remains immutable and is explicitly not migrated.
    with pytest.raises(EffectModelError, match="schema_version"):
        EffectClaim.from_dict(example("effect_claim.invalid"))
    with pytest.raises(EffectModelError, match="aggregate to UNKNOWN"):
        EffectClaim.from_dict(amended_example("M2_divergence_not_contradiction"))
    with pytest.raises(EffectModelError, match="evidence requires CONFLICTING, recorded UNKNOWN"):
        EffectClaim.from_dict(amended_example("H4_uncertainty_erases_conflict"))
    with pytest.raises(EffectModelError, match="ANALYSIS_ERROR"):
        EffectClaim.from_dict(amended_example("H1_error_as_abstain"))
    with pytest.raises(EffectModelError, match="requires an established closure"):
        EffectClaim.from_dict(amended_example("M4_missing_closure"))
    assert EffectClaim.from_dict(amended_example("valid_open_frontier_abstain")).verdict is Verdict.ABSTAIN


def test_no_effect_c1_opaque_candidate():
    with pytest.raises(EffectModelError, match="opaque/unresolved identity"):
        no_effect_claim(implementation_candidates=[candidate(kind=CandidateKind.OPAQUE_EXTERNAL)])
    with pytest.raises(EffectModelError, match="opaque/unresolved identity"):
        no_effect_claim(implementation_candidates=[candidate(kind=CandidateKind.DYNAMIC_UNRESOLVED)])


def frontier(*entries, size=None, truncated=False):
    return dataclasses.replace(settled_acquisition(), frontier=tuple(entries),
                               frontier_size=len(entries) if size is None else size, frontier_truncated=truncated)


def edge(might_settle=(Obligation.PERSISTENCE,)):
    return FrontierEntry(origin=SITE, would_reach_tier=LadderTier.L5, reason=StopReason.TIER_UNAVAILABLE,
                         might_settle=might_settle)


def test_no_effect_c5_relevant_frontier():
    with pytest.raises(EffectModelError, match="C5 fails"):
        no_effect_claim(acquisition=frontier(edge()))
    with pytest.raises(EffectModelError, match="C5 fails"):
        no_effect_claim(acquisition=frontier(edge(might_settle=())))
    with pytest.raises(EffectModelError, match="complete frontier"):
        no_effect_claim(acquisition=dataclasses.replace(settled_acquisition(), frontier=None, frontier_truncated=None))
    with pytest.raises(EffectModelError, match="complete frontier"):
        no_effect_claim(acquisition=frontier(edge((Obligation.BOUNDARY,)), size=5, truncated=True))
    assert no_effect_claim(acquisition=frontier(edge((Obligation.BOUNDARY,)))).verdict is Verdict.NO_EFFECT


def test_no_effect_closure_names_a_refuted_evidence_obligation():
    with pytest.raises(EffectModelError, match="cannot be the refuted"):
        no_effect_claim(closure=Closure(Obligation.IMPLEMENTATION))
    with pytest.raises(EffectModelError, match="not REFUTED"):
        no_effect_claim(closure=Closure(Obligation.BOUNDARY))


@pytest.mark.parametrize("flag", ["C1_no_opaque_or_dynamic_candidate", "C4_no_budget_exhausted_on_contributing_path",
                                  "C6_no_error_on_necessary_obligation"])
def test_a_false_closure_flag_is_not_a_closure(flag):
    for value in (False, None, 1):
        with pytest.raises(EffectModelError, match="must be true"):
            Closure(Obligation.PERSISTENCE, **{flag: value})


def test_closure_only_on_no_effect():
    with pytest.raises(EffectModelError, match="only legal on a NO_EFFECT"):
        unfamiliar_sdk_claim(closure=Closure(Obligation.PERSISTENCE))


# ========================================================== acquisition record


def test_abstain_carries_tier_stop_reason_unresolved_and_frontier_size():
    d = unfamiliar_sdk_claim().to_dict()
    for key in ("highest_tier_reached", "stop_reason", "unresolved_obligations", "frontier_size"):
        broken = json.loads(json.dumps(d))
        broken["acquisition"].pop(key)
        with pytest.raises(EffectModelError, match="missing required"):
            EffectClaim.from_dict(broken)


def test_unresolved_obligations_are_exactly_accounted_for():
    with pytest.raises(EffectModelError, match="must be listed as unresolved"):
        unfamiliar_sdk_claim(acquisition=abstain_acquisition(unresolved=(Obligation.ACTIVATION,)))
    with pytest.raises(EffectModelError, match="cannot be listed as unresolved"):
        proven_claim(acquisition=abstain_acquisition(unresolved=(Obligation.IMPLEMENTATION,)))


def test_settled_means_nothing_is_unknown():
    with pytest.raises(EffectModelError, match="SETTLED"):
        unfamiliar_sdk_claim(acquisition=dataclasses.replace(
            settled_acquisition(), unresolved_obligations=abstain_acquisition().unresolved_obligations))


def test_budget_and_frontier_bookkeeping():
    with pytest.raises(EffectModelError, match="name the exhausted budget"):
        dataclasses.replace(abstain_acquisition(), stop_reason=StopReason.BUDGET_EXHAUSTED)
    with pytest.raises(EffectModelError, match="exactly when the reason is BUDGET_EXHAUSTED"):
        FrontierEntry(origin=SITE, would_reach_tier=LadderTier.L5, reason=StopReason.BUDGET_EXHAUSTED)
    blamed = FrontierEntry(origin=SITE, would_reach_tier=LadderTier.L5, reason=StopReason.BUDGET_EXHAUSTED,
                           budget_name=BudgetName.MAX_DEPENDENCY_HOPS)
    with pytest.raises(EffectModelError, match="not recorded as exhausted"):
        dataclasses.replace(abstain_acquisition(), frontier=(blamed,))
    for reason in (StopReason.SETTLED, StopReason.NO_FURTHER_TIER, StopReason.CLAIM_NOT_INVESTIGATED):
        with pytest.raises(EffectModelError, match="left unopened"):
            FrontierEntry(origin=SITE, would_reach_tier=LadderTier.L5, reason=reason)


def test_frontier_counts_cannot_be_summarised_away():
    with pytest.raises(EffectModelError, match="frontier_size"):
        dataclasses.replace(abstain_acquisition(), frontier_size=0)
    with pytest.raises(EffectModelError, match="marked truncated"):
        dataclasses.replace(abstain_acquisition(), frontier_size=3)
    assert dataclasses.replace(abstain_acquisition(), frontier_size=3, frontier_truncated=True)
    with pytest.raises(EffectModelError, match="not truncated"):
        dataclasses.replace(abstain_acquisition(), frontier_truncated=True)


def test_tier_accounting_is_consistent():
    with pytest.raises(EffectModelError, match="does not match"):
        dataclasses.replace(abstain_acquisition(), highest_tier_reached=LadderTier.L6)
    with pytest.raises(EffectModelError, match="attempted no tier"):
        dataclasses.replace(abstain_acquisition(), stop_reason=StopReason.CLAIM_NOT_INVESTIGATED)
    with pytest.raises(EffectModelError, match="attempted at least one tier"):
        dataclasses.replace(abstain_acquisition(), tiers_attempted=(), highest_tier_reached=LadderTier.L0)


def test_an_uninvestigated_claim_has_no_evidence():
    with pytest.raises(EffectModelError):
        replace(not_investigated_claim(), evidence_packets=(packet("pkt-1", Obligation.BOUNDARY),))


# ============================================================ strict parsing


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(rule_id="DB-WRITE"),
    lambda d: d.update(_case="annotation"),
    lambda d: d.update(schema_version="0.2.0"),
    lambda d: d["acquisition"].update(frontier_size=True),
    lambda d: d["acquisition"].update(frontier_size=1.0),
    lambda d: d.update(verdict="abstain"),
    lambda d: d.update(effect_class="MESSAGE_EMISSION_EFFECT"),
    lambda d: d.update(implementation_candidates={"cand-1": {"kind": "OPAQUE_EXTERNAL"}}),
    lambda d: d.update(claim_id=""),
    lambda d: d.update(verdict_rationale=None),
    lambda d: d["genesis"].update(basis="SINK_RULE_MATCH"),
])
def test_from_dict_rejects_malformed_claims(mutate):
    d = unfamiliar_sdk_claim().to_dict()
    mutate(d)
    with pytest.raises(EffectModelError):
        EffectClaim.from_dict(d)


def test_frozen_examples_round_trip_losslessly():
    for name in ("valid_opaque_abstain", "valid_proven"):
        claim = EffectClaim.from_dict(amended_example(name))
        assert EffectClaim.from_dict(json.loads(json.dumps(claim.to_dict()))) == claim


def test_argument_literals_distinguish_null_from_absent():
    data = unfamiliar_sdk_claim().to_dict()
    data["invocation"]["argument_shape"] = [{"position": 0, "literal": None}, {"position": "value"}]
    claim = EffectClaim.from_dict(data)
    assert claim.to_dict()["invocation"]["argument_shape"] == data["invocation"]["argument_shape"]


def test_claims_are_immutable():
    claim = unfamiliar_sdk_claim()
    with pytest.raises(dataclasses.FrozenInstanceError):
        claim.verdict = Verdict.NO_EFFECT
    with pytest.raises(AttributeError):
        claim.implementation_candidates.add(candidate("cand-2"))


def test_language_is_recorded_not_used():
    claim = unfamiliar_sdk_claim(invocation=Invocation(locator=SITE, callee_expression="x.y()",
                                                       language=Language.GO))
    assert claim.verdict is Verdict.ABSTAIN
    assert descriptors() == claim.descriptors
