"""M0: EffectReceipt.

Covers required M0 test 8: a receipt preserves evidence and counter-evidence.
A receipt built from a claim carries every packet (overridden and negative
included) and every probe outcome, and a receipt edited to drop or misstate
any of them is rejected on load.
"""

from __future__ import annotations

import copy
import dataclasses
import json

import pytest

from actenon_scan.effects import (
    BLOCKING_PROBE_IDS,
    Admissibility,
    EffectModelError,
    EffectReceipt,
    Obligation,
    ProbeClass,
    ProbeOutcome,
    ProbeResult,
    ProofState,
    RenderingConstraints,
    SelectionState,
    StopReason,
    Verdict,
)
from actenon_scan.effects.vocabulary import EVIDENCE_OBLIGATIONS, RECEIPT_ANSWER_KEYS

from ._builders import (
    C,
    R,
    S,
    U,
    all_blocking_probes_complete,
    conflicting_claim,
    error_claim,
    multi_claim,
    no_effect_claim,
    not_investigated_claim,
    proven_claim,
    resolved_claim,
    unfamiliar_sdk_claim,
)
from ._spec import example


def receipt_of(claim):
    return EffectReceipt.from_claim(dataclasses.replace(claim, receipt_id="rcpt-1"))


def roundtrip(receipt):
    return EffectReceipt.from_dict(json.loads(json.dumps(receipt.to_dict())))


def tampered(receipt, edit):
    data = copy.deepcopy(receipt.to_dict())
    edit(data)
    return data


def packet_ids(data):
    return {p["packet_id"] for p in data["evidence_packets"]}


def drop_packet(pid):
    def edit(data):
        data["evidence_packets"] = [p for p in data["evidence_packets"] if p["packet_id"] != pid]
    return edit


def counter_evidence_claim():
    """NO_EFFECT whose rollback packet was surfaced by a BLOCKING PERSISTENCE probe."""
    probes = tuple(
        dataclasses.replace(o, outcome=ProbeResult.FOUND, packet_ids=("pkt-rollback",))
        if o.probe_id == "CP-PER-01" else o
        for o in all_blocking_probes_complete()
    )
    return no_effect_claim(probe_outcomes=probes)


ALL_CLAIMS = {
    "proven": proven_claim,
    "no_effect": no_effect_claim,
    "counter_evidence": counter_evidence_claim,
    "conflicting": conflicting_claim,
    "resolved": resolved_claim,
    "error": error_claim,
    "abstain": unfamiliar_sdk_claim,
    "not_investigated": not_investigated_claim,
    "divergent": lambda: multi_claim(SelectionState.UNRESOLVED_DIVERGENT,
                                     [{Obligation.OPERATION: S}, {Obligation.OPERATION: R}]),
}


# ===================================== 8. evidence and counter-evidence kept


@pytest.mark.parametrize("name", sorted(ALL_CLAIMS))
def test_8_receipt_carries_every_packet_and_probe_of_its_claim(name):
    claim = ALL_CLAIMS[name]()
    receipt = receipt_of(claim)
    assert receipt.evidence_packets == claim.evidence_packets
    assert receipt.probe_outcomes == claim.probe_outcomes
    assert receipt.acquisition == claim.acquisition
    assert receipt.answers.contradictions.contradictions == claim.contradictions
    assert receipt.answers.implementation.candidates == claim.implementation_candidates
    assert receipt.verdict is claim.verdict


@pytest.mark.parametrize("name", sorted(ALL_CLAIMS))
def test_8_receipt_survives_json_roundtrip_unchanged(name):
    receipt = receipt_of(ALL_CLAIMS[name]())
    assert roundtrip(receipt) == receipt
    assert roundtrip(receipt).to_dict() == receipt.to_dict()


def test_8_conflicting_receipt_keeps_both_sides():
    receipt = receipt_of(conflicting_claim())
    answer = receipt.answers.operation
    assert answer.state is C
    assert set(answer.settled_by_packet_ids) == {"pkt-body", "pkt-contract"}
    extracts = {p.packet_id: p.extract.text for p in receipt.evidence_packets}
    assert "UPDATE" in extracts["pkt-body"]
    assert "read-only" in extracts["pkt-contract"]


def test_8_conflicting_receipt_cannot_be_downgraded_to_unknown():
    receipt = receipt_of(conflicting_claim())

    def downgrade(data):
        data["answers"]["operation"] = {"state": "UNKNOWN", "settled_by_packet_ids": []}
        for section in (data["answers"]["unknowns"], data["acquisition"]):
            section["unresolved_obligations"].append("OPERATION")

    with pytest.raises(EffectModelError, match="never discarded"):
        EffectReceipt.from_dict(tampered(receipt, downgrade))

    def downgrade_and_drop_record(data):
        downgrade(data)
        data["answers"]["contradictions"]["contradictions"] = []

    with pytest.raises(EffectModelError, match="never discarded"):
        EffectReceipt.from_dict(tampered(receipt, downgrade_and_drop_record))


def test_8_wholesale_erasure_is_only_detectable_by_rederiving_from_the_claim():
    """AREF-002 defines no receipt digest: a receipt is self-consistent, not tamper-evident.

    Removing every packet, record and settled answer together yields a
    coherent but different receipt. It is caught by comparing with the
    receipt derived from the claim, never by the receipt alone.
    """
    claim = dataclasses.replace(conflicting_claim(), receipt_id="rcpt-1")
    genuine = EffectReceipt.from_claim(claim)

    def erase(data):
        data["answers"]["operation"] = {"state": "UNKNOWN", "settled_by_packet_ids": []}
        for section in (data["answers"]["unknowns"], data["acquisition"]):
            section["unresolved_obligations"].append("OPERATION")
        data["answers"]["contradictions"]["contradictions"] = []
        data["evidence_packets"] = []

    forged = EffectReceipt.from_dict(tampered(genuine, erase))
    assert forged != genuine
    assert forged != EffectReceipt.from_claim(claim)
    assert forged.verdict is Verdict.ABSTAIN and not forged.is_negative_result


def test_8_resolved_receipt_keeps_the_overridden_packet_but_cites_only_the_winner():
    receipt = receipt_of(resolved_claim())
    assert "pkt-contract" in {p.packet_id for p in receipt.evidence_packets}
    assert receipt.answers.operation.state is S
    assert receipt.answers.operation.settled_by_packet_ids == ("pkt-body",)
    (record,) = receipt.answers.contradictions.contradictions
    assert record.overridden_packet_ids == ("pkt-contract",)


def test_8_overridden_packet_cannot_be_dropped_from_a_receipt():
    receipt = receipt_of(resolved_claim())
    with pytest.raises(EffectModelError, match="evidence is never discarded"):
        EffectReceipt.from_dict(tampered(receipt, drop_packet("pkt-contract")))


def test_8_cited_packet_cannot_be_dropped_from_a_receipt():
    receipt = receipt_of(proven_claim())
    with pytest.raises(EffectModelError, match="does not carry"):
        EffectReceipt.from_dict(tampered(receipt, drop_packet("pkt-operation")))


def test_8_no_effect_receipt_carries_its_refuting_packet_and_is_not_safe():
    receipt = receipt_of(no_effect_claim())
    assert receipt.answers.persistence.state is R
    assert receipt.answers.persistence.settled_by_packet_ids == ("pkt-rollback",)
    assert "rollback" in {p.packet_id: p for p in receipt.evidence_packets}["pkt-rollback"].extract.text
    assert receipt.is_negative_result is True
    assert receipt.rendering_constraints.is_negative_result is True
    assert receipt.rendering_constraints.may_render_as_safe is False
    assert "says nothing about the safety" in receipt.answers.effect.statement


def test_8_found_counter_evidence_is_reported_and_its_packet_kept():
    receipt = receipt_of(counter_evidence_claim())
    (found,) = receipt.answers.contradictions.counter_evidence_found
    assert (found.probe_id, found.outcome, found.packet_ids) == ("CP-PER-01", ProbeResult.FOUND, ("pkt-rollback",))
    assert "pkt-rollback" in {p.packet_id for p in receipt.evidence_packets}


def test_8_counter_evidence_cannot_be_suppressed():
    receipt = receipt_of(counter_evidence_claim())

    def hide_report(data):
        data["answers"]["contradictions"]["counter_evidence_found"] = []

    with pytest.raises(EffectModelError, match="counter_evidence_found"):
        EffectReceipt.from_dict(tampered(receipt, hide_report))

    with pytest.raises(EffectModelError, match="unknown packet|does not carry"):
        EffectReceipt.from_dict(tampered(receipt, drop_packet("pkt-rollback")))

    def flip_outcome(data):
        hide_report(data)
        for o in data["probe_outcomes"]:
            if o["probe_id"] == "CP-PER-01":
                o["outcome"] = "NOT_FOUND"

    with pytest.raises(EffectModelError):
        EffectReceipt.from_dict(tampered(receipt, flip_outcome))


def test_8_counter_evidence_cannot_be_invented():
    receipt = receipt_of(no_effect_claim())
    extra = ProbeOutcome("CP-PER-01", Obligation.PERSISTENCE, ProbeClass.BLOCKING, ProbeResult.FOUND,
                         packet_ids=("pkt-rollback",))

    def invent(data):
        data["answers"]["contradictions"]["counter_evidence_found"] = [extra.to_dict()]

    with pytest.raises(EffectModelError, match="counter_evidence_found"):
        EffectReceipt.from_dict(tampered(receipt, invent))


def test_8_not_found_is_never_reported_as_counter_evidence():
    with pytest.raises(EffectModelError, match="not counter-evidence found"):
        dataclasses.replace(receipt_of(proven_claim()).answers.contradictions,
                            counter_evidence_found=all_blocking_probes_complete()[:1])


# ================================================ answers must match evidence


def set_answer(obligation, **fields):
    def edit(data):
        data["answers"][obligation.value.lower()].update(fields)
    return edit


def test_supported_answer_cannot_cite_a_hypothesis_only_packet():
    base = proven_claim()
    hyp = dataclasses.replace(base.evidence_packets[0], packet_id="pkt-hyp",
                              admissibility=Admissibility.HYPOTHESIS_ONLY)
    claim = dataclasses.replace(base, evidence_packets=base.evidence_packets + (hyp,))
    receipt = receipt_of(claim)
    obligation = hyp.obligation
    with pytest.raises(EffectModelError, match="not PROBATIVE"):
        EffectReceipt.from_dict(tampered(receipt, set_answer(obligation, settled_by_packet_ids=["pkt-hyp"])))


def test_supported_answer_must_cite_something():
    receipt = receipt_of(proven_claim())
    with pytest.raises(EffectModelError, match="must name the PROBATIVE packets"):
        EffectReceipt.from_dict(tampered(receipt, set_answer(Obligation.BOUNDARY, settled_by_packet_ids=[])))


def test_supported_answer_cannot_cite_opposing_polarity():
    receipt = receipt_of(resolved_claim())
    with pytest.raises(EffectModelError, match="POSITIVE packets only"):
        EffectReceipt.from_dict(tampered(receipt, set_answer(Obligation.OPERATION,
                                                             settled_by_packet_ids=["pkt-body", "pkt-contract"])))
    with pytest.raises(EffectModelError, match="not PROBATIVE settling evidence on BOUNDARY"):
        EffectReceipt.from_dict(tampered(receipt_of(no_effect_claim()),
                                         set_answer(Obligation.BOUNDARY, settled_by_packet_ids=["pkt-rollback"])))


def test_unknown_answer_cites_nothing():
    receipt = receipt_of(unfamiliar_sdk_claim())
    with pytest.raises(EffectModelError, match="UNKNOWN obligation cannot have been settled"):
        EffectReceipt.from_dict(tampered(receipt, set_answer(Obligation.BOUNDARY, settled_by_packet_ids=["x"])))


def test_unknown_and_error_answers_carry_no_mechanism():
    for claim, o in ((unfamiliar_sdk_claim(), Obligation.BOUNDARY), (error_claim(), Obligation.BOUNDARY)):
        with pytest.raises(EffectModelError, match="no mechanism"):
            EffectReceipt.from_dict(tampered(receipt_of(claim), set_answer(o, mechanism="HTTP")))


def test_error_detail_only_on_error():
    receipt = receipt_of(unfamiliar_sdk_claim())
    with pytest.raises(EffectModelError, match="error_detail"):
        EffectReceipt.from_dict(tampered(receipt, set_answer(Obligation.BOUNDARY, error_detail="boom")))
    ok = tampered(receipt_of(error_claim()), set_answer(Obligation.BOUNDARY, error_detail="parser crashed"))
    assert EffectReceipt.from_dict(ok).answers.boundary.error_detail == "parser crashed"


def test_settled_at_tier_must_be_a_citing_packet_tier():
    receipt = receipt_of(proven_claim())
    with pytest.raises(EffectModelError, match="settled_at_tier"):
        EffectReceipt.from_dict(tampered(receipt, set_answer(Obligation.BOUNDARY, settled_at_tier="L7")))
    ok = tampered(receipt, set_answer(Obligation.BOUNDARY, settled_at_tier="L1"))
    assert EffectReceipt.from_dict(ok).answers.boundary.settled_at_tier.value == "L1"


def test_answer_cannot_be_upgraded_from_unknown_to_supported_without_evidence():
    receipt = receipt_of(unfamiliar_sdk_claim())

    def upgrade(data):
        data["answers"]["boundary"] = {"state": "SUPPORTED", "settled_by_packet_ids": ["pkt-x"]}

    with pytest.raises(EffectModelError, match="does not carry"):
        EffectReceipt.from_dict(tampered(receipt, upgrade))


def test_unknown_cannot_become_refuted_in_a_receipt():
    receipt = receipt_of(unfamiliar_sdk_claim())

    def refute(data):
        data["answers"]["persistence"] = {"state": "REFUTED", "settled_by_packet_ids": []}
        for section in (data["answers"]["unknowns"], data["acquisition"]):
            section["unresolved_obligations"].remove("PERSISTENCE")

    with pytest.raises(EffectModelError):
        EffectReceipt.from_dict(tampered(receipt, refute))


def test_unknown_obligation_must_appear_in_unknowns():
    receipt = receipt_of(unfamiliar_sdk_claim())

    def hide(data):
        for section in (data["answers"]["unknowns"], data["acquisition"]):
            section["unresolved_obligations"].remove("BOUNDARY")

    with pytest.raises(EffectModelError, match="must be listed as unresolved"):
        EffectReceipt.from_dict(tampered(receipt, hide))


def test_unknowns_answer_must_agree_with_acquisition():
    receipt = receipt_of(unfamiliar_sdk_claim())

    def disagree(data):
        data["answers"]["unknowns"]["stop_reason"] = StopReason.SETTLED.value

    with pytest.raises(EffectModelError, match="unknowns answer disagrees"):
        EffectReceipt.from_dict(tampered(receipt, disagree))


def test_divergent_receipt_keeps_both_candidates_and_selects_none():
    receipt = receipt_of(ALL_CLAIMS["divergent"]())
    impl = receipt.answers.implementation
    assert impl.selection_state is SelectionState.UNRESOLVED_DIVERGENT
    assert {c.candidate_id for c in impl.candidates} == {"cand-1", "cand-2"}
    assert impl.selected_candidate_id is None
    assert receipt.answers.operation.state is U

    def select_first(data):
        data["answers"]["implementation"]["selected_candidate_id"] = "cand-1"

    with pytest.raises(EffectModelError, match="no candidate is selected"):
        EffectReceipt.from_dict(tampered(receipt, select_first))

    def drop_second(data):
        data["answers"]["implementation"]["candidates"] = data["answers"]["implementation"]["candidates"][:1]

    with pytest.raises(EffectModelError):
        EffectReceipt.from_dict(tampered(receipt, drop_second))

    def strip_states(data):
        for cand in data["answers"]["implementation"]["candidates"]:
            del cand["obligations"]

    with pytest.raises(EffectModelError, match="carries its own obligation states"):
        EffectReceipt.from_dict(tampered(receipt, strip_states))


def test_divergent_receipt_cannot_adopt_one_candidates_answer():
    receipt = receipt_of(ALL_CLAIMS["divergent"]())

    def adopt_first(data):
        data["answers"]["operation"] = {"state": "SUPPORTED", "settled_by_packet_ids": ["p-cand-1-operation-pos"]}
        for section in (data["answers"]["unknowns"], data["acquisition"]):
            section["unresolved_obligations"].remove("OPERATION")

    with pytest.raises(EffectModelError, match="aggregate to UNKNOWN"):
        EffectReceipt.from_dict(tampered(receipt, adopt_first))


# ===================================================== verdict-level tamper


def test_error_receipt_cannot_become_abstain():
    receipt = receipt_of(error_claim())
    assert receipt.verdict is Verdict.ANALYSIS_ERROR
    assert receipt.answers.boundary.state is ProofState.ERROR

    def abstain(data):
        data["verdict"] = data["answers"]["effect"]["verdict"] = "ABSTAIN"

    with pytest.raises(EffectModelError, match="ANALYSIS_ERROR"):
        EffectReceipt.from_dict(tampered(receipt, abstain))


def test_abstain_receipt_is_never_a_negative_result():
    receipt = receipt_of(unfamiliar_sdk_claim())
    assert receipt.is_negative_result is False

    def negative(data):
        data["rendering_constraints"]["is_negative_result"] = True

    with pytest.raises(EffectModelError, match="only NO_EFFECT is a negative result"):
        EffectReceipt.from_dict(tampered(receipt, negative))


@pytest.mark.parametrize("name", sorted(ALL_CLAIMS))
def test_no_receipt_may_render_as_safe(name):
    receipt = receipt_of(ALL_CLAIMS[name]())
    assert receipt.rendering_constraints.may_render_as_safe is False

    def safe(data):
        data["rendering_constraints"]["may_render_as_safe"] = True

    with pytest.raises(EffectModelError, match="no receipt licenses a safety claim"):
        EffectReceipt.from_dict(tampered(receipt, safe))
    with pytest.raises(EffectModelError):
        RenderingConstraints(is_negative_result=True, may_render_as_safe=True)


def test_effect_answer_must_match_receipt_verdict():
    receipt = receipt_of(unfamiliar_sdk_claim())

    def mismatch(data):
        data["answers"]["effect"]["verdict"] = "NO_EFFECT"

    with pytest.raises(EffectModelError, match="effect answer disagrees"):
        EffectReceipt.from_dict(tampered(receipt, mismatch))


def test_abstain_cannot_be_relabelled_proven_or_no_effect():
    receipt = receipt_of(unfamiliar_sdk_claim())
    for verdict in ("PROVEN_EFFECT", "NO_EFFECT"):
        def relabel(data, verdict=verdict):
            data["verdict"] = data["answers"]["effect"]["verdict"] = verdict
        with pytest.raises(EffectModelError):
            EffectReceipt.from_dict(tampered(receipt, relabel))


# ================================================ BLOCKING probe reporting


def test_unexecuted_blocking_probes_are_reported_incomplete_not_not_found():
    receipt = receipt_of(unfamiliar_sdk_claim())
    assert receipt.probe_outcomes == ()
    assert tuple(receipt.answers.contradictions.blocking_probes_incomplete) == BLOCKING_PROBE_IDS
    assert len(BLOCKING_PROBE_IDS) == 16
    assert receipt.answers.contradictions.counter_evidence_found == ()


def test_proven_receipt_reports_no_incomplete_blocking_probe():
    receipt = receipt_of(proven_claim())
    assert receipt.answers.contradictions.blocking_probes_incomplete == ()


def test_incomplete_probe_must_be_listed_and_completed_probe_must_not():
    base = unfamiliar_sdk_claim()
    incomplete = ProbeOutcome("CP-BND-01", Obligation.BOUNDARY, ProbeClass.BLOCKING, ProbeResult.INCOMPLETE,
                              incomplete_reason=StopReason.TIER_UNAVAILABLE)
    receipt = receipt_of(dataclasses.replace(base, probe_outcomes=(incomplete,)))
    assert "CP-BND-01" in receipt.answers.contradictions.blocking_probes_incomplete

    def unlist(data):
        data["answers"]["contradictions"]["blocking_probes_incomplete"].remove("CP-BND-01")

    with pytest.raises(EffectModelError, match="must be reported as such"):
        EffectReceipt.from_dict(tampered(receipt, unlist))

    completed = receipt_of(proven_claim())

    def list_completed(data):
        data["answers"]["contradictions"]["blocking_probes_incomplete"] = ["CP-BND-01"]

    with pytest.raises(EffectModelError, match="completed but is reported incomplete"):
        EffectReceipt.from_dict(tampered(completed, list_completed))


def test_only_registered_blocking_probes_can_be_listed_incomplete():
    receipt = receipt_of(unfamiliar_sdk_claim())
    for bogus in ("CP-BND-04", "CP-XXX-01"):
        def add(data, bogus=bogus):
            data["answers"]["contradictions"]["blocking_probes_incomplete"].append(bogus)
        with pytest.raises(EffectModelError, match="not a registered BLOCKING probe"):
            EffectReceipt.from_dict(tampered(receipt, add))


def test_proven_receipt_cannot_carry_found_blocking_counter_evidence():
    receipt = receipt_of(proven_claim())

    def found(data):
        for o in data["probe_outcomes"]:
            if o["probe_id"] == "CP-OPR-02":
                o["outcome"] = "FOUND"
                o["packet_ids"] = ["pkt-operation"]
                data["answers"]["contradictions"]["counter_evidence_found"] = [o]

    with pytest.raises(EffectModelError, match="no BLOCKING probe found counter-evidence"):
        EffectReceipt.from_dict(tampered(receipt, found))


def test_proven_receipt_cannot_hide_an_incomplete_blocking_probe():
    receipt = receipt_of(proven_claim())

    def make_incomplete(data):
        for o in data["probe_outcomes"]:
            if o["probe_id"] == "CP-PER-02":
                o["outcome"] = "INCOMPLETE"
                o["incomplete_reason"] = "TIER_UNAVAILABLE"
        data["answers"]["contradictions"]["blocking_probes_incomplete"] = ["CP-PER-02"]

    with pytest.raises(EffectModelError, match="every BLOCKING probe"):
        EffectReceipt.from_dict(tampered(receipt, make_incomplete))


# ================================================ identity and structure


def test_receipt_id_is_required_and_must_match_the_claim():
    with pytest.raises(EffectModelError, match="needs a receipt_id"):
        EffectReceipt.from_claim(unfamiliar_sdk_claim())
    claim = dataclasses.replace(unfamiliar_sdk_claim(), receipt_id="rcpt-a")
    with pytest.raises(EffectModelError, match="names receipt"):
        EffectReceipt.from_claim(claim, receipt_id="rcpt-b")
    assert EffectReceipt.from_claim(unfamiliar_sdk_claim(), receipt_id="rcpt-c").receipt_id == "rcpt-c"


def test_answers_has_exactly_the_eleven_keys():
    receipt = receipt_of(unfamiliar_sdk_claim())
    assert tuple(receipt.to_dict()["answers"]) == RECEIPT_ANSWER_KEYS
    assert len(RECEIPT_ANSWER_KEYS) == 11
    for key in RECEIPT_ANSWER_KEYS:
        def drop(data, key=key):
            del data["answers"][key]
        with pytest.raises(EffectModelError, match=key):
            EffectReceipt.from_dict(tampered(receipt, drop))

    def extra(data):
        data["answers"]["verdict_reasoning"] = "trust me"

    with pytest.raises(EffectModelError, match="verdict_reasoning"):
        EffectReceipt.from_dict(tampered(receipt, extra))


def test_answers_obligation_refuses_implementation():
    receipt = receipt_of(unfamiliar_sdk_claim())
    for o in EVIDENCE_OBLIGATIONS:
        assert receipt.answers.obligation(o).state is U
    with pytest.raises(KeyError):
        receipt.answers.obligation(Obligation.IMPLEMENTATION)


def test_statements_name_no_provider_and_never_say_safe():
    for name, build in ALL_CLAIMS.items():
        statement = receipt_of(build()).answers.effect.statement.lower()
        assert "is safe" not in statement, name
        if receipt_of(build()).verdict is Verdict.ABSTAIN:
            assert "not" in statement or "neither" in statement, name


def test_frozen_valid_receipt_loads_and_roundtrips():
    receipt = EffectReceipt.from_dict(example("effect_receipt.valid"))
    assert roundtrip(receipt) == receipt


def test_frozen_invalid_receipt_is_rejected_for_each_stated_reason():
    data = example("effect_receipt.invalid")
    with pytest.raises(EffectModelError, match="unknowns"):
        EffectReceipt.from_dict(data)
    with pytest.raises(EffectModelError, match="must name the PROBATIVE packets"):
        EffectReceipt.from_dict(data | {"answers": data["answers"] | {"unknowns": {
            "unresolved_obligations": [], "highest_tier_reached": "L0",
            "stop_reason": "CLAIM_NOT_INVESTIGATED", "frontier_size": 0}}})
