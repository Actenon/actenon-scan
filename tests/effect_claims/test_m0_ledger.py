"""M0: CoverageLedger.

Covers required M0 test 9: the ledger distinguishes no effect, unresolved
effect, analysis error and proven effect, and never lets an unresolved or
uninvestigated claim be read as a negative result.
"""

from __future__ import annotations

import copy
import json

import pytest

from actenon_scan.effects import (
    Budgets,
    CoverageLedger,
    EffectClass,
    EffectModelError,
    Interpretation,
    Obligation,
    ProofState,
    SelectionState,
    StopReason,
    Verdict,
)

from ._builders import (
    R,
    S,
    conflicting_claim,
    error_claim,
    invocation,
    multi_claim,
    no_effect_claim,
    not_investigated_claim,
    proven_claim,
    resolved_claim,
    unfamiliar_sdk_claim,
    reidentify,
)
from ._spec import example, amended_example


def distinct(claim, n):
    """The same claim at a different invocation, so identities do not collide."""
    return reidentify(claim, claim_id=f"claim-{n:04d}", invocation_id=f"inv-{n:04d}")


def one_of_each():
    return [
        distinct(proven_claim(), 1),
        distinct(no_effect_claim(), 2),
        distinct(unfamiliar_sdk_claim(), 3),
        distinct(conflicting_claim(), 4),
        distinct(error_claim(), 5),
        not_investigated_claim(),
    ]


def ledger_of(claims, **kwargs):
    kwargs.setdefault("capabilities_discovered", 3)
    kwargs.setdefault("invocations_enumerated", len(claims))
    return CoverageLedger.from_claims(claims, **kwargs)


def tampered(ledger, edit):
    data = copy.deepcopy(ledger.to_dict())
    edit(data)
    return data


# ============================================ 9. the four outcomes stay apart


def test_9_ledger_keeps_proven_no_effect_unresolved_and_error_apart():
    ledger = ledger_of(one_of_each())
    assert ledger.proven_effect == 1
    assert ledger.no_effect == 1
    assert ledger.abstained == 2
    assert ledger.analysis_error == 1
    assert ledger.not_investigated == 1
    assert ledger.unresolved == 3
    assert ledger.negative_results == 1
    assert ledger.claims.instantiated == 6
    assert ledger.claims.investigated == 5


def test_9_only_no_effect_is_a_negative_result():
    without_no_effect = [c for c in one_of_each() if c.verdict is not Verdict.NO_EFFECT]
    ledger = ledger_of(without_no_effect)
    assert ledger.negative_results == 0
    assert ledger.abstained + ledger.not_investigated + ledger.analysis_error == 4
    assert ledger.interpretation.abstained_claims_are_not_negative_results is True
    assert ledger.interpretation.uninvestigated_claims_are_not_negative_results is True


def test_9_each_population_alone_lands_in_its_own_bucket():
    cases = {
        "proven": (proven_claim(), (1, 0, 0, 0, 0)),
        "no_effect": (no_effect_claim(), (0, 1, 0, 0, 0)),
        "abstain": (unfamiliar_sdk_claim(), (0, 0, 1, 0, 0)),
        "conflicting": (conflicting_claim(), (0, 0, 1, 0, 0)),
        "error": (error_claim(), (0, 0, 0, 1, 0)),
        "not_investigated": (not_investigated_claim(), (0, 0, 0, 0, 1)),
    }
    for name, (claim, expected) in cases.items():
        ledger = ledger_of([claim])
        got = (ledger.proven_effect, ledger.no_effect, ledger.abstained, ledger.analysis_error,
               ledger.not_investigated)
        assert got == expected, name


def test_9_uninvestigated_abstain_is_not_counted_as_an_investigated_abstain():
    ledger = ledger_of([not_investigated_claim()])
    assert ledger.verdict_distribution[Verdict.ABSTAIN] == 0
    assert ledger.stop_reason_histogram[StopReason.CLAIM_NOT_INVESTIGATED] == 1
    assert all(sum(per.values()) == 0 for per in ledger.obligation_state_distribution.values())


def test_9_obligation_distribution_counts_every_state_separately():
    ledger = ledger_of(one_of_each())
    dist = ledger.obligation_state_distribution
    assert dist[Obligation.OPERATION][ProofState.CONFLICTING] == 1
    assert dist[Obligation.PERSISTENCE][ProofState.REFUTED] == 1
    assert dist[Obligation.BOUNDARY][ProofState.ERROR] == 1
    assert dist[Obligation.PERSISTENCE][ProofState.UNKNOWN] == 3
    for o in Obligation:
        assert set(dist[o]) == set(ProofState)
        assert sum(dist[o].values()) == 5


def test_9_divergent_unknown_is_not_counted_as_refuted():
    claim = multi_claim(SelectionState.UNRESOLVED_DIVERGENT, [{Obligation.OPERATION: S}, {Obligation.OPERATION: R}])
    ledger = ledger_of([claim])
    assert ledger.obligation_state_distribution[Obligation.OPERATION][ProofState.UNKNOWN] == 1
    assert ledger.obligation_state_distribution[Obligation.OPERATION][ProofState.REFUTED] == 0
    assert ledger.obligation_state_distribution[Obligation.IMPLEMENTATION][ProofState.SUPPORTED] == 1
    assert ledger.negative_results == 0


def test_9_analysis_errors_are_counted_by_obligation():
    ledger = ledger_of(one_of_each())
    assert ledger.analysis_errors.total == 1
    assert dict(ledger.analysis_errors.by_obligation) == {Obligation.BOUNDARY: 1}


def test_9_contradictions_and_precedence_are_counted_apart():
    ledger = ledger_of([distinct(conflicting_claim(), 1), distinct(resolved_claim(), 2)])
    assert ledger.contradictions.total == 2
    assert ledger.contradictions.unresolved == 1
    assert ledger.contradictions.resolved_by_implementation_precedence == 1
    assert dict(ledger.contradictions.by_obligation) == {Obligation.OPERATION: 2}


def test_9_blocking_probes_never_executed_are_not_counted_as_executed():
    ledger = ledger_of([unfamiliar_sdk_claim()])
    assert ledger.counter_evidence.blocking_probes_executed == 0
    ledger = ledger_of([proven_claim()])
    assert ledger.counter_evidence.blocking_probes_executed == 16
    assert ledger.counter_evidence.blocking_probes_incomplete == 0


def test_9_rule_free_claims_are_counted():
    ruled = distinct(unfamiliar_sdk_claim(invocation=invocation(matched_rule_ids=("DB-WRITE",))), 9)
    ledger = ledger_of(one_of_each() + [ruled])
    assert ledger.claims.instantiated_without_any_rule_match == 6


def test_9_statement_refuses_to_read_zero_proven_as_safe():
    ledger = ledger_of([unfamiliar_sdk_claim(), not_investigated_claim()])
    text = ledger.interpretation.statement
    assert ledger.proven_effect == 0
    assert "does not mean" in text and "safe" in text
    assert "not negative results" in text
    assert ledger.interpretation.zero_proven_effect_does_not_mean_safe is True


# ========================================================= tamper rejection


@pytest.mark.parametrize("flag", Interpretation._FLAGS)
def test_interpretation_flags_are_not_configurable(flag):
    ledger = ledger_of(one_of_each())

    def unset(data):
        data["interpretation"][flag] = False

    with pytest.raises(EffectModelError, match=flag):
        CoverageLedger.from_dict(tampered(ledger, unset))


def test_abstain_cannot_be_moved_into_no_effect():
    ledger = ledger_of(one_of_each())

    def launder(data):
        data["verdict_distribution"]["ABSTAIN"] -= 1
        data["verdict_distribution"]["NO_EFFECT"] += 1

    with pytest.raises(EffectModelError, match="NO_EFFECT claim has a REFUTED obligation"):
        CoverageLedger.from_dict(tampered(ledger, launder))

    def launder_conflicting(data):
        launder(data)
        data["obligation_state_distribution"]["OPERATION"]["CONFLICTING"] -= 1
        data["obligation_state_distribution"]["OPERATION"]["REFUTED"] += 1

    rewritten = CoverageLedger.from_dict(tampered(ledger, launder_conflicting))
    assert rewritten != ledger, "a consistent rewrite of the counts is only caught by recomputing from the claims"
    assert CoverageLedger.from_claims(one_of_each(), capabilities_discovered=3, invocations_enumerated=6) == ledger


def test_abstain_cannot_be_moved_into_proven_effect():
    ledger = ledger_of(one_of_each())

    def launder(data):
        data["verdict_distribution"]["ABSTAIN"] -= 1
        data["verdict_distribution"]["PROVEN_EFFECT"] += 1

    with pytest.raises(EffectModelError, match="PROVEN_EFFECT claim has every necessary obligation SUPPORTED"):
        CoverageLedger.from_dict(tampered(ledger, launder))


def test_uninvestigated_claims_cannot_be_folded_into_verdicts():
    ledger = ledger_of(one_of_each())

    def fold(data):
        data["verdict_distribution"]["NO_EFFECT"] += 1

    with pytest.raises(EffectModelError, match="investigated claims only"):
        CoverageLedger.from_dict(tampered(ledger, fold))

    def fold_consistently(data):
        fold(data)
        data["claims"]["investigated"] += 1
        data["claims"]["not_investigated"] -= 1

    with pytest.raises(EffectModelError):
        CoverageLedger.from_dict(tampered(ledger, fold_consistently))


def test_analysis_errors_cannot_be_hidden():
    ledger = ledger_of(one_of_each())

    def hide(data):
        data["analysis_errors"]["total"] = 0

    with pytest.raises(EffectModelError, match="analysis_errors.total counts exactly"):
        CoverageLedger.from_dict(tampered(ledger, hide))


def test_error_verdict_cannot_be_relabelled_abstain_without_breaking_state_counts():
    ledger = ledger_of(one_of_each())

    def relabel(data):
        data["verdict_distribution"]["ANALYSIS_ERROR"] -= 1
        data["verdict_distribution"]["ABSTAIN"] += 1
        data["analysis_errors"] = {"total": 0}

    with pytest.raises(EffectModelError, match="never another verdict"):
        CoverageLedger.from_dict(tampered(ledger, relabel))

    def relabel_and_erase(data):
        relabel(data)
        per = data["obligation_state_distribution"]["BOUNDARY"]
        per["ERROR"] -= 1
        per["UNKNOWN"] += 1

    erased = CoverageLedger.from_dict(tampered(ledger, relabel_and_erase))
    assert erased != ledger, "a consistent rewrite of the counts is only caught by recomputing from the claims"
    assert CoverageLedger.from_claims(one_of_each(), capabilities_discovered=3, invocations_enumerated=6) == ledger


def test_analysis_error_needs_an_error_state():
    ledger = ledger_of([distinct(unfamiliar_sdk_claim(), 1)])

    def invent_error(data):
        data["verdict_distribution"]["ABSTAIN"] -= 1
        data["verdict_distribution"]["ANALYSIS_ERROR"] += 1
        data["analysis_errors"]["total"] = 1

    with pytest.raises(EffectModelError, match="has an ERROR on a necessary obligation"):
        CoverageLedger.from_dict(tampered(ledger, invent_error))


def test_merging_proof_states_is_rejected():
    ledger = ledger_of(one_of_each())

    def merge_unknown_into_refuted(data):
        per = data["obligation_state_distribution"]["PERSISTENCE"]
        per["REFUTED"] += per.pop("UNKNOWN")

    with pytest.raises(EffectModelError, match="UNKNOWN"):
        CoverageLedger.from_dict(tampered(ledger, merge_unknown_into_refuted))

    def merge_conflicting_into_unknown(data):
        per = data["obligation_state_distribution"]["OPERATION"]
        per["UNKNOWN"] += per.pop("CONFLICTING")

    with pytest.raises(EffectModelError, match="CONFLICTING"):
        CoverageLedger.from_dict(tampered(ledger, merge_conflicting_into_unknown))


def test_obligation_distribution_must_sum_to_investigated():
    ledger = ledger_of(one_of_each())

    def inflate(data):
        data["obligation_state_distribution"]["BOUNDARY"]["UNKNOWN"] += 1

    with pytest.raises(EffectModelError, match="sum to the claims investigated"):
        CoverageLedger.from_dict(tampered(ledger, inflate))


def test_verdict_distribution_needs_all_four_verdicts():
    ledger = ledger_of(one_of_each())

    def drop(data):
        del data["verdict_distribution"]["ANALYSIS_ERROR"]

    with pytest.raises(EffectModelError, match="ANALYSIS_ERROR"):
        CoverageLedger.from_dict(tampered(ledger, drop))

    def invent(data):
        data["verdict_distribution"]["SAFE"] = 0

    with pytest.raises(EffectModelError, match="SAFE"):
        CoverageLedger.from_dict(tampered(ledger, invent))


def test_histograms_must_cover_every_instantiated_claim():
    ledger = ledger_of(one_of_each())
    for key in ("highest_tier_reached_histogram", "stop_reason_histogram"):
        def shrink(data, key=key):
            first = next(iter(data[key]))
            data[key][first] -= 1
        with pytest.raises(EffectModelError):
            CoverageLedger.from_dict(tampered(ledger, shrink))


def test_claim_counts_partition():
    ledger = ledger_of(one_of_each())

    def unbalance(data):
        data["claims"]["not_investigated"] += 1

    with pytest.raises(EffectModelError, match="either investigated or not"):
        CoverageLedger.from_dict(tampered(ledger, unbalance))


def test_more_claims_than_invocations_is_rejected():
    with pytest.raises(EffectModelError, match="more claims instantiated"):
        ledger_of(one_of_each(), invocations_enumerated=2)


def test_fidelity_failures_require_fidelity_checked():
    ledger = ledger_of(one_of_each())
    assert "fidelity_checked" not in ledger.to_dict()["evidence"]
    assert "fidelity_failures" not in ledger.to_dict()["evidence"]

    def claim_fidelity(data):
        data["evidence"]["fidelity_failures"] = 0

    with pytest.raises(EffectModelError, match="fidelity was not checked"):
        CoverageLedger.from_dict(tampered(ledger, claim_fidelity))


def test_frontier_breakdowns_cannot_exceed_total():
    ledger = ledger_of([unfamiliar_sdk_claim()])
    assert ledger.frontier.total == 1

    def inflate(data):
        data["frontier"]["by_reason"]["TIER_UNAVAILABLE"] = 2

    with pytest.raises(EffectModelError, match="more than"):
        CoverageLedger.from_dict(tampered(ledger, inflate))

    def settled_as_frontier(data):
        data["frontier"]["by_reason"] = {"SETTLED": 1}

    with pytest.raises(EffectModelError, match="not a reason"):
        CoverageLedger.from_dict(tampered(ledger, settled_as_frontier))


def test_duplicate_claims_are_rejected():
    claim = unfamiliar_sdk_claim()
    with pytest.raises(EffectModelError):
        ledger_of([claim, claim])
    same_identity = type(claim)(**{**{f: getattr(claim, f) for f in claim.__dataclass_fields__},
                                   "claim_id": "claim-other"})
    with pytest.raises(EffectModelError):
        ledger_of([claim, same_identity])


def test_at_least_one_effect_class_is_enabled():
    with pytest.raises(EffectModelError, match="at least one effect class"):
        ledger_of([], invocations_enumerated=0, enabled_effect_classes=())
    ledger = ledger_of([unfamiliar_sdk_claim()])
    assert ledger.enabled_effect_classes == (EffectClass.EXTERNAL_PERSISTENT_STATE_EFFECT,)


def test_budgets_default_to_the_frozen_defaults():
    assert ledger_of([unfamiliar_sdk_claim()]).budgets == Budgets()


def test_empty_ledger_is_all_zero_and_still_not_safe():
    ledger = ledger_of([], invocations_enumerated=0)
    assert (ledger.proven_effect, ledger.no_effect, ledger.unresolved, ledger.analysis_error) == (0, 0, 0, 0)
    assert "does not mean" in ledger.interpretation.statement


def test_ledger_roundtrips_through_json():
    ledger = ledger_of(one_of_each())
    again = CoverageLedger.from_dict(json.loads(json.dumps(ledger.to_dict())))
    assert again == ledger
    assert again.to_dict() == ledger.to_dict()


def test_frozen_valid_ledger_loads_and_roundtrips():
    ledger = CoverageLedger.from_dict(amended_example("valid_ledger"))
    assert CoverageLedger.from_dict(ledger.to_dict()) == ledger
    assert ledger.unresolved == ledger.abstained + ledger.not_investigated


def test_frozen_invalid_ledger_is_rejected():
    with pytest.raises(EffectModelError):
        CoverageLedger.from_dict(example("coverage_ledger.invalid"))
