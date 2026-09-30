"""M0: the closed vocabularies are exactly the frozen AREF-002 vocabularies.

Also establishes that proof states and verdicts cannot be ordered, joined or
loosely coerced, which is the mechanism by which UNKNOWN would otherwise drift
into REFUTED, CONFLICTING into UNKNOWN, or ERROR into ABSTAIN.
"""

from __future__ import annotations

import pytest

from actenon_scan.effects import (
    BLOCKING_PROBE_IDS,
    PROBE_REGISTRY,
    RULE_MATCH_ADMISSIBILITY,
    TIER_CAN_SETTLE,
    Admissibility,
    AssertionPredicate,
    BudgetName,
    Budgets,
    CandidateKind,
    ConditionKind,
    ContradictionResolution,
    EffectClass,
    EffectModelError,
    InertnessBlocker,
    LadderTier,
    Language,
    Obligation,
    ObligationStates,
    PacketKind,
    Polarity,
    ProbeClass,
    ProbeResult,
    ProofState,
    RuleMatchType,
    SelectionState,
    StopReason,
    Strength,
    TargetScope,
    Verdict,
    VersionResolution,
)
from actenon_scan.repository.symbol_index import ResolutionCertainty
from actenon_scan.repository.taint import TaintLattice

from ._spec import manifest, schema, historical_schema


def members(enum_cls) -> list[str]:
    return [m.value for m in enum_cls]


def test_proof_states_are_exactly_the_frozen_five():
    assert members(ProofState) == ["SUPPORTED", "REFUTED", "UNKNOWN", "CONFLICTING", "ERROR"]
    assert members(ProofState) == manifest()["vocabularies"]["proof_states"]["members"]


def test_verdicts_are_exactly_the_frozen_four():
    assert members(Verdict) == ["PROVEN_EFFECT", "NO_EFFECT", "ABSTAIN", "ANALYSIS_ERROR"]
    assert members(Verdict) == manifest()["vocabularies"]["verdicts"]["members"]


@pytest.mark.parametrize("enum_cls, key", [
    (Obligation, "obligations"),
    (CandidateKind, "implementation_candidate_kinds"),
    (SelectionState, "selection_states"),
    (Admissibility, "admissibility"),
    (Polarity, "polarity"),
    (LadderTier, "ladder_tiers"),
    (StopReason, "stop_reasons"),
    (BudgetName, "budget_names"),
    (ContradictionResolution, "contradiction_resolutions"),
])
def test_manifest_vocabularies(enum_cls, key):
    if key == "selection_states":
        assert members(enum_cls) == schema("effect_claim")["$defs"]["selectionState"]["enum"]
    else:
        assert members(enum_cls) == manifest()["vocabularies"][key]["members"]


def _defs(name):
    return schema(name)["$defs"]


@pytest.mark.parametrize("enum_cls, values", [
    (PacketKind, lambda: _defs("evidence")["packetKind"]["enum"]),
    (AssertionPredicate, lambda: historical_schema("evidence")["$defs"]["assertion"]["properties"]["predicate"]["enum"]),
    (RuleMatchType, lambda: _defs("evidence")["ruleMatchType"]["enum"]),
    (VersionResolution, lambda: _defs("evidence")["versionResolution"]["enum"]),
    (Strength, lambda: _defs("evidence")["strength"]["enum"]),
    (ProbeResult, lambda: _defs("evidence")["probeOutcome"]["properties"]["outcome"]["enum"]),
    (ProbeClass, lambda: _defs("evidence")["probeOutcome"]["properties"]["probe_class"]["enum"]),
    (EffectClass, lambda: _defs("effect_claim")["effectClass"]["enum"]),
    (CandidateKind, lambda: _defs("effect_claim")["candidateKind"]["enum"]),
    (InertnessBlocker, lambda: _defs("effect_claim")["genesis"]["properties"]["inertness_blockers"]["items"]["enum"]),
    (Language, lambda: _defs("effect_claim")["invocation"]["properties"]["language"]["enum"]),
    (TargetScope, lambda: _defs("effect_claim")["target"]["properties"]["scope"]["enum"]),
    (ConditionKind, lambda: _defs("effect_claim")["condition"]["properties"]["kind"]["enum"]),
    (ProofState, lambda: _defs("effect_claim")["proofState"]["enum"]),
    (Verdict, lambda: _defs("effect_claim")["verdict"]["enum"]),
])
def test_schema_vocabularies(enum_cls, values):
    assert sorted(members(enum_cls)) == sorted(values())


def test_reused_repository_vocabularies_match_the_schema():
    assert sorted(members(TaintLattice)) == sorted(_defs("effect_claim")["taintState"]["enum"])
    assert sorted(members(ResolutionCertainty)) == sorted(_defs("effect_claim")["resolutionState"]["enum"])


def test_probe_registry_is_the_frozen_closed_registry():
    frozen = {p["probe_id"]: (p["obligation"], p["probe_class"]) for p in manifest()["counter_evidence_probes"]}
    ours = {pid: (spec.obligation.value, spec.probe_class.value) for pid, spec in PROBE_REGISTRY.items()}
    assert ours == frozen
    assert len(PROBE_REGISTRY) == 22
    assert len(BLOCKING_PROBE_IDS) == 16


def test_sink_rule_admissibility_is_the_frozen_table():
    frozen = manifest()["sink_rule_admissibility"]
    assert {m.value for m in RULE_MATCH_ADMISSIBILITY} == set(frozen)
    for match_type, rule in RULE_MATCH_ADMISSIBILITY.items():
        assert rule.admissibility.value == frozen[match_type.value]["admissibility"]
        assert sorted(o.value for o in rule.may_settle) == sorted(frozen[match_type.value]["may_settle"])


def test_rule_matches_never_settle_persistence_or_activation():
    for rule in RULE_MATCH_ADMISSIBILITY.values():
        assert Obligation.PERSISTENCE not in rule.may_settle
        assert Obligation.ACTIVATION not in rule.may_settle
        assert Obligation.IMPLEMENTATION not in rule.may_settle


def test_tier_settlement_table_is_the_frozen_ladder():
    for tier in manifest()["ladder"]:
        assert sorted(o.value for o in TIER_CAN_SETTLE[LadderTier(tier["tier"])]) == sorted(tier["can_settle"])
    by_obligation = {o["id"]: o["settled_by_tiers"] for o in manifest()["obligations"]}
    for o in Obligation:
        assert sorted(t.value for t in LadderTier if o in TIER_CAN_SETTLE[t]) == sorted(by_obligation[o.value])


def test_budget_defaults_are_frozen():
    assert Budgets().to_dict() == manifest()["budgets"]["defaults"]


def test_l8_is_not_an_evidence_tier():
    assert LadderTier.L8 not in LadderTier.evidence_tiers()
    assert TIER_CAN_SETTLE[LadderTier.L8] == frozenset()


# ------------------------------------------------ no ordering, no loose joins


@pytest.mark.parametrize("enum_cls", [ProofState, Verdict, Obligation, SelectionState, LadderTier, Admissibility])
def test_closed_vocabularies_cannot_be_ordered(enum_cls):
    a, b = list(enum_cls)[:2]
    for compare in (lambda: a < b, lambda: a <= b, lambda: a > b, lambda: a >= b):
        with pytest.raises(TypeError):
            compare()
    with pytest.raises(TypeError):
        sorted(enum_cls)


def test_no_lattice_join_can_turn_unknown_into_refuted():
    with pytest.raises(TypeError):
        max([ProofState.UNKNOWN, ProofState.REFUTED])
    with pytest.raises(TypeError):
        min([ProofState.CONFLICTING, ProofState.UNKNOWN])
    with pytest.raises(TypeError):
        max([Verdict.ANALYSIS_ERROR, Verdict.ABSTAIN])


def test_distinct_states_are_distinct():
    assert ProofState.UNKNOWN != ProofState.REFUTED
    assert ProofState.CONFLICTING != ProofState.UNKNOWN
    assert ProofState.ERROR != ProofState.UNKNOWN
    assert ProofState.ERROR != Verdict.ABSTAIN
    assert Verdict.ANALYSIS_ERROR != Verdict.ABSTAIN
    assert Verdict.ABSTAIN != Verdict.NO_EFFECT


def _states(**override):
    fields = dict(implementation=ProofState.SUPPORTED, activation=ProofState.UNKNOWN,
                  boundary=ProofState.UNKNOWN, operation=ProofState.UNKNOWN, persistence=ProofState.UNKNOWN)
    fields.update(override)
    return ObligationStates(**fields)


@pytest.mark.parametrize("bad", [
    Verdict.ABSTAIN,            # a member of the wrong vocabulary
    "unknown",                  # wrong case
    "UNKNOWN ",                 # trailing space
    "Unknown",
    None,                       # no default state exists
    0,
    True,
    "REFUTED_OR_UNKNOWN",
])
def test_proof_state_coercion_is_exact(bad):
    with pytest.raises(EffectModelError):
        _states(persistence=bad)


def test_exact_wire_strings_are_accepted():
    s = _states(persistence="REFUTED")
    assert s.persistence is ProofState.REFUTED


def test_verdict_is_not_a_proof_state_and_vice_versa():
    from actenon_scan.effects._codec import enum_value
    with pytest.raises(EffectModelError):
        enum_value(Verdict, ProofState.ERROR, "verdict")
    with pytest.raises(EffectModelError):
        enum_value(ProofState, Verdict.ANALYSIS_ERROR, "state")
    with pytest.raises(EffectModelError):
        enum_value(Verdict, "ERROR", "verdict")
