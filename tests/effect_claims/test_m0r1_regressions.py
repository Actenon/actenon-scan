"""M0R1 test-first regressions and sealed AREF-002A conformance inputs."""
from __future__ import annotations

import copy
import dataclasses as dc
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys

import jsonschema
import pytest
from referencing import Registry, Resource

from actenon_scan.effects import (
    Admissibility, AssertionPredicate, Contradiction, ContradictionResolution,
    CoverageLedger, EffectClaim, EffectModelError, EffectReceipt, EvidenceAssertion,
    EvidencePacket, Obligation, PacketKind, Polarity, ProbeResult, ProofState,
    SelectionState, StopReason, Verdict, aggregate_claim_states, aggregate_obligation,
)
from ._builders import (
    C, E, R, S, U, full_closure, no_effect_claim, packet, proven_claim,
    resolved_claim, rolled_back_packet, states,
)

ROOT = Path(__file__).resolve().parents[2]
AMENDMENT = ROOT / 'specs' / 'AREF-002A'
CASES = json.loads((AMENDMENT / 'case_registry.json').read_text())


def fixture(name):
    return json.loads((AMENDMENT / 'examples' / (name + '.json')).read_text())


def test_H1_two_candidates_implementation_error_cannot_prove():
    base = proven_claim()
    one = next(iter(base.implementation_candidates))
    candidates = [dc.replace(one, obligations=states(S, S, S, S, S)),
                  dc.replace(one, candidate_id='second', obligations=states(E, S, S, S, S))]
    packets = base.evidence_packets + tuple(dc.replace(p, packet_id='second-'+p.packet_id,
                implementation_candidate_id='second') for p in base.evidence_packets)
    with pytest.raises(EffectModelError):
        dc.replace(base, implementation_candidates=candidates, evidence_packets=packets,
                   selection_state=SelectionState.AGREEMENT_INVARIANT)
    aggregate = aggregate_claim_states(SelectionState.AGREEMENT_INVARIANT,
                                      [x.obligations for x in candidates])
    assert aggregate.implementation is E


def test_H2_positive_ephemeral_is_not_persistence_support():
    with pytest.raises(EffectModelError):
        dc.replace(packet('ephemeral', Obligation.PERSISTENCE),
                   assertion=EvidenceAssertion(AssertionPredicate.STATE_IS_EPHEMERAL))


def test_H3_L1_package_provenance_cannot_override_contract():
    base = resolved_claim()
    with pytest.raises(EffectModelError):
        packets = tuple(dc.replace(p, kind=PacketKind.PACKAGE_PROVENANCE)
                        if p.packet_id == 'pkt-body' else p for p in base.evidence_packets)
        dc.replace(base, evidence_packets=packets)


def test_H4_uncertainty_cannot_hide_conflict_to_allow_negative():
    base = proven_claim()
    durable = next(p for p in base.evidence_packets if p.obligation is Obligation.PERSISTENCE)
    rollback = rolled_back_packet()
    uncertainty = dc.replace(rollback, packet_id='uncertainty',
                            assertion=EvidenceAssertion(AssertionPredicate.COMMIT_OUTCOME_UNDETERMINED))
    operation_read = packet('read', Obligation.OPERATION, polarity=Polarity.NEGATIVE)
    packets = tuple(p for p in base.evidence_packets if p.obligation is not Obligation.OPERATION)
    contradiction = Contradiction(Obligation.PERSISTENCE, durable.implementation_candidate_id,
                                  (durable.packet_id,), (rollback.packet_id,), ContradictionResolution.UNRESOLVED)
    with pytest.raises(EffectModelError):
        dc.replace(base, obligations=states(S, S, S, R, U),
                   evidence_packets=packets+(operation_read, rollback, uncertainty),
                   contradictions=(contradiction,), verdict=Verdict.NO_EFFECT,
                   closure=full_closure(Obligation.OPERATION),
                   acquisition=dc.replace(base.acquisition, stop_reason=StopReason.NO_FURTHER_TIER,
                                          unresolved_obligations=(Obligation.PERSISTENCE,)))


def test_H5_receipt_open_frontier_cannot_load_as_negative():
    data = EffectReceipt.from_claim(no_effect_claim(), 'receipt').to_dict()
    edge = fixture('valid_open_frontier_abstain')['acquisition']['frontier']
    for acq in [data['acquisition'], data['answers']['unknowns']]:
        acq.update(frontier_size=1, frontier=edge, stop_reason='TIER_UNAVAILABLE')
    if 'claim_snapshot' in data:
        data['claim_snapshot']['acquisition'].update(frontier_size=1, frontier=edge,
                                                    stop_reason='TIER_UNAVAILABLE')
    with pytest.raises(EffectModelError):
        EffectReceipt.from_dict(data)


def test_H6_impossible_error_conflict_negative_population_rejected():
    data = fixture('H6_impossible_settled_population')
    # On unrepaired M0, test the semantic defect rather than version rejection.
    from actenon_scan.effects import SCHEMA_VERSION
    data['schema_version'] = SCHEMA_VERSION
    with pytest.raises(EffectModelError, match='BOUNDARY ERROR and CONFLICTING are disjoint'):
        CoverageLedger.from_dict(data)


def test_H6_disjointness_is_checked_without_optional_error_breakdowns():
    data = fixture('H6_impossible_settled_population')
    del data['analysis_errors']['by_obligation']
    with pytest.raises(EffectModelError, match='BOUNDARY ERROR and CONFLICTING are disjoint'):
        CoverageLedger.from_dict(data)


def test_M1_hypothesis_found_does_not_veto_proof():
    base = proven_claim()
    hypothesis = dc.replace(packet('hypothesis', Obligation.PERSISTENCE),
                            admissibility=Admissibility.HYPOTHESIS_ONLY,
                            kind=PacketKind.IDENTIFIER_NAME, polarity=Polarity.NEGATIVE,
                            assertion=EvidenceAssertion(AssertionPredicate.STATE_IS_EPHEMERAL))
    probes = tuple(dc.replace(p, outcome=ProbeResult.FOUND, packet_ids=('hypothesis',))
                   if p.probe_id == 'CP-PER-03' else p for p in base.probe_outcomes)
    assert dc.replace(base, evidence_packets=base.evidence_packets+(hypothesis,),
                      probe_outcomes=probes).verdict is Verdict.PROVEN_EFFECT


TABLE = {S: [S,U,U,C,E], R: [U,R,U,C,E], U: [U,U,U,C,E], C: [C,C,C,C,E], E: [E,E,E,E,E]}
ORDER = (S,R,U,C,E)


@pytest.mark.parametrize('left,right', tuple(itertools.product(ORDER, repeat=2)))
def test_M2_every_ordered_pair(left, right):
    assert aggregate_obligation([left,right]) is TABLE[left][ORDER.index(right)]


def test_M2_triples_order_independent_and_associative():
    for values in itertools.product(ORDER, repeat=3):
        results = {aggregate_obligation(p) for p in itertools.permutations(values)}
        assert len(results) == 1
        a,b,c = values
        assert aggregate_obligation([aggregate_obligation([a,b]),c]) is aggregate_obligation([a,aggregate_obligation([b,c])])


def test_M3_opaque_unknown_singleton_without_sink():
    claim = EffectClaim.from_dict(fixture('valid_opaque_abstain'))
    assert claim.selection_state.value == 'UNRESOLVED_IDENTITY'
    assert all(s is U for _,s in claim.obligations.items())
    assert claim.invocation.matched_rule_ids == ()
    assert claim.verdict is Verdict.ABSTAIN
    assert claim.selected_candidate() is None


def schema_validator(name):
    schemas = [json.loads(p.read_text()) for p in AMENDMENT.glob('*.schema.json')]
    registry = Registry().with_resources((s['$id'],Resource.from_contents(s)) for s in schemas)
    schema = json.loads((AMENDMENT/(name+'.schema.json')).read_text())
    return jsonschema.Draft202012Validator(schema,registry=registry)


def test_M4_runtime_negative_conforms_and_missing_closure_fails():
    data = no_effect_claim().to_dict()
    schema_validator('effect_claim').validate(data)
    del data['closure']
    assert any(e.validator == 'required' and 'closure' in e.message for e in schema_validator('effect_claim').iter_errors(data))
    with pytest.raises(EffectModelError):
        EffectClaim.from_dict(data)


def test_M5_missing_schema_dependency_is_failure_not_skip():
    # Freeze behavior of the test import itself: absence must raise, not importorskip.
    code = '''import builtins, runpy
original = builtins.__import__
def blocked(name, *a, **kw):
    if name in ('jsonschema', 'referencing'):
        raise ImportError('M0R1 simulated missing verifier')
    return original(name, *a, **kw)
builtins.__import__ = blocked
runpy.run_module('tests.effect_claims.test_m0_schema_conformance', run_name='__main__')
'''
    result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                            env={**os.environ, 'PYTHONPATH':str(ROOT)}, capture_output=True,text=True)
    assert result.returncode != 0
    assert 'Skipped' not in result.stderr
    assert 'ImportError: M0R1 simulated missing verifier' in result.stderr


def test_M5_conformance_command_absence_is_fatal():
    result = subprocess.run([sys.executable, '-S', '-B', 'scripts/validate_aref002a.py'],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 2
    assert 'FATAL: required architecture verifier failed' in result.stderr
    assert 'jsonschema' in result.stderr


def test_typed_registry_matches_every_normative_tuple_exactly():
    from actenon_scan.effects._assertions import PROBATIVE_ASSERTIONS
    registry = json.loads((AMENDMENT/'assertion_registry.json').read_text())
    expected = frozenset((r['predicate'],r['obligation'],r['polarity'],s['kind'],s['tier'])
                         for r in registry['rules'] for s in r['sources'])
    assert PROBATIVE_ASSERTIONS == expected


def test_unknown_predicate_is_retained_without_settling_an_obligation():
    claim = EffectClaim.from_dict(fixture('valid_unregistered_hypothesis'))
    assert claim.obligations.persistence is U
    data = next(p.to_dict() for p in claim.evidence_packets if p.admissibility is Admissibility.HYPOTHESIS_ONLY)
    loaded = EvidencePacket.from_dict(data)
    assert not loaded.is_probative
    assert loaded.assertion.predicate == data['assertion']['predicate']
    assert EvidencePacket.from_dict(loaded.to_dict()) == loaded
    data['admissibility'] = 'PROBATIVE'
    with pytest.raises(EffectModelError, match='unregistered predicate/obligation/polarity/source'):
        EvidencePacket.from_dict(data)


@pytest.mark.parametrize('case', CASES, ids=lambda c:c['id'])
def test_sealed_amendment_examples(case):
    data = json.loads((AMENDMENT/case['file']).read_text())
    cls = {'claim':EffectClaim,'receipt':EffectReceipt,'ledger':CoverageLedger,'evidence':EvidencePacket}[case['kind']]
    if case['valid']:
        loaded = cls.from_dict(data)
        again = cls.from_dict(json.loads(json.dumps(loaded.to_dict())))
        assert again == loaded
        schema_validator({'claim':'effect_claim','receipt':'effect_receipt','ledger':'coverage_ledger','evidence':'evidence'}[case['kind']]).validate(loaded.to_dict())
        if 'verdict' in case:assert loaded.verdict.value == case['verdict']
    else:
        with pytest.raises(EffectModelError):
            cls.from_dict(data)


def test_whole_claim_candidate_order_and_equal_states_preserve_identities():
    base = fixture('valid_agreement')
    original = EffectClaim.from_dict(base)
    assert isinstance(original.implementation_candidates, frozenset)
    assert len(original.candidate_ids) == 2
    for order in itertools.permutations(base['implementation_candidates']):
        data = copy.deepcopy(base); data['implementation_candidates'] = list(order)
        assert EffectClaim.from_dict(data) == original
