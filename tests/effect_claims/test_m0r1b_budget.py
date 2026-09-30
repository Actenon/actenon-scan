"""Test-first AREF-002B budget delta; source truth is supplied, never acquired."""
from __future__ import annotations

import copy
import dataclasses as dc
import json
from pathlib import Path
import subprocess
import sys

import pytest

from actenon_scan.effects import EffectClaim, EffectModelError, EffectReceipt, ProofState, Verdict
from ._spec import amended_example

ROOT = Path(__file__).resolve().parents[2]
BUDGET_SPEC = ROOT / 'specs' / 'AREF-002B'


def corrected():
    return json.loads((BUDGET_SPEC / 'examples/valid_unrelated_frontier_negative.json').read_text())


def abstain(data):
    data = copy.deepcopy(data)
    data['verdict'] = 'ABSTAIN'
    data.pop('closure', None)
    data['acquisition'].pop('budget_provenance', None)
    return data


def exclusion(data):
    return data['acquisition']['budget_provenance']['exclusions'][0]


def without_provenance():
    data = corrected()
    data['acquisition'].pop('budget_provenance')
    return data


def test_CASE_A_no_exhaustion_needs_no_budget_witness():
    data = amended_example('valid_no_effect')
    assert not data['acquisition'].get('budget_exhausted')
    claim = EffectClaim.from_dict(data)
    assert claim.verdict is Verdict.NO_EFFECT
    assert claim.acquisition.budget_provenance is None
    assert 'budget_provenance' not in claim.to_dict()['acquisition']


def test_CASE_B_contributing_exhaustion_retains_identity_and_abstains():
    data = without_provenance()
    data['acquisition']['frontier'][0]['might_settle'] = ['PERSISTENCE']
    with pytest.raises(EffectModelError):
        EffectClaim.from_dict(data)
    data['closure']['C4_no_budget_exhausted_on_contributing_path'] = False
    with pytest.raises(EffectModelError, match='C4'):
        EffectClaim.from_dict(data)
    claim = EffectClaim.from_dict(abstain(data))
    assert claim.verdict is Verdict.ABSTAIN
    assert claim.acquisition.budget_exhausted[0].value == 'max_dependency_hops'
    assert claim.obligations.persistence is ProofState.REFUTED


def test_CASE_C_unrelated_exhaustion_with_provenance_can_close():
    claim = EffectClaim.from_dict(corrected())
    assert claim.verdict is Verdict.NO_EFFECT
    assert claim.acquisition.budget_provenance.refuted_obligation.value == 'PERSISTENCE'
    assert claim.invocation.matched_rule_ids == ()


def test_CASE_D_bare_unrelated_label_is_insufficient_but_abstain_is_valid():
    data = without_provenance()
    with pytest.raises(EffectModelError, match='C4.*budget.*provenance'):
        EffectClaim.from_dict(data)
    assert EffectClaim.from_dict(abstain(data)).verdict is Verdict.ABSTAIN


@pytest.mark.parametrize('scope', [None, []])
def test_CASE_E_unknown_relevance_does_not_close_even_with_witness(scope):
    data = corrected()
    if scope is None:
        del data['acquisition']['frontier'][0]['might_settle']
    else:
        data['acquisition']['frontier'][0]['might_settle'] = scope
    with pytest.raises(EffectModelError, match='C5'):
        EffectClaim.from_dict(data)
    assert EffectClaim.from_dict(abstain(data)).verdict is Verdict.ABSTAIN


@pytest.mark.parametrize('missing', ['edge_name', 'budget_list', 'stop_list'])
@pytest.mark.parametrize('verdict', ['NO_EFFECT', 'ABSTAIN'])
def test_CASE_F_missing_identity_is_invalid_not_semantic_abstention(missing, verdict):
    data = without_provenance()
    if verdict == 'ABSTAIN':
        data = abstain(data)
    if missing == 'edge_name':
        del data['acquisition']['frontier'][0]['budget_name']
    elif missing == 'budget_list':
        del data['acquisition']['budget_exhausted']
    else:
        data['acquisition'].update(frontier=[], frontier_size=0)
        del data['acquisition']['budget_exhausted']
    with pytest.raises(EffectModelError, match='budget'):
        EffectClaim.from_dict(data)


def test_historical_unrelated_fixture_remains_invalid_exact_bytes():
    with pytest.raises(EffectModelError, match='budget name'):
        EffectClaim.from_dict(amended_example('valid_unrelated_frontier_negative'))


def test_claim_and_receipt_keep_budget_witness_losslessly():
    original = corrected()
    claim = EffectClaim.from_dict(original)
    assert claim.to_dict() == original
    proof = claim.acquisition.budget_provenance
    assert type(proof.exclusions) is tuple
    assert type(proof.refutation_packet_ids) is tuple
    assert type(proof.exclusions[0].frontier_indices) is tuple
    with pytest.raises(dc.FrozenInstanceError):
        proof.refuted_obligation = 'OPERATION'
    assert EffectClaim.from_dict(json.loads(json.dumps(claim.to_dict()))) == claim
    receipt = EffectReceipt.from_claim(claim, 'budget-receipt')
    wire = receipt.to_dict()
    assert wire['acquisition']['budget_provenance'] == original['acquisition']['budget_provenance']
    assert wire['claim_snapshot']['acquisition']['budget_provenance'] == original['acquisition']['budget_provenance']
    assert EffectReceipt.from_dict(json.loads(json.dumps(wire))) == receipt
    assert hash(EffectClaim.from_dict(original)) == hash(claim)


@pytest.mark.parametrize('bad', ['wrong_budget', 'missing_budget', 'duplicate_budget',
                                'missing_edge', 'extra_edge', 'duplicate_edge',
                                'boolean_edge', 'negative_edge', 'wrong_refutation',
                                'missing_packet', 'wrong_packet', 'positive_packet',
                                'duplicate_packet', 'no_source', 'no_extract',
                                'blank_extract', 'truncated_extract', 'false_verbatim',
                                'unresolved_source_version', 'reversed_source', 'unnormalized_source'])
def test_malformed_budget_proof_is_rejected_for_its_budget_reason(bad):
    data = corrected(); proof = data['acquisition']['budget_provenance']; witness = exclusion(data)
    if bad == 'wrong_budget': witness['budget_name'] = 'max_files_opened'
    elif bad == 'missing_budget': proof['exclusions'] = []
    elif bad == 'duplicate_budget': proof['exclusions'].append(copy.deepcopy(witness))
    elif bad == 'missing_edge': witness['frontier_indices'] = []
    elif bad == 'extra_edge': witness['frontier_indices'] = [0, 1]
    elif bad == 'duplicate_edge': witness['frontier_indices'] = [0, 0]
    elif bad == 'boolean_edge': witness['frontier_indices'] = [False]
    elif bad == 'negative_edge': witness['frontier_indices'] = [-1]
    elif bad == 'wrong_refutation': proof['refuted_obligation'] = 'OPERATION'
    elif bad == 'missing_packet': proof['refutation_packet_ids'] = []
    elif bad == 'wrong_packet': proof['refutation_packet_ids'] = ['missing']
    elif bad == 'positive_packet': proof['refutation_packet_ids'] = ['c1-operation']
    elif bad == 'duplicate_packet': proof['refutation_packet_ids'] *= 2
    elif bad == 'no_source': del witness['locator']
    elif bad == 'no_extract': del witness['extract']
    elif bad == 'blank_extract': witness['extract']['text'] = '  \n '
    elif bad == 'truncated_extract': witness['extract'].update(truncated=True, truncation_marker='...')
    elif bad == 'false_verbatim': witness['extract']['verbatim'] = False
    elif bad == 'unresolved_source_version': witness['locator']['version'] = '1'
    elif bad == 'reversed_source': witness['locator'].update(start_line=2, end_line=1)
    elif bad == 'unnormalized_source': witness['locator']['path'] = '../subject.py'
    with pytest.raises(EffectModelError, match='budget|locator|extract'):
        EffectClaim.from_dict(data)


def test_budget_proof_is_forbidden_when_no_exhaustion_exists():
    data = amended_example('valid_no_effect')
    data['acquisition']['budget_provenance'] = corrected()['acquisition']['budget_provenance']
    with pytest.raises(EffectModelError, match='budget.*exhaust'):
        EffectClaim.from_dict(data)


def test_missing_one_of_two_exhausted_edges_is_not_complete_coverage():
    data = corrected()
    data['acquisition']['frontier'].append(copy.deepcopy(data['acquisition']['frontier'][0]))
    data['acquisition']['frontier_size'] = 2
    with pytest.raises(EffectModelError, match='budget.*frontier'):
        EffectClaim.from_dict(data)
    exclusion(data)['frontier_indices'] = [0, 1]
    assert EffectClaim.from_dict(data).verdict is Verdict.NO_EFFECT


def test_all_budgets_need_distinct_witnesses_even_without_a_frontier_edge():
    data = corrected(); data['acquisition']['budget_exhausted'].append('max_files_opened')
    with pytest.raises(EffectModelError, match='budget.*exhaust'):
        EffectClaim.from_dict(data)
    witness = copy.deepcopy(exclusion(data)); witness.update(budget_name='max_files_opened', frontier_indices=[])
    data['acquisition']['budget_provenance']['exclusions'].append(witness)
    assert EffectClaim.from_dict(data).verdict is Verdict.NO_EFFECT


@pytest.mark.parametrize('scope', [['PERSISTENCE'], ['OPERATION', 'PERSISTENCE']])
def test_exclusion_provenance_cannot_override_relevant_C5(scope):
    data = corrected(); data['acquisition']['frontier'][0]['might_settle'] = scope
    with pytest.raises(EffectModelError, match='C5'):
        EffectClaim.from_dict(data)


def test_unrelated_witness_cannot_override_incomplete_frontier_C5():
    data = corrected(); data['acquisition'].update(frontier_size=2, frontier_truncated=True)
    with pytest.raises(EffectModelError, match='C5'):
        EffectClaim.from_dict(data)


def with_boundary_error():
    data = corrected()
    data['obligations']['BOUNDARY'] = 'ERROR'
    data['implementation_candidates'][0]['obligations']['BOUNDARY'] = 'ERROR'
    data['verdict'] = 'ANALYSIS_ERROR'; del data['closure']
    return data


def with_boundary_conflict():
    data = corrected()
    negative = copy.deepcopy(next(p for p in data['evidence_packets'] if p['obligation'] == 'BOUNDARY'))
    negative.update(packet_id='local-boundary', polarity='NEGATIVE')
    negative['assertion']['predicate'] = 'terminates_in_process_state'
    data['evidence_packets'].append(negative)
    data['obligations']['BOUNDARY'] = 'CONFLICTING'
    data['implementation_candidates'][0]['obligations']['BOUNDARY'] = 'CONFLICTING'
    data['contradictions'] = [{'obligation':'BOUNDARY', 'implementation_candidate_id':'c1',
        'positive_packet_ids':['c1-boundary'], 'negative_packet_ids':['local-boundary'], 'resolution':'UNRESOLVED'}]
    data['acquisition']['unresolved_obligations'] = ['BOUNDARY']
    data['verdict'] = 'ABSTAIN'; del data['closure']
    return data


def test_unrelated_witness_preserves_error_priority():
    data = with_boundary_error()
    assert EffectClaim.from_dict(data).verdict is Verdict.ANALYSIS_ERROR
    data['verdict'] = 'NO_EFFECT'; data['closure'] = corrected()['closure']
    with pytest.raises(EffectModelError, match='ERROR'):
        EffectClaim.from_dict(data)


def test_unrelated_witness_preserves_contradiction_and_C3():
    data = with_boundary_conflict()
    claim = EffectClaim.from_dict(data)
    assert claim.obligations.boundary is ProofState.CONFLICTING
    data['verdict'] = 'NO_EFFECT'; data['closure'] = corrected()['closure']
    with pytest.raises(EffectModelError, match='C3'):
        EffectClaim.from_dict(data)


def test_proof_on_abstain_is_still_checked_not_trusted():
    data = with_boundary_conflict()
    exclusion(data)['frontier_indices'] = []
    with pytest.raises(EffectModelError, match='budget.*frontier'):
        EffectClaim.from_dict(data)


def test_negative_receipt_cannot_drop_exclusion_or_retain_relevant_frontier():
    wire = EffectReceipt.from_claim(EffectClaim.from_dict(corrected()), 'budget-receipt').to_dict()
    missing = copy.deepcopy(wire)
    for obj in (missing, missing['claim_snapshot']):
        del obj['acquisition']['budget_provenance']
    with pytest.raises(EffectModelError, match='C4'):
        EffectReceipt.from_dict(missing)
    relevant = copy.deepcopy(wire)
    for obj in (relevant, relevant['claim_snapshot']):
        obj['acquisition']['frontier'][0]['might_settle'] = ['PERSISTENCE']
    relevant['answers']['unknowns']['frontier'][0]['might_settle'] = ['PERSISTENCE']
    with pytest.raises(EffectModelError, match='C5'):
        EffectReceipt.from_dict(relevant)


def test_budget_verifier_absence_is_fatal():
    result = subprocess.run([sys.executable, '-S', '-B', 'specs/AREF-002B/validate.py'],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 2
    assert result.stderr.strip() == 'FATAL: required schema verifier unavailable'
