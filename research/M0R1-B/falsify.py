"""Post-repair adversarial constructions; no evidence acquisition or source edits."""
from __future__ import annotations
import copy
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from actenon_scan.effects import EffectClaim, EffectReceipt, CoverageLedger, EffectModelError, ProofState, aggregate_obligation

SPEC = ROOT / 'specs' / 'AREF-002A'
RESULTS = []


def fixture(name):
    return json.loads((SPEC / 'examples' / (name + '.json')).read_text())


def reject(name, cls, data):
    try:
        loaded = cls.from_dict(copy.deepcopy(data))
    except EffectModelError as error:
        RESULTS.append({'attempt':name,'pass':True,'result':'REJECTED','reason':str(error)})
    else:
        RESULTS.append({'attempt':name,'pass':False,'result':'ACCEPTED','verdict':getattr(getattr(loaded,'verdict',None),'value',None)})


def retained(name, file, verdict):
    try:
        claim = EffectClaim.from_dict(fixture(file))
        receipt = EffectReceipt.from_claim(claim, 'falsification-receipt')
        again = EffectReceipt.from_dict(json.loads(json.dumps(receipt.to_dict())))
        ok = claim.verdict.value == verdict and receipt.verdict.value == verdict and again == receipt
        RESULTS.append({'attempt':name,'pass':ok,'verdict':claim.verdict.value,
                        'implementation':claim.obligations.implementation.value,
                        'matched_rule_ids':list(claim.invocation.matched_rule_ids)})
    except EffectModelError as error:
        RESULTS.append({'attempt':name,'pass':False,'reason':str(error)})


def main():
    for name in ['H1_error_erased','H1_error_bad_selection','H1_agreement_hides_error',
                 'H2_positive_state_is_ephemeral','H2_positive_state_is_guaranteed_rolled_back',
                 'H2_positive_dry_run_in_force','H2_positive_test_double_in_force','H2_positive_noop',
                 'H2_transport_persistence','H2_transport_operation','H2_unregistered_probative',
                 'H3_tier_not_selection_proof','H3_unlinked_body','H3_package_not_body',
                 'H3_no_recorded_provenance','H3_other_source_identity',
                 'H4_uncertainty_erases_conflict','H4_conflict_negative_closure',
                 'M3_opaque_false_establishment','M3_opaque_supported_identity','M3_opaque_omitted_states']:
        reject(name, EffectClaim, fixture(name))
    reject('H5_receipt_open_frontier',EffectReceipt,fixture('H5_receipt_and_snapshot_open_negative'))
    reject('H5_receipt_strengthening',EffectReceipt,fixture('H5_receipt_strengthened'))
    reject('H6_impossible_ledger',CoverageLedger,fixture('H6_impossible_settled_population'))
    data=fixture('H6_impossible_settled_population');del data['analysis_errors']['by_obligation']
    reject('H6_impossible_ledger_without_breakdown',CoverageLedger,data)
    data=fixture('valid_proven');data['evidence_packets']=[]
    reject('empty_evidence_cannot_prove',EffectClaim,data)
    data=fixture('valid_no_effect');del data['closure']
    reject('missing_negative_closure',EffectClaim,data)
    retained('sink_independent_opaque_genesis','valid_opaque_abstain','ABSTAIN')
    retained('completed_harmless_FOUND','valid_hypothesis_found','PROVEN_EFFECT')
    retained('completed_resolved_FOUND','valid_precedence_found','PROVEN_EFFECT')
    retained('uncertainty_retains_conflict','valid_uncertainty_preserves_conflict','ABSTAIN')
    names=('valid_agreement','valid_divergent','valid_multi_error','valid_multi_conflict')
    permutations=0;ok=True
    for name in names:
        data=fixture(name);expected=EffectClaim.from_dict(data)
        for order in itertools.permutations(data['implementation_candidates']):
            altered=copy.deepcopy(data);altered['implementation_candidates']=list(order)
            loaded=EffectClaim.from_dict(altered);permutations+=1
            ok &= loaded == expected and loaded.to_dict() == expected.to_dict()
    RESULTS.append({'attempt':'candidate_ordering','pass':ok,'permutations':permutations})
    order=tuple(ProofState);combinations=0;ok=True
    for values in itertools.product(order,repeat=3):
        expected=(ProofState.ERROR if ProofState.ERROR in values else ProofState.CONFLICTING
                  if ProofState.CONFLICTING in values else values[0] if len(set(values))==1 else ProofState.UNKNOWN)
        for perm in itertools.permutations(values):
            combinations+=1;ok &= aggregate_obligation(perm) is expected
    RESULTS.append({'attempt':'aggregation_triples_ordering','pass':ok,'permutations':combinations})
    absence=subprocess.run([sys.executable,'-S','-B',str(ROOT/'scripts/validate_aref002a.py')],capture_output=True,text=True,cwd=ROOT)
    RESULTS.append({'attempt':'schema_verifier_absence','pass':absence.returncode==2 and 'FATAL:' in absence.stderr,
                    'exit_code':absence.returncode,'stderr':absence.stderr.strip()})
    # Identical legacy source fixture; import each historical scanner in an isolated process.
    fixture_path=ROOT/'tests/fixtures/vulnerable'
    script="import json; from actenon_scan.engine import scan_path; from actenon_scan.report.json_out import format_json; print(format_json(scan_path("+repr(str(fixture_path))+")))"
    scans={}
    for name,sha in [('baseline','b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16'),('failed_M0','a93b013383ce773b10708d3f30b2a1660e141527'),('M0R1','ec4db0c2ab61c6d5b1c5d8537a9617f2d2534b30'),('M0R1-B',None)]:
        with tempfile.TemporaryDirectory(prefix='m0r1-legacy-') as directory:
            source=ROOT
            if sha:
                archive=subprocess.run(['git','archive','--format=zip',sha],cwd=ROOT,check=True,capture_output=True).stdout
                with zipfile.ZipFile(io.BytesIO(archive)) as zipped:zipped.extractall(directory)
                source=Path(directory)
            result=subprocess.run([sys.executable,'-B','-c',script],cwd=source,
                env={**os.environ,'PYTHONPATH':str(source),'PYTHONDONTWRITEBYTECODE':'1'},check=True,capture_output=True,text=True)
            data=json.loads(result.stdout)
            scans[name]={'sha256':hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest(),
                         'finding_count':data['finding_count']}
    RESULTS.append({'attempt':'legacy_Finding_output_baseline_M0_M0R1_M0R1B','pass':len({s['sha256'] for s in scans.values()})==1,'reports':scans})
    budget_attacks()
    report={'attempts':len(RESULTS),'passed':sum(r['pass'] for r in RESULTS),
            'failed':sum(not r['pass'] for r in RESULTS),'results':RESULTS,
            'claim_boundary':'Supplied proof-record validation only; C4 is represented, not acquired or verified.'}
    (ROOT/'research/M0R1-B/falsification_results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
    return bool(report['failed'])


def budget_attacks():
    from tests.effect_claims.test_m0r1b_budget import (
        corrected, without_provenance, abstain, exclusion,
        with_boundary_error, with_boundary_conflict,
    )
    reject('B1_fake_unrelated_label_without_witness', EffectClaim, without_provenance())
    data=corrected();exclusion(data)['budget_name']='max_files_opened'
    reject('B2_witness_for_wrong_budget',EffectClaim,data)
    data=corrected();data['acquisition']['frontier'].append(copy.deepcopy(data['acquisition']['frontier'][0]));data['acquisition']['frontier_size']=2
    reject('B3_missing_one_exhausted_edge',EffectClaim,data)
    data=corrected();data['acquisition']['budget_provenance']['refuted_obligation']='OPERATION'
    reject('B4_wrong_refutation',EffectClaim,data)
    data=corrected();del exclusion(data)['locator']
    reject('B5_missing_source_provenance',EffectClaim,data)
    data=without_provenance();data['acquisition']['frontier'][0]['might_settle']=['PERSISTENCE']
    reject('B6_C4_true_contributing_exhaustion',EffectClaim,data)
    data=corrected();data['acquisition']['frontier'][0]['might_settle']=['PERSISTENCE']
    reject('B7_witness_cannot_override_C5',EffectClaim,data)
    data=with_boundary_error();data['verdict']='NO_EFFECT';data['closure']=corrected()['closure']
    reject('B8_witness_cannot_hide_ERROR',EffectClaim,data)
    data=with_boundary_conflict();data['verdict']='NO_EFFECT';data['closure']=corrected()['closure']
    reject('B9_witness_cannot_hide_CONFLICTING',EffectClaim,data)
    data=abstain(corrected());del data['acquisition']['frontier'][0]['budget_name']
    reject('B10_missing_identity_cannot_be_ABSTAIN',EffectClaim,data)
    # Beyond the ten required attacks: a valid multi-candidate refutation must
    # cite every retained settling-negative fact, not only one selected packet.
    data=corrected();second=copy.deepcopy(data['implementation_candidates'][0]);second['candidate_id']='c2'
    data['implementation_candidates'].append(second);data['selection_state']='AGREEMENT_INVARIANT'
    packets=copy.deepcopy(data['evidence_packets'])
    for p in data['evidence_packets']:
        if 'binding' in p:p['binding']['relation']='POSSIBLE_TARGET'
    for p in packets:
        p['packet_id']='c2-'+p['packet_id'];p['implementation_candidate_id']='c2'
        if 'binding' in p:p['binding']['relation']='POSSIBLE_TARGET'
    data['evidence_packets'].extend(packets)
    reject('B11_missing_candidate_refutation_packet',EffectClaim,data)
    data['acquisition']['budget_provenance']['refutation_packet_ids'].append('c2-c1-persistence')
    loaded=EffectClaim.from_dict(data)
    invariant=True
    for order in itertools.permutations(data['implementation_candidates']):
        altered=copy.deepcopy(data);altered['implementation_candidates']=list(order)
        invariant &= EffectClaim.from_dict(altered)==loaded
    RESULTS.append({'attempt':'B12_all_candidate_refutations_retained','pass':invariant,'verdict':loaded.verdict.value})
    data=corrected();extra=copy.deepcopy(next(p for p in data['evidence_packets'] if p['packet_id']=='c1-persistence'))
    extra['packet_id']='extra-negative-fact';data['evidence_packets'].append(extra)
    reject('B13_omitted_retained_refutation_fact',EffectClaim,data)
    data['acquisition']['budget_provenance']['refutation_packet_ids'].append('extra-negative-fact')
    RESULTS.append({'attempt':'B14_exact_fact_population_accepted','pass':EffectClaim.from_dict(data).verdict.value=='NO_EFFECT'})
    data=corrected();uncertainty=copy.deepcopy(next(p for p in data['evidence_packets'] if p['packet_id']=='c1-persistence'))
    uncertainty['packet_id']='commit-uncertain';uncertainty['assertion']['predicate']='commit_outcome_undetermined'
    data['evidence_packets'].append(uncertainty)
    data['obligations']['PERSISTENCE']='UNKNOWN';data['implementation_candidates'][0]['obligations']['PERSISTENCE']='UNKNOWN'
    data['acquisition']['unresolved_obligations']=['PERSISTENCE'];data['verdict']='ABSTAIN';data.pop('closure')
    loaded=EffectClaim.from_dict(data)
    RESULTS.append({'attempt':'B15_uncertainty_is_not_a_settling_negative_fact','pass':loaded.obligations.persistence is ProofState.UNKNOWN})
    data['acquisition']['budget_provenance']['refutation_packet_ids'].append('commit-uncertain')
    reject('B16_uncertainty_cannot_supply_refutation_link',EffectClaim,data)
    wire=EffectReceipt.from_claim(EffectClaim.from_dict(corrected()),'budget-falsifier').to_dict()
    for obj in (wire,wire['claim_snapshot']):del obj['acquisition']['budget_provenance']
    reject('B17_receipt_cannot_drop_required_exclusion',EffectReceipt,wire)
    # Runtime observations for the six frozen conceptual cases, not inference.
    a=fixture('valid_no_effect');b=without_provenance();b['acquisition']['frontier'][0]['might_settle']=['PERSISTENCE']
    c=corrected();d=without_provenance();e=corrected();e['acquisition']['frontier'][0].pop('might_settle')
    f=abstain(corrected());f['acquisition'].pop('budget_exhausted')
    observations={}
    for name,record,expected in [('A',a,'NO_EFFECT'),('B',abstain(b),'ABSTAIN'),('C',c,'NO_EFFECT'),('D',abstain(d),'ABSTAIN'),('E',abstain(e),'ABSTAIN'),('F',f,'INVALID')]:
        try:
            claim=EffectClaim.from_dict(record);observed=claim.verdict.value;reason=None
        except EffectModelError as error:observed='INVALID';reason=str(error)
        observations[name]={'expected':expected,'result':observed,'reason':reason}
        RESULTS.append({'attempt':'CASE_'+name,'pass':observed==expected,'result':observed})
    (ROOT/'research/M0R1-B/case_results.json').write_text(json.dumps(observations,indent=2)+'\n')


if __name__=='__main__':raise SystemExit(main())
