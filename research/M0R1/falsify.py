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
    for name,sha in [('baseline','b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16'),('failed_M0','a93b013383ce773b10708d3f30b2a1660e141527'),('M0R1',None)]:
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
    RESULTS.append({'attempt':'legacy_Finding_output_baseline_M0_M0R1','pass':len({s['sha256'] for s in scans.values()})==1,'reports':scans})
    report={'attempts':len(RESULTS),'passed':sum(r['pass'] for r in RESULTS),
            'failed':sum(not r['pass'] for r in RESULTS),'results':RESULTS,
            'claim_boundary':'Supplied proof-record validation only; C4 is represented, not acquired or verified.'}
    (ROOT/'research/M0R1/falsification_results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
    return bool(report['failed'])


if __name__=='__main__':raise SystemExit(main())
