#!/usr/bin/env python3
"""Single-rule contract-provenance oracle over immutable B/A semantics.

No production imports or edits; no source acquisition. Dependencies are mandatory.
"""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile
try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError as error:
    print('FATAL: required schema verifier unavailable: '+str(error),file=sys.stderr)
    raise SystemExit(2)

HERE=Path(__file__).resolve().parent
CHECKS=[]
RAW=[]
PINNED={'LOCKFILE','EXACT_MANIFEST_PIN','INSTALLED_TREE_METADATA'}
B=None
VALIDATORS={}

def load(path):return json.loads(Path(path).read_text())
def fixture(name):return load(HERE/'examples'/(name+'.json'))
def check(label,ok,detail=None):
    CHECKS.append({'name':label,'pass':bool(ok),'detail':detail})
    if not ok:print('FAIL '+label+(': '+str(detail) if detail else ''))

def contract_version(packet):
    if packet.get('tier')=='L6' and packet.get('admissibility')=='PROBATIVE':
        loc=packet.get('locator',{})
        B.require(isinstance(loc.get('package'),str) and bool(loc['package'])
                  and isinstance(loc.get('version'),str) and bool(loc['version'])
                  and loc.get('version_resolution') in PINNED,
                  'CONTRACT_VERSION','PROBATIVE L6 contract requires established recorded version provenance')

def shape(kind,data):
    errors=list(VALIDATORS[kind].iter_errors(data))
    if errors:raise B.A.Invalid('SCHEMA',errors[0].message)

def packet(data):
    contract_version(data);shape('evidence',data);B.A.check_packet(data)
    return 'VALID'

def claim(data):
    for p in data.get('evidence_packets',[]):contract_version(p)
    shape('effect_claim',data)
    return B.claim(data)

def receipt(data):
    for p in data.get('evidence_packets',[]):contract_version(p)
    claim(data['claim_snapshot']);shape('effect_receipt',data)
    return B.receipt(data)

def expect(label,kind,data,want,code=None):
    try:observed={'result':{'evidence':packet,'effect_claim':claim,'effect_receipt':receipt}[kind](data)}
    except B.A.Invalid as error:observed={'result':'INVALID','code':error.code,'reason':str(error)}
    check(label,observed['result']==want and (code is None or observed.get('code')==code),observed)
    schema_valid=not list(VALIDATORS[kind].iter_errors(data))
    # Shape can be broader than semantic constraints, but must reject the new
    # version violations itself and must admit every semantically valid control.
    if code=='CONTRACT_VERSION':check(label+' schema also rejects',not schema_valid)
    elif want!='INVALID':check(label+' schema admits valid control',schema_valid)
    RAW.append({'name':label,'kind':kind,'expected':want,'expected_code':code,'observed':observed,'schema_valid':schema_valid})

def as_receipt(k):
    """Build projections from the frozen receipt contract, without runtime code."""
    answers={'effect':{'effect_class':k['effect_class'],'verdict':k['verdict'],'statement':'Supplied normative proof record: '+k['verdict']},
       'implementation':{'selection_state':k['selection_state'],'candidates':copy.deepcopy(k['implementation_candidates'])},
       'resource':copy.deepcopy(k['descriptors']['target']),'control':copy.deepcopy(k['descriptors']['control']),
       'authority':copy.deepcopy(k['descriptors']['authority'])}
    if k['selection_state']=='SINGLE_ESTABLISHED':answers['implementation']['selected_candidate_id']=k['implementation_candidates'][0]['candidate_id']
    overridden={pid for c in k.get('contradictions',[]) for pid in c.get('overridden_packet_ids',[])}
    for ob in ('ACTIVATION','BOUNDARY','OPERATION','PERSISTENCE'):
        state=k['obligations'][ob]
        polarities={'SUPPORTED':{'POSITIVE'},'REFUTED':{'NEGATIVE'},'CONFLICTING':{'POSITIVE','NEGATIVE'}}.get(state,set())
        answers[ob.lower()]={'state':state,'settled_by_packet_ids':[p['packet_id'] for p in k['evidence_packets'] if p['obligation']==ob
            and p['admissibility']=='PROBATIVE' and p['polarity'] in polarities and p['packet_id'] not in overridden
            and p['assertion']['predicate']!='commit_outcome_undetermined']}
    required={pid for pid,p in B.A.PROBES.items() if p['probe_class']=='BLOCKING'}
    complete={p['probe_id'] for p in k['probe_outcomes'] if p['outcome']!='INCOMPLETE'}
    answers['contradictions']={'contradictions':copy.deepcopy(k.get('contradictions',[])),
        'counter_evidence_found':[copy.deepcopy(p) for p in k['probe_outcomes'] if p['outcome']=='FOUND'],
        'blocking_probes_incomplete':sorted(required-complete)}
    answers['unknowns']={field:copy.deepcopy(k['acquisition'][field]) for field in ('unresolved_obligations','highest_tier_reached','stop_reason','frontier_size','frontier')}
    r={key:copy.deepcopy(k[key]) for key in ('schema_version','claim_id','capability_id','invocation_id','effect_class','verdict','evidence_packets','probe_outcomes','acquisition')}
    r.update(receipt_id='normative-provenance-receipt',answers=answers,claim_snapshot=copy.deepcopy(k),
             rendering_constraints={'is_negative_result':k['verdict']=='NO_EFFECT','may_render_as_safe':False})
    if 'closure' in k:r['closure']=copy.deepcopy(k['closure'])
    return r

def contract_record(ob,negative=False,kind='openapi_operation',mode='LOCKFILE'):
    k=fixture('valid_proven_effect')
    p=next(p for p in k['evidence_packets'] if p['obligation']==ob)
    if negative:
        p['polarity']='NEGATIVE'
        p['assertion']['predicate']={'BOUNDARY':'terminates_in_process_state','OPERATION':'operation_is_observation','PERSISTENCE':'state_is_guaranteed_rolled_back'}[ob]
        k['obligations'][ob]='REFUTED';k['implementation_candidates'][0]['obligations'][ob]='REFUTED'
        k.update(verdict='NO_EFFECT',closure=fixture('valid_no_effect')['closure'])
        k['closure']['refuted_obligation']=ob
    p.update(kind=kind,tier='L6',locator={'path':'contracts/synthetic-contract.json','start_line':7,'end_line':7,
        'package':'synthetic.opaque','version':'2.1.0','version_resolution':mode if mode in PINNED else 'UNPINNED'})
    k['acquisition'].update(highest_tier_reached='L6',tiers_attempted=['L0','L1','L6'])
    if mode not in PINNED:
        p['locator'].pop('version')
        if mode=='hypothesis':
            p['admissibility']='HYPOTHESIS_ONLY'
            k['obligations'][ob]='UNKNOWN';k['implementation_candidates'][0]['obligations'][ob]='UNKNOWN'
            k.update(verdict='ABSTAIN');k.pop('closure',None)
            k['acquisition'].update(unresolved_obligations=[ob],stop_reason='NO_FURTHER_TIER')
        elif mode=='missing_package':p['locator'].pop('package')
        elif mode=='missing_resolution':p['locator'].update(version='2.1.0');p['locator'].pop('version_resolution')
        elif mode=='missing_version':p['locator']['version_resolution']='LOCKFILE'
        elif mode=='fabricated_unpinned':p['locator']['version']='2.1.0'
    return k

def preservation(upstream):
    recorded=load(HERE/'input_preservation.json')
    archive=subprocess.run(['git','archive','--format=zip',recorded['candidate_sha']],cwd=upstream,check=True,capture_output=True).stdout
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        check('historical candidate input bytes',all(hashlib.sha256(z.read(p)).hexdigest()==h for p,h in recorded['upstream_files'].items()))
    prefixes=('specs/AREF-001/','specs/AREF-002/','specs/AREF-002A/','specs/AREF-002B/')
    protected={p:h for p,h in recorded['upstream_files'].items() if p.startswith(prefixes)}
    current={p.relative_to(upstream).as_posix() for directory in prefixes for p in (upstream/directory).rglob('*') if p.is_file()}
    check('earlier specification inventory unchanged',current==set(protected))
    check('earlier specification bytes unchanged',all(hashlib.sha256((upstream/p).read_bytes()).hexdigest()==h for p,h in protected.items()))
    manifest=load(HERE/'MANIFEST.json')
    actual={p.relative_to(HERE).as_posix() for p in HERE.rglob('*') if p.is_file() and p.name not in {'MANIFEST.json','MANIFEST.sha256'}}
    check('proposal sealed inventory exact',actual=={f['path'] for f in manifest['files']})
    check('proposal sealed bytes exact',all((HERE/f['path']).stat().st_size==f['bytes'] and hashlib.sha256((HERE/f['path']).read_bytes()).hexdigest()==f['sha256'] for f in manifest['files']))
    check('proposal SHA inventory exact',(HERE/'MANIFEST.sha256').read_text()==''.join(f['sha256']+'  '+f['path']+'\n' for f in manifest['files']))

def main():
    global B,VALIDATORS
    ap=argparse.ArgumentParser();ap.add_argument('--upstream',type=Path,required=True);ap.add_argument('--output',type=Path)
    args=ap.parse_args();upstream=args.upstream.resolve()
    spec=importlib.util.spec_from_file_location('_frozen_aref002b',upstream/'specs/AREF-002B/validate.py')
    B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
    schemas=[load(p) for directory in ('AREF-002A','AREF-002B') for p in (upstream/'specs'/directory).glob('*.schema.json')]+[load(p) for p in HERE.glob('*.schema.json')]
    registry=Registry().with_resources((s['$id'],Resource.from_contents(s)) for s in schemas)
    for kind in ('evidence','effect_claim','effect_receipt'):
        s=load(HERE/(kind+'.schema.json'));Draft202012Validator.check_schema(s)
        VALIDATORS[kind]=Draft202012Validator(s,registry=registry)
        check(kind+' schema valid',True)
    check('existing pin resolution vocabulary unchanged',PINNED==set(B.BASE['evidence']['$defs']['versionResolution']['enum'])-{'UNPINNED'})
    preservation(upstream)
    for name in ('valid_proven_effect','valid_no_effect','valid_abstain','valid_analysis_error'):
        k=fixture(name);expect(name,'effect_claim',k,k['verdict']);expect(name+' receipt','effect_receipt',as_receipt(k),k['verdict'])
    # Four original directional counterexamples and eight isolated controls.
    for name in sorted((HERE/'examples').glob('*_unpinned_probative.json')):
        k=load(name);expect(name.stem,'effect_claim',k,'INVALID','CONTRACT_VERSION')
        expect(name.stem+' receipt','effect_receipt',as_receipt(k),'INVALID','CONTRACT_VERSION')
    for pattern in ('*_pinned_control.json','*_unpinned_hypothesis.json'):
        for name in sorted((HERE/'examples').glob(pattern)):
            k=load(name);expect(name.stem,'effect_claim',k,k['verdict']);expect(name.stem+' receipt','effect_receipt',as_receipt(k),k['verdict'])
    # The complete registered L6 packet surface, every established version mode,
    # legitimate unpinned retention and all new version-admissibility failures.
    for rule in B.A.RULES:
        for source in rule['sources']:
            if source['tier']!='L6':continue
            for mode in sorted(PINNED)+['hypothesis','unpinned_probative','missing_package','missing_resolution','missing_version','fabricated_unpinned']:
                k=contract_record('OPERATION',kind=source['kind'],mode=mode)
                p=next(p for p in k['evidence_packets'] if p['obligation']=='OPERATION')
                p['obligation']=rule['obligation'];p['polarity']=rule['polarity'];p['assertion']['predicate']=rule['predicate']
                valid=mode in PINNED or mode=='hypothesis'
                expect('packet '+rule['predicate']+' '+source['kind']+' '+mode,'evidence',p,'VALID' if valid else 'INVALID',None if valid else 'CONTRACT_VERSION')
    kinds=sorted(B.A.CONTRACT_KINDS)
    for ob in ('BOUNDARY','OPERATION','PERSISTENCE'):
        for neg in (False,True):
            for kind in kinds:
                for mode in sorted(PINNED)+['hypothesis','unpinned_probative']:
                    k=contract_record(ob,neg,kind,mode);valid=mode in PINNED or mode=='hypothesis'
                    label='record '+ob+(' negative ' if neg else ' positive ')+kind+' '+mode
                    want=k['verdict'] if valid else 'INVALID'
                    expect(label,'effect_claim',k,want,None if valid else 'CONTRACT_VERSION')
                    expect(label+' receipt','effect_receipt',as_receipt(k),want,None if valid else 'CONTRACT_VERSION')
    # Hypotheses cannot become a new blanket proof veto.
    k=fixture('valid_proven_effect');hyp=next(p for p in contract_record('PERSISTENCE',True,mode='hypothesis')['evidence_packets'] if p['obligation']=='PERSISTENCE')
    hyp['packet_id']='unresolved-contract-concern';k['evidence_packets'].append(hyp)
    k['acquisition'].update(highest_tier_reached='L6',tiers_attempted=['L0','L1','L6'])
    next(p for p in k['probe_outcomes'] if p['probe_id']=='CP-PER-03').update(outcome='FOUND',packet_ids=[hyp['packet_id']])
    expect('independent body proof and harmless FOUND contract hypothesis','effect_claim',k,'PROVEN_EFFECT')
    expect('independent body proof receipt','effect_receipt',as_receipt(k),'PROVEN_EFFECT')
    k=fixture('valid_no_effect');hyp=next(p for p in contract_record('OPERATION',mode='hypothesis')['evidence_packets'] if p['obligation']=='OPERATION')
    k['evidence_packets']=[p for p in k['evidence_packets'] if p['obligation']!='OPERATION']+[hyp]
    k['obligations']['OPERATION']='UNKNOWN';k['implementation_candidates'][0]['obligations']['OPERATION']='UNKNOWN'
    k['acquisition'].update(highest_tier_reached='L6',tiers_attempted=['L0','L1','L6'],unresolved_obligations=['OPERATION'],stop_reason='NO_FURTHER_TIER')
    expect('independent closed refutation with unknown other obligation','effect_claim',k,'NO_EFFECT')
    expect('independent closed refutation receipt','effect_receipt',as_receipt(k),'NO_EFFECT')
    # Required verifier must fail, never skip. -S removes verifier site packages.
    absent=subprocess.run([sys.executable,'-S','-B',str(HERE/'validate.py'),'--upstream',str(upstream)],capture_output=True,text=True)
    check('missing schema verifier fails gate',absent.returncode==2 and 'FATAL: required schema verifier unavailable' in absent.stderr)
    failed=sum(not c['pass'] for c in CHECKS)
    summary={'checks':len(CHECKS),'passed':len(CHECKS)-failed,'failed':failed,'scope':'Normative proposal validation, not repaired-runtime readiness','results':CHECKS,'raw':RAW}
    if args.output:
        target=args.output.resolve()
        if target==HERE or HERE in target.parents:raise ValueError('raw output must stay outside sealed proposal')
        target.write_text(json.dumps(summary,indent=2)+'\n')
    print(str(len(CHECKS))+' checks; '+str(len(CHECKS)-failed)+' passed; '+str(failed)+' failed')
    return bool(failed)

if __name__=='__main__':
    try:raise SystemExit(main())
    except (OSError,ValueError,KeyError,subprocess.CalledProcessError) as error:
        print('FATAL: proposal validation infrastructure failed: '+str(error),file=sys.stderr)
        raise SystemExit(2)
