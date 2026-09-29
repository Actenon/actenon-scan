#!/usr/bin/env python3
"""Budget-only normative oracle; inherited proof semantics are not reimplemented.

No production edits, source acquisition, provider knowledge or optional verifier.
Witness truth remains a supplied premise. Historical runtime probes use a local
archive of the exact M0R1 commit, not the current implementation as an oracle.
"""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    print('FATAL: required schema verifier unavailable', file=sys.stderr)
    raise SystemExit(2)

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
UPSTREAM=ROOT/'specs/AREF-002A'
M0R1='ec4db0c2ab61c6d5b1c5d8537a9617f2d2534b30'
spec=importlib.util.spec_from_file_location('_aref002a_budget_base',UPSTREAM/'validate.py')
A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
BASE=copy.deepcopy(A.SCHEMAS)
NEW={n:json.loads((HERE/(n+'.schema.json')).read_text()) for n in ('effect_claim','effect_receipt','budget_provenance')}
A.SCHEMAS.update({n:NEW[n] for n in ('effect_claim','effect_receipt')})
A.REGISTRY=Registry().with_resources((s['$id'],Resource.from_contents(s)) for s in list(BASE.values())+list(NEW.values()))
BUDGETS=set(BASE['evidence']['$defs']['budgetName']['enum'])
CHECKS=[]


def check(label,ok):
    CHECKS.append((label,bool(ok)))
    print(('PASS ' if ok else 'FAIL ')+label)


def require(ok,code,message):
    if not ok:raise A.Invalid(code,message)


def fixture(name,upstream=False):
    return json.loads(((UPSTREAM if upstream else HERE)/'examples'/(name+'.json')).read_text())


def identity(k):
    acq=k['acquisition'];budgets=acq.get('budget_exhausted',[])
    require(isinstance(budgets,list) and set(budgets)<=BUDGETS,'BUDGET_IDENTITY','recorded exhaustion must use frozen budget identities')
    if acq['stop_reason']=='BUDGET_EXHAUSTED':
        require(bool(budgets),'BUDGET_IDENTITY','BUDGET_EXHAUSTED requires a nonempty exhausted-budget list')
    for edge in acq.get('frontier',[]):
        if edge['reason']=='BUDGET_EXHAUSTED':
            require(edge.get('budget_name') in budgets,'BUDGET_IDENTITY','every exhausted edge needs a named budget in the exhausted list')
        else:
            require('budget_name' not in edge,'BUDGET_IDENTITY','a non-budget frontier reason has no budget_name')
    return budgets


def exclusion_provenance(k,budgets):
    proof=k['acquisition'].get('budget_provenance')
    if proof is None:return
    o=proof['refuted_obligation']
    if k.get('closure'):
        require(o==k['closure']['refuted_obligation'],'BUDGET_REFUTATION','budget proof must address this same negative closure')
    overridden={pid for r in k.get('contradictions',[]) for pid in r.get('overridden_packet_ids',[])}
    settling=[p for p in k['evidence_packets'] if p['obligation']==o and p['polarity']=='NEGATIVE'
              and p['admissibility']=='PROBATIVE' and p['packet_id'] not in overridden
              and p['assertion']['predicate']!='commit_outcome_undetermined']
    require(set(proof['refutation_packet_ids'])=={p['packet_id'] for p in settling},'BUDGET_REFUTATION','witness must cite exactly the retained settling-negative facts')
    require({p['implementation_candidate_id'] for p in settling}=={c['candidate_id'] for c in k['implementation_candidates']},
            'BUDGET_REFUTATION','budget proof must cover the refutation for every candidate')
    names=[x['budget_name'] for x in proof['exclusions']]
    require(len(names)==len(set(names)) and set(names)==set(budgets),'BUDGET_COVERAGE','one exclusion witness for each exhausted budget, no extra budget')
    frontier=k['acquisition'].get('frontier',[])
    for x in proof['exclusions']:
        expected={i for i,e in enumerate(frontier) if e['reason']=='BUDGET_EXHAUSTED' and e.get('budget_name')==x['budget_name']}
        require(set(x['frontier_indices'])==expected,'BUDGET_FRONTIER','witness must cover exactly all exhausted edges for its budget')
        loc=x['locator'];path=loc['path']
        require(not path.startswith('/') and not (len(path)>1 and path[1]==':') and '\\' not in path
                and all(p not in ('','..') for p in path.split('/')),'BUDGET_SOURCE','witness source must be normalized and rereadable')
        require(A.contains(loc,loc),'BUDGET_SOURCE','witness source span is reversed')
        if loc.get('version_resolution')=='UNPINNED':require('version' not in loc,'BUDGET_SOURCE','unresolved source version must not be invented')
        elif loc.get('version_resolution'):require(bool(loc.get('version')),'BUDGET_SOURCE','resolved source version must be retained')
        else:require('version' not in loc,'BUDGET_SOURCE','source version needs resolution provenance')
        require(bool(x['extract']['text'].strip()) and not x['extract'].get('truncated',False),
                'BUDGET_SOURCE','empty/truncated text cannot establish the scoped exclusion')


def claim(k):
    budgets=identity(k)
    if k['verdict']=='NO_EFFECT' and budgets:
        require('budget_provenance' in k['acquisition'],'BUDGET_EXCLUSION_MISSING','names/labels and C4=true alone do not establish exclusion provenance')
    # All unamended typed facts, states, verdict/closure checks remain inherited.
    result=A.check_claim(k)
    exclusion_provenance(k,budgets)
    return result


def receipt(r):
    claim(r['claim_snapshot'])
    A.check_receipt(r)
    return r['verdict']


def expect(label,data,result,code=None,kind='claim'):
    try:observed=(receipt if kind=='receipt' else claim)(data)
    except A.Invalid as error:
        check(label,result=='INVALID' and error.code==code)
        return {'result':'INVALID','code':error.code,'reason':str(error)}
    check(label,observed==result)
    return {'result':observed}


def abstain(k):
    k=copy.deepcopy(k);k['verdict']='ABSTAIN';k.pop('closure',None)
    k['acquisition'].pop('budget_provenance',None)
    return k


def named_original():
    k=fixture('valid_unrelated_frontier_negative',True)
    k['acquisition']['budget_exhausted']=['max_dependency_hops']
    k['acquisition']['frontier'][0]['budget_name']='max_dependency_hops'
    return k


def verify_schema_delta():
    # Construct the entire allowed structural delta, detecting unrelated drift.
    expected=copy.deepcopy(BASE['effect_claim']);new=NEW['effect_claim']
    for field in ('$id','title','$comment'):expected[field]=new[field]
    acq=expected['$defs']['acquisition'];acq['properties']['budget_provenance']={'$ref':NEW['budget_provenance']['$id']}
    acq['properties']['budget_exhausted']['uniqueItems']=True
    acq['allOf']=[
        {'if':{'properties':{'stop_reason':{'const':'BUDGET_EXHAUSTED'}},'required':['stop_reason']},'then':{'required':['budget_exhausted'],'properties':{'budget_exhausted':{'minItems':1}}}},
        {'if':{'not':{'required':['budget_exhausted'],'properties':{'budget_exhausted':{'minItems':1}}}},'then':{'not':{'required':['budget_provenance']}}}]
    expected['$defs']['frontierEntry']['allOf']=[{'if':{'properties':{'reason':{'const':'BUDGET_EXHAUSTED'}},'required':['reason']},'then':{'required':['budget_name']},'else':{'not':{'required':['budget_name']}}}]
    expected['allOf'].append({'if':{'required':['verdict','acquisition'],'properties':{'verdict':{'const':'NO_EFFECT'},'acquisition':{'required':['budget_exhausted'],'properties':{'budget_exhausted':{'minItems':1}}}}},'then':{'properties':{'acquisition':{'required':['budget_provenance']}}}})
    check('claim schema changes exactly budget clauses',expected==new)
    old_id=BASE['effect_claim']['$id'];new_id=new['$id']
    def remap(d):
        if isinstance(d,list):return [remap(x) for x in d]
        if isinstance(d,dict):return {key:(new_id+v[len(old_id):] if key=='$ref' and isinstance(v,str) and v.startswith(old_id) else remap(v)) for key,v in d.items()}
        return d
    expected=remap(BASE['effect_receipt'])
    for field in ('$id','title','$comment'):expected[field]=NEW['effect_receipt'][field]
    check('receipt schema changes only claim references',expected==NEW['effect_receipt'])


def historical_runtime_probe():
    inputs={'F_original':fixture('valid_unrelated_frontier_negative',True),
            'D_names_only':named_original(),'C_versioned_witness':fixture('valid_unrelated_frontier_negative')}
    source="""import json,sys
from actenon_scan.effects import EffectClaim,EffectModelError
out={}
for name,data in json.load(sys.stdin).items():
    try:out[name]={'result':EffectClaim.from_dict(data).verdict.value}
    except EffectModelError as e:out[name]={'result':'INVALID','reason':str(e)}
print(json.dumps(out))
"""
    archived=subprocess.run(['git','archive','--format=zip',M0R1],cwd=ROOT,check=True,capture_output=True).stdout
    with tempfile.TemporaryDirectory(prefix='aref002b-m0r1-') as directory:
        with zipfile.ZipFile(io.BytesIO(archived)) as z:z.extractall(directory)
        result=subprocess.run([sys.executable,'-B','-c',source],cwd=directory,input=json.dumps(inputs),text=True,
                              env={**os.environ,'PYTHONPATH':directory,'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,check=True)
    observed=json.loads(result.stdout)
    check('exact M0R1 rejects original missing budget identity',observed['F_original']['result']=='INVALID' and 'budget name' in observed['F_original']['reason'])
    check('exact M0R1 accepts names-only unrelated label',observed['D_names_only']['result']=='NO_EFFECT')
    check('exact M0R1 cannot yet load the new witness codec',observed['C_versioned_witness']['result']=='INVALID' and 'budget_provenance' in observed['C_versioned_witness']['reason'])
    return observed


def main():
    for name,schema in NEW.items():
        Draft202012Validator.check_schema(schema);check(name+' schema is valid',True)
    verify_schema_delta()
    cases={}
    cases['A']=expect('A no exhaustion: valid negative',fixture('valid_no_effect',True),'NO_EFFECT')
    corrected=fixture('valid_unrelated_frontier_negative')
    cases['C']=expect('C supported unrelated exhaustion: valid negative',corrected,'NO_EFFECT')
    # Explicit contributing path: C4 cannot be asserted true; ABSTAIN is well formed.
    b=abstain(corrected);b['acquisition']['frontier'][0]['origin']=copy.deepcopy(next(p for p in b['evidence_packets'] if p['packet_id']=='c1-persistence')['locator'])
    b['acquisition']['frontier'][0]['might_settle']=['PERSISTENCE']
    cases['B']=expect('B contributing exhaustion: valid abstention',b,'ABSTAIN')
    bad=copy.deepcopy(b);bad['verdict']='NO_EFFECT';bad['closure']=copy.deepcopy(corrected['closure']);bad['closure']['C4_no_budget_exhausted_on_contributing_path']=False
    bad['acquisition']['budget_provenance']=copy.deepcopy(corrected['acquisition']['budget_provenance'])
    expect('B false C4 cannot establish negative',bad,'INVALID','SCHEMA')
    d=named_original();expect('D mere unrelated label cannot establish negative',d,'INVALID','BUDGET_EXCLUSION_MISSING')
    cases['D']=expect('D retained identities with no closure: abstention',abstain(d),'ABSTAIN')
    e=abstain(corrected);e['acquisition']['frontier'][0].pop('might_settle')
    cases['E']=expect('E unknown relevance: valid abstention',e,'ABSTAIN')
    bad=copy.deepcopy(corrected);bad['acquisition']['frontier'][0].pop('might_settle')
    expect('E witness cannot erase unknown frontier scope',bad,'INVALID','CLOSURE_C5')
    cases['F']=expect('F missing explicit exhaustion identity: invalid',fixture('valid_unrelated_frontier_negative',True),'INVALID','BUDGET_IDENTITY')
    for field in ('budget_exhausted','edge_name'):
        bad=copy.deepcopy(corrected)
        if field=='budget_exhausted':bad['acquisition'].pop(field)
        else:bad['acquisition']['frontier'][0].pop('budget_name')
        expect('F staged missing '+field,bad,'INVALID','BUDGET_IDENTITY')
    # Narrow adversarial witness and scope checks; no other proof area is reopened.
    for field in ('locator','extract'):
        bad=copy.deepcopy(corrected);del bad['acquisition']['budget_provenance']['exclusions'][0][field]
        expect('exclusion without '+field+' fails',bad,'INVALID','SCHEMA')
    for field,value,code in (
        ('budget_name','max_bytes_read','BUDGET_COVERAGE'),
        ('frontier_indices',[],'BUDGET_FRONTIER'),
        ('frontier_indices',[1],'BUDGET_FRONTIER')):
        bad=copy.deepcopy(corrected);bad['acquisition']['budget_provenance']['exclusions'][0][field]=value
        expect('wrong exclusion '+field+' '+str(value)+' fails',bad,'INVALID',code)
    bad=copy.deepcopy(corrected);bad['acquisition']['budget_provenance']['refutation_packet_ids']=['c1-operation']
    expect('positive/other-obligation packet cannot establish exclusion',bad,'INVALID','BUDGET_REFUTATION')
    bad=copy.deepcopy(corrected);bad['acquisition']['budget_provenance']['refuted_obligation']='OPERATION'
    expect('another refutation cannot authorize this closure',bad,'INVALID','BUDGET_REFUTATION')
    bad=copy.deepcopy(corrected);bad['acquisition']['budget_provenance']['exclusions'][0]['extract']['truncated']=True
    expect('truncated witness does not establish exclusion',bad,'INVALID','BUDGET_SOURCE')
    bad=copy.deepcopy(corrected);bad['acquisition']['frontier'][0]['might_settle']=['OPERATION','PERSISTENCE']
    expect('witness cannot erase a relevant frontier',bad,'INVALID','CLOSURE_C5')
    bad=fixture('valid_no_effect',True);bad['acquisition']['budget_provenance']=copy.deepcopy(corrected['acquisition']['budget_provenance'])
    expect('no exhaustion needs no stale budget proof',bad,'INVALID','SCHEMA')
    witness=corrected['acquisition']['budget_provenance']['exclusions'][0]
    lines=(ROOT/witness['locator']['path']).read_text().splitlines()
    check('corrected fixture witness extract is actually verbatim',witness['extract']['text']=='\n'.join(lines[witness['locator']['start_line']-1:witness['locator']['end_line']]))
    inherited=fixture('valid_unrelated_frontier_negative',True);expected=copy.deepcopy(inherited)
    expected['acquisition']['budget_exhausted']=['max_dependency_hops'];expected['acquisition']['frontier'][0]['budget_name']='max_dependency_hops'
    expected['acquisition']['budget_provenance']=copy.deepcopy(corrected['acquisition']['budget_provenance'])
    check('fixture changes only named budget identity and exclusion provenance',expected==corrected)
    r=fixture('valid_receipt_no_effect',True)
    r['claim_snapshot']=copy.deepcopy(corrected);r['acquisition']=copy.deepcopy(corrected['acquisition']);r['closure']=copy.deepcopy(corrected['closure'])
    r['answers']['unknowns']=copy.deepcopy(corrected['acquisition'])
    # Unknowns has a fixed answer vocabulary; the budget witness travels in the full acquisition/snapshot.
    r['answers']['unknowns']={key:value for key,value in r['answers']['unknowns'].items()
                              if key in NEW['effect_receipt']['$defs']['answers']['properties']['unknowns']['properties']}
    expect('receipt retains new acquisition provenance under inherited projection',r,'NO_EFFECT',kind='receipt')
    # Historical runtime observation is a pressure-point receipt, not conformance authority.
    historical=historical_runtime_probe()
    missing=subprocess.run([sys.executable,'-S','-B',str(Path(__file__).resolve())],capture_output=True,text=True)
    check('missing verifier is fatal, never skipped',missing.returncode==2 and 'FATAL:' in missing.stderr)
    manifest=json.loads((HERE/'MANIFEST.json').read_text())
    for name,expected in manifest['upstream_manifest_sha256'].items():
        folder=ROOT/'specs'/name;up=json.loads((folder/'MANIFEST.json').read_text())
        ok=hashlib.sha256((folder/'MANIFEST.json').read_bytes()).hexdigest()==expected
        for entry in up['files']:
            path=folder/entry['path']
            if not path.exists():path=ROOT/entry['path']
            ok &= path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==entry['sha256']
        check(name+' seal unchanged',ok)
    inventory={f['path'] for f in manifest['files']}
    actual={p.relative_to(HERE).as_posix() for p in HERE.rglob('*') if p.is_file() and p.name not in ('MANIFEST.json','MANIFEST.sha256')}
    check('AREF-002B inventory exact',inventory==actual)
    check('AREF-002B hashes and byte counts exact',all((HERE/f['path']).stat().st_size==f['bytes'] and hashlib.sha256((HERE/f['path']).read_bytes()).hexdigest()==f['sha256'] for f in manifest['files']))
    expected=''.join(f['sha256']+'  specs/AREF-002B/'+f['path']+'\n' for f in manifest['files'])
    check('SHA inventory agrees with manifest',(HERE/'MANIFEST.sha256').read_text()==expected)
    print('CASES '+json.dumps(cases,sort_keys=True))
    print('M0R1_OBSERVED '+json.dumps(historical,sort_keys=True))
    failed=sum(not ok for _,ok in CHECKS)
    print(str(len(CHECKS))+' checks; '+str(len(CHECKS)-failed)+' passed; '+str(failed)+' failed')
    return bool(failed)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (A.Invalid,KeyError,ValueError,OSError,subprocess.CalledProcessError) as error:
        print('FATAL: conformance infrastructure/input error: '+str(error),file=sys.stderr)
        raise SystemExit(2)
