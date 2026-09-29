#!/usr/bin/env python3
"""AREF-002A normative conformance oracle, not production inference.
Consumes authored proof records only. Never imports actenon_scan, acquires source,
executes examples, descends dependencies, or repairs an input. Missing verifier is fatal.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import sys
try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    print('FATAL: schema verifier unavailable; install specs/AREF-002A/requirements-validation.txt', file=sys.stderr)
    raise SystemExit(2)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OBL = ('IMPLEMENTATION','ACTIVATION','BOUNDARY','OPERATION','PERSISTENCE')
STATES = ('SUPPORTED','REFUTED','UNKNOWN','CONFLICTING','ERROR')
VERDICTS = ('PROVEN_EFFECT','NO_EFFECT','ABSTAIN','ANALYSIS_ERROR')
S,R,U,C,E = STATES
RULES = json.loads((HERE/'assertion_registry.json').read_text())['rules']
SCHEMAS = {n:json.loads((HERE/(n+'.schema.json')).read_text()) for n in ('evidence','effect_claim','effect_receipt','coverage_ledger')}
REGISTRY = Registry().with_resources((s['$id'],Resource.from_contents(s)) for s in SCHEMAS.values())
PROBES = {p['probe_id']:p for p in json.loads((ROOT/'specs/AREF-002/architecture_manifest.json').read_text())['counter_evidence_probes']}
BODY_KINDS = {'local_function_body','wrapper_chain_body','dependency_source_body'}
CONTRACT_KINDS = {'openapi_operation','protobuf_service_method','graphql_schema_field','json_schema_node','sdk_operation_metadata','command_specification'}
OPAQUE = {'OPAQUE_EXTERNAL','DYNAMIC_UNRESOLVED'}
class Invalid(Exception):
    def __init__(self,code,detail,path='',validator=''):
        super().__init__(detail);self.code,self.path,self.validator=code,path,validator

def require(ok,code,detail):
    if not ok: raise Invalid(code,detail)

def aggregate(states):
    values=set(states)
    require(bool(values) and values <= set(STATES),'AGGREGATE_INPUT','nonempty valid candidate states required')
    if E in values:return E
    if C in values:return C
    if values=={S}:return S
    if values=={R}:return R
    return U

def shape(name,data):
    v=Draft202012Validator(SCHEMAS[name],registry=REGISTRY)
    errors=sorted(v.iter_errors(data),key=lambda e:(str(list(e.absolute_path)),str(list(e.absolute_schema_path))))
    if errors:
        e=errors[0];raise Invalid('SCHEMA',e.message,'/'+ '/'.join(map(str,e.absolute_path)),e.validator)

def unique(values,code):
    require(len(values)==len(set(values)),code,'duplicate identity')

def contains(outer,inner):
    return (all(outer.get(k)==inner.get(k) for k in ('path','package','version','version_resolution'))
            and outer['start_line']<=inner['start_line']<=inner['end_line']<=outer['end_line']
            and (outer.get('start_column') is None or inner['start_line']!=outer['start_line'] or
                 inner.get('start_column',-1)>=outer['start_column'])
            and (outer.get('end_column') is None or inner['end_line']!=outer['end_line'] or
                 inner.get('end_column',10**12)<=outer['end_column']))

def check_packet(p):
    loc=p['locator']
    require(loc['end_line']>=loc['start_line'],'LOCATOR','reversed evidence span')
    if p['admissibility']=='PROBATIVE':
        matches=[r for r in RULES if (r['predicate'],r['obligation'],r['polarity'])==
                 (p['assertion']['predicate'],p['obligation'],p['polarity']) and
                 {'kind':p['kind'],'tier':p['tier']} in r['sources']]
        require(bool(matches),'ASSERTION_COMPAT','unregistered assertion combination is not PROBATIVE')
    if p['kind'] in ('sink_rule_match','unqualified_name_rule_match'):
        require(bool(p.get('derived_from_rule_id')) and bool(p.get('rule_match_type')),'RULE_PROVENANCE','rule witness must identify match type and source rule')
        if p['admissibility']=='PROBATIVE':
            allowed={'qualified_call','attr_call','open_write','subprocess_deploy','github_rest_mutation'}
            require(p['rule_match_type'] in allowed,'RULE_PROVENANCE','text/name rule cannot settle')
            require(p['obligation']=='BOUNDARY' or p['rule_match_type'] in {'qualified_call','attr_call','github_rest_mutation'},'RULE_PROVENANCE','rule does not witness this obligation')
    elif 'derived_from_rule_id' in p or 'rule_match_type' in p:
        raise Invalid('RULE_PROVENANCE','rule provenance cannot be relabeled as another source kind')
    if loc.get('version_resolution')=='UNPINNED':
        require('version' not in loc,'VERSION','unresolved version may not be fabricated')
    elif loc.get('version_resolution'):
        require(bool(loc.get('version')),'VERSION','resolved version must be recorded')
    else:
        require('version' not in loc,'VERSION','a version requires resolution provenance')
    if p['admissibility']=='PROBATIVE' and p['kind']=='dependency_source_body':
        require(loc.get('version_resolution') not in (None,'UNPINNED'),'VERSION','dependency body must be pinned')

def binding(p,relation,cid,k,frm=None,to=None):
    b=p.get('binding',{})
    return (p['admissibility']=='PROBATIVE' and p['assertion']['predicate']=='implementation_is'
            and p['obligation']=='IMPLEMENTATION' and p['polarity']=='POSITIVE'
            and p['implementation_candidate_id']==cid and b.get('relation')==relation
            and b.get('invocation_id')==k['invocation_id']
            and (frm is None or b.get('from')==frm) and (to is None or b.get('to')==to))

def check_precedence(rec,cand,packets,k):
    require(k['selection_state']=='SINGLE_ESTABLISHED','PRECEDENCE_SELECTION','precedence requires an established unique selected implementation')
    require(cand['kind'] in {'RESOLVED_LOCAL','RESOLVED_DEPENDENCY_SOURCE'} and 'locator' in cand,'PRECEDENCE_BODY','resolved selected body required')
    pr=rec.get('precedence',{})
    select=packets.get(pr.get('selection_packet_id'))
    require(select is not None and binding(select,'SELECTED_TARGET',cand['candidate_id'],k,k['invocation']['locator'],cand['locator']),
            'PRECEDENCE_SELECTION','selected-body binding witness missing or does not bind this invocation/body')
    overridden=set(rec.get('overridden_packet_ids',[]));pos=set(rec['positive_packet_ids']);neg=set(rec['negative_packet_ids'])
    require(overridden in (pos,neg),'PRECEDENCE_SIDE','precedence must resolve exactly one entire side')
    winners=(pos|neg)-overridden
    require(bool(winners),'PRECEDENCE_SIDE','winning side must exist')
    links=pr.get('winning_paths',[])
    require(len(links)==len(winners) and {x['packet_id'] for x in links}==winners,'PRECEDENCE_LINK','every winning packet needs its own body derivation')
    for pid in overridden:
        require(packets[pid]['kind'] in CONTRACT_KINDS and packets[pid]['tier']=='L6',
                'PRECEDENCE_CONTRACT','loser must be machine-readable contract evidence on same candidate/obligation')
    for link in links:
        p=packets[link['packet_id']]
        require(p['kind'] in BODY_KINDS,'PRECEDENCE_BODY','tier or package identity is not resolved-body evidence')
        body=cand['locator']
        for eid in link['binding_packet_ids']:
            edge=packets.get(eid)
            require(edge is not None and binding(edge,'RESOLVED_CALL',cand['candidate_id'],k,body),
                    'PRECEDENCE_LINK','derivation edge needs independent resolved-call binding witness')
            body=edge['binding']['to']
        require(contains(body,p['locator']),'PRECEDENCE_LINK','winning evidence is outside the linked body span')
    return 'POSITIVE' if overridden==neg else 'NEGATIVE'

def check_claim(k,do_shape=True):
    if do_shape:shape('effect_claim',k)
    cands=k['implementation_candidates'];unique([c['candidate_id'] for c in cands],'CANDIDATE_ID')
    packets=k['evidence_packets'];unique([p['packet_id'] for p in packets],'PACKET_ID');byid={p['packet_id']:p for p in packets}
    ids={c['candidate_id'] for c in cands}
    for p in packets:
        check_packet(p);require(p['implementation_candidate_id'] in ids,'PACKET_CANDIDATE','unknown candidate reference')
    selection=k['selection_state'];states={}
    for c in cands:
        require('obligations' in c or (len(cands)==1 and selection=='SINGLE_ESTABLISHED'),'CANDIDATE_STATES','explicit candidate states required except unique established shorthand')
        states[c['candidate_id']]=c.get('obligations',k['obligations'])
        require(states[c['candidate_id']]['IMPLEMENTATION']!=R,'IMPLEMENTATION_REFUTED','IMPLEMENTATION cannot be REFUTED')
        if c['kind'] in OPAQUE:
            require(states[c['candidate_id']]['IMPLEMENTATION'] in {U,E},'OPAQUE_IDENTITY','opaque/unresolved identity cannot be established by a label or locator')
    agg={o:aggregate(s[o] for s in states.values()) for o in OBL}
    require(agg==k['obligations'],'CANDIDATE_AGGREGATION','claim must aggregate every obligation, including candidate IMPLEMENTATION errors')
    records=k.get('contradictions',[]);unique([(x['implementation_candidate_id'],x['obligation']) for x in records],'CONTRADICTION_ID')
    recmap={(x['implementation_candidate_id'],x['obligation']):x for x in records}
    for cid,o in recmap:
        require(cid in ids,'CONTRADICTION_CANDIDATE','unknown contradiction candidate')
    # Validate semantic evidence before interpreting a selection label.
    for cand in cands:
        cid=cand['candidate_id']
        for o in OBL:
            state=states[cid][o]
            allp=[p for p in packets if p['implementation_candidate_id']==cid and p['obligation']==o and p['admissibility']=='PROBATIVE']
            uncertain=any(p['assertion']['predicate']=='commit_outcome_undetermined' for p in allp)
            directional=[p for p in allp if p['assertion']['predicate']!='commit_outcome_undetermined']
            if o=='IMPLEMENTATION':
                directional=[p for p in directional if 'locator' in cand and (binding(p,'SELECTED_TARGET',cid,k,k['invocation']['locator'],cand['locator']) or binding(p,'POSSIBLE_TARGET',cid,k,k['invocation']['locator'],cand['locator']))]
            pos={p['packet_id'] for p in directional if p['polarity']=='POSITIVE'}
            neg={p['packet_id'] for p in directional if p['polarity']=='NEGATIVE'}
            rec=recmap.get((cid,o));winner=None
            if pos and neg:
                require(rec is not None,'CONTRADICTION_MISSING','opposing probative evidence must be recorded')
                require(set(rec['positive_packet_ids'])==pos and set(rec['negative_packet_ids'])==neg,'CONTRADICTION_PACKETS','both complete opposing packet sets must be retained')
                if rec['resolution']=='RESOLVED_IMPLEMENTATION_PRECEDENCE':winner=check_precedence(rec,cand,byid,k)
            else:
                require(rec is None,'CONTRADICTION_PACKETS','contradiction needs both opposing packet sets')
            # ERROR is a declared analysis outcome; it does not need a positive/negative fact.
            if state==E:expected=E
            elif pos and neg and winner is None:expected=C
            elif uncertain:expected=U
            elif winner:expected=S if winner=='POSITIVE' else R
            elif pos:expected=S
            elif neg:expected=R
            else:expected=U
            require(state==expected,'PROOF_STATE','candidate '+cid+' '+o+' requires '+expected+', recorded '+state)
    impl=[s['IMPLEMENTATION'] for s in states.values()]
    if E in impl:expected_selection='SELECTION_ERROR'
    elif any(x!=S for x in impl):expected_selection='UNRESOLVED_IDENTITY'
    elif len(cands)==1:
        cand=cands[0]
        is_selected=any(binding(p,'SELECTED_TARGET',cand['candidate_id'],k,k['invocation']['locator'],cand.get('locator')) for p in packets)
        expected_selection='SINGLE_ESTABLISHED' if is_selected else 'UNRESOLVED_IDENTITY'
    elif all(len({s[o] for s in states.values()})==1 for o in OBL[1:]):expected_selection='AGREEMENT_INVARIANT'
    else:expected_selection='UNRESOLVED_DIVERGENT'
    require(selection==expected_selection,'SELECTION_STATE','selection requires '+expected_selection+', not '+selection)
    outcomes=k['probe_outcomes'];unique([p['probe_id'] for p in outcomes],'PROBE_ID');done={}
    for p in outcomes:
        spec=PROBES.get(p['probe_id']);require(spec is not None,'PROBE_REGISTRY','unknown probe')
        require((p['obligation'],p['probe_class'])==(spec['obligation'],spec['probe_class']),'PROBE_REGISTRY','incorrect probe obligation/class')
        cited=p.get('packet_ids',[]);unique(cited,'PROBE_PACKET')
        if p['outcome']=='FOUND':require(bool(cited),'PROBE_PACKET','FOUND must cite its evidence')
        if p['outcome']=='NOT_FOUND':require(not cited,'PROBE_PACKET','NOT_FOUND must not cite found evidence')
        for pid in cited:
            require(pid in byid and byid[pid]['obligation']==p['obligation'],'PROBE_PACKET','probe cites wrong or absent evidence')
            require(byid[pid]['polarity']=='NEGATIVE' or byid[pid]['admissibility']=='HYPOTHESIS_ONLY','PROBE_PACKET','positive settling packet is not found counter-evidence')
            if p['probe_id']=='CP-PER-05':require(byid[pid]['assertion']['predicate']=='commit_outcome_undetermined','PROBE_PACKET','commit-uncertainty probe requires its typed uncertainty fact')
        done[p['probe_id']]=p['outcome']
    acq=k['acquisition'];frontier=acq.get('frontier');size=acq['frontier_size']
    if frontier is not None:
        require(len(frontier)<=size,'FRONTIER_SIZE','too many frontier entries')
        require(len(frontier)==size or acq.get('frontier_truncated') is True,'FRONTIER_SIZE','missing entries must be marked truncated')
    required_unresolved={o for o in OBL if agg[o] in {U,C}}
    require(required_unresolved<=set(acq['unresolved_obligations']),'UNRESOLVED','unknown/conflicting obligations must be visible')
    require(not any(agg[o] in {S,R} for o in acq['unresolved_obligations']),'UNRESOLVED','settled obligations cannot be listed unresolved')
    require(all(p['tier'] in acq['tiers_attempted'] for p in packets),'ACQUISITION_TIER','packet tier was not attempted')
    if acq['stop_reason']=='CLAIM_NOT_INVESTIGATED':
        require(not packets and not outcomes and not records and k['verdict']=='ABSTAIN','UNINVESTIGATED','uninvestigated claim has no acquired proof')
    if acq['stop_reason']=='SETTLED':
        require(not any(x in {U,E} for x in agg.values()),'ACQUISITION_STOP','SETTLED cannot conceal UNKNOWN or ERROR')
    closure=k.get('closure')
    if closure:
        o=closure['refuted_obligation']
        require(o!='IMPLEMENTATION' and all(s[o]==R for s in states.values()),'CLOSURE_C2','same necessary obligation must be refuted for every candidate')
        require(not any(c['kind'] in OPAQUE for c in cands),'CLOSURE_C1','opaque/dynamic candidate forbids negative closure')
        require(C not in agg.values() and not any(x['resolution']=='UNRESOLVED' for x in records),'CLOSURE_C3','unresolved contradiction forbids NO_EFFECT')
        require(E not in agg.values(),'CLOSURE_C6','necessary error forbids negative closure')
        # C4 is a represented true assertion at M0, deliberately not independently proved.
        require(frontier is not None and len(frontier)==size and not acq.get('frontier_truncated',False),'CLOSURE_C5','complete frontier required for negative closure')
        require(not any(not x.get('might_settle') or o in x['might_settle'] for x in frontier),'CLOSURE_C5','relevant unopened frontier prevents negative closure')
    complete=all(done.get(pid) in ('FOUND','NOT_FOUND') for pid,spec in PROBES.items() if spec['probe_class']=='BLOCKING')
    if E in agg.values():v='ANALYSIS_ERROR'
    elif selection in ('SINGLE_ESTABLISHED','AGREEMENT_INVARIANT') and all(s==S for s in agg.values()) and complete:v='PROVEN_EFFECT'
    elif closure:v='NO_EFFECT'
    else:v='ABSTAIN'
    require(k['verdict']==v,'VERDICT','evidence/closure requires '+v+', recorded '+k['verdict'])
    return v

def check_receipt(r):
    shape('effect_receipt',r);k=r['claim_snapshot'];check_claim(k)
    for f in ('claim_id','capability_id','invocation_id','effect_class','verdict','evidence_packets','probe_outcomes','acquisition'):
        require(r[f]==k[f],'RECEIPT_PROJECTION','receipt differs from validated claim: '+f)
    require(r.get('closure')==k.get('closure'),'RECEIPT_CLOSURE','same C1-C6 closure must travel with receipt')
    a=r['answers'];require(a['effect']['verdict']==k['verdict'] and a['effect']['effect_class']==k['effect_class'],'RECEIPT_PROJECTION','effect answer mismatch')
    require(a['implementation']['selection_state']==k['selection_state'] and a['implementation']['candidates']==k['implementation_candidates'],'RECEIPT_PROJECTION','implementation answer mismatch')
    require(a['implementation'].get('selected_candidate_id')==(k['implementation_candidates'][0]['candidate_id'] if k['selection_state']=='SINGLE_ESTABLISHED' else None),'RECEIPT_PROJECTION','only singleton established implementation is selected')
    for name,key in [('resource','target'),('control','control'),('authority','authority')]:require(a[name]==k['descriptors'][key],'RECEIPT_PROJECTION','descriptor mismatch')
    byid={p['packet_id']:p for p in k['evidence_packets']};overridden={pid for x in k.get('contradictions',[]) for pid in x.get('overridden_packet_ids',[])}
    for o in OBL[1:]:
        ans=a[o.lower()];require(ans['state']==k['obligations'][o],'RECEIPT_PROJECTION','obligation answer mismatch')
        want={'SUPPORTED':{'POSITIVE'},'REFUTED':{'NEGATIVE'},'CONFLICTING':{'POSITIVE','NEGATIVE'}}.get(ans['state'],set())
        ids={p['packet_id'] for p in k['evidence_packets'] if p['obligation']==o and p['admissibility']=='PROBATIVE' and p['polarity'] in want and p['packet_id'] not in overridden and p['assertion']['predicate']!='commit_outcome_undetermined'}
        require(set(ans['settled_by_packet_ids'])==ids,'RECEIPT_PROJECTION','settling citations differ from claim')
    require(a['contradictions']['contradictions']==k.get('contradictions',[]),'RECEIPT_PROJECTION','contradictions lost')
    require(a['contradictions']['counter_evidence_found']==[p for p in k['probe_outcomes'] if p['outcome']=='FOUND'],'RECEIPT_PROJECTION','found evidence lost')
    incomplete={pid for pid,s in PROBES.items() if s['probe_class']=='BLOCKING'}-{p['probe_id'] for p in k['probe_outcomes'] if p['outcome']!='INCOMPLETE'}
    require(set(a['contradictions'].get('blocking_probes_incomplete',[]))==incomplete,'RECEIPT_PROJECTION','missing/incomplete probes must be listed')
    for key,value in a['unknowns'].items():require(value==k['acquisition'].get(key),'RECEIPT_PROJECTION','unknowns differ from acquisition')
    if 'rendering_constraints' in r:require(r['rendering_constraints']['is_negative_result']==(k['verdict']=='NO_EFFECT'),'RECEIPT_PROJECTION','only closed NO_EFFECT is a negative')

def check_ledger(d):
    shape('coverage_ledger',d)
    cs=d['claims'];n=cs['investigated'];v=d['verdict_distribution'];dist=d['obligation_state_distribution']
    require(cs['instantiated']==n+cs['not_investigated'],'LEDGER_TOTAL','claim populations do not partition')
    require(sum(v.values())==n and all(sum(s.values())==n for s in dist.values()),'LEDGER_TOTAL','verdict/state totals must equal investigated claims')
    require(cs['instantiated']<=d['invocations']['enumerated']*len(d['enabled_effect_classes']),'LEDGER_TOTAL','claims exceed enumerated invocations/classes')
    p,no,a,x=[v[z] for z in VERDICTS];es=[s[E] for s in dist.values()]
    require(max(es)<=x<=sum(es),'LEDGER_ERROR','ANALYSIS_ERROR counts necessary ERROR union')
    require(dist['IMPLEMENTATION'][R]==0,'LEDGER_IMPLEMENTATION','IMPLEMENTATION never REFUTED')
    require(p<=min(s[S] for s in dist.values()),'LEDGER_POSITIVE','positive population needs every obligation supported')
    require(no<=sum(dist[o][R] for o in OBL[1:]),'LEDGER_NEGATIVE','negative population needs a refuted obligation')
    for o,s in dist.items():
        require(s[E]+s[C]+p+no<=n,'LEDGER_DISJOINT','ERROR and CONFLICTING on '+o+' are disjoint and cannot belong to settled populations')
    er=d['analysis_errors'];require(er['total']==x,'LEDGER_ERROR_TOTAL','error total counts ANALYSIS_ERROR claims')
    if 'by_obligation' in er:require(all(er['by_obligation'].get(o,0)==dist[o][E] for o in OBL) and set(er['by_obligation'])<=set(OBL),'LEDGER_ERROR_BREAKDOWN','error breakdown must equal ERROR marginals')
    if 'by_cause' in er:require(sum(er['by_cause'].values())==x,'LEDGER_ERROR_BREAKDOWN','primary-cause breakdown partitions errored claims')
    for key in ('highest_tier_reached_histogram','stop_reason_histogram'):require(sum(d[key].values())==cs['instantiated'],'LEDGER_TOTAL','histogram must count all instantiated claims')
    require(d['stop_reason_histogram'].get('CLAIM_NOT_INVESTIGATED',0)==cs['not_investigated'],'LEDGER_TOTAL','uninvestigated histogram mismatch')
    for key in ('by_tier','by_reason'):require(sum(d['frontier'][key].values())<=d['frontier']['total'],'LEDGER_FRONTIER','partial frontier breakdown exceeds total')
    return True

def validate(kind,data):
    if kind=='claim':return check_claim(data)
    if kind=='receipt':return check_receipt(data)
    if kind=='ledger':return check_ledger(data)
    if kind=='evidence':shape('evidence',data);return check_packet(data)
    raise Invalid('KIND','unknown validation object kind')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--no-seal',action='store_true',help='authoring only; explicitly not the conformance gate');args=ap.parse_args()
    checks=[]
    def check(label,ok):checks.append((label,bool(ok)));print(('PASS ' if ok else 'FAIL ')+label)
    for n,s in SCHEMAS.items():Draft202012Validator.check_schema(s);check('schema '+n,True)
    known={s['$id']:s for s in SCHEMAS.values()}
    def refs_resolve(node,base):
        if isinstance(node,list):return all(refs_resolve(x,base) for x in node)
        if not isinstance(node,dict):return True
        if '$ref' in node:
            ref=node['$ref'];name,_,pointer=ref.partition('#');target=known.get(name or base)
            if target is None:return False
            if pointer:
                if not pointer.startswith('/'):return False
                try:
                    for part in pointer[1:].split('/'):target=target[part.replace('~1','/').replace('~0','~')]
                except (KeyError,TypeError):return False
        return all(refs_resolve(v,base) for v in node.values())
    check('every schema reference resolves locally',all(refs_resolve(s,s['$id']) for s in SCHEMAS.values()))
    cases=json.loads((HERE/'case_registry.json').read_text())
    for case in cases:
        try:
            result=validate(case['kind'],json.loads((HERE/case['file']).read_text()))
            ok=case['valid'] and ('verdict' not in case or result==case['verdict'])
            detail='accepted'
        except Invalid as e:
            expected=case.get('expected',{});ok=not case['valid'] and e.code==expected.get('code')
            if 'path' in expected:ok=ok and e.path==expected['path']
            if 'validator' in expected:ok=ok and e.validator==expected['validator']
            detail=e.code+': '+str(e)
        check(case['id']+' '+detail,ok)
    # An independent literal table, not the aggregation function's implementation.
    oracle={S:[S,U,U,C,E],R:[U,R,U,C,E],U:[U,U,U,C,E],C:[C,C,C,C,E],E:[E,E,E,E,E]}
    check('all 25 aggregation pairs',all(aggregate([l,r])==oracle[l][STATES.index(r)] for l in STATES for r in STATES))
    check('125 triples order independent',all(len({aggregate(p) for p in itertools.permutations(t)})==1 for t in itertools.product(STATES,repeat=3)))
    check('aggregation associative',all(aggregate([aggregate([a,b]),c])==aggregate([a,aggregate([b,c])]) for a,b,c in itertools.product(STATES,repeat=3)))
    roundtrips=True;ordered=True
    for case in cases:
        if not case['valid']:continue
        d=json.loads((HERE/case['file']).read_text());clone=json.loads(json.dumps(d,sort_keys=True))
        roundtrips=roundtrips and clone==d and validate(case['kind'],clone)==validate(case['kind'],d)
        if case['kind']=='claim':
            shuffled=copy.deepcopy(d)
            for key in ('implementation_candidates','evidence_packets','probe_outcomes','contradictions'):
                shuffled[key].reverse()
            ordered=ordered and check_claim(shuffled)==check_claim(d)
    check('valid records preserve JSON round-trip state',roundtrips)
    check('claim decisions invariant to reversed record order',ordered)
    check('all four verdict branches have accepted examples',set(c.get('verdict') for c in cases if c['valid'] and c['kind']=='claim')>=set(VERDICTS))
    # Absence is verified in a subprocess without site-packages. No network/install fallback.
    missing=subprocess.run([sys.executable,'-S',str(Path(__file__).resolve())],capture_output=True,text=True)
    check('missing verifier exits 2, never skips',missing.returncode==2 and 'FATAL: schema verifier unavailable' in missing.stderr)
    preservation=json.loads((HERE/'input_preservation.json').read_text())
    check('frozen inputs byte-identical',all((ROOT/path).is_file() and hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==h for path,h in preservation['files'].items()))
    protected={p.relative_to(ROOT).as_posix() for name in ('specs/AREF-001','specs/AREF-002','actenon_scan','tests') for p in (ROOT/name).rglob('*') if p.is_file()}
    check('frozen input inventory unchanged',protected==set(preservation['files']))
    contract=json.loads((HERE/'amendment_contract.json').read_text())
    check('North-Star vocabulary unchanged',contract['proof_states']==list(STATES) and contract['obligations']==list(OBL) and contract['verdicts']==list(VERDICTS) and contract['effect_classes']==['EXTERNAL_PERSISTENT_STATE_EFFECT'])
    check('amended selection vocabulary matches schema',contract['selection_states']==SCHEMAS['effect_claim']['$defs']['selectionState']['enum'])
    encoded=[c['then']['anyOf'] for c in SCHEMAS['evidence']['allOf'] if c.get('if',{}).get('properties',{}).get('admissibility',{}).get('const')=='PROBATIVE' and 'anyOf' in c.get('then',{})]
    schema_tuples=set()
    for row in encoded[0]:
        p=row['properties'];prefix=(p['assertion']['properties']['predicate']['const'],p['obligation']['const'],p['polarity']['const'])
        for source in row['anyOf']:schema_tuples.add(prefix+(source['properties']['kind']['const'],source['properties']['tier']['const']))
    registry_tuples={(r['predicate'],r['obligation'],r['polarity'],s['kind'],s['tier']) for r in RULES for s in r['sources']}
    check('assertion registry exactly encoded in schema',len(encoded)==1 and schema_tuples==registry_tuples)
    if args.no_seal:print('AUTHORING ONLY: manifest verification bypassed; this is not the conformance gate')
    else:
        manifest=json.loads((HERE/'MANIFEST.json').read_text())
        inventory={x['path'] for x in manifest['files']}
        actual={p.relative_to(HERE).as_posix() for p in HERE.rglob('*') if p.is_file() and p.name not in {'MANIFEST.json','MANIFEST.sha256'}}
        check('sealed file inventory exact',inventory==actual)
        check('sealed hashes and byte counts',all((HERE/x['path']).stat().st_size==x['bytes'] and hashlib.sha256((HERE/x['path']).read_bytes()).hexdigest()==x['sha256'] for x in manifest['files']))
        expected=''.join(x['sha256']+'  specs/AREF-002A/'+x['path']+'\n' for x in manifest['files'])
        check('SHA inventory agrees with JSON manifest',(HERE/'MANIFEST.sha256').read_text()==expected)
    failed=[l for l,ok in checks if not ok]
    print(f'{len(checks)} checks; {len(checks)-len(failed)} passed; {len(failed)} failed')
    return 1 if failed else 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except (Invalid,KeyError,ValueError,OSError) as e:
        print('FATAL: conformance infrastructure/input error: '+str(e),file=sys.stderr);raise SystemExit(2)
