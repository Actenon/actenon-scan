"""Deterministic authoring helper for normative proof records, not a scored corpus.
No programs run; no source semantics are acquired. Reads the frozen probe registry.
"""
import copy,json
from collections import Counter
from pathlib import Path
HERE=Path(__file__).resolve().parent
O=['IMPLEMENTATION','ACTIVATION','BOUNDARY','OPERATION','PERSISTENCE']
S,R,U,C,E='SUPPORTED','REFUTED','UNKNOWN','CONFLICTING','ERROR'
probes=json.loads((HERE.parent/'AREF-002/architecture_manifest.json').read_text())['counter_evidence_probes']
examples=HERE/'examples';examples.mkdir(exist_ok=True)
cases=[]
def save(name,kind,data,valid=True,code=None,path=None,validator=None,reason=''):
 file='examples/'+name+'.json';(HERE/file).write_text(json.dumps(data,indent=2)+'\n')
 row={'id':name,'kind':kind,'file':file,'valid':valid,'reason':reason}
 if valid and kind=='claim':row['verdict']=data['verdict']
 if not valid:
  row['expected']={'code':code}
  if path is not None:row['expected']['path']=path
  if validator:row['expected']['validator']=validator
 cases.append(row)
def loc(start,end=None):return {'path':'synthetic/subject.py','start_line':start,'end_line':start if end is None else end}
site=loc(10);body=loc(20,29)
preds={'IMPLEMENTATION':'implementation_is','ACTIVATION':'invocation_executes','BOUNDARY':'egress_mechanism_is','OPERATION':'operation_is_mutation','PERSISTENCE':'state_is_durably_committed'}
def packet(o,cid='c1'):
 p={'packet_id':cid+'-'+o.lower(),'tier':'L0' if o=='IMPLEMENTATION' else 'L1','kind':'local_binding' if o=='IMPLEMENTATION' else 'local_function_body','locator':site if o=='IMPLEMENTATION' else loc(21+O.index(o)), 'assertion':{'predicate':preds[o]},'polarity':'POSITIVE','obligation':o,'implementation_candidate_id':cid,'admissibility':'PROBATIVE','strength':'STRONG','acquisition_cost':{'hops':0,'bytes_read':1},'extract':{'text':'Authored witness for '+o,'verbatim':True}}
 if o=='IMPLEMENTATION':p['binding']={'relation':'SELECTED_TARGET','invocation_id':'inv1','from':site,'to':body}
 return p
base={'schema_version':'0.1.1','claim_id':'claim1','capability_id':'cap1','invocation_id':'inv1','effect_class':'EXTERNAL_PERSISTENT_STATE_EFFECT','invocation':{'locator':site,'callee_expression':'x.f','language':'python','matched_rule_ids':[]},'genesis':{'basis':'NON_REFUTATION_OF_INERTNESS','inertness_established':False},'implementation_candidates':[{'candidate_id':'c1','kind':'RESOLVED_LOCAL','locator':body,'obligations':{o:S for o in O}}],'selection_state':'SINGLE_ESTABLISHED','obligations':{o:S for o in O},'descriptors':{'target':{'coordinates':[],'scope':'unknown'},'control':{'TRIGGER_CONTROL':U,'TARGET_CONTROL':U,'CONTENT_CONTROL':U},'authority':{'state':U},'conditions':[]},'evidence_packets':[packet(o) for o in O],'probe_outcomes':[{'probe_id':p['probe_id'],'obligation':p['obligation'],'probe_class':p['probe_class'],'outcome':'NOT_FOUND'} for p in probes if p['probe_class']=='BLOCKING'],'contradictions':[],'acquisition':{'highest_tier_reached':'L1','stop_reason':'SETTLED','tiers_attempted':['L0','L1'],'unresolved_obligations':[],'frontier_size':0,'frontier':[],'frontier_truncated':False},'verdict':'PROVEN_EFFECT'}
def setstate(k,o,s,cid='c1'):
 k['obligations'][o]=s
 next(c for c in k['implementation_candidates'] if c['candidate_id']==cid)['obligations'][o]=s
 k['acquisition']['unresolved_obligations']=[o for o,s in k['obligations'].items() if s in (U,C)]
 if s in (U,C,E):k['acquisition']['stop_reason']='NO_FURTHER_TIER'
flags=['C1_no_opaque_or_dynamic_candidate','C2_refuted_for_every_candidate','C3_no_conflicting_obligation','C4_no_budget_exhausted_on_contributing_path','C5_relevant_frontier_empty','C6_no_error_on_necessary_obligation']
def closure(o):return {'refuted_obligation':o,**{x:True for x in flags}}
positive=copy.deepcopy(base)
negative=copy.deepcopy(base);setstate(negative,'PERSISTENCE',R);p=negative['evidence_packets'][-1];p['assertion']['predicate']='state_is_guaranteed_rolled_back';p['polarity']='NEGATIVE';negative['closure']=closure('PERSISTENCE');negative['verdict']='NO_EFFECT'
opaque=copy.deepcopy(base);opaque['implementation_candidates']=[{'candidate_id':'c1','kind':'OPAQUE_EXTERNAL','obligations':{o:U for o in O}}];opaque['obligations']={o:U for o in O};opaque['selection_state']='UNRESOLVED_IDENTITY';opaque['evidence_packets']=[];opaque['probe_outcomes']=[];opaque['acquisition']={'highest_tier_reached':'L0','stop_reason':'CLAIM_NOT_INVESTIGATED','tiers_attempted':[],'unresolved_obligations':O,'frontier_size':0,'frontier':[]};opaque['verdict']='ABSTAIN'
error=copy.deepcopy(base);setstate(error,'IMPLEMENTATION',E);error['selection_state']='SELECTION_ERROR';error['verdict']='ANALYSIS_ERROR';error['acquisition']['stop_reason']='ACQUISITION_ERROR'
for name,k in [('proven',positive),('no_effect',negative),('opaque_abstain',opaque),('analysis_error',error)]:save('valid_'+name,'claim',k,reason='Four-verdict satisfiability; empty matched_rule_ids retained.')
# H1 implementation errors cannot be replaced by a label.
x=copy.deepcopy(error);x['obligations']['IMPLEMENTATION']=S;x['selection_state']='SINGLE_ESTABLISHED';x['verdict']='PROVEN_EFFECT';save('H1_error_erased','claim',x,False,'CANDIDATE_AGGREGATION')
x=copy.deepcopy(error);x['selection_state']='SINGLE_ESTABLISHED';save('H1_error_bad_selection','claim',x,False,'SELECTION_STATE')
# H2 registry and safe unknown combinations.
for pred in ['state_is_ephemeral','state_is_guaranteed_rolled_back','dry_run_in_force','test_double_in_force']:
 x=copy.deepcopy(positive);x['evidence_packets'][-1]['assertion']['predicate']=pred;save('H2_positive_'+pred,'claim',x,False,'SCHEMA','/evidence_packets/4','anyOf',reason='Positive persistence incompatible with typed assertion/source registry.')
x=copy.deepcopy(positive);x['evidence_packets'][3]['assertion']['predicate']='operation_is_no_op';save('H2_positive_noop','claim',x,False,'SCHEMA','/evidence_packets/3','anyOf')
x=copy.deepcopy(positive);x['evidence_packets'][-1]['kind']='transport_primitive';save('H2_transport_persistence','claim',x,False,'SCHEMA','/evidence_packets/4','anyOf')
x=copy.deepcopy(positive);x['evidence_packets'][3]['kind']='transport_primitive';save('H2_transport_operation','claim',x,False,'SCHEMA','/evidence_packets/3','anyOf')
x=copy.deepcopy(positive);x['evidence_packets'][-1]['assertion']['predicate']='unregistered_fact';save('H2_unregistered_probative','claim',x,False,'SCHEMA','/evidence_packets/4','anyOf')
x=copy.deepcopy(positive);x['evidence_packets'][-1]['assertion']['predicate']='unregistered_fact';x['evidence_packets'][-1]['admissibility']='HYPOTHESIS_ONLY';setstate(x,'PERSISTENCE',U);x['verdict']='ABSTAIN';save('valid_unregistered_hypothesis','claim',x)
# H3 admissible body-over-contract precedence and FOUND probes.
contract=copy.deepcopy(positive['evidence_packets'][3]);contract.update(packet_id='contract-observation',tier='L6',kind='sdk_operation_metadata',polarity='NEGATIVE');contract['assertion']['predicate']='operation_is_observation';contract['locator']={'path':'synthetic/contract.json','start_line':1,'end_line':1,'package':'synthetic-dependency','version':'1','version_resolution':'EXACT_MANIFEST_PIN'}
precedence=copy.deepcopy(positive);precedence['evidence_packets'].append(contract);precedence['acquisition']['tiers_attempted'].append('L6');precedence['acquisition']['highest_tier_reached']='L6'
rec={'obligation':'OPERATION','implementation_candidate_id':'c1','positive_packet_ids':['c1-operation'],'negative_packet_ids':['contract-observation'],'resolution':'RESOLVED_IMPLEMENTATION_PRECEDENCE','overridden_packet_ids':['contract-observation'],'precedence':{'selection_packet_id':'c1-implementation','winning_paths':[{'packet_id':'c1-operation','binding_packet_ids':[]}]}}
precedence['contradictions']=[rec]
for p in precedence['probe_outcomes']:
 if p['probe_id']=='CP-OPR-01':p.update(outcome='FOUND',packet_ids=['contract-observation'])
save('valid_precedence_found','claim',precedence,reason='Completed FOUND contract counter-evidence is resolved with selected-body provenance.')
x=copy.deepcopy(precedence);x['contradictions'][0]['precedence']['selection_packet_id']='c1-operation';save('H3_tier_not_selection_proof','claim',x,False,'PRECEDENCE_SELECTION')
x=copy.deepcopy(precedence);x['evidence_packets'][3]['locator']=loc(70);save('H3_unlinked_body','claim',x,False,'PRECEDENCE_LINK')
x=copy.deepcopy(precedence);x['evidence_packets'][3]['kind']='package_provenance';save('H3_package_not_body','claim',x,False,'SCHEMA','/evidence_packets/3','anyOf')
x=copy.deepcopy(precedence);del x['contradictions'][0]['precedence'];save('H3_no_recorded_provenance','claim',x,False,'SCHEMA','/contradictions/0','required')
# A linked helper path must contain a typed resolved-call binding, never just a locator.
x=copy.deepcopy(precedence);edge=packet('IMPLEMENTATION');edge['packet_id']='helper-edge';edge['locator']=loc(26);edge['binding']={'relation':'RESOLVED_CALL','invocation_id':'inv1','from':body,'to':loc(70,79)};x['evidence_packets'].append(edge);x['evidence_packets'][3]['locator']=loc(72);x['contradictions'][0]['precedence']['winning_paths'][0]['binding_packet_ids']=['helper-edge'];save('valid_helper_precedence','claim',x)
# H4 uncertainty preserves conflict before other negative closure.
conflict=copy.deepcopy(positive);negp=copy.deepcopy(negative['evidence_packets'][-1]);negp['packet_id']='rollback';unc=copy.deepcopy(negp);unc['packet_id']='undetermined';unc['assertion']['predicate']='commit_outcome_undetermined';conflict['evidence_packets'] += [negp,unc];conflict['contradictions']=[{'obligation':'PERSISTENCE','implementation_candidate_id':'c1','positive_packet_ids':['c1-persistence'],'negative_packet_ids':['rollback'],'resolution':'UNRESOLVED'}];setstate(conflict,'PERSISTENCE',C);conflict['verdict']='ABSTAIN';save('valid_uncertainty_preserves_conflict','claim',conflict)
x=copy.deepcopy(conflict);setstate(x,'PERSISTENCE',U);save('H4_uncertainty_erases_conflict','claim',x,False,'PROOF_STATE')
x=copy.deepcopy(conflict);setstate(x,'BOUNDARY',R);x['evidence_packets'][2]['polarity']='NEGATIVE';x['evidence_packets'][2]['assertion']['predicate']='terminates_in_process_state';x['closure']=closure('BOUNDARY');x['verdict']='NO_EFFECT';save('H4_conflict_negative_closure','claim',x,False,'CLOSURE_C3')
# M1 probe completion versus evidence meaning.
found=copy.deepcopy(positive);hp=copy.deepcopy(positive['evidence_packets'][-1]);hp.update(packet_id='hypothesis',kind='identifier_name',admissibility='HYPOTHESIS_ONLY',polarity='NEGATIVE');hp['assertion']['predicate']='state_is_ephemeral';found['evidence_packets'].append(hp)
for p in found['probe_outcomes']:
 if p['probe_id']=='CP-PER-03':p.update(outcome='FOUND',packet_ids=['hypothesis'])
save('valid_hypothesis_found','claim',found)
x=copy.deepcopy(found);x['verdict']='ABSTAIN';save('M1_blanket_found_veto','claim',x,False,'VERDICT')
for mode in ['MISSING','INCOMPLETE']:
 x=copy.deepcopy(positive)
 if mode=='MISSING':x['probe_outcomes']=x['probe_outcomes'][1:]
 else:x['probe_outcomes'][0]['outcome']='INCOMPLETE'
 save('M1_'+mode.lower()+'_positive','claim',x,False,'VERDICT')
 x['verdict']='ABSTAIN';save('valid_'+mode.lower()+'_probe_abstain','claim',x)
# Initial unknown selection and schema closure.
x=copy.deepcopy(opaque);x['selection_state']='SINGLE_ESTABLISHED';save('M3_opaque_false_establishment','claim',x,False,'SELECTION_STATE')
x=copy.deepcopy(negative);del x['closure'];save('M4_missing_closure','claim',x,False,'SCHEMA','/','required')
x=copy.deepcopy(negative);x['closure']['C4_no_budget_exhausted_on_contributing_path']=False;save('M4_false_closure_flag','claim',x,False,'SCHEMA','/closure/C4_no_budget_exhausted_on_contributing_path','const')
# Relevant frontiers and receipt projection.
openk=copy.deepcopy(negative);openk.pop('closure');openk['verdict']='ABSTAIN';openk['acquisition']['stop_reason']='TIER_UNAVAILABLE';openk['acquisition']['frontier_size']=1;openk['acquisition']['frontier']=[{'origin':site,'would_reach_tier':'L5','reason':'TIER_UNAVAILABLE','might_settle':['PERSISTENCE']}]
save('valid_open_frontier_abstain','claim',openk)
x=copy.deepcopy(openk);x['closure']=closure('PERSISTENCE');x['verdict']='NO_EFFECT';save('H5_claim_open_negative','claim',x,False,'CLOSURE_C5')
def receipt(k):
 k=copy.deepcopy(k);selected=k['implementation_candidates'][0]['candidate_id'] if k['selection_state']=='SINGLE_ESTABLISHED' else None
 impl={'selection_state':k['selection_state'],'candidates':copy.deepcopy(k['implementation_candidates'])}
 if selected:impl['selected_candidate_id']=selected
 overridden={pid for c in k['contradictions'] for pid in c.get('overridden_packet_ids',[])}
 answers={'effect':{'effect_class':k['effect_class'],'verdict':k['verdict'],'statement':'Illustrative '+k['verdict']+' proof record; no source acquisition performed.'},'implementation':impl,'resource':k['descriptors']['target'],'control':k['descriptors']['control'],'authority':k['descriptors']['authority']}
 for o in O[1:]:
  s=k['obligations'][o];want={S:['POSITIVE'],R:['NEGATIVE'],C:['POSITIVE','NEGATIVE']}.get(s,[])
  answers[o.lower()]={'state':s,'settled_by_packet_ids':[p['packet_id'] for p in k['evidence_packets'] if p['obligation']==o and p['admissibility']=='PROBATIVE' and p['polarity'] in want and p['packet_id'] not in overridden and p['assertion']['predicate']!='commit_outcome_undetermined']}
 completed={p['probe_id'] for p in k['probe_outcomes'] if p['outcome']!='INCOMPLETE'}
 answers['contradictions']={'contradictions':k['contradictions'],'counter_evidence_found':[p for p in k['probe_outcomes'] if p['outcome']=='FOUND'],'blocking_probes_incomplete':[p['probe_id'] for p in probes if p['probe_class']=='BLOCKING' and p['probe_id'] not in completed]}
 answers['unknowns']={key:k['acquisition'][key] for key in ['unresolved_obligations','highest_tier_reached','stop_reason','frontier_size','frontier']}
 r={key:k[key] for key in ['schema_version','claim_id','capability_id','invocation_id','effect_class','verdict','evidence_packets','probe_outcomes','acquisition']};r.update(receipt_id='receipt1',answers=answers,claim_snapshot=k,rendering_constraints={'is_negative_result':k['verdict']=='NO_EFFECT','may_render_as_safe':False})
 if 'closure' in k:r['closure']=k['closure']
 return copy.deepcopy(r)
for name,k in [('proven',positive),('no_effect',negative),('abstain',opaque),('analysis_error',error),('found_precedence',precedence)]:save('valid_receipt_'+name,'receipt',receipt(k))
x=receipt(openk);x['verdict']='NO_EFFECT';x['answers']['effect']['verdict']='NO_EFFECT';x['closure']=closure('PERSISTENCE');x['rendering_constraints']['is_negative_result']=True;save('H5_receipt_strengthened','receipt',x,False,'RECEIPT_PROJECTION')
x=receipt(openk);x['claim_snapshot']['verdict']='NO_EFFECT';x['claim_snapshot']['closure']=closure('PERSISTENCE');x['verdict']='NO_EFFECT';x['answers']['effect']['verdict']='NO_EFFECT';x['closure']=closure('PERSISTENCE');save('H5_receipt_and_snapshot_open_negative','receipt',x,False,'CLOSURE_C5')
# Multi-candidate agreement and divergence; aggregation of all five obligations.
multi=copy.deepcopy(positive);cand=copy.deepcopy(multi['implementation_candidates'][0]);cand['candidate_id']='c2';multi['implementation_candidates'].append(cand)
for o in O:multi['evidence_packets'].append(packet(o,'c2'))
for p in multi['evidence_packets']:
 if 'binding' in p:p['binding']['relation']='POSSIBLE_TARGET'
multi['selection_state']='AGREEMENT_INVARIANT';save('valid_agreement','claim',multi)
x=copy.deepcopy(multi);setstate(x,'OPERATION',R,'c2');x['obligations']['OPERATION']=U;x['acquisition']['unresolved_obligations']=['OPERATION'];x['acquisition']['stop_reason']='NO_FURTHER_TIER';x['evidence_packets'][8]['assertion']['predicate']='operation_is_observation';x['evidence_packets'][8]['polarity']='NEGATIVE';x['selection_state']='UNRESOLVED_DIVERGENT';x['verdict']='ABSTAIN';save('valid_divergent','claim',x)
y=copy.deepcopy(x);y['obligations']['OPERATION']=C;save('M2_divergence_not_contradiction','claim',y,False,'CANDIDATE_AGGREGATION')
y=copy.deepcopy(multi);y['implementation_candidates'][1]['obligations']['IMPLEMENTATION']=E;save('H1_agreement_hides_error','claim',y,False,'CANDIDATE_AGGREGATION')
y['obligations']['IMPLEMENTATION']=E;y['selection_state']='SELECTION_ERROR';y['verdict']='ANALYSIS_ERROR';y['acquisition']['stop_reason']='ACQUISITION_ERROR';save('valid_multi_error','claim',y)
# H6 ledger marginals. No fabricated cross-obligation correlations.
ledger=json.loads((HERE.parent/'AREF-002/examples/coverage_ledger.valid.json').read_text());ledger.pop('_case',None);ledger['schema_version']='0.1.1'
def ledger_for(claims):
 d=copy.deepcopy(ledger);n=len(claims);d['capabilities']={'discovered':1};d['invocations']={'enumerated':n};d['claims']={'instantiated':n,'investigated':n,'not_investigated':0};d['verdict_distribution']={v:sum(k['verdict']==v for k in claims) for v in ['PROVEN_EFFECT','NO_EFFECT','ABSTAIN','ANALYSIS_ERROR']};d['obligation_state_distribution']={o:{s:sum(k['obligations'][o]==s for k in claims) for s in [S,R,U,C,E]} for o in O};d['highest_tier_reached_histogram']={'L1':n};d['stop_reason_histogram']={'NO_FURTHER_TIER':n};d['budget_exhaustion']={};d['frontier']={'total':0,'by_tier':{},'by_reason':{}};d['analysis_errors']={'total':d['verdict_distribution']['ANALYSIS_ERROR'],'by_obligation':{o:d['obligation_state_distribution'][o][E] for o in O}}
 for key in ['evidence','counter_evidence','contradictions','performance']:d.pop(key,None)
 d['highest_tier_reached_histogram']=dict(Counter(k['acquisition']['highest_tier_reached'] for k in claims))
 d['stop_reason_histogram']=dict(Counter(k['acquisition']['stop_reason'] for k in claims))
 d['interpretation']['statement']='Authored normative ledger with '+str(n)+' investigated claims; counts do not measure a real repository. Unresolved claims are not negative results.'
 return d
validledger=ledger_for([positive,negative,error,conflict]);save('valid_ledger','ledger',validledger)
x=ledger_for([negative,error]);x['obligation_state_distribution']['BOUNDARY']={S:0,R:0,U:0,C:1,E:1};save('H6_impossible_settled_population','ledger',x,False,'LEDGER_DISJOINT')
x=copy.deepcopy(validledger);x['analysis_errors']['total']=0;save('H6_error_total','ledger',x,False,'LEDGER_ERROR_TOTAL')
x=copy.deepcopy(validledger);x['analysis_errors']['by_obligation']['BOUNDARY']=10;save('H6_error_breakdown','ledger',x,False,'LEDGER_ERROR_BREAKDOWN')
x=copy.deepcopy(validledger);x['analysis_errors']['by_cause']={'parser':2};save('H6_cause_partition','ledger',x,False,'LEDGER_ERROR_BREAKDOWN')
# Boundary cases for the amended semantics, not new acquisition features.
x=copy.deepcopy(positive);x['implementation_candidates'][0].pop('obligations');save('valid_single_established_shorthand','claim',x)
x=copy.deepcopy(opaque);x['implementation_candidates'][0].pop('obligations');save('M3_opaque_omitted_states','claim',x,False,'CANDIDATE_STATES')
x=copy.deepcopy(positive);x['implementation_candidates'][0]['kind']='OPAQUE_EXTERNAL';save('M3_opaque_supported_identity','claim',x,False,'OPAQUE_IDENTITY')
x=copy.deepcopy(precedence);x['evidence_packets'][3]['locator'].update(package='synthetic-other',version='2',version_resolution='EXACT_MANIFEST_PIN');save('H3_other_source_identity','claim',x,False,'PRECEDENCE_LINK')
x=copy.deepcopy(negative);x['acquisition'].update(stop_reason='BUDGET_EXHAUSTED',frontier_size=1,frontier=[{'origin':site,'would_reach_tier':'L5','reason':'BUDGET_EXHAUSTED','might_settle':['OPERATION']}]);save('valid_unrelated_frontier_negative','claim',x,reason='C4 is asserted for the contributing refutation path, not all work; C5 relevance is obligation-specific.')
x=receipt(negative);del x['closure'];save('H5_receipt_missing_closure','receipt',x,False,'SCHEMA','/','required')
x=copy.deepcopy(multi);x['implementation_candidates'][1]['obligations']['OPERATION']=C;x['obligations']['OPERATION']=C;x['evidence_packets'].append(copy.deepcopy(contract));x['evidence_packets'][-1].update(packet_id='c2-observation',implementation_candidate_id='c2');x['contradictions']=[{'obligation':'OPERATION','implementation_candidate_id':'c2','positive_packet_ids':['c2-operation'],'negative_packet_ids':['c2-observation'],'resolution':'UNRESOLVED'}];x['selection_state']='UNRESOLVED_DIVERGENT';x['verdict']='ABSTAIN';x['acquisition'].update(stop_reason='NO_FURTHER_TIER',tiers_attempted=['L0','L1','L6'],highest_tier_reached='L6',unresolved_obligations=['OPERATION']);save('valid_multi_conflict','claim',x)
y=copy.deepcopy(x);y['obligations']['OPERATION']=U;save('M2_conflict_erased','claim',y,False,'CANDIDATE_AGGREGATION')
x['implementation_candidates'][0]['obligations']['OPERATION']=E;x['obligations']['OPERATION']=E;x['verdict']='ANALYSIS_ERROR';x['acquisition'].update(stop_reason='ACQUISITION_ERROR',unresolved_obligations=[]);save('valid_error_over_conflict','claim',x)
y=copy.deepcopy(x);y['obligations']['OPERATION']=C;y['verdict']='ABSTAIN';save('M2_error_erased','claim',y,False,'CANDIDATE_AGGREGATION')
y=copy.deepcopy(error);y['verdict']='ABSTAIN';save('H1_error_as_abstain','claim',y,False,'VERDICT')
overlap=copy.deepcopy(error);setstate(overlap,'ACTIVATION',E);save('valid_ledger_overlapping_errors','ledger',ledger_for([positive,negative,overlap,conflict]))
x=copy.deepcopy(negative);cp=copy.deepcopy(contract);cp.update(packet_id='contract-commit',obligation='PERSISTENCE',polarity='POSITIVE');cp['assertion']['predicate']='state_is_durably_committed';x['evidence_packets'].append(cp);x['acquisition']['tiers_attempted'].append('L6');x['acquisition']['highest_tier_reached']='L6';x['contradictions']=[{'obligation':'PERSISTENCE','implementation_candidate_id':'c1','positive_packet_ids':['contract-commit'],'negative_packet_ids':['c1-persistence'],'resolution':'RESOLVED_IMPLEMENTATION_PRECEDENCE','overridden_packet_ids':['contract-commit'],'precedence':{'selection_packet_id':'c1-implementation','winning_paths':[{'packet_id':'c1-persistence','binding_packet_ids':[]}]}}]
for p in x['probe_outcomes']:
 if p['probe_id']=='CP-PER-02':p.update(outcome='FOUND',packet_ids=['c1-persistence'])
save('valid_negative_precedence','claim',x,reason='Selected-body precedence is symmetric; guaranteed rollback can override a contrary contract.')
save('valid_receipt_negative_precedence','receipt',receipt(x))
(HERE/'case_registry.json').write_text(json.dumps(cases,indent=2)+'\n')
print('Authored',len(cases),'normative fixtures.')
