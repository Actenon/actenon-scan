"""Authority mutation tests: caller metadata is never a proof policy."""
from dataclasses import replace
from itertools import permutations
import pytest
from actenon_scan import Entrypoint,RootKind,scan_effect_claims
from actenon_scan import reachability_kernel as K
from actenon_scan.semantic_ir import BindingEdgeProof,EdgeObligation as O,SemanticState as S,BASE_OBLIGATIONS
from actenon_scan.binding_claims import BindingState

POSITIVES=[
 ('python_function','app.py','entry','def worker():\n    observation.signal()\ndef entry():\n    worker()',{}),
 ('python_method','app.py','Unit.entry','class Unit:\n    def worker(self):\n        observation.signal()\n    def entry(self):\n        self.worker()',{}),
 ('python_import','app.py','entry','from support import worker\ndef entry():\n    worker()',{'support.py':'def worker():\n    observation.signal()'}),
 ('python_closure','app.py','entry','def entry():\n    def worker():\n        observation.signal()\n    def stage():\n        worker()\n    stage()',{}),
 ('python_comprehension','app.py','entry','def worker():\n    observation.signal()\n    return 1\ndef entry():\n    result=[worker() for index in (1,)]',{}),
 ('typescript_function','app.ts','entry','function worker(){observation.signal()}function entry(){worker()}',{}),
 ('typescript_method','app.ts','Unit.entry','class Unit{worker(){observation.signal()}entry(){this.worker()}}',{}),
 ('typescript_import','app.ts','entry','import {worker} from "./support";function entry(){worker()} ',{'support.ts':'export function worker(){observation.signal()}'}),
 ('typescript_alias','app.ts','entry','function worker(){observation.signal()}function entry(){const stored=worker;stored()}',{}),
 ('go_function','app.go','entry','package main\nfunc worker(){observation.signal()}\nfunc entry(){worker()}',{}),
 ('go_method','app.go','Unit.entry','package main\ntype Unit struct{}\nfunc(u Unit)worker(){observation.signal()}\nfunc(u Unit)entry(){u.worker()}',{}),
 ('go_literal','app.go','entry','package main\nfunc entry(){worker:=func(){observation.signal()};worker()}',{}),
]

def run(tmp_path,case):
 _,file,symbol,source,extra=case
 for name,text in {file:source,**extra}.items():(tmp_path/name).write_text(text)
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,symbol)],discover_roots=False)
 assert not r.analysis_errors
 assert any(n.callee_spelling=='observation.signal' for n in r.graph.invocations.values())
 return r,next(b for n in r.graph.invocations.values() for b in n.binding_claims if b.state==BindingState.ESTABLISHED)


def mutations(p):
 for field in vars(p.context):
  if field=='steps':continue
  value=False if field=='complete' else frozenset() if field=='evidence' else ''
  if getattr(p.context,field)!=value:
   yield 'context:'+field,replace(p,context=replace(p.context,**{field:value}))
 for i in range(len(p.context.steps)):
  yield 'step:'+str(i),replace(p,context=replace(p.context,steps=p.context.steps[:i]+p.context.steps[i+1:]))
 yield 'unknown-step',replace(p,context=replace(p.context,steps=p.context.steps+(K.ResolutionStep(K.ResolutionStepKind.UNKNOWN,'unknown','unknown'),)))
 for obligation in O:
  yield 'fact-remove:'+obligation.value,replace(p,facts=tuple((o,s) for o,s in p.facts if o!=obligation))
  for state in (S.UNKNOWN,S.REFUTED):
   yield 'fact-add:'+obligation.value+state.value,replace(p,facts=p.facts+((obligation,state),))
 for i,w in enumerate(p.witnesses):
  yield 'witness-remove:'+str(i),replace(p,witnesses=p.witnesses[:i]+p.witnesses[i+1:])
  for field in ('identity','provenance','source_digest','policy','state'):
   value=S.UNKNOWN if field=='state' else () if field=='provenance' else ''
   if getattr(w,field)==value:continue
   yield 'witness:'+str(i)+':'+field,replace(p,witnesses=p.witnesses[:i]+(replace(w,**{field:value}),)+p.witnesses[i+1:])
 yield 'provenance',replace(p,provenance=())
 yield 'raw-construction',BindingEdgeProof(p.required,p.facts,p.provenance,p.context,p.witnesses)
 yield 'raw-facts-api',K.evaluate(context=p.context,semantic_facts=p.facts,witnesses=p.witnesses,candidates=(p.context.candidate,))

def inventory_mutations(inventory):
 for component in ('bindings','namespaces','sites'):
  values=getattr(inventory,component)
  if not values:continue
  yield component+':removed',replace(inventory,**{component:()})
  first=values[0]
  for field,value in vars(first).items():
   changed=not value if isinstance(value,bool) else value+1 if isinstance(value,int) else () if isinstance(value,tuple) else frozenset() if isinstance(value,frozenset) else 'changed-observation'
   if changed==value:changed=('changed-observation',) if isinstance(value,tuple) else frozenset({'changed-observation'}) if isinstance(value,frozenset) else ''
   yield component+':'+field,replace(inventory,**{component:(replace(first,**{field:changed}),)+values[1:]})

@pytest.mark.parametrize('case',POSITIVES,ids=lambda c:c[0])
def test_binding_inventory_mutation_cannot_issue_authority(tmp_path,monkeypatch,case):
 captured=[];original=K.evaluate
 def record(**kw):
  captured.append(kw)
  return original(**kw)
 monkeypatch.setattr(K,'evaluate',record)
 _,binding=run(tmp_path,case)
 arguments=next(k for k in captured if k['context'].subject==binding.subject and k['context'].candidate==binding.candidate_id)
 for name,inventory in inventory_mutations(arguments['inventory']):
  p=original(**{**arguments,'inventory':inventory})
  assert not p.authorizes(binding.subject,binding.candidate_id,binding.positive_evidence),name

@pytest.mark.parametrize('case',POSITIVES,ids=lambda c:c[0])
def test_proof_mutation_matrix(tmp_path,case):
 _,b=run(tmp_path,case)
 assert b.edge_proof.authorizes(b.subject,b.candidate_id,b.positive_evidence)
 for name,p in mutations(b.edge_proof):
  assert not p.authorizes(b.subject,b.candidate_id,b.positive_evidence),name
  assert replace(b,edge_proof=p).state!=BindingState.ESTABLISHED,name

@pytest.mark.parametrize('kind',list(K.ResolutionStepKind))
def test_every_context_kind_has_central_policy(tmp_path,kind):
 _,b=run(tmp_path,POSITIVES[0]);ctx=b.edge_proof.context
 added=replace(ctx,steps=ctx.steps+(K.ResolutionStep(kind,ctx.environment,'test-observation'),))
 required=K.derive_required_obligations(added)
 if kind==K.ResolutionStepKind.UNKNOWN:assert required is None
 else:
  assert BASE_OBLIGATIONS <= required
  assert b.edge_proof.required <= required
  if kind in {K.ResolutionStepKind.IMPORT_HOP,K.ResolutionStepKind.NAMESPACE_MEMBER}:assert O.IMPORT_PROVENANCE_EXACT in required
  if kind==K.ResolutionStepKind.RECEIVER_DISPATCH:assert O.RECEIVER_COMPATIBLE in required

@pytest.mark.parametrize('case',POSITIVES,ids=lambda c:c[0])
def test_required_metadata_cannot_weaken_policy(tmp_path,case):
 _,b=run(tmp_path,case);p=b.edge_proof
 q=replace(p,required=frozenset())
 assert K.derive_required_obligations(q.context)==K.derive_required_obligations(p.context)
 if p.required-BASE_OBLIGATIONS:assert not q.authorizes(b.subject,b.candidate_id,b.positive_evidence)
 else:assert q.required==p.required

@pytest.mark.parametrize('obligation',list(O))
def test_uncertainty_meet_is_order_independent(obligation):
 for state in (S.UNKNOWN,S.REFUTED):
  pieces=[BindingEdgeProof(frozenset(O),tuple((o,S.SUPPORTED) for o in O)),BindingEdgeProof(frozenset(O),((obligation,state),))]
  for order in permutations(pieces):
   p=order[0].accumulate(order[1])
   assert p.state(obligation)==state
   assert not p.closed
   assert not p.authorizes('site','candidate',())

@pytest.mark.parametrize('language,source,file,symbol',[
 ('python','class Unit:\n    def route(self):\n        forbidden.signal()\n    def entry(self):\n        first=setattr\n        second=first\n        receiver=self\n        second(receiver,"route",fresh)\n        self.route()','app.py','Unit.entry'),
 ('typescript','const first=Object.assign;const second=first;class Unit{route(){forbidden.signal()}entry(){const receiver=this;second(receiver,{route:fresh});this.route()}}','app.ts','Unit.entry'),
 ('typescript','const {set:second}=Reflect;class Unit{route(){forbidden.signal()}entry(){second(this,"route",fresh);this.route()}}','app.ts','Unit.entry'),
 ('python','import support\ndef entry():\n    opaque(support)\n    support.worker()','app.py','entry'),
 ('typescript','import * as support from "./support";function entry(){opaque(support);support.worker()}','app.ts','entry'),
])
def test_escape_and_alias_mutation_are_frontiers(tmp_path,language,source,file,symbol):
 extra='def worker():\n    forbidden.signal()' if language=='python' else 'export function worker(){forbidden.signal()}'
 (tmp_path/('support.py' if language=='python' else 'support.ts')).write_text(extra)
 (tmp_path/file).write_text(source)
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,symbol)],discover_roots=False)
 assert not r.analysis_errors
 assert not any(n.callee_spelling=='forbidden.signal' for n in r.graph.invocations.values())
 assert r.claims and r.graph.coverage_gaps
 events=r.graph.frontend_facts[file]['escape_events'];assert events
 assert any(e['mutation']=='MUTATION_POSSIBLE' for e in events)
 if 'first=' in source or 'first =' in source:
  assert any(e['capabilities']==('MEMBER_MUTATION',) for e in events)


def test_inventory_cannot_ignore_recorded_escape(tmp_path,monkeypatch):
 from actenon_scan.repository import invocation_adapters as A
 original=A._propagate_open_certificates
 def dishonest(units):
  original(units)
  # Deliberately launder facet states. Kernel must still inspect escapes.
  for u in units:
   for certificate in u.certificates.values():
    certificate.facets={f:S.SUPPORTED for f in certificate.facets}
 monkeypatch.setattr(A,'_propagate_open_certificates',dishonest)
 source='class Unit:\n    def worker(self):\n        forbidden.signal()\n    def entry(self):\n        opaque(self)\n        self.worker()'
 (tmp_path/'app.py').write_text(source)
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint('app.py','Unit.entry')],discover_roots=False)
 node=next(n for n in r.graph.invocations.values() if n.callee_spelling=='self.worker')
 assert not node.established_targets and r.claims
 assert not any(n.callee_spelling=='forbidden.signal' for n in r.graph.invocations.values())
 assert any(b.edge_proof.state(O.WRITE_SET_CLOSED)==S.UNKNOWN for b in node.binding_claims if b.candidate_is_local)


def test_candidate_declaration_cannot_be_relabelled(tmp_path,monkeypatch):
 from actenon_scan.repository import invocation_adapters as A
 original=K.evaluate;results=[]
 def attempt(**kw):
  ctx=kw['context']
  if ctx.candidate_kind=='INSTANCE_METHOD':
   # Remove every frontend-supplied receiver hint and disguise the call as a
   # lexical function. The independent declaration inventory must reject it.
   forged=replace(ctx,callee='worker',candidate_kind='FUNCTION',
      evidence=frozenset({'LEXICAL_DECLARATION'}),
      steps=tuple(s for s in ctx.steps if s.kind!=K.ResolutionStepKind.RECEIVER_DISPATCH))
   p=original(**{**kw,'context':forged})
   results.append(p.authorizes(forged.subject,forged.candidate,forged.evidence))
  return original(**kw)
 monkeypatch.setattr(K,'evaluate',attempt)
 run(tmp_path,POSITIVES[1])
 assert results and not any(results)


def test_no_witnessless_inventory_can_issue(tmp_path,monkeypatch):
 original=K.evaluate;attempts=[]
 def damaged(**kw):
  inventory=kw['inventory']
  for field in ('source_digest','grammar_digest','grammar_nodes'):
   value=() if field=='grammar_nodes' else ''
   scopes=tuple(replace(a,**{field:value}) for a in inventory.scopes)
   p=original(**{**kw,'inventory':replace(inventory,scopes=scopes)})
   attempts.append(p.authorizes(kw['context'].subject,kw['context'].candidate,kw['context'].evidence))
  return original(**kw)
 monkeypatch.setattr(K,'evaluate',damaged)
 run(tmp_path,POSITIVES[0])
 assert attempts and not any(attempts)

@pytest.mark.parametrize('file,source,symbol',[
 ('app.py','import support\ndef entry():\n    captured=(support,)[0]\n    opaque(captured)\n    support.worker()','entry'),
 ('app.ts','const mutator=Reflect.set;class Unit{worker(){forbidden.signal()}entry(){const captured=Unit["prototype"];mutator(captured,"worker",fresh);this.worker()}}','Unit.entry'),
 ('app.ts','class Unit{worker(){forbidden.signal()}entry(){const captured=()=>this;opaque(captured);this.worker()}}','Unit.entry'),
 ('app.ts','class Unit{worker(){forbidden.signal()}entry(){opaque(()=>this);this.worker()}}','Unit.entry'),
 ('app.py','class Unit:\n    def worker(self):\n        forbidden.signal()\n    def entry(self):\n        opaque(lambda: self)\n        self.worker()','Unit.entry'),
])
def test_escaping_capability_preserves_captured_mutable_identity(tmp_path,file,source,symbol):
 (tmp_path/file).write_text(source)
 (tmp_path/'support.py').write_text('def worker():\n    forbidden.signal()')
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,symbol)],discover_roots=False)
 assert not r.analysis_errors
 assert r.claims and r.graph.coverage_gaps
 assert not any(n.callee_spelling=='forbidden.signal' for n in r.graph.invocations.values())


def test_escape_identity_bound_fails_closed(tmp_path):
 lines=['class Unit:','    def worker(self):','        forbidden.signal()','    def entry(self):','        capture0=self']
 lines += [f'        capture{i}=capture{i-1}' for i in range(1,40)]
 lines += ['        opaque(capture39)','        self.worker()']
 (tmp_path/'app.py').write_text('\n'.join(lines))
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint('app.py','Unit.entry')],discover_roots=False)
 assert r.claims and any('escape identity resolution bound' in reason for _,reason in r.graph.coverage_gaps)
 assert not any(n.callee_spelling=='forbidden.signal' for n in r.graph.invocations.values())


def test_receiver_path_must_match_declaration_namespace(tmp_path,monkeypatch):
 original=K.evaluate;attempts=[]
 def forged(**kw):
  ctx=kw['context']
  if ctx.candidate_kind=='INSTANCE_METHOD':
   path=tuple(replace(s,identity=ctx.environment) if s.kind==K.ResolutionStepKind.RECEIVER_DISPATCH else s for s in ctx.steps)
   c=replace(ctx,steps=path)
   p=original(**{**kw,'context':c})
   attempts.append(p.authorizes(c.subject,c.candidate,c.evidence))
  return original(**kw)
 monkeypatch.setattr(K,'evaluate',forged)
 run(tmp_path,POSITIVES[1])
 assert attempts and not any(attempts)

@pytest.mark.parametrize('field,value',[('caller_key','other'),('file','other.py'),('line',999),
 ('column',999),('callee_spelling','different'),('lexical_scope_id','other'),('execution_region',None)])
def test_issued_proof_cannot_be_rewired_to_different_site(tmp_path,field,value):
 r,_=run(tmp_path,POSITIVES[0]);node=next(n for n in r.graph.invocations.values() if n.established_targets)
 setattr(node,field,value)
 assert not node.established_targets


def test_issued_proof_cannot_be_rewired_to_different_body(tmp_path):
 r,_=run(tmp_path,POSITIVES[0]);node=next(n for n in r.graph.invocations.values() if n.established_targets)
 node.possible_implementations=(replace(node.possible_implementations[0],callable_key='unrelated'),)
 assert not node.established_targets


@pytest.mark.parametrize('file,source,classification',[
 ('app.py','def worker():\n    forbidden.signal()\ndef anchor():\n    pass\ndef entry(worker):\n    anchor()\n    worker()','LOCAL'),
 ('app.ts','function worker(){forbidden.signal()}function anchor(){}function entry(worker){anchor();worker()}','BOUNDED_LEXICAL'),
 ('app.go','package main\nfunc worker(){forbidden.signal()}\nfunc anchor(){}\nfunc entry(worker func()){anchor();worker()}','BOUNDED_LEXICAL'),
 ('app.py','def worker():\n    forbidden.signal()\ndef anchor():\n    pass\ndef entry(value):\n    selected=value\n    anchor()\n    selected()','LOCAL'),
 ('app.py','if condition:\n    def worker():\n        forbidden.signal()\ndef anchor():\n    pass\ndef entry():\n    anchor()\n    worker()','GLOBAL'),
])
def test_candidate_context_cannot_override_canonical_lexical_binding(tmp_path,monkeypatch,file,source,classification):
 captured=[];original=K.evaluate
 def record(**kw):
  captured.append(kw)
  return original(**kw)
 monkeypatch.setattr(K,'evaluate',record)
 (tmp_path/file).write_text(source)
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,'entry')],discover_roots=False)
 node=next(n for n in r.graph.invocations.values() if n.callee_spelling in {'worker','selected'})
 template=next(k for k in captured if k['context'].callee=='anchor')
 declaration=next(d for d in template['inventory'].declarations if d.binding=='worker')
 from actenon_scan.invocation_graph import stable_id
 ctx=replace(template['context'],subject=node.invocation_id,callee=node.callee_spelling,
     execution_region=node.execution_region.region_id,line=node.line,column=node.column,
     candidate=stable_id('candidate',declaration.callable_key),candidate_key=declaration.callable_key,
     candidate_namespace=declaration.namespace,candidate_kind=declaration.kind,
     steps=(K.ResolutionStep(K.ResolutionStepKind.DECLARATION,declaration.callable_key,'attempt'),
            K.ResolutionStep(K.ResolutionStepKind.LEXICAL_LOOKUP,declaration.namespace,'attempt'),
            K.ResolutionStep(K.ResolutionStepKind.LEXICAL_LOOKUP,node.lexical_scope_id,'attempt')))
 lookup=K.LookupObservation(node.lexical_scope_id,declaration.namespace,classification,
     template['lookup'].provenance+(f'compiler-reference:{node.callee_spelling}:{classification}',))
 proof=original(context=ctx,inventory=template['inventory'],lookup=lookup,
     candidates=(ctx.candidate,),counter_evidence=())
 assert not proof.authorizes(ctx.subject,ctx.candidate,ctx.evidence)

def test_call_site_cannot_be_invented_from_a_valid_inventory(tmp_path,monkeypatch):
 captured=[];original=K.evaluate
 def record(**kw):
  captured.append(kw);return original(**kw)
 monkeypatch.setattr(K,'evaluate',record)
 run(tmp_path,POSITIVES[0])
 kw=next(k for k in captured if k['context'].callee=='worker');ctx=kw['context']
 from actenon_scan.invocation_graph import stable_id
 ctx=replace(ctx,line=999,subject=stable_id('invocation',ctx.language,ctx.file,999,ctx.column,ctx.ordinal))
 p=original(**{**kw,'context':ctx})
 assert not p.authorizes(ctx.subject,ctx.candidate,ctx.evidence)

def test_suspended_target_activation_is_not_caller_counter_metadata(tmp_path,monkeypatch):
 captured=[];original=K.evaluate
 def record(**kw):
  captured.append(kw);return original(**kw)
 monkeypatch.setattr(K,'evaluate',record)
 (tmp_path/'app.py').write_text('async def worker():\n    forbidden.signal()\ndef entry():\n    worker()')
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint('app.py','entry')],discover_roots=False)
 assert not any(n.callee_spelling=='forbidden.signal' for n in r.graph.invocations.values())
 kw=next(k for k in captured if k['context'].callee=='worker')
 p=original(**{**kw,'counter_evidence':()});ctx=p.context
 assert not p.authorizes(ctx.subject,ctx.candidate,ctx.evidence)

@pytest.mark.parametrize('file,body',[
 ('app.py','class Unit:\n    def worker(self):\n        forbidden.signal()\n    def entry(self):\n        captured=self.listener\n        captured()\n        self.worker()'),
 ('app.ts','class Unit{worker(){forbidden.signal()}entry(){const captured=this.listener;captured();this.worker()}}'),
 ('app.ts','class Unit{worker(){forbidden.signal()}entry(){this["listener"]();this.worker()}}'),
])
def test_unknown_callable_capture_is_an_escape_without_explicit_arguments(tmp_path,file,body):
 (tmp_path/file).write_text(body)
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,'Unit.entry')],discover_roots=False)
 assert not r.analysis_errors and r.claims
 assert not any(n.callee_spelling=='forbidden.signal' for n in r.graph.invocations.values())
 assert r.graph.frontend_facts[file]['escape_events']

@pytest.mark.parametrize('field,value',[('owner_key','other'),('lexical_scope','other'),
 ('owner_exact',S.UNKNOWN)])
def test_actual_node_region_must_match_proof(tmp_path,field,value):
 r,_=run(tmp_path,POSITIVES[0]);node=next(n for n in r.graph.invocations.values() if n.established_targets)
 node.execution_region=replace(node.execution_region,**{field:value})
 assert not node.established_targets

def test_unknown_declaration_environment_is_file_scoped(tmp_path):
 for file in ('one.ts','two.ts'):
  (tmp_path/file).write_text('abstract class AbstractUnit { value: string; }')
 (tmp_path/'app.ts').write_text('function worker(){observed.signal()}function entry(){worker()}')
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint('app.ts','entry')],discover_roots=False)
 assert not r.analysis_errors
 assert not any(file=='semantic inventory' for file,_ in r.graph.coverage_gaps)
 assert any(n.callee_spelling=='observed.signal' for n in r.graph.invocations.values())
 environments=[e for facts in r.graph.frontend_facts.values() for e in facts['lexical_environments']]
 assert all(e['environment_id'] for e in environments)
 assert len({e['environment_id'] for e in environments})==len(environments)
