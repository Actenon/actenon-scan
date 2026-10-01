"""M1R4 invariants 14--18, in addition to the inherited thirteen."""
from dataclasses import replace
import pytest
from actenon_scan import Entrypoint,RootKind,scan_effect_claims
from actenon_scan import reachability_kernel as K
from actenon_scan.semantic_ir import EdgeObligation as O,SemanticState as S
from test_m1r4_kernel import POSITIVES,run

@pytest.mark.parametrize('root',list(RootKind))
@pytest.mark.parametrize('language',['python','typescript'])
def test_escape_monotonicity(tmp_path,root,language):
 if language=='python':
  file='app.py';stable='class Unit:\n    def worker(self):\n        marker.signal()\n    def entry(self):\n        self.worker()';altered=stable.replace('        self.worker()','        opaque(self)\n        self.worker()')
 else:
  file='app.ts';stable='class Unit{worker(){marker.signal()}entry(){this.worker()}}';altered=stable.replace('this.worker()','opaque(this);this.worker()')
 def scan(source):
  (tmp_path/file).write_text(source)
  return scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,'Unit.entry',root)],discover_roots=False)
 before=scan(stable);after=scan(altered)
 assert any(n.callee_spelling=='marker.signal' for n in before.graph.invocations.values())
 assert not any(n.callee_spelling=='marker.signal' for n in after.graph.invocations.values())
 edge=next(n for n in after.graph.invocations.values() if n.callee_spelling.endswith('.worker'))
 assert not edge.established_targets and edge.root_ids and after.claims
 assert any(b.edge_proof.state(O.WRITE_SET_CLOSED)==S.UNKNOWN for b in edge.binding_claims if b.candidate_is_local)
 assert after.graph.coverage_gaps

@pytest.mark.parametrize('language',['python','typescript'])
def test_alias_invariant_mutation(tmp_path,language):
 if language=='python':
  file='app.py';prefix='class Unit:\n    def worker(self):\n        forbidden.signal()\n    def entry(self):\n';direct=prefix+'        setattr(self,"worker",fresh)\n        self.worker()';alias=prefix+'        captured=setattr\n        further=captured\n        further(self,"worker",fresh)\n        self.worker()'
 else:
  file='app.ts';prefix='class Unit{worker(){forbidden.signal()}entry(){';direct=prefix+'Object.assign(this,{worker:fresh});this.worker()}}';alias=prefix+'const captured=Object.assign;const further=captured;further(this,{worker:fresh});this.worker()}}'
 for source in (direct,alias):
  (tmp_path/file).write_text(source)
  r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,'Unit.entry')],discover_roots=False)
  assert not any(n.callee_spelling=='forbidden.signal' for n in r.graph.invocations.values())
  assert any(e['capabilities']==('MEMBER_MUTATION',) for e in r.graph.frontend_facts[file]['escape_events'])
  edge=next(n for n in r.graph.invocations.values() if n.callee_spelling.endswith('.worker'))
  assert not edge.established_targets


def test_lexical_environment_soundness(tmp_path):
 header='def worker():\n    live.signal()\n    return 1\ndef previous():\n    forbidden.signal()\n    return 1\n'
 def scan(body):
  (tmp_path/'app.py').write_text(header+'def entry():\n'+body)
  return scan_effect_claims(tmp_path,entrypoints=[Entrypoint('app.py','entry')],discover_roots=False)
 before=scan('    result=[worker() for value in (1,)]\n')
 after=scan('    class Local:\n        worker=previous\n        result=[worker() for value in (1,)]\n')
 assert any(n.callee_spelling=='live.signal' for n in before.graph.invocations.values())
 assert not any(n.callee_spelling=='forbidden.signal' for n in after.graph.invocations.values())
 edge=next(n for n in after.graph.invocations.values() if n.callee_spelling=='worker')
 envs=after.graph.frontend_facts['app.py']['lexical_environments']
 env=next(e for e in envs if e['environment_id']==edge.lexical_scope_id)
 assert env['construct_kind']=='comprehension'
 parent=next(e for e in envs if e['environment_id']==env['lookup_parent'])
 assert parent['construct_kind']!='class'
 assert edge.root_ids and after.claims


def test_resolution_path_monotonicity(tmp_path):
 _,b=run(tmp_path,POSITIVES[0]);ctx=b.edge_proof.context
 derived=K.derive_required_obligations(ctx)
 for kinds in [(K.ResolutionStepKind.IMPORT_HOP,),(K.ResolutionStepKind.RECEIVER_DISPATCH,),
               (K.ResolutionStepKind.IMPORT_HOP,K.ResolutionStepKind.RECEIVER_DISPATCH)]:
  changed=replace(ctx,steps=ctx.steps+tuple(K.ResolutionStep(k,ctx.environment,'observation') for k in kinds))
  assert derived <= K.derive_required_obligations(changed)
  if K.ResolutionStepKind.IMPORT_HOP in kinds:assert O.IMPORT_PROVENANCE_EXACT in K.derive_required_obligations(changed)
  if K.ResolutionStepKind.RECEIVER_DISPATCH in kinds:assert O.RECEIVER_COMPATIBLE in K.derive_required_obligations(changed)
