"""Compiler/runtime differentials: containment is not the lookup environment."""
import ast,symtable,asyncio,builtins,sys,types
from itertools import product
import pytest
from actenon_scan import Entrypoint,RootKind,scan_effect_claims

SCOPES=['module','function','nested_function','class','class_in_function','function_in_class',
 'comprehension_in_class','comprehension_in_function','nested_comprehension','lambda','generator','async']

def source(kind,mode):
 header='def target():\n    live_probe.signal()\n    return (1,)\n'
 binding='target'
 if mode=='import':header='from support import target\n'
 elif mode=='alias':header+='captured=target\n';binding='captured'
 expression=binding+'()'
 if kind=='module':body=expression
 elif kind=='function':body='def active():\n    '+expression+'\nactive()'
 elif kind=='nested_function':body='def active():\n    def deeper():\n        '+expression+'\n    deeper()\nactive()'
 elif kind=='class':body='class Container:\n    '+expression
 elif kind=='class_in_function':body='def active():\n    class Container:\n        '+expression+'\nactive()'
 elif kind=='function_in_class':body='class Container:\n    def target():\n        old_probe.signal()\n    def active(self):\n        '+expression+'\nContainer().active()'
 elif kind=='comprehension_in_class':body='class Container:\n    '+binding+'=lambda: old_probe.signal()\n    result=['+expression+' for index in (0,)]'
 elif kind=='comprehension_in_function':body='def active():\n    result=['+expression+' for index in (0,)]\nactive()'
 elif kind=='nested_comprehension':body='class Container:\n    '+binding+'=lambda: old_probe.signal()\n    result=[['+expression+' for inner in (0,)] for outer in (0,)]'
 elif kind=='lambda':body='stored=lambda: '+expression+'\nstored()'
 elif kind=='generator':body='def suspended():\n    yield '+expression+'\nstored=suspended()'
 else:body='async def active():\n    '+expression+'\nreturn active()'
 return header+'def entry():\n'+'\n'.join('    '+line for line in body.splitlines())+'\n'

@pytest.mark.parametrize('kind,mode,root',list(product(SCOPES,['local','alias','import'],list(RootKind))))
def test_compiler_scope_differential(tmp_path,kind,mode,root,monkeypatch):
 text=source(kind,mode);(tmp_path/'app.py').write_text(text)
 (tmp_path/'support.py').write_text('def target():\n    live_probe.signal()\n    return (1,)\n')
 table=symtable.symtable(text,'app.py','exec')
 assert table.get_name()=='top'
 trace=[]
 class Probe:
  def __init__(self,name):self.name=name
  def signal(self):trace.append(self.name);return (1,)
 monkeypatch.setattr(builtins,'live_probe',Probe('live'),raising=False)
 monkeypatch.setattr(builtins,'old_probe',Probe('old'),raising=False)
 support=types.ModuleType('support')
 exec(compile((tmp_path/'support.py').read_text(),'support.py','exec'),support.__dict__)
 monkeypatch.setitem(sys.modules,'support',support)
 runtime={};exec(compile(text,'app.py','exec'),runtime)
 returned=runtime['entry']()
 if kind=='async':asyncio.run(returned)
 assert 'old' not in trace
 if kind=='generator':assert not trace
 else:assert 'live' in trace

 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint('app.py','entry',root)],discover_roots=False)
 assert not r.analysis_errors
 assert not any(n.callee_spelling=='old_probe.signal' for n in r.graph.invocations.values())
 # All compiler-authenticated witnesses name their compiler block and reference.
 for n in r.graph.invocations.values():
  for b in n.binding_claims:
   if b.state.value!='ESTABLISHED':continue
   proof=b.edge_proof.to_dict()
   witness=next(w for w in proof['witnesses'] if w['obligation']=='LEXICAL_ENVIRONMENT_EXACT')
   assert any('symtable' in p for p in witness['provenance'])
   assert any(p.startswith('compiler-reference:') for p in witness['provenance'])
   assert proof['kernel_validated']
 envs=r.graph.frontend_facts['app.py']['lexical_environments']
 for env in envs:
  if env['construct_kind']=='comprehension':
   parent=next((e for e in envs if e['environment_id']==env['lookup_parent']),None)
   assert parent is None or parent['construct_kind']!='class'
