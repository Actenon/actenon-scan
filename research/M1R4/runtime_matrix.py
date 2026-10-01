"""Deterministic M1R4 scope/escape differential; runtime is a fixture oracle only.

The output directory is outside the checkout. No repository data is acquired.
Each fixture has definite before-call substitution or unconsumed deferred code.
"""
from pathlib import Path
from itertools import product
from hashlib import sha256
import argparse,builtins,json,os,re,shutil,subprocess,sys,tempfile
from actenon_scan import Entrypoint,RootKind,scan_effect_claims

def indent(text):return '\n'.join('    '+l if l else '' for l in text.splitlines())

def comprehension(mode,expression,scope,alias,control):
 files={};header='def old_body():\n    old_probe.signal()\n    return (0,)\n'
 if mode=='global':header+='def helper():\n    live_probe.signal()\n    return (0,)\n';setup=''
 elif mode=='closure':setup='def helper():\n    live_probe.signal()\n    return (0,)\n'
 else:
  files['support.py']='def helper():\n    live_probe.signal()\n    return (0,)\n'
  if mode=='relay':files['relay.py']='from support import helper as original\nhelper=original\n'
  header+='from '+('relay' if mode=='relay' else 'support')+' import helper\n';setup=''
 expr={'list':'[helper() for value in (0,)]','set':'{helper() for value in (0,)}','dict':'{value:helper() for value in (0,)}',
  'filter':'[value for value in (0,) if helper()]','nested':'[[helper() for inner in (0,)] for outer in (0,)]',
  'generator':'(helper() for value in (0,))','outer':'[value for value in helper()]'}[expression]
 member='helper=old_body' if alias else 'def helper():\n    old_probe.signal()\n    return (0,)'
 block='values='+expr
 if control=='conditional':block='if True:\n'+indent(block)
 elif control=='loop':block='for once in (0,):\n'+indent(block)
 body=setup+'class Chamber:\n'+indent(member+'\n'+block)
 if scope=='nested':body='def activate():\n'+indent(body)+'\nactivate()'
 elif scope=='delegate':header+='def activate():\n'+indent(body)+'\n';body='activate()'
 elif scope=='lambda_wrapper':body='def activate():\n'+indent(body)+'\nselected=activate\nselected()'
 files['program.py']=header+'def entry():\n'+indent(body)+'\n'
 return files,'program.py','entry',expression=='outer'

def py_mutation(namespace,operation,capture,scope,alias,conditional):
 files={};header='def replacement(*args):\n    live_probe.signal()\n'
 if namespace=='receiver':
  target='self' if operation=='setattr' else 'Unit';receiver='receiver'
  start='receiver='+target+'\n' if alias else '';target=receiver if alias else target
  suffix='self.route()';symbol='Unit.entry'
 else:
  module='support' if namespace=='module' else 'pkg.support'
  files[('support.py' if namespace=='module' else 'pkg/support.py')]='def route():\n    old_probe.signal()\n'
  if namespace=='deep_module':files['pkg/__init__.py']=''
  header+='import '+module+'\n';target='receiver' if alias else module
  start='receiver='+module+'\n' if alias else '';suffix=module+'.route()';symbol='entry'
 declaration={'direct':'','captured':'mutator='+operation+'\n','chain':'first='+operation+'\nmutator=first\n',
  'nested_chain':'first='+operation+'\nsecond=first\nmutator=second\n'}[capture]
 func=operation if capture=='direct' else 'mutator'
 call=func+'(destination,"route"'+(',replacement' if operation=='setattr' else '')+')'
 if conditional:call='if True:\n'+indent(call)
 if scope=='nested':operation_body='def replace_target(destination):\n'+indent(call)+'\nreplace_target('+target+')'
 else:
  operation_body=call.replace('destination',target)
  if scope=='block':operation_body='for once in (0,):\n'+indent(operation_body)
 body=start+declaration+operation_body+'\n'+suffix
 if namespace=='receiver':source=header+'class Unit:\n    def route(self):\n        old_probe.signal()\n    def entry(self):\n'+indent(indent(body))+'\n'
 else:source=header+'def entry():\n'+indent(body)+'\n'
 files['program.py']=source
 return files,'program.py',symbol,False

def js_mutation(operation,capture,scope,alias,control,container):
 intrinsic={'assign':'Object.assign','define':'Object.defineProperty','set':'Reflect.set','delete':'Reflect.deleteProperty','prototype':'Object.setPrototypeOf'}[operation]
 base,member=intrinsic.split('.')
 declaration={'direct':'','captured':'const mutator='+intrinsic+';','chain':'const first='+intrinsic+';const mutator=first;',
  'destructured':'const {'+member+':mutator}='+base+';',
  'long_chain':'const first='+intrinsic+';const second=first;const mutator=second;'}[capture]
 func=intrinsic if capture=='direct' else 'mutator'
 target='this' if container=='instance' else 'Unit.prototype'
 before='const receiver='+target+';' if alias else '';target='receiver' if alias else target
 dest='destination' if scope=='nested' else target
 call={'assign':func+'('+dest+',{route(){live_probe.signal()}})',
  'define':func+'('+dest+',"route",{value:()=>live_probe.signal()})',
  'set':func+'('+dest+',"route",()=>live_probe.signal())',
  'delete':func+'('+dest+',"route")',
  'prototype':func+'('+dest+',{route(){live_probe.signal()}})'}[operation]
 if control=='if':call='if(true){'+call+';}'
 elif control=='logical':call='true&&'+call+';'
 elif control=='loop':call='for(const once of [1]){'+call+';}'
 else:call+=';'
 if scope=='nested':call='function replaceTarget(destination){'+call+'}replaceTarget('+target+');'
 elif scope=='block':call='{'+call+'}'
 # Deleting an absent instance property doesn't suppress the prototype body.
 # Use a prototype destination for deletion; prototype replacement of a
 # prototype itself also leaves its own route intact and is a positive oracle.
 expected=(operation=='delete' and container=='instance') or (operation=='prototype' and container=='prototype')
 source=declaration+'class Unit{route(){old_probe.signal()}entry(){'+before+call+'this.route();}}'
 return {'program.js':source},'program.js','Unit.entry',expected

def go_store(write,scope,alias,control):
 header='package main\nfunc previous(){old_probe.signal()}\nfunc replacement(){live_probe.signal()}\nfunc values()(func(),int){return replacement,2}\n'
 declaration='selected:=previous;' if not alias else 'original:=previous;selected:=original;'
 if scope=='package':header+=declaration.replace(':=','=').replace('original=','var original=').replace('selected=','var selected=').replace(';','\n');declaration=''
 mutation={'assign':'selected=replacement;','multiple':'extra:=0;selected,extra=replacement,1;_ =extra;',
  'return':'selected,_=values();','range':'for _,selected=range []func(){replacement}{};',
  'receive':'channel:=make(chan func(),1);channel<-replacement;select{case selected=<-channel:};',
  'mixed':'selected,extra:=replacement,1;_ =extra;'}[write]
 if control:mutation='if true{'+mutation+'selected();};';ending=''
 else:ending='selected();'
 body=declaration+mutation+ending+'_ =selected;'
 if scope=='nested':body=declaration+'stage:=func(){'+mutation+ending+'};stage();_ =selected;'
 return {'program.go':header+'func entry(){'+body+'}'},'program.go','entry',False

def programs():
 for d in product(['global','closure','import','relay'],['list','set','dict','filter','nested','generator','outer'],['entry','nested','delegate','lambda_wrapper'],[False,True],['plain','conditional','loop']):
  yield 'python','comprehension',d,comprehension(*d)
 for d in product(['receiver','module','deep_module'],['setattr','delattr'],['direct','captured','chain','nested_chain'],['plain','nested','block'],[False,True],[False,True]):
  yield 'python','escape',d,py_mutation(*d)
 for d in product(['assign','define','set','delete','prototype'],['direct','captured','chain','destructured','long_chain'],['plain','block','nested'],[False,True],['plain','if','logical','loop'],['instance','prototype']):
  yield 'javascript','escape',d,js_mutation(*d)
 for d in product(['assign','multiple','return','range','receive','mixed'],['entry','package','nested'],[False,True],[False,True]):
  yield 'go','write',d,go_store(*d)

class Probe:
 def __init__(self,trace,name):self.trace,self.name=trace,name
 def signal(self):self.trace.append(self.name);return (0,)

def execute_python(src,source,symbol,extra):
 trace=[];builtins.old_probe=Probe(trace,'old');builtins.live_probe=Probe(trace,'live')
 for name in list(sys.modules):
  if name in {'support','relay','pkg'} or name.startswith('pkg.'):sys.modules.pop(name,None)
 sys.path.insert(0,str(src));environment={'__name__':'runtime_fixture'}
 try:
  exec(compile(source,str(src/'program.py'),'exec'),environment)
  try:
   if '.' in symbol: cls,member=symbol.split('.');getattr(environment[cls](),member)()
   else:environment['entry']()
  except AttributeError:pass # deletion fixtures terminate at the missing member
 finally:
  sys.path.pop(0)
  for name in list(sys.modules):
   if name in {'support','relay','pkg'} or name.startswith('pkg.'):sys.modules.pop(name,None)
 return trace

def main():
 parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
 rows=[];go=[]
 for i,(language,family,d,(files,file,symbol,expected)) in enumerate(programs()):
  folder=out/f'case-{i:04d}';src=folder/'source';src.mkdir(parents=True,exist_ok=True)
  for name,source in files.items():p=src/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(source)
  root=list(RootKind)[i%4]
  r=scan_effect_claims(src,entrypoints=[Entrypoint(file,symbol,root)],discover_roots=False)
  if r.analysis_errors:raise AssertionError((i,d,r.analysis_errors))
  reached=any(n.callee_spelling=='old_probe.signal' for n in r.graph.invocations.values())
  row={'id':i,'language':language,'family':family,'dimensions':d,'root':root.value,'source_hash':sha256(json.dumps(files,sort_keys=True).encode()).hexdigest(),
    'expected_old':expected,'scanner_old':reached,'false_established':reached and not expected,'false_unresolved':expected and not reached,
    'claims':len(r.claims),'gaps':len(r.graph.coverage_gaps)}
  if language=='python':row['trace']=execute_python(src,files[file],symbol,files)
  elif language=='javascript':
   oracle=folder/'oracle.cjs';oracle.write_text('const trace=[];const old_probe={signal(){trace.push("old")}};const live_probe={signal(){trace.push("live")}};'+files[file]+';try{new Unit().entry()}catch(e){if(!(e instanceof TypeError))throw e};console.log(JSON.stringify(trace));')
   run=subprocess.run(['node',str(oracle)],text=True,capture_output=True,check=True);row['trace']=json.loads(run.stdout)
  else:go.append((i,files[file],row))
  if row['false_established']:(folder/'false-edge.json').write_text(json.dumps(r.to_dict(),indent=2))
  rows.append(row)
 batch=out/'go-oracle';batch.mkdir(exist_ok=True);entries=[];tokens={'previous','replacement','values','original','entry','selected','old_probe','live_probe'}
 for i,source,row in go:
  prefix=f'case{i}_';source=re.sub(r'\b[A-Za-z_]\w*\b',lambda m:prefix+m[0] if m[0] in tokens else m[0],source)
  (batch/f'case{i}.go').write_text(source+'\nvar '+prefix+'old_probe=probe{"old"}\nvar '+prefix+'live_probe=probe{"live"}')
  entries.append('trace=[]string{};'+prefix+'entry();outputs=append(outputs,trace)')
 (batch/'main.go').write_text('package main\nimport("encoding/json";"os")\nvar trace []string\ntype probe struct{label string}\nfunc(p probe)signal(){trace=append(trace,p.label)}\nfunc main(){outputs:=[][]string{};'+ ';'.join(entries)+';json.NewEncoder(os.Stdout).Encode(outputs)}')
 run=subprocess.run(['go','run','.'],cwd=batch,env={**os.environ,'GO111MODULE':'off','GOCACHE':str(out/'go-cache')},text=True,capture_output=True)
 if run.returncode:raise AssertionError(run.stderr)
 for (_,_,row),trace in zip(go,json.loads(run.stdout),strict=True):row['trace']=trace
 for row in rows:
  if ('old' in row['trace'])!=row['expected_old']:raise AssertionError(('invalid oracle',row))
 summary={'programs':len(rows),'unique_programs':len({r['source_hash'] for r in rows}),'runtime_programs':len(rows),
  'false_established':sum(r['false_established'] for r in rows),'false_unresolved':sum(r['false_unresolved'] for r in rows),
  'languages':{l:sum(r['language']==l for r in rows) for l in ['python','javascript','go']},'cases':rows}
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({k:v for k,v in summary.items() if k!='cases'},indent=2),flush=True)
 if summary['false_established']:raise SystemExit(1)
if __name__=='__main__':main()
