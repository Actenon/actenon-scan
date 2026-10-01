"""Execute the semantic matrix with Python, Node, and a namespaced Go batch.

Every Go input is its own valid program fragment. Namespacing batches compilation
only; each entrypoint runs independently with its own reset trace. Runtime traces
are used for definite replacement/deferred scenarios, never unknown branches.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from hashlib import sha256
from actenon_scan import Entrypoint, RootKind, scan_effect_claims


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    root=Path(__file__).resolve().parents[1]
    spec=importlib.util.spec_from_file_location('semantic_matrix',root/'tests/test_m1r3_generated.py')
    matrix=importlib.util.module_from_spec(spec);spec.loader.exec_module(matrix)
    rows=[];go=[]
    for i,case in enumerate(matrix.CASES):
        file,source,symbol,expected=matrix.program(case)
        folder=out/f'case-{i:04d}';folder.mkdir(exist_ok=True);(folder/file).write_text(source)
        kind=list(RootKind)[i%len(RootKind)]
        result=scan_effect_claims(folder,entrypoints=[Entrypoint(file,symbol,kind)],discover_roots=False)
        if result.analysis_errors:raise AssertionError((case,result.analysis_errors))
        old=any(c.callee_spelling=='old_probe.signal' for c in result.graph.invocations.values())
        row={'case':case,'root_kind':kind.value,'source_sha256':sha256(source.encode()).hexdigest(),'expected_old':expected,
             'scanner_reaches_old':old,'false_established':old and not expected,
             'false_unresolved':expected and not old,'coverage':result.coverage}
        rows.append(row)
        if case[0]=='python':
            trace=[]
            class Probe:
                def __init__(self,label):self.label=label
                def signal(self):trace.append(self.label)
            env={'old_probe':Probe('old'),'live_probe':Probe('live')}
            exec(compile(source,file,'exec'),env)
            try:
                if symbol=='Receiver.entry':env['Receiver']().entry()
                else:env['entry']()
            except (TypeError,UnboundLocalError,NameError,AttributeError):pass
            row['runtime_trace']=trace
        elif case[0]=='typescript':
            runtime=folder/'runtime.cjs'
            invocation='new Receiver().entry()' if symbol=='Receiver.entry' else 'entry()'
            runtime.write_text("let trace=[];let old_probe={signal(){trace.push('old')}};let live_probe={signal(){trace.push('live')}};\n"+source+"\ntry{"+invocation+"}catch(e){if(!(e instanceof TypeError))throw e}console.log(JSON.stringify(trace));")
            completed=subprocess.run([shutil.which('node'),str(runtime)],capture_output=True,text=True,check=True)
            row['runtime_trace']=json.loads(completed.stdout)
        else:go.append((i,source,symbol,row))
    batch=out/'go-runtime';batch.mkdir(exist_ok=True)
    entries=[]
    tokens={'original','live','selected','alias','entry','keep','old_probe','live_probe','Receiver','route'}
    for i,source,symbol,row in go:
        prefix=f'c{i}_'
        converted=re.sub(r'\b[A-Za-z_]\w*\b',lambda m:prefix+m.group() if m.group() in tokens else m.group(),source)
        (batch/f'case_{i}.go').write_text(converted+f'\nvar {prefix}old_probe=probe{{"old"}}\nvar {prefix}live_probe=probe{{"live"}}\n')
        invocation=f'({prefix}Receiver{{}}).{prefix}entry()' if symbol=='Receiver.entry' else f'{prefix}entry()'
        entries.append(f'trace=[]string{{}};{invocation};outputs=append(outputs,trace)')
    (batch/'main.go').write_text('package main\nimport("encoding/json";"os")\nvar trace []string\ntype probe struct{label string}\nfunc(p probe)signal(){trace=append(trace,p.label)}\nfunc main(){outputs:=[][]string{};'+ ';'.join(entries)+';json.NewEncoder(os.Stdout).Encode(outputs)}')
    env={**os.environ,'GO111MODULE':'off','GOCACHE':str(out/'go-cache')}
    completed=subprocess.run([shutil.which('go'),'run','.'],cwd=batch,env=env,capture_output=True,text=True,check=True)
    traces=json.loads(completed.stdout)
    for (_,_,_,row),trace in zip(go,traces,strict=True):row['runtime_trace']=trace
    for row in rows:
        if ('old' in row['runtime_trace'])!=row['expected_old']:raise AssertionError(('invalid oracle',row))
    summary={'programs':len(rows),'unique_source_hashes':len({r['source_sha256'] for r in rows}),
        'runtime_differential_programs':len(rows),'invalid_oracles':0,
        'false_established':sum(r['false_established'] for r in rows),
        'false_unresolved':sum(r['false_unresolved'] for r in rows),
        'languages':{l:sum(r['case'][0]==l for r in rows) for l in matrix.CONTEXTS},'cases':rows}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='cases'},indent=2))
    if summary['false_established']:raise SystemExit(1)


if __name__=='__main__':main()
