"""Audit pinned development R04 without opening other repositories.

Validate every retained proof structurally and inspect at least 25 source edges.
The serialized proof is evidence to check, not a way to issue new authority.
"""
from pathlib import Path
from collections import Counter,defaultdict
from hashlib import sha256
import argparse,json,subprocess
from actenon_scan import reachability_kernel as K
from actenon_scan.repository.ts_symbol_index import _parser_for
from actenon_scan.repository.semantic_frontends import classify_node
from actenon_scan.semantic_ir import EdgeObligation,SemanticState

PIN='1d7a16b25db74ed44539cd5079e2db46b42f08db'

def walk(node):
    yield node
    for child in node.named_children:yield from walk(child)

def diverse(nodes,count):
    buckets=defaultdict(list)
    for n in sorted(nodes,key=lambda n:(n['file'],n['line'])):buckets[n['file']].append(n)
    result=[]
    while len(result)<min(len(nodes),count):
        for file in sorted(buckets):
            if buckets[file]:result.append(buckets[file].pop(0))
            if len(result)==count:return result
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository',type=Path);parser.add_argument('claims',type=Path)
    parser.add_argument('output',type=Path);parser.add_argument('--parent',type=Path)
    args=parser.parse_args();root=args.repository.resolve()
    assert subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()==PIN
    r=json.loads(args.claims.read_text());facts=r['graph']['frontend_facts']
    nodes=r['graph']['invocations'];exact=[n for n in nodes if any(b['state']=='ESTABLISHED' for b in n['binding_claims'])]
    certificates={c['scope']:c for f in facts.values() for c in f['certificates']}
    environments={e['environment_id']:e for f in facts.values() for e in f['lexical_environments']}
    escapes=[e for f in facts.values() for e in f['escape_events']]
    trees={};checks={}
    def tree(file):
        if file not in trees:
            data=(root/file).read_bytes();trees[file]=(data,_parser_for(file).parse(data).root_node)
        return trees[file]
    def excerpt(file,line):
        lines=(root/file).read_text().splitlines()
        return '\n'.join(f'{i+1}: {lines[i]}' for i in range(max(0,line-3),min(len(lines),line+3)))
    for n in exact:
        bindings=[b for b in n['binding_claims'] if b['state']=='ESTABLISHED'];assert len(bindings)==1
        b=bindings[0];p=b['edge_proof'];raw=p['context']
        ctx=K.ResolutionContext(**{**raw,'evidence':frozenset(raw['evidence']),
            'binding_kinds':frozenset(raw['binding_kinds']),
            'steps':tuple(K.ResolutionStep(K.ResolutionStepKind(s['kind']),s['identity'],s['provenance']) for s in raw['steps'])})
        required=K.derive_required_obligations(ctx)
        assert required and {o.value for o in required}==set(p['required'])
        assert p['kernel_validated'] and not b['counter_evidence']
        assert all(p['obligations'][o.value]=='SUPPORTED' for o in required)
        assert (ctx.subject,ctx.language,ctx.file,ctx.line,ctx.column,ctx.owner,ctx.callee,ctx.environment)==(
            n['invocation_id'],n['language'],n['file'],n['line'],n['column'],n['caller_key'],n['callee_spelling'],n['lexical_scope_id'])
        region=n['execution_region'];assert region['mode']=='EAGER' and region['owner_exact']=='SUPPORTED'
        assert (region['region_id'],region['owner_key'],region['lexical_scope'])==(ctx.execution_region,ctx.owner,ctx.environment)
        target=[t for t in n['possible_implementations'] if t['candidate_id']==b['candidate']];assert len(target)==1
        target=target[0];assert (target['file'],target['callable_key'])==(ctx.candidate_file,ctx.candidate_key)
        source_digest=sha256((root/n['file']).read_text(encoding='utf-8-sig').encode()).hexdigest()
        witnesses=tuple(K.ProofWitness(EdgeObligation(w['obligation']),w['identity'],tuple(w['provenance']),
            w['source_digest'],w['policy'],SemanticState(w['state'])) for w in p['witnesses'])
        assert K._witnesses_valid(ctx,required,witnesses)
        assert all(w.source_digest==source_digest for w in witnesses)
        dependencies={ctx.environment,ctx.candidate_namespace}|{s.identity for s in ctx.steps if s.kind in {
            K.ResolutionStepKind.LEXICAL_LOOKUP,K.ResolutionStepKind.IMPORT_HOP,K.ResolutionStepKind.NAMESPACE_MEMBER,K.ResolutionStepKind.RECEIVER_DISPATCH}}
        relevant=[]
        for identity in dependencies:
            env=environments[identity];cert=certificates[identity]
            assert env['closure']=='SUPPORTED' and cert['facets']['lexical_writes_complete']=='SUPPORTED'
            assert cert['facets']['execution_semantics_complete']=='SUPPORTED'
            for event in escapes:
                if any(destination[1]==identity for destination in event['destinations']):
                    relevant.append(event)
                    opened=K.escape_facets(env['language'],env['construct_kind'])
                    assert 'lexical_writes_complete' not in opened or event['mutation']=='NON_MUTATING_PROVEN'
            writes=[w for f in facts.values() for w in f['write_events'] if w['scope']==identity]
            assert not any(w['target_kind']=='UNKNOWN_TARGET' for w in writes)
            assert not any(w['binding']==n['callee_spelling'] and w['operation'] in {'ASSIGN','DELETE','MAY_WRITE'} for w in writes)
            ledger=[b for f in facts.values() for b in f['binding_declarations'] if b['namespace']==identity]
            digest=sha256(json.dumps(sorted(ledger,key=lambda b:json.dumps(b,sort_keys=True)),sort_keys=True).encode()).hexdigest()
            assert 'binding-ledger:'+digest in p['provenance']
        assert any(x.startswith('write-ledger:') for x in p['provenance'])
        assert any(x.startswith('escape-ledger:') for x in p['provenance'])
        assert any(x.startswith('binding-ledger:') for x in p['provenance'])
        declarations=[b for f in facts.values() for b in f['binding_declarations'] if
            b['namespace']==ctx.candidate_namespace and b['name']==n['callee_spelling']]
        assert len(declarations)==1 and declarations[0]['callable_key']==ctx.candidate_key
        assert not declarations[0]['conditional'] and not declarations[0]['counter_evidence']
        checks[n['invocation_id']]={'id':n['invocation_id'],'file':n['file'],'line':n['line'],'callee':n['callee_spelling'],
            'target':target,'required':sorted(o.value for o in required),'resolution_path':raw['steps'],
            'witnesses':[w.to_dict() for w in witnesses if w.obligation in required],
            'dependent_environments':sorted(dependencies),'escape_events':len(relevant),'audit':'all derived obligations and closure witnesses validated'}
    selected=[]
    for n in diverse(exact,25):
        rec=checks[n['invocation_id']];data,syntax=tree(n['file'])
        calls=[c for c in walk(syntax) if c.type=='call_expression' and
            (c.start_point[0]+1,c.start_point[1]+1)==(n['line'],n['column']) and
            c.child_by_field_name('function') and
            data[c.child_by_field_name('function').start_byte:c.child_by_field_name('function').end_byte].decode()==n['callee_spelling']]
        assert len(calls)==1,(n['file'],n['line'],n['column'],n['callee_spelling'])
        call=calls[0];parent=call
        while parent:
            assert classify_node('typescript',parent.type)!='CONSERVATIVELY_UNKNOWN'
            parent=parent.parent
        target=rec['target'];target_data,target_syntax=tree(target['file']);leaf=target['symbol'].split('.')[-1]
        declarations=[c for c in walk(target_syntax) if c.type=='function_declaration' and c.child_by_field_name('name') and
            target_data[c.child_by_field_name('name').start_byte:c.child_by_field_name('name').end_byte].decode()==leaf]
        assert len(declarations)==1 and declarations[0].start_point[0]+1==target['line']
        assert target['file']==n['file'] and leaf==n['callee_spelling']
        parent=call
        while parent and parent.type not in {'function_declaration','arrow_function','function_expression','method_definition'}:parent=parent.parent
        if parent:
            for syntax_node in walk(parent):
                if syntax_node.type in {'required_parameter','optional_parameter','variable_declarator'}:
                    binding=syntax_node.child_by_field_name('name') or syntax_node.child_by_field_name('pattern')
                    assert not binding or data[binding.start_byte:binding.end_byte].decode()!=leaf
        rec.update(call_context=excerpt(n['file'],n['line']),target_context=excerpt(target['file'],target['line']))
        selected.append(rec)
    gaps=r['coverage_gaps'];assert all((root/file).is_file() and reason for file,reason in gaps)
    assert len(gaps)==len(set(map(tuple,gaps)))
    reasons=Counter(reason for _,reason in gaps);added=[]
    if args.parent:
        parent=json.loads(args.parent.read_text());prior=set(map(tuple,parent['coverage_gaps']))
        added=[g for g in gaps if tuple(g) not in prior]
    summary={'commit':PIN,'coverage':r['coverage'],'all_retained_proofs_checked':len(exact),
        'source_edges_audited':len(selected),'distinct_targets_audited':len({e['target']['candidate_id'] for e in selected}),
        'gap_count':len(gaps),'unique_gaps':len(set(map(tuple,gaps))),'gap_reasons':dict(reasons),
        'added_gap_classes':dict(Counter('escape' if 'escaped' in reason else 'escape_bound' if 'escape identity resolution bound' in reason else 'other' for _,reason in added)),
        'retained_audit':selected}
    assert len(selected)>=25
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in {'retained_audit','gap_reasons'}},indent=2))

if __name__=='__main__':main()
