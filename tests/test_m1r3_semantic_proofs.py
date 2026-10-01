"""Authority requires closure, not an empty collection of observed writes."""
from itertools import product
import ast
import pytest

from actenon_scan import Entrypoint, RootKind, scan_effect_claims
from actenon_scan.binding_claims import BindingClaim, BindingEvidence as E, BindingState
from actenon_scan.semantic_ir import (BindingEdgeProof, EdgeObligation as O,
    BASE_OBLIGATIONS, SemanticState as S)
from actenon_scan.repository.semantic_frontends import classify_node


def proof(**changes):
    facts = {k: S.SUPPORTED for k in O}
    facts.update({O(k): S(v) for k, v in changes.items()})
    return BindingEdgeProof(frozenset(O), tuple(facts.items()), ("test-audited-scope",))


def scan(tmp_path, source, file="app.py", symbol="entry"):
    (tmp_path/file).write_text(source)
    r = scan_effect_claims(tmp_path, entrypoints=[Entrypoint(file, symbol)], discover_roots=False)
    assert not r.analysis_errors
    return r


def calls(r, name):
    return [c for c in r.graph.invocations.values() if c.callee_spelling == name]


def test_positive_facts_without_certificate_are_not_authority():
    b = BindingClaim("site", "body", frozenset({E.LEXICAL_DECLARATION}), candidate_is_local=True)
    assert b.state == BindingState.POSSIBLE
    assert not b.edge_proof.closed


@pytest.mark.parametrize("obligation,state", list(product(O, [S.UNKNOWN, S.REFUTED])))
def test_each_required_unknown_or_refutation_blocks_establishment(obligation, state):
    p = proof(**{obligation.value: state})
    b = BindingClaim("site", "body", frozenset({E.LEXICAL_DECLARATION}), candidate_is_local=True, edge_proof=p)
    assert b.state == (BindingState.REFUTED if state == S.REFUTED else BindingState.POSSIBLE)
    supported = proof()
    assert not p.accumulate(supported).closed
    assert p.accumulate(supported).state(obligation) == state


@pytest.mark.parametrize("counter", [e for e in E if e not in {E.LEXICAL_DECLARATION,
    E.IMPORT_PROVENANCE, E.RECEIVER_IDENTITY, E.CALLABLE_SELF_BINDING, E.STRUCTURALLY_EXACT_ALIAS}])
def test_counter_facts_survive_complete_proofs(counter):
    b = BindingClaim("site", "body", frozenset({E.LEXICAL_DECLARATION}), candidate_is_local=True, edge_proof=proof())
    assert b.state == BindingState.ESTABLISHED
    b = b.with_evidence(counter={counter})
    assert b.with_evidence(positive={E.IMPORT_PROVENANCE}).state != BindingState.ESTABLISHED
    assert counter in b.counter_evidence


@pytest.mark.parametrize("file,source,symbol", [
    ("app.py", "def helper():\n    marker.hit()\ndef entry():\n    helper()", "entry"),
    ("app.py", "class S:\n    def helper(self):\n        marker.hit()\n    def entry(self):\n        self.helper()", "S.entry"),
    ("app.ts", "function helper(){marker.hit()}function entry(){helper()}", "entry"),
    ("app.ts", "class S{helper(){marker.hit()}entry(){this.helper()}}", "S.entry"),
    ("app.go", "package main\nfunc helper(){marker.hit()}\nfunc entry(){helper()}", "entry"),
    ("app.go", "package main\nfunc entry(){helper:=func(){marker.hit()};helper()}", "entry"),
    ("app.go", "package main\ntype S struct{}\nfunc(s *S) helper(){marker.hit()}\nfunc(s *S) entry(){s.helper()}", "S.entry"),
])
def test_every_established_edge_carries_required_closure(tmp_path,file,source,symbol):
    r = scan(tmp_path,source,file,symbol)
    assert calls(r, "marker.hit")
    established = [b for c in r.graph.invocations.values() for b in c.binding_claims if b.state == BindingState.ESTABLISHED]
    assert established
    for b in established:
        assert BASE_OBLIGATIONS <= b.edge_proof.required
        assert b.edge_proof.closed and b.edge_proof.provenance
        assert not b.counter_evidence


@pytest.mark.parametrize("file,source,unknown", [
    ("app.py", "def helper():\n    marker.hit()\ndef entry():\n    exec('helper = opaque')\n    helper()", "dynamic Python namespace operation"),
    ("app.ts", "function helper(){marker.hit()}function entry(){eval('helper = opaque');helper()}", "dynamic JavaScript namespace operation"),
    ("app.ts", "function helper(){marker.hit()}function entry(){enum Hidden{A=0}helper()}", "unclassified semantic syntax: enum_declaration"),
])
def test_semantic_closure_monotonicity(tmp_path,file,source,unknown):
    r = scan(tmp_path,source,file)
    assert calls(r,"helper") and not calls(r,"marker.hit")
    local = [b for b in calls(r,"helper")[0].binding_claims if b.candidate_is_local]
    assert local and all(b.edge_proof.state(O.WRITE_SET_CLOSED) == S.UNKNOWN for b in local)
    assert any(unknown in reason for _,reason in r.graph.coverage_gaps)


def test_future_parser_node_defaults_unknown(tmp_path,monkeypatch):
    from actenon_scan.repository import invocation_adapters as adapters
    real = adapters.ast.parse
    class FutureStatement(ast.stmt):
        _fields = ()
    def parse(*args, **kwargs):
        tree = real(*args, **kwargs)
        tree.body[-1].body.insert(0, FutureStatement())
        return tree
    monkeypatch.setattr(adapters.ast,"parse",parse)
    r = scan(tmp_path,"def helper():\n    marker.hit()\ndef entry():\n    helper()")
    assert classify_node("python","FutureStatement") == "CONSERVATIVELY_UNKNOWN"
    assert calls(r,"helper") and not calls(r,"marker.hit")
    assert any("FutureStatement" in reason for _,reason in r.graph.coverage_gaps)


def test_unknown_execution_construct_has_separate_owner(tmp_path,monkeypatch):
    from actenon_scan.repository import invocation_adapters as adapters
    real = adapters.ast.parse
    class FutureContainer(ast.stmt):
        _fields = ('body',)
    def parse(*args, **kwargs):
        tree = real(*args, **kwargs)
        wrapper = FutureContainer()
        wrapper.body = tree.body[-1].body
        tree.body[-1].body = [wrapper]
        return tree
    monkeypatch.setattr(adapters.ast, 'parse', parse)
    r = scan(tmp_path, 'def helper():\n    marker.hit()\ndef entry():\n    helper()')
    assert not calls(r, 'helper') and not calls(r, 'marker.hit')
    roots = {root.callable_key for root in r.graph.roots}
    regions = r.graph.frontend_facts['app.py']['execution_regions']
    assert any(x['mode'] == 'UNKNOWN' and x['owner_key'] not in roots for x in regions)
    assert any('FutureContainer' in reason for _, reason in r.graph.coverage_gaps)


def test_unmodeled_jsx_execution_has_separate_owner(tmp_path):
    r = scan(tmp_path, 'function helper(){marker.hit()}function entry(){return <Widget>{helper()}</Widget>}', 'app.tsx')
    assert not calls(r, 'helper') and not calls(r, 'marker.hit')
    assert any('jsx_' in reason for _, reason in r.graph.coverage_gaps)


def test_unknown_field_under_specialized_visitor_is_audited(tmp_path,monkeypatch):
    from actenon_scan.repository import invocation_adapters as adapters
    real=adapters.ast.parse
    class FutureParameter(ast.AST):
        _fields=()
    def parse(*args,**kwargs):
        tree=real(*args,**kwargs)
        tree.body[-1].type_params=[FutureParameter()]
        return tree
    monkeypatch.setattr(adapters.ast,'parse',parse)
    r=scan(tmp_path,'def helper():\n    marker.hit()\ndef entry():\n    helper()')
    assert calls(r,'helper') and not calls(r,'marker.hit')
    assert any('FutureParameter' in reason for _,reason in r.graph.coverage_gaps)


@pytest.mark.parametrize("write", ["this.helper=opaque", "[this.helper]=[opaque]",
    "[[this.helper]]=[[opaque]]", "({x:this.helper}={x:opaque})", "this['helper']=opaque",
    "delete this.helper", "const captured=this;[captured.helper]=[opaque]"])
def test_lvalue_decomposition_invariance(tmp_path,write):
    r=scan(tmp_path,"class S{helper(){marker.hit()}entry(){"+write+";this.helper()}}","app.ts","S.entry")
    assert calls(r,"this.helper") and not calls(r,"marker.hit")
    assert any(E.REASSIGNMENT_WRITE in b.counter_evidence for b in calls(r,"this.helper")[0].binding_claims)
    events=r.graph.frontend_facts['app.ts']['write_events']
    assert any(e['target_kind']=='MEMBER' and e['member']=='helper' for e in events)


@pytest.mark.parametrize('key',[r'"h\x65lper"',r'"\u0068elper"','`helper`','opaque'])
def test_unproved_computed_keys_are_not_raw_literal_identities(tmp_path,key):
    r=scan(tmp_path,'class S{helper(){marker.hit()}entry(){this['+key+']=unknown;this.helper()}}','app.ts','S.entry')
    assert calls(r,'this.helper') and not calls(r,'marker.hit')
    assert any(e['member']=='*' and e['certainty']=='POSSIBLE' for e in r.graph.frontend_facts['app.ts']['write_events'])


@pytest.mark.parametrize("write", ["for _,selected = range []func(){live}{}",
    "ch:=make(chan func(),1);ch<-live;select{case selected = <-ch:}",
    "selected, introduced := live, 1;_ = introduced"])
def test_go_existing_binding_store_is_explicit_assignment(tmp_path,write):
    source="package main\nfunc live(){}\nfunc entry(){selected:=func(){marker.hit()};"+write+";selected()}"
    r=scan(tmp_path,source,"app.go")
    assert calls(r,"selected") and not calls(r,"marker.hit")
    assert any(e['binding']=='selected' and e['operation']=='ASSIGN'
               for e in r.graph.frontend_facts['app.go']['write_events'])


def test_unproved_candidate_competitor_blocks_graph_authority(tmp_path):
    from actenon_scan.invocation_graph import ImplementationTarget
    r=scan(tmp_path,"def helper():\n    marker.hit()\ndef entry():\n    helper()")
    c=calls(r,"helper")[0]
    assert c.established_targets
    c.possible_implementations += (ImplementationTarget("unproved",opaque=True),)
    assert not c.established_targets


@pytest.mark.parametrize('capture', ['helper','alias','dep.helper'])
def test_callable_object_member_mutation_opens_body_stability(tmp_path,capture):
    (tmp_path/'dep.py').write_text('def helper():\n    old_probe.signal()')
    source='import dep\ndef helper():\n    old_probe.signal()\ndef replacement():\n    live_probe.signal()\nalias=helper\ndef entry():\n    '+capture+'.__code__=replacement.__code__\n    '+capture+'()'
    r=scan(tmp_path,source)
    assert not calls(r,'old_probe.signal')
    assert calls(r,capture)
    assert any('callable object stability' in reason for _,reason in r.graph.coverage_gaps)


@pytest.mark.parametrize('declaration',['const [helper]=[original]',
    'const {x:helper}={x:original}', 'const [[helper]]=[[original]]'])
def test_stable_literal_destructuring_positive(tmp_path,declaration):
    source='function original(){marker.hit()}function entry(){'+declaration+';helper()}'
    r=scan(tmp_path,source,'app.ts')
    assert calls(r,'marker.hit')
    assert calls(r,'helper')[0].established_targets


@pytest.mark.parametrize('declaration',['const [helper]=dynamic',
    'const {x:helper}={get x(){return original}}', 'const [helper=original]=unknown'])
def test_dynamic_destructuring_has_no_exact_alias_evidence(tmp_path,declaration):
    r=scan(tmp_path,'function original(){marker.hit()}function entry(){'+declaration+';helper()}','app.ts')
    assert calls(r,'helper') and not calls(r,'marker.hit')


def test_incomplete_inventory_is_not_write_closure(tmp_path):
    from actenon_scan import GraphLimits
    (tmp_path/'app.py').write_text('def helper():\n    marker.hit()\ndef entry():\n    helper()')
    (tmp_path/'later.py').write_text('import app\napp.helper=unknown')
    r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint('app.py','entry')],discover_roots=False,
                         limits=GraphLimits(max_files=1))
    assert calls(r,'helper') and not calls(r,'marker.hit')
    assert any('max_files' in reason for _,reason in r.graph.coverage_gaps)
    assert any(b.edge_proof.state(O.WRITE_SET_CLOSED)==S.UNKNOWN for b in calls(r,'helper')[0].binding_claims)


def test_unresolved_alias_write_opens_closure(tmp_path):
    source='def helper():\n    marker.hit()\ndef capture():\n    return helper\ndef entry():\n    obj=capture()\n    obj.any_member=unknown\n    helper()'
    r=scan(tmp_path,source)
    assert calls(r,'helper') and not calls(r,'marker.hit')
    assert any('unresolved namespace write destination' in reason for _,reason in r.graph.coverage_gaps)


@pytest.mark.parametrize('file,source,symbol',[
    ('app.py','class Base:\n    def helper(self):\n        old_probe.signal()\n    def entry(self):\n        self.helper()\nclass Derived(Base):\n    def helper(self):\n        live_probe.signal()','Base.entry'),
    ('app.py','def replacement():\n    live_probe.signal()\nclass S:\n    def helper(self):\n        old_probe.signal()\n    def __getattribute__(self,name):\n        if name=="helper":\n            return replacement\n        return object.__getattribute__(self,name)\n    def entry(self):\n        self.helper()','S.entry'),
    ('app.ts','class Base{helper(){old_probe.signal()}entry(){this.helper()}}class Derived extends Base{helper(){live_probe.signal()}}','Base.entry'),
])
def test_unproved_receiver_dispatch_cannot_use_absent_counter_facts(tmp_path,file,source,symbol):
    r=scan(tmp_path,source,file,symbol)
    assert not calls(r,'old_probe.signal')
    assert any('receiver dispatch' in reason for _,reason in r.graph.coverage_gaps)
    local=[b for c in r.graph.invocations.values() for b in c.binding_claims if b.candidate_is_local]
    assert local and all(b.edge_proof.state(O.RECEIVER_COMPATIBLE)==S.UNKNOWN for b in local)
