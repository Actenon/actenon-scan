"""Valid-language imported binding/member stability probes; no sibling production."""
import pytest
from actenon_scan import Entrypoint, RootKind, scan_effect_claims
from actenon_scan.effects import ProofState, Verdict
from actenon_scan.binding_claims import BindingEvidence as E, BindingState

def package_sources(mode):
    app = 'import pkg\nfrom replacement import replacement\ndef entry(flag=True):\n'
    write = {
        'package_member': '    pkg.dep = replacement\n',
        'package_conditional': '    if flag:\n        pkg.dep = replacement\n',
        'package_computed': '    pkg.__dict__["dep"] = replacement\n',
        'package_alias': '    alias=pkg\n    alias.dep = replacement\n',
        'package_cross_alias': '    change.alter()\n',
    }[mode]
    if mode == 'package_cross_alias':
        app = 'import pkg\nimport change\ndef entry(flag=True):\n'
    return {'app.py': app + write + '    pkg.dep.helper()\n',
            'pkg/__init__.py': 'from . import dep\n',
            'pkg/dep.py': 'def helper():\n    old_body.hit()\n',
            'replacement.py': 'class Replacement:\n    def helper(self):\n        pass\nreplacement=Replacement()\n',
            'change.py': 'import pkg as imported\nfrom replacement import replacement\ndef alter():\n    imported.dep=replacement\n'}


CASES = [
    ('python_module_write', 'helper.run', {'app.py':'import helper\ndef replacement():\n    pass\ndef entry():\n    helper.run=replacement\n    helper.run()', 'helper.py':'def run():\n    old_body.hit()'}),
    ('python_module_computed', 'helper.run', {'app.py':'import helper\ndef replacement():\n    pass\ndef entry():\n    helper.__dict__["run"]=replacement\n    helper.run()', 'helper.py':'def run():\n    old_body.hit()'}),
    ('python_cross_module', 'helper.run', {'app.py':'import helper\nfrom change import alter\ndef entry():\n    alter()\n    helper.run()', 'helper.py':'def run():\n    old_body.hit()', 'change.py':'import helper as other\ndef replacement():\n    pass\ndef alter():\n    other.run=replacement'}),
    ('python_alias_replace', 'invoke', {'app.py':'from dep import helper\ndef replacement():\n    pass\ndef entry(flag=True):\n    invoke=helper\n    if flag:\n        invoke=replacement\n    invoke()', 'dep.py':'def helper():\n    old_body.hit()'}),
    ('python_local_rebind', 'helper', {'app.py':'from dep import helper\ndef replacement():\n    pass\ndef entry():\n    helper=replacement\n    helper()', 'dep.py':'def helper():\n    old_body.hit()'}),
    ('python_reexport', 'helper', {'app.py':'from bridge import helper\ndef entry():\n    helper()', 'bridge.py':'from dep import helper\ndef replacement():\n    pass\ncondition=True\nif condition:\n    helper=replacement', 'dep.py':'def helper():\n    old_body.hit()'}),
    ('ts_alias_replace', 'invoke', {'app.ts':'import {helper} from "./dep"; function replacement(){} function entry(flag:boolean){let invoke=helper;if(flag){invoke=replacement;}invoke();}', 'dep.ts':'export function helper(){old_body.hit();}'}),
    ('ts_local_shadow', 'helper', {'app.ts':'import {helper} from "./dep"; function replacement(){} function entry(){const helper=replacement;helper();}', 'dep.ts':'export function helper(){old_body.hit();}'}),
    ('ts_live_export_replace', 'helper', {'app.ts':'import {helper,alter} from "./dep"; function entry(flag:boolean){alter(flag);helper();}', 'dep.ts':'export function helper(){old_body.hit();} function replacement(){} export function alter(flag:boolean){if(flag){helper=replacement;}}'}),
    ('ts_namespace_live_replace', 'api.helper', {'app.ts':'import * as api from "./dep"; function entry(flag:boolean){api.alter(flag);api.helper();}', 'dep.ts':'export function helper(){old_body.hit();} function replacement(){} export function alter(flag:boolean){if(flag){helper=replacement;}}'}),
    ('ts_cross_module_alias', 'invoke', {'app.ts':'import {helper} from "./bridge"; import {alter} from "./dep"; function entry(flag:boolean){const invoke=helper;alter(flag);invoke();}', 'bridge.ts':'import {helper as imported} from "./dep"; export const helper=imported;', 'dep.ts':'export function helper(){old_body.hit();} function replacement(){} export function alter(flag:boolean){if(flag){helper=replacement;}}'}),
    ('ts_mutable_import_member', 'api.helper', {'app.ts':'import {api} from "./dep"; function replacement(){} function entry(){api.helper=replacement;api.helper();}', 'dep.ts':'export const api={helper(){old_body.hit();}};'}),
    ('ts_mutable_computed_member', 'api.helper', {'app.ts':'import {api} from "./dep"; function replacement(){} function entry(key:"helper"){api[key]=replacement;api.helper();}', 'dep.ts':'export const api={helper(){old_body.hit();}};'}),
]
CASES += [(mode, 'pkg.dep.helper', package_sources(mode)) for mode in
          ['package_member','package_conditional','package_computed','package_alias','package_cross_alias']]


def scan(tmp_path, sources, kind):
    for file, source in sources.items():
        path=tmp_path/file;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source)
    return scan_effect_claims(tmp_path,entrypoints=[Entrypoint(next(iter(sources)),'entry',kind)],discover_roots=False)


def forbidden_established(result):
    symbols={t.candidate_id:t.symbol for c in result.graph.invocations.values() for t in c.possible_implementations}
    return [(c,b) for c in result.graph.invocations.values() for b in c.binding_claims
            if b.state==BindingState.ESTABLISHED and symbols[b.candidate_id] in {'dep.helper','pkg.dep.helper','helper.run'}]


@pytest.mark.parametrize('kind',list(RootKind))
@pytest.mark.parametrize('label,spelling,sources',CASES,ids=[c[0] for c in CASES])
def test_import_stability(tmp_path,kind,label,spelling,sources):
    result=scan(tmp_path,sources,kind)
    assert not result.analysis_errors
    calls=[c for c in result.graph.invocations.values() if c.callee_spelling==spelling]
    assert calls, 'mutation must not delete invocation'
    assert not forbidden_established(result)
    assert not any(c.callee_spelling=='old_body.hit' for c in result.graph.invocations.values())
    claims=[c for c in result.claims if c.invocation_id in {call.invocation_id for call in calls}]
    assert claims and all(c.verdict==Verdict.ABSTAIN for c in claims)
    assert all(s==ProofState.UNKNOWN for c in claims for _,s in c.obligations.items())


def target_claims(result, spelling, symbol):
    return [binding for call in result.graph.invocations.values()
            if call.callee_spelling == spelling
            for target in call.possible_implementations if target.symbol == symbol
            for binding in call.binding_claims if binding.candidate_id == target.candidate_id]


@pytest.mark.parametrize('kind', list(RootKind))
@pytest.mark.parametrize('mode', ['package_member', 'package_conditional', 'package_computed',
                                  'package_alias', 'package_cross_alias'])
def test_metamorphic_import_stability_monotonicity(tmp_path, kind, mode):
    sources = package_sources(mode)
    # Remove every supported write for the structurally stable starting state.
    stable = dict(sources, **{'app.py': 'import pkg\ndef entry():\n    pkg.dep.helper()\n',
                             'change.py': ''})
    before = scan(tmp_path, stable, kind)
    prior = target_claims(before, 'pkg.dep.helper', 'pkg.dep.helper')
    assert prior and all(b.state == BindingState.ESTABLISHED for b in prior)
    after = scan(tmp_path, sources, kind)
    possible = target_claims(after, 'pkg.dep.helper', 'pkg.dep.helper')
    assert possible, 'old import provenance must remain a candidate'
    assert all(b.state == BindingState.POSSIBLE for b in possible)
    assert all(E.REASSIGNMENT_WRITE in b.counter_evidence for b in possible)
    assert all(prior[0].positive_evidence <= b.positive_evidence for b in possible)
    assert not any(c.callee_spelling == 'old_body.hit' for c in after.graph.invocations.values())


IMPORT_CONTROLS = [
    ('python_named', 'helper', {'app.py': 'from dep import helper\ndef entry():\n    helper()',
                               'dep.py': 'def helper():\n    marker.hit()'}),
    ('python_alias', 'invoke', {'app.py': 'from dep import helper as imported\ninvoke=imported\ndef entry():\n    invoke()',
                               'dep.py': 'def helper():\n    marker.hit()'}),
    ('python_reexport', 'bridge.helper', {'app.py': 'import bridge\ndef entry():\n    bridge.helper()',
                                         'bridge.py': 'from dep import helper',
                                         'dep.py': 'def helper():\n    marker.hit()'}),
    ('python_package_member', 'pkg.dep.helper', {'app.py': 'import pkg\ndef entry():\n    pkg.dep.helper()',
                                                'pkg/__init__.py': 'from . import dep',
                                                'pkg/dep.py': 'def helper():\n    marker.hit()'}),
    ('python_explicit_submodule', 'pkg.dep.helper', {'app.py': 'import pkg.dep\ndef entry():\n    pkg.dep.helper()',
                                                    'pkg/__init__.py': '',
                                                    'pkg/dep.py': 'def helper():\n    marker.hit()'}),
    ('python_from_submodule', 'dep.helper', {'app.py': 'from pkg import dep\ndef entry():\n    dep.helper()',
                                            'pkg/__init__.py': '',
                                            'pkg/dep.py': 'def helper():\n    marker.hit()'}),
    ('python_captured_module', 'saved.helper', {'app.py': 'import pkg.dep as saved\nimport pkg\ndef entry():\n    pkg.dep=None\n    saved.helper()',
                                               'pkg/__init__.py': '',
                                               'pkg/dep.py': 'def helper():\n    marker.hit()'}),
    ('typescript_named', 'helper', {'app.ts': 'import {helper} from "./dep";function entry(){helper();}',
                                    'dep.ts': 'export function helper(){marker.hit();}'}),
    ('typescript_namespace', 'api.helper', {'app.ts': 'import * as api from "./dep";function entry(){api.helper();}',
                                            'dep.ts': 'export function helper(){marker.hit();}'}),
    ('typescript_reexport_alias', 'invoke', {'app.ts': 'import {helper as invoke} from "./bridge";function entry(){invoke();}',
                                             'bridge.ts': 'import {helper as imported} from "./dep";export const helper=imported;',
                                             'dep.ts': 'export function helper(){marker.hit();}'}),
]


@pytest.mark.parametrize('kind', list(RootKind))
@pytest.mark.parametrize('label,spelling,sources', IMPORT_CONTROLS, ids=[c[0] for c in IMPORT_CONTROLS])
def test_positive_import_controls(tmp_path, kind, label, spelling, sources):
    result = scan(tmp_path, sources, kind)
    assert not result.analysis_errors
    calls = [c for c in result.graph.invocations.values() if c.callee_spelling == spelling]
    assert calls and all(len(c.established_targets) == 1 for c in calls)
    assert any(c.callee_spelling == 'marker.hit' for c in result.graph.invocations.values())


@pytest.mark.parametrize('kind', list(RootKind))
def test_file_presence_cannot_establish_package_member(tmp_path, kind):
    sources = {'app.py': 'import pkg\ndef entry():\n    pkg.dep.helper()',
               'pkg/__init__.py': '', 'pkg/dep.py': 'def helper():\n    old_body.hit()'}
    result = scan(tmp_path, sources, kind)
    assert not result.analysis_errors
    assert any(c.callee_spelling == 'pkg.dep.helper' for c in result.graph.invocations.values())
    assert not forbidden_established(result)
    assert not any(c.callee_spelling == 'old_body.hit' for c in result.graph.invocations.values())


@pytest.mark.parametrize('kind', list(RootKind))
@pytest.mark.parametrize('qualified', [False, True])
def test_deep_import_prefix_write_retains_candidate(tmp_path, kind, qualified):
    sources = {'app.py': ('import pkg.inner.dep' if qualified else 'import pkg') +
               '\ndef entry(flag):\n    if flag:\n        pkg.inner=None\n    pkg.inner.dep.helper()',
               'pkg/__init__.py': 'from . import inner',
               'pkg/inner/__init__.py': 'from . import dep',
               'pkg/inner/dep.py': 'def helper():\n    old_body.hit()'}
    result = scan(tmp_path, sources, kind)
    assert not result.analysis_errors
    bindings = target_claims(result, 'pkg.inner.dep.helper', 'pkg.inner.dep.helper')
    assert bindings and all(b.state == BindingState.POSSIBLE for b in bindings)
    assert all(E.REASSIGNMENT_WRITE in b.counter_evidence for b in bindings)
    assert not any(c.callee_spelling == 'old_body.hit' for c in result.graph.invocations.values())


@pytest.mark.parametrize('kind', list(RootKind))
@pytest.mark.parametrize('namespace', [False, True])
def test_metamorphic_typescript_import_stability(tmp_path, kind, namespace):
    spelling = 'api.helper' if namespace else 'helper'
    app = ('import * as api from "./dep";' if namespace else 'import {helper,alter} from "./dep";')
    app += 'function entry(flag:boolean){' + ('api.alter(flag);' if namespace else 'alter(flag);') + spelling + '();}'
    sources = {'app.ts': app, 'dep.ts': 'export function helper(){old_body.hit();} export function alter(flag:boolean){}'}
    before = scan(tmp_path, sources, kind)
    prior = target_claims(before, spelling, 'dep.helper')
    assert prior and all(b.state == BindingState.ESTABLISHED for b in prior)
    sources['dep.ts'] = 'export function helper(){old_body.hit();} function replacement(){} export function alter(flag:boolean){if(flag){helper=replacement;}}'
    after = scan(tmp_path, sources, kind)
    possible = target_claims(after, spelling, 'dep.helper')
    assert possible and all(b.state == BindingState.POSSIBLE for b in possible)
    assert all(E.REASSIGNMENT_WRITE in b.counter_evidence for b in possible)
    assert not any(c.callee_spelling == 'old_body.hit' for c in after.graph.invocations.values())


@pytest.mark.parametrize('kind', list(RootKind))
@pytest.mark.parametrize('prefix', ['import pkg.dep', 'from pkg import dep'])
def test_implicit_submodule_write_is_not_skipped(tmp_path, kind, prefix):
    spelling = 'dep.helper' if prefix.startswith('from') else 'pkg.dep.helper'
    sources = {'app.py': prefix + '\nimport pkg\ndef entry():\n    pkg.dep=None\n    ' + spelling + '()',
               'pkg/__init__.py': '', 'pkg/dep.py': 'def helper():\n    old_body.hit()'}
    result = scan(tmp_path, sources, kind)
    bindings = target_claims(result, spelling, 'pkg.dep.helper')
    assert not result.analysis_errors
    assert bindings and all(b.state == BindingState.POSSIBLE for b in bindings)
    assert all(E.REASSIGNMENT_WRITE in b.counter_evidence for b in bindings)
    assert not any(c.callee_spelling == 'old_body.hit' for c in result.graph.invocations.values())


@pytest.mark.parametrize('kind', list(RootKind))
def test_import_member_alternatives_survive_file_order(tmp_path, kind, monkeypatch):
    from actenon_scan.repository import invocation_adapters as adapters
    sources = {'app.py': 'import pkg\ndef entry():\n    pkg.dep.helper()',
               'pkg/__init__.py': 'if condition:\n    from . import left as dep\nelse:\n    from . import right as dep',
               'pkg/left.py': 'def helper():\n    old_body.hit()',
               'pkg/right.py': 'def helper():\n    old_body.hit()'}
    result = scan(tmp_path, sources, kind)
    call = next(c for c in result.graph.invocations.values() if c.callee_spelling == 'pkg.dep.helper')
    assert not result.analysis_errors
    assert {t.symbol for t in call.possible_implementations if t.file} == {'pkg.left.helper', 'pkg.right.helper'}
    assert not call.established_targets
    assert all(b.state == BindingState.POSSIBLE for b in call.binding_claims if b.candidate_is_local)
    assert not any(c.callee_spelling == 'old_body.hit' for c in result.graph.invocations.values())
    original = adapters._collect_sources
    monkeypatch.setattr(adapters, '_collect_sources', lambda *a: list(reversed(original(*a))))
    assert scan(tmp_path, sources, kind).to_dict() == result.to_dict()


@pytest.mark.parametrize('kind', list(RootKind))
def test_deep_explicit_import_supplies_each_implicit_member(tmp_path, kind):
    sources = {'app.py': 'import pkg.inner.dep\ndef entry():\n    pkg.inner.dep.helper()',
               'pkg/__init__.py': '', 'pkg/inner/__init__.py': '',
               'pkg/inner/dep.py': 'def helper():\n    marker.hit()'}
    result = scan(tmp_path, sources, kind)
    bindings = target_claims(result, 'pkg.inner.dep.helper', 'pkg.inner.dep.helper')
    assert not result.analysis_errors
    assert bindings and all(b.state == BindingState.ESTABLISHED for b in bindings)
    assert any(c.callee_spelling == 'marker.hit' for c in result.graph.invocations.values())


@pytest.mark.parametrize('kind', list(RootKind))
@pytest.mark.parametrize('write', ['pkg.__dict__[key]=None', 'del pkg.dep'])
def test_computed_or_deleted_prefix_is_counter_evidence(tmp_path, kind, write):
    sources = {'app.py': 'import pkg\ndef entry(key):\n    ' + write + '\n    pkg.dep.helper()',
               'pkg/__init__.py': 'from . import dep',
               'pkg/dep.py': 'def helper():\n    old_body.hit()'}
    result = scan(tmp_path, sources, kind)
    bindings = target_claims(result, 'pkg.dep.helper', 'pkg.dep.helper')
    assert not result.analysis_errors
    assert bindings and all(b.state == BindingState.POSSIBLE for b in bindings)
    assert all(E.REASSIGNMENT_WRITE in b.counter_evidence for b in bindings)
    assert not any(c.callee_spelling == 'old_body.hit' for c in result.graph.invocations.values())


def test_import_prefix_budget_failure_is_analysis_error(tmp_path):
    parts = ['pkg'] + ['child' + str(i) for i in range(40)]
    spelling = '.'.join(parts) + '.helper'
    sources = {'app.py': 'import pkg\ndef entry():\n    ' + spelling + '()'}
    for i in range(len(parts) - 1):
        sources['/'.join(parts[:i + 1]) + '/__init__.py'] = 'from . import ' + parts[i + 1]
    sources['/'.join(parts) + '/__init__.py'] = 'def helper():\n    old_body.hit()'
    result = scan(tmp_path, sources, RootKind.PROGRAM_ENTRY)
    assert any('max_lexical_binding_depth' in message for _, message in result.analysis_errors)
    assert any(c.callee_spelling == spelling for c in result.graph.invocations.values())
    assert result.claims and all(c.verdict == Verdict.ANALYSIS_ERROR for c in result.claims)
    assert not any(c.callee_spelling == 'old_body.hit' for c in result.graph.invocations.values())
