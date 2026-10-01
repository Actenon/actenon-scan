"""All thirteen M1 semantic monotonicity properties, including runtime syntax."""
from pathlib import Path
import pytest
from actenon_scan import Entrypoint,scan_effect_claims
from actenon_scan.binding_claims import BindingEvidence as E

BASE='def helper():\n    marker.hit()\ndef entry():\n    helper()'


def scan(path,source,file='app.py',symbol='entry'):
    path.mkdir(exist_ok=True)
    (path/file).write_text(source)
    result=scan_effect_claims(path,entrypoints=[Entrypoint(file,symbol)],discover_roots=False)
    assert not result.analysis_errors
    return result


def exact(result,name):
    return [t.symbol for c in result.graph.invocations.values() if c.callee_spelling==name for t in c.established_targets]


def test_01_same_name_addition(tmp_path):
    source='def entry():\n    other.helper()'
    before=scan(tmp_path,source)
    after=scan(tmp_path,BASE.split('def entry():')[0]+source)
    assert not exact(before,'other.helper') and not exact(after,'other.helper')


def test_02_shadow_monotonicity(tmp_path):
    assert exact(scan(tmp_path,BASE),'helper')
    assert not exact(scan(tmp_path,BASE.replace('def entry():','def entry(helper):')),'helper')


def test_03_reassignment_monotonicity(tmp_path):
    assert exact(scan(tmp_path,BASE),'helper')
    assert not exact(scan(tmp_path,BASE.replace('    helper()','    helper = unknown\n    helper()')),'helper')


def test_04_import_mutation_monotonicity(tmp_path):
    (tmp_path/'dep.py').write_text('def helper():\n    marker.hit()')
    source='import dep\ndef entry():\n    dep.helper()'
    assert exact(scan(tmp_path,source),'dep.helper')
    assert not exact(scan(tmp_path,source.replace('    dep.helper()','    dep.helper=unknown\n    dep.helper()')),'dep.helper')


def test_05_decorator_monotonicity(tmp_path):
    assert exact(scan(tmp_path,BASE),'helper')
    assert not exact(scan(tmp_path,'@unknown\n'+BASE),'helper')


def test_06_receiver_compatibility(tmp_path):
    source='class S{helper(){marker.hit()}entry(){this.helper()}}'
    assert exact(scan(tmp_path,source,'app.ts','S.entry'),'this.helper')
    assert not exact(scan(tmp_path,source.replace('helper(){','static helper(){',1),'app.ts','S.entry'),'this.helper')


def test_07_uncalled_body_isolation(tmp_path):
    assert exact(scan(tmp_path,BASE),'helper')
    after=scan(tmp_path,BASE.replace('    helper()','    def uncalled():\n        helper()'))
    assert not exact(after,'helper')


def test_08_order_invariance(tmp_path):
    one=tmp_path/'one';two=tmp_path/'two';one.mkdir();two.mkdir()
    for root, order in [(one,['a','b']),(two,['b','a'])]:
        for name in order:(root/(name+'.py')).write_text('def helper():\n    marker.hit()')
        (root/'app.py').write_text('def entry():\n    helper()')
    before=scan(one,(one/'app.py').read_text());after=scan(two,(two/'app.py').read_text())
    assert before.graph.to_dict()==after.graph.to_dict()
    assert not exact(before,'helper')


def test_09_deferred_region_isolation(tmp_path):
    assert exact(scan(tmp_path,BASE),'helper')
    after=scan(tmp_path,BASE.replace('    helper()','    value=(helper() for _ in (1,))\n    return value'))
    assert not exact(after,'helper')
    assert any(r['mode']=='DEFERRED' for r in after.graph.frontend_facts['app.py']['execution_regions'])


def test_10_non_runtime_isolation(tmp_path):
    assert exact(scan(tmp_path,BASE),'helper')
    after=scan(tmp_path,BASE.replace('    helper()','    value: helper()'))
    assert not exact(after,'helper')
    assert any(r['mode']=='NON_RUNTIME' for r in after.graph.frontend_facts['app.py']['execution_regions'])


def test_11_lvalue_decomposition_invariance(tmp_path):
    for write in ['this.helper=unknown','[this.helper]=[unknown]','[[this.helper]]=[[unknown]]','this["helper"]=unknown']:
        r=scan(tmp_path,'class S{helper(){marker.hit()}entry(){'+write+';this.helper()}}','app.ts','S.entry')
        assert not exact(r,'this.helper')
        assert any(E.REASSIGNMENT_WRITE in b.counter_evidence for c in r.graph.invocations.values()
                   if c.callee_spelling=='this.helper' for b in c.binding_claims)


def test_12_unsupported_write_syntax_cannot_preserve_exactness(tmp_path):
    base='class S{helper(){marker.hit()}entry(){this.helper()}}'
    assert exact(scan(tmp_path,base,'app.ts','S.entry'),'this.helper')
    changed=base.replace('entry(){','entry(){(this as any).helper=unknown;')
    result=scan(tmp_path,changed,'app.ts','S.entry')
    assert not exact(result,'this.helper')


def test_13_declare_vs_assign(tmp_path):
    prefix='package main\nfunc original(){marker.hit()}\nfunc live(){}\nvar selected=original\n'
    stable=scan(tmp_path,prefix+'func entry(){for _,selected := range []func(){live}{_ = selected};selected()}','app.go')
    # Conservative block summaries may refuse the outer call even in the
    # declaration form. Neither form may establish the stale assignment edge.
    changed=scan(tmp_path,prefix+'func entry(){for _,selected = range []func(){live}{};selected()}','app.go')
    assert not exact(changed,'selected')
    assert any(e['operation']=='ASSIGN' and e['binding']=='selected'
               for e in changed.graph.frontend_facts['app.go']['write_events'])
