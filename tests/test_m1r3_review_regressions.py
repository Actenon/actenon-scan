"""Third independent review cases: runtime-proven unrelated bodies."""
import pytest
from actenon_scan import Entrypoint, RootKind, scan_effect_claims

CASES = {'go_range_assignment_to_outer': {'files': {'app.go': 'package main\n'
                                                      'func original(){old_probe.signal()}\n'
                                                      'func live(){live_probe.signal()}\n'
                                                      'var selected=original\n'
                                                      'func replace(){for _,selected = range '
                                                      '[]func(){live}{}}\n'
                                                      'func entry(flag '
                                                      'bool){replace();selected()}\n'},
                                  'root_file': 'app.go',
                                  'root_symbol': 'entry'},
 'go_select_receive_assignment': {'files': {'app.go': 'package main\n'
                                                      'func original(){old_probe.signal()}\n'
                                                      'func live(){live_probe.signal()}\n'
                                                      'var selected=original\n'
                                                      'func entry(flag bool){ch:=make(chan '
                                                      'func(),1);ch<-live;select{case selected = '
                                                      '<-ch:};selected()}\n'},
                                  'root_file': 'app.go',
                                  'root_symbol': 'entry'},
 'js_array_member_write_through_receiver_alias': {'files': {'app.js': 'class '
                                                                      'Beacon{route(){old_probe.signal()}entry(){const '
                                                                      'alias=this;[alias.route]=[()=>live_probe.signal()];this.route()}}function '
                                                                      'entry(flag=true){new '
                                                                      'Beacon().entry()}'},
                                                  'root_file': 'app.js',
                                                  'root_symbol': 'app.Beacon.entry'},
 'js_delete_computed_prototype_method': {'files': {'app.js': 'class '
                                                             'Beacon{route(){old_probe.signal()} '
                                                             'entry(){delete '
                                                             'Beacon.prototype["route"];this.route()}} '
                                                             'function entry(flag=true){new '
                                                             'Beacon().entry()}'},
                                         'root_file': 'app.js',
                                         'root_symbol': 'app.Beacon.entry'},
 'js_delete_prototype_method': {'files': {'app.js': 'class Beacon{route(){old_probe.signal()} '
                                                    'entry(){delete '
                                                    'Beacon.prototype.route;this.route()}} '
                                                    'function entry(flag=true){new '
                                                    'Beacon().entry()}'},
                                'root_file': 'app.js',
                                'root_symbol': 'app.Beacon.entry'},
 'js_object_member_write_through_receiver_alias': {'files': {'app.js': 'class '
                                                                       'Beacon{route(){old_probe.signal()}entry(){const '
                                                                       'alias=this;({replacement:alias.route}={replacement:()=>live_probe.signal()});this.route()}}function '
                                                                       'entry(flag=true){new '
                                                                       'Beacon().entry()}'},
                                                   'root_file': 'app.js',
                                                   'root_symbol': 'app.Beacon.entry'},
 'py_async_generator_expression': {'files': {'app.py': 'async def dormant():\n'
                                                       '    old_probe.signal()\n'
                                                       'async def entry(flag=True):\n'
                                                       '    return (await dormant() for i in '
                                                       '(1,2))\n'},
                                   'root_file': 'app.py',
                                   'root_symbol': 'app.entry'},
 'py_future_class_annotation': {'files': {'app.py': 'from __future__ import annotations\n'
                                                    'def dormant():\n'
                                                    '    old_probe.signal()\n'
                                                    'def entry(flag=True):\n'
                                                    '    class Local:\n'
                                                    '        ignored: dormant()\n'
                                                    '    return Local\n'},
                                'root_file': 'app.py',
                                'root_symbol': 'app.entry'},
 'py_generator_filter': {'files': {'app.py': 'def dormant():\n'
                                             '    old_probe.signal()\n'
                                             'def entry(flag=True):\n'
                                             '    return (i for i in (1,2) if dormant())\n'},
                         'root_file': 'app.py',
                         'root_symbol': 'app.entry'},
 'py_lazy_generator_argument': {'files': {'app.py': 'def dormant():\n'
                                                    '    old_probe.signal()\n'
                                                    'def retain(value):\n'
                                                    '    return value\n'
                                                    'def entry(flag=True):\n'
                                                    '    return retain(dormant() for item in '
                                                    '(1,2))\n'},
                                'root_file': 'app.py',
                                'root_symbol': 'app.entry'},
 'py_lazy_generator_assignment': {'files': {'app.py': 'def dormant():\n'
                                                      '    old_probe.signal()\n'
                                                      'def entry(flag=True):\n'
                                                      '    iterator=(dormant() for item in (1,2))\n'
                                                      '    return iterator\n'},
                                  'root_file': 'app.py',
                                  'root_symbol': 'app.entry'},
 'py_local_annotation_is_not_executed': {'files': {'app.py': 'def dormant():\n'
                                                             '    old_probe.signal()\n'
                                                             'def entry(flag=True):\n'
                                                             '    ignored: dormant()\n'},
                                         'root_file': 'app.py',
                                         'root_symbol': 'app.entry'},
 'ts_typed_array_member_replacement': {'files': {'app.ts': 'declare const '
                                                           'old_probe:{signal():void};declare '
                                                           'const live_probe:{signal():void};type '
                                                           'Callback=()=>void;class '
                                                           'Relay{route():void{old_probe.signal()}entry():void{[this.route]=[()=>live_probe.signal()];this.route()}}function '
                                                           'entry(flag:boolean=true):void{new '
                                                           'Relay().entry()}'},
                                       'root_file': 'app.ts',
                                       'root_symbol': 'app.Relay.entry'}}

@pytest.mark.parametrize('kind',list(RootKind))
@pytest.mark.parametrize('label',list(CASES))
def test_third_review_no_invented_execution(tmp_path,label,kind):
    case=CASES[label]
    for name,source in case['files'].items():
        path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source)
    result=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(case['root_file'],case['root_symbol'],kind)],discover_roots=False)
    assert not result.analysis_errors
    assert not [c for c in result.graph.invocations.values() if c.callee_spelling=='old_probe.signal']
    # Runtime uncertain calls still have genesis; metadata/deferred syntax may
    # correctly belong outside the selected execution region.
    for call in result.graph.invocations.values():
        assert any(c.invocation_id==call.invocation_id for c in result.claims)
