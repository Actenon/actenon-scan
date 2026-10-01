"""1,280 valid programs over execution, scope, alias, write and conditionality.

The companion differential runner executes every program. Oracles use definite
replacement/deletion or uninvoked bodies, never a sample of an unknown branch.
"""
from itertools import product
import pytest
from actenon_scan import Entrypoint, RootKind, scan_effect_claims

CONTEXTS={
    'python':['eager','uncalled_def','generator_expression','annotation'],
    'typescript':['eager','uncalled_function','generator_function','arrow'],
    'go':['eager','uncalled_literal','returned_literal','callback'],
}
WRITES={
    'python':['none','assign','tuple','nested','list','conditional','closure','delete'],
    'typescript':['none','assign','array','object','nested','conditional','closure','delete'],
    'go':['none','assign','multiple','range','receive','select','conditional','closure'],
}
CASES=[(lang,context,scope,alias,write,conditional)
       for lang in CONTEXTS for context,scope,alias,write,conditional in product(
           CONTEXTS[lang],['module','local','captured'],[False,True],WRITES[lang],[False,True])]
CASES += [(lang,context,'receiver',alias,write,conditional)
          for lang in CONTEXTS for context,alias,write,conditional in product(
              ['eager','uncalled'],[False,True],
              ['none','assign','range','select'] if lang=='go' else ['none','assign','pattern','delete','computed','escaped'],[False,True])]


def program(case):
    lang,context,scope,alias,write,conditional=case
    if scope=='receiver':return receiver_program(case)
    expected_old=context=='eager' and write=='none'
    if lang=='python':
        imports='def original():\n    old_probe.signal()\ndef live():\n    live_probe.signal()\n'
        declaration=('alias=original\nselected=alias' if alias else 'selected=original')
        statements={
            'none':'', 'assign':'selected=live', 'tuple':'selected, spare = live, 0',
            'nested':'spare, [selected] = 0, [live]', 'list':'[selected]=[live]',
            'conditional':'if True:\n    selected=live',
            'closure':'def replace():\n    '+('global' if scope=='module' else 'nonlocal')+' selected\n    selected=live\nreplace()',
            'delete':'del selected',
        }[write]
        directive=('global' if scope=='module' else 'nonlocal')+' selected\n' if write!='none' and (scope=='module' or scope=='captured') else ''
        body=directive+(statements+'\n' if statements else '')+'selected()'
        if conditional:body='if True:\n'+indent(body)
        if context=='uncalled_def':body='def uncalled():\n'+indent(body)
        elif context=='generator_expression':
            body='def deferred():\n'+indent(body)+'\n    yield None\niterator=(next(deferred()) for _ in (1,))\nreturn iterator'
        elif context=='annotation':
            # The call-shaped local annotation is genuinely non-runtime. Writes
            # remain legal executable setup but cannot execute original.
            body=body.rsplit('selected()',1)[0]+'metadata: selected()'
        if scope=='module':source=imports+declaration+'\ndef entry():\n'+indent(body)+'\n'
        elif scope=='local':source=imports+'def entry():\n'+indent(declaration+'\n'+body)+'\n'
        else:source=imports+'def entry():\n'+indent(declaration+'\ndef inner():\n'+indent(body)+'\ninner()')+'\n'
        # A declared uncalled body has a separate local binding namespace.
        if context=='uncalled_def' and scope=='local' and write!='none':
            source=source.replace('def uncalled():\n','def uncalled():\n        nonlocal selected\n')
        if context=='generator_expression' and scope=='local' and write!='none':
            source=source.replace('def deferred():\n','def deferred():\n        nonlocal selected\n')
        return 'app.py',source,'entry',expected_old
    if lang=='typescript':
        header='function original(){old_probe.signal()}function live(){live_probe.signal()}\n'
        declaration='let alias=original;let selected=alias;' if alias else 'let selected=original;'
        statements={
            'none':'', 'assign':'selected=live;', 'array':'[selected]=[live];',
            'object':'({x:selected}={x:live});', 'nested':'[[selected]]=[[live]];',
            'conditional':'if(true){selected=live;}', 'closure':'(()=>{selected=live})();',
            # Identifier delete is illegal in strict JS. Use a valid lexical
            # replacement with undefined, then an uncallable value invocation.
            'delete':'selected=undefined;',
        }[write]
        body=statements+'selected();'
        if conditional:body='if(true){'+body+'}'
        if context=='uncalled_function':body='function uncalled(){'+body+'}'
        elif context=='generator_function':body='function* deferred(){'+body+'yield null}const iterator=deferred();void iterator;'
        elif context=='arrow':body='const uncalled=()=>{'+body+'};'
        source=header+(declaration+'function entry(){'+body+'}' if scope=='module' else
            'function entry(){'+declaration+body+'}' if scope=='local' else
            'function entry(){'+declaration+'function inner(){'+body+'}inner()}')
        return 'app.js',source,'entry',expected_old
    header='package main\nfunc original(){old_probe.signal()}\nfunc live(){live_probe.signal()}\nfunc keep(callback func()){}\n'
    declaration=(('var alias=original\nvar selected=alias' if alias else 'var selected=original') if scope=='module' else
                 ('alias:=original;selected:=alias' if alias else 'selected:=original'))
    statements={
        'none':'', 'assign':'selected=live;', 'multiple':'spare:=0;selected,spare=live,1;_ = spare;',
        'range':'for _,selected = range []func(){live}{};',
        'receive':'ch:=make(chan func(),1);ch<-live;selected=<-ch;',
        'select':'ch:=make(chan func(),1);ch<-live;select{case selected = <-ch:};',
        'conditional':'if true{selected=live;};', 'closure':'func(){selected=live}();',
    }[write]
    body=statements+'selected()'
    if conditional:body='if true{'+body+'}'
    if context=='uncalled_literal':body='_ = func(){'+body+'}'
    elif context=='returned_literal':body='captured:=func(){'+body+'};_ = captured'
    elif context=='callback':body='keep(func(){'+body+'})'
    source=header+(declaration+'\nfunc entry(){'+body+'}' if scope=='module' else
        'func entry(){'+declaration+';'+body+'}' if scope=='local' else
        'func entry(){'+declaration+';inner:=func(){'+body+'};inner()}')
    return 'app.go',source,'entry',expected_old


def indent(source):
    return '\n'.join('    '+line for line in source.splitlines())


def receiver_program(case):
    lang,context,_,alias,write,conditional=case
    if lang=='python':
        base='captured' if alias else 'self'
        statement={'none':'','assign':base+'.route='+base+'.live',
                   'pattern':'[['+base+'.route]]=[['+base+'.live]]',
                   'delete':'del Receiver.route',
                   'computed':'setattr('+base+',"route",'+base+'.live)',
                   'escaped':'setattr('+base+',"r\\x6fute",'+base+'.live)'}[write]
        body=(statement+'\n' if statement else '')+'self.route()'
        if conditional:body='if True:\n'+indent(body)
        if context=='uncalled':body='def uncalled():\n'+indent(body)
        if alias:body='captured=self\n'+body
        source='class Receiver:\n    def route(self):\n        old_probe.signal()\n    def live(self):\n        live_probe.signal()\n    def entry(self):\n'+indent(indent(body))
        return 'app.py',source,'Receiver.entry',context=='eager' and write=='none'
    if lang=='typescript':
        base='captured' if alias else 'this'
        statement={'none':'','assign':base+'.route='+base+'.live;',
                   'pattern':'[['+base+'.route]]=[['+base+'.live]];',
                   'delete':'delete Receiver.prototype["route"];',
                   'computed':base+'["route"]='+base+'.live;',
                   'escaped':base+'["r\\x6fute"]='+base+'.live;'}[write]
        body=statement+'this.route();'
        if conditional:body='if(true){'+body+'}'
        if context=='uncalled':body='const uncalled=()=>{'+body+'};'
        if alias:body='const captured=this;'+body
        return 'app.js','class Receiver{route(){old_probe.signal()}live(){live_probe.signal()}entry(){'+body+'}}','Receiver.entry',context=='eager' and write=='none'
    # Go receiver reassignment changes the value, not the declared method body.
    # This is a useful false-unresolved oracle, not a stale-target accusation.
    base='captured' if alias else 's'
    statement={'none':'','assign':base+'=Receiver{};',
               'range':'for _,'+base+' = range []Receiver{{}}{};',
               'select':'ch:=make(chan Receiver,1);ch<-Receiver{};select{case '+base+' = <-ch:};'}[write]
    body=statement+base+'.route()'
    if conditional:body='if true{'+body+'}'
    if context=='uncalled':body='_ = func(){'+body+'}'
    if alias:body='captured:=s;'+body
    source='package main\ntype Receiver struct{}\nfunc(s Receiver)route(){old_probe.signal()}\nfunc(s Receiver)entry(){'+body+'}'
    return 'app.go',source,'Receiver.entry',context=='eager'


@pytest.mark.parametrize('case',CASES,ids=lambda c:'-'.join(map(str,c)))
def test_semantic_dimension_matrix(tmp_path,case):
    file,source,symbol,expected_old=program(case)
    (tmp_path/file).write_text(source)
    kind=list(RootKind)[CASES.index(case)%len(RootKind)]
    result=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,symbol,kind)],discover_roots=False)
    assert not result.analysis_errors
    reached=any(c.callee_spelling=='old_probe.signal' for c in result.graph.invocations.values())
    # False unresolved is recorded by the differential runner. An exact stale
    # target is forbidden in every deterministic replacement/deferred case.
    assert expected_old or not reached
    for call in result.graph.invocations.values():
        for binding in call.binding_claims:
            if binding.state.value=='ESTABLISHED':assert binding.edge_proof.closed
