"""M1R1: a local body is followed only through an established binding."""
from pathlib import Path
import pytest
from actenon_scan import Entrypoint, RootKind, scan_effect_claims
from actenon_scan.effects import ProofState, Verdict
from actenon_scan.repository.symbol_index import ResolutionCertainty

REVIEW_CASES = [
 ('python_chain', 'app.py', 'Service.entry', 'class Service:\n    def entry(self):\n        self.client.helper()\n    def helper(self):\n        unrelated.frob()\n', 'self.client.helper'),
 ('typescript_chain', 'app.ts', 'Service.entry', 'class Service {\n entry() { this.client.helper(); }\n helper() { unrelated.frob(); }\n}\n', 'this.client.helper'),
 ('python_ordinary_self', 'app.py', 'entry', 'def entry(self):\n    self.helper()\ndef helper():\n    unrelated.frob()\n', 'self.helper'),
 ('go_local_function', 'app.go', 'entry', 'package main\nfunc entry() {\n helper := func() { actual.frob() }\n helper()\n}\nfunc helper() { unrelated.frob() }\n', 'helper'),
 ('typescript_destructuring', 'app.ts', 'entry', 'function entry(obj: any) {\n const {helper} = obj;\n helper();\n}\nfunction helper() { unrelated.frob(); }\n', 'helper'),
]


def scan(tmp_path, file, source, symbol='entry'):
 (tmp_path/file).write_text(source)
 return scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,symbol)],discover_roots=False)


def assert_honest_call(result, spelling):
 assert result.analysis_errors == []
 calls=[c for c in result.graph.invocations.values() if c.callee_spelling==spelling]
 assert len(calls)==1
 call=calls[0]
 assert call.resolution_certainty != ResolutionCertainty.RESOLVED
 assert call.resolved_callee_identity is None
 assert any(c.invocation_id==call.invocation_id for c in result.claims)
 assert all(c.verdict==Verdict.ABSTAIN for c in result.claims)
 assert all(all(s==ProofState.UNKNOWN for _,s in c.obligations.items()) for c in result.claims)
 assert not any(c.invocation.callee_expression=='unrelated.frob' for c in result.claims)


@pytest.mark.parametrize('label,file,symbol,source,spelling',REVIEW_CASES,ids=[c[0] for c in REVIEW_CASES])
def test_reviewer_false_edges_keep_the_call_without_following_body(tmp_path,label,file,symbol,source,spelling):
 assert_honest_call(scan(tmp_path,file,source,symbol),spelling)


def test_reviewer_nested_import_scope(tmp_path):
 (tmp_path/'good.py').write_text('def helper():\n    actual.frob()\n')
 (tmp_path/'bad.py').write_text('def helper():\n    unrelated.frob()\n')
 result=scan(tmp_path,'app.py','from good import helper\ndef entry():\n    helper()\ndef hidden():\n    from bad import helper\n')
 assert not result.analysis_errors
 assert {c.invocation.callee_expression for c in result.claims}=={'helper','actual.frob'}
 call=next(c for c in result.graph.invocations.values() if c.callee_spelling=='helper')
 assert call.resolution_certainty==ResolutionCertainty.RESOLVED
 assert call.resolved_callee_identity=='good.helper'


@pytest.mark.parametrize('kind',[RootKind.MODEL_CALLABLE,RootKind.PROGRAM_ENTRY,RootKind.RESOURCE_ENTRY])
def test_reviewer_conditional_imports_all_roots(tmp_path,kind):
 (tmp_path/'left.py').write_text('def run():\n    unrelated.frob()\n')
 (tmp_path/'right.py').write_text('def run():\n    unrelated.frob()\n')
 (tmp_path/'app.py').write_text('@tool\ndef entry(flag):\n    if flag:\n        from left import run as chosen\n    else:\n        from right import run as chosen\n    chosen()\n')
 kwargs={} if kind==RootKind.MODEL_CALLABLE else {'entrypoints':[Entrypoint('app.py','entry',kind)],'discover_roots':False}
 result=scan_effect_claims(tmp_path,**kwargs)
 assert_honest_call(result,'chosen')
 assert len(result.claims)==1
 call=next(iter(result.graph.invocations.values()))
 assert {t.symbol for t in call.possible_implementations if t.file}=={'left.run','right.run'}


@pytest.mark.parametrize('file,source,symbol,spelling',[
 ('app.py','class Service:\n    def helper(self):\n        actual.frob()\n    def entry(self):\n        self.helper()\n','Service.entry','self.helper'),
 ('app.ts','class Service { helper() { actual.frob(); } entry() { this.helper(); } }','Service.entry','this.helper'),
 ('app.go','package main\ntype Service struct {}\nfunc (s *Service) helper() { actual.frob() }\nfunc (s *Service) entry() { s.helper() }\n','Service.entry','s.helper'),
])
def test_direct_receiver_positive(tmp_path,file,source,symbol,spelling):
 result=scan(tmp_path,file,source,symbol)
 assert not result.analysis_errors
 call=next(c for c in result.graph.invocations.values() if c.callee_spelling==spelling)
 assert call.resolution_certainty==ResolutionCertainty.RESOLVED
 assert len(result.claims)==2
 assert any(c.invocation.callee_expression=='actual.frob' for c in result.claims)


PYTHON_SHADOWS=[
 ('parameter','def entry(helper):\n    helper()\n'),
 ('assign','def entry(value):\n    helper = value\n    helper()\n'),
 ('annotated','def entry(value):\n    helper: object = value\n    helper()\n'),
 ('tuple','def entry(values):\n    helper, other = values\n    helper()\n'),
 ('list','def entry(values):\n    [helper, other] = values\n    helper()\n'),
 ('local_import','def entry():\n    from unknown import helper\n    helper()\n'),
 ('local_class','def entry():\n    class helper:\n        pass\n    helper()\n'),
 ('loop','def entry(values):\n    for helper in values:\n        helper()\n'),
 ('with','def entry(value):\n    with value as helper:\n        helper()\n'),
 ('except','def entry():\n    try:\n        pass\n    except Exception as helper:\n        helper()\n'),
 ('lambda_parameter','def entry():\n    inner = lambda helper: helper()\n    inner\n'),
]
@pytest.mark.parametrize('label,source',PYTHON_SHADOWS,ids=[x[0] for x in PYTHON_SHADOWS])
def test_python_lexical_bindings_do_not_fall_through(tmp_path,label,source):
 source+='def helper():\n    unrelated.frob()\n'
 if label=='lambda_parameter':
  result=scan(tmp_path,'app.py',source,'entry.<lambda@2:13>')
 else:
  result=scan(tmp_path,'app.py',source)
 assert_honest_call(result,'helper')


TS_SHADOWS=[
 ('const','const helper = obj;'),
 ('let','let helper = obj;'),
 ('var','var helper = obj;'),
 ('arrow','const helper = () => {};'),
 ('object','const { helper } = obj;'),
 ('object_alias','const { source: helper } = obj;'),
 ('object_nested','const { nested: { helper } } = obj;'),
 ('object_rest','const { ...helper } = obj;'),
 ('array','const [helper] = obj;'),
 ('array_rest','const [...helper] = obj;'),
 ('local_class','class helper {}'),
 ('catch','try {} catch(helper) { helper(); }'),
]
@pytest.mark.parametrize('label,declaration',TS_SHADOWS,ids=[x[0] for x in TS_SHADOWS])
def test_ts_lexical_bindings_do_not_fall_through(tmp_path,label,declaration):
 source='function entry(obj: any) { '+declaration+' helper(); }\nfunction helper() { unrelated.frob(); }\n'
 result=scan(tmp_path,'app.ts',source)
 assert not result.analysis_errors
 assert not any(c.invocation.callee_expression=='unrelated.frob' for c in result.claims)
 assert any(c.invocation.callee_expression=='helper' for c in result.claims)
 # A directly initialized arrow may be followed, but never the global helper.
 if label!='arrow':
  assert all(c.resolution_certainty!=ResolutionCertainty.RESOLVED for c in result.graph.invocations.values() if c.callee_spelling=='helper')


GO_SHADOWS=[
 ('short','helper := value'),
 ('short_multiple','helper, other := value, value; _ = other'),
 ('var','var helper func()'),
 ('var_value','var helper = value'),
 ('var_group','var (helper = value;)'),
 ('range','for helper := range values { helper() }'),
 ('range_pair','for _, helper := range values { helper() }'),
]
@pytest.mark.parametrize('label,declaration',GO_SHADOWS,ids=[x[0] for x in GO_SHADOWS])
def test_go_lexical_bindings_do_not_fall_through(tmp_path,label,declaration):
 source='package main\nfunc entry() { '+declaration+'; helper() }\nfunc helper() { unrelated.frob() }\n'
 result=scan(tmp_path,'app.go',source)
 assert not result.analysis_errors
 assert not any(c.invocation.callee_expression=='unrelated.frob' for c in result.claims)
 assert any(c.invocation.callee_expression=='helper' for c in result.claims)
 assert all(c.resolution_certainty!=ResolutionCertainty.RESOLVED for c in result.graph.invocations.values() if c.callee_spelling=='helper')


@pytest.mark.parametrize('file,source,symbol,spelling',[
 ('app.py','class Service:\n    @staticmethod\n    def entry(self):\n        self.helper()\n    def helper(self):\n        unrelated.frob()\n','Service.entry','self.helper'),
 ('app.py','class Service:\n    def entry(self, value):\n        self = value\n        self.helper()\n    def helper(self):\n        unrelated.frob()\n','Service.entry','self.helper'),
 ('app.ts','class Service { entry() { function inner() { this.helper(); } inner(); } helper() { unrelated.frob(); } }','Service.entry','this.helper'),
 ('app.go','package main\ntype Service struct{}\nfunc (s *Service) entry() { s.client.helper() }\nfunc (s *Service) helper() { unrelated.frob() }\n','Service.entry','s.client.helper'),
 ('app.go','package main\ntype Service struct{}\nfunc (s *Service) entry(value *Service) { s = value; s.helper() }\nfunc (s *Service) helper() { unrelated.frob() }\n','Service.entry','s.helper'),
])
def test_receiver_evidence_cannot_be_invented_or_survive_rebinding(tmp_path,file,source,symbol,spelling):
 assert_honest_call(scan(tmp_path,file,source,symbol),spelling)


@pytest.mark.parametrize('source',[
 'if flag:\n    from left import run\nelse:\n    from right import run\ndef entry():\n    run()\n',
 'from left import run\nfrom right import run\ndef entry():\n    run()\n',
])
def test_module_import_alternatives_are_not_last_binding_wins(tmp_path,source):
 for name in ['left','right']:
  (tmp_path/(name+'.py')).write_text('def run():\n    unrelated.frob()\n')
 result=scan(tmp_path,'app.py',source)
 assert_honest_call(result,'run')
 assert len(result.claims)==1
 assert {t.symbol for t in next(iter(result.graph.invocations.values())).possible_implementations if t.file}=={'left.run','right.run'}


@pytest.mark.parametrize('file,source',[
 ('app.py','def entry():\n    def helper():\n        actual.frob()\n    helper()\ndef helper():\n    unrelated.frob()\n'),
 ('app.ts','function entry() { function helper() { actual.frob(); } helper(); }\nfunction helper() { unrelated.frob(); }\n'),
])
def test_nested_function_declaration_is_its_own_binding(tmp_path,file,source):
 result=scan(tmp_path,file,source)
 assert not result.analysis_errors
 assert {c.invocation.callee_expression for c in result.claims}=={'helper','actual.frob'}


def test_import_target_rebinding_does_not_invent_exactness(tmp_path):
 (tmp_path/'helper.py').write_text('def run():\n    unrelated.frob()\nrun = unknown\n')
 result=scan(tmp_path,'app.py','from helper import run\ndef entry():\n    run()\n')
 assert_honest_call(result,'run')

@pytest.mark.parametrize('file,source,symbol,spelling',[
 ('app.py','class Service:\n    def entry(self, value):\n        self.helper = value\n        self.helper()\n    def helper(self):\n        unrelated.frob()\n','Service.entry','self.helper'),
 ('app.ts','class Service { helper() { unrelated.frob(); } entry(value: any) { this.helper = value; this.helper(); } }','Service.entry','this.helper'),
 ('app.ts','class Service { helper() { unrelated.frob(); } entry() { let [helper] = obj; helper(); } }','Service.entry','helper'),
 ('app.ts','function entry() { const inner = helper => helper(); inner(unknown); }\nfunction helper() { unrelated.frob(); }','entry','helper'),
])
def test_receiver_member_stores_and_arrow_parameter_shadowing(tmp_path,file,source,symbol,spelling):
 assert_honest_call(scan(tmp_path,file,source,symbol),spelling)


def test_class_body_calls_remain_owned_by_the_executing_entrypoint(tmp_path):
 result=scan(tmp_path,'app.py','def entry():\n    class Service:\n        state = actual.frob()\n        def hidden(self):\n            unrelated.frob()\n')
 assert not result.analysis_errors
 assert [c.invocation.callee_expression for c in result.claims]==['actual.frob']


def test_go_package_candidates_across_files_remain_set_valued(tmp_path):
 (tmp_path/'one.go').write_text('package main\nfunc helper() { unrelated.frob() }\n')
 result=scan(tmp_path,'app.go','package main\nfunc entry() { helper() }\nfunc helper() { unrelated.frob() }\n')
 assert_honest_call(result,'helper')
 assert {t.file for t in next(iter(result.graph.invocations.values())).possible_implementations if t.file}=={'one.go','app.go'}


def test_python_function_cannot_be_mistaken_for_a_same_named_submodule(tmp_path):
 (tmp_path/'pkg').mkdir()
 (tmp_path/'pkg'/'__init__.py').write_text('def local():\n    pass\n')
 (tmp_path/'pkg'/'local.py').write_text('def run():\n    unrelated.frob()\n')
 result=scan(tmp_path,'app.py','from pkg import local\ndef entry():\n    local.run()\n')
 assert_honest_call(result,'local.run')


def test_ts_scoped_import_resolution_uses_the_importer_directory(tmp_path):
 (tmp_path/'sub').mkdir()
 (tmp_path/'helper.ts').write_text('export function run() { unrelated.frob(); }')
 (tmp_path/'sub'/'helper.ts').write_text('export function run() { actual.frob(); }')
 result=scan(tmp_path,'sub/app.ts','import { run as invoke } from "./helper";\nfunction entry() { invoke(); }')
 assert not result.analysis_errors
 assert {c.invocation.callee_expression for c in result.claims}=={'invoke','actual.frob'}


def test_ts_target_rebinding_keeps_an_unresolved_claim(tmp_path):
 (tmp_path/'helper.ts').write_text('export function run() { unrelated.frob(); }\nrun = unknown;')
 result=scan(tmp_path,'app.ts','import { run } from "./helper";\nfunction entry() { run(); }')
 assert_honest_call(result,'run')


def test_python_import_cycle_terminates_without_picking_a_body(tmp_path):
 (tmp_path/'left.py').write_text('from right import run\n')
 (tmp_path/'right.py').write_text('from left import run\n')
 result=scan(tmp_path,'app.py','from left import run\ndef entry():\n    run()\n')
 assert_honest_call(result,'run')

@pytest.mark.parametrize('declaration',[
 'for (const helper of values) { helper(); }',
 'for (let { helper } of values) { helper(); }',
 '{ function helper() { unrelated.frob(); } } helper();',
 '{ const helper = () => unrelated.frob(); } helper();',
])
def test_ts_loop_and_block_declarations_are_conservatively_scoped(tmp_path,declaration):
 result=scan(tmp_path,'app.ts','function entry(values: any) { '+declaration+' }\nfunction helper() { unrelated.frob(); }')
 assert not result.analysis_errors
 assert not any(c.invocation.callee_expression=='unrelated.frob' for c in result.claims)
 assert any(c.invocation.callee_expression=='helper' for c in result.claims)
 assert all(c.resolution_certainty!=ResolutionCertainty.RESOLVED for c in result.graph.invocations.values() if c.callee_spelling=='helper')


def test_python_receiver_uses_class_declaration_identity(tmp_path):
 result=scan(tmp_path,'app.py','class Service:\n    def entry(self):\n        self.helper()\n    def helper(self):\n        actual.frob()\nclass Service:\n    def helper(self):\n        unrelated.frob()\n','Service.entry')
 assert not result.analysis_errors
 assert {c.invocation.callee_expression for c in result.claims}=={'self.helper','actual.frob'}


def test_lexical_import_resolution_budget_is_an_analysis_error(tmp_path):
 from actenon_scan.effects import Obligation
 for i in range(35):
  (tmp_path/f'm{i}.py').write_text(f'from m{i+1} import run\n')
 (tmp_path/'m35.py').write_text('def run():\n    unrelated.frob()\n')
 result=scan(tmp_path,'app.py','from m0 import run\ndef entry():\n    run()\n')
 assert result.analysis_errors
 assert any('max_lexical_binding_depth' in error for _,error in result.analysis_errors)
 assert len(result.claims)==1
 assert result.claims[0].verdict==Verdict.ANALYSIS_ERROR
 assert result.claims[0].obligations[Obligation.IMPLEMENTATION]==ProofState.ERROR


def test_python_class_lambda_does_not_capture_the_class_namespace(tmp_path):
 source='class Service:\n    def helper(self):\n        unrelated.frob()\n    value = lambda: helper()\n'
 result=scan(tmp_path,'app.py',source,'Service.<lambda@4:13>')
 assert_honest_call(result,'helper')
