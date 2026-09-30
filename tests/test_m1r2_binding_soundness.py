"""Regression controls for the repeat independent M1 review."""
import pytest

from actenon_scan import Entrypoint, RootKind, scan_effect_claims
from actenon_scan.effects import ProofState, Verdict
from actenon_scan.repository.symbol_index import ResolutionCertainty


def scan(tmp_path, file, source, symbol="entry", kind=RootKind.PROGRAM_ENTRY):
    (tmp_path / file).write_text(source)
    result = scan_effect_claims(
        tmp_path, entrypoints=[Entrypoint(file, symbol, kind)], discover_roots=False,
    )
    assert not result.analysis_errors
    return result


def sites(result, spelling):
    return [c for c in result.graph.invocations.values() if c.callee_spelling == spelling]


def honest(result, spelling, exact=False):
    calls = sites(result, spelling)
    assert calls
    for call in calls:
        if not exact:
            assert call.resolution_certainty != ResolutionCertainty.RESOLVED
            assert call.resolved_callee_identity is None
        claims = [c for c in result.claims if c.invocation_id == call.invocation_id]
        assert claims
        assert all(c.verdict == Verdict.ABSTAIN for c in claims)
        assert all(s == ProofState.UNKNOWN for c in claims for _, s in c.obligations.items())
    assert not any(c.callee_spelling.startswith("unrelated.") for c in result.graph.invocations.values())


REVIEW_CASES = [
    ("named_expression", "app.ts", "entry", "function helper() { unrelated.frob(); }\nfunction entry() { const invoke = function helper(n = 1) { if (n > 0) helper(n - 1); }; invoke(); }", "helper", True),
    ("type_switch", "app.go", "entry", "package main\nfunc helper() { unrelated.Frob() }\nfunc entry(value any) { switch helper := value.(type) { case func(): helper() } }", "helper", False),
    ("decorator", "app.py", "entry", "def replace(original):\n    return lambda: None\n@replace\ndef helper():\n    unrelated.frob()\ndef entry():\n    helper()\n", "helper", False),
    ("generator_ownership", "app.ts", "entry", "function entry() { function* hidden() { unrelated.frob(); yield 1; } visible.frob(); }", "visible.frob", False),
    ("static_instance", "app.ts", "Service.entry", "class Service { [key: string]: any; static helper() { unrelated.frob(); } entry() { this.helper(); } }", "this.helper", False),
    ("outer_assignment", "app.ts", "entry", "function helper() { unrelated.frob(); }\nfunction replace() { helper = () => {}; }\nfunction entry() { replace(); helper(); }", "helper", False),
]


@pytest.mark.parametrize("kind", [RootKind.MODEL_CALLABLE, RootKind.PROGRAM_ENTRY, RootKind.RESOURCE_ENTRY])
@pytest.mark.parametrize("label,file,symbol,source,spelling,exact", REVIEW_CASES, ids=[c[0] for c in REVIEW_CASES])
def test_repeat_review_failures(tmp_path, kind, label, file, symbol, source, spelling, exact):
    result = scan(tmp_path, file, source, symbol, kind)
    honest(result, spelling, exact)
    if label == "named_expression":
        invoke, recursive = sites(result, "invoke")[0], sites(result, "helper")[0]
        assert recursive.resolution_certainty == ResolutionCertainty.RESOLVED
        assert recursive.possible_implementations[0].callable_key == invoke.possible_implementations[0].callable_key
    if label == "generator_ownership":
        assert result.coverage["invocations_enumerated"] == 2
        assert result.coverage["invocations_reached"] == 1
    if label == "decorator":
        assert any(t.symbol == "app.helper" for t in sites(result, "helper")[0].possible_implementations)


@pytest.mark.parametrize("file,source,symbol,spelling", [
    ("app.ts", "function helper() { unrelated.frob(); } function entry() { const invoke = function helper() { helper(); }; invoke(); }", "entry", "helper"),
    ("app.ts", "function helper() { unrelated.frob(); } function entry() { const invoke = function helper(helper: any) { helper(); }; invoke(unknown); }", "entry", "helper"),
    ("app.go", "package main\nfunc helper() { unrelated.Frob() }\nfunc entry(value any) { switch helper := value.(type) { case func(): helper(); default: _ = helper } }", "entry", "helper"),
    ("app.py", "def replace(original):\n    return lambda: None\nclass Service:\n    @replace\n    def helper(self):\n        unrelated.frob()\n    def entry(self):\n        self.helper()\n", "Service.entry", "self.helper"),
    ("app.py", "def factory():\n    return unknown\n@factory()\ndef helper():\n    unrelated.frob()\ndef entry():\n    helper()\n", "entry", "helper"),
    ("app.ts", "function entry() { const hidden = function* () { unrelated.frob(); }; visible.frob(); }", "entry", "visible.frob"),
    ("app.ts", "function* helper() { unrelated.frob(); yield 1; } function entry() { helper(); }", "entry", "helper"),
    ("app.ts", "function entry() { const helper = function* internal() { unrelated.frob(); }; helper(); }", "entry", "helper"),
    ("app.ts", "class Service { *helper() { unrelated.frob(); } entry() { this.helper(); } }", "Service.entry", "this.helper"),
    ("app.py", "def helper():\n    unrelated.frob()\n    yield 1\ndef entry():\n    helper()\n", "entry", "helper"),
    ("app.ts", "function replace() { helper = () => {}; } function helper() { unrelated.frob(); } function entry() { replace(); helper(); }", "entry", "helper"),
    ("app.ts", "function entry() { function helper() { unrelated.frob(); } function replace() { helper = () => {}; } replace(); helper(); }", "entry", "helper"),
    ("app.ts", "function helper() { unrelated.frob(); } function replace() { helper += unknown; } function entry() { replace(); helper(); }", "entry", "helper"),
    ("app.ts", "function helper() { unrelated.frob(); } function replace() { helper++; } function entry() { replace(); helper(); }", "entry", "helper"),
    ("app.ts", "function helper() { unrelated.frob(); } function replace() { [helper] = values; } function entry() { replace(); helper(); }", "entry", "helper"),
    ("app.ts", "function helper() { unrelated.frob(); } function replace() { { let helper; } helper = () => {}; } function entry() { replace(); helper(); }", "entry", "helper"),
    ("app.ts", "function helper() { unrelated.frob(); } function replace() { try {} catch(helper) {} helper = () => {}; } function entry() { replace(); helper(); }", "entry", "helper"),
    ("app.ts", "function helper() { unrelated.frob(); } function replace() { for (let helper of values) {} helper = () => {}; } function entry() { replace(); helper(); }", "entry", "helper"),
    ("app.ts", "class Service { helper() { unrelated.frob(); } } function outer() { class Service { entry() { this.helper(); } } }", "Service.entry", "this.helper"),
])
def test_binding_and_ownership_variants(tmp_path, file, source, symbol, spelling):
    result = scan(tmp_path, file, source, symbol)
    # The internal name of an ordinary function expression is an exact self edge.
    recursive = "const invoke = function helper()" in source
    honest(result, spelling, recursive)
    if recursive:
        assert sites(result, spelling)[0].resolution_certainty == ResolutionCertainty.RESOLVED


@pytest.mark.parametrize("source", [
    "function helper() { visible.frob(); } function change(helper: any) { helper = unknown; } function entry() { change(unknown); helper(); }",
    "function helper() { visible.frob(); } function change() { let helper; helper = unknown; } function entry() { change(); helper(); }",
    "function helper() { visible.frob(); } function change() { var helper; helper = unknown; } function entry() { change(); helper(); }",
    "class Service { static helper() { unrelated.frob(); } helper() { visible.frob(); } entry() { this.helper(); } }",
    "class Service { static helper = unknown; helper() { visible.frob(); } entry() { this.helper(); } }",
])
def test_unmodified_outer_and_instance_bindings_stay_exact(tmp_path, source):
    method = source.startswith("class")
    spelling, symbol = ("this.helper", "Service.entry") if method else ("helper", "entry")
    result = scan(tmp_path, "app.ts", source, symbol)
    honest(result, spelling, True)
    assert sites(result, spelling)[0].resolution_certainty == ResolutionCertainty.RESOLVED
    assert sites(result, "visible.frob")


def test_named_expression_name_does_not_leak_to_enclosing_scope(tmp_path):
    result = scan(tmp_path, "app.ts", "function helper() { visible.frob(); } function entry() { const invoke = function helper() {}; invoke(); helper(); }")
    assert sites(result, "helper")[0].resolved_callee_identity == "app.helper"
    assert sites(result, "visible.frob")


def test_go_type_switch_alias_does_not_change_unshadowed_package_binding(tmp_path):
    result = scan(tmp_path, "app.go", "package main\nfunc helper() { visible.Frob() }\nfunc hidden(value any) { switch helper := value.(type) { case func(): helper() } }\nfunc entry() { helper() }")
    assert sites(result, "helper")[0].resolution_certainty == ResolutionCertainty.RESOLVED
    assert sites(result, "visible.Frob")


def test_nested_generator_does_not_make_ordinary_python_body_deferred(tmp_path):
    result = scan(tmp_path, "app.py", "def helper():\n    def hidden():\n        unrelated.frob()\n        yield 1\n    visible.frob()\ndef entry():\n    helper()\n")
    honest(result, "helper", True)
    assert sites(result, "helper")[0].resolution_certainty == ResolutionCertainty.RESOLVED
    assert sites(result, "visible.frob")


@pytest.mark.parametrize("source", [
    "function entry() { helper(); const helper = () => unrelated.frob(); }",
    "function entry() { helper(); const helper = function() { unrelated.frob(); }; }",
    "function entry() { helper(); let helper = () => unrelated.frob(); }",
    "function entry() { function invoke() { helper(); } invoke(); const helper = () => unrelated.frob(); }",
])
def test_local_initializer_is_not_established_before_the_call(tmp_path, source):
    honest(scan(tmp_path, "app.ts", source), "helper")


@pytest.mark.parametrize("source,symbol,spelling", [
    ("async def helper():\n    unrelated.frob()\ndef entry():\n    helper()\n", "entry", "helper"),
    ("class Service:\n    async def helper(self):\n        unrelated.frob()\n    def entry(self):\n        self.helper()\n", "Service.entry", "self.helper"),
    ("async def helper():\n    unrelated.frob()\nasync def wrapper(value):\n    pass\nasync def entry():\n    await wrapper(helper())\n", "entry", "helper"),
])
def test_coroutine_creation_does_not_establish_body_execution(tmp_path, source, symbol, spelling):
    honest(scan(tmp_path, "app.py", source, symbol), spelling)


@pytest.mark.parametrize("source,symbol,spelling", [
    ("async def helper():\n    visible.frob()\nasync def entry():\n    await helper()\n", "entry", "helper"),
    ("class Service:\n    async def helper(self):\n        visible.frob()\n    async def entry(self):\n        await self.helper()\n", "Service.entry", "self.helper"),
])
def test_direct_await_of_exact_coroutine_preserves_valid_resolution(tmp_path, source, symbol, spelling):
    result = scan(tmp_path, "app.py", source, symbol)
    assert sites(result, spelling)[0].resolution_certainty == ResolutionCertainty.RESOLVED
    assert sites(result, "visible.frob")


def test_direct_await_keeps_import_provenance_and_decorator_uncertainty(tmp_path):
    (tmp_path / "helper.py").write_text("async def run():\n    visible.frob()\n")
    result = scan(tmp_path, "app.py", "from helper import run\nasync def entry():\n    await run()\n")
    assert sites(result, "run")[0].resolution_certainty == ResolutionCertainty.RESOLVED
    assert sites(result, "visible.frob")
    (tmp_path / "helper.py").write_text("@unknown\nasync def run():\n    unrelated.frob()\n")
    result = scan(tmp_path, "app.py", "from helper import run\nasync def entry():\n    await run()\n")
    honest(result, "run")
