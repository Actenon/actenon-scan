"""Independent evidence authority, generated combinations and metamorphic checks."""
from itertools import product

import pytest

from actenon_scan import Entrypoint, RootKind, scan_effect_claims
from actenon_scan.effects import ProofState, Verdict
from actenon_scan.invocation_graph import GraphLimits


def scan(tmp_path, file, source, symbol="entry", kind=RootKind.PROGRAM_ENTRY, **kwargs):
    (tmp_path / file).write_text(source)
    result = scan_effect_claims(tmp_path, entrypoints=[Entrypoint(file, symbol, kind)],
                                discover_roots=False, **kwargs)
    assert not result.analysis_errors
    return result


def calls(result, spelling):
    return [c for c in result.graph.invocations.values() if c.callee_spelling == spelling]


def established(call):
    return {b.candidate_id for b in call.binding_claims if b.state.value == "ESTABLISHED"}


def honest(result, spelling, expected):
    sites = calls(result, spelling)
    assert sites, "uncertain calls must survive"
    for call in sites:
        assert bool(established(call)) == expected
        assert call.lexical_scope_id and call.execution_owner_key == call.caller_key
        assert all(b.subject == call.invocation_id for b in call.binding_claims)
        assert all(b.positive_evidence for b in call.binding_claims if b.state.value == "ESTABLISHED")
        claims = [c for c in result.claims if c.invocation_id == call.invocation_id]
        assert claims and all(c.verdict == Verdict.ABSTAIN for c in claims)
        assert all(s == ProofState.UNKNOWN for c in claims for _, s in c.obligations.items())
    assert bool(calls(result, "marker.hit")) == expected


def program(language, scope, binding, callable_kind, shadow, write):
    """192 supported products, with an explicit reachability oracle."""
    if language == "python":
        target = "def target():\n    marker.hit()" if callable_kind == "declared" else "target = lambda: marker.hit()"
        declaration = {"direct": target.replace("target", "helper"),
                       "alias": target + "\nhelper = target", "dynamic": "helper = opaque.value"}[binding]
        statements = (["helper = opaque.value"] if shadow else []) + (["helper = opaque.other"] if write else []) + ["helper()"]
        if scope == "module":
            source = declaration + "\ndef entry():\n" + "\n".join("    " + x for x in statements)
        elif scope == "local":
            source = "def entry():\n" + "\n".join("    " + x for x in (declaration.splitlines() + statements))
        else:
            source = "def entry():\n" + "\n".join("    " + x for x in declaration.splitlines())
            source += "\n    def inner():\n" + "\n".join("        " + x for x in statements) + "\n    inner()"
        return "app.py", source
    if language == "typescript":
        target = "function target(){marker.hit();}" if callable_kind == "declared" else "const target=()=>marker.hit();"
        declaration = {"direct": target.replace("target", "helper"), "alias": target + " const helper=target;",
                       "dynamic": "const helper=opaque.value;"}[binding]
        # Local shadows are separate declarations, writes target existing names.
        shadow_text = "let helper=opaque.value;" if shadow and scope != "local" else ""
        if shadow and scope == "local":
            shadow_text = "{let helper=opaque.value;"
        statements = shadow_text + ("helper=opaque.other;" if write else "") + "helper();" + ("}" if shadow and scope == "local" else "")
        source = (declaration + " function entry(){" + statements + "}" if scope == "module" else
                  "function entry(){" + declaration + statements + "}" if scope == "local" else
                  "function entry(){" + declaration + " function inner(){" + statements + "} inner();}")
        return "app.ts", source
    # Go module-level literals use var, callable declarations only at module level.
    target = ("func target(){marker.hit()}" if scope == "module" and callable_kind == "declared" else
              ("var target = func(){marker.hit()}" if scope == "module" else "target := func(){marker.hit()}"))
    alias = "var helper = target" if scope == "module" else "helper := target"
    unknown = "var helper = opaque.value" if scope == "module" else "helper := opaque.value"
    declaration = {"direct": target.replace("target", "helper"), "alias": target + "\n" + alias, "dynamic": unknown}[binding]
    statements = ("var helper = opaque.value;" if shadow and scope != "local" else "") + ("helper=opaque.other;" if write or (shadow and scope == "local") else "") + "helper()"
    source = (declaration + "\nfunc entry(){" + statements + "}" if scope == "module" else
              "func entry(){" + declaration + ";" + statements + "}" if scope == "local" else
              "func entry(){" + declaration + ";inner:=func(){" + statements + "};inner()}")
    return "app.go", "package main\n" + source


MATRIX = [case for case in product(["python", "typescript", "go"], ["module", "local", "captured"],
                      ["direct", "alias", "dynamic"], ["declared", "expression"], [False, True], [False, True])
          if not (case[0] == "go" and case[1] != "module" and case[3] == "declared")]


@pytest.mark.parametrize("language,scope,binding,callable_kind,shadow,write", MATRIX)
def test_adversarial_matrix(tmp_path, language, scope, binding, callable_kind, shadow, write):
    file, source = program(language, scope, binding, callable_kind, shadow, write)
    symbol = "entry"
    if language == "go" and scope == "captured":
        # Literal value dispatch is deliberately a frontier in this model.
        # Select the literal body explicitly to test its captured lexical scope.
        offset = source.index("func(){", source.index("inner:="))
        line = source[:offset].count("\n") + 1
        column = offset - source.rfind("\n", 0, offset)
        symbol = f"entry.<callback@{line}:{column}>"
    result = scan(tmp_path, file, source, symbol)
    # M1R3 now proves stable literal initializers with normalized write closure.
    expected = binding != "dynamic" and not shadow and not write
    honest(result, "helper", expected)


@pytest.mark.parametrize("language,compatible,write,chain", list(product(["python", "typescript", "go"], [False, True], [False, True], [False, True])))
def test_receiver_matrix(tmp_path, language, compatible, write, chain):
    if language == "python":
        decorated = "    @staticmethod\n" if not compatible else ""
        parameter = "" if not compatible else "self"
        source = "class Service:\n" + decorated + f"    def helper({parameter}):\n        marker.hit()\n    def entry(self):\n"
        source += ("        self.helper=opaque.value\n" if write else "") + "        self." + ("client." if chain else "") + "helper()\n"
        file, symbol, spelling = "app.py", "Service.entry", "self." + ("client." if chain else "") + "helper"
    elif language == "typescript":
        source = "class Service{" + ("static " if not compatible else "") + "helper(){marker.hit()} entry(){"
        source += ("this.helper=opaque.value;" if write else "") + "this." + ("client." if chain else "") + "helper();}}"
        file, symbol, spelling = "app.ts", "Service.entry", "this." + ("client." if chain else "") + "helper"
    else:
        receiver = "*Service" if compatible else "*Other"
        source = f"package main\nfunc(s {receiver}) helper(){{marker.hit()}}\nfunc(s *Service) entry(){{"
        source += ("s.helper=opaque.value;" if write else "") + "s." + ("client." if chain else "") + "helper()}"
        file, symbol, spelling = "app.go", "Service.entry", "s." + ("client." if chain else "") + "helper"
    honest(scan(tmp_path, file, source, symbol), spelling, compatible and not write and not chain)


@pytest.mark.parametrize("language", ["python", "typescript", "go"])
def test_metamorphic_unrelated_callable_and_file_order(tmp_path, language):
    file, source = program(language, "module", "direct", "declared", False, False)
    before = scan(tmp_path, file, source)
    suffix = file.split(".")[-1]
    other = "def helper():\n    forbidden.hit()" if language == "python" else "function helper(){forbidden.hit()}" if language == "typescript" else "package other\nfunc helper(){forbidden.hit()}"
    (tmp_path / ("unrelated." + suffix)).write_text(other)
    after = scan(tmp_path, file, source)
    assert established(calls(before, "helper")[0]) == established(calls(after, "helper")[0])
    assert not calls(after, "forbidden.hit")
    from actenon_scan.repository import invocation_adapters as adapters
    from unittest.mock import patch
    original = adapters._collect_sources
    with patch.object(adapters, "_collect_sources", side_effect=lambda *a: list(reversed(original(*a)))):
        reordered = scan(tmp_path, file, source)
    assert after.to_dict() == reordered.to_dict()


@pytest.mark.parametrize("language", ["python", "typescript", "go"])
def test_metamorphic_uncalled_wrapper(tmp_path, language):
    sources = {"python": ("app.py", "def entry():\n    def hidden():\n        forbidden.hit()\n    visible.hit()"),
               "typescript": ("app.ts", "function entry(){function* hidden(){forbidden.hit();yield 1;}visible.hit()}"),
               "go": ("app.go", "package main\nfunc entry(){hidden:=func(){forbidden.hit()};_ = hidden;visible.hit()}")}
    file, source = sources[language]
    result = scan(tmp_path, file, source)
    assert calls(result, "visible.hit") and not calls(result, "forbidden.hit")
    assert result.coverage["invocations_enumerated"] == 2


@pytest.mark.parametrize("language", ["python", "typescript", "go"])
@pytest.mark.parametrize("mutation", ["shadow", "write"])
def test_metamorphic_shadow_and_write(tmp_path, language, mutation):
    file, source = program(language, "module", "direct", "declared", False, False)
    before = scan(tmp_path, file, source)
    assert established(calls(before, "helper")[0])
    file, source = program(language, "module", "direct", "declared", mutation == "shadow", mutation == "write")
    after = scan(tmp_path, file, source)
    honest(after, "helper", False)


def test_metamorphic_unknown_decorator(tmp_path):
    plain = "def helper():\n    marker.hit()\ndef entry():\n    helper()"
    assert established(calls(scan(tmp_path, "app.py", plain), "helper")[0])
    decorated = "@unknown\n" + plain
    result = scan(tmp_path, "app.py", decorated)
    honest(result, "helper", False)
    assert any("UNKNOWN_DECORATOR" in [x.value for x in b.counter_evidence] for b in calls(result, "helper")[0].binding_claims)


def test_metamorphic_incompatible_static(tmp_path):
    source = "class Service{helper(){marker.hit()}entry(){this.helper()}}"
    assert established(calls(scan(tmp_path, "app.ts", source, "Service.entry"), "this.helper")[0])
    result = scan(tmp_path, "app.ts", source.replace("helper(){", "static helper(){", 1), "Service.entry")
    honest(result, "this.helper", False)
    assert any(b.state.value == "REFUTED" for b in calls(result, "this.helper")[0].binding_claims)


def test_counter_evidence_is_monotonic():
    from actenon_scan.binding_claims import BindingClaim, BindingEvidence, BindingState
    from actenon_scan.semantic_ir import BindingEdgeProof, BASE_OBLIGATIONS, SemanticState
    proof = BindingEdgeProof(facts=tuple((k, SemanticState.SUPPORTED) for k in BASE_OBLIGATIONS))
    claim = BindingClaim("site", "target", frozenset({BindingEvidence.LEXICAL_DECLARATION}), candidate_is_local=True, edge_proof=proof)
    assert claim.state == BindingState.ESTABLISHED
    unstable = claim.with_evidence(counter={BindingEvidence.REASSIGNMENT_WRITE})
    assert unstable.state == BindingState.POSSIBLE
    assert unstable.with_evidence(positive={BindingEvidence.STRUCTURALLY_EXACT_ALIAS}).state == BindingState.POSSIBLE
    assert unstable.counter_evidence <= unstable.with_evidence(positive={BindingEvidence.IMPORT_PROVENANCE}).counter_evidence


def test_resolution_projection_cannot_authorize_traversal(tmp_path):
    from actenon_scan.repository.symbol_index import ResolutionCertainty
    result = scan(tmp_path, "app.py", "def helper():\n    marker.hit()\ndef entry():\n    helper()")
    call = calls(result, "helper")[0]
    call.binding_claims = ()
    call.resolution_certainty = ResolutionCertainty.RESOLVED
    from actenon_scan.invocation_graph import InvocationGraph
    graph = InvocationGraph(roots=result.graph.roots)
    graph.traverse(list(result.graph.invocations.values()), GraphLimits())
    assert all(c.callee_spelling != "marker.hit" for c in graph.invocations.values())


def test_nonlocal_write_finds_nearest_binding_across_empty_scope(tmp_path):
    source = '''def entry():
    def helper():
        marker.hit()
    def wrapper():
        def change():
            nonlocal helper
            helper = lambda: None
        change()
    wrapper()
    helper()
'''
    honest(scan(tmp_path, "app.py", source), "helper", False)


@pytest.mark.parametrize("file,source", [
    ("app.py", "def target():\n    marker.hit()\nalias=target\ndef change():\n    global target\n    target=opaque\ndef entry():\n    alias()"),
    ("app.ts", "function target(){marker.hit()}const alias=target;function change(){target=opaque}function entry(){alias()}"),
    ("app.go", "package main\nfunc target(){marker.hit()}\nvar alias=target\nfunc change(){target=opaque}\nfunc entry(){alias()}"),
])
def test_possible_source_write_downgrades_alias(tmp_path, file, source):
    # Without timeline proof, even a potentially captured earlier value stays possible.
    honest(scan(tmp_path, file, source), "alias", False)


def test_passes_do_not_enumerate_calls_during_scope_construction(tmp_path):
    import ast
    from actenon_scan.repository.invocation_adapters import _python_unit, _construct_execution_ownership
    from actenon_scan.repository.symbol_index import RepositoryIndex
    source = "def entry():\n    def hidden():\n        forbidden.hit()\n    visible.hit()"
    tree = ast.parse(source)
    index = RepositoryIndex(tmp_path)
    index.add_file("app.py", source, tree)
    unit = _python_unit("app.py", source, tree, index, {}, enumerate_calls=False)
    assert not unit.sites
    assert unit.bindings and unit.node_scopes
    _construct_execution_ownership(unit)
    assert len(unit.sites) == 2
    assert {s.owner.key for s in unit.sites} == {s.key for s in unit.symbols}
    assert all(s.lexical_scope for s in unit.sites)


@pytest.mark.parametrize("file,source,symbol,spelling", [
    ("app.py", "class Service:\n    def helper(self):\n        marker.hit()\n    def entry(self):\n        alias=self\n        alias.helper=opaque\n        self.helper()", "Service.entry", "self.helper"),
    ("app.ts", "class Service{helper(){marker.hit()}entry(){const alias=this;alias.helper=opaque;this.helper()}}", "Service.entry", "this.helper"),
])
def test_exact_receiver_alias_write_undermines_member_stability(tmp_path, file, source, symbol, spelling):
    honest(scan(tmp_path, file, source, symbol), spelling, False)


def test_imported_namespace_write_undermines_export_stability(tmp_path):
    (tmp_path / "helper.py").write_text("def run():\n    marker.hit()")
    source = "import helper as module\nfrom helper import run\ndef change():\n    alias=module\n    alias.run=opaque\ndef entry():\n    change()\n    run()"
    honest(scan(tmp_path, "app.py", source), "run", False)


@pytest.mark.parametrize("counter", ["AMBIGUOUS_DECLARATION", "CONDITIONAL_IMPORT", "UNKNOWN_DECORATOR", "REASSIGNMENT_WRITE", "UNRESOLVED_ALIAS", "INCOMPATIBLE_RECEIVER", "LEXICAL_SHADOW"])
def test_every_counter_fact_blocks_establishment_after_more_positive_facts(counter):
    from actenon_scan.binding_claims import BindingClaim, BindingEvidence as E, BindingState
    claim = BindingClaim("site", "target", frozenset({E.LEXICAL_DECLARATION}), candidate_is_local=True)
    blocked = claim.with_evidence(counter={E(counter)})
    for fact in (E.IMPORT_PROVENANCE, E.RECEIVER_IDENTITY, E.CALLABLE_SELF_BINDING, E.STRUCTURALLY_EXACT_ALIAS):
        blocked = blocked.with_evidence(positive={fact})
        assert blocked.state != BindingState.ESTABLISHED
        assert E(counter) in blocked.counter_evidence


def test_shadow_has_explicit_counter_evidence(tmp_path):
    result = scan(tmp_path, "app.py", "def helper():\n    marker.hit()\ndef entry(helper):\n    helper()")
    honest(result, "helper", False)
    assert any(b.state.value == "REFUTED" and any(e.value == "LEXICAL_SHADOW" for e in b.counter_evidence)
               for b in calls(result, "helper")[0].binding_claims)


def test_unknown_frontier_not_refuted_with_incompatible_named_candidate(tmp_path):
    result = scan(tmp_path, "app.ts", "class Service{static helper(){marker.hit()}entry(){this.helper()}}", "Service.entry")
    call = calls(result, "this.helper")[0]
    local = {t.candidate_id for t in call.possible_implementations if t.callable_key}
    assert any(b.state.value == "REFUTED" and b.candidate_id in local for b in call.binding_claims)
    assert any(b.state.value == "UNKNOWN" and b.candidate_id not in local for b in call.binding_claims)


@pytest.mark.parametrize("language", ["python", "typescript", "go"])
def test_root_kind_preserves_binding_claim_semantics(tmp_path, language):
    file, source = program(language, "module", "alias", "declared", False, False)
    results = [scan(tmp_path, file, source, kind=kind) for kind in
               [RootKind.MODEL_CALLABLE, RootKind.PROGRAM_ENTRY, RootKind.RESOURCE_ENTRY]]
    def core(result):
        return {key: (call.lexical_scope_id, call.execution_owner_key,
                      [b.to_dict() for b in call.binding_claims])
                for key, call in result.graph.invocations.items()}
    assert core(results[0]) == core(results[1]) == core(results[2])
    assert len({result.graph.roots[0].root_id for result in results}) == 3
    for result in results:
        honest(result, "helper", True)


def test_namespace_pass_failure_is_an_analysis_error(tmp_path, monkeypatch):
    from actenon_scan.repository import invocation_adapters as adapters
    def fail(*args):
        raise RuntimeError("injected namespace construction failure")
    monkeypatch.setattr(adapters, "_apply_namespace_writes", fail)
    (tmp_path / "app.py").write_text("def entry():\n    opaque.hit()")
    result = scan_effect_claims(tmp_path, entrypoints=[Entrypoint("app.py", "entry")], discover_roots=False)
    assert any("namespace construction failure" in message for _, message in result.analysis_errors)
    assert not result.claims


def test_possible_alternative_cannot_coexist_with_traversal_authority(tmp_path):
    from actenon_scan.binding_claims import BindingClaim
    result = scan(tmp_path, "app.py", "def helper():\n    marker.hit()\ndef entry():\n    helper()")
    call = calls(result, "helper")[0]
    assert call.established_targets
    call.binding_claims += (BindingClaim(call.invocation_id, "unresolved-alternative"),)
    assert not call.established_targets


@pytest.mark.parametrize("file,source", [
    ("app.go", "package main\nfunc helper(){marker.hit()}\nfunc entry(ch chan func()){select{case helper := <-ch:helper()}}"),
    ("app.ts", "function helper(){marker.hit()}function entry(){enum helper {value} helper()}"),
])
def test_additional_parser_declarations_cannot_fall_through(tmp_path, file, source):
    honest(scan(tmp_path, file, source), "helper", False)


def test_namespace_member_declaration_does_not_bind_outer_name(tmp_path):
    source = "function entry(){namespace Box {export function helper(){marker.hit()}}helper()}"
    honest(scan(tmp_path, "app.ts", source), "helper", False)


@pytest.mark.parametrize("declaration", ["func entry()(helper func()){helper();return}", "func entry(){const helper=1;helper()}"])
def test_all_go_signature_and_name_spec_bindings_block_outer_lookup(tmp_path, declaration):
    honest(scan(tmp_path, "app.go", "package main\nfunc helper(){marker.hit()}\n" + declaration), "helper", False)


def test_ambiguous_import_alias_preserves_all_candidates_under_index_order(tmp_path, monkeypatch):
    from actenon_scan.repository import invocation_adapters as adapters
    for module in ("left", "right"):
        (tmp_path / f"{module}.py").write_text("def target():\n    marker.hit()")
    source = "if flag:\n    from left import target\nelse:\n    from right import target\nalias=target\ndef entry():\n    alias()"
    before = scan(tmp_path, "app.py", source)
    honest(before, "alias", False)
    site = calls(before, "alias")[0]
    assert {t.symbol for t in site.possible_implementations if t.callable_key} == {"left.target", "right.target"}
    original = adapters._resolve_binding_claims
    def reverse(unit, site, identity, index, symbols, units):
        return original(unit, site, identity, index, list(reversed(symbols)), list(reversed(units)))
    monkeypatch.setattr(adapters, "_resolve_binding_claims", reverse)
    after = scan(tmp_path, "app.py", source)
    assert before.to_dict() == after.to_dict()


def test_retraversal_with_counter_evidence_removes_previous_body(tmp_path):
    from actenon_scan.binding_claims import BindingEvidence as E
    result = scan(tmp_path, "app.py", "def helper():\n    marker.hit()\ndef entry():\n    helper()")
    graph = result.graph
    all_calls = list(graph.invocations.values())
    call = calls(result, "helper")[0]
    call.binding_claims = tuple(b.with_evidence(counter={E.REASSIGNMENT_WRITE}) for b in call.binding_claims)
    graph.traverse(all_calls, GraphLimits())
    assert not calls(result, "marker.hit")
    assert graph.coverage["established_edges"] == 0
