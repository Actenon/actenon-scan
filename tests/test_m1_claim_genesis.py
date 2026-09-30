"""Sink-free falsifiers written before the M1 implementation."""
from dataclasses import asdict
import json

import pytest

from actenon_scan.claim_genesis import scan_effect_claims
from actenon_scan.invocation_graph import Entrypoint, GraphLimits, RootKind
from actenon_scan.effects import (
    CandidateKind, CoverageLedger, EffectClaim, Obligation, ProofState,
    SelectionState, Verdict,
)
from actenon_scan.engine import scan_path


SOURCES = {
    "python": ("app.py", "@tool\ndef entry(user_input):\n    helper(user_input)\n\n"
               "def helper(user_input):\n    mystery_client.frob(user_input)\n\n"
               "def hidden(user_input):\n    unreachable_client.frob(user_input)\n"),
    "typescript": ("app.ts", "function entry(user_input: any) { helper(user_input); }\n"
                   "function helper(user_input: any) { mystery_client.frob(user_input); }\n"
                   "function hidden(user_input: any) { unreachable_client.frob(user_input); }\n"
                   'server.tool("x", {}, entry);\n'),
    "go": ("app.go", "package main\nfunc entry(user_input string) { helper(user_input) }\n"
           "func helper(user_input string) { mystery_client.frob(user_input) }\n"
           "func hidden(user_input string) { unreachable_client.frob(user_input) }\n"
           'func init() { server.AddTool("x", entry) }\n'),
}


def write_source(tmp_path, language, rename=False):
    path, source = SOURCES[language]
    if rename:
        source = source.replace("mystery_client.frob", "totally_new_library.zqx")
    (tmp_path / path).write_text(source)
    return path


def unknown_claims(result):
    return [c for c in result.claims if c.invocation.callee_expression in
            {"mystery_client.frob", "totally_new_library.zqx"}]


@pytest.mark.parametrize("language", SOURCES)
@pytest.mark.parametrize("kind", [RootKind.MODEL_CALLABLE, RootKind.PROGRAM_ENTRY,
                                  RootKind.RESOURCE_ENTRY])
def test_all_root_kinds_and_languages_create_sink_free_claim(tmp_path, language, kind):
    path = write_source(tmp_path, language)
    roots = () if kind == RootKind.MODEL_CALLABLE else (Entrypoint(path, "entry", kind),)
    result = scan_effect_claims(tmp_path, entrypoints=roots,
                                discover_roots=kind == RootKind.MODEL_CALLABLE)
    assert result.analysis_errors == []
    assert result.unsupported_files == []
    assert len(result.graph.roots) == 1
    assert result.graph.roots[0].kind == kind
    (claim,) = unknown_claims(result)
    assert claim.verdict == Verdict.ABSTAIN
    assert claim.invocation.matched_rule_ids == ()
    assert {c.kind for c in claim.implementation_candidates} == {CandidateKind.OPAQUE_EXTERNAL}
    assert all(s == ProofState.UNKNOWN for _, s in claim.obligations.items())
    assert all(s == "UNKNOWN" for s in claim.descriptors.control.to_dict().values())
    assert claim.descriptors.authority.state == ProofState.UNKNOWN
    assert not any("unreachable_client" in c.invocation.callee_expression for c in result.claims)
    invocation = result.graph.invocations[claim.invocation_id]
    assert invocation.caller_symbol.endswith("helper")
    assert invocation.root_paths[claim.capability_id][-1] == claim.invocation_id
    assert len(invocation.root_paths[claim.capability_id]) == 2
    assert result.coverage["invocations_enumerated"] > result.coverage["invocations_reached"]
    assert result.ledger.claims.instantiated_without_any_rule_match == len(result.claims)
    assert EffectClaim.from_dict(claim.to_dict()) == claim
    assert CoverageLedger.from_dict(result.ledger.to_dict()) == result.ledger


@pytest.mark.parametrize("language", SOURCES)
def test_rename_and_rule_removal_do_not_change_claim_identity(tmp_path, language):
    path = write_source(tmp_path, language)
    before = scan_effect_claims(tmp_path)
    (claim,) = unknown_claims(before)
    site = claim.invocation.locator
    annotated = scan_effect_claims(tmp_path, matched_rule_ids={
        (path, site.start_line, site.start_column): ("OPTIONAL-PROVENANCE",)})
    assert unknown_claims(annotated)[0].identity == claim.identity
    assert unknown_claims(annotated)[0].invocation.matched_rule_ids == ("OPTIONAL-PROVENANCE",)
    write_source(tmp_path, language, rename=True)
    renamed = scan_effect_claims(tmp_path)
    assert unknown_claims(renamed)[0].identity == claim.identity
    assert unknown_claims(renamed)[0].invocation.matched_rule_ids == ()
    assert unknown_claims(renamed)[0].obligations == claim.obligations


@pytest.mark.parametrize("language", SOURCES)
def test_multi_candidate_resolution_is_set_valued_and_does_not_reach_helpers(tmp_path, language):
    snippets = {
        "python": (".py", "@tool\ndef entry(x):\n    candidate(x)\n",
                   "def candidate(x):\n    hidden.frob(x)\n"),
        "typescript": (".ts", 'function entry(x: any) { candidate(x); }\nserver.tool("x", {}, entry);\n',
                       "export function candidate(x: any) { hidden.frob(x); }\n"),
        "go": (".go", 'package main\nfunc entry(x string) { candidate(x) }\nfunc init() { server.AddTool("x", entry) }\n',
               "package other\nfunc candidate(x string) { hidden.frob(x) }\n"),
    }
    ext, source, helper = snippets[language]
    (tmp_path / ("app" + ext)).write_text(source)
    for directory in ("a", "b"):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / ("helper" + ext)).write_text(helper)
    result = scan_effect_claims(tmp_path)
    (claim,) = result.claims
    local = [c for c in claim.implementation_candidates if c.kind == CandidateKind.RESOLVED_LOCAL]
    assert len(local) == 2
    assert {c.locator.path for c in local} == {"a/helper" + ext, "b/helper" + ext}
    assert claim.selection_state == SelectionState.UNRESOLVED_IDENTITY
    assert claim.selected_candidate() is None
    assert claim.verdict == Verdict.ABSTAIN
    assert all(s == ProofState.UNKNOWN for _, s in claim.obligations.items())


@pytest.mark.parametrize("language", SOURCES)
def test_cycle_terminates_and_bound_is_disclosed(tmp_path, language):
    path = write_source(tmp_path, language)
    source = (tmp_path / path).read_text().replace("mystery_client.frob(user_input)", "entry(user_input)")
    (tmp_path / path).write_text(source)
    result = scan_effect_claims(tmp_path)
    assert len(result.claims) == 2
    assert result.coverage_gaps == []
    bounded = scan_effect_claims(tmp_path, limits=GraphLimits(max_depth=1))
    assert len(bounded.claims) == 1
    assert bounded.coverage_gaps


@pytest.mark.parametrize("path,source", [
    ("app.py", "@tool\ndef entry(:\n    mystery_client.frob(x)\n"),
    ("app.ts", 'server.tool("x", {}, (x) => { mystery_client.frob(x); '),
    ("app.go", 'package main\nfunc entry( { mystery_client.frob(x) }'),
])
def test_parser_failure_is_an_analysis_gap_not_abstain(tmp_path, path, source):
    (tmp_path / path).write_text(source)
    result = scan_effect_claims(tmp_path, entrypoints=[Entrypoint(path, "entry")])
    assert result.analysis_errors
    assert not result.claims
    assert result.coverage["analysis_errors"] > 0
    assert result.ledger.claims.instantiated == 0


def test_resolution_crash_is_analysis_error(tmp_path, monkeypatch):
    from actenon_scan.repository.symbol_index import RepositoryIndex
    write_source(tmp_path, "python")
    def broken(*args, **kwargs):
        raise RuntimeError("resolver failed")
    monkeypatch.setattr(RepositoryIndex, "resolve_call_target", broken)
    result = scan_effect_claims(tmp_path)
    assert result.analysis_errors
    assert result.claims
    assert all(c.verdict == Verdict.ANALYSIS_ERROR for c in result.claims)
    assert all(c.obligations[Obligation.IMPLEMENTATION] == ProofState.ERROR for c in result.claims)
    assert result.ledger.analysis_errors.total == len(result.claims)


def test_overlapping_roots_preserve_provenance_and_ledger(tmp_path):
    path = write_source(tmp_path, "python")
    result = scan_effect_claims(tmp_path, entrypoints=[Entrypoint(path, "entry", RootKind.RESOURCE_ENTRY)])
    assert len(result.graph.roots) == 2
    assert len(result.graph.invocations) == 2
    assert len(result.claims) == 4
    assert result.ledger.invocations.enumerated == 4
    assert len({c.capability_id for c in unknown_claims(result)}) == 2
    assert result.coverage["roots_discovered"] == result.coverage["roots_supplied"] == 1


def test_explicit_root_and_single_file_and_missing_root(tmp_path):
    path = write_source(tmp_path, "python")
    result = scan_effect_claims(tmp_path / path, entrypoints=[Entrypoint(path, "helper")],
                                discover_roots=False)
    assert len(unknown_claims(result)) == 1
    missing = scan_effect_claims(tmp_path, entrypoints=[Entrypoint(path, "absent")], discover_roots=False)
    assert missing.analysis_errors
    assert not missing.claims


def test_no_rule_configuration_is_needed_and_legacy_findings_stay_identical(tmp_path, monkeypatch):
    import actenon_scan.claim_genesis as genesis
    from actenon_scan.rules.loader import load_rules
    (tmp_path / "app.py").write_text("import subprocess\n@tool\ndef entry(x):\n    subprocess.run(x)\n    mystery_client.frob(x)\n")
    legacy = [asdict(f) for f in scan_path(tmp_path).findings]
    full = scan_effect_claims(tmp_path)
    rule_free = load_rules()
    rule_free.sinks.clear()
    monkeypatch.setattr(genesis, "load_rules", lambda *a, **k: rule_free)
    empty = scan_effect_claims(tmp_path)
    assert {c.identity for c in full.claims} == {c.identity for c in empty.claims}
    assert len(full.claims) == 2
    monkeypatch.undo()
    assert [asdict(f) for f in scan_path(tmp_path).findings] == legacy
    assert legacy


def test_cli_exposes_explicit_root_and_m0_json(tmp_path, capsys):
    from actenon_scan.cli import main
    path = write_source(tmp_path, "python")
    assert main(["claims", str(tmp_path), "--no-discover-roots", "--entrypoint",
                 path + ":entry:RESOURCE_ENTRY"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["graph"]["roots"][0]["kind"] == "RESOURCE_ENTRY"
    assert len(report["claims"]) == 2
    assert report["coverage_ledger"]["claims"]["instantiated_without_any_rule_match"] == 2


@pytest.mark.parametrize("language,source", [
    ("python", "def container():\n    @tool\n    def nested(x):\n        mystery_client.frob(x)\n"),
    ("typescript", 'server.tool("x", {}, (x: any) => { mystery_client.frob(x); const hidden = () => unreachable.frob(x); });'),
    ("go", 'package main\nfunc init() { server.AddTool("x", func(x string) { mystery_client.frob(x); hidden := func() { unreachable.frob(x) }; _ = hidden }) }'),
])
def test_nested_registered_callback_does_not_execute_uninvoked_nested_body(tmp_path, language, source):
    path = "app" + {"python": ".py", "typescript": ".ts", "go": ".go"}[language]
    (tmp_path / path).write_text(source)
    result = scan_effect_claims(tmp_path)
    assert len(unknown_claims(result)) == 1
    assert not any("unreachable" in c.invocation.callee_expression for c in result.claims)


@pytest.mark.parametrize("language,source,helper", [
    ("python", "@tool\ndef entry(helper):\n    helper()\n", "def helper():\n    unreachable.frob()\n"),
    ("typescript", 'function entry(helper: any) { helper(); }\nserver.tool("x", {}, entry);\n', "function helper() { unreachable.frob(); }\n"),
    ("go", 'package main\nfunc entry(helper func()) { helper() }\nfunc init() { server.AddTool("x", entry) }\n', "func helper() { unreachable.frob() }\n"),
])
def test_parameter_shadowing_does_not_resolve_to_same_named_local_function(tmp_path, language, source, helper):
    ext = {"python": ".py", "typescript": ".ts", "go": ".go"}[language]
    (tmp_path / ("app" + ext)).write_text(source + helper)
    result = scan_effect_claims(tmp_path)
    assert len(result.claims) == 1
    assert result.claims[0].implementation_candidates
    assert result.graph.coverage["resolved_local_calls"] == 0


@pytest.mark.parametrize("language,source,helper", [
    ("python", "from helper import run as invoke\n@tool\ndef entry(x):\n    invoke(x)\n", "def run(x):\n    mystery_client.frob(x)\n"),
    ("typescript", 'import { run as invoke } from "./helper";\nfunction entry(x: any) { invoke(x); }\nserver.tool("x", {}, entry);\n', "export function run(x: any) { mystery_client.frob(x); }\n"),
    ("go", 'package main\nfunc entry(x string) { run(x) }\nfunc init() { server.AddTool("x", entry) }\n', "package main\nfunc run(x string) { mystery_client.frob(x) }\n"),
])
def test_exact_cross_file_bindings_reach_unknown_call(tmp_path, language, source, helper):
    ext = {"python": ".py", "typescript": ".ts", "go": ".go"}[language]
    (tmp_path / ("app" + ext)).write_text(source)
    (tmp_path / ("helper" + ext)).write_text(helper)
    result = scan_effect_claims(tmp_path)
    assert len(unknown_claims(result)) == 1
    assert len(result.claims) == 2
    assert result.coverage["resolved_local_calls"] == 1


@pytest.mark.parametrize("limit", [GraphLimits(max_invocations=1), GraphLimits(max_files=0), GraphLimits(max_bytes=0)])
def test_resource_bounds_are_coverage_gaps(tmp_path, limit):
    write_source(tmp_path, "python")
    result = scan_effect_claims(tmp_path, limits=limit)
    assert result.coverage_gaps
    assert result.ledger.proven_effect == 0


def test_unsupported_language_and_missing_extra_are_disclosed(tmp_path, monkeypatch):
    (tmp_path / "app.rs").write_text("fn entry() { unknown(); }")
    from actenon_scan.repository.ts_symbol_index import TSRepositoryIndex
    write_source(tmp_path, "typescript")
    def unavailable(*a, **k):
        raise ImportError("parser extra missing")
    monkeypatch.setattr(TSRepositoryIndex, "add_file", unavailable)
    result = scan_effect_claims(tmp_path)
    assert {file for file, _ in result.unsupported_files} == {"app.rs", "app.ts"}
    assert not result.claims


def test_frozen_m0_schemas_accept_generated_claims_and_ledger(tmp_path):
    from tests.effect_claims.test_m0_schema_conformance import validator as ledger_validator
    from tests.effect_claims.test_m0r2_schema_conformance import validator
    write_source(tmp_path, "python")
    result = scan_effect_claims(tmp_path)
    for claim in result.claims:
        validator("effect_claim").validate(claim.to_dict())
    ledger_validator("coverage_ledger").validate(result.ledger.to_dict())


def test_import_in_unreachable_function_cannot_bind_entrypoint_call(tmp_path):
    (tmp_path / "app.py").write_text("@tool\ndef entry(x):\n    invoke(x)\ndef hidden():\n    from helper import run as invoke\n")
    (tmp_path / "helper.py").write_text("def run(x):\n    unreachable.frob(x)\n")
    result = scan_effect_claims(tmp_path)
    assert len(result.claims) == 1
    assert result.graph.coverage["resolved_local_calls"] == 0


def test_same_name_duplicate_candidates_are_not_collapsed(tmp_path):
    (tmp_path / "app.py").write_text("@tool\ndef entry(x):\n    candidate(x)\ndef candidate(x):\n    first.frob(x)\ndef candidate(x):\n    second.frob(x)\n")
    result = scan_effect_claims(tmp_path)
    assert len(result.claims) == 1
    assert len([c for c in result.claims[0].implementation_candidates if c.kind == CandidateKind.RESOLVED_LOCAL]) == 2


@pytest.mark.parametrize("language,source", [
    ("python", "@tool\ndef entry():\n    mystery_client().frob()\n"),
    ("typescript", 'function entry() { mystery_client().frob(); }\nserver.tool("x", {}, entry);'),
    ("go", 'package main\nfunc entry() { mystery_client().frob() }\nfunc init() { server.AddTool("x", entry) }'),
])
def test_nested_calls_at_same_column_have_distinct_stable_ids(tmp_path, language, source):
    path = "app" + {"python": ".py", "typescript": ".ts", "go": ".go"}[language]
    (tmp_path / path).write_text(source)
    result = scan_effect_claims(tmp_path)
    assert len(result.claims) == len(result.graph.invocations) == 2
    assert len({c.invocation_id for c in result.claims}) == 2
    (tmp_path / path).write_text(source.replace("mystery_client", "totally_new_library"))
    assert {c.identity for c in scan_effect_claims(tmp_path).claims} == {c.identity for c in result.claims}


def test_closure_parameter_cannot_resolve_to_global_same_named_function(tmp_path):
    (tmp_path / "app.py").write_text("@tool\ndef entry(helper):\n    def inner():\n        helper()\n    inner()\ndef helper():\n    unreachable.frob()\n")
    result = scan_effect_claims(tmp_path)
    assert len(result.claims) == 2
    assert not any("unreachable" in c.invocation.callee_expression for c in result.claims)


def test_go_named_receiver_method_registration_is_a_root(tmp_path):
    (tmp_path / "app.go").write_text('package main\ntype Service struct {}\nfunc (s *Service) entry(x string) { mystery_client.frob(x) }\nfunc (s *Service) setup() { server.AddTool("x", s.entry) }\n')
    result = scan_effect_claims(tmp_path)
    assert len(unknown_claims(result)) == 1
