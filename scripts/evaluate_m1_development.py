"""Reproduce the M1 evaluation on the already-exposed R04 development commit.

This is evaluation-only root configuration, never production recognition.
No other development/held-out repository is opened by this script.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict
import json
from pathlib import Path
import subprocess

from actenon_scan import Entrypoint, RootKind, scan_effect_claims, scan_path
from actenon_scan.detectors.typescript import discover_all_ts_sinks
from actenon_scan.repository.invocation_adapters import _tree_unit, _walk, _text
from actenon_scan.repository.ts_symbol_index import TSRepositoryIndex, _parser_for

R04_SHA = "1d7a16b25db74ed44539cd5079e2db46b42f08db"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.repository.resolve()
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if sha != R04_SHA:
        parser.error("evaluation requires the frozen R04 development commit")
    args.output.mkdir(parents=True, exist_ok=True)
    automatic = scan_effect_claims(root)
    explicit = []
    index = TSRepositoryIndex(root)
    # The checked-in R04 registration-context.ts shows accountTool delegates
    # to registerTool. Select its direct handler argument as a user-supplied
    # root. The application seam is not added to production recognition.
    for path in sorted((root / "apps").rglob("*.tools.ts")):
        file = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8-sig")
        tree = _parser_for(file).parse(source.encode()).root_node
        unit = _tree_unit("typescript", file, source, tree, index)
        by_position = {(n.start_byte, n.end_byte): key for key, n in unit.nodes.items()}
        by_key = {s.key: s for s in unit.symbols}
        for node in _walk(tree):
            if node.type != "call_expression":
                continue
            callee = _text(node.child_by_field_name("function"), source.encode())
            if callee != "context.accountTool":
                continue
            arguments = node.child_by_field_name("arguments")
            if not arguments or not arguments.named_children:
                continue
            handler = arguments.named_children[-1]
            key = by_position.get((handler.start_byte, handler.end_byte))
            if key:
                explicit.append(Entrypoint(file, by_key[key].symbol, RootKind.MODEL_CALLABLE))
    unannotated = scan_effect_claims(root, entrypoints=explicit)
    annotations = defaultdict(set)
    for file in sorted({call.file for call in unannotated.graph.invocations.values()}):
        for match in discover_all_ts_sinks(root / file):
            annotations[(file, match["line"], match["col"] + 1)].add(match["rule_id"])
    annotated = scan_effect_claims(root, entrypoints=explicit, matched_rule_ids=annotations)
    auto_annotated = scan_effect_claims(root, matched_rule_ids=annotations)
    assert {c.identity for c in unannotated.claims} == {c.identity for c in annotated.claims}
    assert all(c.verdict.value == "ABSTAIN" for c in annotated.claims)
    legacy = scan_path(root)
    samples = []
    seen = set()
    for claim in annotated.claims:
        spelling = claim.invocation.callee_expression
        if not spelling.startswith("client.") or claim.invocation.matched_rule_ids:
            continue
        sample = (claim.invocation.locator.path, claim.invocation.locator.start_line, spelling)
        if sample in seen:
            continue
        seen.add(sample)
        samples.append({"file": sample[0], "line": sample[1], "callee": sample[2],
                        "verdict": claim.verdict.value,
                        "obligations": claim.obligations.to_dict(), "matched_rule_ids": []})
    summary = {
        "repository": "cloudflare/mcp-server-cloudflare", "development_evidence": "R04",
        "commit": sha, "automatic": auto_annotated.coverage,
        "automatic_and_explicit": annotated.coverage,
        "legacy_findings": len(legacy.findings), "legacy_capabilities": len(legacy.capabilities),
        "legacy_analysis_errors": len(legacy.analysis_errors),
        "annotation_removal_preserves_every_claim": True,
        "all_claim_verdicts": "ABSTAIN", "all_semantic_obligations": "UNKNOWN",
        "sink_free_sdk_call_sites": len(samples), "sink_free_sdk_examples": samples,
        "limitations": ["Custom registration seam uses explicit, evidence-backed root configuration.",
                        "Static call resolution is conservative; unresolved implementations are not followed.",
                        "No effect has been proven; this evaluation measures genesis only."],
    }
    (args.output / "R04-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.output / "R04-entrypoints.json").write_text(json.dumps([asdict(e) for e in explicit], indent=2) + "\n")
    (args.output / "R04-claims.json").write_text(json.dumps(annotated.to_dict(), indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "sink_free_sdk_examples"}, indent=2))


if __name__ == "__main__":
    main()
