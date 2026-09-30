#!/usr/bin/env python3
"""Validator for the AREF-002 architecture freeze.

Checks three things:

1. Every JSON schema in this directory is a valid JSON Schema 2020-12 document,
   and every example validates (or fails to validate) as intended.
2. The machine-readable architecture manifest agrees with the schemas: every
   closed vocabulary in the manifest is exactly the corresponding schema enum.
3. The Markdown documents agree with the manifest: every relative link resolves,
   every probe id and invariant id cited in prose exists in the manifest, and the
   architectural prohibitions that can be checked mechanically hold.

This validator does not touch anything outside specs/AREF-002/, except to
re-verify that specs/AREF-001/ is still intact.

Usage:
    python3 specs/AREF-002/validate.py
Exit code 0 if every check passes, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:  # pragma: no cover
    print("FATAL: jsonschema and referencing are required. "
          "Install with: python3 -m pip install --user jsonschema")
    sys.exit(2)

HERE = Path(__file__).resolve().parent
EXAMPLES = HERE / "examples"
AREF_001 = HERE.parent / "AREF-001"

SCHEMA_FILES = [
    "evidence.schema.json",
    "effect_claim.schema.json",
    "effect_receipt.schema.json",
    "coverage_ledger.schema.json",
    "architecture_manifest.schema.json",
]

# example file -> (schema file, must_validate)
EXAMPLE_CASES = [
    ("evidence.valid.json", "evidence.schema.json", True),
    ("evidence.invalid.json", "evidence.schema.json", False),
    ("effect_claim.valid.abstain.json", "effect_claim.schema.json", True),
    ("effect_claim.valid.proven.json", "effect_claim.schema.json", True),
    ("effect_claim.invalid.json", "effect_claim.schema.json", False),
    ("effect_receipt.valid.json", "effect_receipt.schema.json", True),
    ("effect_receipt.invalid.json", "effect_receipt.schema.json", False),
    ("coverage_ledger.valid.json", "coverage_ledger.schema.json", True),
    ("coverage_ledger.invalid.json", "coverage_ledger.schema.json", False),
    ("architecture_manifest.invalid.json", "architecture_manifest.schema.json", False),
]

MARKDOWN_FILES = [
    "README.md",
    "AREF-002.md",
    "proof_obligations.md",
    "evidence_acquisition.md",
    "dependency_descent.md",
    "aref_001_delta.md",
    "validation_protocol.md",
    "implementation_plan.md",
    "REPORT.md",
]

RECEIPT_ANSWER_KEYS = [
    "effect",
    "implementation",
    "resource",
    "activation",
    "boundary",
    "operation",
    "persistence",
    "control",
    "authority",
    "contradictions",
    "unknowns",
]

FROZEN_COMMIT = "b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16"

_results: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> bool:
    _results.append((bool(ok), label))
    return bool(ok)


def strip_annotations(node):
    """Remove documentation keys (leading underscore) added to examples.

    The schemas set additionalProperties:false, so the `_case` and
    `_expected_failure` keys that make the examples self-describing must be
    removed before validation. They are stripped rather than allowed, so that a
    genuine stray key is still caught.
    """
    if isinstance(node, dict):
        return {k: strip_annotations(v) for k, v in node.items()
                if not k.startswith("_")}
    if isinstance(node, list):
        return [strip_annotations(v) for v in node]
    return node


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


# ---------------------------------------------------------------- section 1


def build_registry(schemas: dict[str, dict]) -> Registry:
    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(
            schema["$id"], Resource.from_contents(schema)
        )
    return registry


def validate_schemas(schemas: dict[str, dict]) -> None:
    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
            check(True, f"schema is valid JSON Schema 2020-12: {name}")
        except Exception as exc:  # pragma: no cover
            check(False, f"schema is valid JSON Schema 2020-12: {name} -- {exc}")

        check(
            schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
            f"schema declares 2020-12 $schema: {name}",
        )
        check(
            isinstance(schema.get("$id"), str)
            and schema["$id"].startswith("https://actenon.dev/schema/aref-002/"),
            f"schema has an absolute versioned $id: {name}",
        )
        check(
            schema["$id"].endswith("-0.1.0.json"),
            f"schema $id carries the 0.1.0 version: {name}",
        )


def validate_cross_file_refs(schemas: dict[str, dict]) -> None:
    """Every cross-file $ref must target a real $id, not a relative filename."""
    ids = {schema["$id"] for schema in schemas.values()}
    bad: list[str] = []
    total = 0

    def walk(node, origin: str):
        nonlocal total
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                total += 1
                base = ref.split("#", 1)[0]
                if base not in ids:
                    bad.append(f"{origin}: {ref}")
            for value in node.values():
                walk(value, origin)
        elif isinstance(node, list):
            for value in node:
                walk(value, origin)

    for name, schema in schemas.items():
        walk(schema, name)

    check(not bad, f"all {total} cross-file $refs resolve to a known $id"
          + ("" if not bad else f" -- unresolved: {bad}"))


def validate_examples(schemas: dict[str, dict], registry: Registry) -> None:
    for example_name, schema_name, must_pass in EXAMPLE_CASES:
        path = EXAMPLES / example_name
        if not path.exists():
            check(False, f"example exists: {example_name}")
            continue
        instance = strip_annotations(load_json(path))
        validator = Draft202012Validator(schemas[schema_name], registry=registry)
        errors = sorted(validator.iter_errors(instance), key=str)
        if must_pass:
            check(not errors,
                  f"valid example validates: {example_name}"
                  + ("" if not errors else f" -- {errors[0].message}"))
        else:
            check(bool(errors),
                  f"invalid example is rejected: {example_name}")

    # the shipped manifest must validate against its own schema
    manifest = load_json(HERE / "architecture_manifest.json")
    validator = Draft202012Validator(
        schemas["architecture_manifest.schema.json"], registry=registry
    )
    errors = sorted(validator.iter_errors(manifest), key=str)
    check(not errors,
          "architecture_manifest.json validates against its schema"
          + ("" if not errors else f" -- {errors[0].message}"))


def validate_invalid_examples_are_documented() -> None:
    for example_name, _schema_name, must_pass in EXAMPLE_CASES:
        if must_pass:
            continue
        raw = load_json(EXAMPLES / example_name)
        check(
            isinstance(raw.get("_expected_failure"), str)
            and raw["_expected_failure"].strip() != "",
            f"invalid example names its expected failure: {example_name}",
        )


# ---------------------------------------------------------------- section 2


def enum_at(schema: dict, pointer: str) -> list[str]:
    node = schema
    for part in pointer.split("/"):
        if part:
            node = node[part]
    if "enum" in node:
        return list(node["enum"])
    if "const" in node:
        return [node["const"]]
    raise KeyError(f"no enum at {pointer}")


def validate_manifest_vocabularies(schemas: dict[str, dict], manifest: dict) -> None:
    evidence = schemas["evidence.schema.json"]
    claim = schemas["effect_claim.schema.json"]
    vocab = manifest["vocabularies"]

    pairs = [
        ("proof_states", claim, "$defs/proofState"),
        ("verdicts", claim, "$defs/verdict"),
        ("obligations", evidence, "$defs/obligation"),
        ("implementation_candidate_kinds", claim, "$defs/candidateKind"),
        ("selection_states", claim, "$defs/selectionState"),
        ("admissibility", evidence, "$defs/admissibility"),
        ("polarity", evidence, "$defs/polarity"),
        ("ladder_tiers", evidence, "$defs/tierOrAbstain"),
        ("stop_reasons", evidence, "$defs/stopReason"),
        ("budget_names", evidence, "$defs/budgetName"),
    ]
    for key, schema, pointer in pairs:
        members = vocab[key]["members"]
        schema_enum = enum_at(schema, pointer)
        check(
            sorted(members) == sorted(schema_enum),
            f"manifest vocabulary matches schema enum: {key}",
        )
        check(vocab[key]["closed"] is True, f"manifest vocabulary is closed: {key}")

    # contradiction resolutions live on the claim schema's contradiction object
    resolutions = enum_at(claim, "$defs/contradiction/properties/resolution")
    check(
        sorted(vocab["contradiction_resolutions"]["members"]) == sorted(resolutions),
        "manifest vocabulary matches schema enum: contradiction_resolutions",
    )

    # control sub-descriptors are the required keys of the control object
    control_keys = claim["$defs"]["control"]["required"]
    check(
        sorted(vocab["control_sub_descriptors"]["members"]) == sorted(control_keys),
        "manifest control sub-descriptors match the control object's keys",
    )

    # descriptors must be exactly the four retained-separately concepts
    check(
        sorted(vocab["descriptors"]["members"])
        == ["AUTHORITY", "CONDITIONS", "CONTROL", "TARGET"],
        "manifest descriptors are exactly TARGET, CONTROL, AUTHORITY, CONDITIONS",
    )
    check(
        sorted(k.upper() for k in claim["$defs"]["descriptors"]["required"])
        == sorted(vocab["descriptors"]["members"]),
        "claim schema descriptors object carries exactly those four",
    )

    # L8 must not be a legal packet tier
    check(
        "L8" not in enum_at(evidence, "$defs/tier"),
        "L8 is not a legal evidence packet tier (it is a terminal state)",
    )
    check(
        "L8" in enum_at(evidence, "$defs/tierOrAbstain"),
        "L8 is a legal highest-tier-reached value",
    )

    # rule match types must be exactly those the admissibility table covers
    check(
        sorted(manifest["sink_rule_admissibility"].keys())
        == sorted(enum_at(evidence, "$defs/ruleMatchType")),
        "sink rule admissibility table covers every rule match type",
    )


def validate_manifest_semantics(manifest: dict) -> None:
    check(manifest["architecture_id"] == "AREF-002", "manifest identifies AREF-002")
    check(
        manifest["supersedes"]["status"]
        == "SUPERSEDED DESIGN CANDIDATE / NOT AUTHORITATIVE",
        "manifest records AREF-001 as a superseded, non-authoritative candidate",
    )
    check(
        manifest["supersedes"]["preserved_unmodified"] is True,
        "manifest records AREF-001 as preserved unmodified",
    )
    check(
        manifest["frozen_against"]["commit"] == FROZEN_COMMIT,
        "manifest is frozen against the recorded HEAD commit",
    )
    check(
        "claim to be proved" in manifest["founding_principle"],
        "manifest carries the founding principle",
    )

    # obligations
    obligations = {o["id"] for o in manifest["obligations"]}
    check(
        obligations
        == {"IMPLEMENTATION", "ACTIVATION", "BOUNDARY", "OPERATION", "PERSISTENCE"},
        "manifest declares exactly the five v1 obligations",
    )
    for entry in manifest["obligations"]:
        check(
            len(entry["prohibitions"]) >= 2,
            f"obligation carries its frozen prohibitions: {entry['id']}",
        )
        for prohibition in entry["prohibitions"]:
            check(
                prohibition["source"].strip() != "",
                f"every prohibition names a source: {entry['id']}",
            )
    impl = next(o for o in manifest["obligations"] if o["id"] == "IMPLEMENTATION")
    check(
        impl["can_be_refuted"] is False,
        "IMPLEMENTATION is the one obligation that is never REFUTED",
    )

    # HTTP dispatch must never settle OPERATION or PERSISTENCE (requirement 9)
    boundary = next(o for o in manifest["obligations"] if o["id"] == "BOUNDARY")
    text = " ".join(p["prohibition"] for p in boundary["prohibitions"])
    check(
        "never establishes OPERATION or PERSISTENCE" in text,
        "requirement 9 is recorded as a BOUNDARY prohibition",
    )

    # ACTIVATION is deliberately shallow
    activation = next(o for o in manifest["obligations"] if o["id"] == "ACTIVATION")
    check(
        activation["settled_by_tiers"] == ["L0", "L1"],
        "ACTIVATION is settled only by workspace-local tiers",
    )

    # descriptors never gate a verdict
    for descriptor in manifest["descriptors"]:
        check(
            descriptor["is_obligation"] is False
            and descriptor["gates_verdict"] is False,
            f"descriptor is not an obligation and does not gate a verdict: "
            f"{descriptor['id']}",
        )

    # effect classes
    classes = manifest["effect_classes"]
    populated = [c for c in classes if c["status"] == "POPULATED_V1"]
    check(len(populated) == 1, "exactly one effect class is populated in v1")
    check(
        populated[0]["id"] == "EXTERNAL_PERSISTENT_STATE_EFFECT",
        "the populated v1 class is EXTERNAL_PERSISTENT_STATE_EFFECT",
    )
    check(
        sorted(populated[0]["necessary_obligations"]) == sorted(obligations),
        "EPSE declares all five obligations as necessary",
    )
    unpopulated = [c for c in classes if c["status"] == "DECLARED_UNPOPULATED"]
    check(
        len(unpopulated) >= 9,
        f"at least nine future effect classes are declared "
        f"(found {len(unpopulated)})",
    )
    forced = [c for c in unpopulated if c["requires_persistence"] == "yes"]
    check(
        not forced,
        "no future effect class is forced into persistence"
        + ("" if not forced else f" -- {[c['id'] for c in forced]}"),
    )
    for entry in unpopulated:
        check(
            "PERSISTENCE" not in entry["necessary_obligations"],
            f"future class does not require PERSISTENCE: {entry['id']}",
        )
        check(
            "not implemented in v1" in entry["note"].lower(),
            f"future class is marked unimplemented: {entry['id']}",
        )

    # requirement 19's list must be representable
    required_future = {
        "MESSAGE_EMISSION_EFFECT",
        "VALUE_TRANSFER_EFFECT",
        "CODE_EXECUTION_EFFECT",
        "DEPLOYMENT_EFFECT",
        "PERMISSION_CHANGE_EFFECT",
        "SECRET_DISCLOSURE_EFFECT",
        "DEVICE_ACTION_EFFECT",
        "PACKET_CAPTURE_EFFECT",
        "PHYSICAL_ACTION_EFFECT",
    }
    check(
        required_future <= {c["id"] for c in unpopulated},
        "every effect kind named in requirement 19 is declared",
    )

    # ladder
    ladder = manifest["ladder"]
    check(len(ladder) == 9, "the ladder has nine tiers")
    check(
        [t["tier"] for t in ladder]
        == ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8"],
        "ladder tiers are L0 through L8 in order",
    )
    l8 = ladder[-1]
    check(
        l8["is_evidence_source"] is False and l8["can_settle"] == [],
        "L8 is a terminal state and settles nothing",
    )
    check(
        all(t["is_evidence_source"] for t in ladder[:-1]),
        "L0 through L7 are evidence sources",
    )
    for tier in ladder[:-1]:
        for obligation in tier["can_settle"]:
            check(
                obligation in obligations,
                f"ladder tier settles only declared obligations: {tier['tier']}",
            )
    # OPERATION and PERSISTENCE must not be settleable below L1
    for tier in ladder:
        if tier["tier"] in ("L0", "L2", "L3", "L4"):
            check(
                "OPERATION" not in tier["can_settle"]
                and "PERSISTENCE" not in tier["can_settle"],
                f"tier cannot settle OPERATION or PERSISTENCE: {tier['tier']}",
            )

    # budgets
    budgets = manifest["budgets"]
    check(
        sorted(budgets["defaults"].keys())
        == sorted(manifest["vocabularies"]["budget_names"]["members"]),
        "budget defaults cover exactly the frozen budget names",
    )
    check(
        sorted(budgets["scopes"].keys())
        == sorted(manifest["vocabularies"]["budget_names"]["members"]),
        "budget scopes cover exactly the frozen budget names",
    )
    check(
        "UNKNOWN" in budgets["exhaustion_behaviour"]
        and "ABSTAIN" in budgets["exhaustion_behaviour"],
        "budget exhaustion behaviour names UNKNOWN and ABSTAIN (requirement 13)",
    )

    # probes
    probes = manifest["counter_evidence_probes"]
    ids = [p["probe_id"] for p in probes]
    check(len(ids) == len(set(ids)), "probe ids are unique")
    check(
        all(p["obligation"] in obligations for p in probes),
        "every probe targets a declared obligation",
    )
    for obligation in obligations:
        blocking = [
            p for p in probes
            if p["obligation"] == obligation and p["probe_class"] == "BLOCKING"
        ]
        check(
            bool(blocking),
            f"obligation has at least one BLOCKING counter-evidence probe: "
            f"{obligation}",
        )
    per05 = next(p for p in probes if p["probe_id"] == "CP-PER-05")
    check(
        per05["probe_class"] == "BLOCKING" and "UNKNOWN" in per05.get("note", ""),
        "CP-PER-05 is BLOCKING and preserves uncertainty rather than refuting",
    )

    # sink rule admissibility
    admis = manifest["sink_rule_admissibility"]
    for match_type in ("name_call", "sql_execute_pattern", "string_pattern"):
        check(
            admis[match_type]["admissibility"] == "HYPOTHESIS_ONLY",
            f"text- or name-anchored rule is HYPOTHESIS_ONLY: {match_type}",
        )
        check(
            admis[match_type]["may_settle"] == [],
            f"HYPOTHESIS_ONLY rule settles nothing: {match_type}",
        )
    for match_type, entry in admis.items():
        if entry["admissibility"] == "PROBATIVE":
            check(
                "PERSISTENCE" not in entry.get("may_settle", []),
                f"no sink rule alone settles PERSISTENCE: {match_type}",
            )

    # AREF-001 dispositions
    dispositions = manifest["aref_001_dispositions"]
    ids = [d["id"] for d in dispositions]
    check(
        ids == [f"D-{n:02d}" for n in range(1, 15)],
        "all fourteen AREF-001 decisions are classified, in order",
    )
    allowed = {"KEEP", "MODIFY", "REJECT", "DEFER"}
    check(
        all(d["disposition"] in allowed for d in dispositions),
        "every disposition is KEEP, MODIFY, REJECT or DEFER",
    )
    check(
        all(d["reason"].strip() for d in dispositions),
        "every disposition carries a reason",
    )
    rejected = {d["id"] for d in dispositions if d["disposition"] == "REJECT"}
    ontology = {
        d["id"] for d in dispositions
        if d.get("rejected_for_preserving_old_ontology")
    }
    check(
        ontology == rejected,
        "exactly the rejected decisions are flagged as preserving the old ontology",
    )
    check(
        ontology == {"D-01", "D-02", "D-04", "D-06"},
        "the ontology-preserving rejections are D-01, D-02, D-04 and D-06",
    )
    counts = {}
    for entry in dispositions:
        counts[entry["disposition"]] = counts.get(entry["disposition"], 0) + 1
    check(
        counts == {"KEEP": 5, "MODIFY": 4, "REJECT": 4, "DEFER": 1},
        f"disposition counts are KEEP 5 / MODIFY 4 / REJECT 4 / DEFER 1 "
        f"(found {counts})",
    )

    # invariants
    invariants = manifest["invariants"]
    ids = [i["id"] for i in invariants]
    check(len(ids) == len(set(ids)), "invariant ids are unique")
    for prefix, lowest, highest in (("T", 1, 21), ("E", 1, 12), ("D", 1, 12),
                                    ("V", 1, 10)):
        expected = {f"AREF-002-{prefix}{n:02d}"
                    for n in range(lowest, highest + 1)}
        check(
            expected <= set(ids),
            f"invariant series is complete: AREF-002-{prefix}"
            f"{lowest:02d}..{highest:02d}",
        )
    check(
        all(i["statement"].strip() for i in invariants),
        "every invariant carries a statement",
    )

    # validation block
    validation = manifest["validation"]
    check(
        validation["repositories_selected"] is False
        and validation["repositories_inspected"] is False,
        "manifest records that no validation repository is selected or inspected",
    )
    thresholds = validation["thresholds"]
    check(
        thresholds["evidence_fidelity_exact"] == 1.0,
        "evidence fidelity threshold is exactly 1.00",
    )
    check(
        thresholds["false_no_effect_on_effect_units_exact"] == 0,
        "false NO_EFFECT threshold is exactly zero",
    )
    check(
        thresholds["proven_effect_precision_min"] >= 0.9,
        "PROVEN_EFFECT precision threshold is at least 0.90",
    )
    check(
        any("0.95" in c for c in validation["invalidating_conditions"]),
        "abstain-on-everything is an invalidating condition (anti-gaming)",
    )

    # prohibitions
    requirements = {p["requirement"] for p in manifest["prohibitions"]}
    for requirement in ("2", "3", "9", "10", "11", "13", "14", "15", "17", "18"):
        check(
            requirement in requirements,
            f"a prohibition is recorded for requirement {requirement}",
        )


def validate_receipt_answers(schemas: dict[str, dict]) -> None:
    receipt = schemas["effect_receipt.schema.json"]
    answers = receipt["$defs"]["answers"]
    check(
        answers["required"] == RECEIPT_ANSWER_KEYS,
        "receipt answers requires the eleven keys of requirement 16, in order",
    )
    check(
        len(answers["required"]) == 11,
        "receipt answers has exactly eleven required keys",
    )
    check(
        answers.get("additionalProperties") is False,
        "receipt answers admits no extra keys",
    )
    check(
        sorted(answers["properties"].keys()) == sorted(RECEIPT_ANSWER_KEYS),
        "receipt answers declares exactly those eleven properties",
    )
    constraints = receipt["$defs"]["renderingConstraints"]
    check(
        constraints["properties"]["may_render_as_safe"].get("const") is False,
        "no receipt may license a safety claim",
    )


def validate_ledger_interpretation(schemas: dict[str, dict]) -> None:
    ledger = schemas["coverage_ledger.schema.json"]
    check(
        "interpretation" in ledger["required"],
        "the coverage ledger's interpretation block is required",
    )
    interpretation = ledger["$defs"]["interpretation"]["properties"]
    for key in (
        "abstained_claims_are_not_negative_results",
        "uninvestigated_claims_are_not_negative_results",
        "zero_proven_effect_does_not_mean_safe",
    ):
        check(
            interpretation[key].get("const") is True,
            f"ledger interpretation flag is pinned true: {key}",
        )
    for key in ("claims", "verdict_distribution", "frontier", "budget_exhaustion",
                "stop_reason_histogram", "highest_tier_reached_histogram",
                "analysis_errors"):
        check(key in ledger["required"], f"ledger requires: {key}")
    claims = ledger["properties"]["claims"]["required"]
    check(
        "not_investigated" in claims,
        "the ledger requires an uninvestigated-claim count on its own line",
    )


def validate_claim_genesis(schemas: dict[str, dict]) -> None:
    claim = schemas["effect_claim.schema.json"]
    genesis = claim["$defs"]["genesis"]["properties"]
    check(
        genesis["basis"].get("const") == "NON_REFUTATION_OF_INERTNESS",
        "claim genesis is pinned to non-refutation of inertness (requirement 2)",
    )
    check(
        genesis["inertness_established"].get("const") is False,
        "an emitted claim never has inertness established",
    )
    identity = claim["required"]
    check(
        "capability_id" in identity
        and "invocation_id" in identity
        and "effect_class" in identity,
        "claim identity is (capability_id, invocation_id, effect_class)",
    )
    check(
        "rule_id" not in claim["properties"],
        "no rule_id appears in claim identity or top-level properties",
    )
    check(
        claim["properties"]["implementation_candidates"].get("minItems") == 1,
        "a claim always carries at least one implementation candidate",
    )
    kinds = claim["$defs"]["candidateKind"]["enum"]
    check(
        "OPAQUE_EXTERNAL" in kinds and "DYNAMIC_UNRESOLVED" in kinds,
        "OPAQUE_EXTERNAL and DYNAMIC_UNRESOLVED are first-class candidate kinds",
    )
    packets = claim["properties"]["evidence_packets"]
    check(
        "minItems" not in packets,
        "a claim may carry zero evidence packets (existence precedes evidence)",
    )
    closure = claim["$defs"]["closure"]
    for condition in ("C1_no_opaque_or_dynamic_candidate",
                      "C2_refuted_for_every_candidate",
                      "C3_no_conflicting_obligation",
                      "C4_no_budget_exhausted_on_contributing_path",
                      "C5_relevant_frontier_empty",
                      "C6_no_error_on_necessary_obligation"):
        check(
            closure["properties"][condition].get("const") is True,
            f"NO_EFFECT closure condition is required true: {condition}",
        )
    check(
        len([k for k in closure["required"] if k.startswith("C")]) == 6,
        "closure requires all six conditions C1 to C6",
    )


def validate_evidence_admissibility(schemas: dict[str, dict]) -> None:
    evidence = schemas["evidence.schema.json"]
    check(
        enum_at(evidence, "$defs/admissibility")
        == ["PROBATIVE", "HYPOTHESIS_ONLY"],
        "admissibility has exactly two classes and no intermediate",
    )
    extract = evidence["$defs"]["extract"]
    check(
        extract["properties"]["verbatim"].get("const") is True,
        "every packet's extract must be verbatim",
    )
    check(
        "text" in extract["required"] and "verbatim" in extract["required"],
        "extract text and the verbatim flag are both required",
    )
    check(
        evidence["properties"]["obligation"]["$ref"].endswith("/obligation"),
        "a packet targets exactly one obligation",
    )
    conditionals = json.dumps(evidence.get("allOf", []))
    check(
        "identifier_name" in conditionals and "HYPOTHESIS_ONLY" in conditionals,
        "the schema mechanically forbids identifier-anchored probative evidence",
    )
    check(
        "version_resolution" in conditionals,
        "the schema requires package and version on dependency-sourced evidence",
    )
    probe = evidence["$defs"]["probeOutcome"]["properties"]["outcome"]["enum"]
    check(
        sorted(probe) == ["FOUND", "INCOMPLETE", "NOT_FOUND"],
        "probe outcomes distinguish incomplete from not-found",
    )


# ---------------------------------------------------------------- section 3


def validate_markdown(manifest: dict) -> None:
    texts: dict[str, str] = {}
    for name in MARKDOWN_FILES:
        path = HERE / name
        if not path.exists():
            check(False, f"document exists: {name}")
            continue
        texts[name] = path.read_text(encoding="utf-8")
        check(True, f"document exists: {name}")

    corpus = "\n".join(texts.values())

    # every relative markdown link resolves
    link_re = re.compile(r"\[[^\]]+\]\((?!https?:)([^)#]+)(#[^)]*)?\)")
    broken: list[str] = []
    total = 0
    for name, text in texts.items():
        for match in link_re.finditer(text):
            target = match.group(1).strip()
            if not target or target.startswith("mailto:"):
                continue
            total += 1
            if not (HERE / target).exists():
                broken.append(f"{name} -> {target}")
    check(not broken,
          f"all {total} relative links resolve"
          + ("" if not broken else f" -- broken: {broken}"))

    # every invariant id cited in prose exists in the manifest
    declared = {i["id"] for i in manifest["invariants"]}
    cited = set(re.findall(r"AREF-002-[TEDV][0-9]{2}", corpus))
    missing = sorted(cited - declared)
    check(not missing,
          "every invariant id cited in prose is declared in the manifest"
          + ("" if not missing else f" -- undeclared: {missing}"))

    # every probe id cited in prose exists in the registry
    probe_ids = {p["probe_id"] for p in manifest["counter_evidence_probes"]}
    cited_probes = set(re.findall(r"CP-(?:IMPL|ACT|BND|OPR|PER)-[0-9]{2}", corpus))
    missing_probes = sorted(cited_probes - probe_ids)
    check(not missing_probes,
          "every probe id cited in prose is in the registry"
          + ("" if not missing_probes else f" -- unregistered: {missing_probes}"))

    # conversely, every registered probe is documented
    undocumented = sorted(probe_ids - cited_probes)
    check(not undocumented,
          "every registered probe is documented in prose"
          + ("" if not undocumented else f" -- undocumented: {undocumented}"))

    # the fourteen AREF-001 decisions are each discussed in the delta
    delta = texts.get("aref_001_delta.md", "")
    for number in range(1, 15):
        check(
            f"D-{number:02d}" in delta,
            f"delta discusses AREF-001 decision D-{number:02d}",
        )
    for word in ("KEEP", "MODIFY", "REJECT", "DEFER"):
        check(word in delta, f"delta uses the disposition {word}")
    check(
        "No decision is preserved merely because AREF-001 called it frozen" in delta,
        "delta states that no decision is preserved merely for being frozen",
    )

    # the delta's own summary table must agree with the manifest
    dispositions = {d["id"]: d["disposition"]
                    for d in manifest["aref_001_dispositions"]}
    row_re = re.compile(r"^\| (D-\d{2}) \|[^|]*\| \*\*(KEEP|MODIFY|REJECT|DEFER)\*\*",
                        re.MULTILINE)
    rows = dict(row_re.findall(delta))
    check(
        len(rows) == 14,
        f"delta summary table has fourteen rows (found {len(rows)})",
    )
    mismatched = sorted(k for k, v in rows.items() if dispositions.get(k) != v)
    check(
        not mismatched,
        "delta summary table agrees with the manifest"
        + ("" if not mismatched else f" -- mismatched: {mismatched}"),
    )

    # the report must answer all ten final questions and give exactly one verdict
    report = texts.get("REPORT.md", "")
    if report:
        for number in range(1, 11):
            check(
                re.search(rf"(?m)^#+ *Q{number}\b", report) is not None,
                f"report answers final question Q{number}",
            )
        verdict_re = re.compile(
            r"(?m)^\*\*(ARCHITECTURE READY FOR IMPLEMENTATION|"
            r"ARCHITECTURE NOT READY)\*\*$"
        )
        verdicts = verdict_re.findall(report)
        check(
            len(verdicts) == 1,
            f"report states exactly one standalone verdict (found {len(verdicts)})",
        )
        check(
            "section 30" in report.lower() or "## 30" in report,
            "report contains the numbered section the architecture references",
        )

    # the architecture document must carry the founding principle and the trace
    arch = texts.get("AREF-002.md", "")
    check(
        "claim to be proved, not a sink to be matched" in arch,
        "AREF-002.md states the founding principle",
    )
    check(
        "PROVEN INERT" in arch,
        "AREF-002.md states the genesis condition",
    )

    # requirement 20 / STRICT RULES: no held-out repository may be named
    forbidden = ("R05 repository", "R06 repository", "R07 repository")
    named = [f for f in forbidden if f in corpus]
    check(not named, "no held-out validation repository is named")
    protocol = texts.get("validation_protocol.md", "")
    check(
        "No repository has been selected or inspected" in protocol,
        "the validation protocol states that no repository was selected",
    )
    check(
        "preregistered" in protocol.lower(),
        "the validation protocol is preregistered",
    )
    for term in ("precision", "recall", "abstention", "fidelity", "coverage",
                 "first-broken-component", "denominator", "contamination"):
        check(term in protocol.lower(), f"protocol freezes {term}")


def validate_aref_001_untouched() -> None:
    manifest_path = AREF_001 / "MANIFEST.json"
    if not manifest_path.exists():
        check(False, "AREF-001 MANIFEST.json is present")
        return
    import hashlib

    manifest = load_json(manifest_path)
    entries = manifest.get("files") or manifest.get("entries") or []
    if isinstance(entries, dict):
        entries = [{"path": k, **v} if isinstance(v, dict) else
                   {"path": k, "sha256": v} for k, v in entries.items()]
    repo_root = HERE.parent.parent
    mismatched: list[str] = []
    for entry in entries:
        rel = entry.get("path")
        expected = entry.get("sha256")
        if not rel or not expected:
            continue
        target = repo_root / rel
        if not target.exists():
            mismatched.append(f"missing {rel}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            mismatched.append(f"changed {rel}")
    check(
        bool(entries) and not mismatched,
        f"AREF-001 is byte-identical ({len(entries)} hashed files)"
        + ("" if not mismatched else f" -- {mismatched}"),
    )


def main() -> int:
    schemas = {name: load_json(HERE / name) for name in SCHEMA_FILES}
    registry = build_registry(schemas)
    manifest = load_json(HERE / "architecture_manifest.json")

    validate_schemas(schemas)
    validate_cross_file_refs(schemas)
    validate_examples(schemas, registry)
    validate_invalid_examples_are_documented()

    validate_manifest_vocabularies(schemas, manifest)
    validate_manifest_semantics(manifest)
    validate_receipt_answers(schemas)
    validate_ledger_interpretation(schemas)
    validate_claim_genesis(schemas)
    validate_evidence_admissibility(schemas)

    validate_markdown(manifest)
    validate_aref_001_untouched()

    failures = [label for ok, label in _results if not ok]
    for ok, label in _results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
    print()
    print(f"{len(_results)} checks, {len(_results) - len(failures)} passed, "
          f"{len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
