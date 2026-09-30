"""M0: the model's serialised form conforms to the frozen AREF-002 schemas.

The model is stricter than the schemas (it enforces the cross-field rules of
the prose specification); these tests check the converse direction: nothing
the model emits is rejected by the frozen schemas, and every frozen example
is judged the same way by the schema and by the model.
"""

from __future__ import annotations

import dataclasses

import pytest

from actenon_scan.effects import (
    CoverageLedger,
    EffectClaim,
    EffectModelError,
    EffectReceipt,
    EvidencePacket,
    Obligation,
    SelectionState,
)

from ._builders import (
    R,
    S,
    conflicting_claim,
    error_claim,
    multi_claim,
    no_effect_claim,
    not_investigated_claim,
    proven_claim,
    resolved_claim,
    unfamiliar_sdk_claim,
    reidentify,
)
from ._spec import example, schema, schema_resources, historical_schema, amended_example

import jsonschema
import referencing
from referencing.jsonschema import DRAFT202012  # noqa: E402

SCHEMAS = ("evidence", "effect_claim", "effect_receipt", "coverage_ledger")
REGISTRY = referencing.Registry().with_resources(
    (s["$id"], referencing.Resource.from_contents(s, default_specification=DRAFT202012))
    for s in schema_resources()
)


def validator(name, fragment=""):
    root = schema(name)
    target = {"$ref": root["$id"] + fragment} if fragment else root
    return jsonschema.Draft202012Validator(target, registry=REGISTRY,
                                           format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)


def assert_valid(name, data, fragment=""):
    errors = sorted(validator(name, fragment).iter_errors(data), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(f"{list(e.absolute_path)}: {e.message}" for e in errors[:5])


def assert_invalid(name, data):
    assert list(validator(name).iter_errors(data)), f"schema {name} accepted data it should reject"


CLAIMS = {
    "abstain": unfamiliar_sdk_claim,
    "proven": proven_claim,
    "conflicting": conflicting_claim,
    "resolved": resolved_claim,
    "error": error_claim,
    "not_investigated": not_investigated_claim,
    "divergent": lambda: multi_claim(SelectionState.UNRESOLVED_DIVERGENT,
                                     [{Obligation.OPERATION: S}, {Obligation.OPERATION: R}]),
    "agreement": lambda: multi_claim(SelectionState.AGREEMENT_INVARIANT,
                                     [{Obligation.OPERATION: S}, {Obligation.OPERATION: S}]),
}


def test_schemas_are_themselves_valid_draft_2020_12():
    for s in schema_resources():
        jsonschema.Draft202012Validator.check_schema(s)


@pytest.mark.parametrize("name", sorted(CLAIMS))
def test_emitted_claim_conforms(name):
    assert_valid("effect_claim", CLAIMS[name]().to_dict())


@pytest.mark.xfail(strict=True, reason=(
    "Frozen AREF-002 defect: effect_claim.schema.json requires 'closure' when verdict is NO_EFFECT "
    "but does not declare 'closure' under the top-level properties while additionalProperties is "
    "false, so no NO_EFFECT claim can satisfy the schema. AREF-002 is frozen; reported, not fixed."))
def test_emitted_no_effect_claim_conforms():
    historical_validator("effect_claim").validate(historical_negative())


def test_no_effect_schema_defect_is_exactly_the_closure_key():
    data = historical_negative()
    messages = [e.message for e in historical_validator("effect_claim").iter_errors(data)]
    assert messages and all("closure" in m for m in messages), messages
    without = {k: v for k, v in data.items() if k != "closure"}
    messages = [e.message for e in historical_validator("effect_claim").iter_errors(without)]
    assert messages and all("closure" in m for m in messages), messages


@pytest.mark.parametrize("name", sorted(CLAIMS) + ["no_effect"])
def test_emitted_receipt_conforms(name):
    claim = no_effect_claim() if name == "no_effect" else CLAIMS[name]()
    receipt = EffectReceipt.from_claim(dataclasses.replace(claim, receipt_id="rcpt-1"))
    assert_valid("effect_receipt", receipt.to_dict())


def test_emitted_packets_and_probes_conform():
    claims = [build() for build in CLAIMS.values()] + [no_effect_claim()]
    for claim in claims:
        for p in claim.evidence_packets:
            assert_valid("evidence", p.to_dict())
        for o in claim.probe_outcomes:
            assert_valid("evidence", o.to_dict(), "#/$defs/probeOutcome")


def test_emitted_ledger_conforms():
    claims = [reidentify(build(), claim_id=f"claim-{i}", invocation_id=f"inv-{i}")
              for i, build in enumerate(list(CLAIMS.values()) + [no_effect_claim])]
    ledger = CoverageLedger.from_claims(claims, capabilities_discovered=2, invocations_enumerated=len(claims))
    assert_valid("coverage_ledger", ledger.to_dict())
    empty = CoverageLedger.from_claims([], capabilities_discovered=0, invocations_enumerated=0)
    assert_valid("coverage_ledger", empty.to_dict())



def historical_validator(name):
    registry = referencing.Registry().with_resources(
        (historical_schema(n)["$id"], referencing.Resource.from_contents(historical_schema(n))) for n in SCHEMAS)
    return jsonschema.Draft202012Validator(historical_schema(name), registry=registry)


def historical_negative():
    data = no_effect_claim().to_dict()
    data["schema_version"] = "0.1.0"
    for p in data["evidence_packets"]:p.pop("binding", None)
    return data


def test_amended_no_effect_schema_really_passes():
    assert_valid("effect_claim", no_effect_claim().to_dict())

VALID_EXAMPLES = {
    "evidence.valid": ("evidence", EvidencePacket.from_dict),
    "effect_claim.valid.abstain": ("effect_claim", EffectClaim.from_dict),
    "effect_claim.valid.proven": ("effect_claim", EffectClaim.from_dict),
    "effect_receipt.valid": ("effect_receipt", EffectReceipt.from_dict),
    "coverage_ledger.valid": ("coverage_ledger", CoverageLedger.from_dict),
}
INVALID_EXAMPLES = {
    "evidence.invalid": ("evidence", EvidencePacket.from_dict),
    "effect_claim.invalid": ("effect_claim", EffectClaim.from_dict),
    "effect_receipt.invalid": ("effect_receipt", EffectReceipt.from_dict),
    "coverage_ledger.invalid": ("coverage_ledger", CoverageLedger.from_dict),
}


@pytest.mark.parametrize("name", sorted(VALID_EXAMPLES))
def test_valid_example_accepted_by_schema_and_model_and_reemitted_conformant(name):
    schema_name, load = VALID_EXAMPLES[name]
    data = example(name)
    historical_validator(schema_name).validate(data)
    if schema_name == "evidence":
        assert_valid(schema_name, load(data).to_dict())
    else:
        # Old wire records remain historical and cannot acquire missing new provenance.
        with pytest.raises(EffectModelError, match="schema_version"):
            load(data)
        replacement = {"effect_claim.valid.abstain":"valid_opaque_abstain", "effect_claim.valid.proven":"valid_proven",
                       "effect_receipt.valid":"valid_receipt_proven", "coverage_ledger.valid":"valid_ledger"}[name]
        loaded = load(amended_example(replacement))
        assert_valid(schema_name, loaded.to_dict())


@pytest.mark.parametrize("name", sorted(INVALID_EXAMPLES))
def test_invalid_example_rejected_by_schema_and_model(name):
    schema_name, load = INVALID_EXAMPLES[name]
    data = example(name)
    assert_invalid(schema_name, data)
    with pytest.raises(EffectModelError):
        load(data)
