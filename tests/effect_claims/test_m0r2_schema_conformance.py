"""Mandatory C root-profile checks; existing A/B component IDs stay unchanged."""
from __future__ import annotations

import json
import subprocess
import sys

import jsonschema
from referencing import Registry, Resource
import pytest

from actenon_scan.effects import EffectClaim, EffectModelError, EffectReceipt
from ._m0r2 import FOUR, SPEC, example, independent_negative, independent_positive

ROOT = SPEC.parents[1]
RESOURCES = tuple(json.loads(path.read_text())
                  for profile in ("AREF-002A", "AREF-002B", "AREF-002C")
                  for path in sorted((ROOT / "specs" / profile).glob("*.schema.json")))
REGISTRY = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in RESOURCES)


def validator(name):
    return jsonschema.Draft202012Validator(json.loads((SPEC / (name + ".schema.json")).read_text()),
                                          registry=REGISTRY)


@pytest.mark.parametrize("name", ("evidence", "effect_claim", "effect_receipt"))
def test_adopted_root_profiles_are_valid_schema(name):
    jsonschema.Draft202012Validator.check_schema(validator(name).schema)


@pytest.mark.parametrize("path", sorted((SPEC / "examples").glob("*.json")), ids=lambda p: p.stem)
def test_every_sealed_full_record_agrees_with_runtime(path):
    record = json.loads(path.read_text())
    should_be_valid = path.stem not in FOUR
    assert (not list(validator("effect_claim").iter_errors(record))) == should_be_valid
    if should_be_valid:
        claim = EffectClaim.from_dict(record)
        assert claim.verdict.value == record["verdict"]
        receipt = EffectReceipt.from_claim(claim, "conformance-receipt")
        assert not list(validator("effect_receipt").iter_errors(receipt.to_dict()))
        assert EffectReceipt.from_dict(receipt.to_dict()) == receipt
        for packet in claim.evidence_packets:
            assert not list(validator("evidence").iter_errors(packet.to_dict()))
    else:
        with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
            EffectClaim.from_dict(record)


@pytest.mark.parametrize("builder", (independent_positive, independent_negative))
def test_non_veto_full_records_conform_to_C(builder):
    record = builder()
    assert not list(validator("effect_claim").iter_errors(record))
    claim = EffectClaim.from_dict(record)
    receipt = EffectReceipt.from_claim(claim, "non-veto-conformance-receipt")
    assert not list(validator("effect_receipt").iter_errors(receipt.to_dict()))


def test_C_gate_fails_if_required_schema_verifier_is_unavailable():
    run = subprocess.run([sys.executable, "-S", "-B", str(SPEC / "validate.py"), "--upstream", str(ROOT)],
                         cwd=ROOT, capture_output=True, text=True)
    assert run.returncode == 2
    assert "FATAL: required schema verifier unavailable" in run.stderr
