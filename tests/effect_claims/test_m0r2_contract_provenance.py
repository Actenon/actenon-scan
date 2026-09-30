"""M0R2: malformed settling provenance is rejected; hypotheses are retained."""
from __future__ import annotations

import copy

import pytest

from actenon_scan.effects import EffectClaim, EffectModelError, EffectReceipt, EvidencePacket
from ._m0r2 import (
    FOUR, KINDS, PINS, body_precedence, contract_packet, contract_record, example,
    independent_negative, independent_positive, two_candidates,
)


@pytest.mark.parametrize("name", FOUR)
def test_exact_review_counterexample_rejected_at_packet_and_claim_loading(name):
    record = example(name)
    packet = contract_packet(record)
    with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
        EvidencePacket.from_dict(packet)
    with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
        EffectClaim.from_dict(record)
    # The input is not downgraded, discarded, assigned a version, or rewritten.
    assert packet["admissibility"] == "PROBATIVE"
    assert packet["locator"]["version_resolution"] == "UNPINNED"
    assert "version" not in packet["locator"]


@pytest.mark.parametrize("obligation", ("BOUNDARY", "OPERATION", "PERSISTENCE"))
@pytest.mark.parametrize("negative", (False, True))
@pytest.mark.parametrize("kind", KINDS)
def test_unpinned_contract_support_and_refutation_are_invalid(obligation, negative, kind):
    record = contract_record(obligation, negative, kind, resolution="UNPINNED")
    with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
        EffectClaim.from_dict(record)


@pytest.mark.parametrize("negative", (False, True))
def test_two_agreeing_unpinned_packets_cannot_bootstrap_settlement(negative):
    record = contract_record(negative=negative, resolution="UNPINNED")
    extra = copy.deepcopy(contract_packet(record))
    extra["packet_id"] = "second-agreeing-contract"
    record["evidence_packets"].append(extra)
    with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
        EffectClaim.from_dict(record)


@pytest.mark.parametrize("negative", (False, True))
def test_agreeing_candidates_cannot_bootstrap_unpinned_settlement(negative):
    record = two_candidates(contract_record(negative=negative, resolution="UNPINNED"))
    with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
        EffectClaim.from_dict(record)


@pytest.mark.parametrize("change", ("missing_resolution", "missing_version", "missing_package",
                                   "invented_unpinned_version", "unknown_resolution", "lowercase_resolution"))
def test_version_string_cannot_substitute_for_established_provenance(change):
    packet = contract_packet(contract_record())
    loc = packet["locator"]
    if change == "missing_resolution":
        loc.pop("version_resolution")
    elif change == "missing_version":
        loc.pop("version")
    elif change == "missing_package":
        loc.pop("package")
    elif change == "invented_unpinned_version":
        loc["version_resolution"] = "UNPINNED"
    elif change == "unknown_resolution":
        loc["version_resolution"] = "REMEMBERED_VERSION"
    else:
        loc["version_resolution"] = "lockfile"
    with pytest.raises(EffectModelError):
        EvidencePacket.from_dict(packet)


@pytest.mark.parametrize("resolution", PINS)
@pytest.mark.parametrize("negative", (False, True))
@pytest.mark.parametrize("obligation", ("BOUNDARY", "OPERATION", "PERSISTENCE"))
def test_established_version_modes_can_settle_when_otherwise_admissible(resolution, negative, obligation):
    record = contract_record(obligation, negative, resolution=resolution)
    claim = EffectClaim.from_dict(record)
    assert claim.verdict.value == ("NO_EFFECT" if negative else "PROVEN_EFFECT")
    assert claim.obligations[obligation].value == ("REFUTED" if negative else "SUPPORTED")
    receipt = EffectReceipt.from_claim(claim, "pinned-contract-receipt")
    assert EffectReceipt.from_dict(receipt.to_dict()) == receipt


def test_unpinned_hypothesis_is_retained_and_does_not_settle():
    record = contract_record(resolution="UNPINNED", hypothesis=True)
    claim = EffectClaim.from_dict(record)
    retained = next(p for p in claim.evidence_packets if p.tier.value == "L6")
    assert retained.to_dict() == contract_packet(record)
    assert claim.obligations.operation.value == "UNKNOWN"
    assert claim.verdict.value == "ABSTAIN"
    assert retained.locator.version is None


@pytest.mark.parametrize("builder,verdict", ((independent_positive, "PROVEN_EFFECT"),
                                             (independent_negative, "NO_EFFECT")))
def test_retained_unpinned_hypothesis_is_not_a_blanket_veto(builder, verdict):
    record = builder()
    claim = EffectClaim.from_dict(record)
    assert claim.verdict.value == verdict
    hypothesis = next(p for p in claim.evidence_packets if p.tier.value == "L6")
    assert hypothesis.admissibility.value == "HYPOTHESIS_ONLY"
    assert hypothesis.to_dict() == contract_packet(record)
    receipt = EffectReceipt.from_claim(claim, "non-veto-receipt")
    assert all(hypothesis.packet_id not in receipt.answers.obligation(o).settled_by_packet_ids
               for o in claim.necessary_obligations if o.value != "IMPLEMENTATION")
    assert EffectReceipt.from_dict(receipt.to_dict()) == receipt
    if verdict == "NO_EFFECT":
        assert claim.obligations.operation.value == "UNKNOWN"
        assert claim.obligations.persistence.value == "REFUTED"


def test_pinned_selected_body_precedence_remains_valid():
    assert EffectClaim.from_dict(body_precedence()).verdict.value == "PROVEN_EFFECT"


def test_precedence_cannot_launder_even_an_overridden_unpinned_probative_packet():
    record = body_precedence()
    packet = contract_packet(record)
    packet["locator"]["version_resolution"] = "UNPINNED"
    packet["locator"].pop("version")
    with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
        EffectClaim.from_dict(record)


def test_unpinned_contract_cannot_win_implementation_precedence():
    record = body_precedence()
    packet = contract_packet(record)
    packet["locator"]["version_resolution"] = "UNPINNED"
    packet["locator"].pop("version")
    contradiction = record["contradictions"][0]
    contradiction["overridden_packet_ids"] = ["kappa-operation"]
    contradiction["precedence"]["winning_paths"][0]["packet_id"] = "opposing-contract"
    with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
        EffectClaim.from_dict(record)


@pytest.mark.parametrize("name", FOUR)
def test_receipt_cannot_roundtrip_the_exact_unpinned_review_counterexamples(name):
    invalid = example(name)
    pinned = copy.deepcopy(invalid)
    contract_packet(pinned)["locator"].update(version="2.1.0", version_resolution="EXACT_MANIFEST_PIN")
    receipt = EffectReceipt.from_claim(EffectClaim.from_dict(pinned), "counterexample-receipt").to_dict()
    for k in (receipt, receipt["claim_snapshot"]):
        p = contract_packet(k)
        p["locator"]["version_resolution"] = "UNPINNED"
        p["locator"].pop("version")
    with pytest.raises(EffectModelError, match="PROBATIVE L6 contract"):
        EffectReceipt.from_dict(receipt)


def test_sink_independent_opaque_genesis_survives_contract_repair():
    claim = EffectClaim.from_dict(example("valid_abstain"))
    assert claim.invocation.matched_rule_ids == ()
    assert len(claim.implementation_candidates) == 1
    assert next(iter(claim.implementation_candidates)).kind.value == "OPAQUE_EXTERNAL"
    assert claim.selection_state.value == "UNRESOLVED_IDENTITY"
    assert {state.value for _, state in claim.obligations.items()} == {"UNKNOWN"}
    assert claim.verdict.value == "ABSTAIN"
