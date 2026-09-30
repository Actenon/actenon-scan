"""Generic supplied proof records for the adopted contract-provenance profile."""
from __future__ import annotations

import copy
import json
from pathlib import Path

SPEC = Path(__file__).resolve().parents[2] / "specs" / "AREF-002C"
KINDS = (
    "openapi_operation", "protobuf_service_method", "graphql_schema_field",
    "json_schema_node", "sdk_operation_metadata", "command_specification",
)
PINS = ("LOCKFILE", "EXACT_MANIFEST_PIN", "INSTALLED_TREE_METADATA")
FOUR = tuple(
    verdict + "_" + obligation + "_unpinned_probative"
    for verdict in ("proven_effect", "no_effect")
    for obligation in ("operation", "persistence")
)


def example(name):
    return json.loads((SPEC / "examples" / (name + ".json")).read_text())


def contract_record(obligation="OPERATION", negative=False, kind="openapi_operation",
                    resolution="LOCKFILE", hypothesis=False):
    record = example("valid_proven_effect")
    packet = next(p for p in record["evidence_packets"] if p["obligation"] == obligation)
    packet.update(kind=kind, tier="L6", locator={
        "path": "contracts/opaque-operation.json", "start_line": 7, "end_line": 7,
        "package": "synthetic.opaque", "version_resolution": resolution,
    })
    if resolution != "UNPINNED":
        packet["locator"]["version"] = "2.1.0"
    if negative:
        packet["polarity"] = "NEGATIVE"
        packet["assertion"]["predicate"] = {
            "BOUNDARY": "terminates_in_process_state",
            "OPERATION": "operation_is_observation",
            "PERSISTENCE": "state_is_guaranteed_rolled_back",
        }[obligation]
        record["obligations"][obligation] = "REFUTED"
        record["implementation_candidates"][0]["obligations"][obligation] = "REFUTED"
        record.update(verdict="NO_EFFECT", closure=example("valid_no_effect")["closure"])
        record["closure"]["refuted_obligation"] = obligation
    if hypothesis:
        packet["admissibility"] = "HYPOTHESIS_ONLY"
        record["obligations"][obligation] = "UNKNOWN"
        record["implementation_candidates"][0]["obligations"][obligation] = "UNKNOWN"
        record["verdict"] = "ABSTAIN"
        record.pop("closure", None)
        record["acquisition"].update(unresolved_obligations=[obligation], stop_reason="NO_FURTHER_TIER")
    record["acquisition"].update(highest_tier_reached="L6", tiers_attempted=["L0", "L1", "L6"])
    return record


def contract_packet(record):
    return next(p for p in record["evidence_packets"] if p["tier"] == "L6")


def two_candidates(record):
    record = copy.deepcopy(record)
    other = copy.deepcopy(record["implementation_candidates"][0])
    other["candidate_id"] = "second-opaque-id"
    record["implementation_candidates"].append(other)
    more = copy.deepcopy(record["evidence_packets"])
    for p in record["evidence_packets"]:
        if "binding" in p:
            p["binding"]["relation"] = "POSSIBLE_TARGET"
    for p in more:
        p["packet_id"] = "second-" + p["packet_id"]
        p["implementation_candidate_id"] = other["candidate_id"]
        if "binding" in p:
            p["binding"]["relation"] = "POSSIBLE_TARGET"
    record["evidence_packets"].extend(more)
    record["selection_state"] = "AGREEMENT_INVARIANT"
    return record


def body_precedence():
    record = example("valid_proven_effect")
    contract = contract_packet(contract_record(negative=True))
    contract["packet_id"] = "opposing-contract"
    record["evidence_packets"].append(contract)
    record["contradictions"] = [{
        "obligation": "OPERATION", "implementation_candidate_id": "kappa",
        "positive_packet_ids": ["kappa-operation"],
        "negative_packet_ids": ["opposing-contract"],
        "resolution": "RESOLVED_IMPLEMENTATION_PRECEDENCE",
        "overridden_packet_ids": ["opposing-contract"],
        "precedence": {"selection_packet_id": "kappa-implementation",
                       "winning_paths": [{"packet_id": "kappa-operation", "binding_packet_ids": []}]},
    }]
    record["acquisition"].update(highest_tier_reached="L6", tiers_attempted=["L0", "L1", "L6"])
    return record


def independent_positive():
    record = example("valid_proven_effect")
    hypothesis = contract_packet(contract_record("PERSISTENCE", negative=True,
                                resolution="UNPINNED", hypothesis=True))
    hypothesis["packet_id"] = "unresolved-contract-concern"
    record["evidence_packets"].append(hypothesis)
    record["acquisition"].update(highest_tier_reached="L6", tiers_attempted=["L0", "L1", "L6"])
    next(p for p in record["probe_outcomes"] if p["probe_id"] == "CP-PER-03").update(
        outcome="FOUND", packet_ids=[hypothesis["packet_id"]])
    return record


def independent_negative():
    record = example("valid_no_effect")
    hypothesis = contract_packet(contract_record(resolution="UNPINNED", hypothesis=True))
    record["evidence_packets"] = [p for p in record["evidence_packets"] if p["obligation"] != "OPERATION"] + [hypothesis]
    record["obligations"]["OPERATION"] = "UNKNOWN"
    record["implementation_candidates"][0]["obligations"]["OPERATION"] = "UNKNOWN"
    record["acquisition"].update(highest_tier_reached="L6", tiers_attempted=["L0", "L1", "L6"],
                                 unresolved_obligations=["OPERATION"], stop_reason="NO_FURTHER_TIER")
    return record
