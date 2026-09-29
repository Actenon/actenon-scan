"""M0: evidence packets carry verifiable provenance, and admissibility cannot leak.

A packet is one obligation for one candidate, with a locator precise enough to
re-read it and a verbatim extract. Identifier- and text-anchored evidence is
never PROBATIVE, and a sink-rule match settles only what its own match type
structurally witnesses.
"""

from __future__ import annotations

import dataclasses

import pytest

from actenon_scan.effects import (
    Admissibility,
    AssertionPredicate,
    EffectModelError,
    EvidenceAssertion,
    EvidencePacket,
    LadderTier,
    Obligation,
    PacketKind,
    Polarity,
    ProbeClass,
    ProbeOutcome,
    ProbeResult,
    RuleMatchType,
    SourceLocator,
    StopReason,
    VerbatimExtract,
    VersionResolution,
)

from ._builders import packet
from ._spec import example

HYPOTHESIS_ONLY_KINDS = [
    PacketKind.IDENTIFIER_NAME,
    PacketKind.PROSE_DOCUMENTATION,
    PacketKind.SOURCE_TEXT_REGEX,
    PacketKind.HTTP_METHOD,
    PacketKind.UNQUALIFIED_NAME_RULE_MATCH,
]


def pinned(path="node_modules/pkg/index.js", **kw):
    return SourceLocator(path=path, start_line=1, end_line=2, package="pkg", version="1.2.3",
                         version_resolution=VersionResolution.LOCKFILE, **kw)


def test_frozen_valid_packet_round_trips():
    p = EvidencePacket.from_dict(example("evidence.valid"))
    assert EvidencePacket.from_dict(p.to_dict()) == p
    assert p.to_dict()["extract"]["verbatim"] is True


def test_frozen_invalid_packet_is_rejected():
    with pytest.raises(EffectModelError, match="HYPOTHESIS_ONLY"):
        EvidencePacket.from_dict(example("evidence.invalid"))


@pytest.mark.parametrize("kind", HYPOTHESIS_ONLY_KINDS)
def test_identifier_and_text_anchored_evidence_is_never_probative(kind):
    extra = {"derived_from_rule_id": "RULE-X"} if kind is PacketKind.UNQUALIFIED_NAME_RULE_MATCH else {}
    with pytest.raises(EffectModelError, match="HYPOTHESIS_ONLY"):
        packet("p", Obligation.BOUNDARY, kind=kind, **extra)
    ok = packet("p", Obligation.BOUNDARY, kind=kind, admissibility=Admissibility.HYPOTHESIS_ONLY, **extra)
    assert not ok.is_probative


@pytest.mark.parametrize("tier", [LadderTier.L4, LadderTier.L5, LadderTier.L6])
def test_dependency_and_contract_evidence_names_package_and_version(tier):
    kind = PacketKind.OPENAPI_OPERATION if tier is LadderTier.L6 else PacketKind.DEPENDENCY_SOURCE_BODY
    obligation = Obligation.IMPLEMENTATION if tier is LadderTier.L4 else Obligation.BOUNDARY
    with pytest.raises(EffectModelError, match="package and version resolution"):
        packet("p", obligation, tier=tier, kind=kind)
    with pytest.raises(EffectModelError, match="package and version resolution"):
        packet("p", obligation, tier=tier, kind=kind,
               locator=SourceLocator(path="x.js", start_line=1, end_line=1, package="pkg"))
    # At L4 obtaining source is a hypothesis; top-level identity needs a binding witness.
    packet("p", obligation, tier=tier, kind=kind, locator=pinned(),
           admissibility=Admissibility.HYPOTHESIS_ONLY if tier is LadderTier.L4 else Admissibility.PROBATIVE)


def test_unpinned_source_is_recorded_as_unpinned_never_substituted():
    locator = SourceLocator(path="vendor/pkg/a.py", start_line=1, end_line=1, package="pkg",
                            version_resolution=VersionResolution.UNPINNED)
    packet("p", Obligation.BOUNDARY, tier=LadderTier.L5, kind=PacketKind.DEPENDENCY_SOURCE_BODY,
           locator=locator, admissibility=Admissibility.HYPOTHESIS_ONLY)
    with pytest.raises(EffectModelError, match="PROBATIVE dependency body requires pinned version provenance"):
        packet("p", Obligation.BOUNDARY, tier=LadderTier.L5, kind=PacketKind.DEPENDENCY_SOURCE_BODY,
               locator=locator)
    with pytest.raises(EffectModelError, match="UNPINNED"):
        SourceLocator(path="a.py", start_line=1, end_line=1, package="pkg", version="latest",
                      version_resolution=VersionResolution.UNPINNED)
    with pytest.raises(EffectModelError, match="requires the resolved version"):
        SourceLocator(path="a.py", start_line=1, end_line=1, package="pkg",
                      version_resolution=VersionResolution.LOCKFILE)
    with pytest.raises(EffectModelError, match="how it was resolved"):
        SourceLocator(path="a.py", start_line=1, end_line=1, package="pkg", version="1.0.0")


def test_l8_is_not_a_packet_tier():
    with pytest.raises(EffectModelError):
        packet("p", Obligation.BOUNDARY, tier=LadderTier.L8)


@pytest.mark.parametrize("path", ["/etc/passwd", "C:/src/x.py", "src\\x.py", "../x.py", "src/../x.py",
                                  "src//x.py", "", "src/"])
def test_locator_paths_are_normalised_and_relative(path):
    with pytest.raises(EffectModelError):
        SourceLocator(path=path, start_line=1, end_line=1)


@pytest.mark.parametrize("fields", [
    dict(start_line=0, end_line=1),
    dict(start_line=5, end_line=4),
    dict(start_line=True, end_line=1),
    dict(start_line=1.0, end_line=1),
    dict(start_line="1", end_line=1),
    dict(start_line=3, end_line=3, start_column=9, end_column=2),
    dict(start_line=1, end_line=1, start_column=-1),
])
def test_locator_spans_are_well_formed(fields):
    with pytest.raises(EffectModelError):
        SourceLocator(path="a.py", **fields)


def test_extract_is_verbatim_and_truncation_is_marked():
    with pytest.raises(EffectModelError):
        VerbatimExtract(text="")
    with pytest.raises(EffectModelError, match="truncation marker"):
        VerbatimExtract(text="abc", truncated=True)
    with pytest.raises(EffectModelError, match="untruncated"):
        VerbatimExtract(text="abc", truncation_marker="...")
    assert VerbatimExtract(text="abc", truncated=True, truncation_marker="[...]").verbatim is True
    for verbatim in (False, None, "true", 1):
        with pytest.raises(EffectModelError):
            VerbatimExtract.from_dict({"text": "abc", "verbatim": verbatim})
    with pytest.raises(EffectModelError):
        VerbatimExtract.from_dict({"text": "abc"})


# ---------------------------------------------------------- sink-rule packets


def rule_packet(match_type, obligation, admissibility=Admissibility.PROBATIVE, **kw):
    kind = kw.pop("kind", PacketKind.SINK_RULE_MATCH)
    return packet("p-rule", obligation, kind=kind, admissibility=admissibility, tier=LadderTier.L0
                  if obligation is Obligation.BOUNDARY else LadderTier.L1,
                  derived_from_rule_id=kw.pop("rule_id", "RULE-1"), rule_match_type=match_type, **kw)


@pytest.mark.parametrize("match_type", [RuleMatchType.SQL_EXECUTE_PATTERN, RuleMatchType.STRING_PATTERN])
@pytest.mark.parametrize("obligation", [Obligation.BOUNDARY, Obligation.OPERATION])
def test_text_pattern_rules_are_hypothesis_only(match_type, obligation):
    with pytest.raises(EffectModelError, match="HYPOTHESIS_ONLY"):
        rule_packet(match_type, obligation)
    assert not rule_packet(match_type, obligation, Admissibility.HYPOTHESIS_ONLY).is_probative


def test_name_call_rules_are_hypothesis_only_and_use_their_own_kind():
    with pytest.raises(EffectModelError):
        rule_packet(RuleMatchType.NAME_CALL, Obligation.BOUNDARY, Admissibility.HYPOTHESIS_ONLY)
    with pytest.raises(EffectModelError, match="HYPOTHESIS_ONLY"):
        rule_packet(RuleMatchType.NAME_CALL, Obligation.BOUNDARY, kind=PacketKind.UNQUALIFIED_NAME_RULE_MATCH)
    rule_packet(RuleMatchType.NAME_CALL, Obligation.OPERATION, Admissibility.HYPOTHESIS_ONLY,
                kind=PacketKind.UNQUALIFIED_NAME_RULE_MATCH)


@pytest.mark.parametrize("match_type, obligation", [
    (RuleMatchType.ATTR_CALL, Obligation.PERSISTENCE),
    (RuleMatchType.QUALIFIED_CALL, Obligation.PERSISTENCE),
    (RuleMatchType.QUALIFIED_CALL, Obligation.ACTIVATION),
    (RuleMatchType.OPEN_WRITE, Obligation.OPERATION),
    (RuleMatchType.SUBPROCESS_DEPLOY, Obligation.OPERATION),
    (RuleMatchType.GITHUB_REST_MUTATION, Obligation.PERSISTENCE),
])
def test_probative_rule_matches_settle_only_what_they_witness(match_type, obligation):
    with pytest.raises(EffectModelError, match="cannot settle"):
        rule_packet(match_type, obligation)
    rule_packet(match_type, obligation, Admissibility.HYPOTHESIS_ONLY)


def test_a_structural_rule_match_may_settle_boundary():
    p = rule_packet(RuleMatchType.ATTR_CALL, Obligation.BOUNDARY)
    assert p.is_probative and p.is_rule_derived


def test_rule_provenance_is_tied_to_rule_packet_kinds_both_ways():
    with pytest.raises(EffectModelError, match="name the rule"):
        rule_packet(RuleMatchType.ATTR_CALL, Obligation.BOUNDARY, rule_id=None)
    with pytest.raises(EffectModelError, match="match type"):
        packet("p", Obligation.BOUNDARY, tier=LadderTier.L0, kind=PacketKind.SINK_RULE_MATCH,
               derived_from_rule_id="RULE-1")
    with pytest.raises(EffectModelError, match="only legal on rule-match packets"):
        packet("p", Obligation.BOUNDARY, derived_from_rule_id="RULE-1")
    with pytest.raises(EffectModelError, match="only legal on rule-match packets"):
        packet("p", Obligation.BOUNDARY, rule_match_type=RuleMatchType.ATTR_CALL)


# ------------------------------------------------- obligation / tier / polarity


@pytest.mark.parametrize("tier, obligation", [
    (LadderTier.L0, Obligation.OPERATION),
    (LadderTier.L0, Obligation.PERSISTENCE),
    (LadderTier.L2, Obligation.OPERATION),
    (LadderTier.L3, Obligation.BOUNDARY),
    (LadderTier.L5, Obligation.ACTIVATION),
    (LadderTier.L7, Obligation.ACTIVATION),
])
def test_probative_evidence_only_from_a_tier_that_can_settle_it(tier, obligation):
    loc = pinned() if tier in (LadderTier.L4, LadderTier.L5, LadderTier.L6) else None
    with pytest.raises(EffectModelError, match="cannot settle"):
        packet("p", obligation, tier=tier, locator=loc)
    packet("p", obligation, tier=tier, locator=loc, admissibility=Admissibility.HYPOTHESIS_ONLY)


@pytest.mark.parametrize("predicate, obligation, polarity", [
    (AssertionPredicate.OPERATION_IS_MUTATION, Obligation.OPERATION, Polarity.NEGATIVE),
    (AssertionPredicate.OPERATION_IS_MUTATION, Obligation.PERSISTENCE, Polarity.POSITIVE),
    (AssertionPredicate.STATE_IS_GUARANTEED_ROLLED_BACK, Obligation.PERSISTENCE, Polarity.POSITIVE),
    (AssertionPredicate.EGRESS_MECHANISM_IS, Obligation.OPERATION, Polarity.POSITIVE),
    (AssertionPredicate.INVOCATION_DOES_NOT_EXECUTE, Obligation.ACTIVATION, Polarity.POSITIVE),
    (AssertionPredicate.IMPLEMENTATION_IS, Obligation.BOUNDARY, Polarity.POSITIVE),
    (AssertionPredicate.COMMIT_OUTCOME_UNDETERMINED, Obligation.OPERATION, Polarity.POSITIVE),
])
def test_assertions_bear_on_their_own_obligation_and_polarity(predicate, obligation, polarity):
    base = packet("p", Obligation.BOUNDARY)
    with pytest.raises(EffectModelError, match="predicate"):
        dataclasses.replace(base, assertion=EvidenceAssertion(predicate), obligation=obligation, polarity=polarity)


def test_packet_from_dict_is_strict():
    d = packet("p", Obligation.BOUNDARY).to_dict()
    for mutate in (
        lambda x: x.update(extra=1),
        lambda x: x.pop("extract"),
        lambda x: x.update(obligation=None),
        lambda x: x.update(obligation=["BOUNDARY", "OPERATION"]),
        lambda x: x["acquisition_cost"].update(hops=True),
        lambda x: x.update(tier="l1"),
        lambda x: x.update(packet_id="has space"),
    ):
        bad = packet("p", Obligation.BOUNDARY).to_dict()
        mutate(bad)
        with pytest.raises(EffectModelError):
            EvidencePacket.from_dict(bad)
    assert EvidencePacket.from_dict(d) == packet("p", Obligation.BOUNDARY)


# ------------------------------------------------------------- probe outcomes


def test_probes_come_from_the_closed_registry():
    with pytest.raises(EffectModelError, match="registry"):
        ProbeOutcome("CP-OPR-09", Obligation.OPERATION, ProbeClass.BLOCKING, ProbeResult.NOT_FOUND)
    with pytest.raises(EffectModelError, match="registered as"):
        ProbeOutcome("CP-ACT-03", Obligation.ACTIVATION, ProbeClass.BLOCKING, ProbeResult.NOT_FOUND)
    with pytest.raises(EffectModelError, match="registered as"):
        ProbeOutcome("CP-OPR-01", Obligation.PERSISTENCE, ProbeClass.BLOCKING, ProbeResult.NOT_FOUND)


def test_probe_results_are_not_interchangeable():
    with pytest.raises(EffectModelError, match="incomplete_reason"):
        ProbeOutcome("CP-OPR-01", Obligation.OPERATION, ProbeClass.BLOCKING, ProbeResult.NOT_FOUND,
                     incomplete_reason=StopReason.TIER_UNAVAILABLE)
    with pytest.raises(EffectModelError, match="cite the packets"):
        ProbeOutcome("CP-OPR-01", Obligation.OPERATION, ProbeClass.BLOCKING, ProbeResult.FOUND)
    with pytest.raises(EffectModelError, match="found nothing"):
        ProbeOutcome("CP-OPR-01", Obligation.OPERATION, ProbeClass.BLOCKING, ProbeResult.NOT_FOUND,
                     packet_ids=("p",))
    incomplete = ProbeOutcome("CP-OPR-01", Obligation.OPERATION, ProbeClass.BLOCKING, ProbeResult.INCOMPLETE,
                              incomplete_reason=StopReason.TIER_UNAVAILABLE)
    assert not incomplete.completed
