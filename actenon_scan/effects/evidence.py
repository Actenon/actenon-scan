"""Evidence packets, source provenance and counter-evidence probe outcomes.

Frozen by ``specs/AREF-002/evidence_acquisition.md`` and
``specs/AREF-002/evidence.schema.json``. A packet never instantiates or
suppresses a claim; it can only bear on one obligation for one implementation
candidate, and only a ``PROBATIVE`` packet can ever move a state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from actenon_scan.effects import _codec as c
from actenon_scan.effects._assertions import PROBATIVE_ASSERTIONS
from actenon_scan.effects.vocabulary import (
    HYPOTHESIS_ONLY_KINDS,
    PROBE_REGISTRY,
    RULE_MATCH_ADMISSIBILITY,
    RULE_PACKET_KINDS,
    TIERS_REQUIRING_PACKAGE,
    Admissibility,
    AssertionPredicate,
    LadderTier,
    Obligation,
    PacketKind,
    Polarity,
    ProbeClass,
    ProbeResult,
    RuleMatchType,
    StopReason,
    Strength,
    VersionResolution,
)


def _check_path(path: str, where: str) -> str:
    path = c.text(path, where)
    if "\\" in path:
        raise c.fail(where, "must be forward-slash separated")
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise c.fail(where, "must be relative to the scan root")
    if any(part in ("", "..") for part in path.split("/")):
        raise c.fail(where, f"{path!r} is not a normalised relative path")
    return path


@dataclass(frozen=True)
class SourceLocator:
    """Where evidence came from, precisely enough to re-read and re-verify it."""

    path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None
    symbol: str | None = None
    package: str | None = None
    version: str | None = None
    version_resolution: VersionResolution | None = None
    document_pointer: str | None = None

    def __post_init__(self) -> None:
        w = "locator"
        _check_path(self.path, f"{w}.path")
        c.integer(self.start_line, f"{w}.start_line", 1)
        c.integer(self.end_line, f"{w}.end_line", 1)
        if self.end_line < self.start_line:
            raise c.fail(w, "end_line precedes start_line")
        c.optional_integer(self.start_column, f"{w}.start_column", 0)
        c.optional_integer(self.end_column, f"{w}.end_column", 0)
        if (self.start_column is not None and self.end_column is not None
                and self.start_line == self.end_line and self.end_column < self.start_column):
            raise c.fail(w, "end_column precedes start_column on a single-line span")
        c.optional_text(self.symbol, f"{w}.symbol")
        c.optional_text(self.package, f"{w}.package", min_length=1)
        c.optional_text(self.version, f"{w}.version", min_length=1)
        c.optional_text(self.document_pointer, f"{w}.document_pointer")
        object.__setattr__(self, "version_resolution", c.optional_enum(
            VersionResolution, self.version_resolution, f"{w}.version_resolution"))
        if self.version is not None and self.version_resolution is None:
            raise c.fail(w, "a version must state how it was resolved")
        if self.version_resolution is VersionResolution.UNPINNED and self.version is not None:
            raise c.fail(w, "UNPINNED means no resolvable version; none may be substituted")
        if self.version_resolution not in (None, VersionResolution.UNPINNED) and self.version is None:
            raise c.fail(w, f"{self.version_resolution.value} resolution requires the resolved version")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"path": self.path, "start_line": self.start_line, "end_line": self.end_line}
        c.put(out, "start_column", self.start_column)
        c.put(out, "end_column", self.end_column)
        c.put(out, "symbol", self.symbol)
        c.put(out, "package", self.package)
        c.put(out, "version", self.version)
        c.put(out, "version_resolution", self.version_resolution and self.version_resolution.value)
        c.put(out, "document_pointer", self.document_pointer)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "locator") -> "SourceLocator":
        r = c.Reader(data, where, ("path", "start_line", "end_line"), (
            "start_column", "end_column", "symbol", "package", "version",
            "version_resolution", "document_pointer"))
        return cls(**{k: r.get(k) for k in (
            "path", "start_line", "end_line", "start_column", "end_column", "symbol",
            "package", "version", "version_resolution", "document_pointer")})


@dataclass(frozen=True)
class VerbatimExtract:
    """Byte-identical source text. There is no non-verbatim extract."""

    text: str
    truncated: bool | None = None
    truncation_marker: str | None = None

    def __post_init__(self) -> None:
        c.text(self.text, "extract.text")
        c.optional_boolean(self.truncated, "extract.truncated")
        c.optional_text(self.truncation_marker, "extract.truncation_marker", min_length=1)
        if self.truncated and self.truncation_marker is None:
            raise c.fail("extract", "a truncated extract requires an explicit truncation marker")
        if self.truncation_marker is not None and not self.truncated:
            raise c.fail("extract", "a truncation marker on an untruncated extract")

    @property
    def verbatim(self) -> bool:
        return True

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"text": self.text, "verbatim": True}
        c.put(out, "truncated", self.truncated)
        c.put(out, "truncation_marker", self.truncation_marker)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "extract") -> "VerbatimExtract":
        r = c.Reader(data, where, ("text", "verbatim"), ("truncated", "truncation_marker"))
        if r.get("verbatim") is not True:
            raise c.fail(r.at("verbatim"), "must be exactly true")
        return cls(text=r.get("text"), truncated=r.get("truncated"),
                   truncation_marker=r.get("truncation_marker"))


@dataclass(frozen=True)
class AcquisitionCost:
    hops: int
    bytes_read: int
    artefacts_opened: int | None = None
    wall_ms: int | None = None

    def __post_init__(self) -> None:
        c.integer(self.hops, "acquisition_cost.hops")
        c.integer(self.bytes_read, "acquisition_cost.bytes_read")
        c.optional_integer(self.artefacts_opened, "acquisition_cost.artefacts_opened")
        c.optional_integer(self.wall_ms, "acquisition_cost.wall_ms")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"hops": self.hops, "bytes_read": self.bytes_read}
        c.put(out, "artefacts_opened", self.artefacts_opened)
        c.put(out, "wall_ms", self.wall_ms)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "acquisition_cost") -> "AcquisitionCost":
        r = c.Reader(data, where, ("hops", "bytes_read"), ("artefacts_opened", "wall_ms"))
        return cls(**{k: r.get(k) for k in ("hops", "bytes_read", "artefacts_opened", "wall_ms")})


@dataclass(frozen=True)
class EvidenceAssertion:
    predicate: AssertionPredicate | str
    detail: str | None = None

    def __post_init__(self) -> None:
        if type(self.predicate) is str:
            c.text(self.predicate, "assertion.predicate", min_length=1)
            if self.predicate in {p.value for p in AssertionPredicate}:
                object.__setattr__(self, "predicate", AssertionPredicate(self.predicate))
        else:
            object.__setattr__(self, "predicate", c.enum_value(
                AssertionPredicate, self.predicate, "assertion.predicate"))
        c.optional_text(self.detail, "assertion.detail")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"predicate": self.predicate.value if isinstance(self.predicate, AssertionPredicate) else self.predicate}
        c.put(out, "detail", self.detail)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "assertion") -> "EvidenceAssertion":
        r = c.Reader(data, where, ("predicate",), ("detail",))
        return cls(predicate=r.get("predicate"), detail=r.get("detail"))


@dataclass(frozen=True)
class BindingWitness:
    """Supplied binding provenance; M0 validates links, not source truth."""

    relation: str
    invocation_id: str
    source: SourceLocator
    target: SourceLocator

    def __post_init__(self) -> None:
        c.text(self.relation, "binding.relation")
        if self.relation not in {"SELECTED_TARGET", "POSSIBLE_TARGET", "RESOLVED_CALL"}:
            raise c.fail("binding.relation", "unknown binding relation")
        c.identifier(self.invocation_id, "binding.invocation_id")
        c.instance(SourceLocator, self.source, "binding.from")
        c.instance(SourceLocator, self.target, "binding.to")

    def to_dict(self) -> dict:
        return {"relation": self.relation, "invocation_id": self.invocation_id,
                "from": self.source.to_dict(), "to": self.target.to_dict()}

    @classmethod
    def from_dict(cls, data: Any, where: str = "binding") -> "BindingWitness":
        r = c.Reader(data, where, ("relation", "invocation_id", "from", "to"))
        return cls(r.get("relation"), r.get("invocation_id"),
                   SourceLocator.from_dict(r.get("from"), r.at("from")),
                   SourceLocator.from_dict(r.get("to"), r.at("to")))


@dataclass(frozen=True)
class EvidencePacket:
    """One unit of evidence: one obligation, one implementation candidate."""

    packet_id: str
    tier: LadderTier
    kind: PacketKind
    locator: SourceLocator
    assertion: EvidenceAssertion
    polarity: Polarity
    obligation: Obligation
    implementation_candidate_id: str
    admissibility: Admissibility
    strength: Strength
    acquisition_cost: AcquisitionCost
    extract: VerbatimExtract
    derived_from_rule_id: str | None = None
    rule_match_type: RuleMatchType | None = None
    notes: str | None = None
    binding: BindingWitness | None = None

    def __post_init__(self) -> None:
        w = f"packet {self.packet_id!r}"
        c.identifier(self.packet_id, f"{w}.packet_id")
        c.identifier(self.implementation_candidate_id, f"{w}.implementation_candidate_id")
        for name, cls in (("tier", LadderTier), ("kind", PacketKind), ("polarity", Polarity),
                          ("obligation", Obligation), ("admissibility", Admissibility),
                          ("strength", Strength)):
            object.__setattr__(self, name, c.enum_value(cls, getattr(self, name), f"{w}.{name}"))
        object.__setattr__(self, "rule_match_type", c.optional_enum(
            RuleMatchType, self.rule_match_type, f"{w}.rule_match_type"))
        c.instance(SourceLocator, self.locator, f"{w}.locator")
        c.instance(EvidenceAssertion, self.assertion, f"{w}.assertion")
        c.instance(AcquisitionCost, self.acquisition_cost, f"{w}.acquisition_cost")
        c.instance(VerbatimExtract, self.extract, f"{w}.extract")
        c.optional_text(self.derived_from_rule_id, f"{w}.derived_from_rule_id", min_length=1)
        c.optional_text(self.notes, f"{w}.notes")
        c.optional_instance(BindingWitness, self.binding, f"{w}.binding")

        if self.tier is LadderTier.L8:
            raise c.fail(w, "L8 is the terminal ABSTAIN state, not an evidence tier")
        if self.tier in TIERS_REQUIRING_PACKAGE and (
                self.locator.package is None or self.locator.version_resolution is None):
            raise c.fail(w, f"{self.tier.value} evidence must name its package and version resolution")
        if self.kind in HYPOTHESIS_ONLY_KINDS and self.admissibility is not Admissibility.HYPOTHESIS_ONLY:
            raise c.fail(w, f"{self.kind.value} evidence is identifier- or text-anchored and "
                            "can only be HYPOTHESIS_ONLY")
        self._check_rule_provenance(w)
        self._check_predicate(w)
        if self.is_probative and self.kind is PacketKind.DEPENDENCY_SOURCE_BODY and self.locator.version_resolution in (None, VersionResolution.UNPINNED):
            raise c.fail(w, "PROBATIVE dependency body requires pinned version provenance")

    def _check_rule_provenance(self, w: str) -> None:
        is_rule_kind = self.kind in RULE_PACKET_KINDS
        has_rule_fields = self.derived_from_rule_id is not None or self.rule_match_type is not None
        if has_rule_fields and not is_rule_kind:
            raise c.fail(w, "rule provenance fields are only legal on rule-match packets")
        if not is_rule_kind:
            return
        if self.derived_from_rule_id is None:
            raise c.fail(w, f"a {self.kind.value} packet must name the rule it was derived from")
        if self.kind is PacketKind.SINK_RULE_MATCH:
            if self.rule_match_type is None:
                raise c.fail(w, "a sink_rule_match packet must record the rule's match type")
            if self.rule_match_type is RuleMatchType.NAME_CALL:
                raise c.fail(w, "a name_call match is an unqualified_name_rule_match packet")
        elif self.rule_match_type not in (None, RuleMatchType.NAME_CALL):
            raise c.fail(w, "an unqualified_name_rule_match packet can only carry match type name_call")
        if self.rule_match_type is None:
            return
        rule = RULE_MATCH_ADMISSIBILITY[self.rule_match_type]
        if rule.admissibility is Admissibility.HYPOTHESIS_ONLY and self.is_probative:
            raise c.fail(w, f"{self.rule_match_type.value} rule matches are HYPOTHESIS_ONLY")
        if self.is_probative and self.obligation not in rule.may_settle:
            raise c.fail(w, f"a {self.rule_match_type.value} rule match cannot settle "
                            f"{self.obligation.value}")

    def _check_predicate(self, w: str) -> None:
        predicate = self.assertion.to_dict()["predicate"]
        key = (predicate, self.obligation.value, self.polarity.value, self.kind.value, self.tier.value)
        if self.is_probative and key not in PROBATIVE_ASSERTIONS:
            raise c.fail(w, "unregistered predicate/obligation/polarity/source combination cannot settle proof")
        if self.binding is not None and not (self.is_probative and predicate == "implementation_is"
                and self.obligation is Obligation.IMPLEMENTATION and self.polarity is Polarity.POSITIVE
                and self.kind in {PacketKind.LOCAL_BINDING, PacketKind.TYPE_DECLARATION, PacketKind.INTERFACE_DECLARATION}):
            raise c.fail(w, "binding requires a PROBATIVE implementation_is binding assertion")
        if self.is_probative and predicate == "implementation_is" and self.binding is None:
            raise c.fail(w, "implementation_is requires binding provenance")

    @property
    def is_probative(self) -> bool:
        return self.admissibility is Admissibility.PROBATIVE

    @property
    def is_rule_derived(self) -> bool:
        return self.kind in RULE_PACKET_KINDS

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "packet_id": self.packet_id,
            "tier": self.tier.value,
            "kind": self.kind.value,
            "locator": self.locator.to_dict(),
            "assertion": self.assertion.to_dict(),
            "polarity": self.polarity.value,
            "obligation": self.obligation.value,
            "implementation_candidate_id": self.implementation_candidate_id,
            "admissibility": self.admissibility.value,
            "strength": self.strength.value,
            "acquisition_cost": self.acquisition_cost.to_dict(),
            "extract": self.extract.to_dict(),
        }
        c.put(out, "derived_from_rule_id", self.derived_from_rule_id)
        c.put(out, "rule_match_type", self.rule_match_type and self.rule_match_type.value)
        c.put(out, "notes", self.notes)
        c.put(out, "binding", self.binding and self.binding.to_dict())
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "packet") -> "EvidencePacket":
        r = c.Reader(data, where, (
            "packet_id", "tier", "kind", "locator", "assertion", "polarity", "obligation",
            "implementation_candidate_id", "admissibility", "strength", "acquisition_cost",
            "extract"), ("derived_from_rule_id", "rule_match_type", "notes", "binding"))
        return cls(
            packet_id=r.get("packet_id"),
            tier=r.get("tier"),
            kind=r.get("kind"),
            locator=SourceLocator.from_dict(r.get("locator"), r.at("locator")),
            assertion=EvidenceAssertion.from_dict(r.get("assertion"), r.at("assertion")),
            polarity=r.get("polarity"),
            obligation=r.get("obligation"),
            implementation_candidate_id=r.get("implementation_candidate_id"),
            admissibility=r.get("admissibility"),
            strength=r.get("strength"),
            acquisition_cost=AcquisitionCost.from_dict(r.get("acquisition_cost"), r.at("acquisition_cost")),
            extract=VerbatimExtract.from_dict(r.get("extract"), r.at("extract")),
            derived_from_rule_id=r.get("derived_from_rule_id"),
            rule_match_type=r.get("rule_match_type"),
            notes=r.get("notes"),
            binding=None if "binding" not in r else BindingWitness.from_dict(r.get("binding"), r.at("binding")),
        )


@dataclass(frozen=True)
class ProbeOutcome:
    """The recorded outcome of one probe from the closed registry.

    Non-execution is never ``NOT_FOUND``: an unexecuted probe has no outcome,
    and a probe that could not finish is ``INCOMPLETE``.
    """

    probe_id: str
    obligation: Obligation
    probe_class: ProbeClass
    outcome: ProbeResult
    incomplete_reason: StopReason | None = None
    packet_ids: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        w = f"probe {self.probe_id!r}"
        c.text(self.probe_id, f"{w}.probe_id")
        object.__setattr__(self, "obligation", c.enum_value(Obligation, self.obligation, f"{w}.obligation"))
        object.__setattr__(self, "probe_class", c.enum_value(ProbeClass, self.probe_class, f"{w}.probe_class"))
        object.__setattr__(self, "outcome", c.enum_value(ProbeResult, self.outcome, f"{w}.outcome"))
        object.__setattr__(self, "incomplete_reason", c.optional_enum(
            StopReason, self.incomplete_reason, f"{w}.incomplete_reason"))
        ids = tuple(c.identifier(p, f"{w}.packet_ids") for p in c.sequence(self.packet_ids, f"{w}.packet_ids"))
        object.__setattr__(self, "packet_ids", c.unique(ids, f"{w}.packet_ids"))

        spec = PROBE_REGISTRY.get(self.probe_id)
        if spec is None:
            raise c.fail(w, "not in the closed counter-evidence probe registry")
        if (spec.obligation, spec.probe_class) != (self.obligation, self.probe_class):
            raise c.fail(w, f"registered as {spec.probe_class.value} for {spec.obligation.value}")
        if self.outcome is ProbeResult.INCOMPLETE:
            if self.incomplete_reason is StopReason.SETTLED:
                raise c.fail(w, "SETTLED is not a reason for a probe to be incomplete")
        elif self.incomplete_reason is not None:
            raise c.fail(w, "only an INCOMPLETE probe has an incomplete_reason")
        if self.outcome is ProbeResult.FOUND and not self.packet_ids:
            raise c.fail(w, "a probe that found counter-evidence must cite the packets it produced")
        if self.outcome is ProbeResult.NOT_FOUND and self.packet_ids:
            raise c.fail(w, "a probe that found nothing cannot have produced packets")

    @property
    def completed(self) -> bool:
        return self.outcome is not ProbeResult.INCOMPLETE

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "probe_id": self.probe_id,
            "obligation": self.obligation.value,
            "probe_class": self.probe_class.value,
            "outcome": self.outcome.value,
        }
        c.put(out, "incomplete_reason", self.incomplete_reason and self.incomplete_reason.value)
        if self.packet_ids:
            out["packet_ids"] = list(self.packet_ids)
        return out

    @classmethod
    def from_dict(cls, data: Any, where: str = "probe_outcome") -> "ProbeOutcome":
        r = c.Reader(data, where, ("probe_id", "obligation", "probe_class", "outcome"),
                     ("incomplete_reason", "packet_ids"))
        return cls(probe_id=r.get("probe_id"), obligation=r.get("obligation"),
                   probe_class=r.get("probe_class"), outcome=r.get("outcome"),
                   incomplete_reason=r.get("incomplete_reason"),
                   packet_ids=r.get("packet_ids", ()))


def check_packet_set(packets: tuple, candidate_ids: frozenset, where: str) -> dict:
    """Shared by claims and receipts: unique ids, known candidates. Returns id -> packet."""
    by_id: dict[str, EvidencePacket] = {}
    for p in packets:
        if p.packet_id in by_id:
            raise c.fail(where, f"duplicate packet id {p.packet_id!r}")
        if p.implementation_candidate_id not in candidate_ids:
            raise c.fail(where, f"packet {p.packet_id!r} names unknown candidate "
                                f"{p.implementation_candidate_id!r}")
        by_id[p.packet_id] = p
    return by_id


def check_probe_set(outcomes: tuple, packets_by_id: dict, where: str) -> dict:
    """Shared by claims and receipts: unique probes, cited packets exist and match."""
    by_id: dict[str, ProbeOutcome] = {}
    for o in outcomes:
        if o.probe_id in by_id:
            raise c.fail(where, f"probe {o.probe_id!r} recorded twice")
        for pid in o.packet_ids:
            packet = packets_by_id.get(pid)
            if packet is None:
                raise c.fail(where, f"probe {o.probe_id!r} cites unknown packet {pid!r}")
            if packet.obligation is not o.obligation:
                raise c.fail(where, f"probe {o.probe_id!r} cites packet {pid!r} for another obligation")
            if packet.is_probative and packet.polarity is not Polarity.NEGATIVE:
                raise c.fail(where, "a positive settling packet is not found counter-evidence")
            if o.probe_id == "CP-PER-05" and packet.assertion.predicate is not AssertionPredicate.COMMIT_OUTCOME_UNDETERMINED:
                raise c.fail(where, "commit-uncertainty probe requires its typed uncertainty assertion")
        by_id[o.probe_id] = o
    return by_id
