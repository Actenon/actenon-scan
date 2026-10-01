"""Internal frontend proofs; these are binding facts, never effect predicates."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SemanticState(str, Enum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"


class EdgeObligation(str, Enum):
    TARGET_EXACT = "TARGET_EXACT"
    EXECUTION_OWNER_EXACT = "EXECUTION_OWNER_EXACT"
    EVALUATION_EAGER = "EVALUATION_EAGER"
    WRITE_SET_CLOSED = "WRITE_SET_CLOSED"
    RECEIVER_COMPATIBLE = "RECEIVER_COMPATIBLE"
    IMPORT_PROVENANCE_EXACT = "IMPORT_PROVENANCE_EXACT"


BASE_OBLIGATIONS = frozenset({EdgeObligation.TARGET_EXACT,
    EdgeObligation.EXECUTION_OWNER_EXACT, EdgeObligation.EVALUATION_EAGER,
    EdgeObligation.WRITE_SET_CLOSED})


def meet(states):
    states = tuple(states)
    if SemanticState.REFUTED in states:
        return SemanticState.REFUTED
    return SemanticState.SUPPORTED if states and all(s == SemanticState.SUPPORTED for s in states) else SemanticState.UNKNOWN


@dataclass(frozen=True)
class BindingEdgeProof:
    required: frozenset[EdgeObligation] = BASE_OBLIGATIONS
    facts: tuple[tuple[EdgeObligation, SemanticState], ...] = ()
    provenance: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "required", BASE_OBLIGATIONS | frozenset(EdgeObligation(x) for x in self.required))
        converted = tuple((EdgeObligation(k), SemanticState(v)) for k, v in self.facts)
        object.__setattr__(self, "facts", converted)

    def state(self, obligation):
        return meet(v for k, v in self.facts if k == obligation)

    @property
    def closed(self):
        return all(self.state(k) == SemanticState.SUPPORTED for k in self.required)

    @property
    def refuted(self):
        return any(self.state(k) == SemanticState.REFUTED for k in self.required)

    def accumulate(self, other):
        # Duplicate facts are retained: UNKNOWN/REFUTED cannot be overwritten.
        return BindingEdgeProof(self.required | other.required, self.facts + other.facts,
                                tuple(sorted(set(self.provenance + other.provenance))))

    def to_dict(self):
        return {"required": sorted(k.value for k in self.required),
                "obligations": {k.value: self.state(k).value for k in sorted(self.required, key=lambda k: k.value)},
                "provenance": list(self.provenance)}


class EvaluationMode(str, Enum):
    EAGER = "EAGER"
    DEFERRED = "DEFERRED"
    NON_RUNTIME = "NON_RUNTIME"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ExecutionRegion:
    region_id: str
    lexical_scope: str
    owner_key: str
    mode: EvaluationMode
    reason: str
    owner_exact: SemanticState = SemanticState.SUPPORTED

    @property
    def eager(self):
        return SemanticState.SUPPORTED if self.mode == EvaluationMode.EAGER else SemanticState.UNKNOWN

    def to_dict(self):
        return {**vars(self), "mode": self.mode.value, "owner_exact": self.owner_exact.value}


class TargetKind(str, Enum):
    LEXICAL_BINDING = "LEXICAL_BINDING"
    MEMBER = "MEMBER"
    NAMESPACE_MEMBER = "NAMESPACE_MEMBER"
    UNKNOWN_TARGET = "UNKNOWN_TARGET"


class WriteOperation(str, Enum):
    DECLARE = "DECLARE"
    ASSIGN = "ASSIGN"
    DELETE = "DELETE"
    MAY_WRITE = "MAY_WRITE"


class WriteCertainty(str, Enum):
    EXACT = "EXACT"
    POSSIBLE = "POSSIBLE"


@dataclass(frozen=True)
class WriteEvent:
    scope: str
    target_kind: TargetKind
    operation: WriteOperation
    binding: str = ""
    base: str = ""
    member: str = ""
    certainty: WriteCertainty = WriteCertainty.EXACT
    line: int = 0
    syntax: str = ""

    def to_dict(self):
        return {**vars(self), "target_kind": self.target_kind.value,
                "operation": self.operation.value, "certainty": self.certainty.value}


@dataclass
class CompletenessCertificate:
    scope: str
    # A certificate starts UNKNOWN. Only the frontend's completed inventory
    # audit can seal a facet; subsequent counter-facts only open it again.
    facets: dict[str, SemanticState] = field(default_factory=dict)
    limitations: set[str] = field(default_factory=set)

    def state(self, facet):
        return self.facets.get(facet, SemanticState.UNKNOWN)

    def open(self, facets, reason):
        self.limitations.add(reason)
        for facet in facets:
            self.facets[facet] = SemanticState.UNKNOWN

    def to_dict(self):
        return {"scope": self.scope, "facets": {k: v.value for k, v in sorted(self.facets.items())},
                "limitations": sorted(self.limitations)}


COMPLETENESS_FACETS = ("execution_semantics_complete", "lexical_writes_complete",
    "member_writes_complete", "import_semantics_complete", "receiver_semantics_complete")
