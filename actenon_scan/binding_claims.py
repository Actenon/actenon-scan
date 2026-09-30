"""Internal lexical binding evidence. This is not an effect proof vocabulary."""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum


class BindingState(str, Enum):
    ESTABLISHED = "ESTABLISHED"
    POSSIBLE = "POSSIBLE"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"


class BindingEvidence(str, Enum):
    LEXICAL_DECLARATION = "LEXICAL_DECLARATION"
    IMPORT_PROVENANCE = "IMPORT_PROVENANCE"
    RECEIVER_IDENTITY = "RECEIVER_IDENTITY"
    CALLABLE_SELF_BINDING = "CALLABLE_SELF_BINDING"
    STRUCTURALLY_EXACT_ALIAS = "STRUCTURALLY_EXACT_ALIAS"
    LEXICAL_SHADOW = "LEXICAL_SHADOW"
    AMBIGUOUS_DECLARATION = "AMBIGUOUS_DECLARATION"
    CONDITIONAL_IMPORT = "CONDITIONAL_IMPORT"
    CONDITIONAL_DECLARATION = "CONDITIONAL_DECLARATION"
    UNKNOWN_DECORATOR = "UNKNOWN_DECORATOR"
    REASSIGNMENT_WRITE = "REASSIGNMENT_WRITE"
    INCOMPATIBLE_RECEIVER = "INCOMPATIBLE_RECEIVER"
    UNRESOLVED_ALIAS = "UNRESOLVED_ALIAS"
    UNRESOLVED_IMPORT = "UNRESOLVED_IMPORT"
    UNESTABLISHED_RECEIVER = "UNESTABLISHED_RECEIVER"
    DEFERRED_EXECUTION = "DEFERRED_EXECUTION"
    EXECUTION_NOT_ESTABLISHED = "EXECUTION_NOT_ESTABLISHED"
    NO_BINDING_PROOF = "NO_BINDING_PROOF"
    INITIALIZATION_NOT_ESTABLISHED = "INITIALIZATION_NOT_ESTABLISHED"


@dataclass(frozen=True)
class BindingClaim:
    subject: str
    candidate_id: str
    positive_evidence: frozenset[BindingEvidence] = frozenset()
    counter_evidence: frozenset[BindingEvidence] = frozenset()
    candidate_is_local: bool = False

    def __post_init__(self):
        positive = frozenset(BindingEvidence(e) for e in self.positive_evidence)
        counter = frozenset(BindingEvidence(e) for e in self.counter_evidence)
        supporting = {BindingEvidence.LEXICAL_DECLARATION, BindingEvidence.IMPORT_PROVENANCE,
                      BindingEvidence.RECEIVER_IDENTITY, BindingEvidence.CALLABLE_SELF_BINDING,
                      BindingEvidence.STRUCTURALLY_EXACT_ALIAS}
        if not self.subject or not self.candidate_id or not positive <= supporting or counter & supporting:
            raise ValueError("invalid binding subject/candidate or evidence polarity")
        object.__setattr__(self, "positive_evidence", positive)
        object.__setattr__(self, "counter_evidence", counter)

    @property
    def state(self) -> BindingState:
        if self.candidate_is_local and self.counter_evidence & {BindingEvidence.INCOMPATIBLE_RECEIVER,
                                    BindingEvidence.LEXICAL_SHADOW}:
            return BindingState.REFUTED
        if self.counter_evidence:
            return BindingState.POSSIBLE if self.candidate_is_local or self.positive_evidence else BindingState.UNKNOWN
        if self.positive_evidence & {BindingEvidence.LEXICAL_DECLARATION, BindingEvidence.CALLABLE_SELF_BINDING}:
            return BindingState.ESTABLISHED
        return BindingState.POSSIBLE if self.positive_evidence or self.candidate_is_local else BindingState.UNKNOWN

    def with_evidence(self, *, positive=(), counter=()):
        """Accumulation never removes a previously observed counter-fact."""
        return replace(self, positive_evidence=self.positive_evidence | frozenset(positive),
                       counter_evidence=self.counter_evidence | frozenset(counter))

    def to_dict(self):
        return {"subject": self.subject, "candidate": self.candidate_id,
                "positive_evidence": sorted(e.value for e in self.positive_evidence),
                "counter_evidence": sorted(e.value for e in self.counter_evidence),
                "state": self.state.value}
