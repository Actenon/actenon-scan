"""Closed AREF-002 vocabularies and the frozen tables that constrain them.

Every enum here is closed: its members are exactly the frozen members of
``specs/AREF-002/architecture_manifest.json`` and the schemas beside it. The
enums are deliberately **not orderable**. Proof states and verdicts are not a
lattice, so ``max``, ``sorted`` or a comparison cannot be used to "join" them;
that is how ``UNKNOWN`` would silently become ``REFUTED`` or ``CONFLICTING``
would silently become ``UNKNOWN``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType


class _ClosedVocabulary(str, Enum):
    def __str__(self) -> str:
        return self.value

    def _no_order(self, other):
        raise TypeError(f"{type(self).__name__} is a closed vocabulary with no ordering")

    __lt__ = __le__ = __gt__ = __ge__ = _no_order


class ProofState(_ClosedVocabulary):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    CONFLICTING = "CONFLICTING"
    ERROR = "ERROR"


class Verdict(_ClosedVocabulary):
    PROVEN_EFFECT = "PROVEN_EFFECT"
    NO_EFFECT = "NO_EFFECT"
    ABSTAIN = "ABSTAIN"
    ANALYSIS_ERROR = "ANALYSIS_ERROR"


class Obligation(_ClosedVocabulary):
    IMPLEMENTATION = "IMPLEMENTATION"
    ACTIVATION = "ACTIVATION"
    BOUNDARY = "BOUNDARY"
    OPERATION = "OPERATION"
    PERSISTENCE = "PERSISTENCE"


class EffectClass(_ClosedVocabulary):
    EXTERNAL_PERSISTENT_STATE_EFFECT = "EXTERNAL_PERSISTENT_STATE_EFFECT"


class CandidateKind(_ClosedVocabulary):
    RESOLVED_LOCAL = "RESOLVED_LOCAL"
    RESOLVED_DEPENDENCY_SOURCE = "RESOLVED_DEPENDENCY_SOURCE"
    CONTRACT_DECLARED = "CONTRACT_DECLARED"
    OPAQUE_EXTERNAL = "OPAQUE_EXTERNAL"
    DYNAMIC_UNRESOLVED = "DYNAMIC_UNRESOLVED"
    TEST_DOUBLE = "TEST_DOUBLE"


class SelectionState(_ClosedVocabulary):
    SINGLE_ESTABLISHED = "SINGLE_ESTABLISHED"
    AGREEMENT_INVARIANT = "AGREEMENT_INVARIANT"
    UNRESOLVED_DIVERGENT = "UNRESOLVED_DIVERGENT"
    SELECTION_ERROR = "SELECTION_ERROR"
    UNRESOLVED_IDENTITY = "UNRESOLVED_IDENTITY"


class Admissibility(_ClosedVocabulary):
    PROBATIVE = "PROBATIVE"
    HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"


class Polarity(_ClosedVocabulary):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"


class Strength(_ClosedVocabulary):
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"


class LadderTier(_ClosedVocabulary):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"
    L5 = "L5"
    L6 = "L6"
    L7 = "L7"
    L8 = "L8"

    @classmethod
    def evidence_tiers(cls) -> tuple["LadderTier", ...]:
        """L0 to L7. L8 is the terminal ABSTAIN state, not an evidence source."""
        return tuple(t for t in cls if t is not cls.L8)

    @property
    def position(self) -> int:
        """Ladder position. Used for reach accounting only, never to resolve evidence."""
        return int(self.value[1:])


class StopReason(_ClosedVocabulary):
    SETTLED = "SETTLED"
    NO_FURTHER_TIER = "NO_FURTHER_TIER"
    TIER_UNAVAILABLE = "TIER_UNAVAILABLE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    ACQUISITION_ERROR = "ACQUISITION_ERROR"
    CLAIM_NOT_INVESTIGATED = "CLAIM_NOT_INVESTIGATED"
    CYCLE = "CYCLE"
    MAX_TIER_REACHED = "MAX_TIER_REACHED"
    CANDIDATE_LIMIT = "CANDIDATE_LIMIT"


class BudgetName(_ClosedVocabulary):
    MAX_LADDER_TIER = "max_ladder_tier"
    MAX_DEPENDENCY_HOPS = "max_dependency_hops"
    MAX_FILES_OPENED = "max_files_opened"
    MAX_BYTES_READ = "max_bytes_read"
    MAX_WALL_MS_PER_CLAIM = "max_wall_ms_per_claim"
    MAX_CLAIMS_INVESTIGATED = "max_claims_investigated"
    MAX_IMPLEMENTATION_CANDIDATES = "max_implementation_candidates"


class PacketKind(_ClosedVocabulary):
    LOCAL_CALL_SITE = "local_call_site"
    LOCAL_BINDING = "local_binding"
    LOCAL_CONTROL_FLOW = "local_control_flow"
    LOCAL_FUNCTION_BODY = "local_function_body"
    WRAPPER_CHAIN_BODY = "wrapper_chain_body"
    TYPE_DECLARATION = "type_declaration"
    INTERFACE_DECLARATION = "interface_declaration"
    PACKAGE_PROVENANCE = "package_provenance"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    DEPENDENCY_LOCKFILE = "dependency_lockfile"
    DEPENDENCY_SOURCE_BODY = "dependency_source_body"
    OPENAPI_OPERATION = "openapi_operation"
    PROTOBUF_SERVICE_METHOD = "protobuf_service_method"
    GRAPHQL_SCHEMA_FIELD = "graphql_schema_field"
    JSON_SCHEMA_NODE = "json_schema_node"
    SDK_OPERATION_METADATA = "sdk_operation_metadata"
    COMMAND_SPECIFICATION = "command_specification"
    SQL_STATEMENT = "sql_statement"
    DOCUMENT_STORE_OPERATION = "document_store_operation"
    SHELL_COMMAND = "shell_command"
    TRANSPORT_PRIMITIVE = "transport_primitive"
    DRIVER_PRIMITIVE = "driver_primitive"
    SINK_RULE_MATCH = "sink_rule_match"
    UNQUALIFIED_NAME_RULE_MATCH = "unqualified_name_rule_match"
    IDENTIFIER_NAME = "identifier_name"
    PROSE_DOCUMENTATION = "prose_documentation"
    SOURCE_TEXT_REGEX = "source_text_regex"
    HTTP_METHOD = "http_method"
    COUNTER_EVIDENCE_PROBE = "counter_evidence_probe"


class AssertionPredicate(_ClosedVocabulary):
    IMPLEMENTATION_IS = "implementation_is"
    INVOCATION_EXECUTES = "invocation_executes"
    INVOCATION_DOES_NOT_EXECUTE = "invocation_does_not_execute"
    EGRESS_MECHANISM_IS = "egress_mechanism_is"
    TERMINATES_IN_PROCESS_STATE = "terminates_in_process_state"
    OPERATION_IS_MUTATION = "operation_is_mutation"
    OPERATION_IS_OBSERVATION = "operation_is_observation"
    STATE_IS_DURABLY_COMMITTED = "state_is_durably_committed"
    STATE_IS_GUARANTEED_ROLLED_BACK = "state_is_guaranteed_rolled_back"
    STATE_IS_EPHEMERAL = "state_is_ephemeral"
    COMMIT_OUTCOME_UNDETERMINED = "commit_outcome_undetermined"
    OPERATION_IS_NO_OP = "operation_is_no_op"
    DRY_RUN_IN_FORCE = "dry_run_in_force"
    TEST_DOUBLE_IN_FORCE = "test_double_in_force"


class RuleMatchType(_ClosedVocabulary):
    ATTR_CALL = "attr_call"
    QUALIFIED_CALL = "qualified_call"
    NAME_CALL = "name_call"
    OPEN_WRITE = "open_write"
    SQL_EXECUTE_PATTERN = "sql_execute_pattern"
    STRING_PATTERN = "string_pattern"
    SUBPROCESS_DEPLOY = "subprocess_deploy"
    GITHUB_REST_MUTATION = "github_rest_mutation"


class VersionResolution(_ClosedVocabulary):
    LOCKFILE = "LOCKFILE"
    EXACT_MANIFEST_PIN = "EXACT_MANIFEST_PIN"
    INSTALLED_TREE_METADATA = "INSTALLED_TREE_METADATA"
    UNPINNED = "UNPINNED"


class ProbeClass(_ClosedVocabulary):
    BLOCKING = "BLOCKING"
    ADVISORY = "ADVISORY"


class ProbeResult(_ClosedVocabulary):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    INCOMPLETE = "INCOMPLETE"


class ContradictionResolution(_ClosedVocabulary):
    UNRESOLVED = "UNRESOLVED"
    RESOLVED_IMPLEMENTATION_PRECEDENCE = "RESOLVED_IMPLEMENTATION_PRECEDENCE"


class InertnessBlocker(_ClosedVocabulary):
    OPAQUE_EXTERNAL_CANDIDATE = "OPAQUE_EXTERNAL_CANDIDATE"
    DYNAMIC_UNRESOLVED_CANDIDATE = "DYNAMIC_UNRESOLVED_CANDIDATE"
    UNRESOLVED_CALLEE = "UNRESOLVED_CALLEE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    NON_EMPTY_FRONTIER = "NON_EMPTY_FRONTIER"
    NO_PROBATIVE_REFUTATION = "NO_PROBATIVE_REFUTATION"
    CONFLICTING_OBLIGATION = "CONFLICTING_OBLIGATION"
    ACQUISITION_ERROR = "ACQUISITION_ERROR"


class Language(_ClosedVocabulary):
    PYTHON = "python"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"
    GO = "go"
    OTHER = "other"


class TargetScope(_ClosedVocabulary):
    SINGLE = "single"
    SET = "set"
    ALL = "all"
    UNKNOWN = "unknown"


class ConditionKind(_ClosedVocabulary):
    GUARD = "guard"
    FEATURE_FLAG = "feature_flag"
    ENVIRONMENT_PREDICATE = "environment_predicate"
    BRANCH_CONDITION = "branch_condition"
    EXCEPTION_HANDLER = "exception_handler"


SCHEMA_VERSION = "0.1.1"
GENESIS_BASIS = "NON_REFUTATION_OF_INERTNESS"

NECESSARY_OBLIGATIONS: "MappingProxyType[EffectClass, tuple[Obligation, ...]]" = MappingProxyType({
    EffectClass.EXTERNAL_PERSISTENT_STATE_EFFECT: tuple(Obligation),
})

EVIDENCE_OBLIGATIONS: tuple[Obligation, ...] = tuple(
    o for o in Obligation if o is not Obligation.IMPLEMENTATION
)
"""The four non-implementation receipt answers; IMPLEMENTATION uses binding evidence."""

ESTABLISHED_SELECTIONS = frozenset({
    SelectionState.SINGLE_ESTABLISHED,
    SelectionState.AGREEMENT_INVARIANT,
})

OPAQUE_CANDIDATE_KINDS = frozenset({CandidateKind.OPAQUE_EXTERNAL, CandidateKind.DYNAMIC_UNRESOLVED})

HYPOTHESIS_ONLY_KINDS = frozenset({
    PacketKind.IDENTIFIER_NAME,
    PacketKind.PROSE_DOCUMENTATION,
    PacketKind.SOURCE_TEXT_REGEX,
    PacketKind.HTTP_METHOD,
    PacketKind.UNQUALIFIED_NAME_RULE_MATCH,
})

RULE_PACKET_KINDS = frozenset({PacketKind.SINK_RULE_MATCH, PacketKind.UNQUALIFIED_NAME_RULE_MATCH})

TIERS_REQUIRING_PACKAGE = frozenset({LadderTier.L4, LadderTier.L5, LadderTier.L6})

TIER_CAN_SETTLE: "MappingProxyType[LadderTier, frozenset[Obligation]]" = MappingProxyType({
    LadderTier.L0: frozenset({Obligation.IMPLEMENTATION, Obligation.ACTIVATION, Obligation.BOUNDARY}),
    LadderTier.L1: frozenset(Obligation),
    LadderTier.L2: frozenset({Obligation.IMPLEMENTATION, Obligation.BOUNDARY}),
    LadderTier.L3: frozenset({Obligation.IMPLEMENTATION}),
    LadderTier.L4: frozenset({Obligation.IMPLEMENTATION}),
    LadderTier.L5: frozenset({Obligation.IMPLEMENTATION, Obligation.BOUNDARY,
                              Obligation.OPERATION, Obligation.PERSISTENCE}),
    LadderTier.L6: frozenset({Obligation.BOUNDARY, Obligation.OPERATION, Obligation.PERSISTENCE}),
    LadderTier.L7: frozenset({Obligation.BOUNDARY, Obligation.OPERATION, Obligation.PERSISTENCE}),
    LadderTier.L8: frozenset(),
})


@dataclass(frozen=True)
class RuleAdmissibility:
    admissibility: Admissibility
    may_settle: frozenset


RULE_MATCH_ADMISSIBILITY: "MappingProxyType[RuleMatchType, RuleAdmissibility]" = MappingProxyType({
    RuleMatchType.QUALIFIED_CALL: RuleAdmissibility(
        Admissibility.PROBATIVE, frozenset({Obligation.BOUNDARY, Obligation.OPERATION})),
    RuleMatchType.ATTR_CALL: RuleAdmissibility(
        Admissibility.PROBATIVE, frozenset({Obligation.BOUNDARY, Obligation.OPERATION})),
    RuleMatchType.OPEN_WRITE: RuleAdmissibility(
        Admissibility.PROBATIVE, frozenset({Obligation.BOUNDARY})),
    RuleMatchType.SUBPROCESS_DEPLOY: RuleAdmissibility(
        Admissibility.PROBATIVE, frozenset({Obligation.BOUNDARY})),
    RuleMatchType.GITHUB_REST_MUTATION: RuleAdmissibility(
        Admissibility.PROBATIVE, frozenset({Obligation.BOUNDARY, Obligation.OPERATION})),
    RuleMatchType.NAME_CALL: RuleAdmissibility(Admissibility.HYPOTHESIS_ONLY, frozenset()),
    RuleMatchType.SQL_EXECUTE_PATTERN: RuleAdmissibility(Admissibility.HYPOTHESIS_ONLY, frozenset()),
    RuleMatchType.STRING_PATTERN: RuleAdmissibility(Admissibility.HYPOTHESIS_ONLY, frozenset()),
})

DIRECTIONAL_PREDICATES: "MappingProxyType[AssertionPredicate, tuple[Obligation, Polarity]]" = MappingProxyType({
    AssertionPredicate.INVOCATION_EXECUTES: (Obligation.ACTIVATION, Polarity.POSITIVE),
    AssertionPredicate.INVOCATION_DOES_NOT_EXECUTE: (Obligation.ACTIVATION, Polarity.NEGATIVE),
    AssertionPredicate.EGRESS_MECHANISM_IS: (Obligation.BOUNDARY, Polarity.POSITIVE),
    AssertionPredicate.TERMINATES_IN_PROCESS_STATE: (Obligation.BOUNDARY, Polarity.NEGATIVE),
    AssertionPredicate.OPERATION_IS_MUTATION: (Obligation.OPERATION, Polarity.POSITIVE),
    AssertionPredicate.OPERATION_IS_OBSERVATION: (Obligation.OPERATION, Polarity.NEGATIVE),
    AssertionPredicate.STATE_IS_DURABLY_COMMITTED: (Obligation.PERSISTENCE, Polarity.POSITIVE),
    AssertionPredicate.STATE_IS_GUARANTEED_ROLLED_BACK: (Obligation.PERSISTENCE, Polarity.NEGATIVE),
})

PREDICATE_OBLIGATION: "MappingProxyType[AssertionPredicate, Obligation]" = MappingProxyType({
    AssertionPredicate.IMPLEMENTATION_IS: Obligation.IMPLEMENTATION,
    AssertionPredicate.COMMIT_OUTCOME_UNDETERMINED: Obligation.PERSISTENCE,
})
"""Non-directional predicates whose obligation is nevertheless fixed."""

UNCERTAINTY_PREDICATES = frozenset({AssertionPredicate.COMMIT_OUTCOME_UNDETERMINED})
"""Predicates that preserve uncertainty: they never settle a state (REI-002; AREF-002-T09)."""

FRONTIER_REASONS = frozenset({
    StopReason.BUDGET_EXHAUSTED,
    StopReason.TIER_UNAVAILABLE,
    StopReason.MAX_TIER_REACHED,
    StopReason.CANDIDATE_LIMIT,
    StopReason.ACQUISITION_ERROR,
})

CONTRACT_TIERS = frozenset({LadderTier.L2, LadderTier.L6})
RESOLVED_SOURCE_TIERS = frozenset({LadderTier.L1, LadderTier.L5})
RESOLVED_CANDIDATE_KINDS = frozenset({CandidateKind.RESOLVED_LOCAL, CandidateKind.RESOLVED_DEPENDENCY_SOURCE})

UNDETERMINED_COMMIT_PROBE = "CP-PER-05"


@dataclass(frozen=True)
class ProbeSpec:
    obligation: Obligation
    probe_class: ProbeClass


def _probes(obligation: Obligation, prefix: str, blocking: tuple[int, ...], advisory: tuple[int, ...]):
    out = {}
    for n in sorted(blocking + advisory):
        cls = ProbeClass.BLOCKING if n in blocking else ProbeClass.ADVISORY
        out[f"CP-{prefix}-{n:02d}"] = ProbeSpec(obligation, cls)
    return out


PROBE_REGISTRY: "MappingProxyType[str, ProbeSpec]" = MappingProxyType({
    **_probes(Obligation.IMPLEMENTATION, "IMPL", (1, 2, 4), (3,)),
    **_probes(Obligation.ACTIVATION, "ACT", (1, 2), (3, 4)),
    **_probes(Obligation.BOUNDARY, "BND", (1, 2, 3), (4,)),
    **_probes(Obligation.OPERATION, "OPR", (1, 2, 3), (4,)),
    **_probes(Obligation.PERSISTENCE, "PER", (1, 2, 3, 4, 5), (6,)),
})

BLOCKING_PROBE_IDS: tuple[str, ...] = tuple(
    pid for pid, spec in PROBE_REGISTRY.items() if spec.probe_class is ProbeClass.BLOCKING
)

RECEIPT_ANSWER_KEYS: tuple[str, ...] = (
    "effect", "implementation", "resource", "activation", "boundary", "operation",
    "persistence", "control", "authority", "contradictions", "unknowns",
)
