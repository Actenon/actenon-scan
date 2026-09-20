"""Function effect summaries and interprocedural propagation.

A function's *effect set* is the set of consequential side-effect
categories its execution can produce — directly (via a sink it calls)
or indirectly (via a function it calls whose effects have already been
summarised).

Effect propagation is *monotonic* and reaches a fixed point: each
function's effect set can only grow as we discover more callees, never
shrink. Recursion and mutual recursion are handled by processing the
call graph's SCCs in dependency order and iterating within each SCC
until the effect sets stop changing.

Each :class:`EffectSummary` carries *provenance*: the concrete sink
that gave rise to each effect. A function that calls
``subprocess.run`` inherits ``SHELL_EXECUTION`` with provenance
pointing back to that call. A function that calls a helper which
calls ``subprocess.run`` inherits the same effect, with provenance
pointing to the helper's summary, which itself points to the concrete
sink.

Conservative by construction
----------------------------

- A function with NO observed sink and NO observed callees has an
  EMPTY effect set, *not* an UNKNOWN one. This is sound: we have
  evidence it does nothing consequential (locally) and we don't model
  dynamic dispatch, so we can't claim otherwise.
- A function whose callee set includes an UNRESOLVED edge has an
  UNKNOWN effect — the unknown is explicit, never silently promoted
  to "safe".
- An effect is only added to a function's summary when we have either
  direct evidence (a sink in its body) or propagated evidence (a
  callee whose summary contains it).

The :class:`EffectType` catalogue is deliberately small. New effect
types should be added when a sink rule warrants one — the catalogue is
intentionally NOT a one-to-one mapping to rule IDs.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from actenon_scan.repository.call_graph import CallGraph, CallEdge
from actenon_scan.repository.symbol_index import (
    RepositoryIndex,
    ResolutionCertainty,
    Symbol,
)


# ---------------------------------------------------------------------------
# Effect types
# ---------------------------------------------------------------------------


class EffectType(str, Enum):
    """Catalogue of consequential side-effect categories.

    The values are stable strings so they serialise to JSON naturally.
    New effect types should be added here when warranted by a sink
    family — do not invent one-off strings elsewhere.
    """

    SHELL_EXECUTION = "shell_execution"
    CODE_EXECUTION = "code_execution"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    DATA_MUTATION = "data_mutation"
    DATA_DELETION = "data_deletion"
    IDENTITY_MUTATION = "identity_mutation"
    ACCESS_CONTROL_MUTATION = "access_control_mutation"
    MONEY_MUTATION = "money_mutation"
    MONEY_REFUND = "money_refund"
    COMMUNICATION_SEND = "communication_send"
    EMAIL_SEND = "email_send"
    REPOSITORY_MUTATION = "repository_mutation"
    DEPLOY_ACTION = "deploy_action"
    CONTAINER_EXECUTION = "container_execution"
    INFRASTRUCTURE_MUTATION = "infrastructure_mutation"
    CREDENTIAL_ACCESS = "credential_access"
    NETWORK_EGRESS = "network_egress"
    BROWSER_ACTION = "browser_action"
    # Sentinel for an effect we know exists but cannot classify.
    UNKNOWN_EFFECT = "unknown_effect"


# Mapping from sink rule ID prefix → EffectType. This is the bridge
# between the rule-based sink detector and the effect model.
# Rule IDs in default_rules.json look like "EXEC-SHELL", "PAY-STRIPE-REFUND",
# "DATA-DELETE-SQL", etc. We map the *category* (rule_id minus suffixes
# like -WEAK/-UNBOUND) to the effect.
_RULE_ID_TO_EFFECT: dict[str, EffectType] = {
    "EXEC-SHELL": EffectType.SHELL_EXECUTION,
    "EXEC-CODE": EffectType.CODE_EXECUTION,
    "EXEC-CONTAINER": EffectType.CONTAINER_EXECUTION,
    "EXEC-SHELL-GO": EffectType.SHELL_EXECUTION,
    "FILE-WRITE": EffectType.FILE_WRITE,
    "FILE-OPEN-WRITE": EffectType.FILE_WRITE,
    "DATA-DELETE-FILE": EffectType.FILE_DELETE,
    "DATA-DELETE-OS": EffectType.FILE_DELETE,
    "DATA-DELETE-OBJ": EffectType.DATA_DELETION,
    "DATA-DELETE-SQL": EffectType.DATA_DELETION,
    "DATA-DELETE-SQL-RAW": EffectType.DATA_DELETION,
    "DATABASE-MUTATE": EffectType.DATA_MUTATION,
    "DATABASE-ORM-MUTATE": EffectType.DATA_MUTATION,
    "IDENTITY-CHANGE": EffectType.IDENTITY_MUTATION,
    "IDENTITY-IAM-MUTATE": EffectType.ACCESS_CONTROL_MUTATION,
    "ACCESS-CONTROL-MUTATE": EffectType.ACCESS_CONTROL_MUTATION,
    "PAY-STRIPE-REFUND": EffectType.MONEY_REFUND,
    "PAY-BRAINTREE": EffectType.MONEY_MUTATION,
    "PAY-GENERIC-REFUND": EffectType.MONEY_REFUND,
    "COMMUNICATION-SEND": EffectType.COMMUNICATION_SEND,
    "COMMUNICATION-SEND-NAME": EffectType.COMMUNICATION_SEND,
    "EMAIL-PROVIDER-SEND": EffectType.EMAIL_SEND,
    "REPOSITORY-MUTATION": EffectType.REPOSITORY_MUTATION,
    "GITHUB-REST-MUTATION": EffectType.REPOSITORY_MUTATION,
    "DEPLOY-SUBPROCESS": EffectType.DEPLOY_ACTION,
    "DEPLOY-K8S": EffectType.INFRASTRUCTURE_MUTATION,
    "DEPLOY-TERRAFORM": EffectType.INFRASTRUCTURE_MUTATION,
    "GIT-MUTATE": EffectType.REPOSITORY_MUTATION,
    "BROWSER-ACTION": EffectType.BROWSER_ACTION,
    "SECRET-READ": EffectType.CREDENTIAL_ACCESS,
    "NET-EGRESS": EffectType.NETWORK_EGRESS,
    "PROVIDER-SDK-CALL": EffectType.UNKNOWN_EFFECT,
}


def effect_for_rule_id(rule_id: str) -> EffectType | None:
    """Map a sink rule ID to its effect type.

    Strips ``-WEAK`` / ``-UNBOUND`` suffixes. Returns ``None`` for
    unknown rule IDs (effect unknown — explicitly NOT promoted to
    "no effect").
    """
    base = rule_id
    for suffix in ("-WEAK", "-UNBOUND"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return _RULE_ID_TO_EFFECT.get(base)


# ---------------------------------------------------------------------------
# Effect summaries
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EffectProvenance:
    """Where an effect on a function's summary came from.

    Either ``concrete_sink`` (a direct sink in this function's body) or
    ``propagated_from`` (the qualified name of a callee whose summary
    contains this effect). Both can be present: a single effect might
    be both directly caused and propagated (in which case the summary
    preserves both pieces of evidence).
    """

    concrete_sink: tuple[str, int] | None = None  # (file, line)
    propagated_from: str | None = None  # callee qualified name
    # The rule_id of the underlying sink (for diagnostics). For propagated
    # effects, this is the rule_id of the *original* concrete sink.
    rule_id: str = ""


@dataclass
class EffectSummary:
    """The effect set of a single function.

    ``effects`` maps EffectType → list of provenance entries (one per
    distinct source of the same effect; de-duplicated by ``concrete_sink``
    location only).
    """

    qualified_name: str
    effects: dict[EffectType, list[EffectProvenance]] = field(default_factory=dict)
    # Whether this summary includes any UNRESOLVED callee. If True, the
    # effect set is *incomplete* and downstream analysis must treat it
    # as a lower bound, not a complete description.
    has_unresolved_callee: bool = False

    def add(
        self,
        effect: EffectType,
        *,
        concrete_sink: tuple[str, int] | None = None,
        propagated_from: str | None = None,
        rule_id: str = "",
    ) -> None:
        prov = EffectProvenance(
            concrete_sink=concrete_sink,
            propagated_from=propagated_from,
            rule_id=rule_id,
        )
        # De-duplicate on (concrete_sink, propagated_from, rule_id)
        existing = self.effects.setdefault(effect, [])
        for e in existing:
            if e == prov:
                return
        existing.append(prov)

    def add_from(self, other: "EffectSummary", callee_qname: str) -> None:
        """Inherit effects from a callee's summary.

        Provenance is rewritten so each inherited effect points back to
        the callee (which itself contains the original sink provenance).
        """
        if other.has_unresolved_callee:
            self.has_unresolved_callee = True
        for effect, provs in other.effects.items():
            for prov in provs:
                self.add(
                    effect,
                    concrete_sink=prov.concrete_sink,
                    propagated_from=callee_qname,
                    rule_id=prov.rule_id,
                )

    @property
    def effect_types(self) -> set[EffectType]:
        return set(self.effects.keys())

    def is_empty(self) -> bool:
        return not self.effects and not self.has_unresolved_callee

    def describes(self) -> str:
        """Human-readable one-liner: ``fn: SHELL_EXECUTION, MONEY_MUTATION``."""
        if not self.effects:
            if self.has_unresolved_callee:
                return f"{self.qualified_name}: UNKNOWN (unresolved callee)"
            return f"{self.qualified_name}: no effects"
        parts = ", ".join(sorted(e.value for e in self.effects))
        if self.has_unresolved_callee:
            parts += " + UNKNOWN"
        return f"{self.qualified_name}: {parts}"


# ---------------------------------------------------------------------------
# Propagation
# ---------------------------------------------------------------------------


@dataclass
class EffectPropagation:
    """Result of effect propagation across the whole call graph.

    ``summaries`` maps qualified_name → EffectSummary. ``iterations``
    is the number of fixed-point passes performed (for diagnostics
    and for tests asserting convergence on recursive graphs).
    """

    summaries: dict[str, EffectSummary] = field(default_factory=dict)
    iterations: int = 0
    # The qualified names of functions whose summary includes an
    # UNRESOLVED callee. Downstream authority analysis must treat these
    # as incomplete.
    incomplete: list[str] = field(default_factory=list)


def propagate_effects(
    graph: CallGraph,
    *,
    direct_sinks: dict[str, list[tuple[EffectType, tuple[str, int], str]]] | None = None,
    max_iterations: int = 16,
) -> EffectPropagation:
    """Compute effect summaries for every function in the call graph.

    ``direct_sinks`` is an optional map from caller qualified name →
    list of ``(effect, (file, line), rule_id)`` tuples for sinks directly
    in that function's body. When provided, these seed the summaries
    before propagation begins. When omitted, summaries start empty and
    only propagation adds effects.

    The algorithm:

    1. Seed each function's summary with its direct sinks.
    2. Process SCCs in reverse topological order (callees before callers).
    3. Within an SCC, iterate to fixed point: for each function, inherit
       effects from each callee.
    4. Repeat until no summary changes.

    Conservative properties:

    - UNRESOLVED callees are recorded on the caller's summary
      (``has_unresolved_callee=True``) — never silently dropped.
    - An effect never disappears from a summary once added (monotonic).
    - Iterations are bounded by ``max_iterations``; if the fixed point
      isn't reached, the propagation is still returned (with the
      summaries at the last iteration) and ``iterations`` will equal
      ``max_iterations``. Downstream analysis can detect this case.
    """
    direct_sinks = direct_sinks or {}
    prop = EffectPropagation()

    # Seed summaries.
    for qname in graph.nodes:
        s = EffectSummary(qualified_name=qname)
        for effect, loc, rule_id in direct_sinks.get(qname, []):
            s.add(effect, concrete_sink=loc, rule_id=rule_id)
        prop.summaries[qname] = s

    # Also seed summaries for callers that have edges but no Symbol entry
    # (they're still in edges_by_caller keys).
    for caller in graph.edges_by_caller:
        if caller not in prop.summaries:
            prop.summaries[caller] = EffectSummary(qualified_name=caller)
    for callee in graph.edges_by_callee:
        if callee not in prop.summaries:
            prop.summaries[callee] = EffectSummary(qualified_name=callee)

    # Compute SCCs and a topological order (callees-first).
    sccs = graph.sccs()
    # Map node → SCC index
    node_to_scc: dict[str, int] = {}
    for i, scc in enumerate(sccs):
        for n in scc:
            node_to_scc[n] = i
    # Build inter-SCC DAG: scc_a → scc_b if any edge from a node in a
    # goes to a node in b and a != b.
    scc_succ: dict[int, set[int]] = defaultdict(set)
    for caller, edges in graph.edges_by_caller.items():
        a = node_to_scc.get(caller)
        if a is None:
            continue
        for e in edges:
            b = node_to_scc.get(e.callee)
            if b is None or b == a:
                continue
            scc_succ[a].add(b)
    # Reverse topological order: process leaves first (callees before callers).
    # Use DFS-based postorder.
    visited_sccs: set[int] = set()
    order: list[int] = []
    # Use iterative DFS postorder.
    for start in range(len(sccs)):
        if start in visited_sccs:
            continue
        stack: list[tuple[int, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                if node not in visited_sccs:
                    visited_sccs.add(node)
                    order.append(node)
                continue
            if node in visited_sccs:
                continue
            stack.append((node, True))
            for succ in scc_succ.get(node, set()):
                if succ not in visited_sccs:
                    stack.append((succ, False))
    # `order` is postorder: children before parents → callees before callers.
    # That's exactly the order we want.

    # Fixed-point iteration.
    for iteration in range(max_iterations):
        changed = False
        for scc_idx in order:
            # Within an SCC, iterate to local fixed point (bounded).
            # A small bound is fine because SCCs are typically small.
            for _ in range(len(sccs[scc_idx]) + 1):
                local_changed = False
                for qname in sccs[scc_idx]:
                    summary = prop.summaries[qname]
                    before = (frozenset(summary.effects.keys()), summary.has_unresolved_callee)
                    for edge in graph.edges_by_caller.get(qname, []):
                        if edge.is_unresolved():
                            summary.has_unresolved_callee = True
                            continue
                        callee_summary = prop.summaries.get(edge.callee)
                        if callee_summary is None:
                            # The callee isn't in our summaries yet (e.g.
                            # it's a sink rule_id text, not a function).
                            # Treat as unresolved so we don't silently lose it.
                            summary.has_unresolved_callee = True
                            continue
                        # Inherit the callee's effects, provenance points
                        # back to the callee (which itself contains the
                        # original sink provenance).
                        before_keys = set(summary.effects.keys())
                        summary.add_from(callee_summary, edge.callee)
                        if set(summary.effects.keys()) != before_keys:
                            local_changed = True
                    after = (frozenset(summary.effects.keys()), summary.has_unresolved_callee)
                    if after != before:
                        local_changed = True
                if not local_changed:
                    break
                changed = True
        prop.iterations = iteration + 1
        if not changed:
            break

    # Populate the `incomplete` list (functions with UNRESOLVED callees).
    for qname, summary in prop.summaries.items():
        if summary.has_unresolved_callee:
            prop.incomplete.append(qname)
    prop.incomplete.sort()

    return prop
