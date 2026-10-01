"""M1: instantiate frozen M0 obligations from a sink-independent graph.

No semantic evidence acquisition or inertness proof is attempted in M1.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Mapping

from actenon_scan.effects import (
    Acquisition, Authority, Budgets, CandidateKind, CapabilityCounts, Control,
    CoverageLedger, Descriptors, EffectClaim, EffectClass, Genesis,
    ImplementationCandidate, InertnessBlocker, Invocation, InvocationCounts,
    LadderTier, Language, Obligation, ObligationStates, ProofState, SelectionState,
    SourceLocator, StopReason, Target, TargetScope, Verdict,
)
from actenon_scan.invocation_graph import Entrypoint, GraphLimits, InvocationGraph, stable_id
from actenon_scan.repository.invocation_adapters import build_invocation_graph
from actenon_scan.rules.loader import load_rules


@dataclass
class ClaimGenesisResult:
    graph: InvocationGraph
    claims: tuple[EffectClaim, ...]
    ledger: CoverageLedger

    @property
    def analysis_errors(self):
        return self.graph.analysis_errors

    @property
    def unsupported_files(self):
        return self.graph.unsupported_files

    @property
    def coverage_gaps(self):
        return self.graph.coverage_gaps

    @property
    def coverage(self):
        return {**self.graph.coverage,
                "claims_instantiated": self.ledger.claims.instantiated,
                "claims_without_rule_match": self.ledger.claims.instantiated_without_any_rule_match}

    def to_dict(self):
        return {"milestone": "M1_UNIVERSAL_CLAIM_GENESIS", "graph": self.graph.to_dict(),
                "claims": [c.to_dict() for c in self.claims],
                "coverage_ledger": self.ledger.to_dict(), "coverage": self.coverage,
                "analysis_errors": [list(e) for e in self.analysis_errors],
                "unsupported_files": [list(e) for e in self.unsupported_files],
                "coverage_gaps": [list(e) for e in self.coverage_gaps]}


def scan_effect_claims(
    target: str | Path, *, entrypoints: Iterable[Entrypoint] = (),
    discover_roots: bool = True, config: str | Path | None = None,
    include_globs: list[str] | None = None, exclude_globs: list[str] | None = None,
    limits: GraphLimits | None = None,
    matched_rule_ids: Mapping[tuple[str, int, int], Iterable[str]] | None = None,
) -> ClaimGenesisResult:
    """Enumerate root-reached calls and create EPSE claims without sink gating.

    Explicit paths are workspace-relative; symbols may be qualified or unique
    file-local names. Columns are one-based UTF-8 byte offsets. ``matched_rule_ids``
    is optional caller-supplied provenance keyed by (file, line, column); neither
    it nor the configured sink catalogue changes genesis or proof states.
    """
    limits = limits or GraphLimits()
    roots = tuple(entrypoints)
    if any(not isinstance(ep, Entrypoint) for ep in roots):
        raise TypeError("entrypoints must contain Entrypoint values")
    graph = build_invocation_graph(Path(target), entrypoints=roots, discover_roots=discover_roots,
                                   reachability_cfg=load_rules(config).reachability, limits=limits,
                                   include_globs=include_globs, exclude_globs=exclude_globs,
                                   matched_rule_ids=matched_rule_ids)
    claims = []
    for invocation_id, call in sorted(graph.invocations.items()):
        unknown = ProofState.UNKNOWN
        error = bool(call.resolution_error)
        states = ObligationStates(ProofState.ERROR if error else unknown,
                                  unknown, unknown, unknown, unknown)
        candidates = []
        for target in call.possible_implementations:
            kind = CandidateKind.RESOLVED_LOCAL if target.file else (
                CandidateKind.DYNAMIC_UNRESOLVED if target.dynamic else CandidateKind.OPAQUE_EXTERNAL)
            locator = SourceLocator(target.file, target.line, target.line,
                                    start_column=target.column) if target.file else None
            candidates.append(ImplementationCandidate(target.candidate_id, kind, states,
                                                       target.symbol, locator))
        blockers = [InertnessBlocker.NO_PROBATIVE_REFUTATION]
        if any(c.kind == CandidateKind.OPAQUE_EXTERNAL for c in candidates):
            blockers.append(InertnessBlocker.OPAQUE_EXTERNAL_CANDIDATE)
        if any(c.kind == CandidateKind.DYNAMIC_UNRESOLVED for c in candidates):
            blockers.append(InertnessBlocker.DYNAMIC_UNRESOLVED_CANDIDATE)
        if error:
            blockers.append(InertnessBlocker.ACQUISITION_ERROR)
        acquisition = Acquisition(
            highest_tier_reached=LadderTier.L0,
            stop_reason=StopReason.ACQUISITION_ERROR if error else StopReason.CLAIM_NOT_INVESTIGATED,
            tiers_attempted=(LadderTier.L0,) if error else (),
            unresolved_obligations=tuple(o for o, s in states.items() if s == unknown),
            frontier_size=0, frontier=(), frontier_truncated=False,
        )
        for root_id in call.root_ids:
            claims.append(EffectClaim(
                claim_id=stable_id("claim", root_id, invocation_id, EffectClass.EXTERNAL_PERSISTENT_STATE_EFFECT.value),
                capability_id=root_id, invocation_id=invocation_id,
                effect_class=EffectClass.EXTERNAL_PERSISTENT_STATE_EFFECT,
                invocation=Invocation(SourceLocator(call.file, call.line, call.line, start_column=call.column),
                                      call.callee_spelling, Language(call.language), call.matched_rule_ids),
                genesis=Genesis(tuple(blockers)), implementation_candidates=candidates,
                selection_state=SelectionState.SELECTION_ERROR if error else SelectionState.UNRESOLVED_IDENTITY,
                obligations=states,
                descriptors=Descriptors(Target((), TargetScope.UNKNOWN), Control(unknown, unknown, unknown),
                                        Authority(unknown)),
                acquisition=acquisition,
                verdict=Verdict.ANALYSIS_ERROR if error else Verdict.ABSTAIN,
                verdict_rationale=call.resolution_error or "M1 creates the obligation; effect evidence has not been acquired.",
            ))
    claims = tuple(claims)
    ledger = CoverageLedger.from_claims(
        claims, capabilities_discovered=len(graph.roots),
        invocations_enumerated=graph.coverage["root_invocation_occurrences"],
        budgets=Budgets(max_files_opened=limits.max_files, max_bytes_read=limits.max_bytes,
                        max_implementation_candidates=max((len(c.implementation_candidates) for c in claims), default=1)),
    )
    # Preserve the frozen ledger's root-scoped arithmetic and enrich its
    # existing optional accounting fields rather than adding verdict counters.
    matched = sum(len(c.root_paths) for c in graph.invocations.values() if c.matched_rule_ids)
    ledger = replace(ledger,
                     capabilities=CapabilityCounts(len(graph.roots), Counter(Language(r.language) for r in graph.roots)),
                     invocations=InvocationCounts(ledger.invocations.enumerated, matched,
                                                  ledger.invocations.enumerated - matched,
                                                  Counter(c.invocation.language for c in claims)),
                     claims=replace(ledger.claims, by_language=Counter(c.invocation.language for c in claims)))
    return ClaimGenesisResult(graph, claims, ledger)
