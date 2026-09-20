"""Repository-level analysis layer for actenon-scan.

This package adds **repository-level** analysis primitives underneath the
existing per-file detector architecture. The existing scan engine
(``actenon_scan.engine``) remains the primary entry point — the modules in
this package provide reusable cross-file intelligence that the engine
opt-in uses to **augment** (never replace) its per-file findings.

Design principles (see COVERAGE.md for the full statement):

1. **FALSE ASSURANCE IS WORSE THAN A REVIEWABLE FALSE POSITIVE.**
   Every analysis state has a literal ``UNKNOWN`` value; nothing labelled
   ``unknown`` is ever silently promoted to ``safe``.

2. **EVIDENCE OVER HEURISTICS.** Call-graph edges carry provenance
   (resolved symbol, imported alias, heuristic name match). Resolved
   edges always dominate heuristic edges.

3. **BACKWARDS COMPATIBILITY.** Nothing in this package changes the
   behaviour of the existing per-file pipeline. It runs *after* the
   per-file scan and only adds new findings/evidence; it never
   suppresses or downgrades an existing finding.

4. **EVERY NEW ANALYSIS CLAIM REQUIRES A TEST.**
   See ``tests/repository/`` and ``tests/adversarial/``.

Public surface (re-exported here for convenience):

- :class:`RepositoryIndex` — file + symbol + import + call-site index.
- :class:`Symbol`, :class:`Import`, :class:`CallSite`, :class:`SourceLocation`
- :class:`CallGraph` — interprocedural call graph with provenance.
- :class:`EffectSummary`, :class:`EffectType` — function effect set.
- :class:`AnalysisCertainty` — explicit certainty levels.
- :class:`TaintFact`, :class:`TaintLattice` — provenance tracking.
"""

from __future__ import annotations

from actenon_scan.repository.symbol_index import (
    RepositoryIndex,
    Symbol,
    SymbolKind,
    Import,
    ImportKind,
    CallSite,
    SourceLocation,
    ResolvedTarget,
    ResolutionCertainty,
)
from actenon_scan.repository.call_graph import (
    CallGraph,
    CallEdge,
    CallPath,
    build_call_graph,
    transitive_reachable,
)
from actenon_scan.repository.effect_summary import (
    EffectType,
    EffectSummary,
    EffectPropagation,
    propagate_effects,
    effect_for_rule_id,
)
from actenon_scan.repository.taint import (
    TaintLattice,
    TaintFact,
    TaintOrigin,
    TaintTrace,
    function_local_dataflow,
)
from actenon_scan.repository.certainty import (
    AnalysisCertainty,
    CERTAINTY_ORDER,
    combine_certainty,
)
from actenon_scan.repository.guard_resolution import (
    GuardStyle,
    GuardBodyInspection,
    GuardResolution,
    resolve_guard_call,
    inspect_guard_body,
)
from actenon_scan.repository.guard_semantics import (
    GuardKind,
    GuardClassification,
    classify_guard_name,
    classify_guard_call,
    action_authorization_strength,
    extract_action_label,
    infer_sink_action_label,
)
from actenon_scan.repository.authority_binding import (
    BindingState,
    BindingResult,
    compare_authority_to_sink,
    compare_all_authority_to_sink_params,
    overall_binding_state,
)
from actenon_scan.repository.cfg import (
    CFGNode,
    CFG,
    build_cfg,
    dominators,
    dominates,
    reverse_postorder,
)
from actenon_scan.repository.ts_symbol_index import (
    TSRepositoryIndex,
    TSSymbol,
    TSSymbolKind,
    TSImport,
    TSCallSite,
    TSResolvedTarget,
)

__all__ = [
    # symbol index
    "RepositoryIndex",
    "Symbol",
    "SymbolKind",
    "Import",
    "ImportKind",
    "CallSite",
    "SourceLocation",
    "ResolvedTarget",
    "ResolutionCertainty",
    # call graph
    "CallGraph",
    "CallEdge",
    "CallPath",
    "build_call_graph",
    "transitive_reachable",
    # effect summaries
    "EffectType",
    "EffectSummary",
    "EffectPropagation",
    "propagate_effects",
    "effect_for_rule_id",
    # taint
    "TaintLattice",
    "TaintFact",
    "TaintOrigin",
    "TaintTrace",
    "function_local_dataflow",
    # certainty
    "AnalysisCertainty",
    "CERTAINTY_ORDER",
    "combine_certainty",
    # guard resolution (Slice 7)
    "GuardStyle",
    "GuardBodyInspection",
    "GuardResolution",
    "resolve_guard_call",
    "inspect_guard_body",
    # guard semantics (Slice 5)
    "GuardKind",
    "GuardClassification",
    "classify_guard_name",
    "classify_guard_call",
    "action_authorization_strength",
    "extract_action_label",
    "infer_sink_action_label",
    # authority binding (Slice 8)
    "BindingState",
    "BindingResult",
    "compare_authority_to_sink",
    "compare_all_authority_to_sink_params",
    "overall_binding_state",
    # CFG (Slice 6)
    "CFGNode",
    "CFG",
    "build_cfg",
    "dominators",
    "dominates",
    "reverse_postorder",
    # TS symbol index (Slice 11 partial)
    "TSRepositoryIndex",
    "TSSymbol",
    "TSSymbolKind",
    "TSImport",
    "TSCallSite",
    "TSResolvedTarget",
]
