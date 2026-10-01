# M1R2A: imported-member stability reconciliation

Base: `d8fa32193c324b7feee02832156eb8e6718c6f9a`.

Only sibling regression source was recovered. The 18 recovered diagnostics
produce 13 failures and 5 passes on the exact base, but those 13 TypeScript
failures assign immutable ES module namespace exports. They are not valid
replacement cases and are not used as merge blockers. Valid translations use
mutable exports changed in their declaring module, mutable exported objects,
local aliases/shadows and conditional replacements.

The independent valid matrix reproduces 20 failures out of 72 probes: five
Python package-prefix mutation variants under all four root kinds. Calls remain
present; their BindingClaims have IMPORT_PROVENANCE + LEXICAL_DECLARATION, no
counter-evidence, and ESTABLISHED state to pkg.dep.helper. Its unrelated body
is followed. The candidate is still clean when this result is recorded.

The repair follows each imported namespace member through lexical provenance
before selecting the final callable. Every traversed prefix contributes its
positive and counter-evidence to the final BindingClaim. Explicit qualified
imports supply evidence of implicit submodule bindings; mere files existing
under a package do not. Direct imported module aliases retain their distinct
object identity rather than being confused with later package-attribute writes.

Mutated prefixes retain legitimate old implementation candidates as POSSIBLE,
with REASSIGNMENT_WRITE counter-evidence. Only ESTABLISHED callable claims may
enqueue bodies. This remains a bounded workspace-only lexical operation, with
no dependency-source, effect, provider or M2 acquisition. Existing language
index utilities and the frozen M0 proof kernel remain unchanged.

Validation: 177 new permanent regressions pass, including import-stability
metamorphisms, positive imports, ambiguous alternatives under reversed file
order, computed/deleted prefixes, and explicit deep import paths. Exhausting
the existing binding-depth budget remains ANALYSIS_ERROR, with the invocation
present. The original 216-case matrix has zero false-established cases; all
eight metamorphic invariants pass.

The focused suite has 628 passes; the full suite has 1,929 passes, 12 existing
skips and four existing expected failures. Effects: 629 passes and one expected
failure. Legacy tests: 672 passes, 12 skips and three expected failures. The
fresh frozen comparison is byte-identical: 263 inputs, 108 individual findings,
24 repository findings. The pinned R04 graph/claims are also byte-identical:
141 roots, 839 reached invocations, 1,661 claims, 1,605 without rules, 105
established edges, 45 possible edges, 734 unknown edges, zero errors/gaps.

Compact validation evidence is recorded in
`research/M1R2A/import-stability-validation.json`; local source/result pairs,
red/green logs and serialized comparisons are in `outputs/m1r2a` outside the
repository. Only sibling tests were recovered; no sibling production commit
was ported. The analysis remains bounded lexical analysis and does not model
general import hooks, reflective runtime behavior or arbitrary object values.
