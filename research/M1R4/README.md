# M1R4 development validation

Parent: `1430f7839fa6e771a463892dbfb3fdafc052773a`.
Validation: 2026-10-02, Python 3.14.6, Node 24.16.0, Go 1.26.4, all extras.
The committed `validation.json` binds evidence hashes to production file hashes;
the enclosing descendant commit identifies the final candidate.

The parent failed all 400 reproduced review regressions: 180 Python lexical
environment cases, 216 captured mutation cases and four contextual obligation
omissions. The repair passes all 400. Additional internal falsifiers caught five
canonical-binding forgeries, two site/activation forgeries and one file-scope
inventory collision before their corresponding changes. They are permanent
regressions. These are development tests, not independent held-out evidence.

The new runtime matrix executes 2,232 distinct deterministic valid programs:
960 Python, 1,200 JavaScript and 72 Go. The parent invents 1,464 runtime-impossible
edges on this matrix; the candidate invents zero. There are 288 false unresolved
observations: 48 conservative Python class/outer-iterable lookups, 120 JavaScript
deletions of absent own properties and 120 prototype mutations that leave the
own method intact. Conservative chronology and namespace summaries are retained.
The separate compiler/runtime differential suite has 144 cases.

Twelve stable positive controls issue genuine kernel proofs. Mutating these
proofs produces 1,044 rejected proof variants; another 384 changes to their sealed
semantic inventories are rejected. All 18 metamorphic invariants pass. Focused
M1 tests: 2,723 passed. Full repository suite: 4,024 passed, 12 skipped, four
expected failures, 89 passed subtests. Effect tests: 629 passed, one expected
failure. Legacy tests: 672 passed, 12 skipped, three expected failures, 89 passed
subtests. Frozen Findings are byte-identical: 263 inputs, 108 individual findings,
24 repository findings; SHA-256
`5286f71a8bab789850d3ea3a3da9f57356cf277dad4ec6d9f6cf2dda0543c6b9`.

Pinned development R04 remains at `1d7a16b25db74ed44539cd5079e2db46b42f08db`.
It yields 141 roots, 748 reached invocations, 1,524 claims, 1,469 claims without
rules, 62 ESTABLISHED, 77 POSSIBLE, 686 UNKNOWN, zero REFUTED, zero errors and
1,259 distinct coverage gaps. All claims ABSTAIN; semantic obligations stay
UNKNOWN. All 62 retained proofs are structurally audited, with 25 source edges
inspected across eight distinct targets. The 600 added gaps disclose 599 escape
limitations and one bounded escape-identity expansion. Repeated claims, summary
and root outputs are byte-identical. No retained established count was targeted.

Supplementary inherited probes need explicit interpretation. The unmodified
59-probe suite has three failed assertions: two require UNRESOLVED for empty Go
local function values even though the actual local body is safely resolved (both
also fail on the parent); one compares complete source-bound witness output
after changing source text. An external adapted copy retains the negative causal
assertions, accepts the actual Go literal and normalizes only the changed source
digests. That copy plus 978 independent property cases passes all 1,037 tests.
The original external files are unchanged. Another supplementary contract and
coverage suite passes 68 and fails three pre-existing precision assertions about
unrelated Python type-alias gaps in sibling/nested/separate files. Those failures
also reproduce on the parent and do not invent reachability. They remain known
conservative limitations, not green assertions.

Reproduce from the candidate with all extras and the stated runtimes:

```sh
python -m pytest tests/test_m1* tests/effect_claims
python -m pytest
PYTHONPATH=. python research/M1R4/runtime_matrix.py /tmp/m1r4-runtime
PYTHONPATH=. python research/M1R4/proof_mutations.py /tmp/m1r4-proofs.json
PYTHONPATH=. python scripts/evaluate_m1_development.py /path/to/pinned-R04 /tmp/m1r4-r04
PYTHONPATH=. python research/M1R4/audit_r04.py /path/to/pinned-R04 /tmp/m1r4-r04/R04-claims.json /tmp/m1r4-audit.json
```

Detailed local logs and generated traces are outside the checkout under
`outputs/m1r4`; their hashes are in `validation.json`. The prior synthetic fixture
exposure is recorded in `research/contamination-ledger.json`. Actual held-out
repositories were not opened. M0/AREF are unchanged; no M2 or provider logic is
included. The kernel's internal issuance boundary and bounded supported subset
are described in `docs/M1R4-trusted-kernel.md`.
