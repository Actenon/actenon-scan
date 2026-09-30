# Single-issue amendment

## Authority and exact supersession

AREF-002B supersedes only:

1. AREF-002A's declaration that `valid_unrelated_frontier_negative.json` is valid
   despite omitted budget identity: the corrected normative example is the file
   of that name under this package. The original bytes and its historical validator
   result remain evidence, never rewritten.
2. AREF-002A's omission of an M0-recordable provenance requirement for excluding
   **recorded budget exhaustion** from negative closure. C4's semantic meaning is
   unchanged; its true literal alone is insufficient in this one situation.
3. The corresponding claim acquisition/frontier schema clauses, plus the receipt's
   references to those claim clauses. A distinct budget profile adds the supplied
   proof record and its conditional requirement.

AREF-002 dependency_descent.md §4.3 item 3 and §6.1 remain authoritative: an
exhausted budget is named regardless of relevance. C4 and C5 remain separate:
no contributing-path exhaustion, and no relevant unopened frontier. Neither is
replaced by a global stop-reason heuristic.

No change is made to H1–H6/M1–M5, aggregation, selection, assertion compatibility,
precedence, verdict ordering, receipt projection rules, ledger arithmetic, probes,
sink independence, budgets or the North-Star ontology. Receipt references change
only because its existing acquisition/snapshot projections must retain budget
provenance. No new necessary obligation or typed assertion predicate is introduced.

## Adjudication

The historical VALID designation conflicts with unconditional identity recording;
the schema/validator omitted those inherited conditions. M0R1's three identity
checks are correct and must remain. Adding both budget fields makes the historical
record load as NO_EFFECT without any separate evidence for excluding the exhausted
path. That conforms to AREF-002A's explicitly deferred C4 provenance, but cannot
satisfy the current requirement to distinguish supported irrelevance from a bare
label. This is a narrowly bounded normative contradiction/representation gap,
with a concrete malformed fixture; it is not a reason to weaken the inherited rule.

The smallest correction meeting both requirements is a versioned corrected fixture,
conditional schema checks for existing budget identities, and one source-linked,
refutation-linked exclusion record required only for an exhausted NO_EFFECT.
Budget-name-only correction was tested and rejected as insufficient for Case D.

[budget_provenance.md](budget_provenance.md) freezes the representation and rules.
[m0r1_delta.md](m0r1_delta.md) states the only future implementation/test delta.
No such delta is implemented here.
