# M0R1-B — budget provenance and final revalidation

READY TO PUSH FOR INDEPENDENT M0R1 REVIEW: YES

Only the AREF-002B budget delta is implemented. Exhaustion identities remain mandatory;
NO_EFFECT with recorded exhaustion additionally requires supplied source-linked exclusions,
exact retained refutation packet references across every candidate, and exact coverage of
all recorded exhausted budgets/edges. Receipt acquisition and claim snapshots retain the
new record through the existing projections. C5 independently rejects relevant, unknown
or incompletely enumerated frontiers. M0 does not acquire or verify witness source truth.

MILESTONE: M0R1-B

PARENT SHA: ec4db0c2ab61c6d5b1c5d8537a9617f2d2534b30

NEW SHA: the new descendant checkpoint containing this receipt; reported after commit.

AREF-002B MANIFEST: 1ca543937178db80f455ce2a10bb65a49948bc24a0c8be49a58067efe30bdaec

CASE A: PASS — no exhaustion; NO_EFFECT without a witness.

CASE B: PASS — contributing exhaustion; ABSTAIN, identities retained.

CASE C: PASS — complete supplied unrelatedness proof; NO_EFFECT permitted.

CASE D: PASS — bare label/provenance absent; proposed NO_EFFECT rejected; ABSTAIN valid.

CASE E: PASS — unknown relevance; proposed NO_EFFECT rejected; ABSTAIN valid.

CASE F: PASS — explicit exhaustion missing identity/list is INVALID, including if labelled ABSTAIN.

BUDGET IDENTITY: PASS

EXCLUSION PROVENANCE: PASS

EDGE COVERAGE: PASS

C4: PASS — conditional supplied-record guard; no contributing-path truth assurance.

C5 INDEPENDENCE: PASS

H1-H6: PASS (each retained targeted regression plus the sealed adversarial cases).

M1-M5: PASS (including ordered-pair/triple aggregation and fatal verifier absence).

SINK-INDEPENDENT GENESIS: PASS

OPAQUE SINGLETON: PASS — UNRESOLVED_IDENTITY, five UNKNOWN, zero rule IDs, ABSTAIN.

AREF-002 VALIDATOR: 298/298 unchanged.

AREF-002A HISTORICAL VALIDATION: 86/86 in the exact failed-M0 preservation context.

AREF-002B VALIDATOR: 39/39 unchanged; its historical runtime probes still archive ec4db0c.

CURRENT CONFORMANCE GATE: 528 passed, 1 permitted historical AREF-002 schema xfailed.

FOCUSED TESTS: 46/46 budget tests; complete effect-claim gate as above.

LEGACY TESTS: 672 passed, 12 pre-existing skipped, 3 pre-existing xfailed, 89 subtests passed.
The same suite was re-run at b8a6a62, a93b013, ec4db0c: identical counts, no failures.

FULL TESTS: 1200 passed, 12 pre-existing skipped, 4 pre-existing xfailed, 89 subtests passed.

FALSIFICATION: 58/58; the original 35 M0R1 checks retained, all ten required budget
attacks rejected, seven further provenance/candidate/receipt checks and Cases A-F.
750 aggregation triple permutations, eight original whole-claim candidate orders, and
additional budget-bearing candidate permutations held. All four scanners produced the
same nine-finding canonical JSON SHA256:
0cb2bdb2f4151477e05a86ba9cde258536578e4a8b8dbcbb5e2a4a2cdcc7804b.

UNEXPECTED FAILURES: 0 in final acceptance.

PROVIDER-SPECIFIC KNOWLEDGE INTRODUCED: NO

R05/R06/R07 ACCESSED: NO

AREF-001 MODIFIED: NO

AREF-002 MODIFIED: NO

AREF-002A MODIFIED: NO

AREF-002B MODIFIED AFTER IMPLEMENTATION START: NO — all 159 protected files/inventory unchanged.

DEVIATIONS: NONE.

UNRESOLVED: NONE within this repair scope. Independent review and remote supported-Python
CI are pending; validation here used Python 3.14.6. No push, merge or M1 work.

GIT STATUS: pre-checkpoint exact status saved in working_tree_before_checkpoint.txt;
final status is verified and reported after creating the authorized descendant.

## Historical supersession and retained raw evidence

The one malformed AREF-002A VALID fixture is explicitly superseded in current conformance
by the sealed B fixture. Its unchanged original is covered by a real INVALID regression;
no new skip/xfail was added. Every other frozen A case remains selected unchanged.
Claim/receipt schema profiles use B; evidence/ledger schemas and the assertion registry
remain A. The required CI job now also runs the unchanged B validator.

Test-first logs preserve 16 genuine pre-repair failures. The first test-authoring run
also expected the verifier's error message to include a dependency name; that assertion
was corrected to its exact frozen fatal message before production changes. A test-authored
second budget initially used a nonexistent name; the initial failing run is retained and
that input was corrected to max_files_opened, retaining the exact coverage assertion.
The ad-hoc preflight helper initially assumed identical manifest formats; the corrected
helper verified every protected file before production changes, as recorded in preflight.json.
These authoring corrections did not change any frozen input or runtime proof semantics.

Concurrent legacy/full runs passed with four pytest temporary-directory cleanup warnings.
A separate full run with an isolated basetemp passed without warnings. All raw runs remain
preserved. Historical legacy snapshots also used isolated temporary directories.

See [results](test_results.json), [falsification receipts](falsification_results.json),
[preservation](preservation_final.json), [contamination check](contamination_check.json),
and [file inventory](file_inventory.json). Historical M0R1 research evidence is unchanged.
