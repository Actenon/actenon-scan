# Conformance validation and its limits

Run the required command in [schema_conformance.md](schema_conformance.md).
`validate.py` reads authored records, the local amended schemas and registry, and
the frozen AREF-002 probe definitions. It never imports production Actenon, performs
source analysis, opens dependencies, executes example programs or changes records.

`case_registry.json` lists each example's kind, intended validity and, for negative
cases, its exact expected rejection code. Schema rejections also specify the JSON
pointer and schema keyword. Rejecting an input for an unrelated error is a failed
test. An unexpected exception fails the gate; it is not treated as semantic abstention.

The examples are **normative authored proof records**, not REI experimental cases.
Their `synthetic/` locators and extracts illustrate records; they are not claims
that source fidelity or real effects have been measured. No source program is run.

| Required assurance | Executable check |
|---|---|
| 1. Corrected schemas valid | Draft202012Validator.check_schema for all four |
| 2. Every verdict satisfiable | Accepted `valid_proven`, `valid_no_effect`, `valid_opaque_abstain`, `valid_analysis_error`; corresponding receipts |
| 3. Closed NO_EFFECT passes | `valid_no_effect`, `valid_receipt_no_effect` |
| 4. Missing NO_EFFECT closure fails | `M4_missing_closure`, `H5_receipt_missing_closure` |
| 5. Opaque all-UNKNOWN singleton valid | `valid_opaque_abstain` |
| 6. Empty rule IDs legal | Four-verdict valid claims and receipts contain `matched_rule_ids=[]` |
| 7. ERROR dominates | Literal table, triples, H1 cases, `valid_error_over_conflict` |
| 8. CONFLICTING dominates non-error | Literal table, `valid_multi_conflict`, `M2_conflict_erased` |
| 9. S/R becomes UNKNOWN | Literal table, `valid_divergent`, `M2_divergence_not_contradiction` |
| 10. Ephemeral not positive persistence | `H2_positive_state_is_ephemeral` and registry check |
| 11. Transport cannot settle persistence | `H2_transport_persistence`; operation counterpart |
| 12. Tier insufficient for precedence | H3 invalid selection/body/source/provenance cases |
| 13. Relevant unopened frontier blocks NO_EFFECT | H5 claim and loaded receipt cases; unrelated-frontier negative remains valid |
| 14. Completed FOUND is not a veto | `valid_hypothesis_found`, `valid_precedence_found`, `M1_blanket_found_veto` |
| 15. Detectable impossible ledgers rejected | H6 disjointness and error-breakdown cases |
| 16. Missing verifier fails gate | Actual `python -S validate.py` subprocess requires fatal exit 2 |

The gate additionally checks complete ordered aggregation pairs, all triple
permutations, associativity, reversed candidate/packet/probe/contradiction order,
JSON round trips of valid records, unchanged vocabulary, registry/schema agreement,
protected-file hashes/inventory and the exact sealed amendment inventory.

The round-trip check here proves JSON record preservation, not the repaired
production codec, which does not yet exist. The repair task must exercise its own
types and serializers against the same semantics. Likewise, this oracle does not
replace unaffected M0 validation or independently prove assertion truth, candidate
enumeration, C4 completeness, source fidelity, effective permissions or real-world
recall. Aggregate ledger bounds are necessary, not a complete correlation solver.

## Preservation and sealing

`input_preservation.json` records SHA-256 of files in `specs/AREF-001`,
`specs/AREF-002`, `actenon_scan` and `tests` before amendment authoring. Validation
checks both exact inventory and bytes. The completed task also checks Git status
to ensure all new files lie under this amendment directory.

`MANIFEST.json` inventories every amendment file except the two manifest files
themselves, with path relative to this directory, byte length and SHA-256.
`MANIFEST.sha256` expresses the same inventory with repository-relative paths.
Excluding the manifests avoids a recursive self-hash. They are integrity
inventories, not cryptographic authentication or receipt tamper detection.

`build_examples.py` is preserved for authoring provenance. CI validates the sealed
JSON files and their expected outcomes; it never regenerates them to obtain success.
The authoring `--no-seal` run is explicitly labeled and cannot substitute for the
default sealed gate.
