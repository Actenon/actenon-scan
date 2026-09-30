# M0R1 — proof-kernel repair receipt

MILESTONE: M0R1

STARTING M0 SHA: a93b013383ce773b10708d3f30b2a1660e141527

AREF-002A MANIFEST HASH: 00ef6dd054b0f4a8ca14876147a2f5b82fecc6f4475d883bd7b49f23b60549ac

CHECKPOINT BRANCH: feat/aref-002-m0r1-proof-kernel-repair

READY FOR INDEPENDENT M0R1 REVIEW: NO

The eleven authorized repairs are implemented and their targeted regressions pass. The complete acceptance gate is red because a sealed positive example conflicts with an inherited budget-provenance requirement. No production or frozen-spec change was made to conceal that failure.

FILES CREATED:

- `actenon_scan/effects/_assertions.py`
- `research/M0R1/H6_intended_reason_red.txt`
- `research/M0R1/NORMATIVE_CONFLICT.md`
- `research/M0R1/RECEIPT.md`
- `research/M0R1/baseline_full.txt`
- `research/M0R1/baseline_full_path.txt`
- `research/M0R1/contamination_check.json`
- `research/M0R1/direct_amendment_validator.txt`
- `research/M0R1/direct_aref002_validator.txt`
- `research/M0R1/falsification_harness_initial_error.txt`
- `research/M0R1/falsification_results.json`
- `research/M0R1/falsification_run.txt`
- `research/M0R1/falsify.py`
- `research/M0R1/file_inventory.json`
- `research/M0R1/focused_iteration1.txt`
- `research/M0R1/focused_iteration2.txt`
- `research/M0R1/focused_iteration3.txt`
- `research/M0R1/focused_iteration4.txt`
- `research/M0R1/focused_iteration5.txt`
- `research/M0R1/focused_tests.txt`
- `research/M0R1/frozen_validators.txt`
- `research/M0R1/full_tests.txt`
- `research/M0R1/legacy_tests.txt`
- `research/M0R1/m0_full_before.txt`
- `research/M0R1/m0_full_before_path.txt`
- `research/M0R1/preflight.json`
- `research/M0R1/preservation_final.json`
- `research/M0R1/runtime_example_audit.json`
- `research/M0R1/test_first_red.txt`
- `research/M0R1/test_results.json`
- `research/M0R1/working_tree_before_checkpoint.txt`
- `scripts/validate_aref002a.py`
- `specs/AREF-002A/AMENDMENT.md`
- `specs/AREF-002A/MANIFEST.json`
- `specs/AREF-002A/MANIFEST.sha256`
- `specs/AREF-002A/README.md`
- `specs/AREF-002A/REPORT.md`
- `specs/AREF-002A/aggregation.md`
- `specs/AREF-002A/amendment_contract.json`
- `specs/AREF-002A/assertion_compatibility.md`
- `specs/AREF-002A/assertion_registry.json`
- `specs/AREF-002A/build_examples.py`
- `specs/AREF-002A/case_registry.json`
- `specs/AREF-002A/closure_and_receipts.md`
- `specs/AREF-002A/coverage_ledger.schema.json`
- `specs/AREF-002A/effect_claim.schema.json`
- `specs/AREF-002A/effect_receipt.schema.json`
- `specs/AREF-002A/evidence.schema.json`
- `specs/AREF-002A/examples/H1_agreement_hides_error.json`
- `specs/AREF-002A/examples/H1_error_as_abstain.json`
- `specs/AREF-002A/examples/H1_error_bad_selection.json`
- `specs/AREF-002A/examples/H1_error_erased.json`
- `specs/AREF-002A/examples/H2_positive_dry_run_in_force.json`
- `specs/AREF-002A/examples/H2_positive_noop.json`
- `specs/AREF-002A/examples/H2_positive_state_is_ephemeral.json`
- `specs/AREF-002A/examples/H2_positive_state_is_guaranteed_rolled_back.json`
- `specs/AREF-002A/examples/H2_positive_test_double_in_force.json`
- `specs/AREF-002A/examples/H2_transport_operation.json`
- `specs/AREF-002A/examples/H2_transport_persistence.json`
- `specs/AREF-002A/examples/H2_unregistered_probative.json`
- `specs/AREF-002A/examples/H3_no_recorded_provenance.json`
- `specs/AREF-002A/examples/H3_other_source_identity.json`
- `specs/AREF-002A/examples/H3_package_not_body.json`
- `specs/AREF-002A/examples/H3_tier_not_selection_proof.json`
- `specs/AREF-002A/examples/H3_unlinked_body.json`
- `specs/AREF-002A/examples/H4_conflict_negative_closure.json`
- `specs/AREF-002A/examples/H4_uncertainty_erases_conflict.json`
- `specs/AREF-002A/examples/H5_claim_open_negative.json`
- `specs/AREF-002A/examples/H5_receipt_and_snapshot_open_negative.json`
- `specs/AREF-002A/examples/H5_receipt_missing_closure.json`
- `specs/AREF-002A/examples/H5_receipt_strengthened.json`
- `specs/AREF-002A/examples/H6_cause_partition.json`
- `specs/AREF-002A/examples/H6_error_breakdown.json`
- `specs/AREF-002A/examples/H6_error_total.json`
- `specs/AREF-002A/examples/H6_impossible_settled_population.json`
- `specs/AREF-002A/examples/M1_blanket_found_veto.json`
- `specs/AREF-002A/examples/M1_incomplete_positive.json`
- `specs/AREF-002A/examples/M1_missing_positive.json`
- `specs/AREF-002A/examples/M2_conflict_erased.json`
- `specs/AREF-002A/examples/M2_divergence_not_contradiction.json`
- `specs/AREF-002A/examples/M2_error_erased.json`
- `specs/AREF-002A/examples/M3_opaque_false_establishment.json`
- `specs/AREF-002A/examples/M3_opaque_omitted_states.json`
- `specs/AREF-002A/examples/M3_opaque_supported_identity.json`
- `specs/AREF-002A/examples/M4_false_closure_flag.json`
- `specs/AREF-002A/examples/M4_missing_closure.json`
- `specs/AREF-002A/examples/valid_agreement.json`
- `specs/AREF-002A/examples/valid_analysis_error.json`
- `specs/AREF-002A/examples/valid_divergent.json`
- `specs/AREF-002A/examples/valid_error_over_conflict.json`
- `specs/AREF-002A/examples/valid_helper_precedence.json`
- `specs/AREF-002A/examples/valid_hypothesis_found.json`
- `specs/AREF-002A/examples/valid_incomplete_probe_abstain.json`
- `specs/AREF-002A/examples/valid_ledger.json`
- `specs/AREF-002A/examples/valid_ledger_overlapping_errors.json`
- `specs/AREF-002A/examples/valid_missing_probe_abstain.json`
- `specs/AREF-002A/examples/valid_multi_conflict.json`
- `specs/AREF-002A/examples/valid_multi_error.json`
- `specs/AREF-002A/examples/valid_negative_precedence.json`
- `specs/AREF-002A/examples/valid_no_effect.json`
- `specs/AREF-002A/examples/valid_opaque_abstain.json`
- `specs/AREF-002A/examples/valid_open_frontier_abstain.json`
- `specs/AREF-002A/examples/valid_precedence_found.json`
- `specs/AREF-002A/examples/valid_proven.json`
- `specs/AREF-002A/examples/valid_receipt_abstain.json`
- `specs/AREF-002A/examples/valid_receipt_analysis_error.json`
- `specs/AREF-002A/examples/valid_receipt_found_precedence.json`
- `specs/AREF-002A/examples/valid_receipt_negative_precedence.json`
- `specs/AREF-002A/examples/valid_receipt_no_effect.json`
- `specs/AREF-002A/examples/valid_receipt_proven.json`
- `specs/AREF-002A/examples/valid_single_established_shorthand.json`
- `specs/AREF-002A/examples/valid_uncertainty_preserves_conflict.json`
- `specs/AREF-002A/examples/valid_unregistered_hypothesis.json`
- `specs/AREF-002A/examples/valid_unrelated_frontier_negative.json`
- `specs/AREF-002A/input_preservation.json`
- `specs/AREF-002A/ledger_consistency.md`
- `specs/AREF-002A/m0_repair_contract.md`
- `specs/AREF-002A/precedence.md`
- `specs/AREF-002A/probe_semantics.md`
- `specs/AREF-002A/requirements-validation.txt`
- `specs/AREF-002A/schema_conformance.md`
- `specs/AREF-002A/selection.md`
- `specs/AREF-002A/validate.py`
- `specs/AREF-002A/validation.md`
- `tests/effect_claims/test_m0r1_regressions.py`

FILES MODIFIED:

- `.github/workflows/ci.yml`
- `actenon_scan/effects/__init__.py`
- `actenon_scan/effects/claim.py`
- `actenon_scan/effects/evidence.py`
- `actenon_scan/effects/ledger.py`
- `actenon_scan/effects/receipt.py`
- `actenon_scan/effects/vocabulary.py`
- `pyproject.toml`
- `tests/effect_claims/_builders.py`
- `tests/effect_claims/_spec.py`
- `tests/effect_claims/test_m0_claim.py`
- `tests/effect_claims/test_m0_evidence.py`
- `tests/effect_claims/test_m0_ledger.py`
- `tests/effect_claims/test_m0_receipt.py`
- `tests/effect_claims/test_m0_schema_conformance.py`
- `tests/effect_claims/test_m0_vocabulary.py`

H1: PASS

H2: PASS

H3: PASS

H4: PASS

H5: PASS

H6: PASS

M1: PASS

M2: PASS

M3: PASS

M4: PASS

M5: PASS

SINK-INDEPENDENT GENESIS: PASS

OPAQUE SINGLETON: PASS

AGGREGATION: PASS

TYPED ASSERTIONS: PASS

PRECEDENCE: PASS

NEGATIVE CLOSURE: PASS

RECEIPT NON-STRENGTHENING: PASS

LEDGER CONSISTENCY: PASS

PROBE SEMANTICS: PASS

SCHEMA GATE: FAIL — mandatory dependency enforcement passes, but full runtime conformance has the frozen budget-example failure.

AREF-002A VALIDATOR: 86/86 in the exact historical M0 preservation context; direct repaired-checkout run 84/86, failing only its historical source/test preservation checks. Both raw outputs retained.

AREF-002 VALIDATOR: 298/298, including historical AREF-001 preservation.

FOCUSED TESTS: 481 passed, 1 failed, 1 historical xfailed.

LEGACY TESTS: 672 passed, 12 skipped, 3 xfailed, 89 subtests passed — identical to pre-M0 baseline.

FULL TESTS: 1153 passed, 1 failed, 12 pre-existing skipped, 4 xfailed, 89 subtests passed.

FALSIFICATION ATTEMPTS: 35/35 passed; malformed/error-support, reversed typed assertions, tier-only/unlinked precedence, uncertainty-erased contradiction, open-frontier negative receipt, impossible ledger, opaque false identity, harmless/resolved FOUND, ordering, missing schema verifier and legacy Finding invariance. 750 triple permutations and 8 whole-claim candidate orders checked. All three scanner versions emitted identical 9-finding JSON reports (canonical SHA256 0cb2bdb2f4151477e05a86ba9cde258536578e4a8b8dbcbb5e2a4a2cdcc7804b).

PROVIDER-SPECIFIC KNOWLEDGE INTRODUCED: NO

R05/R06/R07 ACCESSED: NO

AREF-001 MODIFIED: NO

AREF-002 MODIFIED: NO

AREF-002A MODIFIED AFTER IMPLEMENTATION BEGAN: NO

DEVIATIONS:

- AREF-002A preservation validation must use its frozen M0 context; the unchanged validator deliberately pins the failed implementation and cannot pass directly after any repair. Added a documented snapshot-context wrapper and a separate mandatory current-runtime test gate. The direct run remains recorded as 84/86, not relabeled as a pass.
- Full acceptance did not pass. The scored frozen example was not changed, skipped, marked xfail or substituted. Repairs were completed and checkpointed as not ready.
- The local falsification harness initially named a nonexistent fixture; its raw error was preserved before correcting that research-only reference. No REI experiment was rerun.

UNRESOLVED:

- [Frozen budget-provenance conflict](NORMATIVE_CONFLICT.md): `valid_unrelated_frontier_negative.json` omits budget_name and the exhausted budget list required by unamended AREF-002. A versioned normative correction is required before a green gate; this task does not authorize it.
- Independent adversarial review and supported-Python CI matrix remain unexecuted. Local tests ran on Python 3.14.6.

GIT STATUS: empty after the new local descendant checkpoint; no push, merge or PR.

Validation limits: C4 is a represented assertion, not a proof of contributing-path completeness. Binding/body witnesses are supplied records; M0R1 does not acquire or truth-check source semantics. No M1 or evidence acquisition was implemented. Receipt validation is self-consistency, not cryptographic tamper detection. Ledger marginals enforce sound necessary bounds, not exact joint realizability.

Raw evidence: [test results](test_results.json), [falsification](falsification_results.json), [runtime example audit](runtime_example_audit.json), [preservation hashes](preservation_final.json), [contamination check](contamination_check.json), [file inventory](file_inventory.json).
