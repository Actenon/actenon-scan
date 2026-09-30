# Exact adjudication and supersession

Classification: NORMATIVE PROVENANCE INCONSISTENCY WITH A RUNTIME CONFORMANCE GAP.

AREF-002 evidence_acquisition.md §4.1, §6.1 and E04 require package name and pinned
version for contract-sourced packets. dependency_descent.md §5.1 includes L6.
However §5.3 and D08 permit retaining physically present UNPINNED material, and
AREF-002A's schema/oracle and source-constraints prose do not explicitly separate
that retention from settling admissibility. Production follows the permissive
schema/oracle for L6 while requiring pinning for probative dependency bodies.

The four reviewed counterexamples establish this conformance gap, not that a remote
mutation occurred or that every unversioned local contract is factually wrong.
The prior HIGH finding is about violating a required proof precondition. Passing
the old conformance oracle does not settle the conflicting normative language.

The smallest conservative decision is:

1. Reading/recording material is separate from admitting it as a settling fact.
2. Every PROBATIVE L6 packet MUST record nonempty package and resolved version,
   with version_resolution LOCKFILE, EXACT_MANIFEST_PIN or INSTALLED_TREE_METADATA.
3. UNPINNED L6 material may be retained HYPOTHESIS_ONLY. Its unresolved version
   must remain explicit; no version may be invented. All inherited metadata and
   extract requirements remain in force.
4. A packet falsely claiming PROBATIVE status without that provenance is INVALID.
   A loader MUST NOT silently relabel it, refute an obligation, or change its polarity.
5. Independently admissible support/refutation remains usable. The existence of an
   unpinned hypothesis is not a blanket veto on PROVEN_EFFECT or NO_EFFECT.

Upon adoption, this decision supersedes only the permissive L6-version condition
in A's evidence schema/oracle and the ambiguity about UNPINNED settling evidence
in A's source constraints and 002's §5.3/D08. It clarifies E04 for the current profile:
resolved version is mandatory for PROBATIVE contract evidence; unpinned retained
material is explicitly non-probative. B budget rules and every other condition stay.

The three profiles are additive conjunctions with sealed upstream schemas. They
add no fields or enum values and preserve wire schema_version 0.1.1 and inherited
additionalProperties=false. New IDs distinguish this normative profile. An existing
proof state cannot be changed simply because an old record had that wire number.

No alternative content-hash attestation, source snapshot mechanism or new source
acquisition capability is introduced. Such alternatives might be useful later,
but would require their own explicit provenance contract. A version string is not
proof of truth: M0 checks the supplied record, not whether that pin matches reality.
