# Blocking-probe completion and found evidence

The probe IDs, classes, applicability and required checks remain those in the
immutable AREF-002 `architecture_manifest.json`. This amendment changes how their
outcomes participate in proof, not what acquisition must look for.

| Outcome | Completion | Effect on proof |
|---|---|---|
| Missing required BLOCKING probe | Not completed | Blocks PROVEN_EFFECT |
| INCOMPLETE | Not completed | Blocks PROVEN_EFFECT; preserve reason/frontier |
| NOT_FOUND | Completed | No found evidence; does not itself refute any obligation |
| FOUND | Completed | Cited evidence enters ordinary typed admissibility and proof-state evaluation |

FOUND MUST cite actual packet IDs for the same obligation. NOT_FOUND cannot cite
found packets. IDs must be unique and resolvable. Counter-evidence is distinct from
supporting evidence; a positive settling packet cannot be passed off as found
counter-evidence. HYPOTHESIS_ONLY packets may express a concern without settling it.

A completed FOUND probe is **not** an additional semantic veto. Specifically:

- HYPOTHESIS_ONLY evidence cannot block an otherwise established proof merely
  because a BLOCKING probe found it.
- Admissible negative facts can refute an obligation or create CONFLICTING with
  positive facts. They block proof through those states.
- Counter-evidence legitimately overridden by selected-body precedence is retained
  and explained, but does not remain a blanket veto after resolution.
- CP-PER-05's commit uncertainty is handled as the typed uncertainty fact; it
  cannot demote an unresolved conflict to UNKNOWN.

ADVISORY probes retain their original reporting/triage role. Their existence or
absence adds no new required conjunction term. The semantics of any evidence
they actually supply are still governed by admissibility, not the probe label.

The conformance examples deliberately include two valid PROVEN_EFFECT claims
with completed FOUND probes: a hypothesis-only concern, and contrary contract
evidence resolved through recorded selected-body precedence. They also include
missing and incomplete required probes, each requiring ABSTAIN in otherwise
supported claims.
