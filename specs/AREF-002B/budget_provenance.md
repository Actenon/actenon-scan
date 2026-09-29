# Budget identity, exclusion provenance and negative closure

## 1. Identity is independent of relevance

`acquisition.budget_exhausted` is the unique set of budget names exhausted for this
claim, using the unchanged seven-budget vocabulary. A BUDGET_EXHAUSTED stop requires
a nonempty list. Every BUDGET_EXHAUSTED frontier entry requires `budget_name`; that
name must be in the list. A non-budget frontier reason must not carry budget_name.
These are record-validity conditions, not optional evidence-strength preferences.

An exhausted budget must be retained even if proven unrelated to the refutation.
A successful/global stop reason does not erase other recorded exhaustion. If no
exhaustion exists, the list may be absent or empty, no budget_name is needed, and
no budget_provenance record is required or allowed. No default budget may be guessed.

## 2. Optional acquisition record, conditional negative requirement

The new `acquisition.budget_provenance` object contains:

- `refuted_obligation`: the non-IMPLEMENTATION obligation whose negative closure
  is being assessed;
- `refutation_packet_ids`: exactly the remaining NEGATIVE PROBATIVE fact packets
  settling that obligation, across all implementation candidates, excluding
  overridden and uncertainty packets;
- `exclusions`: exactly one source-linked witness per recorded exhausted budget.
  Each contains `budget_name`, `frontier_indices`, a precise `locator` and a
  nonempty `extract` with `verbatim=true` and no truncation.

Each exclusion attests both that **every affected exhaustion path** for that budget
is outside acquisition paths contributing to the named refutation, and that the
exact listed exhausted frontier entries cannot settle that refuted obligation.
This is the meaning of the supplied proof record; a label, package identity or
method name is not a substitute. The producer must substantiate that meaning
from the recorded source/analysis material. M0 validates representation and links,
not truth of the text or path completeness.

The witness's frontier_indices must equal, without duplication, all indices of
BUDGET_EXHAUSTED frontier entries carrying its budget_name. There is one witness
for every budget in the list, no extra budget, and no frontier index may be dropped
or reassigned. An empty index list is permitted only when no frontier entry names
that budget; the witness must still attest non-contribution of all its affected
exhaustion paths. Fully enumerated frontier accounting remains required.

The refutation must be the closure's same obligation. Every candidate must be
represented in its probative negative packet references. Missing, wrong-candidate,
positive, hypothesis-only, uncertainty, overridden or unrelated-obligation references
cannot supply that provenance. Witness locators must retain ordinary normalized
source/version/span identity; the packet/source association remains the producer's
responsibility. The locator/extract need not be implementation code: it may be a
source-linked analysis proof record establishing the two scoped propositions.
A generic explanation lacking a rereadable locator and verbatim extract is not one.

For NO_EFFECT with any recorded exhaustion this record is REQUIRED, together with
all inherited C1–C6 conditions. Nonempty might_settle excluding the refuted obligation
is the represented frontier scope; in exhausted negatives it is evidence-backed
by the exclusion witness, not accepted as standalone proof. Missing/empty scope
is UNKNOWN and conservatively relevant, regardless of a supplied exclusion claim.
An explicit scope containing the refuted obligation also prevents closure.

For ABSTAIN, the exhaustion identities and frontier remain recorded, but no
unsupported exclusion witness is required or invented. No new obligation state
is assigned merely to represent failed/unknown closure. The five obligation states
retain their existing evidence and may include a legitimately REFUTED obligation.
The claim simply lacks established negative closure.

## 3. The four situations

| Situation | Budget record | C4 and C5 | Result, assuming other negative conditions |
|---|---|---|---|
| No exhaustion | Names absent/empty; no witnesses | C4 may remain represented true; C5 evaluated normally | NO_EFFECT may be valid |
| Exhaustion on contributing/refuting path | Identities retained | C4 false; never assert true with an exclusion witness | ABSTAIN, unless an inherited necessary ERROR requires ANALYSIS_ERROR |
| Exhaustion established unrelated | Names, complete edge mapping, source-linked exclusion and exact refutation links retained | C4 may remain true; C5 must independently pass with supported scope | NO_EFFECT may be valid |
| Exhaustion relevance unknown, or merely labelled unrelated | Identities retained; missing proof is not fabricated | C4 not established; unknown/relevant frontier also fails C5 | ABSTAIN, subject to unchanged ERROR priority |

This profile does not make the global BUDGET_EXHAUSTED stop a blanket veto.
It also does not make a global SETTLED stop proof of C4. An unrelated exhausted
budget can coexist with a negative only through the supplied scoped proof record.

## 4. Invalid records versus semantic abstention

Case F (exhaustion explicitly recorded without identity/list provenance) is INVALID:
it cannot be loaded as a conformance-checked claim or converted into semantic
ABSTAIN. The producer must correct the record with actual identity evidence; the
validator must not guess a budget. This is an output/harness/provenance failure,
not proof of an effect, a refutation, or by itself a new necessary ANALYSIS_ERROR.

Cases B/D/E have valid ABSTAIN representations with names retained and closure
omitted. A proposed NO_EFFECT with unsupported/missing closure provenance is
rejected; a producer must emit ABSTAIN rather than that stronger invalid record.
An explicit false C4 in a NO_EFFECT closure is also invalid. Failed negative
closure does not weaken or discard the underlying refutation evidence.

C4 remains a represented assertion at M0. The additional witness prevents a bare
unrelated label from being the entire budget exclusion, but does not prove source
truth, exclude concealed exhaustion, cryptographically authenticate evidence, or
implement acquisition/path analysis. Those remain later responsibilities.
