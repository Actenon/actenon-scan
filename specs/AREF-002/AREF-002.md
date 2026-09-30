# AREF-002 — Resource Effect Inference: corrected architecture freeze

**Status:** AUTHORITATIVE. Supersedes AREF-001 as a design.
**Supersedes:** `specs/AREF-001/` — retained unmodified as
`SUPERSEDED DESIGN CANDIDATE / NOT AUTHORITATIVE`.
**Frozen against:** `actenon-scan` @ `b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16`
(branch `main`, version `1.5.0`).
**Verdict:** see [REPORT.md](REPORT.md) §30.

---

## 1. The founding principle

> **A consequential effect is a claim to be proved, not a sink to be matched.**

Everything below is a consequence of that sentence. Where AREF-002 and AREF-001
differ, the difference is traceable to it.

## 2. What was wrong with AREF-001

AREF-001 was built without the REI evidence and reconstructed Resource Effect
Inference out of the material it could see: the sink-rule engine. Its pipeline
was

```
detect_sinks → rule-ID catalogue lookup → resource annotation
```

and its unit of work was "one record per sink call site". Under that design an
effect **cannot exist** unless a rule already fired. That is precisely the
failure R04 measured: 0 of 17 manually identified consequential paths in
`cloudflare/mcp-server-cloudflare` @ `1d7a16b2` were detected, and the
first-broken-component analysis put **13 of 17 at "H — semantic resource-effect
recognition"**: high-level SDK resource operations were not recognised as
effects at all. Two more failed at registration, two at handler extraction,
none at interprocedural resolution. The 322 unresolved-call records were not
established as causal for any of the 17 misses.

A rule-gated architecture cannot repair an H-class failure, because H is the
absence of a rule. AREF-001's D-01, D-02, D-04 and D-06 each encode that gate,
which is why all four are **REJECTED** ([aref_001_delta.md](aref_001_delta.md)).

## 3. The corrected architecture

```
CAPABILITY
   │   a model-reachable entry surface: what the model can cause to run
   ▼
INVOCATION
   │   EVERY call site in the capability's analysed region.
   │   No rule match is required, consulted, or relevant here.
   ▼
POSSIBLE IMPLEMENTATIONS            (SET-VALUED — requirement 3)
   │   {RESOLVED_LOCAL, RESOLVED_DEPENDENCY_SOURCE, CONTRACT_DECLARED,
   │    OPAQUE_EXTERNAL, DYNAMIC_UNRESOLVED, TEST_DOUBLE}
   │   each candidate carries its own evidence packet set (requirement 4)
   ▼
EFFECT CLAIM                        (the central domain object)
   │   instantiated unless the invocation is PROVEN INERT for the class.
   │   Default state is "claim exists, verdict ABSTAIN" — never "no claim".
   ▼
EVIDENCE  ──────────────►  COUNTER-EVIDENCE
   │   nine-tier bounded ladder        mandatory adversarial probes,
   │   (evidence_acquisition.md)       executed before PROVEN_EFFECT
   ▼
PROOF OBLIGATIONS
   │   IMPLEMENTATION · ACTIVATION · BOUNDARY · OPERATION · PERSISTENCE
   │   each independently ∈ {SUPPORTED, REFUTED, UNKNOWN, CONFLICTING, ERROR}
   ▼
VERDICT
   │   PROVEN_EFFECT · NO_EFFECT · ABSTAIN · ANALYSIS_ERROR
   ▼
EFFECT RECEIPT
       the auditable artefact answering eleven fixed questions
```

Retained **separately**, never as proof obligations (requirement 8):
**TARGET**, **CONTROL**, **AUTHORITY**, **CONDITIONS**. REI-002 is the reason:
a fixed-target effect was still `PROVEN_EFFECT` with `TRIGGER_CONTROL =
SUPPORTED` and `TARGET_CONTROL = REFUTED`, and authority remained separate from
effect throughout. Folding any of the four into the obligation conjunction would
contradict a measured result.

## 4. The central domain object

### 4.1 Identity

An `EffectClaim` is identified by

```
(capability_id, invocation_id, effect_class)
```

Implementations live **inside** the claim as a set, not as separate claims.
That is deliberate: one invocation with three candidate implementations is one
question with three answers in evidence, not three questions. It is also what
makes "alternative implementations remain separate evidence packets" (REI-002)
expressible — the packets differ, the claim does not fork.

### 4.2 Genesis — the inversion, stated exactly

> An `EffectClaim` for effect class `E` is instantiated for invocation `I`
> **unless `I` is PROVEN INERT for `E`**.

`PROVEN INERT` requires, for **every** implementation candidate of `I`, at least
one `PROBATIVE` evidence packet refuting a **necessary** obligation of `E`,
under established closure (§7.4). Anything less — an unresolved callee, an
opaque package, a dynamic dispatch, an exhausted budget — leaves the claim
instantiated with obligations `UNKNOWN` and verdict `ABSTAIN`.

Three consequences, all intended:

1. **Claim existence never depends on a rule hit** (requirement 2). The word
   "rule" does not appear in the genesis condition.
2. **An unfamiliar SDK call produces a claim.** Its single candidate is
   `OPAQUE_EXTERNAL`, inertness cannot be established, so the claim exists. The
   full trace is [§13](#13-the-critical-question-traced) and
   [REPORT.md](REPORT.md) Q8.
3. **Claims are numerous.** Instantiation is cheap and universal;
   *investigation* is budgeted and prioritised. The gap between the two is not
   hidden — it is the Coverage Ledger (§10), and it is why "0 findings" cannot
   mean "safe".

### 4.3 What a claim is not

It is not a finding, not an annotation on a finding, and not a severity. It is a
hypothesis with an evidentiary record and a verdict. A claim with verdict
`ABSTAIN` is a first-class output: it says "this invocation may produce this
effect class and here is exactly what we could not establish".

## 5. Proof states — frozen (requirement 5)

| State | Meaning |
|---|---|
| `SUPPORTED` | ≥1 `PROBATIVE` packet asserts the obligation and no unresolved contradiction |
| `REFUTED` | ≥1 `PROBATIVE` packet denies the obligation and no unresolved contradiction |
| `UNKNOWN` | no `PROBATIVE` packet either way, or acquisition did not reach the tier that could settle it |
| `CONFLICTING` | `PROBATIVE` packets of opposing polarity on the same obligation for the same implementation, not resolved by an admissible precedence rule |
| `ERROR` | acquisition or analysis for this obligation failed |

`ERROR` is the state REI-002 did not need and production does. It is separated
from `UNKNOWN` because "we did not find out" and "our analysis broke" require
different responses: the first is a coverage fact, the second is a bug.

`CONFLICTING` never silently collapses to `UNKNOWN`. The verdict may be
`ABSTAIN` in both cases, but the receipt must distinguish them, because a
contradiction is a stronger signal about the code than an absence
(requirement 14, [proof_obligations.md](proof_obligations.md) §6).

## 6. Top-level verdicts — frozen (requirement 6)

| Verdict | Condition |
|---|---|
| `PROVEN_EFFECT` | §7.3 conjunction holds and the counter-evidence pass completed |
| `NO_EFFECT` | ≥1 necessary obligation `REFUTED` **and** closure established (§7.4) |
| `ABSTAIN` | anything else that is not an error |
| `ANALYSIS_ERROR` | `ERROR` on an obligation the verdict depends on |

## 7. Proof obligations — frozen (requirement 7)

Five independent obligations. "Independent" means each is settled by its own
evidence and none is inferred from another. The prohibitions in §7.2 exist
because REI-002 measured each of them.

### 7.1 The five

| Obligation | Question | Settled by |
|---|---|---|
| `IMPLEMENTATION` | *Which code actually runs?* | candidate set + selection state (§8) |
| `ACTIVATION` | *Is this invocation executed when the capability runs?* | reachability and execution-position evidence |
| `BOUNDARY` | *Does the effect leave the analysed state into an external system?* | dispatch/transport/driver evidence |
| `OPERATION` | *Is the operation contract a mutation rather than an observation?* | operation contract semantics |
| `PERSISTENCE` | *Does the mutation outlive the request?* | commit/rollback/lifetime evidence |

### 7.2 Frozen prohibitions, each traceable to a measured result

| Prohibition | Source |
|---|---|
| HTTP/network dispatch may support `ACTIVATION` and `BOUNDARY` but **never** establishes `OPERATION` or `PERSISTENCE` (requirement 9) | REI-002: *every carrier used POST*, yet an identical-source pair changed classification solely because the operation contract changed between mutation and observation |
| Construction is not activation | REI-002 |
| Dispatch is not persistence | REI-002 |
| External boundary does not imply persistence | REI-002 |
| Persistence is independent of transport | REI-002 |
| Guaranteed rollback **refutes** persistence | REI-002 |
| Unknown commit-versus-rollback preserves uncertainty (`UNKNOWN`, never `SUPPORTED`) | REI-002 |
| Names may generate hypotheses but never establish an obligation (requirement 10) | REI-001B lexical-adversary and double-masking invariance; REI-001's masking counterfactual was never validly run, so name evidence has **no** confirmatory standing |
| The dangerous implementation is never selected because it is dangerous | REI-002 |
| Authority is not an obligation of effect | REI-002 |

### 7.3 `PROVEN_EFFECT` — the exact conjunction

For `EXTERNAL_PERSISTENT_STATE_EFFECT`:

```
IMPLEMENTATION  sufficiently established        (§8.3)
AND ACTIVATION  = SUPPORTED
AND BOUNDARY    = SUPPORTED
AND OPERATION   = SUPPORTED
AND PERSISTENCE = SUPPORTED
AND no unresolved implementation selection capable of changing the conclusion
AND no CONFLICTING state on any necessary obligation
AND every BLOCKING counter-evidence probe executed to completion  (§9)
```

This is REI-002's stated requirement verbatim, plus the counter-evidence clause
that requirement 15 adds for production.

### 7.4 `NO_EFFECT` — closure, defined so it cannot be fudged

`NO_EFFECT` requires a necessary obligation `REFUTED` **under a sufficiently
closed analysed path**. "Sufficiently closed" is the conjunction:

| | Closure condition |
|---|---|
| C1 | No implementation candidate is `OPAQUE_EXTERNAL` or `DYNAMIC_UNRESOLVED` |
| C2 | The refutation holds, by `PROBATIVE` evidence, for **every** candidate |
| C3 | No necessary obligation is `CONFLICTING` |
| C4 | No budget was exhausted on any acquisition path that contributed to the refutation |
| C5 | The dependency-descent frontier relevant to the refuted obligation is empty |
| C6 | No `ERROR` on any necessary obligation |

If any condition fails the verdict is `ABSTAIN`. There is no "probably no
effect". This definition exists because an under-specified `NO_EFFECT` is the
one ambiguity that would force an ontology change after R05/R06: it is the only
verdict that makes a safety claim.

## 8. Implementations — set-valued (requirements 3, 4)

### 8.1 Candidate kinds

| Kind | Meaning |
|---|---|
| `RESOLVED_LOCAL` | body in the scanned workspace |
| `RESOLVED_DEPENDENCY_SOURCE` | body in pinned dependency source (ladder L5) |
| `CONTRACT_DECLARED` | declaration/interface/contract without a body (L2/L6) |
| `OPAQUE_EXTERNAL` | a real callee with package identity but no obtainable body or contract |
| `DYNAMIC_UNRESOLVED` | reflection, computed member access, runtime registry |
| `TEST_DOUBLE` | a mock/stub/fake injected at this site |

`OPAQUE_EXTERNAL` is a **first-class candidate, not an error**. This single
decision is what allows a claim to exist for an SDK Actenon has never seen.

### 8.2 Separate evidence packets

Each candidate owns its packet set. Packets are never merged across candidates,
and divergence between candidates is **not** a contradiction — REI-002:
*alternative implementations remained separate evidence packets*. Contradiction
is intra-candidate only (§6 of [proof_obligations.md](proof_obligations.md)).

### 8.3 Selection states

| State | Meaning | `IMPLEMENTATION` obligation |
|---|---|---|
| `SINGLE_ESTABLISHED` | exactly one admissible candidate | `SUPPORTED` |
| `AGREEMENT_INVARIANT` | several candidates, identical values on all other necessary obligations | `SUPPORTED` |
| `UNRESOLVED_DIVERGENT` | several candidates that disagree on a necessary obligation | `UNKNOWN` |
| `SELECTION_ERROR` | resolution failed | `ERROR` |

"Sufficiently established" = `SINGLE_ESTABLISHED` or `AGREEMENT_INVARIANT`.
`AGREEMENT_INVARIANT` is what makes the architecture usable without resolving
every polymorphic call: if all three candidates mutate external persistent
state, which one runs does not change the verdict. Selection is **never**
performed by severity, by danger, by name plausibility, or by recency.

## 9. Counter-evidence before `PROVEN_EFFECT` (requirement 15)

A frozen, closed probe registry per obligation. Each probe is `BLOCKING` or
`ADVISORY`. `PROVEN_EFFECT` requires every `BLOCKING` probe to have been
**executed to completion** — not merely to have found nothing. A blocking probe
that cannot complete within budget yields `ABSTAIN`.

Illustrative `PERSISTENCE` probes (full registry:
[proof_obligations.md](proof_obligations.md) §7): guaranteed rollback or
transaction abort; dry-run / validate-only / plan-only parameter; in-memory or
emulator implementation; test-double injection at the site; feature flag
defaulting closed; documented no-op on the observed argument shape.

The asymmetry is deliberate. Establishing an effect requires actively looking
for the reasons it might not hold; refuting one does not require looking for
reasons it might.

## 10. Coverage ledger — first class (requirement 17)

The ledger is a required output whenever the analysis runs, in every format. It
reports, at minimum: capabilities discovered; invocations enumerated; claims
instantiated; claims investigated; verdict distribution; per-obligation state
distribution; ladder tier reached histogram; budget-exhaustion counts;
unresolved-reason histogram; descent frontier size; analysis errors; and the
literal statement that uninvestigated and abstained claims are **not** negative
results.

> **"0 `PROVEN_EFFECT`" is never rendered as "safe", "clean", or "no effects".**
> It is rendered together with the abstention count, the uninvestigated count
> and the frontier size, or it is not rendered at all.

Schema: [coverage_ledger.schema.json](coverage_ledger.schema.json). This
promotes AREF-001's D-13 from a counter pair to a first-class artefact, and it
is the only instrument that distinguishes "this repository has no external
persistent effects" from "we could not open a single dependency".

## 11. Effect classes (requirements 18, 19)

### 11.1 The obligation algebra is frozen; the class registry is extensible

An effect class declares which obligations from the shared vocabulary are
**necessary** for it, plus any class-specific obligations. The verdict function
is generic over that declaration. Adding a class adds a row; it does not change
the ontology.

### 11.2 v1 populates exactly one class

```
EXTERNAL_PERSISTENT_STATE_EFFECT
  necessary: IMPLEMENTATION, ACTIVATION, BOUNDARY, OPERATION, PERSISTENCE
```

### 11.3 Future classes must not be forced into persistence

Registered as **declared but unpopulated** in
[architecture_manifest.json](architecture_manifest.json), each with the
obligation set it will need and an explicit note that `PERSISTENCE` is *not*
among them:

| Planned class | Necessary obligations (indicative) | `PERSISTENCE`? |
|---|---|---|
| `MESSAGE_EMISSION_EFFECT` | IMPLEMENTATION, ACTIVATION, BOUNDARY, OPERATION, DELIVERY_ATTEMPT | no |
| `VALUE_TRANSFER_EFFECT` (payments) | IMPLEMENTATION, ACTIVATION, BOUNDARY, OPERATION, SETTLEMENT | no |
| `CODE_EXECUTION_EFFECT` | IMPLEMENTATION, ACTIVATION, EXECUTION_SEMANTICS | no |
| `DEPLOYMENT_EFFECT` | IMPLEMENTATION, ACTIVATION, BOUNDARY, OPERATION, ROLLOUT_SCOPE | no |
| `PERMISSION_CHANGE_EFFECT` | IMPLEMENTATION, ACTIVATION, BOUNDARY, OPERATION, POLICY_SCOPE | maybe, per instance |
| `SECRET_DISCLOSURE_EFFECT` | IMPLEMENTATION, ACTIVATION, BOUNDARY, DISCLOSURE_SINK | no |
| `DEVICE_ACTION_EFFECT` | IMPLEMENTATION, ACTIVATION, BOUNDARY, ACTUATION | no |
| `PACKET_CAPTURE_EFFECT` | IMPLEMENTATION, ACTIVATION, CAPTURE_SCOPE | no |
| `PHYSICAL_ACTION_EFFECT` | IMPLEMENTATION, ACTIVATION, BOUNDARY, ACTUATION, IRREVERSIBILITY | no |

None is implemented in v1, and none of their obligations may be used by the
v1 verdict function. They are frozen here so that the algebra is visibly
sufficient for them — a message send is not a persistent-state mutation, and an
architecture that could only express it as one would be wrong.

## 12. Known sink rules become evidence sources (requirement 11)

Sink rules keep exactly one job: supplying evidence packets. They do not decide
whether an effect exists, cannot instantiate a claim, and cannot block one.

Admissibility is determined by the rule's **own match type**, using the taxonomy
already in `actenon_scan/rules/default_rules.json`:

| Rule match type | Anchored on | Admissibility as evidence |
|---|---|---|
| `qualified_call`, `attr_call` | a resolved dotted symbol | `PROBATIVE` for `BOUNDARY` and/or `OPERATION`, per the rule's declared mapping |
| `open_write`, `subprocess_deploy`, `github_rest_mutation` | a structural argument pattern | `PROBATIVE`, narrowly, for the obligation the structure witnesses |
| `name_call` | an unqualified function name | `HYPOTHESIS_ONLY` — may raise and prioritise a claim, never establish an obligation |
| `sql_execute_pattern`, `string_pattern` | a regex over text | `HYPOTHESIS_ONLY` for `OPERATION`; the settling evidence is L7 operation semantics |

Two properties follow, and both matter. A rule may **raise** a claim's priority
but not its verdict. And the absence of any matching rule has **no effect
whatsoever** on whether a claim exists — which is the whole correction.

## 13. The critical question, traced

> *Can this architecture create and investigate an `EffectClaim` for an
> unfamiliar high-level SDK call for which Actenon has no existing sink rule?*

**Yes.** The trace, with the rule engine never consulted:

| Step | What happens | Rule involved? |
|---|---|---|
| 1 | A tool handler is discovered as a `CAPABILITY` | no |
| 2 | Every call site in its analysed region is enumerated as an `INVOCATION`, including `await client.zones.settings.edit(...)` | no |
| 3 | Callee resolution yields one candidate: `OPAQUE_EXTERNAL`, carrying package coordinates from L3/L4 | no |
| 4 | Inertness cannot be established (C1 fails on `OPAQUE_EXTERNAL`) | no |
| 5 | `EffectClaim(EPSE)` is **instantiated**; all five obligations `UNKNOWN`; verdict `ABSTAIN` | no |
| 6 | The ladder ascends: L3 package identity → L4 manifest pin → L5 pinned source → the candidate is reclassified `RESOLVED_DEPENDENCY_SOURCE` | no |
| 7 | L5 body yields `BOUNDARY = SUPPORTED` (a real transport dispatch) | no |
| 8 | L6/L7 yield `OPERATION` from the **contract**, not the HTTP verb, and `PERSISTENCE` from commit/lifetime semantics | no |
| 9 | Counter-evidence probes run; if all `BLOCKING` probes complete and find nothing, verdict becomes `PROVEN_EFFECT`; if L5–L7 are unreachable, verdict stays `ABSTAIN` with a named tier and reason | no |

Step 5 is the answer. The claim exists at step 5, before any evidence is
acquired and without any rule. Under AREF-001 there would be no claim at all,
and the R04 H-class failure would be preserved.

**If the answer to this question were `NO`, the architecture would be invalid.**
It is `YES`, and the property is pinned by validation obligation
`AREF-002-V03` ([validation_protocol.md](validation_protocol.md) §9).

## 14. What AREF-002 does not claim

Stated here rather than in a footnote, because the frozen evidence is explicit
about its own limits and an architecture that overstated them would be
unfaithful to it.

Neither REI-001B nor REI-002 established arbitrary SDK understanding,
real-world generalisation, persistence in the wild, authority, successful remote
execution, or complete consequential-effect coverage. REI-001 is **permanently
INCONCLUSIVE**: its mandatory public/member/variable name-masking counterfactual
had zero valid runs because the experimental transformer renamed a JSON schema
key, and it was not repaired after reveal. Consequently **no confirmatory weight
is placed on name-masking invariance from REI-001 anywhere in this freeze**; the
name-independence property rests on REI-001B's package-remasking, second
vocabulary masking and lexical-adversary invariants, all of which passed within
their controlled corpus.

Both passing experiments were controlled-corpus results: REI-001B 30/30 over 30
cases with 165 counterfactual runs; REI-002 36/36 over 36 cases with 126
counterfactual runs. Controlled-corpus success is the reason to attempt a
real-world freeze — it is not evidence of real-world effectiveness. That is
what R05/R06 will test, and the protocol is preregistered in
[validation_protocol.md](validation_protocol.md) before any repository has been
selected, inspected or identified.

## 15. Artefacts

| File | Contents |
|---|---|
| [AREF-002.md](AREF-002.md) | this document — the architecture freeze |
| [proof_obligations.md](proof_obligations.md) | the five obligations, states, verdict function, contradiction rules, counter-evidence registry |
| [evidence_acquisition.md](evidence_acquisition.md) | the nine-tier ladder, admissibility, evidence fidelity |
| [dependency_descent.md](dependency_descent.md) | bounded descent, budgets, frontier, determinism |
| [aref_001_delta.md](aref_001_delta.md) | every AREF-001 decision: KEEP / MODIFY / REJECT / DEFER |
| [validation_protocol.md](validation_protocol.md) | the preregistered R05/R06 protocol |
| [implementation_plan.md](implementation_plan.md) | slice plan — specified, not executed |
| [REPORT.md](REPORT.md) | final report, the ten questions, the recommendation |
| `effect_claim.schema.json` | the central domain object |
| `effect_receipt.schema.json` | the eleven-answer receipt |
| `evidence.schema.json` | evidence and counter-evidence packets |
| `coverage_ledger.schema.json` | the coverage ledger |
| `architecture_manifest.json` | machine-readable vocabularies, classes, budgets, ladder |
| `architecture_manifest.schema.json` | schema for the above |
| `examples/` | positive and negative schema instances |
| `validate.py` | schema, cross-document and manifest validator |
| `MANIFEST.json` / `MANIFEST.sha256` | SHA-256 inventory |
