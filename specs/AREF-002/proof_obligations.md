# AREF-002 — Proof obligations, proof states, verdict function, contradictions, counter-evidence

**Status:** frozen. Normative. Part of the AREF-002 architecture freeze.
**Parent:** [AREF-002.md](AREF-002.md)

This document is the complete specification of how an `EffectClaim` acquires a
verdict. It freezes: the obligations (§2), the descriptors that are deliberately
*not* obligations (§3), the proof-state semantics (§4), the verdict function
(§5), contradiction handling (§6), the counter-evidence probe registry (§7), and
the invariants an implementation must be tested against (§8).

---

## 1. Scope and the one-sentence rule

Every rule below is a consequence of one sentence: **an effect is a claim to be
proved, not a sink to be matched.** Therefore each obligation is phrased as a
*question about the world*, answerable in principle for code Actenon has never
seen, and never as *"does a rule match?"*.

Two framing rules apply throughout.

**Framing rule 1 — obligations are independent.** No obligation may be inferred
from another. The implementation may not compute `PERSISTENCE` from `BOUNDARY`,
may not compute `OPERATION` from transport, and may not compute `ACTIVATION`
from the fact that an object was constructed. Independence is not a stylistic
preference: each of those three inferences is individually prohibited by a
measured REI-002 result (§2.7).

**Framing rule 2 — obligations are settled only by admissible evidence.** An
obligation moves off `UNKNOWN` only when an evidence packet whose admissibility
is `PROBATIVE` targets it. Everything else — names, plausibility, rule-ID
folklore, severity, the analyst's expectation — is `HYPOTHESIS_ONLY` and cannot
move a state. See [evidence_acquisition.md](evidence_acquisition.md) §5.

---

## 2. The five obligations

The obligation vocabulary is frozen and closed for v1:

```
IMPLEMENTATION · ACTIVATION · BOUNDARY · OPERATION · PERSISTENCE
```

For `EXTERNAL_PERSISTENT_STATE_EFFECT` (EPSE) all five are **necessary**. Other
effect classes declare their own necessary subset plus class-specific
obligations ([AREF-002.md](AREF-002.md) §11); the machinery in §4–§7 is generic
over that declaration.

### 2.1 `IMPLEMENTATION` — *which code actually runs?*

Settled by the implementation candidate set and its selection state
([AREF-002.md](AREF-002.md) §8.3):

| Selection state | `IMPLEMENTATION` |
|---|---|
| `SINGLE_ESTABLISHED` | `SUPPORTED` |
| `AGREEMENT_INVARIANT` | `SUPPORTED` |
| `UNRESOLVED_DIVERGENT` | `UNKNOWN` |
| `SELECTION_ERROR` | `ERROR` |

**Cannot settle it:** the name of the callee; the name of the variable it is
called on; the presence of a sink rule; the danger of one candidate relative to
another. *The dangerous implementation is never selected because it is
dangerous.*

`IMPLEMENTATION` is the only obligation that is never `REFUTED`. There is no
such thing as "proved that no code runs" at an enumerated call site; the
absence of a callee is `SELECTION_ERROR` or a non-call, not a refutation.

### 2.2 `ACTIVATION` — *is this invocation executed when the capability runs?*

`SUPPORTED` requires positive evidence that the invocation lies on an execution
path from the capability entry under conditions that are not statically
excluded. `REFUTED` requires positive evidence that it cannot execute
(unreachable branch under a statically decidable condition; code in a
`__main__`-guarded region never entered by the capability; a literal
`if False`).

**Cannot settle it:**

- **Construction is not activation.** `client = Foo()` at module scope, or a
  builder chain that never terminates in a call, does not activate anything.
  REI-002 measured this distinction directly.
- **Import is not activation.**
- **A rule match is not activation.** A sink rule firing says nothing about
  whether the line runs.

Conditional execution is not refutation. A guarded invocation is
`ACTIVATION = SUPPORTED` with the guard recorded as a `CONDITIONS` descriptor
(§3.4). Collapsing "runs only if X" into "does not run" is prohibited.

### 2.3 `BOUNDARY` — *does the effect leave the analysed state into an external system?*

`SUPPORTED` requires evidence of a real egress mechanism: a network transport
dispatch, a filesystem write handle, a database driver execution, a subprocess
spawn, an IPC or device write. `REFUTED` requires evidence that the operation
terminates inside process state (a pure in-memory structure; a local cache with
no backing store; an emulator or in-memory driver).

**Cannot settle:** `BOUNDARY = SUPPORTED` does **not** establish `OPERATION`
and does **not** establish `PERSISTENCE` (requirement 9). This is the single
most important prohibition in the document and the one AREF-001 structurally
violated by mapping a rule ID straight to an effect. REI-002's decisive
observation: **every carrier used POST**, and an identical-source pair changed
classification solely because the *operation contract* differed. Transport is
therefore evidence of egress only.

### 2.4 `OPERATION` — *is the operation contract a mutation rather than an observation?*

`SUPPORTED` requires evidence about the semantics of the operation being
requested, from a source that actually defines those semantics: a
machine-readable API contract (L6); the underlying SQL / document-store /
command / transport-level operation the call reduces to (L7); or the resolved
implementation body that performs it (L1/L5).

`REFUTED` requires the same class of evidence establishing that the operation is
an observation (a read, a list, a get, a describe — *as established by the
contract, not by the verb in the identifier*).

**Cannot settle it:**

- **The HTTP method.** POST is not mutation evidence. REI-002 is explicit.
- **The identifier.** `deleteEverything` is `HYPOTHESIS_ONLY`; `get_thing` that
  issues `UPDATE` is a mutation. Names generate hypotheses (requirement 10).
- **A `name_call`, `sql_execute_pattern` or `string_pattern` rule hit.** These
  are text/identifier anchored and are `HYPOTHESIS_ONLY` for `OPERATION`
  ([AREF-002.md](AREF-002.md) §12).
- **Unknown SQL/command semantics.** REI-002's own conclusion for an
  unrecognised statement is *abstain*: the state stays `UNKNOWN`. Guessing from
  a keyword prefix is prohibited.

### 2.5 `PERSISTENCE` — *does the mutation outlive the request?*

`SUPPORTED` requires evidence of durable commitment: an explicit commit; a
driver whose default is autocommit *as established by the driver's own
source/contract, not assumed*; a write to durable storage with no rollback
path; a remote contract that documents the change as retained.

`REFUTED` requires evidence of guaranteed non-durability: a guaranteed rollback
or transaction abort on every path; an in-memory or ephemeral backing store; a
documented no-op; a dry-run/validate-only mode that is unconditional at this
site.

**Cannot settle it:**

- **Dispatch is not persistence.** Sending a request does not establish that the
  remote side retained anything.
- **External boundary does not imply persistence.**
- **Transport does not imply persistence** — persistence is independent of
  transport.
- **Unknown commit-versus-rollback preserves uncertainty.** If it cannot be
  determined whether the surrounding transaction commits, `PERSISTENCE` is
  `UNKNOWN`. It is never `SUPPORTED` by default and never `SUPPORTED` "because
  most code commits".

Guaranteed rollback is the canonical `REFUTED` case and is also a `BLOCKING`
counter-evidence probe (§7.5). Both roles are intentional: it can refute the
obligation directly, and it must be *looked for* before `PROVEN_EFFECT`.

### 2.6 Independence, restated as a prohibition table

| Forbidden inference | Because |
|---|---|
| `BOUNDARY` ⟹ `OPERATION` | REI-002: every carrier used POST; classification changed with the operation contract alone |
| `BOUNDARY` ⟹ `PERSISTENCE` | REI-002: external boundary does not imply persistence |
| transport kind ⟹ `PERSISTENCE` | REI-002: persistence is independent of transport |
| dispatch ⟹ `PERSISTENCE` | REI-002: dispatch is not persistence |
| construction ⟹ `ACTIVATION` | REI-002: construction is not activation |
| identifier text ⟹ any obligation | requirement 10; REI-001B lexical-adversary invariance |
| rule-ID presence ⟹ any obligation `SUPPORTED` | requirement 11; a rule is an evidence source, not an ontology |
| rule-ID absence ⟹ any obligation `REFUTED` | requirement 2; absence of a rule is absence of evidence |
| `OPERATION` `UNKNOWN` ⟹ `PERSISTENCE` `UNKNOWN` | independence: they may be settled by different tiers and one may be refuted while the other is unknown |

### 2.7 Provenance of §2

Every prohibition above is traceable to a frozen measured result, not to
architectural taste. The mapping is in the table in
[AREF-002.md](AREF-002.md) §7.2 and is re-stated in machine-readable form in
[architecture_manifest.json](architecture_manifest.json)
(`obligations[].prohibitions`).

---

## 3. Retained separately — never obligations (requirement 8)

`TARGET`, `CONTROL`, `AUTHORITY`, `CONDITIONS` are **descriptors**. They are
recorded on the claim, reported in the receipt, and may modulate priority,
severity presentation and triage. They are **not** in the `PROVEN_EFFECT`
conjunction, and a missing or refuted descriptor never blocks a verdict.

REI-002 is the reason this is a hard rule rather than a convention: a
fixed-target effect was still `PROVEN_EFFECT` with `TRIGGER_CONTROL =
SUPPORTED` and `TARGET_CONTROL = REFUTED`. Any design that folded target
controllability into the conjunction would contradict a measured result.

### 3.1 `TARGET`

What external resource the effect acts on: a coordinate set (transport, host or
service identity, container/namespace, object identity) each field carrying its
own resolution state (`resolved`, `heuristic`, `unresolved`). A fully
`unresolved` target does not weaken the verdict; it weakens the *receipt's*
answer to "what resource?", which is reported honestly as unknown.

### 3.2 `CONTROL`

Three independent sub-descriptors, each carrying a `ProofState`:

| Sub-descriptor | Question |
|---|---|
| `TRIGGER_CONTROL` | can the model cause the invocation to happen? |
| `TARGET_CONTROL` | can the model choose the resource acted on? |
| `CONTENT_CONTROL` | can the model choose the written content? |

They are kept separate because they have different consequences and because
REI-002 measured a case where they disagreed. Control is **not** taint reused
under a new name; it is a claim-level summary that an implementation may derive
from the existing `TaintLattice` but must report per sub-descriptor.

### 3.3 `AUTHORITY`

Who or what authorised the effect (a checked permission, an approved decision,
a human confirmation). *Authority is not an obligation of effect* — REI-002. A
fully authorised effect is still an effect; an unauthorised read is still not an
effect. Conflating the two is how a scanner ends up reporting policy violations
as effects and effects as policy violations.

### 3.4 `CONDITIONS`

The guards, flags, environment predicates and branch conditions under which the
invocation executes. Recorded, never used to refute `ACTIVATION` (§2.2). A
feature flag that defaults closed *is* an `ADVISORY` counter-evidence probe
(§7.2) — it appears in the receipt and in triage, and it does not by itself
produce `NO_EFFECT`.

---

## 4. Proof states

### 4.1 The closed vocabulary

```
SUPPORTED · REFUTED · UNKNOWN · CONFLICTING · ERROR
```

### 4.2 Assignment rules

Let `P⁺(o, c)` be the set of `PROBATIVE` packets of positive polarity targeting
obligation `o` for implementation candidate `c`, and `P⁻(o, c)` the negative
set. `HYPOTHESIS_ONLY` packets are excluded from both by construction.

| Condition | State of `o` for `c` |
|---|---|
| acquisition for `o` raised an internal error | `ERROR` |
| `P⁺ ≠ ∅` and `P⁻ ≠ ∅` and no admissible precedence rule applies (§6) | `CONFLICTING` |
| `P⁺ ≠ ∅` and `P⁻ ≠ ∅` and precedence resolves to positive | `SUPPORTED` |
| `P⁺ ≠ ∅` and `P⁻ ≠ ∅` and precedence resolves to negative | `REFUTED` |
| `P⁺ ≠ ∅`, `P⁻ = ∅` | `SUPPORTED` |
| `P⁻ ≠ ∅`, `P⁺ = ∅` | `REFUTED` |
| both empty | `UNKNOWN` |

`ERROR` takes precedence over all other rows. An obligation that errored is not
also reported as `UNKNOWN`: the two mean different things and the coverage
ledger counts them separately.

### 4.3 Aggregation across candidates

Per-candidate states are aggregated to the claim only through the selection
state (§2.1 and [AREF-002.md](AREF-002.md) §8.3):

- `SINGLE_ESTABLISHED` — the single candidate's states are the claim's states.
- `AGREEMENT_INVARIANT` — all candidates share identical states on every
  necessary obligation; those states are the claim's states.
- `UNRESOLVED_DIVERGENT` — every necessary obligation on which the candidates
  disagree becomes `UNKNOWN` at claim level. It does **not** become
  `CONFLICTING`: inter-candidate divergence is not a contradiction (§6.5).
- `SELECTION_ERROR` — `IMPLEMENTATION` is `ERROR`; other obligations keep their
  per-candidate aggregate but cannot support `PROVEN_EFFECT`.

### 4.4 Monotonicity and re-entrancy

Within a single analysis run, a state may move from `UNKNOWN` to any other state
as the ladder ascends, and from `SUPPORTED`/`REFUTED` to `CONFLICTING` when
opposing probative evidence arrives. A state must **never** move from
`CONFLICTING` to `SUPPORTED` or `REFUTED` except by an admissible precedence
rule in §6, and must never move from `SUPPORTED`/`REFUTED`/`CONFLICTING` back to
`UNKNOWN` — evidence is not discarded to simplify a verdict.

An obligation state is a pure function of the packet set plus the precedence
rules. It must not depend on packet arrival order. This is testable and is
obligation `AREF-002-T04` (§8).

---

## 5. The verdict function

### 5.1 Definition

Given effect class `E` with necessary obligation set `N(E)`, claim `K`, and its
aggregated states `S(o)` for `o ∈ N(E)`:

```
verdict(K, E):

  # 1. errors first — an analysis failure must never masquerade as a result
  if ∃ o ∈ N(E) : S(o) = ERROR
      return ANALYSIS_ERROR

  # 2. proof of effect
  if  implementation_sufficiently_established(K)
  and ∀ o ∈ N(E) : S(o) = SUPPORTED
  and no unresolved implementation selection can change the conclusion
  and ∄ o ∈ N(E) : S(o) = CONFLICTING
  and every BLOCKING counter-evidence probe for E executed to completion
      return PROVEN_EFFECT

  # 3. proof of no effect — closure required (C1..C6)
  if  ∃ o ∈ N(E) : S(o) = REFUTED
  and closure_established(K, o)
      return NO_EFFECT

  # 4. everything else
  return ABSTAIN
```

`implementation_sufficiently_established(K)` is
`selection_state ∈ {SINGLE_ESTABLISHED, AGREEMENT_INVARIANT}`, which by §2.1
also means `S(IMPLEMENTATION) = SUPPORTED`; it is written separately in the
conjunction because it additionally forbids `AGREEMENT_INVARIANT` being claimed
without having compared every candidate on every necessary obligation.

### 5.2 Ordering is normative

The four blocks are evaluated in the order written. `ANALYSIS_ERROR` outranks
everything: a run that broke may not emit `NO_EFFECT`. `PROVEN_EFFECT` is
checked before `NO_EFFECT` only so that a contradictory claim cannot satisfy
both — it cannot, since `PROVEN_EFFECT` forbids `CONFLICTING` and requires all
`SUPPORTED`, while `NO_EFFECT` requires a `REFUTED`; the orderings are disjoint
by construction and the explicit order removes any implementation freedom.

### 5.3 `closure_established` — C1…C6

Restated normatively from [AREF-002.md](AREF-002.md) §7.4. For refuted
obligation `o`:

| | Condition | Rationale |
|---|---|---|
| C1 | no candidate is `OPAQUE_EXTERNAL` or `DYNAMIC_UNRESOLVED` | you cannot prove a negative about code you never obtained |
| C2 | the refutation holds by `PROBATIVE` evidence for **every** candidate | one inert candidate does not make the site inert |
| C3 | no necessary obligation is `CONFLICTING` | a contradiction is not a clean negative |
| C4 | no budget was exhausted on an acquisition path contributing to the refutation | a truncated search is not a closed one |
| C5 | the dependency-descent frontier relevant to `o` is empty | see [dependency_descent.md](dependency_descent.md) §6 |
| C6 | no necessary obligation is `ERROR` | redundant with §5.1 block 1, retained so that closure is self-contained |

If any fails: `ABSTAIN`. **There is no "probably no effect".**

### 5.4 Why `ABSTAIN` is the default and not a failure

`ABSTAIN` is the honest verdict for the overwhelming majority of invocations in
any real repository, and the architecture is designed so that this is visible
rather than silently rendered as safety. An `ABSTAIN` claim must always carry:
the highest ladder tier reached, the reason acquisition stopped, the frontier it
did not open, and which obligations remain `UNKNOWN`/`CONFLICTING`. An
`ABSTAIN` without those fields is an invalid output, not a lenient one.

### 5.5 What the verdict is not

The verdict is not a severity, not a `CapabilityState`, and not a gate on
existing Actenon findings. Whether and how verdicts influence reporting is an
integration decision deferred to [implementation_plan.md](implementation_plan.md)
§7 and gated on R05/R06.

---

## 6. Contradiction handling (requirement 14)

### 6.1 What a contradiction is

Two `PROBATIVE` evidence packets of opposing polarity targeting **the same
obligation** for **the same implementation candidate**.

The worked case from requirement 14: a machine-readable contract (L6) declares
the operation a READ, and the resolved implementation body (L5) performs a
MUTATE. `OPERATION` has `P⁺ ≠ ∅` and `P⁻ ≠ ∅`.

### 6.2 The default is `CONFLICTING` and it persists

Absent an admissible precedence rule, the state is `CONFLICTING`, the verdict is
`ABSTAIN` (a `CONFLICTING` necessary obligation blocks `PROVEN_EFFECT` by §5.1
and blocks `NO_EFFECT` by C3), and both packets are reported in the receipt with
their verbatim extracts.

### 6.3 The one admissible precedence rule

> **Resolved-implementation precedence.** A `PROBATIVE` packet derived from the
> resolved source of the **actually selected** implementation outranks a
> `CONTRACT_DECLARED` packet for the same obligation — **only when
> `S(IMPLEMENTATION) = SUPPORTED` via `SINGLE_ESTABLISHED`, and the resolved
> source is the body of that single established candidate.**

Rationale: what runs is what runs. A contract that disagrees with the code it
purports to describe is a documentation defect, and the code is the operative
evidence — but only when we actually know that this code is what executes. If
selection is `AGREEMENT_INVARIANT`, `UNRESOLVED_DIVERGENT` or `SELECTION_ERROR`,
the precedence rule does **not** apply and `CONFLICTING` stands. Under
`AGREEMENT_INVARIANT` we know the candidates agree on the obligation values, not
which body is authoritative over a contract.

When the rule applies, the state becomes that of the resolved-source packet, the
resolution is recorded as
`contradiction_resolution = "RESOLVED_IMPLEMENTATION_PRECEDENCE"`, and the
overridden packet remains in the receipt. A resolution is never silent.

### 6.4 Prohibited resolutions

| Prohibited | Why |
|---|---|
| recency ("the newer doc wins") | not evidence about execution |
| severity ("the more dangerous reading wins") | manufactures effects; the mirror of REI-002's *the dangerous implementation is never selected because it is dangerous* |
| safety ("the safer reading wins") | manufactures false assurance, which the repository's own stance calls worse than a reviewable false positive |
| tier number alone ("higher tier wins") | L6 is not automatically better than L5, nor the reverse; only §6.3's execution-grounded rule is admissible |
| packet `strength` | `strength` is presentational and prioritisational only (§6.7) |
| majority vote | two weak reads do not outvote one probative mutate |
| dropping one packet | evidence is never discarded to obtain a verdict |

### 6.5 Inter-candidate divergence is not a contradiction

If candidate A's body mutates and candidate B's body reads, that is not a
contradiction — it is `UNRESOLVED_DIVERGENT` selection, handled by §4.3, and the
claim-level obligation is `UNKNOWN`. REI-002: *alternative implementations
remained separate evidence packets.* Merging them into a contradiction would
destroy that separation and would make a polymorphic site indistinguishable from
a mis-documented one.

### 6.6 Counter-evidence is not automatically a contradiction

A counter-evidence probe that *finds* something produces a normal negative-
polarity packet, and the §4.2 rules then apply: if it is `PROBATIVE` and
positive probative evidence exists, the state becomes `CONFLICTING`; if it is
`PROBATIVE` and there is none, the state becomes `REFUTED`; if it is
`HYPOTHESIS_ONLY` it is recorded and reported and moves nothing.

### 6.7 `strength` versus admissibility

`admissibility ∈ {PROBATIVE, HYPOTHESIS_ONLY}` decides whether a packet can move
a state — and nothing else does. `strength` is an ordinal annotation used for
receipt presentation and investigation prioritisation. **`strength` never
affects a state transition and never resolves a contradiction.** The two-value
admissibility vocabulary is deliberate: a third, intermediate class would create
exactly the kind of unresolved architectural ambiguity that readiness forbids.

---

## 7. Counter-evidence probe registry (requirement 15)

### 7.1 The rule

Before a claim may reach `PROVEN_EFFECT`, every `BLOCKING` probe for the
class's necessary obligations must have been **executed to completion**.
"Completion" means the probe ran its defined search over the available evidence
tiers and returned a definite found/not-found result. A probe that could not
complete — budget exhausted, tier unreachable, file unreadable — yields
`ABSTAIN`, recorded as `blocking_probe_incomplete` with the probe id.

The asymmetry is intentional and stated in [AREF-002.md](AREF-002.md) §9:
establishing an effect requires actively searching for reasons it might not
hold; refuting one does not require searching for reasons it might.

### 7.2 Probe classes

- **`BLOCKING`** — must complete before `PROVEN_EFFECT`. Chosen because a
  positive finding would plausibly flip a necessary obligation.
- **`ADVISORY`** — recorded and reported; does not gate the verdict. Chosen
  because a positive finding changes triage priority, not the truth of the
  effect.

The registry is **closed for v1**: an implementation may not add probes without
amending this document, and may not silently skip one.

### 7.3 `IMPLEMENTATION` probes

| id | Probe | Class |
|---|---|---|
| `CP-IMPL-01` | Is a test double / mock / stub / fake injected at this site or by the enclosing fixture? | `BLOCKING` |
| `CP-IMPL-02` | Is the callee monkey-patched, re-assigned or shadowed before this site? | `BLOCKING` |
| `CP-IMPL-03` | Is the resolved symbol a re-export or alias whose ultimate target differs? | `ADVISORY` |
| `CP-IMPL-04` | Is the site inside a type-checking-only block (`if TYPE_CHECKING`, ambient declaration)? | `BLOCKING` |

### 7.4 `ACTIVATION` probes

| id | Probe | Class |
|---|---|---|
| `CP-ACT-01` | Is the enclosing function dead — never referenced, never registered, never exported? | `BLOCKING` |
| `CP-ACT-02` | Is the site statically unreachable (literal false condition, code after unconditional raise/return)? | `BLOCKING` |
| `CP-ACT-03` | Is the site in test-only, example-only, fixture or generated-sample code? | `ADVISORY` |
| `CP-ACT-04` | Is the site behind a feature flag whose default is closed? | `ADVISORY` |

`CP-ACT-03` and `CP-ACT-04` are advisory on purpose. Test code and closed flags
are triage facts; treating either as refutation is how real effects get
suppressed by a file path.

### 7.5 `BOUNDARY` probes

| id | Probe | Class |
|---|---|---|
| `CP-BND-01` | Is the transport/driver an in-memory, emulator, fake or local-stub implementation? | `BLOCKING` |
| `CP-BND-02` | Is egress unconditionally disabled at this site (offline mode, `dry_run` transport, null sink)? | `BLOCKING` |
| `CP-BND-03` | Does the write terminate in a process-local buffer that is never flushed on any path? | `BLOCKING` |
| `CP-BND-04` | Is the destination a loopback or ephemeral test endpoint? | `ADVISORY` |

### 7.6 `OPERATION` probes

| id | Probe | Class |
|---|---|---|
| `CP-OPR-01` | Does the machine-readable contract (L6) classify this operation as an observation? | `BLOCKING` |
| `CP-OPR-02` | Does the underlying statement/command (L7) reduce to a read (`SELECT`, `find`, `describe`, `GET`-semantics)? | `BLOCKING` |
| `CP-OPR-03` | Is a `dry_run` / `validate_only` / `plan_only` / `preview` parameter passed at this site? | `BLOCKING` |
| `CP-OPR-04` | Is the mutation semantics conditional on an argument not resolvable at this site? | `ADVISORY` |

`CP-OPR-01` and `CP-OPR-02` are the probes that make `OPERATION` contract-driven
rather than verb-driven. They are also the probes most likely to be
*incomplete*, because L6/L7 evidence is frequently unavailable — which is the
honest reason this architecture will abstain often
([REPORT.md](REPORT.md) Q10).

### 7.7 `PERSISTENCE` probes

| id | Probe | Class |
|---|---|---|
| `CP-PER-01` | Is rollback or transaction abort guaranteed on every path from this site? | `BLOCKING` |
| `CP-PER-02` | Is a dry-run / validate-only / plan-only mode in force? | `BLOCKING` |
| `CP-PER-03` | Is the backing store in-memory, ephemeral, a temporary file removed on exit, or an emulator? | `BLOCKING` |
| `CP-PER-04` | Is the operation documented as a no-op for the observed argument shape? | `BLOCKING` |
| `CP-PER-05` | Is the commit-versus-rollback outcome undetermined at this site? | `BLOCKING` |
| `CP-PER-06` | Is the written state subject to a documented TTL shorter than the request lifetime? | `ADVISORY` |

`CP-PER-05` deserves comment: it is `BLOCKING` and a *positive* finding does not
refute persistence — it forces `PERSISTENCE = UNKNOWN`, because *unknown
commit-versus-rollback preserves uncertainty* (REI-002). This is the one probe
whose positive result yields `ABSTAIN` rather than `NO_EFFECT`, and it is the
architecture's main defence against the "it dispatched, therefore it persisted"
error.

### 7.8 What probes may not do

A probe may not consult a rule ID to decide whether to run. A probe may not be
skipped because a claim "looks obvious". A probe's non-execution may not be
recorded as a not-found result — the receipt distinguishes
`found` / `not_found` / `incomplete`, and `incomplete` on a `BLOCKING` probe
forces `ABSTAIN`.

---

## 8. Invariants and test obligations

Each invariant is stated so that it can be written as an executable test before
the corresponding production code exists. Ids are referenced from
[implementation_plan.md](implementation_plan.md) and
[validation_protocol.md](validation_protocol.md).

| Id | Invariant |
|---|---|
| `AREF-002-T01` | An invocation with zero matching sink rules and a single `OPAQUE_EXTERNAL` candidate instantiates an `EffectClaim` with all necessary obligations `UNKNOWN` and verdict `ABSTAIN`. |
| `AREF-002-T02` | Injecting or removing every sink rule changes no claim's *existence*; it may change only evidence packets and priority. |
| `AREF-002-T03` | A `HYPOTHESIS_ONLY` packet — including every `name_call`, `string_pattern` and `sql_execute_pattern` derived packet — never changes an obligation state. |
| `AREF-002-T04` | Obligation states are invariant under permutation of packet arrival order. |
| `AREF-002-T05` | `BOUNDARY = SUPPORTED` with `OPERATION = UNKNOWN` never yields `PROVEN_EFFECT`. |
| `AREF-002-T06` | An HTTP POST dispatch with no contract or operation-semantics evidence yields `OPERATION = UNKNOWN` and `PERSISTENCE = UNKNOWN`. |
| `AREF-002-T07` | Identical source differing only in the operation contract yields different `OPERATION` states (the REI-002 discrimination property). |
| `AREF-002-T08` | Guaranteed rollback on all paths yields `PERSISTENCE = REFUTED`; and `NO_EFFECT` only if C1–C6 hold. |
| `AREF-002-T09` | Undetermined commit yields `PERSISTENCE = UNKNOWN` and verdict `ABSTAIN`, never `SUPPORTED`. |
| `AREF-002-T10` | Contract-says-READ versus body-says-MUTATE yields `CONFLICTING` unless §6.3 applies exactly; when it applies, the overridden packet is still present in the receipt. |
| `AREF-002-T11` | Inter-candidate divergence yields `UNRESOLVED_DIVERGENT` and claim-level `UNKNOWN`, never `CONFLICTING`. |
| `AREF-002-T12` | A `BLOCKING` probe that cannot complete forces `ABSTAIN` even when all five obligations are otherwise `SUPPORTED`. |
| `AREF-002-T13` | `TARGET_CONTROL = REFUTED` with `TRIGGER_CONTROL = SUPPORTED` does not prevent `PROVEN_EFFECT` (the REI-002 fixed-target case). |
| `AREF-002-T14` | `AUTHORITY` present or absent never changes a verdict. |
| `AREF-002-T15` | Budget exhaustion on a contributing path forces `ABSTAIN`, never `NO_EFFECT`. |
| `AREF-002-T16` | `ERROR` on a necessary obligation yields `ANALYSIS_ERROR`, and the claim is not counted as a negative anywhere in the ledger. |
| `AREF-002-T17` | Every emitted `ABSTAIN` carries a highest-tier-reached, a stop reason, an unresolved-obligation list and a frontier size. |
| `AREF-002-T18` | Every emitted verdict has a schema-valid `EffectReceipt` whose `answers` object contains all eleven required keys. |
| `AREF-002-T19` | A run producing zero `PROVEN_EFFECT` emits a coverage ledger, and no output path renders that as "safe", "clean" or "no effects". |
| `AREF-002-T20` | No v1 verdict computation reads an obligation belonging only to a declared-unpopulated future effect class. |
