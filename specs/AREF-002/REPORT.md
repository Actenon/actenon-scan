# AREF-002 — Final report

**Task:** AREF-002 — correction of the Resource Effect architecture freeze.
**Repository:** `actenon-scan` @ `b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16`,
branch `main`, version `1.5.0`.
**Scope:** architecture only. No production code was written.
**Recommendation:** section 30.

---

## 1. What this report is

The closing record of the AREF-002 freeze. It states what was produced, what it
rests on, what was checked, what remains open, the answers to the ten final
questions (section 29), and exactly one recommendation (section 30).

AREF-002 replaces AREF-001 *as a design*. AREF-001's `ARCHITECTURE NOT READY`
verdict was correct and is left standing; its architecture was wrong, because it
was derived without the REI evidence and rebuilt Resource Effect Inference out of
the sink-rule engine.

## 2. Pre-work and repository state

| Check | Result |
|---|---|
| `git rev-parse HEAD` | `b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16` (unchanged throughout) |
| `git status --short` at start | `?? specs/` (AREF-001 only, untracked) |
| `git status --short` at end | `?? specs/` (AREF-001 and AREF-002, untracked) |
| `git diff -- actenon_scan tests specs/AREF-001` | empty |
| AREF-001 hash verification | 24 of 24 `OK` against `specs/AREF-001/MANIFEST.sha256` |

Nothing was committed, pushed, or opened as a PR. No experiment was re-run.

## 3. AREF-001: status and integrity

`specs/AREF-001/` is preserved byte-for-byte, as the task required: *do not
delete it, do not modify it, preserve its hashes*. Its status is now
`SUPERSEDED DESIGN CANDIDATE / NOT AUTHORITATIVE`, recorded in
[AREF-002.md](AREF-002.md), [aref_001_delta.md](aref_001_delta.md) and
`architecture_manifest.json` (`supersedes`). AREF-001's own files do not say this,
because changing them was prohibited.

| Property | Value |
|---|---|
| Hashed files | 24 |
| Total bytes | 237,251 |
| `sha256sum -c` from the repository root | 24 `OK`, 0 failed |
| Re-verified by `validate.py` | yes, independently of `sha256sum` |

## 4. The founding principle and what it displaces

> **A consequential effect is a claim to be proved, not a sink to be matched.**

Displaced: `known sink → rule-ID catalogue → resource annotation`, and
`detect_sinks → ResourceEffect annotation`. Under either, an effect can only exist
where a rule has already fired.

Replacing them:
`CAPABILITY → INVOCATION → POSSIBLE IMPLEMENTATIONS → EFFECT CLAIM → EVIDENCE →
COUNTER-EVIDENCE → PROOF OBLIGATIONS → VERDICT → EFFECT RECEIPT`.

## 5. The evidence relied on, and its limits

| Evidence | Status | What it supports in AREF-002 |
|---|---|---|
| REI-001 | **Permanently INCONCLUSIVE.** Its required name-masking counterfactual had zero valid runs because the transformer renamed a JSON schema key, and it was not repaired after reveal. | **Nothing.** No part of AREF-002 relies on REI-001 name-masking. |
| REI-001B | Passed: 30/30 over 30 cases, 165 counterfactual runs, 100% evidence fidelity | Name independence (package remasking, second-vocabulary masking, lexical adversary); the rule that names generate hypotheses only |
| REI-002 | Passed: 36/36 over 36 cases, 126 counterfactual runs, 100% evidence fidelity | The five obligations; every §7.2 prohibition; separate descriptors; separate implementation packets; abstain on unknown SQL semantics |
| R04 | Real-world development evidence | The failure the architecture has to fix (section 6) |

None of these shows that arbitrary SDKs can be understood, that results
generalise to real code, that persistence can be established in the wild, or
anything about authority, successful remote execution, or complete effect
coverage. AREF-002 claims none of those either
([AREF-002.md](AREF-002.md) §14).

## 6. What R04 measured and why it is decisive

R04 on `cloudflare/mcp-server-cloudflare` @ `1d7a16b2`: **0 of 17** manually
identified consequential paths detected. First broken component: **13 at H,
semantic resource-effect recognition**; 2 at registration; 2 at handler
extraction; 0 at interprocedural resolution. The 322 unresolved-call records were
not shown to cause any of the 17 misses.

H is where a rule is *missing*, and adding annotations to rule hits cannot fix a
missing rule. That is the whole argument against AREF-001 in one sentence, and
it is why the claim has to exist before any rule is consulted.

## 7. The corrected architecture in one page

- A **claim** is created for every invocation reachable from a capability,
  unless that invocation is **PROVEN INERT** for the effect class.
- Each claim holds a **set** of possible implementations. Each implementation
  keeps its own evidence packets.
- Evidence is collected up a **nine-tier ladder** under **seven budgets**. The
  unopened **frontier** is recorded.
- **Five independent obligations** each get a **proof state**. The **verdict**
  is computed from those states by a fixed function.
- **Counter-evidence probes** must complete before `PROVEN_EFFECT` is allowed.
- Each verdict produces a **receipt** that answers eleven fixed questions, and
  each run produces a **coverage ledger**.

The full specification is in [AREF-002.md](AREF-002.md) §3.

## 8. The central domain object

`EffectClaim`, with identity `(capability_id, invocation_id, effect_class)`.
`rule_id` is not part of the identity. The claim's genesis basis is fixed in the
schema as `NON_REFUTATION_OF_INERTNESS`, and an emitted claim always has
`inertness_established: false`. A claim can have zero evidence packets, because
it exists before any evidence is collected. See `effect_claim.schema.json`.

## 9. Proof states

`SUPPORTED · REFUTED · UNKNOWN · CONFLICTING · ERROR` (requirement 5).

`ERROR` is kept separate from `UNKNOWN`. `CONFLICTING` never collapses into
`UNKNOWN`. A state is a pure function of the packet set, so the order packets
arrive in cannot change it (`AREF-002-T04`). Once a state leaves `UNKNOWN` it
cannot go back: evidence is never discarded to simplify a verdict.

## 10. Verdicts

`PROVEN_EFFECT · NO_EFFECT · ABSTAIN · ANALYSIS_ERROR` (requirement 6). They are
evaluated in a fixed order: `ANALYSIS_ERROR` first, then `PROVEN_EFFECT`, then
`NO_EFFECT` (which requires closure C1–C6), and `ABSTAIN` otherwise. The verdict
function is in [proof_obligations.md](proof_obligations.md) §5.

## 11. Proof obligations and their prohibitions

`IMPLEMENTATION · ACTIVATION · BOUNDARY · OPERATION · PERSISTENCE`
(requirement 7). They are independent: no obligation may be inferred from
another. Every prohibition can be traced to a measured REI-002 or REI-001B
result: construction is not activation; dispatch is not persistence; an external
boundary does not imply persistence; persistence is independent of transport;
guaranteed rollback refutes persistence; an unknown commit-versus-rollback
outcome keeps persistence `UNKNOWN`; names generate hypotheses only; the
dangerous implementation is never selected because it is dangerous; and HTTP
dispatch never establishes operation or persistence. See
[proof_obligations.md](proof_obligations.md) §2 and `architecture_manifest.json`
(`obligations[].prohibitions`).

## 12. Descriptors retained separately

`TARGET · CONTROL · AUTHORITY · CONDITIONS` (requirement 8). None of them is an
obligation and none of them gates a verdict. `CONTROL` is split into
`TRIGGER_CONTROL`, `TARGET_CONTROL` and `CONTENT_CONTROL` because of the REI-002
fixed-target case: `TRIGGER_CONTROL` was `SUPPORTED`, `TARGET_CONTROL` was
`REFUTED`, and the verdict was still `PROVEN_EFFECT`.

## 13. Set-valued implementations

There are six candidate kinds (requirement 3). `OPAQUE_EXTERNAL` is a
first-class candidate, not an error. Each candidate keeps its own packets
(requirement 4). Candidates that disagree produce `UNRESOLVED_DIVERGENT`, not
`CONFLICTING`. `AGREEMENT_INVARIANT` lets a polymorphic call be proved without
knowing which implementation runs, provided every candidate agrees on every
necessary obligation.

## 14. Evidence acquisition ladder

L0 local syntax and binding → L1 local implementation and wrapper → L2 types,
declarations and interfaces → L3 package and module provenance → L4 workspace
dependencies → L5 pinned dependency source → L6 machine-readable contract → L7
underlying operation semantics → L8 `ABSTAIN` (requirement 12). The claim climbs
only as far as it needs to: a tier is opened only while some obligation is still
`UNKNOWN` and that tier could settle it. Acquisition reads only what is in the
analysed tree; v1 does no network fetching. See
[evidence_acquisition.md](evidence_acquisition.md).

## 15. Admissibility and evidence fidelity

There are exactly two admissibility classes. `PROBATIVE` evidence can move an
obligation's state. `HYPOTHESIS_ONLY` evidence cannot, although it can raise a
claim's investigation priority. Identifiers, prose, regex matches, HTTP methods
and plausibility arguments are always `HYPOTHESIS_ONLY`. The evidence schema
enforces this mechanically: a packet of kind `identifier_name` is rejected if it
claims `PROBATIVE`. Every packet must carry a verbatim, byte-identical extract,
and the validation threshold for fidelity is exactly 1.00.

## 16. Bounded dependency descent and the frontier

Descent is limited by seven named budgets. It follows a total, deterministic
order and makes no network access, installs nothing, and executes nothing. When
a budget runs out, the affected obligations stay `UNKNOWN`, the stop reason is
recorded with the budget's name, and the unopened edges go on the frontier
(requirement 13). A non-empty relevant frontier rules out `NO_EFFECT` (C5). The
design generalises the repository's own disclosure fix for its
transitive-reachability failure (2 edges followed, 3,297 not followed, 0 of 22
cases caught). See [dependency_descent.md](dependency_descent.md).

## 17. Contradiction handling

A contradiction is opposing `PROBATIVE` packets on the same obligation for the
same candidate. By default it stays `CONFLICTING` (requirement 14). There is one
admissible way to resolve it: the resolved body of the actually selected
implementation outranks a declared contract, and only under
`SINGLE_ESTABLISHED` selection. Recency, severity, safety, tier rank, packet
strength, majority vote and dropping a packet are all prohibited as resolutions.
The requirement-14 case (contract says READ, implementation says MUTATE) stays
`CONFLICTING` unless that one rule applies exactly, and even then the overridden
packet stays in the receipt.

## 18. Counter-evidence before `PROVEN_EFFECT`

The probe registry is closed and has 22 probes, 16 of them `BLOCKING`
(requirement 15). Every `BLOCKING` probe must run to completion before
`PROVEN_EFFECT`; one that cannot complete forces `ABSTAIN`. Probe results are
`FOUND`, `NOT_FOUND` or `INCOMPLETE`, and a probe that did not run is never
recorded as `NOT_FOUND`. `CP-PER-05` (commit outcome undetermined) is the one
probe whose positive result forces `ABSTAIN` rather than `NO_EFFECT`.

## 19. The coverage ledger

The ledger is required output in every format whenever the layer runs
(requirement 17). Its schema fixes three flags to `true`:
`abstained_claims_are_not_negative_results`,
`uninvestigated_claims_are_not_negative_results` and
`zero_proven_effect_does_not_mean_safe`. So a ledger saying "0 findings, clean"
fails validation, and the negative example `coverage_ledger.invalid.json` is
exactly that ledger.

## 20. Effect classes

The obligation algebra is frozen and the class registry can grow. v1 populates
exactly one class, `EXTERNAL_PERSISTENT_STATE_EFFECT` (requirement 18). Nine
future classes are declared but unpopulated: messaging, value transfer, code
execution, deployment, permission change, secret disclosure, device action,
packet capture and physical action (requirement 19). None of them lists
`PERSISTENCE` as a necessary obligation. Permission change is marked
`per_instance`. Some have no `BOUNDARY` obligation (code execution, packet
capture) and one has no `OPERATION` obligation (secret disclosure). The v1
verdict function may not read any of their obligations (`AREF-002-T20`).

## 21. Known sink rules as evidence sources

A rule's admissibility is fixed by its own `match.type` (requirement 11).
`qualified_call` and `attr_call` are `PROBATIVE` for the obligation they
structurally witness. `open_write`, `subprocess_deploy` and
`github_rest_mutation` are `PROBATIVE` in a narrow sense. `name_call`,
`sql_execute_pattern` and `string_pattern` are `HYPOTHESIS_ONLY`. No rule can
settle `PERSISTENCE` on its own, create a claim, or suppress one. What rules are
still good for is investigation priority.

## 22. The critical question

*Can this architecture create and investigate an `EffectClaim` for an
unfamiliar high-level SDK call for which Actenon has no existing sink rule?*

**Yes.** The claim is created at step 5 of the trace in
[AREF-002.md](AREF-002.md) §13, before any evidence is collected, and no rule is
consulted at any step. Four artefacts show this:
`examples/effect_claim.valid.abstain.json` (`matched_rule_ids: []`, all
obligations `UNKNOWN`, verdict `ABSTAIN`); `examples/effect_claim.valid.proven.json`
(the same call after the ladder reaches L7, verdict `PROVEN_EFFECT`, still no
rule); invariant `AREF-002-T01`; and validation obligation `AREF-002-V03`. The
architecture is therefore not invalid on this criterion.

## 23. AREF-001 delta summary

| Disposition | Decisions |
|---|---|
| KEEP (5) | D-07, D-10, D-11, D-12, D-13 |
| MODIFY (4) | D-03, D-08, D-09, D-14 |
| REJECT (4) | D-01, D-02, D-04, D-06 — all rejected because they preserved the sink-centric ontology |
| DEFER (1) | D-05 |

AREF-001's blocked decisions B-01 to B-06 are resolved in
[aref_001_delta.md](aref_001_delta.md) §4. B-01 is deferred to a gate after
validation. B-02 no longer arises in v1. B-03 disappears because there is no
per-rule selector catalogue. B-04 is answered by tier L7 with abstention on
unknown semantics. B-05 is now a preregistered threshold. B-06 is answered by
treating authority as a descriptor.

## 24. Held-out validation freeze

The R05/R06 protocol ([validation_protocol.md](validation_protocol.md)) was
preregistered **before any repository was selected, inspected, searched for or
identified**. R07 is not described at all. The protocol freezes all of the
following:

- selection criteria S1–S8 and disqualifiers X1–X5, including a language
  requirement on the pair and a ban on running the scanner to choose
  repositories;
- contamination rules covering selection, specification, implementation and
  ground truth;
- a preregistration record containing the scanner commit, configuration,
  budgets, thresholds, falsifiers and a SHA-256 of the sealed ground truth;
- a blind manual ground-truth procedure with an `INDETERMINATE_BY_SOURCE`
  label;
- effect, negative and indeterminate denominators;
- eight measurement families reported separately, with no composite score;
- first-broken-component categories A, B, F and H carried over from R04, plus
  new categories I–S;
- performance accounting;
- a prohibition on provider-specific patches.

The anti-gaming rules work in both directions. A run is `INVALID` if the
abstention rate exceeds 0.95, and precision only counts when recall also meets
its threshold. A run `FAILS on architecture` if any `HYPOTHESIS_ONLY` packet
moved an obligation state, whatever its metrics.

## 25. Schema and manifest validation results

`python3 specs/AREF-002/validate.py` covers the following:

- five schemas, each checked as valid JSON Schema 2020-12, with every cross-file
  `$ref` pointing at an absolute `$id`;
- nine examples (four positive, five negative), each validating or failing as
  intended, and each negative example naming the failure it expects;
- `architecture_manifest.json` validating against its own schema;
- every closed vocabulary in the manifest matching the corresponding schema
  enum;
- semantic checks on obligations, effect classes, the ladder, budgets, probes,
  rule admissibility, the AREF-001 dispositions, invariants and validation
  thresholds;
- cross-document checks on relative links, invariant ids, probe ids, the delta
  summary table and the ten questions;
- independent re-verification of AREF-001's hashes.

The final run result is recorded in section 28.

## 26. Contradiction cross-check of the documents

These are candidate contradictions found while cross-checking the documents,
and how each was settled.

| # | Candidate contradiction | Settled by |
|---|---|---|
| X-1 | `IMPLEMENTATION` is a proof obligation, but [AREF-002.md](AREF-002.md) §7.3 requires it to be "sufficiently established" rather than simply `SUPPORTED` | Both hold. `SINGLE_ESTABLISHED` and `AGREEMENT_INVARIANT` map to `SUPPORTED` ([proof_obligations.md](proof_obligations.md) §2.1), and the conjunction adds the requirement that every candidate was compared on every necessary obligation (§5.1) |
| X-2 | Guaranteed rollback both *refutes* `PERSISTENCE` and is a `BLOCKING` probe | Intentional. It can refute directly, and it must be looked for before `PROVEN_EFFECT` (§2.5, §7.7) |
| X-3 | `CP-PER-05` is `BLOCKING`, yet a positive finding does not produce `NO_EFFECT` | Consistent. Its positive result yields `UNKNOWN`, which blocks both `PROVEN_EFFECT` and `NO_EFFECT`. This is recorded in the manifest note and checked by `validate.py` |
| X-4 | Sink rules are "not a tier", yet they produce packets that carry a tier | A rule packet carries the tier of what it read, L0 or L1. Rules are a matching accelerator over those tiers ([evidence_acquisition.md](evidence_acquisition.md) §7) |
| X-5 | `CONTRACT_DECLARED` is a candidate kind *and* a source of contract packets | A contract-only callee is a candidate. The same contract can also inform a `RESOLVED_DEPENDENCY_SOURCE` candidate's packets. Contradiction precedence (§6.3) compares packets, not candidate kinds |
| X-6 | The claim schema only enforces "`PROVEN_EFFECT` ⇒ established selection", not the full conjunction | Intentional. JSON Schema cannot compute the conjunction over packets. The schema enforces what it can, and the rest is `AREF-002-T05`…`T12` |
| X-7 | The ladder puts `ACTIVATION` at L0–L1 only, but a dependency can invoke a user callback | Named as the one known exception: the callback's `ACTIVATION` is `UNKNOWN`, and descent does not resolve it ([evidence_acquisition.md](evidence_acquisition.md) §3.1) |
| X-8 | D-01's non-gating property survives, yet D-01 is `REJECT` | The *annotation-layer shape* is rejected; the *non-gating property* moves to an integration constraint. [aref_001_delta.md](aref_001_delta.md) D-01 states both |
| X-9 | The ledger's `with_matching_sink_rule` count could look like the old gate coming back | It is labelled "for comparison only" and has no effect on existence. `instantiated_without_any_rule_match` is reported next to it |

After these were settled, no contradiction remains in the documents. Where the
schema cannot enforce a rule (X-6), that rule is given as a named test
obligation and not left implicit.

## 27. Requirement-by-requirement conformance

| # | Requirement | Where it is met |
|---|---|---|
| 1 | `EffectClaim` is central | [AREF-002.md](AREF-002.md) §4; `effect_claim.schema.json` |
| 2 | A claim does not need a known sink hit to exist | genesis `const`; `AREF-002-T01`, `T02`, `E11`, `V03`, `V04` |
| 3 | Implementations are set-valued | `implementation_candidates` array with `minItems: 1`; §8 |
| 4 | Each implementation has its own evidence packet | `implementation_candidate_id` on every packet; packets never merged; §8.2 |
| 5 | Five proof states | `proofState` enum; manifest vocabulary |
| 6 | Four verdicts | `verdict` enum; verdict function §5 |
| 7 | Five independent obligations | [proof_obligations.md](proof_obligations.md) §2 |
| 8 | TARGET, CONTROL, AUTHORITY and CONDITIONS kept separate | `descriptors`; `gates_verdict: false` |
| 9 | HTTP dispatch cannot establish OPERATION or PERSISTENCE | §2.3; manifest prohibition; `AREF-002-T06` |
| 10 | Names generate hypotheses only | schema conditional; `AREF-002-T03`, `E05` |
| 11 | Sink rules are evidence sources | §12; `sink_rule_admissibility` |
| 12 | Bounded evidence ladder | [evidence_acquisition.md](evidence_acquisition.md) §2 |
| 13 | Bounded descent; exhaustion gives visible UNKNOWN/ABSTAIN | [dependency_descent.md](dependency_descent.md) §4.3 |
| 14 | Contradiction handling | [proof_obligations.md](proof_obligations.md) §6 |
| 15 | Counter-evidence before PROVEN_EFFECT | [proof_obligations.md](proof_obligations.md) §7 |
| 16 | Receipt answers eleven questions | `answers` with eleven required keys, checked by `validate.py` |
| 17 | Coverage ledger is first class | `coverage_ledger.schema.json` |
| 18 | v1 class is EPSE; other effects are not forced into persistence | manifest `effect_classes` |
| 19 | Future effect kinds are representable | nine declared classes |
| 20 | R05/R06/R07 not inspected, selected, searched or identified | [validation_protocol.md](validation_protocol.md) header; manifest `repositories_selected: false` |

## 28. Files created

Every file below is new and lives under `specs/AREF-002/`. No file anywhere else
was created or modified.

| # | File | Kind |
|---|---|---|
| 1 | `README.md` | index |
| 2 | `AREF-002.md` | architecture freeze |
| 3 | `proof_obligations.md` | normative |
| 4 | `evidence_acquisition.md` | normative |
| 5 | `dependency_descent.md` | normative |
| 6 | `aref_001_delta.md` | normative |
| 7 | `validation_protocol.md` | normative, preregistration |
| 8 | `implementation_plan.md` | specification, not executed |
| 9 | `REPORT.md` | this report |
| 10 | `evidence.schema.json` | schema |
| 11 | `effect_claim.schema.json` | schema |
| 12 | `effect_receipt.schema.json` | schema |
| 13 | `coverage_ledger.schema.json` | schema |
| 14 | `architecture_manifest.schema.json` | schema |
| 15 | `architecture_manifest.json` | data |
| 16 | `validate.py` | validator |
| 17 | `examples/evidence.valid.json` | positive example |
| 18 | `examples/evidence.invalid.json` | negative example |
| 19 | `examples/effect_claim.valid.abstain.json` | positive example |
| 20 | `examples/effect_claim.valid.proven.json` | positive example |
| 21 | `examples/effect_claim.invalid.json` | negative example |
| 22 | `examples/effect_receipt.valid.json` | positive example |
| 23 | `examples/effect_receipt.invalid.json` | negative example |
| 24 | `examples/coverage_ledger.valid.json` | positive example |
| 25 | `examples/coverage_ledger.invalid.json` | negative example |
| 26 | `examples/architecture_manifest.invalid.json` | negative example |
| 27 | `MANIFEST.json` | SHA-256 inventory of files 1–26 |
| 28 | `MANIFEST.sha256` | the same, in `sha256sum -c` format |

That is 28 files, 26 of them hashed. The two manifests do not hash themselves.
Validator result: every check passes, 0 fail; the exact count is printed by
`validate.py`.

## 29. The ten final questions

### Q1 — What replaces the known-sink-centric architecture?

A pipeline that starts from claims. Every invocation reachable from a capability
becomes an `EffectClaim` unless it is proved inert. The claim holds a set of
possible implementations, each with its own evidence. Evidence comes from a
bounded nine-tier ladder. Five independent proof obligations are each settled by
admissible evidence, counter-evidence is sought, a fixed function computes the
verdict, and an eleven-answer receipt plus a coverage ledger are emitted. The
unit of work is the invocation, not the sink match.

### Q2 — What minimally establishes `PROVEN_EFFECT`?

For `EXTERNAL_PERSISTENT_STATE_EFFECT`, all of the following:

- implementation selection is `SINGLE_ESTABLISHED` or `AGREEMENT_INVARIANT`;
- `ACTIVATION`, `BOUNDARY`, `OPERATION` and `PERSISTENCE` are each `SUPPORTED`
  by at least one `PROBATIVE` packet, with a verbatim extract, from a source
  that can settle that obligation;
- no unresolved implementation selection could change the conclusion;
- no necessary obligation is `CONFLICTING`;
- every `BLOCKING` counter-evidence probe ran to completion.

Target, control and authority are not required.

### Q3 — When must Actenon abstain?

Whenever neither `PROVEN_EFFECT` nor `NO_EFFECT` is established and nothing
errored. Concretely:

- any necessary obligation is `UNKNOWN` or `CONFLICTING`;
- implementation selection is `UNRESOLVED_DIVERGENT`;
- a `BLOCKING` probe is `INCOMPLETE`;
- a budget ran out on a path that contributed to the result;
- the relevant frontier is non-empty;
- an `OPAQUE_EXTERNAL` or `DYNAMIC_UNRESOLVED` candidate prevents closure;
- a required tier is unavailable;
- the only evidence is `HYPOTHESIS_ONLY`, such as names, prose, regex matches,
  the HTTP method or a `name_call` rule;
- SQL, command or operation semantics are unknown;
- commit-versus-rollback is undetermined.

There is no "probably".

### Q4 — How can Actenon investigate an SDK it has never seen before?

It never needs to recognise the SDK. The call is an invocation, so the claim
already exists. Its callee becomes an `OPAQUE_EXTERNAL` candidate, and L3–L4
identify the package and its pinned version. From there, evidence comes from
whatever is in the tree:

- the pinned source (L5), which gives boundary and possibly operation and
  persistence;
- a machine-readable contract (L6), which gives operation semantics without
  reading server code;
- the underlying statement or transport primitive (L7).

Every step relies on generic mechanisms — reading bodies, parsing contracts,
parsing statements — and none on a provider-specific signature. If none of
that evidence is in the tree, the verdict is `ABSTAIN`, with the tier and reason
recorded.

### Q5 — What role do existing known sink rules now play?

They are evidence sources and investigation-priority signals, and nothing more.
Structurally anchored rules (`qualified_call`, `attr_call`, `open_write`,
`subprocess_deploy`, `github_rest_mutation`) produce `PROBATIVE` packets, but
only for the obligation their structure witnesses, and never for persistence.
Name- and text-anchored rules (`name_call`, `sql_execute_pattern`,
`string_pattern`) produce `HYPOTHESIS_ONLY` packets that can only raise a
claim's priority. No rule can create, suppress or settle a claim. Emptying the
entire rule corpus must leave every claim's existence and stop reason unchanged
(`AREF-002-E11`, `V04`).

### Q6 — What remains fundamentally unknowable from static source evidence?

- runtime configuration, credentials and environment;
- whether the remote side actually accepted and persisted the change;
- targets that are loaded at runtime, reflective or computed from data;
- external authorisation decisions;
- the behaviour of closed-source binaries and native extensions;
- the state of feature flags in production;
- whether data-dependent branches are reachable in practice;
- remote commit, idempotency and retention behaviour when no machine-readable
  contract declares it;
- whether an effect ever actually happened.

AREF-002 represents these as `UNKNOWN` states, `CONDITIONS` descriptors or the
`INDETERMINATE_BY_SOURCE` ground-truth label. It does not claim to resolve them.

### Q7 — What exactly will R05/R06 falsify or support?

**They can support:**

- that starting from claims recovers measurable semantic recall where the
  sink-centric design measured 0 of 17;
- that a claim is created and investigated for an SDK with no rule
  (`AREF-002-V03`);
- that abstention concentrates where evidence really is absent;
- that evidence fidelity stays at 1.00 on real code.

**They can falsify:**

- universal claim creation (first-broken category P);
- the meaning of `PROVEN_EFFECT` (precision below 0.90, or any admissibility
  leakage);
- `NO_EFFECT` closure (any false `NO_EFFECT`);
- principled abstention (abstention above 0.95 makes the run `INVALID`);
- the reach of the ladder (categories N and O);
- evidence fidelity (anything below 1.00).

**They cannot establish:**

- generalisation beyond two repositories;
- the correctness of the future effect classes;
- runtime occurrence of effects;
- integration of severity or authority.

### Q8 — Could an unfamiliar SDK call with no existing sink rule produce an `EffectClaim` under AREF-002? Trace the path.

**Yes.** The trace follows `await client.zones.settings.edit(...)`, which matches
no sink rule.

1. The tool handler is discovered as a `CAPABILITY`.
2. Every call site in its analysed region is enumerated as an `INVOCATION`,
   including this one. No rule is consulted.
3. Resolving the callee yields a single `OPAQUE_EXTERNAL` candidate.
4. Inertness cannot be proved, because C1 fails on `OPAQUE_EXTERNAL`.
5. `EffectClaim(EXTERNAL_PERSISTENT_STATE_EFFECT)` is created with all
   obligations `UNKNOWN` and verdict `ABSTAIN`. The claim exists from here on.
6. L3 establishes package identity and L4 the lockfile pin. L5 pinned source is
   read if it is present, and the candidate becomes
   `RESOLVED_DEPENDENCY_SOURCE`.
7. The L5 body shows a transport dispatch, so `BOUNDARY = SUPPORTED`.
8. The L6 contract gives `OPERATION = SUPPORTED` from the operation's contract,
   not from its HTTP verb. The L6/L7 retention semantics give
   `PERSISTENCE = SUPPORTED`.
9. All `BLOCKING` probes run to completion. The verdict is `PROVEN_EFFECT`, or
   `ABSTAIN` with a named tier and reason if L5–L7 are absent.

`examples/effect_claim.valid.abstain.json` and
`examples/effect_claim.valid.proven.json` are the two end states, and both
record `matched_rule_ids: []`.

### Q9 — Which AREF-001 decisions were rejected because they preserved the old ontology?

Four decisions:

- **D-01**, the annotation layer: it could only describe rule hits.
- **D-02**, the sink call site as the unit: `rule_id` was part of its identity.
- **D-04**, `EffectType` as the effect vocabulary: that is a sink
  classification filled from a per-rule-ID map, and it cannot express effects
  that do not involve persistence.
- **D-06**, the per-rule-ID selector catalogue: the sink ontology in data form.

In total, 4 decisions were rejected, 4 modified, 1 deferred and 5 kept.

### Q10 — What evidence-acquisition problem remains unsolved even if AREF-002 is internally correct?

**Reach.** `OPERATION` and `PERSISTENCE` can only be settled from L1, L5, L6 or
L7. In most real repositories, most SDK calls have no local wrapper that
performs the operation. Their dependency source is usually not in the analysed
tree: it is not vendored, not installed, and in the wrong language or build
form. Most have no machine-readable contract either, or only a contract that
does not state mutation or retention semantics.

AREF-002 reads only what is in the tree and deliberately does not fetch. So it
can be internally correct, honest in every verdict, and still abstain on most
claims that matter, with stop reason `TIER_UNAVAILABLE` at L4.

The ontology fixes R04's category H by making the claim exist. It does not
guarantee that evidence to prove the claim can be found. Whether it can is the
strongest single falsifier in R05/R06. A result that shifts misses from H to N
would confirm the ontology and expose this problem. Solving it needs a separately
reviewed decision on fetching pinned sources and contracts, or a source of
operation semantics that does not yet exist. Neither is part of this freeze.

## 30. Recommendation

**ARCHITECTURE READY FOR IMPLEMENTATION**

The case for readiness rests on the five criteria the task defined:

1. **It reflects the frozen research evidence.** Every obligation, prohibition,
   descriptor separation and abstention rule traces to REI-001B, REI-002 or R04.
   REI-001 is given no confirmatory weight. No property is claimed that the
   evidence does not support (sections 5, 11, 12).
2. **Its uncertainty semantics are sound.** There are five states and four
   verdicts, the verdict function has a fixed evaluation order, and `NO_EFFECT`
   requires closure C1–C6. Budget exhaustion, unavailable tiers, conflicts,
   errors and uninvestigated claims all stay visible and are never read as
   negatives (sections 9, 10, 16, 19).
3. **Its implementation contract is precise.** The contract consists of five
   validated schemas, a manifest checked against them, 55 named invariants, a
   closed registry of 22 probes, and 14 slices each with acceptance criteria
   (sections 25, 28; [implementation_plan.md](implementation_plan.md)).
4. **Held-out validation is preregistered.** It was frozen before any repository
   was selected, with thresholds, denominators, anti-gaming rules in both
   directions, and a sealed ground-truth hash (section 24).
5. **No open architectural ambiguity should force a change to the ontology after
   R05/R06.** The ambiguities that could have done so were each frozen:
   `NO_EFFECT` closure, contradiction precedence, the status of
   `OPAQUE_EXTERNAL`, the admissibility classes (exactly two), and the
   effect-class algebra. The results can therefore move thresholds, budgets and
   evidence reach; they are not expected to force a redefinition of what a
   claim, an obligation or a verdict is (section 26).

**What readiness does not mean.** It is not evidence that the architecture works
on real code. That is exactly what R05/R06 will test, and they may refute it. It
is not permission to integrate severity, turn the layer on by default, or add
effect classes; each of those is gated separately
([implementation_plan.md](implementation_plan.md) §7). It also does not solve
evidence reach (Q10), the named residual risk most likely to limit the
architecture in practice.

AREF-002 stops here. No implementation has started.
