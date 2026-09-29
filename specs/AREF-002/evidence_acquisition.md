# AREF-002 — Evidence acquisition ladder, admissibility, evidence fidelity

**Status:** frozen. Normative. Part of the AREF-002 architecture freeze.
**Parent:** [AREF-002.md](AREF-002.md)
**Companion:** [dependency_descent.md](dependency_descent.md) (how tiers L4–L7 are
reached under budget), [proof_obligations.md](proof_obligations.md) (what the
acquired evidence is allowed to settle).

This document freezes the bounded evidence acquisition ladder required by
requirement 12, the structure of an evidence packet, the two-value admissibility
vocabulary (§5), and the evidence-fidelity rule (§6).

---

## 1. The acquisition principle

An `EffectClaim` exists before any evidence is acquired
([AREF-002.md](AREF-002.md) §4.2). Acquisition therefore never decides whether a
claim exists; it decides only **how much of the claim can be settled**, and it
must make its own limits visible.

Three rules govern the whole ladder.

1. **Bounded.** Every tier has a cost and every run has a budget
   ([dependency_descent.md](dependency_descent.md) §4). The ladder terminates.
2. **Visible.** The highest tier reached, the reason acquisition stopped, and
   the frontier left unopened are recorded on every claim and aggregated in the
   coverage ledger. A claim that stopped at L3 says so.
3. **Honest.** Exhaustion produces `UNKNOWN` obligations and an `ABSTAIN`
   verdict. It never produces a guess, an assumption, a default, or a
   "probably". This is requirement 13 and it is the rule most likely to be
   eroded under pressure to show findings.

---

## 2. The ladder

Nine tiers. L0–L7 are evidence sources; **L8 is a terminal state, not a source**.
Tier numbers denote *acquisition cost and distance from the call site*, not
authority. A higher tier is not automatically better evidence — see §5.4.

| Tier | Name | What it yields |
|---|---|---|
| L0 | `LOCAL_SYNTAX_BINDING` | the call site itself: callee expression, argument shapes, literals, local bindings, enclosing control flow, guards, the capability path to the site |
| L1 | `LOCAL_IMPLEMENTATION_WRAPPER` | bodies of functions/methods defined in the scanned workspace, including the wrapper chain the site calls through |
| L2 | `TYPES_DECLARATIONS_INTERFACES` | type annotations, stubs, `.d.ts`, interfaces, protocols, abstract methods, ambient declarations — declarations without bodies |
| L3 | `PACKAGE_MODULE_PROVENANCE` | which external package/module the callee belongs to, and the import path that identifies it |
| L4 | `WORKSPACE_DEPENDENCIES` | dependency manifests and lockfiles: the declared and pinned version of that package in *this* workspace |
| L5 | `PINNED_DEPENDENCY_SOURCE` | the actual source of the pinned dependency, when vendored or otherwise obtainable within budget |
| L6 | `MACHINE_READABLE_CONTRACT` | OpenAPI/Swagger, JSON Schema, protobuf/gRPC service definitions, GraphQL SDL, SDK-shipped operation metadata, CLI/command specifications |
| L7 | `UNDERLYING_OPERATION_SEMANTICS` | the SQL statement, document-store operation, shell command, transport-level operation or driver primitive the call reduces to |
| L8 | `ABSTAIN` | terminal. No further admissible evidence is obtainable within budget. |

### 2.1 L0 — local syntax and binding

Always available; cost effectively zero. Yields the invocation's existence
(hence the claim), the argument shape, and the syntactic guards feeding the
`CONDITIONS` descriptor.

What L0 can settle: `ACTIVATION` in the narrow static cases (`if False`, code
after an unconditional `raise`), and `CP-OPR-03`-style argument findings
(`dry_run=True` as a literal).

What L0 cannot settle: `OPERATION` and `PERSISTENCE` — the call site text does
not define the semantics of the operation. `BOUNDARY` only when the site *is* the
egress primitive (a literal `open(path, "w")`, a `subprocess` spawn), not when it
merely looks like one.

### 2.2 L1 — local implementation and wrapper chain

The single highest-value tier in practice, because most repositories wrap their
SDK calls. Following `self._write(...)` into a local method that calls
`self._table.put_item(...)` converts an unanalysable site into an analysable one
at negligible cost.

What L1 can settle: `IMPLEMENTATION` (to `RESOLVED_LOCAL`), and any obligation
the local body itself witnesses. Wrapper traversal is descent and is budgeted
([dependency_descent.md](dependency_descent.md) §3.1).

### 2.3 L2 — types, declarations, interfaces

Yields the callee's *declared* shape without a body. Its role is to narrow the
implementation candidate set and to supply `CONTRACT_DECLARED` candidates.

What L2 can settle: `IMPLEMENTATION` narrowing; `BOUNDARY` when a declaration
unambiguously names a transport or driver type. It **cannot** settle `OPERATION`
from a method name in an interface — that is a name, and names are
`HYPOTHESIS_ONLY` (requirement 10). A declaration whose *docstring or
annotation* states mutation semantics is L2-sourced `CONTRACT_DECLARED` evidence
and is `PROBATIVE` only when it is a structured contract rather than prose; prose
documentation is `HYPOTHESIS_ONLY` (§5.3).

### 2.4 L3 — package and module provenance

Establishes package identity for the callee. Does **not** establish any
obligation on its own: knowing a call is `boto3` does not establish boundary,
operation or persistence for *this* call.

Its architectural job is to make `OPAQUE_EXTERNAL` candidates *identified* rather
than anonymous, which is what makes L4–L7 addressable at all. A provider-name
lookup table at L3 that asserts effects would be a provider-specific signature
and is prohibited (requirement 20 / the STRICT RULES).

### 2.5 L4 — workspace dependencies

Manifests and lockfiles (`pyproject.toml`, `requirements*.txt`, `uv.lock`,
`poetry.lock`, `package.json`, `package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`, `go.mod`, `go.sum`). Yields the *pinned* identity — the specific
version whose semantics we would be reasoning about.

Pinning matters for reproducibility: an obligation settled from dependency source
is only meaningful if the receipt names the version it read. An unpinned
dependency caps admissible descent ([dependency_descent.md](dependency_descent.md)
§5.3).

### 2.6 L5 — pinned dependency source

The body of the external callee, when obtainable: vendored trees, a workspace
virtual environment present in the scanned tree, `node_modules`, a Go module
cache, a monorepo sibling. This is where an unfamiliar SDK becomes analysable and
the candidate is reclassified `RESOLVED_DEPENDENCY_SOURCE`.

**Acquisition is strictly local.** AREF-002 freezes no network fetch: the
architecture reads what is present in the analysed tree. Whether a future slice
may fetch pinned source is deferred
([implementation_plan.md](implementation_plan.md) §7) and is out of scope for
v1. This is a deliberate limitation, and it is the largest single cause of the
abstention risk named in [REPORT.md](REPORT.md) Q10.

### 2.7 L6 — machine-readable contracts

The tier that makes `OPERATION` determinable for remote APIs without reading
server code. A contract that declares an operation's effect semantics is
`PROBATIVE` for `OPERATION`, and may be `PROBATIVE` for `PERSISTENCE` when it
declares retention or idempotency/commit semantics.

**Machine-readable is required.** Prose documentation, README text and marketing
descriptions are `HYPOTHESIS_ONLY`. The distinction is not pedantry: a structured
contract can be parsed deterministically and quoted verbatim; prose invites the
analyser to infer what it already expected.

### 2.8 L7 — underlying operation semantics

The deepest admissible tier: the operation the call actually reduces to. A
`cursor.execute(q)` reduces to an SQL statement; a `collection.update_one`
reduces to a document-store mutation; a `subprocess.run([...])` reduces to a
command invocation; an SDK method reduces to a wire-level operation.

L7 is where `OPERATION` and `PERSISTENCE` are most often genuinely settled, and
it carries the ladder's sharpest prohibition: **an unrecognised statement,
command or operation yields `UNKNOWN`, not a guess.** REI-002's own conclusion
for unknown SQL semantics is to abstain. Keyword-prefix inference
(`"starts with DELETE"`) on a statement that could not be parsed is prohibited;
a *parsed* statement whose root operation is `DELETE` is legitimate L7 evidence.

### 2.9 L8 — `ABSTAIN`

Terminal. Reached when no tier below can be advanced within budget. It produces
no packets. Reaching L8 with `UNKNOWN` obligations is the correct, expected
outcome for most claims and must be reported as coverage, never as absence of
effect ([AREF-002.md](AREF-002.md) §10).

---

## 3. Traversal

### 3.1 Order

Ascending tier order, cheapest first, so that a claim settled at L1 never pays
L5 cost. Traversal is **demand-driven per obligation**: a claim ascends only
while at least one necessary obligation is `UNKNOWN` and at least one unopened
tier could settle it.

Which tiers can settle which obligations — a claim does not ascend for an
obligation no higher tier can address:

| Obligation | Tiers that may settle it |
|---|---|
| `IMPLEMENTATION` | L0, L1, L2, L3, L4, L5 |
| `ACTIVATION` | L0, L1 |
| `BOUNDARY` | L0, L1, L2, L5, L6, L7 |
| `OPERATION` | L1, L5, L6, L7 |
| `PERSISTENCE` | L1, L5, L6, L7 |

`ACTIVATION` is intentionally shallow: whether a call runs is a property of the
analysed workspace, not of a dependency's internals. A dependency that invokes a
user callback is the known exception and is recorded as `UNKNOWN` activation for
the callback, not resolved by descent.

### 3.2 Stopping conditions

Acquisition stops for a claim when any holds, and the reason is recorded:

| Stop reason | Meaning |
|---|---|
| `SETTLED` | every necessary obligation is `SUPPORTED`, `REFUTED` or `CONFLICTING` |
| `NO_FURTHER_TIER` | no unopened tier can address any remaining `UNKNOWN` obligation |
| `TIER_UNAVAILABLE` | the next tier's artefact is absent (no lockfile, no vendored source, no contract) |
| `BUDGET_EXHAUSTED` | a budget in [dependency_descent.md](dependency_descent.md) §4 was hit |
| `ACQUISITION_ERROR` | a read or parse failed |
| `CLAIM_NOT_INVESTIGATED` | the claim was instantiated but never scheduled |

`TIER_UNAVAILABLE` and `BUDGET_EXHAUSTED` are distinguished because they have
different remedies: the first is a property of the analysed repository, the
second of our configuration. Conflating them would make the coverage ledger
uninterpretable — and interpreting them is precisely what R05/R06's
first-broken-component analysis requires
([validation_protocol.md](validation_protocol.md) §7).

### 3.3 Determinism

For a fixed workspace, configuration and budget, the acquired packet set and the
stop reason must be identical across runs. Ordering within a tier follows the
deterministic rules in [dependency_descent.md](dependency_descent.md) §3.3. A
non-deterministic ladder cannot be preregistered, and an un-preregisterable
architecture cannot be validated.

---

## 4. Evidence packets

### 4.1 Required fields

Schema: `evidence.schema.json`.

| Field | Meaning |
|---|---|
| `packet_id` | stable identifier within the claim |
| `tier` | `L0`…`L7` (never `L8`) |
| `kind` | the acquisition mechanism (e.g. `local_call_site`, `local_function_body`, `type_declaration`, `dependency_manifest`, `dependency_source_body`, `openapi_operation`, `sql_statement`, `sink_rule_match`) |
| `locator` | where it came from: path, line span, and for dependency/contract evidence the package name and pinned version |
| `assertion` | the claim the packet makes, as a structured statement |
| `polarity` | `POSITIVE` or `NEGATIVE` with respect to the targeted obligation |
| `obligation` | the single obligation targeted |
| `implementation_candidate_id` | the candidate this packet pertains to |
| `admissibility` | `PROBATIVE` or `HYPOTHESIS_ONLY` (§5) |
| `strength` | ordinal, presentational and prioritisational only |
| `acquisition_cost` | tier plus a hop/bytes accounting, for budget reconciliation |
| `extract` | the **verbatim** source text the assertion rests on (§6) |

### 4.2 One packet, one obligation, one candidate

A packet targets exactly one obligation for exactly one implementation
candidate. Evidence that bears on two obligations produces two packets with the
same extract. This keeps §4.2 of [proof_obligations.md](proof_obligations.md)
computable and prevents a single "it's a database write" packet from silently
settling boundary, operation and persistence at once — which is precisely the
conflation AREF-001's rule-ID-to-effect map performed.

### 4.3 Counter-evidence packets

Counter-evidence is not a separate type. A probe (§7 of
[proof_obligations.md](proof_obligations.md)) produces ordinary packets, normally
`NEGATIVE`, plus a probe outcome record (`found` / `not_found` / `incomplete`).
The probe outcome is what gates `PROVEN_EFFECT`; the packet is what moves state.

---

## 5. Admissibility

### 5.1 Two classes, and only two

| Class | Power |
|---|---|
| `PROBATIVE` | may move an obligation from `UNKNOWN` to `SUPPORTED`/`REFUTED`, and may create `CONFLICTING` |
| `HYPOTHESIS_ONLY` | may instantiate nothing, settle nothing, refute nothing; may raise a claim's investigation priority and may trigger a counter-evidence search |

There is no third class. A middle tier ("weakly probative") would reintroduce
exactly the ambiguity that lets a name-derived signal drift into a verdict, and
it would make the anti-gaming criteria in
[validation_protocol.md](validation_protocol.md) §8 unmeasurable.

### 5.2 What is `PROBATIVE`

Evidence is `PROBATIVE` for an obligation when it is **structural or
contractual and it addresses that obligation directly**:

- L0/L1 structural facts about the site or a resolved local body
- L2 declarations that name a type whose semantics are defined, not inferred
- L5 resolved dependency bodies
- L6 machine-readable contracts
- L7 parsed underlying operations
- structurally anchored sink-rule matches, per §7

### 5.3 What is `HYPOTHESIS_ONLY` — exhaustively

| Source | Why |
|---|---|
| any identifier: function, method, variable, parameter, module, file or package **name** | requirement 10; REI-001B lexical-adversary and vocabulary-masking invariance |
| prose documentation, comments, README text | not machine-checkable; invites confirmation of a prior expectation |
| regex matches over source text (`string_pattern`, `sql_execute_pattern`) | text proximity is not semantics |
| unqualified-name rule matches (`name_call`) | the anchor is a bare name |
| HTTP method or status code as operation evidence | REI-002: every carrier used POST |
| plausibility, frequency, "most SDKs do X", provider reputation | not evidence about this code |
| a previous run's verdict | circular |

The first row is load-bearing and is deliberately absolute. Name evidence rests
on **REI-001B** — package remasking, second-vocabulary masking, lexical
adversary — because **REI-001 is permanently INCONCLUSIVE**: its public/member/
variable name-masking counterfactual had zero valid runs after the transformer
renamed a JSON schema key, and was not repaired. No confirmatory weight is
placed on REI-001 anywhere.

### 5.4 Admissibility is not tier rank

A low tier can be `PROBATIVE` (an L0 literal `dry_run=True`) and a high tier can
be `HYPOTHESIS_ONLY` (an L6 contract's prose `description` field). Tier governs
*cost and reach*; admissibility governs *power*. Contradictions are therefore
never resolved by comparing tier numbers
([proof_obligations.md](proof_obligations.md) §6.4).

### 5.5 Admissibility leakage is an architecture failure

If an implementation ever lets a `HYPOTHESIS_ONLY` packet move an obligation
state, that is not a tuning problem to be corrected by a threshold; it is a
violation of the architecture. It is invariant `AREF-002-T03`
([proof_obligations.md](proof_obligations.md) §8) and a declared FAIL condition
of R05/R06 ([validation_protocol.md](validation_protocol.md) §8.4).

---

## 6. Evidence fidelity

### 6.1 The rule

Every packet carries a **verbatim extract** of the source text its assertion
rests on, together with a locator sufficient to retrieve it: path, line span,
and for dependency or contract evidence the package name and pinned version.

The extract must be byte-identical to the analysed source. Paraphrase,
normalisation, reconstruction, truncation without an explicit marker, and
"equivalent" text are all violations.

### 6.2 Why it is frozen as a hard requirement

REI-001B and REI-002 both measured evidence fidelity at **100%** — every cited
line matched the source exactly. That is the property that makes a claim
reviewable by a human who does not trust the analyser, and it is the only
defence against an architecture that reasons correctly but cites the wrong line.
R05/R06 therefore set the threshold at exactly **1.00**: any fidelity failure
fails the run ([validation_protocol.md](validation_protocol.md) §8.3). A
threshold below 1.00 would be a threshold for fabricated evidence.

### 6.3 Extracts for non-source evidence

L4 and L6 evidence is often structured data, not code. The extract is the
verbatim serialised fragment (the manifest line, the contract node), not a
summary of it. Where an extract must be truncated for size it is truncated with
an explicit marker and the locator remains sufficient to retrieve the whole.

---

## 7. Known sink rules as a cross-cutting evidence source (requirement 11)

Sink rules are **not a tier**. They are a pattern-matching accelerator over
L0/L1 that can emit packets. Their admissibility is fixed by each rule's own
`match.type` in `actenon_scan/rules/default_rules.json`:

| `match.type` | Anchor | Admissibility |
|---|---|---|
| `qualified_call`, `attr_call` | resolved dotted symbol | `PROBATIVE` for the obligation(s) the rule's declared mapping witnesses — normally `BOUNDARY`, sometimes `OPERATION` |
| `open_write` | argument-structure witness of a write mode | `PROBATIVE`, narrowly, for `BOUNDARY` |
| `subprocess_deploy` | argument-structure witness of a command shape | `PROBATIVE`, narrowly |
| `github_rest_mutation` | argument-structure witness of a mutating REST shape | `PROBATIVE`, narrowly |
| `name_call` | bare function name | `HYPOTHESIS_ONLY` |
| `sql_execute_pattern`, `string_pattern` | regex over text | `HYPOTHESIS_ONLY` for `OPERATION` |

Three consequences are frozen:

1. **No rule may instantiate a claim.** Claims come from invocations
   ([AREF-002.md](AREF-002.md) §4.2).
2. **No rule may suppress a claim.** Rule absence has no bearing on existence.
3. **A `PROBATIVE` rule packet still only settles the obligation it
   structurally witnesses.** A rule that matches `cursor.execute` witnesses a
   driver boundary; it does not witness that the statement mutates, and it never
   witnesses persistence. AREF-001's `_RULE_ID_TO_EFFECT`-style single mapping
   from rule ID to effect is rejected for exactly this reason
   ([aref_001_delta.md](aref_001_delta.md) D-04, D-06).

A practical note that is part of the freeze: the existing rule corpus is
language-skewed (31 Python sink rule IDs; the TypeScript detector emits 9; the
Go detector emits 9 with a `-GO` suffix, and `effect_for_rule_id` returns `None`
for 8 of those 9 because normalisation strips only `-WEAK`/`-UNBOUND`). Under
AREF-001 that skew would translate directly into missing effects. Under AREF-002
it translates into *lower-priority investigation* of TypeScript and Go claims,
which the coverage ledger reports per language — a visible coverage fact rather
than a silent absence.

---

## 8. Worked traces

### 8.1 Unfamiliar SDK, source available

`await client.zones.settings.edit({...})`, no sink rule matches.

| Tier | Result |
|---|---|
| L0 | invocation enumerated; claim instantiated; candidate `OPAQUE_EXTERNAL`; all obligations `UNKNOWN` |
| L1 | no local body — the callee is not defined in the workspace |
| L2 | `.d.ts` declares the method; candidate gains a `CONTRACT_DECLARED` sibling |
| L3 | package identity established |
| L4 | lockfile pins the version |
| L5 | pinned source present; body resolves a transport dispatch → `BOUNDARY = SUPPORTED`; candidate becomes `RESOLVED_DEPENDENCY_SOURCE` |
| L6 | shipped operation metadata declares the operation a mutation → `OPERATION = SUPPORTED` |
| L7 | the operation's declared retention settles `PERSISTENCE = SUPPORTED` |
| probes | all `BLOCKING` probes complete, none found |
| verdict | `PROVEN_EFFECT` — with no rule involved at any step |

### 8.2 The same SDK, source unavailable

| Tier | Result |
|---|---|
| L0–L4 | as above |
| L5 | `TIER_UNAVAILABLE` — dependency not vendored, no local environment |
| L6 | `TIER_UNAVAILABLE` — no contract in the tree |
| verdict | `ABSTAIN`, highest tier `L4`, stop reason `TIER_UNAVAILABLE`, `OPERATION`/`PERSISTENCE` `UNKNOWN`, frontier recorded |

§8.2 is the common case in real repositories, and it is the honest output. It is
also the concrete shape of the unsolved problem in [REPORT.md](REPORT.md) Q10 and
the primary falsifier that R05/R06 will expose.

### 8.3 A familiar rule hit that does not reach `PROVEN_EFFECT`

`cursor.execute(query)` where `query` is built from a runtime value.

| Tier | Result |
|---|---|
| L0 | claim instantiated |
| rule | an `attr_call` rule packet → `BOUNDARY = SUPPORTED` (driver egress) |
| rule | a `sql_execute_pattern` packet → `HYPOTHESIS_ONLY`, moves nothing |
| L7 | the statement is not statically determinable; unknown semantics → `OPERATION = UNKNOWN` |
| verdict | `ABSTAIN` |

Under AREF-001's rule-ID-to-effect mapping this site would have carried a
destructive-SQL effect annotation. Under AREF-002 it abstains and says why. This
is the same conflation class as the recorded `_name_looks_db` false positive,
where an unanchored substring match let `"sandbox"` satisfy `"db"` and a shell
executor was reported as destructive SQL at HIGH severity.

---

## 9. Invariants and test obligations

| Id | Invariant |
|---|---|
| `AREF-002-E01` | A claim records the highest tier reached and exactly one stop reason. |
| `AREF-002-E02` | Ascent is demand-driven: no tier is opened when no necessary obligation is `UNKNOWN` and addressable by it. |
| `AREF-002-E03` | Every packet carries a byte-identical verbatim extract and a locator sufficient to retrieve it. |
| `AREF-002-E04` | Dependency- and contract-sourced packets carry package name and pinned version. |
| `AREF-002-E05` | No packet whose only anchor is an identifier is `PROBATIVE`. |
| `AREF-002-E06` | No packet targets more than one obligation or more than one implementation candidate. |
| `AREF-002-E07` | An unparsed statement or command yields `UNKNOWN`, never a keyword-prefix inference. |
| `AREF-002-E08` | Prose documentation never yields a `PROBATIVE` packet. |
| `AREF-002-E09` | The packet set and stop reason are identical across runs for a fixed workspace, configuration and budget. |
| `AREF-002-E10` | `TIER_UNAVAILABLE` and `BUDGET_EXHAUSTED` are never merged into one reason. |
| `AREF-002-E11` | Removing the entire sink-rule corpus changes no claim's existence and no claim's stop reason. |
| `AREF-002-E12` | No tier consults a provider-specific identifier table to establish an obligation. |
