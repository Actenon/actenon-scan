# AREF-001 §3 — Data model

All string values in this section are exact. They are the values that appear in
`schema/resource-effect.schema.json`, in
`catalogue/resource-effect-catalogue.draft.json`, and in the examples. A
mismatch between this document and the schemas is a freeze defect; the check
that no such mismatch exists is recorded in
[10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md) §10.2 and is enforced by
`validate.py`.

## 3.1 The record

```
ResourceEffect
├── effect            : EffectType          (existing, reused — D-04)
├── kind              : ResourceKind        (new, closed — D-05)
├── selector          : ResourceSelector | null
├── scope             : ResourceScope       (new, closed)
├── controllability   : TaintLattice        (existing, reused — D-03)
├── certainty         : AnalysisCertainty   (existing, reused — D-08)
├── rule_id           : str                 (as emitted, unnormalised)
├── normalised_rule_id: str                 (catalogue key — D-14)
├── language          : "python" | "typescript" | "go"
├── catalogue_status  : "frozen" | "draft" | "blocked" | "absent"
└── unresolved_reason : str | null          (required when certainty is unknown)
```

`ResourceSelector`:

```
ResourceSelector
├── text     : str              # source text of the selecting expression
├── origin   : SelectorOrigin   # where the value came from, syntactically
└── certainty: AnalysisCertainty
```

### Why `selector` is nullable but `kind` is not

`kind` answers "what class of thing", and the catalogue can answer that from
the rule ID alone: `os.remove` acts on a filesystem path whatever its argument
is. `selector` answers "which instance", and that genuinely may not be present
in the call — a zero-argument call, a call whose declared argument position is
absent, or a `*args` splat. Making `kind` non-nullable (with an
`unknown_resource` member) and `selector` nullable puts the distinction between
"cannot classify" and "nothing to classify" in the type, where a consumer can
see it.

## 3.2 `EffectType` — reused, not redefined

Values are exactly the members of
`actenon_scan.repository.effect_summary.EffectType` at the frozen commit:

```
shell_execution        code_execution           file_write
file_delete            data_mutation            data_deletion
identity_mutation      access_control_mutation  money_mutation
money_refund           communication_send       email_send
repository_mutation    deploy_action            container_execution
infrastructure_mutation credential_access       network_egress
browser_action         unknown_effect
```

Twenty members, of which `unknown_effect` is the sentinel. REI adds none.
`schema/resource-effect.schema.json` pins this list as an `enum`, which means
a future `EffectType` addition requires a schema bump — a deliberate friction
that keeps the two in step.

## 3.3 `ResourceKind` — the new closed enum, v0

Twenty members, of which `unknown_resource` is the mandatory sentinel. The set
is deliberately at the same granularity as `EffectType`: coarse enough that a
rule ID determines it, fine enough that two rules with the same effect on
different resource classes are distinguishable.

| Value | Denotes | Illustrative shipped rules |
|---|---|---|
| `filesystem_path` | A path in the local or mounted filesystem | `DATA-DELETE-FILE`, `DATA-DELETE-OS`, `FILE-WRITE`, `FILE-OPEN-WRITE` |
| `database_table` | A named table or collection | (reserved; reachable only once SQL parsing is authorised — B-04) |
| `database_row_set` | A set of rows selected by a predicate | `DATA-DELETE-SQL`, `DATA-DELETE-SQL-RAW`, `DATABASE-MUTATE`, `DATABASE-ORM-MUTATE` |
| `object_store_key` | A key/prefix in an object store | `DATA-DELETE-OBJ` |
| `os_process` | A process the call causes to exist | `EXEC-SHELL` |
| `code_string` | Source text the call causes to be evaluated | `EXEC-CODE` |
| `container_image` | A container or image the call runs | `EXEC-CONTAINER` |
| `payment_object` | A charge, refund, payout or transfer | `PAY-STRIPE-REFUND`, `PAY-BRAINTREE`, `PAY-GENERIC-REFUND` |
| `identity_principal` | A user, service account or credential subject | `IDENTITY-CHANGE` |
| `access_policy` | A permission, role, grant or policy document | `ACCESS-CONTROL-MUTATE`, `IDENTITY-IAM-MUTATE` |
| `message_channel` | A channel, room or conversation | `COMMUNICATION-SEND`, `COMMUNICATION-SEND-NAME` |
| `email_recipient` | An address or recipient list | `EMAIL-PROVIDER-SEND` |
| `vcs_ref` | A branch, tag, ref or commit | `GIT-MUTATE` |
| `repository_object` | A file, issue, PR or release inside a hosted repository | `REPOSITORY-MUTATION`, `GITHUB-REST-MUTATION` |
| `deploy_target` | An environment or release target | `DEPLOY-SUBPROCESS` |
| `infrastructure_resource` | A cluster object or IaC-managed resource | `DEPLOY-K8S`, `DEPLOY-TERRAFORM` |
| `secret_store_entry` | A secret, key or token being read | `SECRET-READ` |
| `network_endpoint` | A URL or host the call sends to | `NET-EGRESS` |
| `browser_target` | A page, frame or DOM target | `BROWSER-ACTION` |
| `unknown_resource` | Sentinel. Not classified | `PROVIDER-SDK-CALL`, and every rule with no catalogue entry |

`database_table` is present but unreachable in v0. That is intentional and is
recorded rather than hidden: it is the member B-04 would activate, and leaving
it out would force a schema bump the moment the SQL decision is taken.

**The membership of this table is frozen as a *schema*, not as a *finding*.**
Whether these twenty classes are the right twenty for real code is exactly what
the missing REI evidence would say. That is B-02.

## 3.4 `ResourceScope` — four values

| Value | Meaning | How it is established in v0 |
|---|---|---|
| `single` | The call acts on one identifiable instance | The catalogue entry declares `scope_rule: "single"` and the selector resolved |
| `set` | The call acts on a bounded plurality | The catalogue entry declares `scope_rule: "set"` (e.g. a list/glob argument) and the selector resolved |
| `all` | The call acts on every instance of the kind | Only from an explicitly declared `scope_rule: "all"` catalogue entry |
| `unknown` | Not established | Everything else. **This is the v0 default for almost every rule.** |

This is the honest position and it should be read as a limitation, not as
modesty. Distinguishing `single` from `all` usually requires understanding a
predicate — a SQL `WHERE` clause, a glob, a recursive flag. v0 has no such
capability, because B-04 is unclosed. So v0 `scope` is `unknown` for every rule
whose scope depends on a predicate, and the disclosure counter (D-13) will show
that plainly.

Freezing four values now, while only two are reachable, costs nothing and means
the schema does not move when B-04 closes.

## 3.5 `controllability` — reused `TaintLattice`

Exact values, weakest to strongest join order as implemented in
`actenon_scan/repository/taint.py`:

```
untainted  →  constrained  →  external  →  model_derived  →  model_controlled  →  unknown
```

`unknown` is the **strongest** for join purposes. REI must preserve that: a
selector whose taint cannot be established is `unknown`, and `unknown` joined
with anything is `unknown`. REI performs no taint analysis of its own; it reads
the state the existing function-local dataflow produces for the selecting
expression, and reports `unknown` where that analysis does not reach.

## 3.6 `SelectorOrigin` — eight values

| Value | Meaning |
|---|---|
| `literal` | A constant in the source |
| `parameter` | A parameter of the enclosing function |
| `local_variable` | A local whose assignment was seen |
| `attribute` | An attribute access (`self.path`, `cfg.bucket`) |
| `receiver` | The call's own receiver (`conn` in `conn.execute(...)`) |
| `expression` | A composite the layer did not decompose (f-string, concat, call) |
| `absent` | The declared position/keyword is not present in the call |
| `dynamic` | A splat, comprehension, or computed key — structurally unresolvable |

`absent` and `dynamic` are distinct on purpose. `absent` is a catalogue
question — the declaration may be wrong. `dynamic` is a language question — no
declaration could have helped. Collapsing them would make the catalogue
unimprovable, because there would be no way to count declarations that are
simply incorrect.

## 3.7 `certainty` — reused `AnalysisCertainty`

```
analysis_error  <  unsupported  <  unknown  <  heuristic  <  strong  <  proven
```

Combination rules, all three of which follow existing code
(`certainty.combine_certainty`, `CallPath.certainty`):

1. **Weakest link.** `certainty = combine(entry.max_certainty,
   selector.certainty, reachability_certainty)`.
2. **Errors dominate.** Any `analysis_error` input yields `analysis_error`.
3. **Reachability caps.** The result may never exceed the certainty of the
   reachability claim on the annotated capability (D-08).

Ceiling per catalogue status, frozen:

| `catalogue_status` | Maximum achievable `certainty` |
|---|---|
| `frozen` | `strong` |
| `draft` | `heuristic` |
| `blocked` | `unknown` |
| `absent` | `unknown` |

`proven` is **unreachable in v0**, for every rule, by construction. A static
argument-position read is not a proof that the resource is what the catalogue
says it is; claiming `proven` would be exactly the kind of overstatement the
repository's `UNKNOWN`-first stance exists to prevent. `proven` remains in the
enum because the enum is shared, not because v0 can earn it.

## 3.8 UNKNOWN semantics — the four rules

These are the rules that make REI safe to ship without its evidence, and they
are the ones a reviewer should attack first.

**U-1. Unknown is a value, never an omission.** Every annotated site has a
`resource_effect` object. Absence of a key means the layer did not run, never
that the resource is uninteresting.

**U-2. Unknown is never promoted.** No downstream consumer may read
`unknown_resource`, `scope: unknown`, or `certainty: unknown` as "no resource",
"narrow scope", or "safe". Report text must never render an unknown as a
negative claim. The prescribed rendering is `resource: not determined
(<unresolved_reason>)`.

**U-3. Unknown is counted.** `resource_effect_unknown_count` is emitted in
every format, always (D-13, invariant I-11).

**U-4. Unknown carries a machine-readable reason.** When `certainty` is
`unknown`, `unresolved_reason` is required and must be one of a closed set:

```
rule_id_not_in_catalogue        catalogue_entry_blocked
declared_argument_absent        selector_is_dynamic
selector_not_decomposable       scope_requires_predicate_analysis
taint_state_unavailable         call_site_not_located
language_not_supported          analysis_error
```

A closed reason set is what makes the catalogue improvable: counting reasons
tells you whether the next unit of work is catalogue coverage
(`rule_id_not_in_catalogue`), a wrong declaration
(`declared_argument_absent`), or a genuine language limit
(`selector_is_dynamic`). An open-ended free-text reason would be unreadable in
aggregate, which is the state the disclosure counter exists to escape.

## 3.9 Determinism

Two scans of identical inputs must produce byte-identical `resource_effect`
records. The layer may not depend on dict iteration order, filesystem order, or
any clock. Selector `text` is the exact source slice via `ast.get_source_segment`
(or the language-appropriate equivalent), never a reconstruction. Invariant
I-12.
