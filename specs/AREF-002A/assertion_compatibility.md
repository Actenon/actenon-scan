# Typed assertion compatibility

The registry in [assertion_registry.json](assertion_registry.json) is normative.
An admissible directional assertion is a registered tuple of **predicate,
obligation, polarity, source kind and source tier**, with PROBATIVE admissibility
and the required provenance. Mere schema syntax, an evidence tier, packet strength
or a nonempty extract does not establish semantic admissibility.

The schema encodes this registry for PROBATIVE packets; the semantic validator
also checks it. A producer unable to establish a registered combination MUST keep
the evidence HYPOTHESIS_ONLY, leaving unsupported obligations UNKNOWN. A supplied
packet that falsely claims PROBATIVE status is invalid input; loaders must reject
it, not silently rewrite its polarity, source kind, predicate or admissibility.
Unknown predicate strings are permitted only as non-settling hypotheses.

## Directional meanings

| Predicate | Obligation | Permitted polarity / meaning |
|---|---|---|
| implementation_is | IMPLEMENTATION | POSITIVE; requires typed binding witness |
| invocation_executes / invocation_does_not_execute | ACTIVATION | POSITIVE / NEGATIVE |
| egress_mechanism_is / terminates_in_process_state | BOUNDARY | POSITIVE / NEGATIVE |
| operation_is_mutation / operation_is_observation | OPERATION | POSITIVE / NEGATIVE |
| state_is_durably_committed | PERSISTENCE | POSITIVE |
| state_is_ephemeral / state_is_guaranteed_rolled_back | PERSISTENCE | NEGATIVE only |
| operation_is_no_op / dry_run_in_force | OPERATION or PERSISTENCE | NEGATIVE only; separately justified packets for each obligation |
| commit_outcome_undetermined | PERSISTENCE | NEGATIVE wire polarity, **uncertainty, not a refutation** |
| test_double_in_force | None by itself | HYPOTHESIS_ONLY; independently establish actual operation/boundary/lifetime |

A test double may still dispatch real effects; its label cannot support or refute
external production effect. A guaranteed no-op is different from its suggestive
name. Dry-run must be established in force at this invocation, not merely available.
Transport-only packets cannot settle OPERATION or PERSISTENCE. A driver packet
may settle persistence only when it carries a registered commitment/lifetime
assertion from driver semantics; dispatch alone remains boundary evidence.

## Source constraints

The JSON registry enumerates exact combinations, rather than permitting all
predicates at any apparently strong tier. In this bounded profile:

- Local binding/type/interface witnesses establish implementation identity.
- Local control flow/call evidence or executable body evidence establishes activation.
- Resolved local/wrapper/dependency bodies can supply the registered effect facts.
- Formal machine-readable operation contracts supply operation/lifetime semantics
  at L6. Mere prose or unregistered declaration semantics remain hypotheses.
- Parsed SQL/document-store/command semantics can supply operation facts at L7.
- Transport primitives establish egress only. Driver semantics are independently typed.
- Name, regex, HTTP-method and package identity evidence cannot settle these facts.

Dependency-source packets require recorded pinned-version provenance. Contract
and dependency tiers retain AREF-002's package/version-resolution fields; version
uncertainty must remain explicit and must never be fabricated as a resolved version.

The existing rule-match taxonomy is retained solely for compatibility. Structurally
anchored matches may contribute only the registered obligation-specific assertions;
bare-name/text matches remain hypotheses. Existing taxonomy strings are not new
provider signatures. Rule provenance cannot be relabeled as body provenance. No
rule match is required in any valid example here.

Each packet bears on one obligation and one candidate. A shared extract may
support multiple separately justified packets; duplicating its bytes does not
make additional facts admissible. All opposing probative packets must be retained.

`commit_outcome_undetermined` is excluded from positive/negative fact sets. State
evaluation preserves ERROR first and unresolved opposing facts second, before
applying uncertainty. See [closure_and_receipts.md](closure_and_receipts.md).
No numeric confidence or lexical inference rule is introduced.
