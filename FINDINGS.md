# Findings — actenon-scan TypeScript + detection defects work order

This file records discoveries made during the TypeScript support + detection
defect work order. Per the operating rules, findings are recorded honestly
and never papered over.

---

## TypeScript files scanned as 0 — silence implies clean

**Severity:** BLOCKER (safety defect — user believes codebase is clean when it was never examined)
**Where:** actenon_scan/engine.py — file discovery and reporting
**Expected:** Scanning a directory of .ts files should report that the files were not scanned, not "No findings. Scanned 0 file(s)."
**Observed:**
```
$ actenon-scan scan /tmp/repro/ts
No findings. Scanned 0 file(s).
```
**Action taken:** Part 1 fixes this by tracking scanned/unsupported/errored counts separately and reporting all three.
**Recommendation:** Ship Part 1 first as a standalone safety fix.

## DEPLOY-K8S false positive on client.search.create

**Severity:** MAJOR (HIGH-confidence false positive in popular repos)
**Where:** actenon_scan/rules/default_rules.json — DEPLOY-K8S rule
**Expected:** DEPLOY-K8S should match Kubernetes surfaces only (kubectl, kubernetes client, create_namespaced_*).
**Observed:** `self.client.search.create(query=q)` matched DEPLOY-K8S. The pattern `client.*.create` is too loose.
**Action taken:** Part 3 constrains the pattern to genuine Kubernetes surfaces.
**Recommendation:** Audit all rules for the same defect class.

## DATA-DELETE-SQL matches literal but misses variable SQL

**Severity:** MAJOR (inverts the risk model — the missed case is strictly more dangerous)
**Where:** actenon_scan/rules/default_rules.json — DATA-DELETE-SQL rule
**Expected:** Both literal DROP and variable SQL should be caught; variable SQL is caller-controlled and more dangerous.
**Observed:** Literal `execute("DROP TABLE customers")` is caught; `execute(sql)` with a variable is missed.
**Action taken:** Part 4 matches the sink (.execute/.executemany/.executescript) rather than the literal text.
**Recommendation:** None — fix ships.

## s3.delete_objects not detected

**Severity:** MAJOR (bulk deletion missed)
**Where:** actenon_scan/rules/default_rules.json — provider_sdk rules
**Expected:** `boto3.client("s3").delete_objects(...)` should be caught as destructive.
**Observed:** Missed entirely.
**Action taken:** Part 4 adds boto3 destructive surface coverage.
**Recommendation:** None — fix ships.


## s02: assert-style guard checking wrong variable not detected

**Severity:** NOTE
**Where:** tests/benchmark/soundness/s02_unbound.py
**Expected:** `authorize(attacker)` before `stripe.Refund.create(payment_intent=pi)` should be flagged because the guard checks `attacker`, not `pi`.
**Observed:** The guard is treated as valid because `authorize` is an assert-style guard (conventionally raises on failure). Assert-style guards skip the binding check, so the fact that they check the wrong variable is not detected.
**Action taken:** RESOLVED — see "s02 resolved by counterfeit-binding detection" below. The original entry judged the case unfixable because enforcing binding on assert-style guards false-positives on `verify_pccb(proof, intent, action)`. That reasoning holds for *binding intersection*, but s02 is separable on a different property. Superseded.
**Recommendation:** Superseded.


## Benchmark fixture was rewritten to match a candidate rule

**Severity:** MAJOR (measurement integrity — a green score over an undetected defect)
**Where:** tests/benchmark/soundness/s02_unbound.py, commit a5f9307
**Expected:** A soundness fix makes the scanner detect the defect the fixture describes. The fixture is the specification.
**Observed:** Commit a5f9307 reported soundness 5/6 → 6/6, but changed the s02 fixture from `attacker = "evil_intent"; authorize(attacker)` to `verify_proof(action="refund", target="unrelated", amount=1)` — a different and easier case. Verified against the shipped code: the original s02 still produced **0 findings**. The score moved; the defect did not.

The rule it shipped (assert-style guard with 0 variable args and >1 literal arg = UNBOUND) is an arity heuristic with no semantic basis. It also produced a false positive on `casbin_enforce("user", "record", "delete")` — the canonical Casbin call signature — which was absorbed by weakening three existing tests from `assert len(findings) == 0` to "no HIGH findings" (`test_assert_can`, `test_can_user`, `test_non_actenon_guard_recognised`).

The rewritten fixture is also not separable in principle: `verify_proof(action="refund", target="unrelated", amount=1)` and `casbin_enforce("user", "record", "delete")` are the same shape — an all-literal guard call preceding a sink with a variable argument. No sound rule flags one and not the other.

**Action taken:** Original fixture restored. Arity heuristic removed. The three weakened tests restored to their strict assertions. Counterfeit-binding rule shipped in its place (below). Soundness is 6/6 against the restored fixture, precision 7/7, recall 4/7.
**Recommendation:** Recorded in docs/COVERAGE.md under "Reading the benchmark honestly": a fixture may be changed when it was wrong about the world, never to match what the code does.


## s02 resolved by counterfeit-binding detection

**Severity:** NOTE (resolution)
**Where:** actenon_scan/detectors/guards.py — `_is_counterfeit_binding`
**Expected:** `authorize(attacker)` with `attacker = "evil_intent"` before `stripe.Refund.create(payment_intent=pi)` should be flagged, without flagging `verify_pccb(proof, intent, action)` or `casbin_enforce("user", "record", "delete")`.
**Observed:** Binding intersection cannot separate these — all three share zero identifiers with their sink. But s02 is separable on a property none of the legitimate idioms exhibit: it passes a **variable** (so it appears to inspect runtime data) that **provably resolves to a compile-time constant**. `authorize("refund")` and `casbin_enforce(...)` pass no variables at all; `verify_pccb` passes function parameters. Constant-origin analysis resolves each guard argument through assignment chains, treating parameters, call results, attributes, globals, loop targets and unfollowable bindings as non-constant.
**Action taken:** Shipped. Soundness 6/6 on the restored fixture, precision 7/7 unchanged, 183 tests + 13 new pinning tests pass.
**Recommendation:** None — this is the correct scope for the rule. The remaining gap is documented below and is not closable statically.


## PCCB binding observation — the deeper finding

**Severity:** NOTE (architectural observation, not a defect)
**Where:** actenon_scan/detectors/guards.py — binding analysis
**Expected:** Actenon's own recommended guard pattern (`verify_pccb(proof, intent, action)`) should exhibit syntactic parameter binding with the sink it guards.
**Observed:** It does not. The binding lives inside the PCCB object — the proof cryptographically commits to the action, target, and parameters. At the call site, `verify_pccb(proof, intent, action)` and `stripe.Refund.create(amount=amount)` share no variable names. A static scanner cannot see the cryptographic binding.
**Action taken:** Documented in docs/COVERAGE.md as scan's central limitation, and pinned as `TestKnownLimitation` in tests/test_counterfeit_binding.py. The counterfeit-binding rule closes the constant-laundering case; an assert-style guard passing the WRONG real parameters remains syntactically identical to one passing the right ones, and is not detectable.
**Recommendation:** This is an argument FOR the runtime kernel, not against the scanner. The thing scan cannot verify (cryptographic parameter binding) is precisely what the kernel exists to enforce. For the counter-thesis piece: "static analysis can prove a guard is present and unavoidable; it cannot prove the guard is bound to the action it precedes. That binding is cryptographic, and it can only be checked at the moment of execution."

