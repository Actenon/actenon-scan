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
**Action taken:** This is a deliberate tradeoff. Enforcing binding on assert-style guards would produce false positives on legitimate guards like `verify_pccb(proof, intent, action)` before `stripe.Refund.create(amount=amount)` — the guard checks a proof/intent triplet, not the amount, but it still authorizes the action. The false-positive cost of flagging these as UNBOUND is too high. The s02 benchmark case is recorded as a known limitation.
**Recommendation:** A future v3 could attempt semantic binding analysis (does the guard's argument semantically relate to the sink's argument?), but this requires type inference or dataflow analysis beyond the current scope.

