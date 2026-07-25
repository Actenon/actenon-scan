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


## check_permission reclassification — name-based assert-style limitation

**Severity:** NOTE
**Where:** actenon_scan/detectors/guards.py — _is_assert_style_guard()
**Expected:** check_permission with discarded result should be detected as a soundness defect (WEAK) if the function returns a bool rather than raising.
**Observed:** check_permission is classified as assert-style (raises on failure), so a discarded result produces 0 findings. The s06 fixture was changed to use has_permission (genuinely returns bool, not assert-style) to test the discarded-result case.
**Analysis:** The reclassification is correct for the common case — every major framework that ships `check_permission` (Flask-Login, Django, FastAPI) raises on failure. However, a custom `check_permission` that returns bool instead of raising would be a false negative. This is an inherent limitation of name-based classification: static analysis cannot determine whether a function raises or returns. The s06 fixture correctly tests the soundness case using `has_permission`, which is genuinely non-assert-style.
**Action taken:** s06 fixture changed from check_permission to has_permission. The fixture change was declared per RULE 3 with justification in PR #29.
**Recommendation:** No action. The name-based classification is the best available heuristic. A future v3 could use type inference or cross-module analysis to determine whether a guard raises, but this is beyond the current scope.


---

## v0.8.0 run — performance, corpus precision, gating number

### PERF-01: the published 0.6s figure was measured on an unrepresentative repo

**Severity:** claim defect (fixed)

The v0.7.0 README reported 0.6s on 2,500 files. Measured on real agent
repositories the published package took 6.5s on langchain. The gap was the
benchmark repository, not the measurement: a synthetic tree of small files
does not resemble the codebases this tool targets.

`tests/benchmark/perf-fixture.json` now pins **langchain-ai/langchain @
fa7ce760a26437a904a4c93db75333f01d65ed83** (2,536 .py on disk, 1,954 scanned)
as the canonical performance fixture. All perf claims are measured against it.

**Honesty note on the before/after numbers.** The 6,539ms in the work order was
the *published package on different hardware*. On the machine used for this
run, `origin/main` measured **2,809ms** on the same fixture. Comparing the new
1,917ms against 6,539ms would have been a 3.4x claim produced by changing what
was measured, which RULE 3 forbids. The honest same-hardware numbers are below.

### PERF-02: the profile contradicted two standing assumptions

cProfile over a full langchain scan (top entries, 10.7s under the profiler):

| entry | calls | cumtime |
|---|---|---|
| `ast.walk` | 4,858,675 | 5.75s |
| `detect_sinks` | 605 | 4.69s |
| `_find_declarative_guarded_classes` | **1,951** | **2.74s** |
| `_build_parent_map_for_engine` | 605 | 1.36s |
| `_build_parent_map` (sinks) | 605 | 1.35s |
| `ast.parse` | 1,951 | **0.30s** |
| `_collect_files` | 1 | 0.33s |

Two assumptions did not survive it:

* **"Parse each file once and share the AST."** Already true. `ast.parse` was
  2.8% of runtime and never the bottleneck. The cost is *walking* the tree, not
  building it — five-plus independent full walks per file.
* **"The reachability short-circuit is the largest single win."** Measured, a
  marker set derived from the reachability config skips only 31% of files, and
  just 240 of the 961 that survive the sink pre-filter. Agent frameworks mention
  `Tool`, `execute` and `call` everywhere, so a marker scan helps least on
  exactly the repositories where speed matters. It is a real ~25% cut of the
  expensive path, not the dominant term.

The two dominant terms were both waste:

1. `_find_declarative_guarded_classes` ran on all 1,951 parsed files and its
   **return value was discarded** for the 1,346 that had no sink substring. It
   was called only so a detector crash would surface. 25% of runtime for a
   thrown-away value.
2. `_build_parent_map_for_engine` and `_build_parent_map` are byte-identical
   functions, each building the same map for the same file. 12% of runtime.

**Narrowed contract (deliberate).** A file with no sink substring and no
reachability marker is now skipped before any detector runs, so a detector
crash on such a file is no longer reported. Such a file cannot produce a
finding, so no finding is lost — only diagnostics on files that yield nothing.
`tests/test_guards.py::test_skipped_file_is_not_analysed` documents this, and
the original crash-isolation guarantee is still tested on files that *are*
analysed.

### PERF-03: results after optimisation (same hardware, same fixture)

| repo | origin/main | optimised serial | optimised `--jobs` | findings |
|---|---|---|---|---|
| langchain | 2,809ms | 1,917ms | **774ms** | 0 → 0 → 0 |
| crewai | 3,273ms | 2,367ms | **1,091ms** | 12 → 12 → 12 |
| openai-agents | 2,931ms | 2,060ms | **666ms** | 0 → 0 → 0 |
| autogen | 1,722ms | 1,355ms | **813ms** | 0 → 0 → 0 |
| mcp-python-sdk | 915ms | 599ms | **284ms** | 1 → 1 → 1 |

Findings are byte-identical in every column;
`tests/test_engine_parallel.py` locks serial/parallel equivalence, because a
faster scanner that finds different things is a different scanner.

Serial meets the <2s target on the pinned fixture (1,917ms). Two repos exceed
2s serially (crewai 2,367ms, openai-agents 2,060ms) and are reported as such
rather than dropped from the table; with `--jobs` all five are well under.

### PERF-04: `--changed-only` walked the whole tree

The flag converted the git diff into include-globs and then walked the entire
repository to filter down to it — the exact fixed cost the flag exists to
avoid. Worse, `_scan_typescript_files` and `_collect_unsupported_files` each
rglob'd the tree independently: together 178ms of a 194ms single-file run.

The diff's file list is now passed through directly. **1 file: 150ms. 3 files:
165ms.** Target was under 200ms.

### PREC-01: browser automation was treated as an agent framework

**Severity:** HIGH — shipped false positive, found by the corpus, in a control repo.

`playwright` and `selenium` were listed in `reachability.agent_frameworks`.
Every documentation screenshot script in **fastapi** — a non-agent precision
control — imports playwright and starts a dev server at module level, so all
12 produced findings. A finding in a control repo is a precision failure by
definition.

Driving a browser is not agent-reachability. Both entries removed. A genuine
browser agent (browser-use, in the corpus) registers tools and reaches the HIGH
paths, so it does not depend on this signal — browser-use still reports 0.
Regression fixture: `tests/benchmark/precision/p12_playwright_docs_script.py`.

### PREC-02: module-level code was treated as agent-reachable

**Severity:** HIGH — 19 false positives, 0 true positives. Measured precision 0/19.

A sink at module scope in a file importing an agent framework returned MEDIUM
confidence. On the corpus this fired 19 times, **all 19 false positives**, all
agno cookbook setup: `os.remove("tmp/data.db")` before constructing an Agent,
`shutil.rmtree` of a seed directory, `DB_PATH.unlink()` before seeding a demo
table.

The defect is not imprecision, it is unsoundness. Module-level statements run
at **import time**. An LLM cannot select or invoke them. This is the same
reasoning already used to exclude `if __name__ == "__main__":` blocks, applied
consistently to the rest of module scope.

Gated behind `reachability.module_level_reachability` (default **false**) so
the signal is recoverable rather than deleted. No hand-triaged true positive
depended on it: all 30 surviving corpus findings are HIGH confidence.

### PREC-03: inter-agent transport was treated as external communication

**Severity:** MEDIUM — 2 false positives.

`COMMUNICATION-SEND` matched `weather_client.send_message(request)` where the
receiver is an `A2AClient`. That is one agent handing a task to another, not a
side effect on the outside world — the dominant category in the recorded r05
negative result (framework message-passing plumbing).

The rules gained `exclude_receiver_types` for A2A/event-bus/runtime receivers,
mirroring the existing `_is_db_receiver` constraint used for the same class of
problem. Genuine Slack and email sends in superagi still fire.
Regression fixture: `tests/benchmark/precision/p13_a2a_send_message.py`.

### CORPUS-01: measured precision on 25 pinned repositories

21,308 Python files and 2,168 TypeScript files across 25 repos pinned by SHA.

| stage | findings | control-repo findings |
|---|---|---|
| as shipped in v0.7.0 | 63 | **12** (fastapi) |
| after PREC-01 | 51 | 0 |
| after PREC-02 | 32 | 0 |
| after PREC-03 | **30** | 0 |

All 30 survivors are hand-triaged TRUE POSITIVE in
`tests/benchmark/corpus-triage.json`, each with the rationale that produced the
verdict. Every one is HIGH confidence and sits inside a tool implementation.

**Zero findings across all five non-agent controls:** requests, flask, fastapi,
click, rich.

Measured precision on this corpus is **30/30**. That number is only worth
something because the three classes above were found by the same measurement
and fixed rather than argued away — the shipped scanner scored 51/63.

### GATE-01: corpus-demonstrated recall, 3 vs 4 — resolved

`baseline.json` records `recall_corpus: 3`. `corpus-evidence.json` contains
**four entries**. Neither file was wrong: r04 is explicitly
`"triage": "false_positive"`, kept deliberately as a negative result (the
`__main__` exclusion, with the note "No corpus TP found for this architecture
yet"). Three entries are true positives, so the gating number 3 is correct.

What was missing is the thing that lets a reader confuse the two: nothing tied
the count in `baseline.json` to the verdicts in `corpus-evidence.json`, so
counting entries gave 4 while the gate said 3.
`scripts/check_benchmark_integrity.py::check_corpus_recall_matches_evidence`
now asserts `recall_corpus == count(triage == "true_positive")` and rejects any
evidence entry without a valid verdict. The drift cannot recur silently.
