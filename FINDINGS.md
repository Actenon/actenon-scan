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

---

## v0.8.0 release run

### PERF-05: parallel-by-default cost time on the machines most users have

**Severity:** HIGH — a default that made the headline claim false for the majority.

`--jobs` defaulted to `os.cpu_count()`, so parallelism was ON for everyone.
Measured on a low-core CI container it was consistently **worse** than serial:

| repo | serial | `--jobs 4` | verdict |
|---|---|---|---|
| langchain | 5,206ms | 5,710ms | 10% slower |
| crewai | 5,680ms | 6,086ms | 7% slower |
| openai-agents | 5,682ms | 6,251ms | 10% slower |

On the 10-core reference host the same flag on the same repositories is
**2.1–2.75x faster**. Both measurements are real; neither is an error.

**The discriminator is core count, not file count.** This matters because the
existing guard was a 200-file floor, and every repo in the low-core table is
far above it — langchain is 1,954 files. A file-count floor cannot fix a
core-count problem. Parallelism needs *spare* cores: with as many workers as
cores, nothing is left for the parent, and per-worker interpreter startup plus
rule loading is never amortised.

Crossover measured on the 10-core host (best of 3, files x jobs):

| files | serial | j2 | j4 | j8 | j10 | best |
|---|---|---|---|---|---|---|
| 65 | 81ms | 84 | 84 | 84 | 85 | serial |
| 121 | 670ms | 689 | 682 | 683 | 685 | serial |
| 133 | 501ms | 503 | 501 | 501 | 501 | tie |
| 277 | 1,159ms | 872 | 596 | 521 | 492 | j10 (2.36x) |
| 586 | 619ms | 445 | 333 | 298 | 288 | j10 (2.15x) |
| 957 | 2,413ms | 1,624 | 1,290 | 1,128 | 1,108 | j10 (2.18x) |
| 1,954 | 2,026ms | 1,247 | 867 | 747 | 737 | j10 (2.75x) |

**Fix.** `auto_jobs(file_count, cpu_count)` parallelises only at **8+ cores**
and **250+ files**, and returns at most `cores - 1` so the parent is not
competing with its own workers. An explicit `--jobs N` always overrides it.

**Honest limitation.** This host has 10 cores, so `--jobs 4` here runs four
workers on ten cores with no contention — my numbers *understate* the harm on
a real 4-core box rather than reproducing it. I could not reproduce the
low-core regression directly. The 5–7 core range is therefore **unmeasured**,
and per the rule that ambiguity resolves to the safe side it defaults to
serial. The safe side is the mode that is never slower, not the one that is
sometimes faster.

**Gate.** `scripts/check_perf_gate.py` asserts the default mode is never more
than 5% slower than forced serial, and runs on GitHub-hosted runners — 2–4
cores, the exact hardware where the regression appeared. The old behaviour
would fail it.

**Sequencing note.** The work order scheduled the v0.8.0 release before this
fix. I inverted that order deliberately: the release notes lead with "roughly
2x faster", and shipping parallel-by-default would have made that claim false
for every user on a 2–4 core runner — which is most CI. One release that is
correct everywhere beats a release plus a same-week 0.8.1. Recorded here
because deviating from a stated order is exactly the kind of decision that
should be visible rather than silent.

### RELEASE-01: v0.8.0 shipped four merged work orders that users could not get

Repo and PyPI both sat at 0.7.0 while `main` carried guard resolution by
definition, the ~2x serial speedup, three fixed false-positive classes, the
25-repo measured corpus, and the coverage contract. Every one of those was
invisible to every user. Released as 0.8.0.

### CORPUS-02: the pinned corpus cannot see upstream drift

The pins in `pinned_repos.json` are what make "30 findings, 30 true positives"
reproducible — it is a statement about those exact trees. It is therefore also
blind by construction: a new agent pattern appearing upstream is invisible
until someone re-pins, and re-pinning means redoing the hand triage.

`scripts/corpus_freshness.py` + a monthly workflow now diff each pin against
upstream HEAD and file one tracking issue. It is deliberately non-failing and
read-only: a freshness check that edits the corpus it audits is not a check,
so the workflow also asserts `git diff --quiet tests/benchmark/` afterwards.

Verified by rolling the `requests` pin back nine commits: the job detected the
moved SHA (`74c56d5ff` → `69f848470`), fetched HEAD, re-scanned, and reported
the delta. On the real corpus all 25 repos are still at their pins, so a run
today reports zero movement — which is why the stale-pin test was necessary.
A report that says "nothing changed" proves nothing unless you have seen it
say something else.

The re-pin procedure is in CONTRIBUTING.md: re-pin, re-scan, re-triage every
changed finding, and state old and new counts in the PR. Re-pinning without
re-triage is the same defect class as swapping a benchmark fixture.

### GATE-02: the coverage contract holds under all three failure modes

A gate that passes everything is worse than no gate. Verified by running the
real checker against deliberately broken copies:

| failure mode | result |
|---|---|
| row COVERED with no evidence citation | rejected |
| row COVERED citing an entry triaged `false_positive` | rejected |
| COVERED count disagreeing with `baseline.recall_corpus` | rejected |
| unmodified repo | passes, 3 COVERED |

The second is the one that matters: the cited key *exists* in
corpus-evidence.json, so a check that only tested for presence would pass it.
It records a failure, not a capability.

These are now `tests/test_coverage_contract_gate.py` rather than a one-off
demonstration, so the gate's own failure modes are regression-tested.

---

# Work Order 1 — Consequential-action coverage gaps

## Baseline reproduction (recorded before any changes)

Commit: 473c14fe1fcd3f6d40c9383dfd474390dff0872b
Version: 0.8.0

Three empirically established misses:

1. `gh.get_repo(repo).create_file(path, "m", content, branch=branch)`
   — NO FINDINGS (confirmed miss)
2. `psycopg2.connect("x").cursor().execute(query)`
   — NO FINDINGS (confirmed miss)
3. `smtplib.SMTP("host").send_message(message)`
   — FINDING (COMMUNICATION-SEND). NOTE: this case is NOT missed at
   v0.8.0. The work order's premise that send_message is missed
   appears to reference an earlier version. The architectural concern
   (name-based exclusion is fragile) remains valid and is addressed
   in Part 1.

Four working cases (all confirmed firing at baseline):

1. `requests.put(f"https://api.github.com/repos/{repo}/contents/{path}", ...)`
   — NET-EGRESS (high)
2. `WebClient("token").chat_postMessage(channel=channel, text=text)`
   — COMMUNICATION-SEND (medium)
3. `cursor.execute(query)` (variable literally named cursor)
   — DATA-DELETE-SQL (high)
4. `smtp.sendmail(sender, recipients, body)`
   — COMMUNICATION-SEND (medium)

## Part 1.3 — Precision-narrowing audit verdicts

### _is_db_receiver — REGRESSION FOUND (fixed in Part 2.9)

- False-positive case it was intended to remove: `step.execute(cmd)`
  where `step` is a non-DB domain object. **Remains clean** ✓
- Nearest legitimate consequential case it accidentally suppresses:
  `psycopg2.connect("x").cursor().execute(query)` — the chained-call
  form. **Suppressed** ✗ (the miss this work order targets).
- Root cause: `_is_db_receiver` only handles ONE level of chaining.
  For `psycopg2.connect("x").cursor().execute(query)`, the receiver
  of `.execute()` is `psycopg2.connect("x").cursor()` (a Call). The
  code checks if the inner call's function name ends with
  `connect`/`create_engine`/etc., but the inner call's function is
  `psycopg2.connect.cursor` (an Attribute on a Call), so
  `call_name = "psycopg2.connect.cursor"` which does not end with
  `connect`. Returns False → finding suppressed.
- Fix: Part 2.9 rewrites `_is_db_receiver` to use receiver-origin
  resolution, which walks the chain to the outermost constructor.
- Regression fixture added: tests/corpus/DATA-DELETE-SQL/vulnerable/
  04_chained_psycopg2.py (added in Part 2.9 commit).

### BROWSER-ACTION narrowing — SAFE

- False-positive case it was intended to remove: a non-agent
  documentation script (`p12_playwright_docs_script.py`) driving
  Playwright at module level. **Remains clean** ✓ (0 findings)
- Nearest legitimate consequential case: `page.click(selector)` in
  an MCP tool. **Still fires** ✓ (BROWSER-ACTION, browser_action)
- Mechanism: BROWSER-ACTION uses `qualified_patterns` like
  `page.click`, `frame.click`, `element.click`, `locator.click`,
  `driver.click`. The full dotted name must match — a non-browser
  `btn.click()` does not match because `btn.click != page.click`.
- Regression fixture added: tests/corpus/BROWSER-ACTION/safe/
  04_non_browser_click.py (non-browser `.click()` must stay clean).

### COMMUNICATION-SEND A2A exclusion — SAFE (after Part 1 fix)

- False-positive case it was intended to remove: Agno A2A
  `weather_client.send_message(request)` where `weather_client` is
  an `A2AClient`. **Remains clean** ✓ (0 findings, p13 fixture)
- Nearest legitimate consequential case: `smtplib.SMTP("host")
  .send_message(message)`. **Still fires** ✓ (COMMUNICATION-SEND)
- Name-collision false-negative case (SMTP client named
  `a2a_client`): **Now fires** ✓ (was previously suppressed by the
  bare-name fallback `or recv.id`). This is the Part 1 fix.
- Inline A2A constructor case (`A2AClient(...).send_message(...)`):
  **Now correctly excluded** ✓ (was previously firing because no
  var_types entry existed). This is a precision improvement.
- Regression fixtures added:
  - tests/benchmark/recall/r08_smtp_send_message.py (Part 1)
  - tests/corpus/COMMUNICATION-SEND/vulnerable/04_smtp_named_a2a_client.py
    (Part 1.3 audit)

### COMMUNICATION-SEND-NAME exclude_receiver_types — DEAD CONFIG (harmless)

- The rule has `type=name_call` (bare function calls like
  `sendmail(...)`). `_match_name_call` does not check
  `exclude_receiver_types` because a bare function call has no
  receiver. The `exclude_receiver_types` key on this rule is dead
  config — present but never read. Harmless: no behaviour change,
  no false positive, no false negative. Documented for future
  cleanup.

### Other qualified_call rules (DATA-DELETE-OBJ, DATABASE-ORM-MUTATE,
GIT-MUTATE, SECRET-READ) — NO EXCLUSION, NO NARROWING

- These rules use `_match_qualified_call` with explicit
  `qualified_patterns` and no `exclude_receiver_types`. They match
  the full dotted name (e.g., `session.delete`, `repo.push`). There
  is no name-based narrowing to audit.
- Pre-existing precision note: `session.delete` matches BOTH
  NET-EGRESS (priority 10) and DATABASE-ORM-MUTATE (priority 20).
  NET-EGRESS wins by priority. A non-DB `session.delete()` (e.g.,
  a cache session) fires as NET-EGRESS. This is out of scope for
  this work order and recorded as a residual risk.


## Part 2.10 — Corpus delta after receiver-origin resolution

Re-ran the full pinned corpus (12 repos: the 7 with baseline findings
+ all 5 controls) against the rewritten _is_db_receiver and the new
receiver-origin resolver.

Results:
  baseline findings: 30
  w01 findings:      30
  LOST:   0
  GAINED: 0
  Control repos (requests, flask, fastapi, click, rich): all 0 → 0

The receiver-origin resolution is precision-neutral on the existing
corpus. No false positives introduced, no true positives lost. The
chained psycopg2 case is now detected (Part 2.9) without affecting
any other finding.

## Part 2.9 — _is_db_receiver rewrite verdict

REGRESSION FOUND → FIXED.

- The chained form `psycopg2.connect(dsn).cursor().execute(query)` was
  suppressed at baseline. Root cause: _is_db_receiver only handled one
  level of chaining.
- Fix: _is_db_receiver now uses _resolve_receiver_origin to walk the
  chain to the outermost constructor. For the chained form, the origin
  resolves to `psycopg2.connect` (strong DB evidence).
- Name-based heuristic preserved as a fallback for the common
  `cursor.execute(query)` idiom where `cursor` is just a variable
  name. This is acceptable because the sink itself (.execute with a
  non-literal arg) is strong evidence; the name adds confirming
  evidence rather than carrying the whole decision.
- Paired fixtures:
  - tests/corpus/DATA-DELETE-SQL/vulnerable/04_chained_psycopg2.py
    (legitimate chained case must fire)
  - tests/corpus/DATA-DELETE-SQL/safe/04_non_db_execute.py
    (non-DB step.execute() must stay clean)


## Part 5 — Campaign target validation

### Pinned corpus scan results

Scanned all available pinned MCP servers + computer-use agent with the
new W01 rules (REPOSITORY-MUTATION, GITHUB-REST-MUTATION,
EMAIL-PROVIDER-SEND):

| Repo | Category | Files | New W01 findings |
|------|----------|-------|------------------|
| mcp-servers (modelcontextprotocol/servers) | mcp_server | 14 py + 65 ts | 0 (1 existing FILE-WRITE) |
| mcp-python-sdk | mcp_server | 819 py | 0 (1 existing NET-EGRESS) |
| github-mcp-server | mcp_server | 208 go + 4 ts | 0 (Go unsupported; 4 TS files are UI) |
| mcp-atlassian | mcp_server | 283 py | 0 |
| browser-use | application (computer-use) | 370 py | 0 |

### Hand-triage of new findings

ZERO new findings from the W01 rules across the scanned campaign
targets. The new rules fire on fixtures but not on the existing
pinned corpus.

### Why the GitHub MCP server produced zero findings

The official GitHub MCP server (github/github-mcp-server) implements
its mutation tools (create_file, delete_file, create_pull, etc.) in
Go. The actenon-scan scanner supports Python and TypeScript but not
Go. The 4 TypeScript files in the repo are frontend UI code
(vite.config.ts, vite-env.d.ts, useMcpApp.ts, toolResult.ts) — none
contain MCP tool definitions or mutation sinks.

This is a recorded limitation: the scanner cannot detect
repository-mutation surfaces in Go-based MCP servers. The
REPOSITORY-MUTATION and GITHUB-REST-MUTATION rules are validated
against Python (PyGithub) and Python/TS (raw requests/httpx) fixtures
respectively, but no corpus true positive exists yet for a Go-based
GitHub mutation tool.

### Control repositories

All 5 control repositories (requests, flask, fastapi, click, rich)
remain at 0 findings across all W01 rules.

### Campaign readiness

The scanner can detect:
- PyGithub mutation in agent-reachable Python tools (fixture-verified)
- Raw GitHub REST mutation in agent-reachable Python tools (fixture-verified)
- SMTP email send in agent-reachable Python tools (fixture-verified)
- SendGrid/Resend/SES/Postmark email send in agent-reachable Python tools (fixture-verified)
- Chained psycopg2 database mutation in agent-reachable Python tools (fixture-verified)

The scanner cannot detect (recorded as residual risk):
- Go-based MCP server mutation tools (language unsupported)
- GitLab/Bitbucket equivalents (no real-world occurrence validated)

