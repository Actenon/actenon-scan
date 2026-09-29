# AREF-001 §1 — Evidence availability

This section is the most important one in AREF-001. The task specified that
AREF-001 be built on evidence identified as **REI-001**, **REI-001B** and
**REI-002**. That evidence was searched for and **is not accessible in this
working environment**. Nothing in this directory substitutes for it, invents
it, or re-derives it by re-running an experiment.

## 1.1 Search procedure

Performed at commit `b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16`, before any
artefact was written. Every command is reproducible.

| # | Search | Command | Result |
|---|---|---|---|
| E-1 | Token search across the whole working tree | `grep -ril "REI-001\|REI-001B\|REI-002\|AREF" . --exclude-dir=.git` | 1 file matched: `research/reachability-ground-truth/evidence.json` |
| E-2 | Exact token extraction from that one match | `grep -oi "REI-[0-9A-Za-z]*\|AREF[0-9A-Za-z_-]*" research/reachability-ground-truth/evidence.json \| sort \| uniq -c` | `1 areful` — a substring of the English word "careful". **Not a reference.** E-1 was a false positive |
| E-3 | Commit-message search across all refs | `git log --all --format='%h %s' \| grep -iE "rei[- _]\|resource.effect\|aref"` | no output |
| E-4 | Filename search across the whole filesystem | `find / -xdev \( -iname '*REI-00*' -o -iname '*AREF*' -o -iname '*rei_00*' \)` | no output |
| E-5 | Agent persistent store | `find /cursor/stores/self -type f` | empty (`artifacts/` directory exists and is empty) |
| E-6 | Conventional hand-off locations | listing of `/tmp`, `/home/ubuntu`, `/workspace` root | no evidence bundle, no attachment directory, no `REI*` path |
| E-7 | Remote refs | `git branch -a` — 68 refs enumerated | no branch, tag or ref whose name references REI, resource-effect, or AREF |

## 1.2 Result

**REI-001: NOT AVAILABLE. REI-001B: NOT AVAILABLE. REI-002: NOT AVAILABLE.**

No artefact bearing any of these identifiers exists in the working tree, in
any local or remote git ref reachable from this clone, in the agent store, or
anywhere on the filesystem of this environment.

Three consequences follow, and all three are load-bearing:

1. AREF-001 cannot cite REI findings. It does not. Every empirical claim in
   this directory is sourced either to a file in this repository at the frozen
   commit, or to a command whose output is reproduced inline.
2. Decisions whose correct answer depends on REI measurement are **not made**.
   They are enumerated as B-01…B-06 in
   [08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md).
3. Because B-01…B-06 are load-bearing rather than cosmetic, the freeze's
   verdict is `ARCHITECTURE NOT READY`. See [REPORT.md](REPORT.md) §30.

The task's instruction was explicit: *"If evidence required by the task is
unavailable, record that fact. DO NOT invent it and DO NOT rerun the
experiments."* That instruction is followed literally. The experiments were
not re-run, no proxy measurement was substituted for them, and no number
attributed to REI-001, REI-001B or REI-002 appears anywhere in AREF-001.

## 1.3 What the identifiers probably denote — stated as a hypothesis, not a fact

A reviewer who holds the missing evidence needs to know what AREF-001 assumed
it would contain, so that they can check the assumption. This is a hypothesis
about the *shape* of the evidence, inferred from the naming convention of the
repository's other work orders. It is not a claim about its contents.

| Identifier | Hypothesised subject | Which blocked decision it would close |
|---|---|---|
| REI-001 | A baseline measurement: for real sink call sites, can a resource selector be extracted statically, and at what rate per rule family? | B-03, B-02 |
| REI-001B | A follow-up narrowing one family — by the naming pattern used elsewhere in this repository, a `B` suffix denotes a corrective or narrowing pass on the same question. SQL statement parsing is the most likely candidate, being the one family where the selector is inside a string literal | B-04 |
| REI-002 | A precision measurement: what fraction of inferred resource effects are wrong, and what does a wrong one cost a reader? | B-01, B-05, B-06 |

**If this hypothesis is wrong, the mapping above is wrong and B-01…B-06 must be
re-derived against the real evidence.** That is a cheap correction: the blocked
decisions are listed separately from the frozen ones precisely so that the
frozen part survives a wrong guess about the blocked part.

## 1.4 Accessible evidence, and why it is not a substitute

One substantial evidence body **is** accessible:
`research/reachability-ground-truth/` (3.7 MB; inventory, seeded stratified
sample, 160 human labels, adjudication rules, chains, analysis, full-scan
verification). Its README is dated, versioned, and states its own limitations.

It is **reachability** evidence. It answers "can an agent-controlled boundary
reach this sink?" REI asks a different question: "given that a sink is reached,
what does it act on?" The two are orthogonal — a perfectly resolved call path
tells you nothing about whether `cursor.execute(q)` deletes one row or the
table.

AREF-001 uses that evidence for exactly three purposes, all of them
architectural rather than empirical:

| Use | What is taken | Where |
|---|---|---|
| U-1 | The demonstrated fact that *name-based* inference is this repository's dominant false-positive mechanism (`"sandbox"` contains `"db"` → a shell executor reported as destructive SQL at HIGH) | Justifies frozen decision **D-07**: no name-based resource inference in v0 |
| U-2 | The demonstrated fact that a reachability layer can ship, be enabled by default, and resolve almost nothing, because nobody measured resolution separately from findings | Justifies frozen decision **D-13** (a mandatory disclosure counter) and invariant **I-11** |
| U-3 | The documented separation between reachability and authority binding, and the standing rule that where the relationship cannot be established the state is `UNKNOWN / RUNTIME VERIFICATION REQUIRED`, never `AUTHORISED` | Justifies frozen decisions **D-07**, **D-08** and invariant **I-04** |

None of these is a resource-effect measurement. None is presented as one.

## 1.5 Evidence that AREF-001 asserts on its own account

Two claims in this directory are empirical statements about the shipped
scanner rather than citations. Both were produced by running a command against
the frozen commit, both are reproduced with their command, and both are
recorded as *observations* — neither was fixed, because fixing them would be a
scanner change.

| Claim | Where | Reproduction |
|---|---|---|
| `_RULE_ID_TO_EFFECT` contains 32 rule IDs; `default_rules.json` ships 31 Python sinks; the set difference is exactly `{EXEC-SHELL-GO}` in one direction and empty in the other | [10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md) §10.4 | Command given inline in §10.4 |
| `effect_for_rule_id` returns `None` for 8 of the 9 rule IDs the Go detector emits, because it strips only `-WEAK` and `-UNBOUND`, not `-GO` | [10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md) §10.5 | Command given inline in §10.5 |

Both directly constrain the REI catalogue design (see **D-14**), which is why
they are in the freeze at all.
