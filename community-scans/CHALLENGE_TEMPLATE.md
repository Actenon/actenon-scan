# Soundness Challenge — Submission Template

> Copy this file to `community-scans/CHALLENGE-NNN.md` (next available
> number — see `tests/challenge/` for the existing sequence) and fill in
> the fields below. Then either open a GitHub issue with the
> `soundness-challenge` label and paste this content, or open a PR that
> adds the fixture file and this metadata file.

This template is the public embodiment of the rule stated in
[`docs/COVERAGE.md`](../docs/COVERAGE.md): **silence must never imply
safety**. A scanner that hides its misses is more dangerous than one
that publishes them. Submitting a case here is the single most useful
thing an external reader can do for this tool.

The schema below mirrors
[`tests/challenge/CHALLENGE-001.yml`](../tests/challenge/CHALLENGE-001.yml)
and [`CHALLENGE-002.yml`](../tests/challenge/CHALLENGE-002.yml). A
maintainer will port accepted submissions into that directory as a
permanent regression fixture.

---

## Challenge metadata

<!-- Required fields. Replace the bracketed placeholders. -->

| Field | Value |
|-------|-------|
| `id` | CHALLENGE-NNN <!-- next available number after the highest in tests/challenge/ --> |
| `title` | <!-- short description, ≤ 80 chars --> |
| `class` | false-positive \| missed-sink \| wrong-classification |
| `language` | python \| typescript \| go |
| `status` | open |
| `submitted_by` | <!-- your github handle, no leading @ --> |
| `submitted_date` | YYYY-MM-DD |
| `issue` | <!-- github issue number; leave blank if submitting via PR --> |
| `rule_id` | <!-- the affected rule, e.g. EXEC-SHELL, PAY-STRIPE-REFUND-GO, or "n/a" for missed-sink --> |
| `expected` | finding \| no-finding |
| `evidence` | <!-- file:line plus a 1–3 sentence explanation of WHY this is a soundness defect --> |
| `fixture_file` | <!-- path to a minimal reproducing source file you are submitting alongside this metadata --> |

### Filling in the fields

- **`id`** — Use the next available `CHALLENGE-NNN`. The two existing
  cases are `CHALLENGE-001` and `CHALLENGE-002`. Your first external
  submission is `CHALLENGE-003`.
- **`class`** — Pick the one that matches the defect:
  - `false-positive` — scan reports a finding that should not be one
    (e.g. a guard dominates the sink and scan missed it, or no
    model-controlled input reaches the sink on the analysed path).
  - `missed-sink` — scan reports clean on code that contains a real,
    agent-reachable consequential action it should have flagged.
  - `wrong-classification` — scan flags the right call but mis-states
    severity, category, guard dominance, or binding state in a way that
    misleads a reviewer.
- **`language`** — Must be one of `python`, `typescript`, or `go`.
  Submissions in other languages are out of scope; see COVERAGE.md
  "Language support" — unsupported files are reported as unsupported,
  never as clean, and that is documented coverage, not a miss.
- **`rule_id`** — Look it up in
  [`actenon_scan/rules/default_rules.json`](../actenon_scan/rules/default_rules.json)
  or the per-language sink family matrix in COVERAGE.md. For
  `missed-sink` cases where the rule does not exist yet, write the
  proposed rule ID and mark `class: missed-sink`.
- **`expected`** — What scan *should* say on this fixture. `finding`
  means it should flag; `no-finding` means it should report clean.
- **`evidence`** — The non-negotiable part. Cite the line in the fixture
  file, then in 1–3 sentences explain the defect. For
  `false-positive`, name the guard scan failed to honour and why it
  dominates. For `missed-sink`, name the agent boundary (e.g.
  `@mcp.tool`, `@tool`, `BaseTool._run`) and the sink, and explain why
  model-controlled input reaches it. For `wrong-classification`, name
  the field scan got wrong and what the correct value is.
- **`fixture_file`** — A minimal reproducing source file submitted in
  the same PR. Mirror the pattern in
  [`tests/challenge/CHALLENGE-001.go`](../tests/challenge/CHALLENGE-001.go):
  a single file, a comment header naming the challenge and the source,
  and the smallest code that reproduces the defect. Strip everything
  that is not load-bearing.

### YAML form (for the test fixture)

When the maintainer ports your submission into
`tests/challenge/CHALLENGE-NNN.yml`, it will look like this — keep
your submission structurally compatible:

```yaml
# Challenge case metadata.
# External submission. Credited to <github handle>.

issue: <github issue number, or 0 if PR-only>
submitter: <github handle, no leading @>
class: false-positive  # or missed-sink | wrong-classification
language: go           # or python | typescript
title: "<short description>"
description: >
  <1–3 sentence explanation of the defect, the agent boundary, the sink,
  and why scan's current output is wrong. Reference COVERAGE.md where
  relevant.>
expected: finding      # or no-finding
rule_id: <rule id, or proposed id for missed-sink>
status: open
note: >
  <optional maintainer note — what makes this distinct from existing
  open cases, what fixing it would require.>
```

---

## Submission checklist

Before opening the issue or PR, confirm:

- [ ] The fixture file is a single source file in Python, TypeScript,
      or Go.
- [ ] The fixture is **minimal** — every line is load-bearing for the
      defect. No imports of frameworks that are not exercised. No
      helper code that does not contribute to the finding.
- [ ] You ran `actenon-scan scan <fixture>` (or `uvx actenon-scan scan`)
      and the output you observed matches what you describe in
      `evidence`. Paste the exact command and the relevant output lines
      into the issue or PR description.
- [ ] You stated the **scanner version** (`actenon-scan --version` or
      the `uvx`-resolved version).
- [ ] You cited the **rule_id** correctly, or proposed a new one for a
      `missed-sink` case.
- [ ] You checked [`docs/COVERAGE.md`](../docs/COVERAGE.md) and the
      case is **not** already documented as NOT COVERED. Documented
      limitations (custom agent loops `r05`, action/observation dispatch
      `r06`, dynamic dispatch, parameter binding to assert-style
      guards, the per-file analysis limit without
      `--repository-analysis`) are out of scope — they are known and
      disclosed, not misses.
- [ ] You checked the existing open cases in
      [`docs/SOUNDNESS_CHALLENGE.md`](../docs/SOUNDNESS_CHALLENGE.md)
      and this is not a duplicate.
- [ ] You are not submitting under NDA or with disclosure restrictions
      — see [Disclosure](#disclosure) below.

---

## What we look for

We want adversarial cases that show scan **missing a real danger** or
**producing a false positive on benign code**. Concretely:

- A supported-language sink scan fails to flag, where model-controlled
  input provably reaches it from a recognised agent boundary
  (`@mcp.tool`, `@tool`, `BaseTool._run`, `@function_tool`,
  `setRequestHandler`, action/observation dispatch, raw tool-schema
  dispatch).
- A guard scan fails to honour, where the guard is in the recognised
  vocabulary in
  [`actenon_scan/detectors/guards.py`](../actenon_scan/detectors/guards.py)
  and dominates the sink on every path — and scan still reports the
  sink as unguarded.
- A finding scan produces on code with **no** model-controlled input on
  the analysed path, where the path is provably constant or
  server-configured (the shape of `CHALLENGE-001`).
- A finding where scan's guard-dominance analysis is wrong — the guard
  sits in a branch the sink does not share, and scan reports the sink
  as guarded anyway.
- A finding where scan's authority-binding analysis is wrong — it
  claims BOUND or UNBOUND where the opposite is true, in a way that
  would mislead a reviewer reading the report.

The prize cases are the ones we did not anticipate. If your fixture
exposes a class of defect not represented in `tests/challenge/` or
`tests/benchmark/soundness/`, say so explicitly in `evidence`.

---

## What we DON'T want

To keep the channel load-bearing, the following are out of scope:

- **Style nits.** Naming, formatting, idioms, docstrings, type
  annotations. Scan is not a linter.
- **Performance complaints.** Scan time on a fixture is not a
  soundness issue. Performance benchmarks live in
  `tests/benchmark/perf-fixture.json` and the README Performance
  section; regressions there are CI failures, not soundness
  challenges.
- **Suggestions for new rules without a defect.** "It would be nice
  if scan flagged X" is a feature request, not a soundness case. A
  soundness case requires a defect — scan says X where the truth is Y,
  on code that exists today.
- **Unsupported languages.** Rust, Java, C#, Ruby, PHP, etc. are
  documented as unsupported in COVERAGE.md. They are reported as
  unsupported, never as clean. Filing a challenge that "scan reports
  clean on my Rust repo" will be rejected as out of scope — the
  supported-languages list is the contract, not a bug.
- **Documented limitations filed as misses.** If COVERAGE.md already
  says scan does not do X (custom agent loops, dynamic dispatch,
  parameter binding to assert-style guards, per-file analysis without
  `--repository-analysis`), submitting "scan does not do X" is not a
  new finding. The disclosure is the finding.
- **Findings from a configuration scan does not support.** Custom
  guard names that `--guard` resolves, custom sinks registered via
  config, or fixtures excluded by `.actenon-scan.json` are not
  soundness defects — they are configuration the user controls.

Submissions in these categories will be closed as `wontfix` with a
pointer to the relevant section of COVERAGE.md.

---

## Response time

- **Acknowledgement within 30 days.** Every submission receives a
  public first response within 30 days — even if only to say
  "received, triage queued". We will not silently ignore submissions.
  If 30 days pass with no response, ping the issue; that itself is a
  process bug we want to hear about.
- **Triage outcome.** After acknowledgement, the submission moves to
  `accepted`, `rejected` (with reason), or `wontfix` (documented
  limitation). Accepted cases are added to the scoreboard in
  [`docs/SOUNDNESS_CHALLENGE.md`](../docs/SOUNDNESS_CHALLENGE.md)
  immediately — **before** they are fixed. The open misses are the
  point of the scoreboard.
- **Fix timeline.** Accepted cases are not promised a fix timeline.
  Some may be fixed in the next release; some may stay open for
  months while the underlying detector is reworked; some may never be
  fixed and remain visible as known limitations. What we promise is
  visibility, not a closure date.
- **Credit.** The submitter's GitHub handle is recorded in both the
  scoreboard and the fixture file when the case is accepted, and stays
  there when the case is fixed.

---

## Disclosure

<a name="disclosure"></a>

Submissions are **public by default**. The fixture file, the metadata,
and the triage discussion all live in this repository. This is the
opposite of a private vulnerability disclosure — the entire point of
the channel is to make scan's blind spots visible to anyone who reads
the scoreboard.

If your fixture is derived from a real codebase and you do not want
that codebase named, that is fine — strip it down to a minimal
reproducing fixture that does not identify the source (as
`CHALLENGE-001.go` is derived from `anthropic-sdk-go` but does not
name it in the fixture body). The maintainer will preserve your
anonymisation.

If your fixture is itself a vulnerability in a third-party codebase,
**do not submit it here** — report it to that codebase under their
security policy. This channel is for defects in **scan's analysis**,
not for vulnerabilities in scanned code. See
[`SECURITY.md`](../SECURITY.md) for the boundary between the two.

Reporter credit is given by GitHub handle. We will not publish a name
you did not provide. If you submit anonymously, say so in
`submitted_by` and we will record the case as `submitted_by:
anonymous`.

---

## Lifecycle

```
       submitted
           │
           ▼
     acknowledged (≤ 30 days)
           │
           ▼
        triaged
           │
   ┌───────┼───────┐
   ▼       ▼       ▼
accepted rejected wontfix
   │       │       │
   ▼       │       │
added to scoreboard  │
(open miss visible) │
   │       │       │
   ▼       │       │
fixture ported to   │
tests/challenge/    │
(expected-to-fail)  │
   │       │       │
   ▼       │       │
fixed     │       │
   │       │       │
   ▼       │       │
fixture flipped to  │
expected-to-pass    │
(regression test)    │
```

The scoreboard at
[`docs/SOUNDNESS_CHALLENGE.md`](../docs/SOUNDNESS_CHALLENGE.md) is
regenerated by `scripts/generate_soundness_scoreboard.py` from the
`tests/challenge/CHALLENGE-NNN.yml` files. Adding a case is therefore
a one-file change: drop the YAML, drop the fixture, regenerate the
scoreboard, open the PR.
