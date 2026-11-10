# From a Scan finding to runtime control with Airlock

**Discover with Scan. Protect and verify with Airlock. Built on Permit, Kernel and Protocol.**

Scan is a static analyser. It is complete on its own: no account, no runtime, no Actenon
dependency. This page is for the case where a finding makes you want *runtime* control over one
action as well. It covers what Scan suggests, what Airlock actually does today, and what it
does not do yet.

## What a Scan finding means

A finding says that model-controlled input reaches a consequential call (one that changes,
deletes, sends, deploys or spends) and that Scan found no recognised dominating authority check on
the analysed path. A finding is **not**:

- proof of an exploitable vulnerability;
- proof that no guard exists elsewhere (a gateway, a framework hook, an external policy);
- proof that the agent is externally reachable.

Scan also reports what it could *not* analyse: unsupported languages, unfollowed dynamic calls and
excluded files. See [COVERAGE.md](COVERAGE.md). Silence never implies safety.

## Two ways to remediate

| | 1. Repository-native guard (default) | 2. Actenon Airlock (optional) |
|---|---|---|
| Command | `actenon-scan fix <file:line>` | `airlock init` → `airlock init --approve` → `airlock run` |
| What it adds | An authorisation check in your own code, using your own convention | A runtime broker that blocks the action until you approve its exact target, then refuses calls outside it, with signed receipts |
| Dependencies | None | Airlock (pre-release, Python 3.11+) |
| Credentials | Unchanged | Airlock holds `GITHUB_TOKEN`; the agent process receives an opaque handle |
| Languages | Python, TypeScript, Go | Python only |
| Verifies the outcome on the provider | No | Not in Local Mode (see [Verified GitHub file creation](#verified-github-file-creation)) |

Scan's own fix stays the default. Scan never installs Airlock, never imports it and never approves
anything.

## When Scan suggests Airlock

Only when **all** of these hold:

- the most-exposed finding is in a **Python** file;
- Scan's authority extraction (`actenon_scan.authority`, the same evidence Airlock compiles its
  runtime authority from) identifies the call as **`github.contents.write`**, for example PyGithub's
  `Repository.create_file`;
- you ran a directory scan (`actenon-scan scan <dir>`) with the default human-readable output, or
  `actenon-scan explain`.

For anything else (HTTP calls, other GitHub actions such as issues or pull requests, shell commands,
databases, payments, TypeScript or Go findings) Scan prints **no** Airlock suggestion. Airlock may
intercept some of those, but this handoff has not been checked end to end for them, so Scan does
not recommend it. JSON, SARIF, Markdown, HTML and list output never contain the suggestion.

## What Airlock does with the finding

What happens depends on whether Scan could resolve **which repository** the write goes to:

| Scan's target | Airlock's behaviour | What Scan prints |
|---|---|---|
| Fixed in code or `.env` (`RESOLVED`), e.g. `github.com/acme/release-notes` | `airlock init` shows the exact power and grants nothing. `airlock init --approve` approves it. `airlock run` allows that power and denies anything outside it. | review → approve → run |
| Chosen by the model (a tool parameter) | Airlock will not approve a write whose target the model chooses. The call stays blocked even after approval. | "Not yet", plus how to fix the target first |
| Unresolved (computed at runtime) or a template | Stays blocked even after approval. | "Not yet", plus how to fix the target first |

A model-chosen target is the most common case in real MCP and tool code. The honest answer is that
Airlock cannot help with it as written: either add a repository-native guard, or fix the
repository in code or configuration so a human can approve exactly that repository.

## Walkthrough (checked 2026-11-05, macOS arm64, clean environment, no real credentials)

A small MCP server lets an agent publish release notes. As first written, the model picks the
repository:

```python
@mcp.tool()
def publish_release_notes(repo: str, path: str, content: str, message: str) -> str:
    repository = gh.get_repo(repo)
    result = repository.create_file(path, message, content, branch="main")
```

`uvx actenon-scan scan .` reports:

```text
Most exposed: app/server.py:15  create_file()
  Consequence:               REPOSITORY
  Target:                    repository chosen by the model (parameter `repo` of tool `publish_release_notes`)
  Model-controlled inputs:   path, message, content
...
Next:
  uvx actenon-scan explain app/server.py:15  # show the analysed path
  uvx actenon-scan fix app/server.py:15      # default remediation: a repository-native guard

Optional: enforce it at runtime with Actenon Airlock (pre-release; Python; Local Mode)
  Not yet: the model chooses the repository, and Airlock will not approve a write
  whose target the model chooses. It keeps this call blocked, even after approval.
```

Fix the repository in code (`RELEASE_REPO = "acme/release-notes"`; `gh.get_repo(RELEASE_REPO)`)
and scan again. Scan now prints the exact power and the commands. Run them in the agent's own
Python environment (its dependencies must be installed there):

```console
$ pip install "git+https://github.com/Actenon/actenon-airlock.git"
$ airlock init --command app/server.py
+ github.contents.write @ github.com/acme/release-notes
  Scope: GitHub contents.write on github.com/acme/release-notes through https://api.github.com
+ github.repo.read @ github.com/acme/release-notes
! github.repo.read (app/server.py:23): Unresolved or template authority remains blocked
Runtime: BLOCKED UNTIL APPROVED
$ airlock init --approve --command app/server.py
Approved 2 powers. Unresolved powers remain blocked; their calls are denied at runtime with signed receipts.
$ airlock run -- app/server.py        # the server's normal launch command, now under Airlock
```

In the check, an MCP client initialised the server, listed its tools, and called the second tool
with `repo="someone-else/private"`. Airlock refused the call before it reached the network:

```text
AIRLOCK DENY github.repo.read @ https://api.github.com/repos/someone-else/private: out of scope
  reason: out of scope | no credential released | not executed
```

Measured in that clean environment: Scan from a cold `uvx` cache took under 5 s to the first
finding. Installing Airlock from GitHub took about 21 s. Review, approval and the refused call took
about 2 s. That makes four commands after the scan. These are command times, not the time a person
needs to read and decide. No independent developer has been timed yet.

Only `GITHUB_TOKEN`, `GH_TOKEN`, `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` are brokered by default.
Keep the token in the shell that runs `airlock`: the agent process sees an opaque handle, not the
token. Other credentials need an explicit `--credential NAME=https://origin` binding at approval
time (see the Airlock README).

## What Local Mode does not do

- **It does not verify the outcome on GitHub.** A response from GitHub is recorded as `AMBIGUOUS`,
  never as committed, and the effect stays held so a blind retry is refused.
- **It is not a sandbox.** Local Mode is cooperative interception inside the agent's own Python
  process. It protects a cooperative agent from unintended powers. It does not protect against
  hostile code, native extensions or an attacker who controls the same user account. Use
  Protected Mode (a container boundary) for that threat model.
- **It is not a generic MCP wrapper.** The walkthrough works because Airlock analysed *this
  server's own Python source* and approved the powers it found. Airlock cannot vouch for an
  arbitrary MCP server, which may hold standing credentials or reach services by other routes.

## Verified GitHub file creation

Independent outcome verification exists for one consequence: creating one precisely reviewed file
through GitHub's Contents API, in **Protected Mode**. It needs:

- Docker and the Protected Mode candidate image;
- a reviewed profile naming the repository's numeric and node IDs, the branch, the path, the commit
  message, the content's SHA-256 and the expected parent commit;
- a separately approved operator key outside the project;
- a repository-scoped token held only by the supervisor, and no other writer on the target branch
  during creation and readback.

The supervisor makes at most one write. A lost or uncertain response stays `AMBIGUOUS`. Only an
independent readback of the exact provider state can settle it. This is materially more setup than
the Local Mode walkthrough, and it is still a development candidate. See Airlock's
[GitHub consequence profile](https://github.com/Actenon/actenon-airlock/blob/main/docs/github-consequence.md)
and [Protected Mode](https://github.com/Actenon/actenon-airlock/blob/main/docs/protected-mode.md).

## Status

- Airlock is **not published to a package registry**. The install command above follows its default
  branch. For repeatable testing, pin an exact reviewed commit:
  `pip install "git+https://github.com/Actenon/actenon-airlock.git@<commit>"`.
- Supported by this handoff: Python, `github.contents.write`, Local Mode enforcement.
- Not supported by this handoff: TypeScript and Go agents, other GitHub actions, arbitrary HTTP
  APIs, databases, payments and cloud APIs, and outcome verification outside the Protected Mode
  profile above.
