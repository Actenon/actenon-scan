#!/usr/bin/env python3
"""Actenon Scan's pre-publication release gate.

Adapted from actenon-protocol's scripts/release_gate.py (the shared Actenon
gate), with Permit/Kernel's registry-input safeguard and the controls Scan's
own release history lacked: before this gate, any ``v*`` tag (or a manual
dispatch) built and uploaded with a long-lived API token, with no check that
the commit was on main or that CI had passed on it.

Single source of truth: .github/required-checks.json
  {
    "repository": "Actenon/actenon-scan",
    "package": "actenon-scan",
    "branch": "main",
    "pull_request": [<check-run names required to merge>],
    "release": [<check-run names that must have succeeded on the tagged commit>],
    "producers": {<check-run name>: <workflow file that must produce it>}
  }

Modes
  validate          The contract is well formed and keeps every mandatory release
                    check; each required name is produced by exactly one job, in the
                    workflow it is bound to, which runs unfiltered on every pull
                    request and cannot be skipped or soft-failed; and publish.yml is
                    fail-closed (publish_workflow_problems). CI job "Required-check
                    names exist" runs this, and ``gate`` runs it again on the tagged
                    commit.
  gate              First job of publish.yml. Refuses unless: the run is a tag push;
                    the tag is exactly v<version> for the pyproject version; the
                    checkout and the tag are the run's commit; no candidate source
                    pin remains; the contract validates; the commit is on
                    origin/main; every "release" check's latest run on that exact
                    commit succeeded, was reported by GitHub Actions and came from
                    its bound workflow; and the repository's release controls (main
                    protection, release-tag ruleset, reviewed pypi environment) are
                    in force. Any unreadable state is a refusal, never a pass.
  dist              The build output is exactly the wheel and sdist for VERSION, with
                    matching metadata. --write-sums records their SHA-256 (the
                    approved artifacts); --check-sums verifies against a record.
  verify-pypi       After publication: PyPI's files for VERSION are exactly the
                    approved artifacts (names and SHA-256), none yanked, each with a
                    trusted-publishing attestation from this repository's
                    publish.yml in the pypi environment whose subject is that file.
  verify-installed  A clean install from PyPI is the approved wheel: pip's install
                    report names one distribution with the approved hash, and every
                    installed package file equals the wheel's bytes.
  print-protection | print-tag-rulesets | print-environment
                    The settings an owner applies (docs/RELEASE_CHECKLIST.md).
"""

from __future__ import annotations

import argparse
import base64
import email.parser
import fnmatch
import hashlib
import io
import itertools
import json
import os
import re
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - CI installs pyyaml
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = Path(".github") / "required-checks.json"
PUBLISH_WORKFLOW = "publish.yml"
GITHUB_ACTIONS_APP_ID = 15368
GITHUB_ACTIONS_SLUG = "github-actions"
ENVIRONMENT = "pypi"
RELEASE_TAG_PATTERN = "v*.*.*"  # never matches the moving Action tag "v1"
EXPR = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_.-]+)\s*\}\}")
SHA_RE = re.compile(r"[0-9a-f]{40}")
RELEASE_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
PINNED_USES = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
CANDIDATE_CONSTRAINTS = Path(".github") / "candidate-constraints.txt"

# The release floor. The contract may add checks but can never drop one of these
# without editing this code-owned gate: functional tests on every supported
# Python, the zero-dependency base install, architecture conformance, the built
# wheel, Protocol drift, detection quality, performance, the self-scan, README
# claims, and the contract/publish-workflow validation itself.
MANDATORY_RELEASE_CHECKS = frozenset({
    "test (3.10)",
    "test (3.11)",
    "test (3.12)",
    "Base install (no extras) — zero-dep guarantee",
    "Required AREF-002A/002B/002C proof-model conformance",
    "Built wheel installs and scans a directory",
    "drift-gate (3.10)",
    "drift-gate (3.11)",
    "drift-gate (3.12)",
    "Recall / Precision / Soundness",
    "Default mode is never slower than serial",
    "sarif",
    "Verify README claims (machine-enforced)",
    "Required-check names exist",
})

PUBLISH_JOBS = ("release-gate", "build", "publish", "verify-registry")
SOFT_PASS = ("always()", "failure()", "cancelled()", "continue-on-error")


def error(msg: str) -> None:
    print(f"::error::{msg}")


# --------------------------------------------------------------------------- #
# Contract and workflow validation
# --------------------------------------------------------------------------- #

def load_contract(root: Path = ROOT) -> dict[str, Any]:
    return json.loads((root / CONTRACT).read_text(encoding="utf-8"))


def _triggers(doc: dict) -> Any:
    # PyYAML reads the bare key `on` as boolean True.
    return doc.get("on", doc.get(True))


def load_workflows(root: Path = ROOT) -> dict[str, dict]:
    if yaml is None:
        sys.exit("release_gate: pyyaml is required (pip install pyyaml)")
    return {
        wf.name: (yaml.safe_load(wf.read_text(encoding="utf-8")) or {})
        for wf in sorted((root / ".github" / "workflows").glob("*.y*ml"))
    }


def _matrix_rows(matrix: Any) -> list[dict]:
    if not isinstance(matrix, dict):
        return [{}]
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude") and isinstance(v, list)}
    rows = [dict(zip(axes, combo)) for combo in itertools.product(*axes.values())] if axes else [{}]
    for extra in matrix.get("include", []) or []:
        rows.append(dict(extra))
    excludes = matrix.get("exclude", []) or []
    return [r for r in rows if not any(all(r.get(k) == v for k, v in ex.items()) for ex in excludes)]


def produced_check_names(workflows: dict[str, dict]) -> dict[str, list[tuple[str, str]]]:
    """check-run name -> [(workflow file, job id)] for every job in every workflow."""
    names: dict[str, list[tuple[str, str]]] = {}
    for wf_name, doc in workflows.items():
        for job_id, job in (doc.get("jobs") or {}).items():
            job = job or {}
            explicit = "name" in job
            template = str(job.get("name", job_id))
            for row in _matrix_rows((job.get("strategy") or {}).get("matrix")):
                if explicit or not row:
                    name = EXPR.sub(lambda m, row=row: str(row.get(m.group(1), m.group(0))), template)
                else:
                    # GitHub names an unnamed matrix job "<job id> (<values>, ...)".
                    name = f"{job_id} ({', '.join(str(v) for v in row.values())})"
                names.setdefault(name, []).append((wf_name, job_id))
    return names


def _pull_request_trigger(doc: dict) -> tuple[bool, dict]:
    on = _triggers(doc)
    if isinstance(on, dict):
        return "pull_request" in on, on.get("pull_request") or {}
    if isinstance(on, list):
        return "pull_request" in on, {}
    return on == "pull_request", {}


def _required_job_problems(name: str, wf_name: str, doc: dict, job_id: str, branch: str) -> list[str]:
    problems = []
    runs_on_pr, pr = _pull_request_trigger(doc)
    if not runs_on_pr:
        problems.append(f"{name!r}: {wf_name} does not run on pull_request, so it cannot gate a merge")
    elif {"paths", "paths-ignore", "branches-ignore"} & set(pr) or (
            "branches" in pr and branch not in (pr.get("branches") or [])):
        problems.append(f"{name!r}: {wf_name} filters pull_request runs; a filtered check is never "
                        f"produced on some commits and cannot be required")
    job = (doc.get("jobs") or {}).get(job_id) or {}
    if "if" in job:
        problems.append(f"{name!r}: job {job_id} in {wf_name} has a job-level 'if' and can be skipped")
    if job.get("continue-on-error") or any((s or {}).get("continue-on-error") for s in job.get("steps") or []):
        problems.append(f"{name!r}: job {job_id} in {wf_name} uses continue-on-error and can pass while failing")
    return problems


def contract_problems(cfg: dict[str, Any], workflows: dict[str, dict]) -> list[str]:
    problems: list[str] = []
    for key, kind in (("repository", str), ("package", str), ("branch", str),
                      ("pull_request", list), ("release", list), ("producers", dict)):
        if not isinstance(cfg.get(key), kind) or not cfg.get(key):
            problems.append(f"required-checks.json: {key!r} must be a non-empty {kind.__name__}")
    if problems:
        return problems
    for kind in ("pull_request", "release"):
        names = cfg[kind]
        if not all(isinstance(n, str) and n for n in names):
            problems.append(f"required-checks.json {kind}: every entry must be a non-empty string")
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            problems.append(f"required-checks.json {kind}: duplicate names {dupes}")
    missing = sorted(MANDATORY_RELEASE_CHECKS - set(cfg["release"]))
    if missing:
        problems.append(f"required-checks.json release: mandatory release checks missing: {missing}")
    unmerged = sorted(set(cfg["release"]) - set(cfg["pull_request"]))
    if unmerged:
        problems.append(f"required-checks.json: release checks not required to merge: {unmerged}")
    produced = produced_check_names(workflows)
    required = set(cfg["pull_request"]) | set(cfg["release"])
    for name in sorted(required):
        sources = produced.get(name, [])
        bound = cfg["producers"].get(name)
        if not sources:
            problems.append(f"required-checks.json: no job produces a check named {name!r}")
        elif len(sources) > 1:
            problems.append(f"required-checks.json: {name!r} is produced by several jobs {sources}; "
                            f"a required name must be unambiguous")
        elif bound is None:
            problems.append(f"required-checks.json producers: {name!r} is not bound to a workflow")
        elif sources[0][0] != bound:
            problems.append(f"required-checks.json producers: {name!r} is bound to {bound} "
                            f"but produced by {sources[0][0]}")
        else:
            problems += _required_job_problems(name, bound, workflows[bound], sources[0][1], cfg["branch"])
    stale = sorted(set(cfg["producers"]) - required)
    if stale:
        problems.append(f"required-checks.json producers: entries for names that are not required: {stale}")
    return problems


def _steps_text(job: dict) -> str:
    return "\n".join(str((s or {}).get("run", "")) for s in job.get("steps") or [])


def publish_workflow_problems(workflows: dict[str, dict]) -> list[str]:
    """The publish route cannot be reached except through the gate."""
    problems: list[str] = []
    doc = workflows.get(PUBLISH_WORKFLOW)
    if doc is None:
        return [f"{PUBLISH_WORKFLOW} is missing"]
    on = _triggers(doc)
    if not (isinstance(on, dict) and set(on) == {"push"} and isinstance(on["push"], dict)
            and set(on["push"]) == {"tags"} and on["push"]["tags"] == [RELEASE_TAG_PATTERN]):
        problems.append(f"{PUBLISH_WORKFLOW} must trigger only on push of tags [{RELEASE_TAG_PATTERN!r}] "
                        f"(no workflow_dispatch, branches or other events); found {on!r}")
    if doc.get("permissions") != {}:
        problems.append(f"{PUBLISH_WORKFLOW} must set top-level 'permissions: {{}}'")
    jobs = doc.get("jobs") or {}
    if set(jobs) != set(PUBLISH_JOBS):
        problems.append(f"{PUBLISH_WORKFLOW} jobs must be exactly {list(PUBLISH_JOBS)}; found {sorted(jobs)}")
        return problems
    raw = json.dumps(doc)
    if "secrets." in raw or "PYPI_API_TOKEN" in raw or '"password"' in raw:
        problems.append(f"{PUBLISH_WORKFLOW} must not use secrets or a password: trusted publishing only")
    for job_id, job in jobs.items():
        job = job or {}
        for step in job.get("steps") or []:
            uses = (step or {}).get("uses")
            if uses and not PINNED_USES.match(uses):
                problems.append(f"{PUBLISH_WORKFLOW} {job_id}: action {uses!r} is not pinned to a commit SHA")
        if job.get("continue-on-error") or any((s or {}).get("continue-on-error") for s in job.get("steps") or []):
            problems.append(f"{PUBLISH_WORKFLOW} {job_id}: continue-on-error is not allowed")
        cond = str(job.get("if", ""))
        if any(word in cond for word in SOFT_PASS):
            problems.append(f"{PUBLISH_WORKFLOW} {job_id}: condition {cond!r} can run after a failure")
        perms = job.get("permissions") or {}
        if job_id != "publish" and perms.get("id-token"):
            problems.append(f"{PUBLISH_WORKFLOW} {job_id}: only the publish job may request id-token")
        if job_id != "publish" and job.get("environment"):
            problems.append(f"{PUBLISH_WORKFLOW} {job_id}: only the publish job may use an environment")

    def needs(job_id: str) -> set[str]:
        n = jobs[job_id].get("needs") or []
        return {n} if isinstance(n, str) else set(n)

    gate_job = jobs["release-gate"]
    if not re.search(r"scripts/release_gate\.py gate\b", _steps_text(gate_job)):
        problems.append(f"{PUBLISH_WORKFLOW} release-gate: must run 'scripts/release_gate.py gate'")
    if "if" in gate_job or needs("release-gate"):
        problems.append(f"{PUBLISH_WORKFLOW} release-gate: must run unconditionally, first")
    if "release-gate" not in needs("build"):
        problems.append(f"{PUBLISH_WORKFLOW} build: must need release-gate")
    if not re.search(r"scripts/release_gate\.py dist\b.*--write-sums", _steps_text(jobs["build"])):
        problems.append(f"{PUBLISH_WORKFLOW} build: must record the approved artifacts with 'release_gate.py dist --write-sums'")
    pub = jobs["publish"]
    if not {"release-gate", "build"} <= needs("publish"):
        problems.append(f"{PUBLISH_WORKFLOW} publish: must need release-gate and build")
    cond = str(pub.get("if", ""))
    for clause in ("github.event_name == 'push'", "startsWith(github.ref, 'refs/tags/v')",
                   "needs.release-gate.result == 'success'", "needs.build.result == 'success'"):
        if clause not in cond:
            problems.append(f"{PUBLISH_WORKFLOW} publish: condition must include {clause!r}")
    if "||" in cond:
        problems.append(f"{PUBLISH_WORKFLOW} publish: condition must not contain '||'")
    env = pub.get("environment")
    env_name = env.get("name") if isinstance(env, dict) else env
    if env_name != ENVIRONMENT:
        problems.append(f"{PUBLISH_WORKFLOW} publish: must deploy through the {ENVIRONMENT!r} environment")
    if (pub.get("permissions") or {}) != {"id-token": "write"}:
        problems.append(f"{PUBLISH_WORKFLOW} publish: permissions must be exactly {{id-token: write}}")
    steps = pub.get("steps") or []
    publish_idx = [i for i, s in enumerate(steps) if str((s or {}).get("uses", "")).startswith("pypa/gh-action-pypi-publish@")]
    verify_idx = [i for i, s in enumerate(steps) if "SHA256SUMS" in str((s or {}).get("run", ""))]
    if len(publish_idx) != 1:
        problems.append(f"{PUBLISH_WORKFLOW} publish: must have exactly one pypa/gh-action-pypi-publish step")
    elif not verify_idx or min(verify_idx) > publish_idx[0]:
        problems.append(f"{PUBLISH_WORKFLOW} publish: the approved artifacts must be verified before upload")
    elif (steps[publish_idx[0]].get("with") or {}).get("attestations") is False:
        problems.append(f"{PUBLISH_WORKFLOW} publish: attestations must not be disabled")
    ver = jobs["verify-registry"]
    if "publish" not in needs("verify-registry"):
        problems.append(f"{PUBLISH_WORKFLOW} verify-registry: must need publish")
    vtext = _steps_text(ver)
    for needle, what in (("release_gate.py verify-pypi", "check PyPI against the approved artifacts"),
                         ("--require-hashes", "install from PyPI with the approved hashes"),
                         ("release_gate.py verify-installed", "compare the installed package to the approved wheel"),
                         ("actenon-scan scan", "run a real scan with the installed package"),
                         ("check_version_coherence.py --mode release", "assert pyproject, tag and PyPI agree")):
        if needle not in vtext:
            problems.append(f"{PUBLISH_WORKFLOW} verify-registry: must {what} ({needle!r})")
    for wf_name, other in workflows.items():
        if wf_name == PUBLISH_WORKFLOW:
            continue
        text = json.dumps(other)
        if "gh-action-pypi-publish" in text or "twine upload" in text or "PYPI_API_TOKEN" in text:
            problems.append(f"{wf_name}: a second PyPI publishing route bypasses the release gate")
        if '"id-token": "write"' in text:
            problems.append(f"{wf_name}: requests id-token: write; only {PUBLISH_WORKFLOW} may mint an OIDC token")
        for job in (other.get("jobs") or {}).values():
            env = (job or {}).get("environment")
            if (env.get("name") if isinstance(env, dict) else env) == ENVIRONMENT:
                problems.append(f"{wf_name}: deploys to the {ENVIRONMENT!r} environment outside {PUBLISH_WORKFLOW}")
    return problems


def validate_problems(root: Path = ROOT) -> list[str]:
    workflows = load_workflows(root)
    return contract_problems(load_contract(root), workflows) + publish_workflow_problems(workflows)


def validate(root: Path = ROOT) -> int:
    problems = validate_problems(root)
    for p in problems:
        error(p)
    if problems:
        return 1
    cfg = load_contract(root)
    print(f"required-checks.json OK: {len(cfg['pull_request'])} PR checks, {len(cfg['release'])} release "
          f"checks, each produced by its bound workflow; {PUBLISH_WORKFLOW} is fail-closed")
    return 0


# --------------------------------------------------------------------------- #
# Registry-input safeguard
# --------------------------------------------------------------------------- #

def _all_requirements(project: dict) -> list[str]:
    reqs = list(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        reqs += list(extra or [])
    return reqs


def source_pin_problems(root: Path = ROOT) -> list[str]:
    """A release is built and tested only from registry inputs."""
    problems = []
    if (root / CANDIDATE_CONSTRAINTS).exists():
        problems.append(f"registry release refuses coordinated source pins: {CANDIDATE_CONSTRAINTS} exists. "
                        f"Publish and verify the canonical Protocol, delete the file and its PIP_CONSTRAINT "
                        f"lines, and rerun the required checks on the new commit first")
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    if (data.get("tool") or {}).get("uv", {}).get("sources"):
        problems.append("registry release refuses tool.uv.sources overrides")
    for req in _all_requirements(data.get("project") or {}):
        if re.search(r"(^|\s)@\s*\S+://|git\+", req.split(";")[0]):
            problems.append(f"registry release refuses a direct-reference requirement: {req!r}")
    lock = root / "uv.lock"
    if lock.exists() and re.search(r"source = \{ (git|url|path|directory) = ", lock.read_text(encoding="utf-8")):
        problems.append("registry release refuses non-registry sources in uv.lock")
    for wf in sorted((root / ".github" / "workflows").glob("*.y*ml")):
        text = wf.read_text(encoding="utf-8")
        if "PIP_CONSTRAINT" in text or "git+https://" in text:
            problems.append(f"registry release refuses candidate inputs in {wf.name} (PIP_CONSTRAINT or git+ URL)")
    return problems


# --------------------------------------------------------------------------- #
# GitHub state
# --------------------------------------------------------------------------- #

class GitHubAPI:
    def __init__(self, token: str, api: str = "https://api.github.com") -> None:
        self.token, self.api = token, api

    def get(self, path: str) -> Any:
        req = urllib.request.Request(
            f"{self.api}/{path}",
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


def _paged(github: Any, path: str, key: str) -> list[dict]:
    items: list[dict] = []
    sep = "&" if "?" in path else "?"
    for page in itertools.count(1):
        batch = github.get(f"{path}{sep}per_page=100&page={page}")
        got = batch.get(key) if isinstance(batch, dict) else None
        if not isinstance(got, list):
            raise ValueError(f"unexpected response for {path}: no {key!r} list")
        items += got
        if len(got) < 100 or page >= 50:
            return items
    return items  # pragma: no cover


def check_problems(github: Any, repo: str, sha: str, cfg: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    try:
        runs = _paged(github, f"repos/{repo}/actions/runs?head_sha={sha}", "workflow_runs")
    except Exception as exc:  # unreadable state is a refusal
        return [f"could not list workflow runs for {sha}: {exc}"]
    suite_path = {r.get("check_suite_id"): str(r.get("path", "")).split("@")[0] for r in runs
                  if r.get("head_sha") == sha}
    for name in cfg["release"]:
        want = f".github/workflows/{cfg['producers'][name]}"
        try:
            check_runs = _paged(github, f"repos/{repo}/commits/{sha}/check-runs?filter=latest&"
                                        f"check_name={urllib.parse.quote(name)}", "check_runs")
        except Exception as exc:
            problems.append(f"could not read check {name!r} on {sha}: {exc}")
            continue
        check_runs = [r for r in check_runs if r.get("name") == name]
        if not check_runs:
            problems.append(f"required check {name!r} never ran on {sha}")
            continue
        for r in check_runs:
            app = (r.get("app") or {}).get("slug")
            path = suite_path.get((r.get("check_suite") or {}).get("id"))
            if app != GITHUB_ACTIONS_SLUG:
                problems.append(f"required check {name!r} on {sha} was reported by {app!r}, not GitHub Actions")
            elif r.get("head_sha") != sha:
                problems.append(f"required check {name!r} belongs to {r.get('head_sha')}, not {sha}")
            elif path != want:
                problems.append(f"required check {name!r} on {sha} came from {path or 'an unknown workflow'}, "
                                f"not {want}")
            elif r.get("status") != "completed" or r.get("conclusion") != "success":
                problems.append(f"required check {name!r} on {sha}: {r.get('status')}/{r.get('conclusion')}")
    return problems


def controls_problems(github: Any, repo: str, cfg: dict[str, Any], tag: str) -> list[str]:
    """Main protection, immutable owner-created release tags, and a reviewed pypi environment."""
    problems: list[str] = []
    branch = cfg["branch"]
    try:
        protection = (github.get(f"repos/{repo}/branches/{branch}") or {}).get("protection") or {}
        status = protection.get("required_status_checks") or {}
        if not protection.get("enabled"):
            problems.append(f"{branch} is not protected")
        if status.get("enforcement_level") != "everyone":
            problems.append(f"{branch} protection does not apply its required checks to administrators")
        bound = {c.get("context") for c in status.get("checks") or [] if c.get("app_id") == GITHUB_ACTIONS_APP_ID}
        unbound = sorted(set(cfg["pull_request"]) - bound)
        if unbound:
            problems.append(f"{branch} protection does not require these checks from GitHub Actions: {unbound}")
    except Exception as exc:
        problems.append(f"could not read {branch} protection: {exc}")
    ref = f"refs/tags/{tag}"
    try:
        seen = {"creation": False, "update": False, "deletion": False}
        for summary in github.get(f"repos/{repo}/rulesets?targets=tag&includes_parents=true") or []:
            # includes_parents: an organisation-level ruleset is listed here too, and its detail
            # is readable through the repository only with this flag.
            rs = github.get(f"repos/{repo}/rulesets/{summary['id']}?includes_parents=true")
            if rs.get("target") != "tag" or rs.get("enforcement") != "active":
                continue
            cond = (rs.get("conditions") or {}).get("ref_name") or {}
            if not any(fnmatch.fnmatchcase(ref, p) for p in cond.get("include") or []) or any(
                    fnmatch.fnmatchcase(ref, p) for p in cond.get("exclude") or []):
                continue
            for rule in rs.get("rules") or []:
                if rule.get("type") in seen:
                    seen[rule["type"]] = True
        absent = [k for k, v in seen.items() if not v]
        if absent:
            problems.append(f"no active tag ruleset restricts {absent} for {ref}")
    except Exception as exc:
        problems.append(f"could not read tag rulesets: {exc}")
    try:
        env = github.get(f"repos/{repo}/environments/{ENVIRONMENT}")
        rules = env.get("protection_rules") or []
        reviewers = [rv for r in rules if r.get("type") == "required_reviewers" for rv in r.get("reviewers") or []]
        if not reviewers:
            problems.append(f"environment {ENVIRONMENT!r} has no required reviewers")
        if env.get("can_admins_bypass") is not False:
            problems.append(f"environment {ENVIRONMENT!r} lets administrators bypass its reviewers")
        policy = env.get("deployment_branch_policy") or {}
        if not policy.get("custom_branch_policies"):
            problems.append(f"environment {ENVIRONMENT!r} does not restrict which refs may deploy")
        else:
            refs = _paged(github, f"repos/{repo}/environments/{ENVIRONMENT}/deployment-branch-policies",
                          "branch_policies")
            if not refs or any(p.get("type") != "tag" for p in refs):
                problems.append(f"environment {ENVIRONMENT!r} must allow deployments from release tags only")
            elif not any(fnmatch.fnmatchcase(tag, p.get("name", "")) for p in refs):
                problems.append(f"environment {ENVIRONMENT!r} does not allow deployments from {tag}")
    except Exception as exc:
        problems.append(f"could not read environment {ENVIRONMENT!r}: {exc}")
    return problems


def _git(args: list[str], root: Path = ROOT) -> tuple[int, str]:
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip()


def version_from(path: Path) -> str:
    return tomllib.loads(path.read_text(encoding="utf-8"))["project"]["version"]


def gate(version: str, tag_prefix: str = "v", *, root: Path = ROOT, env: dict[str, str] | None = None,
         github: Any = None, git: Callable[[list[str]], tuple[int, str]] | None = None,
         validator: Callable[[Path], list[str]] = validate_problems) -> int:
    env = dict(os.environ) if env is None else env
    git = git or (lambda args: _git(args, root))

    def refuse(*msgs: str) -> int:
        for m in msgs:
            error(m)
        return 1

    event = env.get("GITHUB_EVENT_NAME", "")
    if event != "push":
        return refuse(f"publishing runs only on a release-tag push; this is a {event or 'unknown'!r} event")
    if not RELEASE_VERSION_RE.fullmatch(version):
        return refuse(f"version {version!r} is not a final X.Y.Z release")
    tag = f"{tag_prefix}{version}"
    expected_ref = f"refs/tags/{tag}"
    ref = env.get("GITHUB_REF", "")
    if ref != expected_ref:
        return refuse(f"publishing requires the tag {expected_ref}; this run is for {ref or '<no ref>'}")
    sha = env.get("GITHUB_SHA", "")
    if not SHA_RE.fullmatch(sha):
        return refuse(f"GITHUB_SHA {sha!r} is not a commit id")
    cfg = load_contract(root)
    repo = env.get("GITHUB_REPOSITORY", "")
    if repo != cfg.get("repository"):
        return refuse(f"this run is in {repo or '<unknown>'}, not {cfg.get('repository')}")
    rc, head = git(["rev-parse", "HEAD"])
    if rc or head != sha:
        return refuse(f"the checkout ({head or 'unreadable'}) is not the run's commit {sha}")
    rc, target = git(["rev-parse", f"{expected_ref}^{{commit}}"])
    if rc or target != sha:
        return refuse(f"{expected_ref} resolves to {target or 'nothing'}, not {sha}")
    pins = source_pin_problems(root)
    if pins:
        return refuse(*pins)
    invalid = validator(root)
    if invalid:
        return refuse(*invalid)
    branch = cfg["branch"]
    rc, _ = git(["fetch", "--no-tags", "--quiet", "origin", branch])
    if rc:
        return refuse(f"could not fetch origin/{branch}")
    rc, _ = git(["merge-base", "--is-ancestor", sha, f"origin/{branch}"])
    if rc:
        return refuse(f"tagged commit {sha} is not on origin/{branch}: release only merged, reviewed history")
    if github is None:
        token = env.get("GITHUB_TOKEN") or env.get("GH_TOKEN")
        if not token:
            return refuse("GITHUB_TOKEN is required to read check runs and release controls")
        github = GitHubAPI(token)
    problems = check_problems(github, repo, sha, cfg) + controls_problems(github, repo, cfg, tag)
    if problems:
        return refuse(*problems)
    print(f"release gate OK: {expected_ref} at {sha} is on origin/{branch}; {len(cfg['release'])} required "
          f"checks succeeded on that commit; release controls are in force")
    return 0


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_artifacts(package: str, version: str) -> tuple[str, str]:
    norm = re.sub(r"[-_.]+", "_", package).lower()
    return f"{norm}-{version}-py3-none-any.whl", f"{norm}-{version}.tar.gz"


def _meta(text: str) -> tuple[str, str]:
    msg = email.parser.Parser().parsestr(text)
    return msg.get("Name", ""), msg.get("Version", "")


def dist_problems(dist: Path, package: str, version: str) -> list[str]:
    wheel, sdist = expected_artifacts(package, version)
    present = sorted(p.name for p in dist.iterdir() if p.is_file()) if dist.is_dir() else []
    problems = []
    for name in (wheel, sdist):
        if name not in present:
            problems.append(f"missing artifact {name}")
    extra = sorted(set(present) - {wheel, sdist})
    if extra:
        problems.append(f"unexpected files in {dist}: {extra}")
    if problems:
        return problems
    norm = wheel.split("-")[0]
    try:
        with zipfile.ZipFile(dist / wheel) as zf:
            name, ver = _meta(zf.read(f"{norm}-{version}.dist-info/METADATA").decode())
            if zf.testzip() is not None:
                problems.append(f"{wheel} is corrupt")
    except (KeyError, zipfile.BadZipFile) as exc:
        return [f"{wheel} is not a valid wheel: {exc}"]
    if (name, ver) != (package, version):
        problems.append(f"{wheel} metadata says {name} {ver}, not {package} {version}")
    try:
        with tarfile.open(dist / sdist) as tf:
            member = tf.extractfile(f"{norm}-{version}/PKG-INFO")
            name, ver = _meta(member.read().decode()) if member else ("", "")
    except (KeyError, tarfile.TarError) as exc:
        return problems + [f"{sdist} is not a valid sdist: {exc}"]
    if (name, ver) != (package, version):
        problems.append(f"{sdist} metadata says {name} {ver}, not {package} {version}")
    return problems


def read_sums(path: Path) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.+-]+)", line)
        if not m or m.group(2) in sums:
            raise ValueError(f"malformed or duplicate SHA256SUMS line: {line!r}")
        sums[m.group(2)] = m.group(1)
    return sums


def dist_main(dist: Path, package: str, version: str, write: Path | None, check: Path | None) -> int:
    problems = dist_problems(dist, package, version)
    if problems:
        for p in problems:
            error(p)
        return 1
    actual = {name: sha256(dist / name) for name in expected_artifacts(package, version)}
    if check is not None:
        try:
            approved = read_sums(check)
        except (OSError, ValueError) as exc:
            error(f"approved artifact record unreadable: {exc}")
            return 1
        if approved != actual:
            error(f"artifacts differ from the approved record: approved={approved} actual={actual}")
            return 1
    if write is not None:
        write.write_text("".join(f"{actual[n]}  {n}\n" for n in sorted(actual)), encoding="utf-8")
    for n in sorted(actual):
        print(f"{actual[n]}  {n}")
    return 0


def _fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def pypi_problems(package: str, version: str, approved: dict[str, str], repo: str,
                  fetch: Callable[[str], Any] = _fetch_json) -> list[str]:
    problems = []
    release = fetch(f"https://pypi.org/pypi/{package}/{version}/json")
    files = {u["filename"]: u for u in release.get("urls") or []}
    if set(files) != set(approved):
        problems.append(f"PyPI serves {sorted(files)} for {version}; approved {sorted(approved)}")
    for name, want in sorted(approved.items()):
        info = files.get(name)
        if info is None:
            continue
        if (info.get("digests") or {}).get("sha256") != want:
            problems.append(f"{name}: PyPI sha256 {(info.get('digests') or {}).get('sha256')} != approved {want}")
        if info.get("yanked"):
            problems.append(f"{name} is yanked")
        try:
            prov = fetch(f"https://pypi.org/integrity/{package}/{version}/{name}/provenance")
        except Exception as exc:
            problems.append(f"{name}: no trusted-publishing provenance on PyPI ({exc})")
            continue
        ok = False
        for bundle in prov.get("attestation_bundles") or []:
            pub = bundle.get("publisher") or {}
            if (pub.get("kind"), pub.get("repository"), pub.get("workflow"), pub.get("environment")) != (
                    "GitHub", repo, PUBLISH_WORKFLOW, ENVIRONMENT):
                continue
            for att in bundle.get("attestations") or []:
                try:
                    stmt = json.loads(base64.b64decode(att["envelope"]["statement"]))
                except Exception:
                    continue
                if any(s.get("name") == name and (s.get("digest") or {}).get("sha256") == want
                       for s in stmt.get("subject") or []):
                    ok = True
        if not ok:
            problems.append(f"{name}: no attestation from {repo} {PUBLISH_WORKFLOW} in environment "
                            f"{ENVIRONMENT!r} whose subject is the approved file")
    return problems


def verify_pypi_main(package: str, version: str, sums: Path, repo: str, wait: int) -> int:
    approved = read_sums(sums)
    deadline = time.monotonic() + wait
    while True:
        try:
            problems = pypi_problems(package, version, approved, repo)
        except Exception as exc:
            problems = [f"could not read PyPI: {exc}"]
        if not problems or time.monotonic() >= deadline:
            break
        time.sleep(20)
    for p in problems:
        error(p)
    if problems:
        return 1
    print(f"PyPI {package}=={version}: exactly the approved artifacts, trusted-published from {repo}")
    return 0


INSTALLED_PROBE = r"""
import importlib.metadata as md, json, sys
import actenon_scan
d = md.distribution(sys.argv[1])
print(json.dumps({"module": actenon_scan.__file__, "version": d.version,
                  "files": {str(f): str(f.locate()) for f in d.files or []}}))
"""
PIP_ADDED = ("INSTALLER", "REQUESTED", "RECORD", "direct_url.json")


def installed_problems(python: str, wheel: Path, report: dict[str, Any], approved: dict[str, str],
                       package: str, version: str, workdir: Path) -> list[str]:
    problems = []
    installs = report.get("install") or []
    if len(installs) != 1:
        problems.append(f"pip installed {len(installs)} distributions; a zero-dependency release installs one")
    for item in installs:
        meta = item.get("metadata") or {}
        url = (item.get("download_info") or {}).get("url", "")
        got = ((item.get("download_info") or {}).get("archive_info") or {}).get("hashes", {}).get("sha256")
        fname = urllib.parse.unquote(url.rsplit("/", 1)[-1])
        if (meta.get("name"), meta.get("version")) != (package, version):
            problems.append(f"pip installed {meta.get('name')} {meta.get('version')}, not {package} {version}")
        if not url.startswith("https://files.pythonhosted.org/"):
            problems.append(f"pip installed from {url!r}, not PyPI")
        if fname != wheel.name or got != approved.get(wheel.name):
            problems.append(f"pip installed {fname} sha256 {got}; approved {wheel.name} {approved.get(wheel.name)}")
    proc = subprocess.run([python, "-I", "-c", INSTALLED_PROBE, package], cwd=workdir,
                          capture_output=True, text=True)
    if proc.returncode:
        return problems + [f"installed package does not import: {proc.stderr.strip()}"]
    info = json.loads(proc.stdout)
    if info["version"] != version:
        problems.append(f"installed version {info['version']} != {version}")
    if "site-packages" not in info["module"]:
        problems.append(f"actenon_scan imported from {info['module']}, not the installed package")
    with zipfile.ZipFile(wheel) as zf:
        members = [m for m in zf.namelist() if not m.endswith("/")]
        for m in members:
            if m.split("/")[0].endswith(".dist-info") and m.split("/")[-1] in PIP_ADDED:
                continue
            loc = info["files"].get(m)
            if loc is None:
                problems.append(f"{m} from the approved wheel is not installed")
            elif Path(loc).read_bytes() != zf.read(m):
                problems.append(f"installed {m} differs from the approved wheel")
        wheel_set = set(members)
        extra = sorted(f for f in info["files"] if f not in wheel_set and "__pycache__" not in f
                       and not f.startswith("../") and f.split("/")[-1] not in PIP_ADDED)
        if extra:
            problems.append(f"installed files not in the approved wheel: {extra}")
    return problems


# --------------------------------------------------------------------------- #
# Settings an owner applies
# --------------------------------------------------------------------------- #

def print_protection(cfg: dict[str, Any]) -> int:
    print(json.dumps({
        "required_status_checks": {"strict": True, "checks": [
            {"context": n, "app_id": GITHUB_ACTIONS_APP_ID} for n in cfg["pull_request"]]},
        "enforce_admins": True,
        "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": True},
        "restrictions": None,
        "required_linear_history": False,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "required_conversation_resolution": True,
    }, indent=2))
    return 0


def print_tag_rulesets() -> int:
    include = {"ref_name": {"include": [f"refs/tags/{RELEASE_TAG_PATTERN}"], "exclude": []}}
    print(json.dumps([
        {"name": "release tags: owner-created", "target": "tag", "enforcement": "active",
         "conditions": include, "rules": [{"type": "creation"}],
         "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]},
        {"name": "release tags: immutable", "target": "tag", "enforcement": "active",
         "conditions": include, "rules": [{"type": "update"}, {"type": "deletion"}, {"type": "non_fast_forward"}],
         "bypass_actors": []},
    ], indent=2))
    return 0


def print_environment(reviewer_id: int) -> int:
    print(json.dumps({
        "environment": {"wait_timer": 0, "prevent_self_review": False, "can_admins_bypass": False,
                        "reviewers": [{"type": "User", "id": reviewer_id}],
                        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
        "deployment_branch_policies": [{"name": RELEASE_TAG_PATTERN, "type": "tag"}],
    }, indent=2))
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("validate", "gate", "dist", "verify-pypi", "verify-installed",
                                     "print-protection", "print-tag-rulesets", "print-environment"))
    ap.add_argument("--version")
    ap.add_argument("--version-from")
    ap.add_argument("--tag-prefix", default="v")
    ap.add_argument("--dist", type=Path)
    ap.add_argument("--write-sums", type=Path)
    ap.add_argument("--check-sums", type=Path)
    ap.add_argument("--sums", type=Path)
    ap.add_argument("--wait", type=int, default=0)
    ap.add_argument("--python")
    ap.add_argument("--report", type=Path)
    ap.add_argument("--workdir", type=Path)
    ap.add_argument("--reviewer-id", type=int)
    args = ap.parse_args(argv)
    if args.mode == "validate":
        return validate()
    cfg = load_contract()
    if args.mode == "print-protection":
        return print_protection(cfg)
    if args.mode == "print-tag-rulesets":
        return print_tag_rulesets()
    if args.mode == "print-environment":
        if args.reviewer_id is None:
            ap.error("print-environment needs --reviewer-id (gh api users/<login> --jq .id)")
        return print_environment(args.reviewer_id)
    version = args.version or (version_from(ROOT / args.version_from) if args.version_from else None)
    if not version:
        ap.error(f"{args.mode} needs --version or --version-from")
    if args.mode == "gate":
        return gate(version, args.tag_prefix)
    if args.mode == "dist":
        if args.dist is None:
            ap.error("dist needs --dist")
        return dist_main(args.dist, cfg["package"], version, args.write_sums, args.check_sums)
    if args.sums is None:
        ap.error(f"{args.mode} needs --sums (the approved SHA256SUMS)")
    if args.mode == "verify-pypi":
        return verify_pypi_main(cfg["package"], version, args.sums, cfg["repository"], args.wait)
    if not (args.python and args.dist and args.report):
        ap.error("verify-installed needs --python, --dist and --report")
    wheel = args.dist / expected_artifacts(cfg["package"], version)[0]
    problems = installed_problems(args.python, wheel, json.loads(args.report.read_text(encoding="utf-8")),
                                  read_sums(args.sums), cfg["package"], version, args.workdir or Path.cwd())
    for p in problems:
        error(p)
    if problems:
        return 1
    print(f"installed {cfg['package']}=={version} is the approved wheel, byte for byte")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
