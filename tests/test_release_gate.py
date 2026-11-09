"""Negative tests for scripts/release_gate.py: the gate refuses every way a
release can be wrong, and accepts only the exact tag, on main, with every
required check green and the release controls in force.

Workflow-structure (bypass) tests live in tests/test_publish_workflow.py,
which needs pyyaml.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
OTHER = "b" * 40
VERSION = "1.6.0"
TAG = f"v{VERSION}"
REPO = "Actenon/actenon-scan"


def _load():
    spec = importlib.util.spec_from_file_location("scan_release_gate", ROOT / "scripts" / "release_gate.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


rg = _load()
CONTRACT = json.loads((ROOT / ".github" / "required-checks.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    shutil.copy(ROOT / ".github" / "required-checks.json", tmp_path / ".github" / "required-checks.json")
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "actenon-scan"\nversion = "{VERSION}"\ndependencies = []\n'
        '[project.optional-dependencies]\ndev = ["pytest>=8.0", "actenon-protocol[types]>=1.1.0,<2"]\n',
        encoding="utf-8",
    )
    return tmp_path


def env(**over: str) -> dict[str, str]:
    base = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": f"refs/tags/{TAG}", "GITHUB_SHA": SHA,
            "GITHUB_REPOSITORY": REPO}
    base.update(over)
    return base


class FakeGit:
    def __init__(self, head: str = SHA, tag: str | None = SHA, on_main: bool = True, fetch_ok: bool = True):
        self.head, self.tag, self.on_main, self.fetch_ok = head, tag, on_main, fetch_ok

    def __call__(self, args: list[str]) -> tuple[int, str]:
        if args == ["rev-parse", "HEAD"]:
            return 0, self.head
        if args[:1] == ["rev-parse"]:
            return (0, self.tag) if self.tag else (128, "")
        if args[:1] == ["fetch"]:
            return (0, "") if self.fetch_ok else (1, "")
        if args[:2] == ["merge-base", "--is-ancestor"]:
            return (0, "") if self.on_main else (1, "")
        raise AssertionError(args)


def green_check(name: str, **over) -> dict:
    run = {"name": name, "head_sha": SHA, "status": "completed", "conclusion": "success",
           "app": {"slug": "github-actions"}, "check_suite": {"id": f"suite:{CONTRACT['producers'][name]}"}}
    run.update(over)
    return run


class FakeGitHub:
    """Serves a fully green, fully controlled repository unless told otherwise."""

    def __init__(self) -> None:
        self.checks = {name: [green_check(name)] for name in CONTRACT["release"]}
        self.workflow_runs = [
            {"head_sha": SHA, "check_suite_id": f"suite:{wf}", "path": f".github/workflows/{wf}"}
            for wf in sorted(set(CONTRACT["producers"].values()))
        ]
        self.branch = {"protection": {"enabled": True, "required_status_checks": {
            "enforcement_level": "everyone",
            "checks": [{"context": n, "app_id": 15368} for n in CONTRACT["pull_request"]]}}}
        self.rulesets = {
            1: {"target": "tag", "enforcement": "active", "rules": [{"type": "creation"}],
                "conditions": {"ref_name": {"include": ["refs/tags/v*.*.*"], "exclude": []}}},
            2: {"target": "tag", "enforcement": "active",
                "rules": [{"type": "update"}, {"type": "deletion"}, {"type": "non_fast_forward"}],
                "conditions": {"ref_name": {"include": ["refs/tags/v*.*.*"], "exclude": []}}},
        }
        self.environment = {"can_admins_bypass": False,
                            "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User"}]},
                                                 {"type": "branch_policy"}],
                            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        self.policies = [{"name": "v*.*.*", "type": "tag"}]
        self.fail: set[str] = set()

    def get(self, path: str):
        for needle in self.fail:
            if needle in path:
                raise OSError(f"HTTP 502 for {path}")
        if "/actions/runs?" in path:
            return {"workflow_runs": self.workflow_runs if "page=1" in path else []}
        if "/check-runs?" in path:
            from urllib.parse import parse_qs, urlsplit
            name = parse_qs(urlsplit(path).query)["check_name"][0]
            assert "filter=latest" in path
            return {"check_runs": self.checks.get(name, []) if "page=1" in path else []}
        if path.endswith(f"/branches/{CONTRACT['branch']}"):
            return self.branch
        if "/rulesets?" in path:
            return [{"id": i} for i in self.rulesets]
        if "/rulesets/" in path:
            assert path.endswith("?includes_parents=true")  # organisation rulesets are readable too
            return self.rulesets[int(path.split("?")[0].rsplit("/", 1)[1])]
        if path.endswith("/deployment-branch-policies?per_page=100&page=1"):
            return {"branch_policies": self.policies}
        if path.endswith("/environments/pypi"):
            return self.environment
        raise AssertionError(path)


def run_gate(root: Path, *, version: str = VERSION, environ=None, github=None, git=None) -> int:
    return rg.gate(version, "v", root=root, env=environ or env(), github=github or FakeGitHub(),
                   git=git or FakeGit(), validator=lambda _root: [])


# --------------------------------------------------------------------------- #
# Gate: accepted only in the one correct state
# --------------------------------------------------------------------------- #

def test_gate_accepts_exact_tag_on_main_with_green_checks_and_controls(root, capsys):
    assert run_gate(root) == 0
    assert "release gate OK" in capsys.readouterr().out


@pytest.mark.parametrize("event", ["workflow_dispatch", "release", "pull_request", "schedule", ""])
def test_gate_refuses_anything_but_a_tag_push(root, event, capsys):
    assert run_gate(root, environ=env(GITHUB_EVENT_NAME=event)) == 1
    assert "release-tag push" in capsys.readouterr().out


@pytest.mark.parametrize("ref", ["refs/heads/main", "refs/tags/v1.6.1", "refs/tags/v1.5.0",
                                 "refs/tags/1.6.0", "refs/tags/v1", "refs/tags/v1.6.0-integration", ""])
def test_gate_refuses_wrong_tag_or_version(root, ref, capsys):
    assert run_gate(root, environ=env(GITHUB_REF=ref)) == 1
    assert "publishing requires the tag refs/tags/v1.6.0" in capsys.readouterr().out


@pytest.mark.parametrize("version", ["1.6.0rc1", "1.6.0.dev1", "1.6", "1.6.0+local"])
def test_gate_refuses_non_final_versions(root, version, capsys):
    assert run_gate(root, version=version, environ=env(GITHUB_REF=f"refs/tags/v{version}")) == 1
    assert "not a final X.Y.Z release" in capsys.readouterr().out


def test_gate_refuses_a_checkout_that_is_not_the_run_commit(root, capsys):
    assert run_gate(root, git=FakeGit(head=OTHER)) == 1
    assert "is not the run's commit" in capsys.readouterr().out


@pytest.mark.parametrize("tag", [OTHER, None])
def test_gate_refuses_a_tag_that_does_not_point_at_the_commit(root, tag, capsys):
    assert run_gate(root, git=FakeGit(tag=tag)) == 1
    assert "refs/tags/v1.6.0 resolves to" in capsys.readouterr().out


def test_gate_refuses_a_commit_that_is_not_on_main(root, capsys):
    assert run_gate(root, git=FakeGit(on_main=False)) == 1
    assert "is not on origin/main" in capsys.readouterr().out


def test_gate_refuses_when_main_cannot_be_fetched(root, capsys):
    assert run_gate(root, git=FakeGit(fetch_ok=False)) == 1
    assert "could not fetch origin/main" in capsys.readouterr().out


def test_gate_refuses_another_repository(root, capsys):
    assert run_gate(root, environ=env(GITHUB_REPOSITORY="someone/actenon-scan")) == 1
    assert "not Actenon/actenon-scan" in capsys.readouterr().out


def test_gate_refuses_a_malformed_sha(root, capsys):
    assert run_gate(root, environ=env(GITHUB_SHA="HEAD")) == 1
    assert "is not a commit id" in capsys.readouterr().out


def test_gate_refuses_when_the_contract_or_publish_workflow_is_invalid(root, capsys):
    code = rg.gate(VERSION, "v", root=root, env=env(), github=FakeGitHub(), git=FakeGit(),
                   validator=lambda _root: ["publish.yml must set top-level 'permissions: {}'"])
    assert code == 1
    assert "permissions: {}" in capsys.readouterr().out


def test_gate_without_a_token_refuses(root, capsys):
    assert rg.gate(VERSION, "v", root=root, env=env(), git=FakeGit(), validator=lambda _r: []) == 1
    assert "GITHUB_TOKEN is required" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Gate: required checks on the exact commit
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", CONTRACT["release"])
def test_gate_refuses_a_missing_required_check(root, name, capsys):
    gh = FakeGitHub()
    gh.checks[name] = []
    assert run_gate(root, github=gh) == 1
    assert f"required check {name!r} never ran on {SHA}" in capsys.readouterr().out


@pytest.mark.parametrize("conclusion", ["failure", "skipped", "cancelled", "neutral", "timed_out",
                                        "action_required", "stale", None])
def test_gate_refuses_a_required_check_that_did_not_succeed(root, conclusion, capsys):
    gh = FakeGitHub()
    gh.checks["test (3.12)"] = [green_check("test (3.12)", conclusion=conclusion)]
    assert run_gate(root, github=gh) == 1
    assert f"required check 'test (3.12)' on {SHA}: completed/{conclusion}" in capsys.readouterr().out


def test_gate_refuses_an_in_progress_required_check(root, capsys):
    gh = FakeGitHub()
    gh.checks["sarif"] = [green_check("sarif", status="in_progress", conclusion=None)]
    assert run_gate(root, github=gh) == 1
    assert "in_progress/None" in capsys.readouterr().out


def test_gate_refuses_when_any_latest_run_of_a_check_failed(root, capsys):
    gh = FakeGitHub()
    name = "Required AREF-002A/002B/002C proof-model conformance"
    gh.checks[name] = [green_check(name), green_check(name, conclusion="failure")]
    assert run_gate(root, github=gh) == 1
    assert "completed/failure" in capsys.readouterr().out


def test_gate_refuses_a_same_named_check_from_another_app(root, capsys):
    gh = FakeGitHub()
    gh.checks["test (3.11)"] = [green_check("test (3.11)", app={"slug": "some-ci-app"})]
    assert run_gate(root, github=gh) == 1
    assert "was reported by 'some-ci-app', not GitHub Actions" in capsys.readouterr().out


def test_gate_refuses_a_same_named_check_from_another_workflow(root, capsys):
    gh = FakeGitHub()
    gh.workflow_runs.append({"head_sha": SHA, "check_suite_id": "suite:evil", "path": ".github/workflows/evil.yml"})
    gh.checks["Built wheel installs and scans a directory"] = [
        green_check("Built wheel installs and scans a directory", check_suite={"id": "suite:evil"})]
    assert run_gate(root, github=gh) == 1
    assert "came from .github/workflows/evil.yml, not .github/workflows/ci.yml" in capsys.readouterr().out


def test_gate_refuses_a_check_whose_workflow_run_is_for_another_commit(root, capsys):
    gh = FakeGitHub()
    for run in gh.workflow_runs:
        if run["path"].endswith("benchmark.yml"):
            run["head_sha"] = OTHER
    assert run_gate(root, github=gh) == 1
    assert "came from an unknown workflow" in capsys.readouterr().out


def test_gate_refuses_a_check_run_reported_for_another_commit(root, capsys):
    gh = FakeGitHub()
    gh.checks["drift-gate (3.10)"] = [green_check("drift-gate (3.10)", head_sha=OTHER)]
    assert run_gate(root, github=gh) == 1
    assert f"belongs to {OTHER}" in capsys.readouterr().out


@pytest.mark.parametrize("needle", ["/actions/runs?", "/check-runs?", "/branches/", "/rulesets", "/environments/"])
def test_gate_refuses_when_github_state_is_unreadable(root, needle, capsys):
    gh = FakeGitHub()
    gh.fail.add(needle)
    assert run_gate(root, github=gh) == 1
    assert "could not" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Gate: release controls must be in force
# --------------------------------------------------------------------------- #

def test_gate_refuses_an_unprotected_main(root, capsys):
    gh = FakeGitHub()
    gh.branch = {"protection": {"enabled": False}}
    assert run_gate(root, github=gh) == 1
    assert "main is not protected" in capsys.readouterr().out


def test_gate_refuses_protection_that_exempts_admins(root, capsys):
    gh = FakeGitHub()
    gh.branch["protection"]["required_status_checks"]["enforcement_level"] = "non_admins"
    assert run_gate(root, github=gh) == 1
    assert "to administrators" in capsys.readouterr().out


def test_gate_refuses_protection_missing_a_check_or_not_bound_to_actions(root, capsys):
    gh = FakeGitHub()
    checks = gh.branch["protection"]["required_status_checks"]["checks"]
    checks[:] = [c for c in checks if c["context"] != "sarif"]
    checks[0]["app_id"] = None
    assert run_gate(root, github=gh) == 1
    out = capsys.readouterr().out
    assert "'sarif'" in out and repr(checks[0]["context"]) in out


@pytest.mark.parametrize("drop", ["creation", "update", "deletion"])
def test_gate_refuses_without_a_full_tag_ruleset(root, drop, capsys):
    gh = FakeGitHub()
    for rs in gh.rulesets.values():
        rs["rules"] = [r for r in rs["rules"] if r["type"] != drop]
    assert run_gate(root, github=gh) == 1
    assert f"no active tag ruleset restricts ['{drop}']" in capsys.readouterr().out


@pytest.mark.parametrize("change", [{"enforcement": "evaluate"}, {"enforcement": "disabled"},
                                    {"conditions": {"ref_name": {"include": ["refs/tags/ts-*"], "exclude": []}}},
                                    {"conditions": {"ref_name": {"include": ["refs/tags/v*.*.*"],
                                                                 "exclude": ["refs/tags/v1.6.*"]}}}])
def test_gate_refuses_a_ruleset_that_is_inactive_or_does_not_cover_the_tag(root, change, capsys):
    gh = FakeGitHub()
    for rs in gh.rulesets.values():
        rs.update(change)
    assert run_gate(root, github=gh) == 1
    assert "no active tag ruleset restricts" in capsys.readouterr().out


def test_gate_refuses_an_environment_without_reviewers(root, capsys):
    gh = FakeGitHub()
    gh.environment["protection_rules"] = [{"type": "branch_policy"}]
    assert run_gate(root, github=gh) == 1
    assert "has no required reviewers" in capsys.readouterr().out


@pytest.mark.parametrize("bypass", [True, None])
def test_gate_refuses_an_environment_admins_can_bypass(root, bypass, capsys):
    gh = FakeGitHub()
    gh.environment["can_admins_bypass"] = bypass
    assert run_gate(root, github=gh) == 1
    assert "lets administrators bypass" in capsys.readouterr().out


def test_gate_refuses_an_environment_open_to_any_ref(root, capsys):
    gh = FakeGitHub()
    gh.environment["deployment_branch_policy"] = None
    assert run_gate(root, github=gh) == 1
    assert "does not restrict which refs may deploy" in capsys.readouterr().out


@pytest.mark.parametrize("policies", [[{"name": "main", "type": "branch"}], [],
                                      [{"name": "v*.*.*", "type": "tag"}, {"name": "*", "type": "branch"}]])
def test_gate_refuses_an_environment_that_deploys_from_branches(root, policies, capsys):
    gh = FakeGitHub()
    gh.policies = policies
    assert run_gate(root, github=gh) == 1
    assert "from release tags only" in capsys.readouterr().out


def test_gate_refuses_an_environment_policy_that_excludes_the_tag(root, capsys):
    gh = FakeGitHub()
    gh.policies = [{"name": "v2.*.*", "type": "tag"}]
    assert run_gate(root, github=gh) == 1
    assert "does not allow deployments from v1.6.0" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Gate: registry inputs only
# --------------------------------------------------------------------------- #

def test_gate_refuses_the_candidate_constraints_file(root, capsys):
    (root / ".github" / "candidate-constraints.txt").write_text(
        "actenon-protocol @ git+https://github.com/Actenon/actenon-protocol.git@" + SHA + "\n", encoding="utf-8")
    assert run_gate(root) == 1
    assert "candidate-constraints.txt exists" in capsys.readouterr().out


def test_gate_refuses_pip_constraint_in_a_workflow(root, capsys):
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "env:\n  PIP_CONSTRAINT: x\n", encoding="utf-8")
    assert run_gate(root) == 1
    assert "candidate inputs in ci.yml" in capsys.readouterr().out


@pytest.mark.parametrize("req", ['"actenon-protocol @ git+https://github.com/Actenon/actenon-protocol.git@main"',
                                 '"pkg @ https://example.com/pkg.whl"'])
def test_gate_refuses_direct_reference_requirements(root, req, capsys):
    text = (root / "pyproject.toml").read_text().replace('"pytest>=8.0"', f'"pytest>=8.0", {req}')
    (root / "pyproject.toml").write_text(text)
    assert run_gate(root) == 1
    assert "direct-reference requirement" in capsys.readouterr().out


def test_gate_refuses_uv_sources_and_git_locks(root, capsys):
    (root / "pyproject.toml").write_text((root / "pyproject.toml").read_text()
                                         + '[tool.uv.sources]\nactenon-protocol = { git = "https://x" }\n')
    (root / "uv.lock").write_text('[[package]]\nname = "x"\nsource = { git = "https://x?rev=1" }\n')
    assert run_gate(root) == 1
    out = capsys.readouterr().out
    assert "tool.uv.sources" in out and "uv.lock" in out


def test_this_candidate_is_refused_until_the_protocol_pin_is_removed():
    """The release identity rule: while Scan's CI pins the unpublished Protocol
    candidate, no commit of this tree can be published."""
    if (ROOT / ".github" / "candidate-constraints.txt").exists():
        assert rg.source_pin_problems(ROOT)
    else:
        assert rg.source_pin_problems(ROOT) == []


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #

def _wheel(path: Path, name: str = "actenon-scan", version: str = VERSION, files=None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for member, data in (files or {"actenon_scan/__init__.py": b"x = 1\n"}).items():
            zf.writestr(member, data)
        zf.writestr(f"actenon_scan-{VERSION}.dist-info/METADATA",
                    f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n")
        zf.writestr(f"actenon_scan-{VERSION}.dist-info/RECORD", "")
    return path


def _sdist(path: Path, name: str = "actenon-scan", version: str = VERSION) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        data = f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n".encode()
        info = tarfile.TarInfo(f"actenon_scan-{VERSION}/PKG-INFO")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return path


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    d = tmp_path / "dist"
    d.mkdir()
    _wheel(d / f"actenon_scan-{VERSION}-py3-none-any.whl")
    _sdist(d / f"actenon_scan-{VERSION}.tar.gz")
    return d


def test_dist_accepts_exactly_the_two_artifacts_and_records_them(dist, tmp_path):
    sums = tmp_path / "SHA256SUMS"
    assert rg.dist_main(dist, "actenon-scan", VERSION, sums, None) == 0
    recorded = rg.read_sums(sums)
    assert recorded == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in dist.iterdir()}
    assert rg.dist_main(dist, "actenon-scan", VERSION, None, sums) == 0


@pytest.mark.parametrize("missing", [f"actenon_scan-{VERSION}-py3-none-any.whl", f"actenon_scan-{VERSION}.tar.gz"])
def test_dist_refuses_a_missing_artifact(dist, missing, capsys):
    (dist / missing).unlink()
    assert rg.dist_main(dist, "actenon-scan", VERSION, None, None) == 1
    assert f"missing artifact {missing}" in capsys.readouterr().out


def test_dist_refuses_an_empty_or_absent_dist(tmp_path, capsys):
    assert rg.dist_main(tmp_path / "nowhere", "actenon-scan", VERSION, None, None) == 1
    assert capsys.readouterr().out.count("missing artifact") == 2


def test_dist_refuses_extra_files(dist, capsys):
    (dist / f"actenon_scan-{VERSION}-cp312-cp312-linux_x86_64.whl").write_bytes(b"x")
    assert rg.dist_main(dist, "actenon-scan", VERSION, None, None) == 1
    assert "unexpected files" in capsys.readouterr().out


def test_dist_refuses_artifacts_for_another_version(dist, capsys):
    assert rg.dist_main(dist, "actenon-scan", "1.6.1", None, None) == 1
    assert "missing artifact actenon_scan-1.6.1" in capsys.readouterr().out


def test_dist_refuses_mismatched_metadata(dist, capsys):
    _wheel(dist / f"actenon_scan-{VERSION}-py3-none-any.whl", version="1.5.0")
    assert rg.dist_main(dist, "actenon-scan", VERSION, None, None) == 1
    assert "metadata says actenon-scan 1.5.0" in capsys.readouterr().out


def test_dist_refuses_a_corrupt_wheel(dist, capsys):
    (dist / f"actenon_scan-{VERSION}-py3-none-any.whl").write_bytes(b"not a zip")
    assert rg.dist_main(dist, "actenon-scan", VERSION, None, None) == 1
    assert "is not a valid wheel" in capsys.readouterr().out


def test_dist_refuses_artifacts_that_differ_from_the_approved_record(dist, tmp_path, capsys):
    sums = tmp_path / "SHA256SUMS"
    assert rg.dist_main(dist, "actenon-scan", VERSION, sums, None) == 0
    _wheel(dist / f"actenon_scan-{VERSION}-py3-none-any.whl", files={"actenon_scan/__init__.py": b"x = 2\n"})
    assert rg.dist_main(dist, "actenon-scan", VERSION, None, sums) == 1
    assert "differ from the approved record" in capsys.readouterr().out


@pytest.mark.parametrize("text", ["", "deadbeef  actenon_scan-1.6.0.tar.gz\n",
                                  ("a" * 64 + "  x.whl\n") * 2])
def test_dist_refuses_a_malformed_approved_record(dist, tmp_path, text, capsys):
    sums = tmp_path / "SHA256SUMS"
    sums.write_text(text)
    assert rg.dist_main(dist, "actenon-scan", VERSION, None, sums) == 1
    assert "approved" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# After publication: PyPI holds exactly the approved, attested artifacts
# --------------------------------------------------------------------------- #

WHL = f"actenon_scan-{VERSION}-py3-none-any.whl"
SDIST = f"actenon_scan-{VERSION}.tar.gz"
APPROVED = {WHL: "1" * 64, SDIST: "2" * 64}


def _provenance(name: str, digest: str, **publisher) -> dict:
    pub = {"kind": "GitHub", "repository": REPO, "workflow": "publish.yml", "environment": "pypi"}
    pub.update(publisher)
    stmt = base64.b64encode(json.dumps({"subject": [{"name": name, "digest": {"sha256": digest}}]}).encode()).decode()
    return {"attestation_bundles": [{"publisher": pub, "attestations": [{"envelope": {"statement": stmt}}]}]}


def pypi(files=None, provenance=None):
    files = APPROVED if files is None else files

    def fetch(url: str):
        if url.endswith(f"/{VERSION}/json"):
            return {"urls": [{"filename": n, "digests": {"sha256": h}, "yanked": False} for n, h in files.items()]}
        name = url.rsplit("/", 2)[-2]
        prov = (provenance or {}).get(name, _provenance(name, files.get(name, "")))
        if isinstance(prov, Exception):
            raise prov
        return prov
    return fetch


def test_pypi_accepts_exactly_the_approved_attested_files():
    assert rg.pypi_problems("actenon-scan", VERSION, APPROVED, REPO, pypi()) == []


def test_pypi_refuses_a_missing_file():
    problems = rg.pypi_problems("actenon-scan", VERSION, APPROVED, REPO, pypi({WHL: APPROVED[WHL]}))
    assert any("PyPI serves" in p for p in problems)


def test_pypi_refuses_an_extra_file():
    files = dict(APPROVED, **{f"actenon_scan-{VERSION}-py2-none-any.whl": "3" * 64})
    assert any("PyPI serves" in p for p in rg.pypi_problems("actenon-scan", VERSION, APPROVED, REPO, pypi(files)))


def test_pypi_refuses_a_different_hash():
    files = dict(APPROVED, **{WHL: "9" * 64})
    problems = rg.pypi_problems("actenon-scan", VERSION, APPROVED, REPO, pypi(files))
    assert any(f"{WHL}: PyPI sha256" in p for p in problems)


def test_pypi_refuses_a_yanked_file():
    def fetch(url):
        data = pypi()(url)
        if url.endswith("/json"):
            data["urls"][0]["yanked"] = True
        return data
    assert any("is yanked" in p for p in rg.pypi_problems("actenon-scan", VERSION, APPROVED, REPO, fetch))


@pytest.mark.parametrize("publisher", [{"repository": "someone/actenon-scan"}, {"workflow": "other.yml"},
                                       {"environment": "testpypi"}, {"kind": "GitLab"}])
def test_pypi_refuses_an_attestation_from_another_publisher(publisher):
    prov = {WHL: _provenance(WHL, APPROVED[WHL], **publisher)}
    problems = rg.pypi_problems("actenon-scan", VERSION, APPROVED, REPO, pypi(provenance=prov))
    assert any(f"{WHL}: no attestation" in p for p in problems)


def test_pypi_refuses_an_attestation_for_other_bytes():
    prov = {SDIST: _provenance(SDIST, "8" * 64)}
    problems = rg.pypi_problems("actenon-scan", VERSION, APPROVED, REPO, pypi(provenance=prov))
    assert any(f"{SDIST}: no attestation" in p for p in problems)


def test_pypi_refuses_a_token_upload_without_provenance():
    prov = {WHL: OSError("HTTP 404"), SDIST: OSError("HTTP 404")}
    problems = rg.pypi_problems("actenon-scan", VERSION, APPROVED, REPO, pypi(provenance=prov))
    assert sum("no trusted-publishing provenance" in p for p in problems) == 2


# --------------------------------------------------------------------------- #
# After publication: the clean install is the approved wheel
# --------------------------------------------------------------------------- #

@pytest.fixture
def installed(tmp_path: Path):
    """A real venv with a real wheel built from a tiny package named actenon-scan."""
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    py = venv / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    wheel = _wheel(tmp_path / WHL, files={"actenon_scan/__init__.py": b"__version__ = '1.6.0'\n",
                                          "actenon_scan/core.py": b"X = 1\n"})
    # A minimal, valid wheel: add WHEEL and a RECORD pip can accept.
    with zipfile.ZipFile(wheel, "a") as zf:
        zf.writestr(f"actenon_scan-{VERSION}.dist-info/WHEEL",
                    "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    _rewrite_record(wheel)
    subprocess.run([str(py), "-m", "pip", "install", "--no-index", "--no-deps", "-q", str(wheel)], check=True)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    report = {"install": [{"metadata": {"name": "actenon-scan", "version": VERSION},
                           "download_info": {"url": f"https://files.pythonhosted.org/packages/ab/{WHL}",
                                             "archive_info": {"hashes": {"sha256": digest}}}}]}
    return py, wheel, report, {WHL: digest, SDIST: "2" * 64}, venv


def _rewrite_record(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as zf:
        items = {n: zf.read(n) for n in zf.namelist() if not n.endswith("RECORD")}
    record = f"actenon_scan-{VERSION}.dist-info/RECORD"
    lines = []
    for n, data in items.items():
        h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        lines.append(f"{n},sha256={h},{len(data)}")
    lines.append(f"{record},,")
    with zipfile.ZipFile(wheel, "w") as zf:
        for n, data in items.items():
            zf.writestr(n, data)
        zf.writestr(record, "\n".join(lines) + "\n")


def test_installed_accepts_the_approved_wheel(installed, tmp_path):
    py, wheel, report, approved, _ = installed
    assert rg.installed_problems(str(py), wheel, report, approved, "actenon-scan", VERSION, tmp_path) == []


def test_installed_refuses_a_modified_installed_file(installed, tmp_path):
    py, wheel, report, approved, venv = installed
    core = next(venv.rglob("site-packages/actenon_scan/core.py"))
    core.write_bytes(b"X = 2\n")
    problems = rg.installed_problems(str(py), wheel, report, approved, "actenon-scan", VERSION, tmp_path)
    assert "installed actenon_scan/core.py differs from the approved wheel" in problems


def test_installed_refuses_an_install_of_other_bytes(installed, tmp_path):
    py, wheel, report, approved, _ = installed
    report["install"][0]["download_info"]["archive_info"]["hashes"]["sha256"] = "0" * 64
    problems = rg.installed_problems(str(py), wheel, report, approved, "actenon-scan", VERSION, tmp_path)
    assert any("approved" in p and "0" * 64 in p for p in problems)


def test_installed_refuses_an_install_from_outside_pypi(installed, tmp_path):
    py, wheel, report, approved, _ = installed
    report["install"][0]["download_info"]["url"] = f"https://mirror.example/{WHL}"
    problems = rg.installed_problems(str(py), wheel, report, approved, "actenon-scan", VERSION, tmp_path)
    assert any("not PyPI" in p for p in problems)


def test_installed_refuses_extra_distributions(installed, tmp_path):
    py, wheel, report, approved, _ = installed
    report["install"].append(report["install"][0])
    problems = rg.installed_problems(str(py), wheel, report, approved, "actenon-scan", VERSION, tmp_path)
    assert any("zero-dependency release installs one" in p for p in problems)


# --------------------------------------------------------------------------- #
# Settings an owner applies
# --------------------------------------------------------------------------- #

def test_printed_tag_rulesets_protect_release_tags_but_not_the_moving_v1_tag(capsys):
    import fnmatch
    assert rg.print_tag_rulesets() == 0
    rulesets = json.loads(capsys.readouterr().out)
    include = {p for rs in rulesets for p in rs["conditions"]["ref_name"]["include"]}
    assert all(fnmatch.fnmatchcase("refs/tags/v1.6.0", p) for p in include)
    assert not any(fnmatch.fnmatchcase("refs/tags/v1", p) for p in include)
    rules = {r["type"]: rs["bypass_actors"] for rs in rulesets for r in rs["rules"]}
    assert set(rules) >= {"creation", "update", "deletion"}
    assert rules["update"] == rules["deletion"] == []


def test_printed_protection_requires_every_pr_check_from_github_actions(capsys):
    assert rg.print_protection(CONTRACT) == 0
    out = json.loads(capsys.readouterr().out)
    assert {c["context"] for c in out["required_status_checks"]["checks"]} == set(CONTRACT["pull_request"])
    assert {c["app_id"] for c in out["required_status_checks"]["checks"]} == {15368}
    assert out["enforce_admins"] is True and out["allow_force_pushes"] is False
    assert out["required_linear_history"] is False  # a merge commit keeps the tested SHA on main


def test_printed_environment_is_reviewed_tag_only_and_not_admin_bypassable(capsys):
    assert rg.print_environment(42) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["environment"]["reviewers"] == [{"type": "User", "id": 42}]
    assert out["environment"]["can_admins_bypass"] is False
    assert out["deployment_branch_policies"] == [{"name": "v*.*.*", "type": "tag"}]
