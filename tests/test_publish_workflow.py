"""Release-gate bypass tests: publish.yml and the required-checks contract are
validated fail-closed, and every loosening is refused by
scripts/release_gate.py validate (CI job "Required-check names exist", and
again by the gate on the tagged commit).

Also executes publish.yml's own artifact-verification and requirement steps.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.6.0"


def _load():
    spec = importlib.util.spec_from_file_location("scan_release_gate_wf", ROOT / "scripts" / "release_gate.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


rg = _load()
WORKFLOWS = rg.load_workflows(ROOT)
CONTRACT = rg.load_contract(ROOT)


def problems(workflows=None, contract=None) -> list[str]:
    wfs = WORKFLOWS if workflows is None else workflows
    return rg.contract_problems(CONTRACT if contract is None else contract, wfs) + rg.publish_workflow_problems(wfs)


def mutate_publish(fn):
    wfs = copy.deepcopy(WORKFLOWS)
    fn(wfs["publish.yml"])
    return problems(wfs)


def jobs(doc):
    return doc["jobs"]


def step(doc, job, predicate):
    return next(s for s in jobs(doc)[job]["steps"] if predicate(s))


def on(doc):
    return doc.get("on", doc.get(True))


def test_repository_contract_and_publish_workflow_validate():
    assert problems() == []
    assert rg.validate(ROOT) == 0


# publish.yml as of 16388227 (Scan PR #103 head), verbatim: dispatchable, ungated, with an
# API-token fallback. Embedded rather than read from git history, so this test also runs in
# CI's shallow checkout.
OLD_PUBLISH_WORKFLOW = """\
name: Publish to PyPI

# Publishes actenon-scan to PyPI on tag pushes (v*).
#
# Two publishing modes:
# 1. Trusted publishing (OIDC) — preferred. No API token needed.
#    Configure at: https://pypi.org/manage/project/actenon-scan/settings/publishing/
# 2. API token — fallback. Set the PYPI_API_TOKEN secret in this repo
#    (or make it an org-wide secret).
#
# To publish v0.1.4+:
#   git tag -a v0.1.4 -m "v0.1.4"
#   git push origin v0.1.4

on:
  push:
    tags:
      - "v*"
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Install build dependencies
        run: pip install build twine

      - name: Build sdist + wheel
        run: python -m build --sdist --wheel --outdir dist/

      - name: Verify the wheel installs in a clean venv
        run: |
          python -m venv /tmp/test-install
          /tmp/test-install/bin/pip install --upgrade pip
          /tmp/test-install/bin/pip install dist/actenon_scan-*.whl
          /tmp/test-install/bin/actenon-scan --version
          # --version never imports the repository layer. A directory scan
          # does: a wheel missing actenon_scan.repository crashed here with
          # ModuleNotFoundError while --version still passed.
          /tmp/test-install/bin/actenon-scan scan tests/benchmark/recall --fail-on none --no-cache > /dev/null

      - name: Run regression tests before publishing
        run: |
          pip install -e ".[dev]"
          python -m pytest tests/test_root_level_files.py tests/test_regression.py -v

      - name: Twine check
        run: twine check dist/*

      - uses: actions/upload-artifact@v7
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/v')
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@v8
        with:
          name: dist
          path: dist/

      - name: Publish to PyPI (trusted publishing)
        if: ${{ !env.PYPI_API_TOKEN }}
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          print-hash: true

      - name: Publish to PyPI (API token fallback)
        if: ${{ env.PYPI_API_TOKEN }}
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}
          print-hash: true
    env:
      PYPI_API_TOKEN: ${{ secrets.PYPI_API_TOKEN }}
"""


def test_old_token_publish_workflow_is_refused():
    """The workflow this PR replaces is refused on every count that let it publish around a gate."""
    old = yaml.safe_load(OLD_PUBLISH_WORKFLOW)
    assert "workflow_dispatch" in on(old) and "PYPI_API_TOKEN" in OLD_PUBLISH_WORKFLOW  # it is the real one
    wfs = copy.deepcopy(WORKFLOWS)
    wfs["publish.yml"] = old
    found = rg.publish_workflow_problems(wfs)
    assert any("must trigger only on push of tags" in p and "workflow_dispatch" in p for p in found)
    assert "publish.yml must set top-level 'permissions: {}'" in found
    assert any("jobs must be exactly" in p for p in found)


# --------------------------------------------------------------------------- #
# Triggers: no manual or untagged route
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("trigger", [
    {"push": {"tags": ["v*.*.*"]}, "workflow_dispatch": None},
    {"push": {"tags": ["v*.*.*"]}, "workflow_dispatch": {"inputs": {"ref": {"default": "main"}}}},
    {"push": {"tags": ["v*.*.*"], "branches": ["main"]}},
    {"push": {"tags": ["v*"]}},
    {"push": {"tags": ["*"]}},
    {"push": {"tags": ["v*.*.*"]}, "release": {"types": ["published"]}},
    {"push": {"tags": ["v*.*.*"]}, "workflow_call": None},
    {"push": {"tags": ["v*.*.*"]}, "repository_dispatch": None},
    {"push": None},
])
def test_publish_refuses_any_trigger_but_release_tag_push(trigger):
    def retrigger(d):
        d.pop(True, None)
        d.pop("on", None)
        d["on"] = trigger

    found = mutate_publish(retrigger)
    assert any("must trigger only on push of tags" in p for p in found)
    assert any(repr(trigger) in p for p in found)  # the mutated trigger was the one judged


# --------------------------------------------------------------------------- #
# Ordering and conditions: build and publish strictly depend on the gate
# --------------------------------------------------------------------------- #

def test_build_must_need_the_gate():
    found = mutate_publish(lambda d: jobs(d)["build"].pop("needs"))
    assert "publish.yml build: must need release-gate" in found


@pytest.mark.parametrize("needs", [["build"], ["release-gate"], []])
def test_publish_must_need_gate_and_build(needs):
    found = mutate_publish(lambda d: jobs(d)["publish"].update({"needs": needs}))
    assert "publish.yml publish: must need release-gate and build" in found


@pytest.mark.parametrize("cond", [
    "always()",
    "${{ always() }}",
    "!cancelled() && needs.release-gate.result == 'success' && needs.build.result == 'success' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
    "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && needs.build.result == 'success'",
    "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && (needs.release-gate.result == 'success' || needs.release-gate.result == 'failure') && needs.build.result == 'success'",
    "startsWith(github.ref, 'refs/tags/v') && needs.release-gate.result == 'success' && needs.build.result == 'success'",
    "",
])
def test_publish_condition_cannot_skip_or_survive_a_failed_gate(cond):
    found = mutate_publish(lambda d: jobs(d)["publish"].update({"if": cond}))
    assert any("publish.yml publish: condition" in p for p in found)


def test_gate_job_cannot_be_conditional_or_soft_failed():
    assert "publish.yml release-gate: must run unconditionally, first" in mutate_publish(
        lambda d: jobs(d)["release-gate"].update({"if": "false"}))
    assert "publish.yml release-gate: continue-on-error is not allowed" in mutate_publish(
        lambda d: step(d, "release-gate", lambda s: "release_gate.py gate" in s.get("run", "")).update(
            {"continue-on-error": True}))
    assert "publish.yml release-gate: continue-on-error is not allowed" in mutate_publish(
        lambda d: jobs(d)["release-gate"].update({"continue-on-error": True}))


def test_gate_job_must_run_the_gate():
    found = mutate_publish(lambda d: step(d, "release-gate", lambda s: "release_gate.py gate" in s.get("run", "")).update(
        {"run": "echo skipping the gate"}))
    assert "publish.yml release-gate: must run 'scripts/release_gate.py gate'" in found


def test_no_extra_job_can_publish_around_the_gate():
    found = mutate_publish(lambda d: jobs(d).update({"publish-fast": {"runs-on": "ubuntu-latest", "steps": []}}))
    assert any("jobs must be exactly" in p for p in found)


# --------------------------------------------------------------------------- #
# Credentials: trusted publishing through the reviewed environment only
# --------------------------------------------------------------------------- #

def _publish_step(d):
    return step(d, "publish", lambda s: str(s.get("uses", "")).startswith("pypa/gh-action-pypi-publish@"))


@pytest.mark.parametrize("mutation", [
    lambda d: _publish_step(d).setdefault("with", {}).update({"password": "${{ secrets.PYPI_API_TOKEN }}"}),
    lambda d: jobs(d)["publish"].update({"env": {"PYPI_API_TOKEN": "${{ secrets.PYPI_API_TOKEN }}"}}),
    lambda d: _publish_step(d).setdefault("with", {}).update({"user": "__token__", "password": "pypi-AgEI"}),
])
def test_publish_refuses_token_routes(mutation):
    assert any("trusted publishing only" in p for p in mutate_publish(mutation))


@pytest.mark.parametrize("env", [None, "testpypi", {"name": "release"}])
def test_publish_must_use_the_reviewed_pypi_environment(env):
    found = mutate_publish(lambda d: jobs(d)["publish"].update({"environment": env}))
    assert "publish.yml publish: must deploy through the 'pypi' environment" in found


@pytest.mark.parametrize("perms", [{"id-token": "write", "contents": "write"}, {}, {"contents": "read"}])
def test_publish_permissions_are_exactly_oidc(perms):
    found = mutate_publish(lambda d: jobs(d)["publish"].update({"permissions": perms}))
    assert "publish.yml publish: permissions must be exactly {id-token: write}" in found


@pytest.mark.parametrize("job", ["release-gate", "build", "verify-registry"])
def test_only_the_publish_job_may_mint_an_oidc_token(job):
    found = mutate_publish(lambda d: jobs(d)[job].setdefault("permissions", {}).update({"id-token": "write"}))
    assert f"publish.yml {job}: only the publish job may request id-token" in found


def test_top_level_permissions_must_be_empty():
    assert "publish.yml must set top-level 'permissions: {}'" in mutate_publish(
        lambda d: d.update({"permissions": {"contents": "write"}}))
    assert "publish.yml must set top-level 'permissions: {}'" in mutate_publish(lambda d: d.pop("permissions"))


@pytest.mark.parametrize("uses", ["pypa/gh-action-pypi-publish@release/v1", "pypa/gh-action-pypi-publish@v1.14.3",
                                  "pypa/gh-action-pypi-publish@7245906"])
def test_publish_actions_are_pinned_to_commits(uses):
    found = mutate_publish(lambda d: _publish_step(d).update({"uses": uses}))
    assert any("is not pinned to a commit SHA" in p for p in found)


def test_attestations_cannot_be_disabled():
    found = mutate_publish(lambda d: _publish_step(d)["with"].update({"attestations": False}))
    assert "publish.yml publish: attestations must not be disabled" in found


# --------------------------------------------------------------------------- #
# Artifacts: only the approved, recorded build is uploaded
# --------------------------------------------------------------------------- #

def test_build_must_record_the_approved_artifacts():
    found = mutate_publish(lambda d: jobs(d)["build"].update({"steps": [
        s for s in jobs(d)["build"]["steps"] if "--write-sums" not in s.get("run", "")]}))
    assert any("release_gate.py dist --write-sums" in p for p in found)


def test_artifacts_must_be_verified_before_upload():
    def drop(d):
        jobs(d)["publish"]["steps"] = [s for s in jobs(d)["publish"]["steps"] if "SHA256SUMS" not in s.get("run", "")]
    assert "publish.yml publish: the approved artifacts must be verified before upload" in mutate_publish(drop)

    def after(d):
        steps = jobs(d)["publish"]["steps"]
        verify = next(s for s in steps if "SHA256SUMS" in s.get("run", ""))
        steps.remove(verify)
        steps.append(verify)
    assert "publish.yml publish: the approved artifacts must be verified before upload" in mutate_publish(after)


@pytest.mark.parametrize("needle", ["release_gate.py verify-pypi", "--require-hashes", "release_gate.py verify-installed",
                                    "actenon-scan scan", "check_version_coherence.py --mode release"])
def test_post_publication_verification_cannot_be_dropped(needle):
    def drop(d):
        for s in jobs(d)["verify-registry"]["steps"]:
            if needle in s.get("run", ""):
                s["run"] = s["run"].replace(needle, "true")
    assert any("publish.yml verify-registry: must" in p and repr(needle) in p for p in mutate_publish(drop))


def test_post_publication_verification_must_follow_publish():
    found = mutate_publish(lambda d: jobs(d)["verify-registry"].update({"needs": ["build"]}))
    assert "publish.yml verify-registry: must need publish" in found


# --------------------------------------------------------------------------- #
# No second route in any other workflow
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("job", [
    {"steps": [{"uses": "pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086"}]},
    {"steps": [{"run": "twine upload dist/*"}]},
    {"steps": [{"run": "echo", "env": {"TOKEN": "${{ secrets.PYPI_API_TOKEN }}"}}]},
    {"permissions": {"id-token": "write"}, "steps": [{"run": "echo"}]},
    {"environment": "pypi", "steps": [{"run": "echo"}]},
    {"environment": {"name": "pypi"}, "steps": [{"run": "echo"}]},
])
def test_no_other_workflow_can_publish(job):
    wfs = copy.deepcopy(WORKFLOWS)
    wfs["sneaky.yml"] = {"on": {"workflow_dispatch": None}, "jobs": {"x": dict(job, **{"runs-on": "ubuntu-latest"})}}
    assert any(p.startswith("sneaky.yml:") for p in problems(wfs))


# --------------------------------------------------------------------------- #
# The required-checks contract
# --------------------------------------------------------------------------- #

def mutate_contract(fn):
    cfg = copy.deepcopy(CONTRACT)
    fn(cfg)
    return problems(contract=cfg)


@pytest.mark.parametrize("name", sorted(rg.MANDATORY_RELEASE_CHECKS))
def test_contract_cannot_drop_a_mandatory_release_check(name):
    found = mutate_contract(lambda c: c["release"].remove(name))
    assert any("mandatory release checks missing" in p and name in p for p in found)


def test_mandatory_floor_covers_tests_conformance_wheel_and_security():
    floor = rg.MANDATORY_RELEASE_CHECKS
    assert {f"test (3.{m})" for m in (10, 11, 12)} <= floor
    assert "Required AREF-002A/002B/002C proof-model conformance" in floor
    assert "Built wheel installs and scans a directory" in floor
    assert "Base install (no extras) — zero-dep guarantee" in floor
    assert "sarif" in floor and "Required-check names exist" in floor


def test_contract_release_checks_must_also_gate_merges():
    found = mutate_contract(lambda c: c["pull_request"].remove("sarif"))
    assert any("release checks not required to merge" in p for p in found)


def test_contract_refuses_unknown_names():
    found = mutate_contract(lambda c: (c["release"].append("Unit tests"), c["pull_request"].append("Unit tests"),
                                       c["producers"].update({"Unit tests": "ci.yml"})))
    assert "required-checks.json: no job produces a check named 'Unit tests'" in found


def test_contract_refuses_a_wrong_producer_binding():
    found = mutate_contract(lambda c: c["producers"].update({"sarif": "ci.yml"}))
    assert any("'sarif' is bound to ci.yml but produced by actenon-scan-sarif.yml" in p for p in found)


def test_contract_refuses_unbound_and_stale_producers():
    assert any("is not bound to a workflow" in p for p in mutate_contract(lambda c: c["producers"].pop("sarif")))
    assert any("not required" in p for p in mutate_contract(lambda c: c["producers"].update({"lychee": "link-check.yml"})))


def test_contract_refuses_duplicate_entries():
    found = mutate_contract(lambda c: c["release"].append("sarif"))
    assert any("duplicate names ['sarif']" in p for p in found)


@pytest.mark.parametrize("key", ["repository", "package", "branch", "pull_request", "release", "producers"])
def test_contract_requires_every_key(key):
    found = mutate_contract(lambda c: c.pop(key))
    assert any(repr(key) in p for p in found)


def test_required_name_produced_twice_is_ambiguous():
    wfs = copy.deepcopy(WORKFLOWS)
    wfs["shadow.yml"] = {"on": {"pull_request": None}, "jobs": {"shadow": {"name": "sarif", "runs-on": "ubuntu-latest",
                                                                            "steps": [{"run": "true"}]}}}
    assert any("'sarif' is produced by several jobs" in p for p in problems(wfs))


@pytest.mark.parametrize("pr", [{"paths": ["actenon_scan/**"]}, {"paths-ignore": ["docs/**"]},
                                {"branches": ["release"]}, {"branches-ignore": ["main"]}])
def test_required_check_workflows_cannot_be_path_or_branch_filtered(pr):
    wfs = copy.deepcopy(WORKFLOWS)
    on(wfs["perf-gate.yml"])["pull_request"] = pr
    assert any("filters pull_request runs" in p and "perf-gate.yml" in p for p in problems(wfs))


def test_required_check_workflows_must_run_on_pull_requests():
    wfs = copy.deepcopy(WORKFLOWS)
    on(wfs["benchmark.yml"]).pop("pull_request")
    assert any("does not run on pull_request" in p for p in problems(wfs))


def test_required_jobs_cannot_be_skipped_or_soft_failed():
    wfs = copy.deepcopy(WORKFLOWS)
    wfs["ci.yml"]["jobs"]["wheel-smoke"]["if"] = "github.event_name == 'push'"
    assert any("has a job-level 'if'" in p for p in problems(wfs))
    wfs = copy.deepcopy(WORKFLOWS)
    wfs["ci.yml"]["jobs"]["architecture-conformance"]["steps"][-1]["continue-on-error"] = True
    assert any("uses continue-on-error" in p for p in problems(wfs))


# --------------------------------------------------------------------------- #
# publish.yml's own steps, executed
# --------------------------------------------------------------------------- #

def _verify_step_script() -> str:
    return step(WORKFLOWS["publish.yml"], "publish", lambda s: "SHA256SUMS" in s.get("run", ""))["run"]


@pytest.fixture
def release(tmp_path: Path) -> Path:
    dist = tmp_path / "release" / "dist"
    dist.mkdir(parents=True)
    (dist / f"actenon_scan-{VERSION}-py3-none-any.whl").write_bytes(b"wheel bytes")
    (dist / f"actenon_scan-{VERSION}.tar.gz").write_bytes(b"sdist bytes")
    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(dist.iterdir()))
    (tmp_path / "release" / "SHA256SUMS").write_text(sums)
    return tmp_path


def _run_verify(cwd: Path, version: str = VERSION) -> subprocess.CompletedProcess:
    if shutil.which("bash") is None or shutil.which("python3") is None:
        pytest.skip("bash and python3 are required to execute the workflow step")
    return subprocess.run(["bash", "-eo", "pipefail", "-c", _verify_step_script()], cwd=cwd,
                          env=dict(os.environ, VERSION=version), capture_output=True, text=True)


def test_publish_step_accepts_the_approved_artifacts(release):
    proc = _run_verify(release)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.parametrize("damage", [
    lambda r: (r / "release/dist" / f"actenon_scan-{VERSION}-py3-none-any.whl").unlink(),
    lambda r: (r / "release/dist" / f"actenon_scan-{VERSION}.tar.gz").unlink(),
    lambda r: (r / "release/dist" / "extra-1.0.tar.gz").write_bytes(b"x"),
    lambda r: (r / "release/SHA256SUMS").unlink(),
    lambda r: (r / "release/dist" / f"actenon_scan-{VERSION}.tar.gz").write_bytes(b"tampered"),
    lambda r: (r / "release/SHA256SUMS").write_text((r / "release/SHA256SUMS").read_text() + "0" * 64 + "  x\n"),
    lambda r: shutil.rmtree(r / "release/dist"),
])
def test_publish_step_refuses_missing_extra_or_tampered_artifacts(release, damage):
    damage(release)
    proc = _run_verify(release)
    assert proc.returncode != 0
    assert "::error::" in proc.stdout + proc.stderr


def test_publish_step_refuses_a_version_output_that_is_not_a_release(release):
    assert _run_verify(release, version="").returncode != 0
    assert _run_verify(release, version="1.6.0rc1").returncode != 0


def test_registry_install_requirement_pins_both_approved_hashes(release):
    if shutil.which("bash") is None or shutil.which("awk") is None:
        pytest.skip("bash and awk are required to execute the workflow step")
    script = step(WORKFLOWS["publish.yml"], "verify-registry", lambda s: "--require-hashes" in s.get("run", ""))["run"]
    awk = script.split("cat ")[0]  # only the requirement-writing part; installing needs the network
    temp = release / "tmp"
    temp.mkdir()
    subprocess.run(["bash", "-eo", "pipefail", "-c", awk], cwd=release, check=True,
                   env=dict(os.environ, VERSION=VERSION, RUNNER_TEMP=str(temp)))
    line = (temp / "requirements.txt").read_text().strip()
    hashes = [h.split()[0] for h in (release / "release" / "SHA256SUMS").read_text().splitlines()]
    assert line == f"actenon-scan=={VERSION} " + " ".join(f"--hash=sha256:{h}" for h in hashes)
