"""Workflow hygiene: each CI job checks out once and sets up Python once.

A bad merge of a Dependabot action bump left ci.yml's ``test`` and
``base-install-test`` jobs with two ``actions/checkout`` steps and two
``actions/setup-python`` steps, the first setup-python pinning no
``python-version`` at all. The job still went green, so neither CI nor
actionlint noticed: duplicated steps are valid workflow syntax. This test
makes the duplication, and an unpinned setup-python, a test failure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _steps():
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        jobs = (yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}).get("jobs") or {}
        for job_name, job in jobs.items():
            yield workflow.name, job_name, job.get("steps") or []


def _action(step: dict) -> str:
    return str(step.get("uses", "")).split("@", 1)[0]


@pytest.mark.parametrize("action", ["actions/checkout", "actions/setup-python"])
def test_each_job_uses_the_action_at_most_once(action: str) -> None:
    offenders = [
        f"{workflow}:{job}"
        for workflow, job, steps in _steps()
        if sum(_action(step) == action for step in steps) > 1
    ]
    assert not offenders, f"{action} appears more than once in: {offenders}"


def test_every_setup_python_pins_a_version() -> None:
    offenders = [
        f"{workflow}:{job}"
        for workflow, job, steps in _steps()
        for step in steps
        if _action(step) == "actions/setup-python"
        and not (step.get("with") or {}).get("python-version")
    ]
    assert not offenders, f"setup-python without python-version in: {offenders}"
