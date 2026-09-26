"""Execute action.yml's scan step the way GitHub runs it.

The composite action builds its CLI command by string concatenation and
then gates the build on the scan's exit code. Reading the YAML is not
enough to catch a malformed command line, so these tests extract the
``Run actenon-scan`` step, substitute the ``${{ ... }}`` expressions, and
run it under GitHub's bash invocation (``bash --noprofile --norc -eo
pipefail``) against a real fixture.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash required to execute the action step"
)


def _load_action() -> dict:
    return yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))


def _run_scan_step(
    workdir: Path, inputs: dict[str, str], shim_body: str | None = None
) -> dict[str, str]:
    """Run the action's scan step in ``workdir`` and return its step outputs.

    ``shim_body`` replaces the ``actenon-scan`` executable (default: run
    this checkout's scanner).
    """
    action = _load_action()
    values = {name: str(spec.get("default", "")) for name, spec in action["inputs"].items()}
    values.update(inputs)
    step = next(s for s in action["runs"]["steps"] if s.get("id") == "scan")
    context = {
        "github.event_name": "push",
        "github.base_ref": "",
        "steps.scope.outputs.scope": "full",
    }

    def substitute(match: re.Match) -> str:
        expr = match.group(1).strip()
        if expr.startswith("inputs."):
            return values[expr[len("inputs."):]]
        return context[expr]

    script = re.sub(r"\$\{\{(.*?)\}\}", substitute, step["run"])
    step_env = {
        key: re.sub(r"\$\{\{(.*?)\}\}", substitute, str(value))
        for key, value in (step.get("env") or {}).items()
    }

    # Put an `actenon-scan` shim on PATH that runs THIS checkout with the
    # current interpreter, so the test does not depend on a console script.
    shim_dir = workdir.parent / "shim"
    shim_dir.mkdir(exist_ok=True)
    shim = shim_dir / "actenon-scan"
    shim.write_text(
        shim_body or f'#!/bin/sh\nexec "{sys.executable}" -m actenon_scan "$@"\n'
    )
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)

    output_file = workdir.parent / "github_output"
    output_file.write_text("")
    env = dict(os.environ)
    env.update(step_env)
    env["PATH"] = f"{shim_dir}{os.pathsep}{env.get('PATH', '')}"
    env["PYTHONPATH"] = f"{ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["GITHUB_OUTPUT"] = str(output_file)
    env["XDG_CACHE_HOME"] = str(workdir.parent / "cache")
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=workdir, env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    outputs = {}
    for line in output_file.read_text().splitlines():
        key, _, value = line.partition("=")
        outputs[key] = value
    outputs["_stdout"] = proc.stdout
    return outputs


@pytest.fixture()
def repo_with_unsupported_and_finding(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    work.mkdir()
    (work / "agent.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool()
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout
    """))
    (work / "worker.rb").write_text("system(params[:cmd])\n")
    return work


def test_fail_on_unsupported_input_produces_a_valid_command(
    repo_with_unsupported_and_finding: Path,
) -> None:
    """`fail-on-unsupported: true` must not break the scan command line.

    It was appended without a separating space, producing
    `--fail-on high--fail-on-unsupported`: argparse rejected it (exit 2),
    no results.json was written, the outputs reported 0 findings, and the
    build passed — opting into stricter gating disabled the gate.
    """
    out = _run_scan_step(
        repo_with_unsupported_and_finding,
        {"fail-on": "high", "fail-on-unsupported": "true"},
    )
    assert "invalid choice" not in out["_stdout"], out["_stdout"]
    assert out["exit_code"] == "1", out
    assert int(out["findings-count"]) >= 1, out


def test_fail_step_runs_on_any_nonzero_scan_exit() -> None:
    """A scanner crash or usage error (exit 2) must fail the action.

    Gating only on exit code 1 let exit 2 — no results produced at all —
    pass as a green check with 0 findings.
    """
    action = _load_action()
    fail_step = next(
        s for s in action["runs"]["steps"] if s.get("name") == "Fail on findings"
    )
    condition = fail_step["if"].replace(" ", "")
    assert "steps.scan.outputs.exit_code!='0'" in condition, fail_step["if"]


def test_crash_without_results_is_not_reported_as_findings(tmp_path: Path) -> None:
    """A traceback exits 1 — the same code as "findings found". Without a
    results.json the step must report an incomplete scan (exit_code 3),
    not a findings failure with 0 counts."""
    work = tmp_path / "repo"
    work.mkdir()
    out = _run_scan_step(
        work,
        {"fail-on": "none"},
        shim_body="#!/bin/sh\necho 'Traceback (most recent call last):' >&2\nexit 1\n",
    )
    assert out["exit_code"] == "3", out


def test_paths_with_spaces_are_passed_as_one_argument(tmp_path: Path) -> None:
    work = tmp_path / "repo"
    (work / "my agent").mkdir(parents=True)
    (work / "my agent" / "agent.py").write_text(textwrap.dedent("""\
        import os
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool()
        def rm(path: str) -> None:
            os.remove(path)
    """))
    out = _run_scan_step(work, {"path": "my agent", "fail-on": "none"})
    assert out["exit_code"] == "0", out
    assert int(out["findings-count"]) == 1, out
