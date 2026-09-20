"""Resource-boundary entry point tests.

FastAPI/Flask route handlers are detected as reachable, and non-handler
functions in the same file are not.

The signal is OPT-IN: it ships off, and these tests enable it. That is the
whole subject of `tests/test_resource_boundary_optin.py`, which asserts the
default is off and that the same sources produce nothing without the flag.
`_scan_source` therefore enables it explicitly — the behaviour under test
here is what the signal does when a user asks for it, not whether it is on.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path


def _scan_source(source: str):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.py"
        p.write_text(source)
        return scan_path(Path(td), resource_boundary=True)


def test_fastapi_route_handler_unguarded():
    """FastAPI @app.post handler with unguarded sink is flagged."""
    source = '''import subprocess
from fastapi import FastAPI
app = FastAPI()

@app.post("/run")
def run_command(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''
    result = _scan_source(source)
    active = [f for f in result.findings if not f.suppressed]
    assert len(active) >= 1
    assert any(f.rule_id == "EXEC-SHELL" for f in active)


def test_fastapi_route_handler_guarded():
    """FastAPI handler with dominating guard is GUARD_FOUND, not a finding."""
    source = '''import subprocess, os
from fastapi import FastAPI
app = FastAPI()

@app.delete("/files/{path}")
def delete_file(path: str):
    authorize(path)
    os.remove(path)

def authorize(path: str) -> None:
    if not path.startswith("/safe/"):
        raise PermissionError(path)
'''
    result = _scan_source(source)
    caps = [c for c in result.capabilities if c.category == "data_destruction"]
    assert len(caps) == 1
    assert caps[0].state == "GUARD_FOUND"
    assert caps[0].reachability_reason == "resource_boundary"


def test_flask_route_handler_unguarded():
    """Flask @app.route handler with unguarded sink is flagged."""
    source = '''import subprocess
from flask import Flask, request
app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run_command():
    cmd = request.form["cmd"]
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''
    result = _scan_source(source)
    active = [f for f in result.findings if not f.suppressed]
    assert len(active) >= 1


def test_non_handler_function_not_flagged():
    """A non-handler function in the same file is NOT reachable."""
    source = '''import subprocess
from fastapi import FastAPI
app = FastAPI()

@app.post("/run")
def run_command(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()

def internal_helper(cmd: str):
    # This is NOT a route handler — should not be flagged
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''
    result = _scan_source(source)
    active = [f for f in result.findings if not f.suppressed]
    # Only the route handler should be flagged, not internal_helper
    assert len(active) == 1
    assert active[0].line < 10  # the route handler is before line 10


def test_flask_blueprint_route():
    """Flask Blueprint (@bp.route) is detected."""
    source = '''import os
from flask import Blueprint
bp = Blueprint("api", __name__)

@bp.route("/delete/<path>", methods=["DELETE"])
def delete_file(path):
    os.remove(path)
'''
    result = _scan_source(source)
    active = [f for f in result.findings if not f.suppressed]
    assert len(active) >= 1
    assert active[0].rule_id == "DATA-DELETE-OS"


def test_fastapi_router():
    """FastAPI APIRouter (@router.post) is detected."""
    source = '''import os
from fastapi import APIRouter
router = APIRouter()

@router.post("/cleanup")
def cleanup(directory: str):
    os.remove(directory)
'''
    result = _scan_source(source)
    active = [f for f in result.findings if not f.suppressed]
    assert len(active) >= 1


def test_capability_records_resource_boundary_source():
    """Capability records resource_boundary as the reachability reason."""
    source = '''import subprocess
from fastapi import FastAPI
app = FastAPI()

@app.post("/run")
def run_command(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''
    result = _scan_source(source)
    caps = result.capabilities
    assert len(caps) >= 1
    assert "resource_boundary" in caps[0].reachability_reason


def test_every_source_in_this_file_is_silent_at_defaults():
    """The counterpart assertion: none of the above fires unless asked for.

    Each source here is a plain web handler with no agent framework. Scanned
    at defaults they must all be silent, which is what makes pallets/flask
    come back clean.
    """
    sources = [
        '''import subprocess
from fastapi import FastAPI
app = FastAPI()

@app.post("/run")
def run_command(cmd: str):
    subprocess.run(cmd, shell=True)
''',
        '''import subprocess
from flask import Flask, request
app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run_command():
    subprocess.run(request.form["cmd"], shell=True)
''',
        '''import subprocess
from fastapi import APIRouter
router = APIRouter()

@router.post("/run")
def run_command(cmd: str):
    subprocess.run(cmd, shell=True)
''',
    ]
    for source in sources:
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "test.py").write_text(source)
            result = scan_path(Path(td))
            findings = [f for f in result.findings if not f.suppressed]
            assert findings == [], (
                f"resource-boundary fired at defaults: "
                f"{[(f.rule_id, f.line) for f in findings]}"
            )
