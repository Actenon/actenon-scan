"""Every command string the build prints must resolve in that same build.

Release-integrity regression guard. A shipped build that prints
``actenon-scan explain <loc>`` while registering no ``explain`` subparser
sends the user to ``invalid choice``. The gate asserts against the live
subparser registry, so it travels with whatever build is under test.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GATE = REPO / "scripts" / "check_printed_commands.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_printed_commands", GATE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_printed_commands"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_gate_passes_on_this_build():
    """The shipped source prints no command this build cannot run."""
    gate = _load_gate()
    assert gate.main() == 0


def test_registry_includes_the_commands_the_scan_output_advertises():
    """`explain` and `fix` are the two commands the scan footer prints."""
    gate = _load_gate()
    registered = gate.registered_subcommands()
    assert {"scan", "explain", "fix"} <= registered


def test_html_format_is_a_real_choice():
    """`--format html` is advertised in docs and must parse."""
    from actenon_scan.cli import build_parser

    args = build_parser().parse_args(["scan", ".", "--format", "html"])
    assert args.format == "html"


@pytest.mark.parametrize(
    "text,expected",
    [
        # Invocations — introduced by a marker, command-shaped remainder.
        ("Next: actenon-scan explain foo.py:42", True),
        ("  actenon-scan fix a/b.py:1", True),
        ("`actenon-scan scan .`", True),
        ("  uvx actenon-scan scan .", True),
        ("Run 'actenon-scan install github --help' for details.", True),
        ("actenon-scan rules", True),
        # Prose — must never be mistaken for a command.
        ("the contract between actenon-scan and any code that embeds it", False),
        ("Path to an actenon-scan config file (JSON or YAML).", False),
        ("file in the actenon-scan repository for supported architectures", False),
        ("# actenon-scan configuration", False),
    ],
)
def test_invocation_discriminator(text, expected):
    gate = _load_gate()
    match = gate.COMMAND_RE.search(text)
    assert match is not None
    assert gate._is_invocation(text, match.start(), match.end()) is expected


def test_gate_fails_on_an_unregistered_printed_command(tmp_path, monkeypatch):
    """A printed hint for a command that does not exist must fail the gate."""
    gate = _load_gate()
    pkg = tmp_path / "actenon_scan"
    pkg.mkdir()
    (pkg / "report.py").write_text(
        'def f(loc):\n    return f"Next: actenon-scan triage {loc}"\n'
    )
    monkeypatch.setattr(gate, "PKG", pkg)
    monkeypatch.setattr(gate, "REPO", tmp_path)
    assert gate.main() == 1
