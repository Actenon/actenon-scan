"""Vulnerable fixture: same class shape as constructor_params_guard.py
but WITHOUT the `dependencies` kwarg on the instantiation.

Negative control for the constructor_params branch — proves the scanner
isn't blanket-suppressing every class named ShellTool. The sink inside
`ShellTool._run` must still fire.
"""
from langchain_core.tools import BaseTool
import subprocess


class ShellTool(BaseTool):
    def _run(self, cmd: str):
        return subprocess.run(cmd, shell=True)


# No constructor_params kwarg → 'ShellTool' is NOT added to
# guarded_classes → the sink inside ShellTool._run must fire.
app = ShellTool()
