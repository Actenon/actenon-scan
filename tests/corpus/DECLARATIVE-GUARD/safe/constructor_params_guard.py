"""Safe fixture: tool instantiated with `dependencies=[Depends(auth)]`.

This is the constructor_params declarative-guard path. It exercises the
branch in _find_declarative_guarded_classes that crashed in v0.2.2
(AttributeError: 'Name' object has no attribute 'name').

The scanner must:
  1. Walk all Call nodes and find `ShellTool(dependencies=[...])`.
  2. Add 'ShellTool' to guarded_classes (via _callee_name, not .name).
  3. See the sink (subprocess.run) is inside class ShellTool.
  4. Suppress the finding as declaratively guarded.

This is the call shape that crashed every plain constructor call in v0.2.2,
so it MUST stay in the corpus — without it the corpus gate does not cover
the constructor_params branch.
"""
from langchain_core.tools import BaseTool
from fastapi import Depends
from auth import require_auth
import subprocess


class ShellTool(BaseTool):
    def _run(self, cmd: str):
        return subprocess.run(cmd, shell=True)


# Constructor-param declarative guard: the `dependencies` kwarg declares
# that this tool requires authorization to run. The plain-Name call shape
# (`ShellTool(...)`) is exactly what triggered the v0.2.2 AttributeError.
app = ShellTool(dependencies=[Depends(require_auth)])
