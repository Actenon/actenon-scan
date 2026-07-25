# r06: action/observation class (OpenHands style) — MISSED today
# Expected: >=1 finding (subprocess.run inside an action dispatcher)
# Pattern: Action dataclass with command field, Runtime.run_action() dispatches to sink
import subprocess
from dataclasses import dataclass

@dataclass
class CmdRunAction:
    command: str
    thought: str = ""

class Runtime:
    def run_action(self, action) -> str:
        """Execute an action. This is the agent boundary."""
        if isinstance(action, CmdRunAction):
            return self._run_cmd(action)
        return "unknown action"

    def _run_cmd(self, action: CmdRunAction) -> str:
        result = subprocess.run(action.command, shell=True, capture_output=True, text=True)
        return result.stdout

runtime = Runtime()
