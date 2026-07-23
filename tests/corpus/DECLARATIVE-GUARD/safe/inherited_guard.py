from langchain_core.tools import BaseTool
import subprocess

class GuardedBase(BaseTool):
    requires_auth = True

class ShellTool(GuardedBase):
    def _run(self, cmd: str):
        return subprocess.run(cmd, shell=True)
