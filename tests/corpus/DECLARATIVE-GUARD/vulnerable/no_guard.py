from langchain_core.tools import BaseTool
import subprocess

class ShellTool(BaseTool):
    def _run(self, cmd: str):
        return subprocess.run(cmd, shell=True)
