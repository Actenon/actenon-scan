# r03: BaseTool._run — PASSES today
# Expected: >=1 finding (subprocess.run inside BaseTool._run)
from langchain_core.tools import BaseTool

class ShellTool(BaseTool):
    name: str = "shell"
    description: str = "Run a shell command"

    def _run(self, cmd: str):
        import subprocess
        subprocess.run(cmd, shell=True)
