from langchain_core.tools import BaseTool
import subprocess

# Tool class instantiated with permissions= constructor param
class SecureShellTool(BaseTool):
    def _run(self, cmd: str):
        """Guarded by permissions= constructor param."""
        return subprocess.run(cmd, shell=True)

# The permissions= kwarg marks SecureShellTool as guarded
SecureShellTool(permissions=["admin"])
