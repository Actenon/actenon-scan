import subprocess

class InternalHelper:
    """Not an Action subclass — not agent-reachable."""
    def run(self, cmd):
        return subprocess.run(cmd, shell=True)
