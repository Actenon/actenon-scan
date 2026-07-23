import subprocess

def internal_helper(cmd):
    """subprocess in a non-tool function — not agent-reachable."""
    return subprocess.run(cmd, shell=False, capture_output=True)
