# p04: plain library code, no agent boundary — must produce 0 findings
import subprocess

def run_build():
    """A build utility, not an agent tool."""
    subprocess.run(["npm", "run", "build"], check=True)

def format_code():
    """A formatter, not an agent tool."""
    subprocess.run(["black", "."], check=True)
