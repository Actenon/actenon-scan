import subprocess
from crewai import Tool

@Tool("Runner", "Runs a process")
def run_process(cmd: str) -> str:
    """Run a process."""
    proc = subprocess.Popen(cmd, shell=True)
    proc.wait()
    return "done"
