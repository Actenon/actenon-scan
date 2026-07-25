# r04: OpenAI @function_tool — PASSES today
# Expected: >=1 finding (subprocess.run inside @function_tool)
from agents import function_tool, RunContext

@function_tool
def run_command(ctx: RunContext, cmd: str) -> str:
    """Run a shell command."""
    import subprocess
    subprocess.run(cmd, shell=True)
    return "done"
