# r07: raw tool-schema dispatch — MISSED today
# Expected: >=1 finding (subprocess.run inside a dispatch function that
# switches on tool name from a TOOLS schema list)
import subprocess
import json

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a shell command",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The command to run"}
                },
                "required": ["command"]
            }
        }
    }
]

def dispatch_tool(name: str, args: dict) -> str:
    """Dispatch a tool call from the LLM. This is the agent boundary."""
    if name == "run_command":
        command = args.get("command", "")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    return "unknown tool"
