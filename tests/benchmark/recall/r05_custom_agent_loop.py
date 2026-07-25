# r05: custom agent loop (Open Interpreter style) — MISSED today
# Expected: >=1 finding (subprocess.run inside a method that receives LLM output)
# Pattern: class with chat() -> run() -> subprocess, where the LLM output
# flows into the command argument.
import subprocess
import json

class Agent:
    def chat(self, user_input: str) -> str:
        """Chat with the agent. LLM output flows into run()."""
        # Simulate LLM generating a command
        llm_output = f"echo {user_input}"
        return self.run(llm_output)

    def run(self, code: str) -> str:
        """Run code from the LLM. This is the agent boundary."""
        result = subprocess.run(code, shell=True, capture_output=True, text=True)
        return result.stdout

agent = Agent()
agent.chat("hello")
