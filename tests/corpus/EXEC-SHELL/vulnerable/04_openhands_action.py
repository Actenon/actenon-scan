from openhands.events.action import Action
import subprocess

class RunCommandAction(Action):
    def run(self, command: str) -> str:
        """OpenHands action: run a shell command."""
        return subprocess.run(command, shell=True, capture_output=True).stdout.decode()
