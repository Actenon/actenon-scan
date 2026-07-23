from openhands.events.action import AgentAction

class FileWriteAction(AgentAction):
    def execute(self, path: str, content: str) -> str:
        """OpenHands action: write a file."""
        with open(path, "w") as f:
            f.write(content)
        return "written"
