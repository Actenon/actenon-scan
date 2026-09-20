# r11: same-class method resolution — BaseTool._run calls self.helper() which has a sink.
# Real source: crewAIInc/crewAI @ b3aaaab023a53a08db4d36c9430b3463f1efcc7d
#               lib/crewai-tools/src/crewai_tools/tools/stagehand_tool/stagehand_tool.py:506
# Pattern: StagehandTool(BaseTool)._run -> self._async_run() -> sink at :506
# Expected: >=1 finding (same_class_method signal, MEDIUM confidence)

from crewai_tools.tools.base_tool import BaseTool
import subprocess


class StagehandTool(BaseTool):
    def _run(self, query: str) -> str:
        """Agent-reachable entrypoint — _run is a tool_base_class_method."""
        return self._async_run(query)

    def _async_run(self, query: str) -> str:
        """Same-class method called from _run. Contains the sink."""
        # The sink — agent-controlled query flows to subprocess
        result = subprocess.run(query, shell=True, capture_output=True)
        return result.stdout.decode()
