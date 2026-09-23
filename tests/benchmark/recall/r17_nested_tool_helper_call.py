# r17: nested @tool entrypoint calling a same-class helper (AgentMiddleware).
# Real source: langchain-ai/langchain @ fa7ce760a26437a904a4c93db75333f01d65ed83
#   libs/langchain_v1/langchain/agents/middleware/file_search.py:314
#     (FilesystemFileSearchMiddleware._ripgrep_search)
#   libs/partners/anthropic/langchain_anthropic/middleware/anthropic_tools.py:1040
#     (_FilesystemClaudeFileToolMiddleware._handle_delete)
# Pattern: AgentMiddleware subclass __init__ defines a nested @tool-decorated
#          function that calls self._handle_delete(...) (a same-class method).
#          The sink sits inside the helper method.
# Mechanism: LOCAL_HELPER_CALL (nested @tool entrypoint + same-class method).
# Expected: >=1 finding (same_class_method signal, MEDIUM confidence, 1 hop)

import shutil
from langchain_core.tools import tool


class FileMiddleware:
    def __init__(self):
        @tool
        def file_tool(command: str, path: str):
            if command == "delete":
                return self._handle_delete(path)
            return "noop"

        self.tools = [file_tool]

    def _handle_delete(self, path: str) -> str:
        import os
        full_path = os.path.join("/tmp", path)
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)  # sink
        return f"deleted {path}"
