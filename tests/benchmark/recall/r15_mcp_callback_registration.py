# r15: MCP callback registration via @server.call_tool() + executor dispatch.
# Real source: browser-use/browser_use @ 0964ad452a9f3fe249042a5ffb235e5f98519b2e
#               browser_use/mcp/cli_mcp.py:128 (and the :105 multi-hop chain)
# Pattern: CLIMCPServer._register_handlers decorates a nested async function
#          with @self.server.call_tool(); that handler invokes a same-class
#          method via asyncio.to_thread(self._execute, code). The sink is
#          exec(code, ns) inside _execute (line 128).
# Mechanism: CALLBACK_REGISTRATION (the @server.call_tool() boundary) and
#          MULTI_HOP_LOCAL_CALL (the :105 chain through _ensure_namespace).
# Expected: >=1 finding (same_class_method signal, MEDIUM confidence, 1 hop)
#
# Conservative notes:
#  - @self.server.call_tool() matches the "call_tool" entry in
#    tool_decorators via the new suffix-matching rule. The nested handler
#    becomes an agent-reachable entrypoint.
#  - asyncio.to_thread(self._execute, code) is recognised as a same-class
#    call edge (the executor invokes _execute on the same `self`).
#  - getattr(self, name) and other dynamic registration shapes are NOT
#    resolved — disclosed as unresolved entry points.

import asyncio
from mcp.server import Server


class CLIMCPServer:
    def __init__(self):
        self.server = Server("browser-use")
        self._namespace = None
        self._register_handlers()

    def _register_handlers(self):
        @self.server.call_tool()
        async def handle_call_tool(name, arguments):
            arguments = arguments or {}
            if name == "browser_exec":
                code = arguments.get("code")
                output = await asyncio.to_thread(self._execute, code)
                return output
            return "unknown"

    def _execute(self, code: str) -> str:
        ns = {}
        exec(code, ns)  # sink at line ~36 (exec in _execute)
        return ""
