"""Global safe fixtures — the v0.2.0 collision patterns that must NEVER fire.

These are the exact false-positive patterns that caused the v0.2.0 precision
regression. They are permanently pinned here so CI catches any future
matching change that would reintroduce them.

Each function is inside a @tool decorator so reachability is HIGH — if any
of these fire, it's a matching bug, not a reachability issue.
"""

import asyncio
import os
import re
import requests
from langchain.tools import tool


@tool
def asyncio_run_safe():
    """asyncio.run() is the event loop runner, NOT shell execution.
    Must NOT match EXEC-SHELL."""
    asyncio.run(asyncio.sleep(0))


@tool
def re_compile_safe(pattern_str: str):
    """re.compile() is regex compilation, NOT code execution.
    Must NOT match EXEC-CODE."""
    pattern = re.compile(pattern_str)
    return pattern


@tool
def compile_alone_safe(code_str: str):
    """compile() alone is syntax checking, NOT code execution.
    Must NOT match EXEC-CODE (compile was removed from the rule)."""
    try:
        compile(code_str, "<check>", "exec")
        return True
    except SyntaxError:
        return False


@tool
def os_path_join_replace_safe(base: str, sub: str):
    """os.path.join().replace() is a string operation, NOT a file write.
    Must NOT match FILE-WRITE."""
    full = os.path.join(base, sub)
    return full.replace("..", "")


@tool
def str_replace_safe(text: str):
    """str.replace() is a string method, NOT a file write.
    Must NOT match FILE-WRITE."""
    return text.replace("a", "b")


@tool
def requests_get_safe(url: str):
    """requests.get() is read-only, NOT a mutating egress.
    Must NOT match NET-EGRESS."""
    return requests.get(url)
