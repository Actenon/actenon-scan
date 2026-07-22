"""Vulnerable fixture: an MCP @server.tool that calls os.remove and shutil.rmtree."""

import os
import shutil

from mcp.server import Server

server = Server("file-manager")


@server.tool()
def cleanup_files(file_path: str, dir_path: str) -> str:
    """Clean up files and directories."""
    os.remove(file_path)
    shutil.rmtree(dir_path)
    return "cleaned up"
