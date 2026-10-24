"""
Proxsynth MCP - Server Factory & Tool Loader
Initializes FastMCP ("proxsynth") instance and registers all 83 modular tools.
"""

import sys
import os

try:
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        from mcp.server import Server as FastMCP

from mcp_core.envelope import register_tool

mcp = FastMCP("proxsynth")


def proxsynth_tool(name=None, description=None):
    """Convenient tool registration decorator bound to the active mcp server instance."""
    return register_tool(mcp, name=name, description=description)


# Import all tool modules so decorators execute and register on mcp
import mcp_core.tools


def build_mcp():
    """Returns the fully initialized and registered FastMCP instance."""
    return mcp


def build_and_run():
    """Executes the FastMCP server with stdio transport."""
    mcp.run()


if __name__ == "__main__":
    build_and_run()
