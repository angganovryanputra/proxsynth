"""
Proxsynth MCP Core Package
Exposes server factory and entrypoints for standard MCP client interaction.
"""

from mcp_core.server import build_mcp, build_and_run, mcp

__all__ = ["build_mcp", "build_and_run", "mcp"]
