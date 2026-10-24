"""
Proxsynth MCP - Project Context & Workspace Scope Tools
"""

import json
from typing import Optional

from mcp_core.server import proxsynth_tool
from mcp_core.gateway import (
    DEFAULT_PROJECT,
    _active_project,
    _active_write_project,
    _resolve_project
)
import mcp_core.gateway as gateway


@proxsynth_tool(name="set_active_project")
async def set_active_project(project: str, write_project: Optional[str] = None) -> str:
    """
    Sets the active project workspace scope for the current MCP session.
    When set, subsequent tool calls without an explicit project parameter will default to this project.
    Passing 'all', '*', 'any', or 'global' enables global visibility stream across all projects.
    When using 'all', you can optionally set write_project to specify which workspace receives write operations.
    """
    p = (project or "").strip().lower()
    if write_project:
        gateway._active_write_project = write_project.strip().lower()
    elif p in ("all", "*", "any", "global"):
        gateway._active_write_project = None

    if p in ("all", "*", "any", "global"):
        gateway._active_project = "all"
        return json.dumps({
            "status": "success",
            "active_project": "all",
            "view_mode": "global",
            "write_project": gateway._active_write_project or DEFAULT_PROJECT,
            "scope_mode": "GLOBAL_ALL_PROJECTS",
            "message": f"Global multi-project stream enabled for reading. Mutation writes will target '{gateway._active_write_project or DEFAULT_PROJECT}' (or target asset's tagged project)."
        }, indent=2)

    gateway._active_project = p if p else DEFAULT_PROJECT
    gateway._active_write_project = gateway._active_project
    return json.dumps({
        "status": "success",
        "active_project": gateway._active_project,
        "view_mode": "scoped",
        "write_project": gateway._active_write_project,
        "scope_mode": "PROJECT_ISOLATED",
        "message": f"Active project context set to '{gateway._active_project}' for both reads and writes."
    }, indent=2)


@proxsynth_tool(name="get_active_project")
async def get_active_project() -> str:
    """
    Returns the currently active project workspace scope, view mode, and write project.
    """
    is_global = (gateway._active_project or "").lower() in ("all", "*", "any", "global")
    return json.dumps({
        "active_project": gateway._active_project or DEFAULT_PROJECT,
        "view_mode": "global" if is_global else "scoped",
        "write_project": gateway._active_write_project or (gateway._active_project if not is_global else DEFAULT_PROJECT),
        "session_active_project": gateway._active_project,
        "default_project": DEFAULT_PROJECT,
        "is_global_stream": is_global
    }, indent=2)
