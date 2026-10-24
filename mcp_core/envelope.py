"""
Proxsynth MCP - Centralized Tool Registration Envelope & Structured Formatter
Applies standardized MCP annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint),
injects outputSchema for read-only tools, and provides dual-channel execution:
- Direct Python calls return the raw string/data (for 100% test & legacy compatibility).
- FastMCP / MCP JSON-RPC protocol callers receive CallToolResult with structuredContent and text content fallback (<=400 chars).
"""

import json
import functools
import inspect
from typing import Optional, Callable, Any

from mcp.types import CallToolResult, TextContent, ToolAnnotations
from mcp_core.tool_meta import (
    meta,
    STRUCTURED_READ_ONLY_TOOLS,
    STRUCTURED_OUTPUT_SCHEMAS,
    TOOL_PERMS
)


def register_tool(server, name: Optional[str] = None, description: Optional[str] = None):
    """
    Decorator factory registering a tool onto FastMCP MCPServer with standard annotations
    and structuredContent translation for read-only tools.
    """
    def decorator(fn: Callable) -> Callable:
        tool_name = name or fn.__name__
        ann = meta(tool_name)
        tool_desc = description or fn.__doc__ or f"Proxsynth tool: {tool_name}"

        is_structured = tool_name in STRUCTURED_READ_ONLY_TOOLS

        if is_structured:
            @functools.wraps(fn)
            async def structured_wrapper(*args, **kwargs) -> CallToolResult:
                raw_res = await fn(*args, **kwargs)

                if isinstance(raw_res, CallToolResult):
                    return raw_res

                # Check for explicit structured payload cached by tool execution
                structured_data = getattr(fn, "_last_structured", None)
                if structured_data is None:
                    if isinstance(raw_res, dict):
                        structured_data = raw_res
                    elif isinstance(raw_res, str):
                        try:
                            structured_data = json.loads(raw_res)
                        except Exception:
                            structured_data = {"result": raw_res}
                    else:
                        structured_data = {"result": raw_res}

                text_fallback = (str(raw_res) if not isinstance(raw_res, dict) else json.dumps(raw_res, indent=2))[:400]

                return CallToolResult(
                    content=[TextContent(type="text", text=text_fallback)],
                    structured_content=structured_data
                )

            # Register wrapper into FastMCP tool manager
            server.tool(
                name=tool_name,
                description=tool_desc,
                annotations=ann
            )(structured_wrapper)

            # Assign outputSchema on the registered tool definition in FastMCP tool manager
            try:
                for t in server._tool_manager.list_tools():
                    if t.name == tool_name:
                        t.output_schema = STRUCTURED_OUTPUT_SCHEMAS.get(tool_name, {"type": "object"})
                        if hasattr(t, "fn_metadata"):
                            t.fn_metadata.output_model = None
                        break
            except Exception:
                pass

            # Return original fn for python direct callers
            return fn
        else:
            # Standard tool registration with annotations
            server.tool(
                name=tool_name,
                description=tool_desc,
                annotations=ann
            )(fn)
            return fn

    return decorator
