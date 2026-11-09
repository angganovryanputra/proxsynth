"""
Proxsynth MCP - Centralized Tool Registration Envelope & Structured Formatter
Applies standardized MCP annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint),
injects outputSchema for read-only tools, and provides dual-channel execution:
- Direct Python calls return the raw string/data (for 100% test & legacy compatibility).
- FastMCP / MCP JSON-RPC protocol callers receive CallToolResult with structuredContent and text content fallback (<=400 chars).
"""

import os
import json
import functools
import inspect
import contextvars
from typing import Optional, Callable, Any

from mcp.types import CallToolResult, TextContent, ToolAnnotations
from mcp_core import diag
from mcp_core.tool_meta import (
    meta,
    STRUCTURED_READ_ONLY_TOOLS,
    STRUCTURED_OUTPUT_SCHEMAS,
    TOOL_PERMS,
    POWER_MODE_TOOLS,
    HEXAGON_MODE_TOOLS
)

# Per-call structured payload. A ContextVar is isolated per asyncio task, so concurrent
# tool invocations never read each other's data (previously stashed on the function
# object as fn._last_structured, which was shared mutable state across calls).
_structured_ctx: "contextvars.ContextVar[Optional[dict]]" = contextvars.ContextVar(
    "proxsynth_structured_payload", default=None
)


def set_structured(data: Optional[dict]) -> None:
    """Tools call this to attach an explicit structuredContent payload for the current call."""
    _structured_ctx.set(data)


def _coerce_to_dict(raw_res: Any) -> dict:
    """structuredContent must be a JSON object. Coerce whatever a tool returned into one."""
    if isinstance(raw_res, dict):
        return raw_res
    if isinstance(raw_res, list):
        return {"items": raw_res}
    if isinstance(raw_res, str):
        try:
            parsed = json.loads(raw_res)
        except Exception:
            return {"result": raw_res}
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            return {"items": parsed}
        return {"result": parsed}
    return {"result": raw_res}


def register_tool(server, name: Optional[str] = None, description: Optional[str] = None):
    """
    Decorator factory registering a tool onto FastMCP MCPServer with standard annotations
    and structuredContent translation for read-only tools.
    """
    def decorator(fn: Callable) -> Callable:
        tool_name = name or fn.__name__

        # Dual-Mode Registry Check:
        # When PROXSYNTH_TOOL_MODE="power", FastMCP only registers the 18 consolidated power & context tools,
        # cutting prompt token consumption by ~80% (measured) while direct Python callers retain full access to all 104 tools.
        tool_mode = os.getenv("PROXSYNTH_TOOL_MODE", "full").strip().lower()
        if tool_mode == "power" and tool_name not in POWER_MODE_TOOLS:
            return fn
        if tool_mode == "hexagon" and tool_name not in HEXAGON_MODE_TOOLS:
            return fn

        ann = meta(tool_name)
        tool_desc = description or fn.__doc__ or f"Proxsynth tool: {tool_name}"

        is_structured = tool_name in STRUCTURED_READ_ONLY_TOOLS

        if is_structured:
            @functools.wraps(fn)
            async def structured_wrapper(*args, **kwargs) -> CallToolResult:
                token = _structured_ctx.set(None)
                try:
                    raw_res = await fn(*args, **kwargs)

                    if isinstance(raw_res, CallToolResult):
                        return raw_res

                    # Prefer an explicit payload the tool published via set_structured();
                    # otherwise coerce the raw return value into a JSON object.
                    structured_data = _structured_ctx.get()
                    if structured_data is None:
                        structured_data = _coerce_to_dict(raw_res)
                finally:
                    _structured_ctx.reset(token)

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
                diag.exc(f"attach output_schema for {tool_name}")

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
