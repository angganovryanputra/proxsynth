"""
Proxsynth Automated Self-Test Acceptance Gate (Task 7)
Verifies:
1. Clean import of backend.app and mcp_core.server.
2. Complete MCP tool registry containing all 83 tools.
3. MCP-standard ToolAnnotations on all 83 tools.
4. outputSchema on the 8 read-only tools and structuredContent execution.
5. Project workspace scoping consistency.
"""

import sys
import os
import json
import asyncio

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def test_imports():
    print("[1/5] Testing side-effect free imports of backend.app & mcp_core.server...")
    try:
        import backend.app
        import mcp_core.server
        import mcp_server
        print("  -> Passed: backend.app and mcp_core.server imported successfully.")
    except Exception as e:
        print(f"  -> FAILED: Import error: {e}")
        return False
    return True


def test_tool_count_and_annotations():
    print("[2/5] Testing MCP tools registry and standard annotations...")
    import mcp_core.server as s
    from mcp_core.tool_meta import STRUCTURED_READ_ONLY_TOOLS, TOOL_PERMS

    tools = s.mcp._tool_manager.list_tools()
    total = len(tools)
    print(f"  -> Total registered tools: {total}")
    if total != 83:
        print(f"  -> FAILED: Expected exactly 83 tools, found {total}")
        return False

    missing_annotations = []
    missing_hints = []
    for t in tools:
        if not t.annotations:
            missing_annotations.append(t.name)
            continue
        ann = t.annotations
        dumped = ann.model_dump(by_alias=True) if hasattr(ann, "model_dump") else {}
        read_only = getattr(ann, "read_only_hint", None)
        if read_only is None:
            read_only = dumped.get("readOnlyHint")
        if read_only is None:
            missing_hints.append(f"{t.name}: missing readOnlyHint")

        destructive = getattr(ann, "destructive_hint", None)
        if destructive is None:
            destructive = dumped.get("destructiveHint")
        if destructive is None:
            missing_hints.append(f"{t.name}: missing destructiveHint")

    if missing_annotations:
        print(f"  -> FAILED: Tools missing annotations: {missing_annotations}")
        return False
    if missing_hints:
        print(f"  -> FAILED: Tools missing hint attributes: {missing_hints[:5]}")
        return False

    print("  -> Passed: All 83 tools registered with standardized ToolAnnotations.")
    return True


def test_structured_schemas():
    print("[3/5] Testing outputSchema on 8 read-only tools...")
    import mcp_core.server as s
    from mcp_core.tool_meta import STRUCTURED_READ_ONLY_TOOLS

    tools = {t.name: t for t in s.mcp._tool_manager.list_tools()}
    missing_schema = []
    for name in STRUCTURED_READ_ONLY_TOOLS:
        t = tools.get(name)
        if not t or not getattr(t, "output_schema", None):
            missing_schema.append(name)

    if missing_schema:
        print(f"  -> FAILED: Structured read-only tools missing output_schema: {missing_schema}")
        return False

    print(f"  -> Passed: All 8 structured tools publish outputSchema ({len(STRUCTURED_READ_ONLY_TOOLS)} verified).")
    return True


async def test_structured_content_execution():
    print("[4/5] Testing structuredContent return on get_traffic_history...")
    import mcp_core.server as s
    tool = s.mcp._tool_manager.get_tool("get_traffic_history")
    if not tool:
        print("  -> FAILED: get_traffic_history not found in tool manager.")
        return False

    # Execute tool via FastMCP call_tool (the MCP protocol path used by OpenCode)
    res = await s.mcp.call_tool("get_traffic_history", {"project": "all", "limit": 5})
    if not hasattr(res, "structured_content") or not isinstance(res.structured_content, dict):
        print(f"  -> FAILED: Expected structured_content dict, got {type(getattr(res, 'structured_content', None))}")
        return False

    if not hasattr(res, "content") or not res.content or not getattr(res.content[0], "text", None):
        print("  -> FAILED: Missing text content fallback in CallToolResult.")
        return False

    # Verify text fallback length <= 400
    text_len = len(res.content[0].text)
    if text_len > 400:
        print(f"  -> FAILED: Text fallback exceeds 400 chars: {text_len}")
        return False

    print(f"  -> Passed: structuredContent dict populated, fallback text length ({text_len} <= 400).")
    return True


async def test_project_scoping():
    print("[5/5] Testing set_active_project('all') -> get_active_project() consistency...")
    import mcp_core.server as s
    import mcp_core.gateway as gateway

    # Set to 'all'
    set_res_str = await s.mcp.call_tool("set_active_project", {"project": "all"})
    # Get active project
    get_res_str = await s.mcp.call_tool("get_active_project", {})

    get_data = json.loads(get_res_str.content[0].text)
    if get_data.get("active_project") != "all":
        print(f"  -> FAILED: Expected active_project 'all', got {get_data.get('active_project')}")
        return False
    if get_data.get("view_mode") != "global":
        print(f"  -> FAILED: Expected view_mode 'global', got {get_data.get('view_mode')}")
        return False

    # Reset back to default
    await s.mcp.call_tool("set_active_project", {"project": "default"})
    print("  -> Passed: Scoping transitions and global view_mode verified.")
    return True


async def main():
    print("=" * 65)
    print("PROXSYNTH AUTOMATED ACCEPTANCE GATE (TASK 7 SELF-TEST)")
    print("=" * 65)

    success = True
    success = success and test_imports()
    success = success and test_tool_count_and_annotations()
    success = success and test_structured_schemas()
    success = success and await test_structured_content_execution()
    success = success and await test_project_scoping()

    print("=" * 65)
    if success:
        print("ALL ACCEPTANCE GATE CHECKS PASSED (EXIT CODE 0)")
        print("=" * 65)
        sys.exit(0)
    else:
        print("ACCEPTANCE GATE FAILED (EXIT CODE 1)")
        print("=" * 65)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
