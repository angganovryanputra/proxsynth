"""
Proxsynth MCP - Session Tools
Modular component of Proxsynth FastMCP Server.
"""

import os
import sys
import re
import json
import time
import asyncio
import urllib.parse
from typing import Optional, Dict, Any, List, Union, Tuple
import httpx
import difflib
from sqlalchemy import func

from backend.database import (
    SessionLocal,
    ActiveSession,
    HttpLog,
    Finding,
    Project,
    AgentCommandLog,
    CapturedPayload,
    TargetAsset,
    TargetService,
    TargetEndpoint,
    OastEvent,
    TestingHypothesis
)
from backend.analyzer import analyze_traffic
from backend.browser_handler import render_page, spawn_interactive_login
from backend.intercept_manager import (
    is_intercept_enabled,
    create_intercept_trap,
    pop_intercept_result,
    check_scope,
    async_check_scope
)
from backend.security_utils import (
    check_command_safe_mode,
    async_check_command_safe_mode,
    check_ssrf_safety,
    async_check_ssrf_safety
)
from backend.target_manager import (
    upsert_target_asset,
    add_or_update_service,
    add_or_update_endpoint,
    get_attack_surface_graph
)
from backend.oast_engine import (
    generate_oast_token as engine_generate_oast_token,
    poll_oast_events as engine_poll_oast_events
)
from backend.user_agents import apply_rotating_user_agent, get_random_user_agent
from backend.fuzzer import run_fuzz_attack, BUILTIN_PAYLOADS, MARKER_REGEX

from mcp_core.server import proxsynth_tool
from mcp_core.gateway import (
    DEFAULT_PROJECT,
    BACKEND_URL,
    get_backend_url,
    _resolve_project,
    _active_project,
    _active_write_project,
    _persist_and_stream_log,
    _persist_and_stream_command,
    _persist_and_stream_payload,
    _extract_domain_cookies,
    _get_outbound_client,
    _get_dashboard_client
)
import mcp_core.gateway as gateway
from mcp_core.tool_meta import TOOL_PERMS, TOOL_HARNESS_METADATA


@proxsynth_tool(name="set_identity_session")
async def set_identity_session(
    domain: str,
    identity_role: str = "attacker",
    raw_cookies: str = "",
    project: Optional[str] = None
) -> str:
    """
    Registers an authenticated session tagged with a specific identity role (e.g. 'attacker', 'victim', 'admin', 'guest').
    Enables Proxynth's Autonomous BOLA/IDOR Shadow Matrix to test authorization boundaries across identities.
    
    Parameters:
      - domain: Target hostname (e.g. 'target.local' or 'api.target.com').
      - identity_role: The role tag (default: 'attacker', or 'victim', 'admin', 'guest').
      - raw_cookies: Cookie string (e.g. 'session=xyz; token=abc').
      - project: Workspace name (defaults to active project).
    """
    from backend.bola_matrix import set_identity_session as engine_set_identity
    target_project = _resolve_project(project, allow_all=False)
    res = engine_set_identity(
        project=target_project,
        domain=domain,
        identity_role=identity_role,
        raw_cookie_str=raw_cookies
    )
    return json.dumps({
        "status": "success",
        "message": f"Session identity [{identity_role}] registered for {domain}.",
        "identity": res
    }, indent=2)


# ==============================================================================
# MCP Tool 16: test_bola_idor (Autonomous BOLA / IDOR Verification)
# ==============================================================================

@proxsynth_tool(name="register_auth_recipe")
async def register_auth_recipe(
    login_url: str,
    method: str = "POST",
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    token_json_path: str = "token",
    auth_header_format: str = "Bearer {token}",
    cookie_names: Optional[List[str]] = None,
    project: Optional[str] = None
) -> str:
    """
    Registers an autonomous re-authentication recipe for zero-human session maintenance.
    Whenever authentication drops or a 401 is encountered, Proxynth will replay this recipe
    in the background, refresh bearer tokens / session cookies, and keep the agent unblocked.
    """
    from backend.auth_macro import register_auth_recipe
    proj = _resolve_project(project, allow_all=False)
    res = register_auth_recipe(
        project=proj,
        login_url=login_url,
        method=method,
        payload=payload,
        headers=headers,
        token_json_path=token_json_path,
        auth_header_format=auth_header_format,
        cookie_names=cookie_names
    )
    return json.dumps(res, indent=2)

@proxsynth_tool(name="execute_reauthentication")
async def execute_reauthentication(project: Optional[str] = None) -> str:
    """
    Manually or proactively triggers the registered re-authentication recipe for a project.
    Refreshes session tokens and cookies in the active credential vault.
    """
    from backend.auth_macro import execute_reauth
    proj = _resolve_project(project, allow_all=False)
    res = await execute_reauth(proj)
    return json.dumps(res, indent=2)

@proxsynth_tool(name="get_csrf_tokens")
async def get_csrf_tokens(domain: Optional[str] = None, project: Optional[str] = None) -> str:
    """
    Retrieves all auto-tracked and manual anti-CSRF tokens extracted from HTTP responses.
    """
    from backend.session_tracker import get_tracked_csrf_tokens
    proj = _resolve_project(project, allow_all=True)
    tokens = get_tracked_csrf_tokens(domain=domain, project=proj)
    return json.dumps(tokens, indent=2)

@proxsynth_tool(name="set_csrf_token")
async def set_csrf_token(
    domain: str,
    token_value: str,
    token_name: str = "csrf_token",
    project: Optional[str] = None
) -> str:
    """
    Manually sets an anti-CSRF token for a target domain, which will be auto-injected
    into subsequent POST/PUT/PATCH/DELETE requests.
    """
    from backend.session_tracker import set_manual_csrf_token
    proj = _resolve_project(project, allow_all=False)
    rec = set_manual_csrf_token(domain=domain, token_name=token_name, token_value=token_value, project=proj)
    return json.dumps(rec, indent=2)

@proxsynth_tool(name="clear_csrf_tokens")
async def clear_csrf_tokens(domain: Optional[str] = None, project: Optional[str] = None) -> str:
    """
    Clears cached anti-CSRF tokens for a domain or project.
    """
    from backend.session_tracker import clear_tracked_csrf_tokens
    proj = _resolve_project(project, allow_all=True)
    cleared = clear_tracked_csrf_tokens(domain=domain, project=proj)
    return json.dumps({"status": "success", "cleared_count": cleared}, indent=2)


# ==============================================================================
# MCP Tools: Advanced Multi-Dimensional Traffic Search
# ==============================================================================
