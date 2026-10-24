"""
Proxsynth MCP - Oast Tools
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


@proxsynth_tool(name="generate_oast_token")
async def generate_oast_token(
    vuln_type: str = "BLIND_CALLBACK",
    description: str = "",
    provider: str = "auto",
    project: Optional[str] = None
) -> str:
    """
    Generates a unique Out-of-Band Application Security Testing (OAST) interaction token
    for detecting blind vulnerabilities (Blind SSRF, Out-of-band SQLi, Blind RCE, XXE, JNDI).
    Supports public Interactsh ('interactsh'), custom callback ('custom'), local ('local'), or 'auto'.
    Returns the token and pre-built callback URL to embed inside your exploit payload.
    After injecting the payload into the target, call 'poll_oast_events(token)' to verify if target contacted Proxynth!
    """
    target_project = _resolve_project(project, allow_all=False)
    oast_meta = engine_generate_oast_token(
        project=target_project,
        description=description,
        vuln_type=vuln_type,
        provider=provider
    )
    return json.dumps(oast_meta, indent=2)


# ==============================================================================
# MCP Tool 14: poll_oast_events (Verify Blind Callback Reception)
# ==============================================================================

@proxsynth_tool(name="poll_oast_events")
async def poll_oast_events(
    token: str,
    timeout_seconds: float = 5.0,
    project: Optional[str] = None
) -> str:
    """
    Awaits and retrieves any incoming callbacks received for a specific OAST token.
    If the target server triggered the callback, returns confirmation with target IP, HTTP method,
    headers, and exfiltrated body data.
    """
    target_project = _resolve_project(project, allow_all=True)
    events = await engine_poll_oast_events(
        token=token,
        project=target_project,
        timeout_seconds=timeout_seconds
    )
    if not events:
        return json.dumps({
            "status": "pending",
            "token": token,
            "callback_received": False,
            "callbacks_count": 0,
            "events": [],
            "message": f"No callbacks received yet for token '{token}' after waiting {timeout_seconds}s."
        }, indent=2)

    return json.dumps({
        "status": "confirmed_interaction",
        "token": token,
        "callback_received": True,
        "callbacks_count": len(events),
        "events": events
    }, indent=2)


# ==============================================================================
# MCP Tool 15: set_identity_session (Multi-Identity Vault for BOLA/IDOR Testing)
# ==============================================================================

@proxsynth_tool(name="spray_oast_canaries")
async def spray_oast_canaries(
    target_url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: str = "",
    target_params: Optional[List[str]] = None,
    vuln_types: Optional[List[str]] = None,
    project: Optional[str] = None,
    agent_id: str = "primary_agent"
) -> str:
    """
    Autonomously sprays multi-protocol OAST canary tokens (HTTP, DNS, LDAP/JNDI, XXE) across
    all discovered query, body, and header parameters. Correlates incoming out-of-band callbacks
    to deterministically detect Blind SSRF, Blind RCE, XXE, and Log4j with zero manual effort.

    Parameters:
      - target_url: Full URL of the target endpoint.
      - method: HTTP method ('GET', 'POST', etc.). Defaults to 'GET'.
      - headers: Optional custom headers.
      - body: Optional body data.
      - target_params: Specific parameters to spray (leave empty to auto-discover all parameters).
      - vuln_types: List of vulnerability vectors ('ssrf', 'dns', 'log4j', 'xxe', 'all'). Defaults to ['ssrf', 'dns', 'log4j'].
      - project: Project workspace name. Defaults to active project or 'default'.
      - agent_id: Identifier of the testing agent. Defaults to 'primary_agent'.
    """
    from backend.oast_sprayer import spray_oast_canaries as run_spray

    target_project = _resolve_project(project, allow_all=False)

    # Scope validation
    db = SessionLocal()
    try:
        is_allowed, block_reason = await async_check_scope(target_project, target_url, db)
        if not is_allowed:
            return f"[!] Out of Scope: Target '{target_url}' violates guardrail policy: {block_reason}"
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        upstream_proxy = proj_obj.upstream_proxy if proj_obj else None
    finally:
        db.close()

    res = await run_spray(
        target_url=target_url,
        method=method,
        headers=headers,
        body=body,
        target_params=target_params,
        vuln_types=vuln_types,
        project=target_project,
        agent_id=agent_id,
        upstream_proxy=upstream_proxy
    )
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tool 34: record_testing_hypothesis (P3)
# ==============================================================================

@proxsynth_tool(name="setup_public_tunnel")
async def setup_public_tunnel(
    provider: str = "auto",
    local_port: int = 8000,
    project: Optional[str] = None
) -> str:
    """
    Spins up a public Cloudflare Quick Tunnel or ngrok tunnel, binding the public URL
    to Proxsynth's OAST callback listener. Enables external targets to deliver callbacks
    (SSRF, Blind SQLi, XXE, OOB RCE) across NAT and firewalls.
    """
    from backend.tunnel_manager import start_public_tunnel
    proj = _resolve_project(project, allow_all=False)
    res = await start_public_tunnel(provider=provider, local_port=local_port, project=proj)
    return json.dumps(res, indent=2)

@proxsynth_tool(name="get_tunnel_status")
async def get_tunnel_status() -> str:
    """
    Returns the operational status, provider, public URL, uptime, and callback base URL
    for the active public ingress tunnel.
    """
    from backend.tunnel_manager import get_tunnel_status as get_status
    return json.dumps(get_status(), indent=2)

@proxsynth_tool(name="close_public_tunnel")
async def close_public_tunnel() -> str:
    """
    Gracefully terminates the active public tunnel and restores the OAST callback URL to local backend.
    """
    from backend.tunnel_manager import stop_public_tunnel
    res = await stop_public_tunnel()
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tools: Autonomous Interception & Match/Replace Rules
# ==============================================================================
