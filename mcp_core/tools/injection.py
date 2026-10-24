"""
Proxsynth MCP - Injection Tools
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


@proxsynth_tool(name="fuzz_endpoint")
async def fuzz_endpoint(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: str = "",
    payload_type: str = "sqli",
    custom_payloads: Optional[list] = None,
    concurrency: int = 5,
    delay_ms: Optional[float] = 50.0,
    jitter_ms: Optional[float] = 25.0,
    project: Optional[str] = None,
    agent_id: str = "primary_agent"
) -> str:
    """
    Executes high-speed parameter fuzzing against a target endpoint using position markers (§...§).
    Automates baseline request calculation, differential analysis, status code changes, response length deltas,
    and offensive anomaly detection (SQL errors, reflected payloads, WAF blocks) using rotating legitimate browser headers.
    Features adaptive pacing (delay_ms) and randomized jitter (jitter_ms) to avoid Imperva / Cloudflare bot-bans.

    Parameters:
      - url: Target URL with optional §marker§ (e.g. 'http://target/api/users?id=§1§')
      - method: HTTP method ('GET', 'POST', etc.)
      - headers: Optional custom HTTP headers
      - body: Request body with optional §marker§ (e.g. '{"user":"§admin§","pass":"test"}')
      - payload_type: Built-in payload preset ('sqli', 'xss', 'traversal', 'cmd_injection', 'ssti', 'auth_bypass')
      - custom_payloads: Optional list of custom string payloads to inject
      - concurrency: Concurrent worker threads (default: 5)
      - delay_ms: Milliseconds delay between requests to avoid WAF / bot protection bans (default: 50.0)
      - jitter_ms: Randomized millisecond jitter added to delay (default: 25.0)
      - project: Project workspace name
      - agent_id: Identifier of calling AI agent
    """
    target_project = _resolve_project(project, allow_all=False)

    # Scope check on baseline URL
    db = SessionLocal()
    proj_proxy = ""
    try:
        clean_url = MARKER_REGEX.sub(r"\1", url)
        is_allowed, block_reason = await async_check_scope(target_project, clean_url, db)
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    if not is_allowed:
        return f"[!] BLOCKED BY PROXSYNTH SCOPE GUARD: Target '{url}' is outside authorized scope ({block_reason})."

    # Select payloads
    active_payloads = custom_payloads or BUILTIN_PAYLOADS.get(payload_type.lower().strip(), BUILTIN_PAYLOADS["sqli"])

    upstream_proxy = proj_proxy.strip() if proj_proxy else (os.getenv("PROXSYNTH_UPSTREAM_PROXY") or "").strip()
    result = await run_fuzz_attack(
        base_url=url,
        method=method,
        headers=headers or {},
        body=body or "",
        payloads=active_payloads,
        concurrency=concurrency,
        delay_ms=delay_ms,
        jitter_ms=jitter_ms,
        upstream_proxy=upstream_proxy or None,
        project=target_project,
        agent_id=agent_id
    )
    return json.dumps(result, indent=2)


# ==============================================================================
# MCP Tool 24: execute_workflow_sequence (Multi-Step Stateful Workflow Engine)
# ==============================================================================

@proxsynth_tool(name="test_race_condition")
async def test_race_condition(
    url: str,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = "",
    concurrency: int = 20,
    project: Optional[str] = None,
    agent_id: str = "primary_agent"
) -> str:
    """
    Executes microsecond-synchronized concurrent bursts against web endpoints
    using an asyncio.Barrier connection-prewarming pipeline to identify race conditions,
    double-spending, coupon reuse, and state-breakage flaws.

    Parameters:
      - url: Target endpoint URL.
      - method: HTTP method (default: 'POST').
      - headers: Optional request headers.
      - body: Optional request payload.
      - concurrency: Number of synchronized requests in burst (default: 20, max: 50).
      - project: Project workspace name.
      - agent_id: Identifier of the calling AI agent.
    """
    from backend.race_engine import run_race_attack

    target_project = _resolve_project(project, allow_all=False)

    db = SessionLocal()
    proj_proxy = ""
    try:
        is_allowed, block_reason = await async_check_scope(target_project, url, db)
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    if not is_allowed:
        return f"[!] BLOCKED BY PROXSYNTH SCOPE GUARD: Target '{url}' is outside authorized scope ({block_reason})."

    upstream_proxy = proj_proxy.strip() if proj_proxy else (os.getenv("PROXSYNTH_UPSTREAM_PROXY") or "").strip()

    result = await run_race_attack(
        url=url,
        method=method,
        headers=headers or {},
        body=body or "",
        concurrency=concurrency,
        upstream_proxy=upstream_proxy or None,
        project=target_project,
        agent_id=agent_id
    )
    return json.dumps(result, indent=2)


# ==============================================================================
# MCP Tool 26: mine_javascript_assets (Passive & Active JS Recon & Secret Miner)
# ==============================================================================

@proxsynth_tool(name="audit_differential_injection")
async def audit_differential_injection(
    url: str,
    param_name: str,
    method: str = "GET",
    param_type: str = "query",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    project: Optional[str] = None,
    log_id: Optional[int] = None
) -> str:
    """
    Validates Blind SQL Injection, NoSQLi, and SSTI using 3-point boolean differential comparison
    and statistical Z-score timing verification, completely eliminating network jitter false positives.
    """
    from backend.differential_oracle import audit_differential_injection
    proj = _resolve_project(project, allow_all=False)
    res = await audit_differential_injection(
        url=url, param_name=param_name, method=method, param_type=param_type,
        base_headers=headers, base_body=body, project=proj, log_id=log_id
    )
    return json.dumps(res, indent=2)
