"""
Proxsynth MCP - Autonomous Tools
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


@proxsynth_tool(name="get_tool_harness_manifest")
async def get_tool_harness_manifest() -> str:
    """
    [HARNESS: READ_ONLY]
    Returns the complete security harness manifest for all Proxynth FastMCP tools,
    including read_only hints, destructive flags, and capability taxonomy.
    Essential for autonomous AI harnesses to auto-approve safe reconnaissance tools
    while prompting confirmation for intrusive mutations or destructive commands.
    """
    return json.dumps({
        "status": "success",
        "total_tools": len(TOOL_HARNESS_METADATA),
        "manifest": TOOL_HARNESS_METADATA
    }, indent=2)

@proxsynth_tool(name="get_campaign_status")
async def get_campaign_status(campaign_id: str) -> str:
    """
    [HARNESS: READ_ONLY]
    Retrieves real-time status, phase progress, target classification, execution metrics,
    circuit breaker status, and findings summary for an autonomous security campaign.
    Use this tool to poll the progress of campaigns spawned by run_autonomous_security_campaign.
    """
    from backend.campaign_orchestrator import get_campaign_status as engine_get_campaign_status
    res = engine_get_campaign_status(campaign_id=campaign_id)
    return json.dumps(res, indent=2)

@proxsynth_tool(name="list_campaigns")
async def list_campaigns(project: Optional[str] = None) -> str:
    """
    [HARNESS: READ_ONLY]
    Lists all registered autonomous security campaigns across the workspace or filtered by project.
    """
    from backend.campaign_orchestrator import list_campaigns as engine_list_campaigns
    proj = _resolve_project(project, allow_all=True)
    res = engine_list_campaigns(project=proj)
    return json.dumps({"status": "success", "campaigns": res}, indent=2)

@proxsynth_tool(name="run_autonomous_security_campaign")
async def run_autonomous_security_campaign(
    target_url: str,
    modes: Optional[List[str]] = None,
    project: Optional[str] = None,
    max_pages: int = 15,
    deep_verify: bool = True,
    ports_profile: str = "top_100",
    enable_spa: bool = True,
    wait_for_completion: bool = False,
    consecutive_5xx_threshold: int = 3
) -> str:
    """
    [HARNESS: DESTRUCTIVE / HIGH_IMPACT]
    Unified Autonomous Campaign Orchestrator ('God Tool').
    Executes a comprehensive, coordinated multi-track security audit:
    0. Universal Target Classification -> Supports Web URLs, APIs, IPs, CIDRs, or hostnames
    1. Track Infra & Network -> Built-in async port scanner & service exposure auditor (Redis, Elastic, Docker)
    2. Track Web & SPA -> Hybrid crawler with Playwright Chromium DOM engine for React/Vue/Angular
    3. Track API Security -> Route discovery, OpenAPI schema ingestion, & API Gateway 401/403 bypass
    4. Deep Vulnerability Engine -> OAST canary spray (SSRF/RCE), BFLA verb tampering, Mass Assignment, Numeric Logic
    5. Deterministic Verification Gate -> Verifies all findings with specialized oracles and eliminates false positives
    6. Intelligent 5xx Circuit Breaker -> Auto-pauses if >=3 consecutive 503/502 errors occur to prevent target crashes

    By default (wait_for_completion=False), returns a campaign_id immediately to prevent MCP 120s timeouts.
    Call get_campaign_status(campaign_id) to poll real-time phase progress and findings.
    """
    from backend.campaign_orchestrator import run_autonomous_security_campaign as engine_run_campaign
    proj = _resolve_project(project, allow_all=False)
    res = await engine_run_campaign(
        target_url=target_url,
        modes=modes,
        project=proj,
        max_pages=max_pages,
        deep_verify=deep_verify,
        ports_profile=ports_profile,
        enable_spa=enable_spa,
        wait_for_completion=wait_for_completion,
        consecutive_5xx_threshold=consecutive_5xx_threshold
    )
    return json.dumps(res, indent=2)

@proxsynth_tool(name="get_autonomous_attack_guidance")
async def get_autonomous_attack_guidance(
    project: Optional[str] = None,
    log_id: Optional[int] = None,
    target_url: Optional[str] = None
) -> str:
    """
    Cognitive Attack Advisor: Analyzes target HTTP traffic or active project attack surface,
    evaluating heuristic signals (object IDs, admin paths, mass assignment candidates,
    numeric parameters, reflection sinks, SSRF callbacks, JWT tokens) and directly
    recommends the next high-impact FastMCP security tools to invoke with exact arguments.
    """
    from backend.attack_advisor import get_project_attack_guidance, suggest_attack_actions
    proj = _resolve_project(project, allow_all=False)

    if log_id:
        db = SessionLocal()
        try:
            entry = db.query(HttpLog).filter(HttpLog.id == int(log_id)).first()
            if entry:
                hdrs = {}
                try:
                    hdrs = json.loads(entry.request_headers) if isinstance(entry.request_headers, str) else entry.request_headers
                except Exception:
                    pass
                actions = suggest_attack_actions(
                    url=entry.url,
                    method=entry.method,
                    headers=hdrs,
                    body=entry.request_body,
                    response_status=entry.status_code,
                    response_body=entry.response_body,
                    log_id=entry.id
                )
                return json.dumps({
                    "status": "success",
                    "log_id": log_id,
                    "target_url": entry.url,
                    "recommended_actions": actions
                }, indent=2)
        finally:
            db.close()

    if target_url:
        actions = suggest_attack_actions(url=target_url)
        return json.dumps({
            "status": "success",
            "target_url": target_url,
            "recommended_actions": actions
        }, indent=2)

    res = get_project_attack_guidance(project=proj, limit=15)
    return json.dumps(res, indent=2)
