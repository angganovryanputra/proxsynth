"""
Proxsynth MCP - Vault Tools
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


@proxsynth_tool(name="record_test_payload")
async def record_test_payload(
    target_url: str,
    vuln_type: str,
    raw_payload: str,
    target_param: str = "",
    mutation_type: str = "DIRECT",
    outcome: str = "TESTED",
    http_method: str = "GET",
    response_signature: str = "",
    http_status: Optional[int] = None,
    reasoning: str = "",
    project: Optional[str] = None,
    agent_id: str = "primary_agent"
) -> str:
    """
    Explicitly catalogs a specialized pentest payload (SQLi, XSS, SSRF, SSTI, RCE, IDOR, etc.)
    crafted or tested by the AI into the Proxynth Payload Vault for operator review, verification, and 1-click replay.
    Returns Payload ID for programmatic chaining.
    """
    target_project = _resolve_project(project, allow_all=False)
    target_agent = (agent_id or "primary_agent").strip()

    payload_data = {
        "project": target_project,
        "agent_id": target_agent,
        "vuln_type": vuln_type.upper(),
        "target_param": target_param or "",
        "raw_payload": raw_payload,
        "mutation_type": mutation_type or "DIRECT",
        "target_url": target_url,
        "http_method": (http_method or "GET").upper(),
        "outcome": outcome or "TESTED",
        "response_signature": response_signature or "",
        "http_status": http_status,
        "notes": reasoning or ""
    }
    payload_id = await _persist_and_stream_payload(payload_data)
    payload_id_str = f"#{payload_id}" if payload_id else "#untracked"

    return (
        f"Project: [{target_project}] | Payload ID: {payload_id_str} | Captured {http_method.upper()} payload '{raw_payload[:80]}' for {vuln_type} on param '{target_param}'. "
        f"Logged in Proxynth Payload Vault (Use Payload ID for chained replay/verification)."
    )


# ==============================================================================
# MCP Tool 5b: get_captured_payloads (Payload Vault Query & Search)
# ==============================================================================

@proxsynth_tool(name="get_captured_payloads")
async def get_captured_payloads(
    project: Optional[str] = None,
    vuln_type: Optional[str] = None,
    outcome: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> str:
    """
    Retrieves captured security testing payloads from the Proxynth Payload Vault.
    Supports filtering by project scope ('all' or specific project), vulnerability type (SQLI, XSS, SSRF, RCE, IDOR, etc.),
    outcome (CONFIRMED, ANOMALY, BLOCKED, TESTED), and full-text keyword search across raw payloads, target URLs, and parameters.
    Returns structured JSON with payload records and count statistics.
    """
    target_proj = _resolve_project(project, allow_all=True)
    payload_results = None

    # 1. Query running Dashboard API first
    try:
        client = await _get_dashboard_client()
        params = {
            "project": target_proj,
            "limit": min(max(1, limit), 500),
            "offset": max(0, offset)
        }
        if vuln_type and vuln_type.upper() != "ALL":
            params["vuln_type"] = vuln_type.upper()
        if outcome and outcome.upper() != "ALL":
            params["outcome"] = outcome.upper()
        if search:
            params["search"] = search

        resp = await client.get(f"{get_backend_url()}/api/payloads", params=params)
        if resp.status_code == 200:
            payload_results = resp.json()
    except Exception:
        pass

    # 2. Local database fallback
    if payload_results is None:
        db = SessionLocal()
        try:
            q = db.query(CapturedPayload)
            if target_proj.upper() != "ALL":
                q = q.filter(CapturedPayload.project == target_proj.lower())
            if vuln_type and vuln_type.upper() != "ALL":
                q = q.filter(CapturedPayload.vuln_type == vuln_type.upper())
            if outcome and outcome.upper() != "ALL":
                q = q.filter(CapturedPayload.outcome == outcome.upper())
            if search:
                pattern = f"%{search}%"
                q = q.filter(
                    (CapturedPayload.raw_payload.ilike(pattern)) |
                    (CapturedPayload.target_param.ilike(pattern)) |
                    (CapturedPayload.target_url.ilike(pattern)) |
                    (CapturedPayload.notes.ilike(pattern))
                )
            total = q.count()
            items = q.order_by(CapturedPayload.id.desc()).offset(offset).limit(limit).all()
            payload_results = {
                "total": total,
                "limit": limit,
                "offset": offset,
                "payloads": [p.to_dict() for p in items]
            }
        finally:
            db.close()

    return json.dumps(payload_results, indent=2)


# ==============================================================================
# MCP Tool 6: get_log_detail (Full Request/Response Body Inspection & Distillation)
# ==============================================================================

@proxsynth_tool(name="mutate_payload")
async def mutate_payload(
    raw_payload: str,
    vuln_type: str = "SQLI",
    strategy: str = "ALL"
) -> str:
    """
    Generates evasive, obfuscated variations of an exploit payload (SQLi, XSS, Path Traversal)
    to bypass commercial Web Application Firewalls (Cloudflare, AWS WAF, Akamai, ModSecurity).
    Returns mutated payloads and recommended header spoofing sets.
    """
    from backend.waf_mutator import mutate_payload as engine_mutate
    res = engine_mutate(raw_payload=raw_payload, vuln_type=vuln_type, strategy=strategy)
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tool 18: analyze_waf_response (WAF Fingerprinting & Bypass Recommendations)
# ==============================================================================

@proxsynth_tool(name="analyze_waf_response")
async def analyze_waf_response(
    status_code: int,
    headers: Dict[str, Any],
    body: str = ""
) -> str:
    """
    Fingerprints active WAF vendor signatures from response status, headers, and body patterns.
    Returns detected vendors (Cloudflare, AWS WAF, Akamai, ModSecurity, Imperva) and targeted bypass tactics.
    """
    from backend.waf_mutator import analyze_waf_response as engine_analyze_waf
    res = engine_analyze_waf(status_code=status_code, headers=headers, body=body)
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tool 19: infer_hidden_endpoints (Semantic API Spec Reconstructor)
# ==============================================================================
