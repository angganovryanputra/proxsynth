"""
Proxsynth MCP - Authz Tools
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


@proxsynth_tool(name="test_bola_idor")
async def test_bola_idor(
    log_id: int,
    project: Optional[str] = None
) -> str:
    """
    Executes an on-demand BOLA/IDOR shadow test on a specific logged endpoint (by Log ID).
    Proxynth replays the request using registered secondary identities (attacker, unauthenticated)
    and checks if unauthorized access succeeds.
    """
    from backend.database import SessionLocal, HttpLog
    from backend.bola_matrix import execute_bola_shadow_replay
    target_project = _resolve_project(project, allow_all=False)
    db = SessionLocal()
    try:
        log = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if not log:
            return f"[!] Log #{log_id} not found."
        req_hdrs = json.loads(log.request_headers) if log.request_headers else {}
        finding = await execute_bola_shadow_replay(
            log_id=log.id,
            project=target_project,
            url=log.url,
            method=log.method,
            req_headers=req_hdrs,
            req_body=log.request_body,
            orig_status=log.status_code,
            orig_body=log.response_body
        )
        if finding:
            return json.dumps({
                "status": "VULNERABILITY_CONFIRMED",
                "message": "BOLA/IDOR vulnerability detected! Unauthorized identity successfully accessed object data.",
                "finding": finding
            }, indent=2)
        else:
            return json.dumps({
                "status": "CLEAN_OR_NO_DISCLOSURE",
                "message": f"Shadow replays against Log #{log_id} returned authorization errors or identical denial as expected."
            }, indent=2)
    finally:
        db.close()


# ==============================================================================
# MCP Tool 17: mutate_payload (Adaptive WAF Evasion Engine)
# ==============================================================================

@proxsynth_tool(name="get_bola_access_matrix")
async def get_bola_access_matrix(project: Optional[str] = None) -> str:
    """
    Retrieves the cross-identity BOLA/IDOR access control matrix for candidate object-level endpoints.
    Lists candidate endpoints, active identity roles, and current vulnerability/protection states.
    """
    from backend.bola_matrix import get_bola_matrix_data
    proj = _resolve_project(project, allow_all=True)
    matrix = get_bola_matrix_data(project=proj)
    return json.dumps(matrix, indent=2)

@proxsynth_tool(name="run_bola_matrix_scan")
async def run_bola_matrix_scan(project: Optional[str] = None) -> str:
    """
    Executes automated BOLA shadow replay scans across all observed candidate endpoints in the project.
    Tests each candidate endpoint against all secondary identities and unauthenticated roles.
    """
    from backend.bola_matrix import run_full_bola_matrix_scan
    proj = _resolve_project(project, allow_all=False)
    res = await run_full_bola_matrix_scan(project=proj)
    return json.dumps(res, indent=2)

@proxsynth_tool(name="audit_jwt_security")
async def audit_jwt_security(
    token: str,
    test_url: Optional[str] = None,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    claims_override: Optional[Dict[str, Any]] = None,
    project: Optional[str] = None
) -> str:
    """
    Audits JSON Web Tokens (JWT) for critical session vulnerabilities:
    - Algorithm None bypasses ('none', 'None', 'NONE')
    - Weak secret dictionary brute-force cracking (HS256/HS384/HS512)
    - Privilege escalation / claim tampering (role: admin, is_admin: True)
    - Key ID (kid) parameter manipulation
    - Automated live replay against target endpoint with Soft-403 heuristic detection.

    Parameters:
      - token: Raw JWT string (with or without 'Bearer ' prefix).
      - test_url: Optional protected endpoint URL to verify exploitability in live replay mode.
      - method: HTTP method for test_url (default: 'GET').
      - headers: Optional baseline request headers.
      - claims_override: Optional key-value dictionary to inject into token payload.
      - project: Project workspace name.
    """
    from backend.jwt_tester import audit_jwt_security as run_jwt_audit

    target_project = _resolve_project(project, allow_all=False)

    db = SessionLocal()
    proj_proxy = ""
    try:
        if test_url:
            is_allowed, block_reason = await async_check_scope(target_project, test_url, db)
            if not is_allowed:
                return f"[!] BLOCKED BY PROXSYNTH SCOPE GUARD: Target '{test_url}' is outside authorized scope ({block_reason})."
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    upstream_proxy = proj_proxy.strip() if proj_proxy else (os.getenv("PROXSYNTH_UPSTREAM_PROXY") or "").strip()

    result = await run_jwt_audit(
        token=token,
        test_url=test_url,
        method=method,
        headers=headers,
        claims_override=claims_override,
        upstream_proxy=upstream_proxy or None,
        project=target_project
    )
    return json.dumps(result, indent=2)


# ==============================================================================
# MCP Tool 29: delete_attack_surface_node
# ==============================================================================

@proxsynth_tool(name="audit_bfla_permissions")
async def audit_bfla_permissions(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, Any]] = None,
    body: Optional[str] = None,
    project: Optional[str] = None,
    log_id: Optional[int] = None
) -> str:
    """
    Audits an endpoint for Broken Function Level Authorization (BFLA) and HTTP Method Tampering.
    Tests method flipping (PUT, DELETE, PATCH against GET endpoints), verb tunneling headers (X-HTTP-Method-Override),
    and administrative privilege escalation across all secondary identities (attacker, unauthenticated).
    """
    from backend.bfla_engine import audit_bfla_endpoint
    proj = _resolve_project(project, allow_all=False)
    res = await audit_bfla_endpoint(url=url, method=method, req_headers=headers, req_body=body, project=proj, log_id=log_id)
    return json.dumps(res, indent=2)

@proxsynth_tool(name="audit_mass_assignment")
async def audit_mass_assignment(
    log_id: int,
    custom_attributes: Optional[Dict[str, Any]] = None,
    project: Optional[str] = None
) -> str:
    """
    Scans a captured mutation request (POST, PUT, PATCH) for Mass Assignment (Over-Posting) flaws.
    Injects elevated privilege attributes (e.g. role, is_admin, tier, balance, permissions)
    and verifies whether the server binds and persists the injected properties.
    """
    from backend.mass_assignment_engine import audit_mass_assignment
    proj = _resolve_project(project, allow_all=False)
    res = await audit_mass_assignment(log_id=log_id, custom_attributes=custom_attributes, project=proj)
    return json.dumps(res, indent=2)

@proxsynth_tool(name="audit_numeric_business_logic")
async def audit_numeric_business_logic(
    log_id: int,
    target_param: Optional[str] = None,
    project: Optional[str] = None
) -> str:
    """
    Audits numeric, currency, quantity, and limit parameters for Business Logic & Boundary Flaws.
    Tests negative values (-1, -9999), zero-cost bypasses, fractional underflow (0.0000001),
    and integer arithmetic overflow (2147483648).
    """
    from backend.logic_fuzzer import audit_numeric_business_logic
    proj = _resolve_project(project, allow_all=False)
    res = await audit_numeric_business_logic(log_id=log_id, target_param=target_param, project=proj)
    return json.dumps(res, indent=2)
