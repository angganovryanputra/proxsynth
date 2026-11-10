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
    On-demand Broken Access Control audit (BOLA / IDOR / BFLA) of a captured flow, by Log ID.
    Proxsynth classifies which access-control tests the flow warrants, replays it under every
    registered secondary identity (and unauthenticated), decides validity per vector with a
    confidence, enumerates adjacent numeric object ids, and returns a machine-actionable
    decision (VULNERABLE / LIKELY_SECURE / NOT_APPLICABLE / INCONCLUSIVE) plus a next_action
    the LLM can follow to verify and export a confirmed finding.
    """
    from backend.bola_matrix import audit_bac_flow
    target_project = _resolve_project(project, allow_all=False)
    res = await audit_bac_flow(log_id=log_id, project=target_project)
    return json.dumps(res, indent=2)


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
    project: Optional[str] = None,
    public_key_pem: Optional[str] = None,
    jwks_url: Optional[str] = None
) -> str:
    """
    Audits JSON Web Tokens (JWT) for critical session vulnerabilities:
    - Algorithm None bypasses ('none', 'None', 'NONE')
    - Algorithm confusion RS256 -> HS256 (server's public key reused as HMAC secret)
    - Weak secret dictionary brute-force cracking (HS256/HS384/HS512)
    - Privilege escalation / claim tampering (role: admin, is_admin: True)
    - Key ID (kid) manipulation and jku/x5u out-of-band remote key-fetch (SSRF)
    - Automated live replay against target endpoint with Soft-403 heuristic detection.

    Parameters:
      - token: Raw JWT string (with or without 'Bearer ' prefix).
      - test_url: Optional protected endpoint URL to verify exploitability in live replay mode.
      - method: HTTP method for test_url (default: 'GET').
      - headers: Optional baseline request headers.
      - claims_override: Optional key-value dictionary to inject into token payload.
      - project: Project workspace name.
      - public_key_pem: Optional server RSA public key (PEM). Enables the RS256->HS256
        algorithm-confusion variant, which forges an HS256 token using this key as the
        HMAC secret. Without it (and without jwks_url) that attack class is skipped.
      - jwks_url: Optional JWKS or PEM/certificate URL. When public_key_pem is not given,
        the key is fetched and derived from here (e.g. '.well-known/jwks.json').
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
        project=target_project,
        public_key_pem=public_key_pem,
        jwks_url=jwks_url
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


@proxsynth_tool(name="run_two_tier_access_control_orchestrator")
async def run_two_tier_access_control_orchestrator(
    target_base: Optional[str] = None,
    user_a_role: str = "user_a",
    user_b_role: str = "user_b",
    auto_exploit: bool = True,
    token_a: Optional[str] = None,
    token_b: Optional[str] = None,
    cookies_a: Optional[str] = None,
    cookies_b: Optional[str] = None,
    auth_headers_a: Optional[Dict[str, str]] = None,
    auth_headers_b: Optional[Dict[str, str]] = None,
    endpoints: Optional[List[Dict[str, Any]]] = None,
    project: Optional[str] = None,
    test_unauthenticated: bool = True,
    export_nuclei: Optional[bool] = None
) -> str:
    """
    [AUTONOMOUS: HIGH-LEVERAGE TWO-TIER ORCHESTRATOR]
    Executes the comprehensive Two-Tier Access Control & Business Logic Orchestrator:
    - Tier 1: Maps target endpoints, classifies sensitivity (BOLA, BFLA, Logic Flaws, Public).
    - Deterministic Core: Executes 3-Way Replay (Original Token A, Swapped Token B, Stripped No-Auth),
      computes semantic structural diff, detects soft-errors, and verifies state mutations.
    - Tier 2: Evaluates anomalies, eliminates false positives, persists confirmed findings to database,
      and automatically synthesizes reproducible ProjectDiscovery Nuclei YAML templates.
    """
    from backend.access_control_orchestrator import AccessControlOrchestrator
    from backend.database import SessionLocal, ActiveSession
    proj = _resolve_project(project, allow_all=False)
    target = target_base or "http://127.0.0.1:8000"
    should_export = auto_exploit if export_nuclei is None else export_nuclei

    sess_a = {
        "token": token_a,
        "raw_cookie_str": cookies_a,
        "auth_headers": auth_headers_a or {}
    }
    sess_b = {
        "token": token_b,
        "raw_cookie_str": cookies_b,
        "auth_headers": auth_headers_b or {}
    }

    # Auto-resolve from ActiveSession if direct credentials omitted
    if not token_a and not cookies_a:
        db = SessionLocal()
        try:
            rec_a = db.query(ActiveSession).filter(ActiveSession.project == proj, ActiveSession.role == user_a_role).first()
            if rec_a:
                sess_a["token"] = rec_a.session_token
                sess_a["raw_cookie_str"] = rec_a.cookies
                if rec_a.headers:
                    try:
                        sess_a["auth_headers"] = json.loads(rec_a.headers) if isinstance(rec_a.headers, str) else rec_a.headers
                    except Exception:
                        pass
            rec_b = db.query(ActiveSession).filter(ActiveSession.project == proj, ActiveSession.role == user_b_role).first()
            if rec_b:
                sess_b["token"] = rec_b.session_token
                sess_b["raw_cookie_str"] = rec_b.cookies
                if rec_b.headers:
                    try:
                        sess_b["auth_headers"] = json.loads(rec_b.headers) if isinstance(rec_b.headers, str) else rec_b.headers
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            db.close()

    orchestrator = AccessControlOrchestrator(project=proj)
    res = await orchestrator.execute_full_campaign(
        target_base=target,
        session_a=sess_a,
        session_b=sess_b,
        endpoints=endpoints,
        test_unauthenticated=test_unauthenticated,
        export_nuclei=should_export
    )
    return json.dumps(res, indent=2)
