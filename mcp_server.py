"""
Proxynth MCP - Autonomous Security Testing Gateway & Interception Platform
Version: 0.1.0-beta (Initial Beta Release)
Model Context Protocol (MCP) Server Entrypoint (Stdio & SSE Transport)
Features: Scope Guardrails, Interactive Intercept Proxy Trap, AI Reasoning Correlation, & Multi-Project Isolation.
"""

__version__ = "0.1.0-beta"

import os
import sys
import re
import json
import time
import asyncio
import urllib.parse
import warnings
from typing import Optional, Dict, Any, List, Union, Tuple
import httpx

warnings.filterwarnings("ignore", message=r".*eof_received.*")

try:
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        from mcp.server import Server as FastMCP

# Ensure current directory is on pythonpath
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import difflib
from backend.database import init_db, SessionLocal, ActiveSession, HttpLog, Finding, Project, AgentCommandLog, CapturedPayload, TargetAsset, TargetService, TargetEndpoint, OastEvent
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

# Initialize FastMCP Server
mcp = FastMCP("proxsynth")

def get_backend_url() -> str:
    return os.getenv("PROXSYNTH_BACKEND_URL", os.getenv("PROXSYNTH_BACKEND_URL", "http://127.0.0.1:8000")).rstrip("/")

BACKEND_URL = get_backend_url()
DEFAULT_PROJECT = os.getenv("PROXSYNTH_PROJECT", os.getenv("PROXSYNTH_PROJECT", "default")).strip().lower()

# Session State Scope Management
_active_project: Optional[str] = None

def _resolve_project(project: Optional[str] = None, allow_all: bool = True) -> str:
    """
    Resolusi hierarki project:
    1. Explicit 'all', '*', 'any', 'global' -> return 'all' (if allow_all else _active_project or DEFAULT_PROJECT)
    2. Explicit project string -> return sanitized string
    3. None / empty -> 
       - If _active_project is set: return _active_project (if allow_all or _active_project != 'all' else DEFAULT_PROJECT)
       - If _active_project is None: if allow_all return 'all' else DEFAULT_PROJECT
    """
    p = (project or "").strip().lower()
    if p in ("all", "*", "any", "global"):
        if allow_all:
            return "all"
        return _active_project if (_active_project and _active_project not in ("all", "*", "any", "global")) else DEFAULT_PROJECT
    if p:
        return p
    if _active_project:
        if not allow_all and _active_project in ("all", "*", "any", "global"):
            return DEFAULT_PROJECT
        return _active_project
    return "all" if allow_all else DEFAULT_PROJECT

# Ensure DB is created
init_db()


# Persistent connection pools for high-throughput concurrency
_dashboard_client: Optional[httpx.AsyncClient] = None
_client_loop = None
_outbound_clients: Dict[str, httpx.AsyncClient] = {}
_outbound_loop = None

async def _get_dashboard_client() -> httpx.AsyncClient:
    global _dashboard_client, _client_loop
    current_loop = asyncio.get_running_loop()
    if _dashboard_client is None or _dashboard_client.is_closed or _client_loop != current_loop:
        if _dashboard_client and not _dashboard_client.is_closed:
            try:
                await _dashboard_client.aclose()
            except Exception:
                pass
        hdrs = {}
        api_key = os.getenv("PROXSYNTH_API_KEY", os.getenv("PROXSYNTH_API_KEY", "")).strip()
        if api_key:
            hdrs["X-Proxynth-Key"] = api_key
            hdrs["X-Proxynth-Key"] = api_key
        _dashboard_client = httpx.AsyncClient(
            headers=hdrs,
            timeout=2.0,
            proxy=None,
            trust_env=False,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50, keepalive_expiry=30.0)
        )
        _client_loop = current_loop
    return _dashboard_client

async def _get_outbound_client(proxy_cfg: str = "") -> httpx.AsyncClient:
    global _outbound_clients, _outbound_loop
    current_loop = asyncio.get_running_loop()
    if _outbound_loop != current_loop:
        _outbound_clients.clear()
        _outbound_loop = current_loop
    key = proxy_cfg.strip() if proxy_cfg else "direct"
    verify_ssl = os.getenv("PROXSYNTH_VERIFY_SSL", os.getenv("PROXSYNTH_VERIFY_SSL", "false")).lower() == "true"
    if key not in _outbound_clients or _outbound_clients[key].is_closed:
        kwargs = {
            "verify": verify_ssl,
            "follow_redirects": True,
            "timeout": 30.0,
            "limits": httpx.Limits(max_keepalive_connections=30, max_connections=100, keepalive_expiry=60.0)
        }
        if proxy_cfg and proxy_cfg.strip():
            kwargs["proxy"] = proxy_cfg.strip()
        else:
            kwargs["proxy"] = None
            kwargs["trust_env"] = False
        _outbound_clients[key] = httpx.AsyncClient(**kwargs)
    return _outbound_clients[key]


async def _persist_and_stream_log(
    log_payload: Dict[str, Any],
    flag_status: Optional[str] = None,
    findings: Optional[list] = None
) -> Dict[str, Any]:
    """
    Dispatches log to running FastAPI dashboard via HTTP POST so it broadcasts over WebSockets.
    When the dashboard is online, its centralized triage performs single-pass analysis and returns
    findings and flag_status. Falls back to direct SQLite database write if dashboard is offline.
    Returns dict containing {"id": int, "flag_status": str, "findings": list}.
    """
    try:
        client = await _get_dashboard_client()
        resp = await client.post(f"{get_backend_url()}/api/logs", json=log_payload)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                return {
                    "id": data.get("id"),
                    "flag_status": data.get("flag_status", flag_status or "CLEAN"),
                    "findings": data.get("findings", findings or [])
                }
    except Exception:
        pass

    db = SessionLocal()
    try:
        proj = (log_payload.get("project") or DEFAULT_PROJECT).strip().lower()
        if not db.query(Project).filter(Project.name == proj).first():
            db.add(Project(name=proj, description="Auto-created workspace"))
            db.commit()

        entry = HttpLog(
            project=proj,
            agent_id=log_payload.get("agent_id", "primary_agent") or "primary_agent",
            source=log_payload.get("source", "HTTP_CLIENT"),
            method=log_payload.get("method", "GET"),
            url=log_payload.get("url", ""),
            host=log_payload.get("host", ""),
            path=log_payload.get("path", "/"),
            status_code=log_payload.get("status_code"),
            duration_ms=log_payload.get("duration_ms", 0),
            request_headers=json.dumps(log_payload.get("request_headers", {})),
            request_body=(log_payload.get("request_body") or "")[:5242880],
            response_headers=json.dumps(log_payload.get("response_headers", {})),
            response_body=(log_payload.get("response_body") or "")[:5242880],
            reasoning=log_payload.get("reasoning", "") or "",
            flag_status="CLEAN"
        )
        effective_flag = flag_status
        effective_findings = findings if findings is not None else []
        if effective_flag is None:
            effective_flag, effective_findings = analyze_traffic(entry)

        # Check for agent-supplied finding in payload
        agent_title = (log_payload.get("finding_title") or "").strip()
        agent_flag = (log_payload.get("flag_status") or "").strip().upper()
        if agent_title:
            agent_sev = (log_payload.get("finding_severity") or "HIGH").strip().upper()
            agent_cat = (log_payload.get("finding_category") or "Agent Reported").strip()
            agent_ev = log_payload.get("finding_evidence") or log_payload.get("reasoning") or ""
            agent_desc = log_payload.get("finding_description") or f"Finding explicitly recorded by agent ({log_payload.get('agent_id', 'primary_agent')})."
            agent_rem = log_payload.get("finding_remediation") or "Apply input validation, parameterized queries, and least privilege controls."
            effective_findings.insert(0, {
                "title": agent_title,
                "severity": agent_sev,
                "category": agent_cat,
                "evidence": agent_ev,
                "description": agent_desc,
                "remediation": agent_rem
            })
            if agent_flag:
                effective_flag = agent_flag
            else:
                effective_flag = "CONFIRMED" if agent_sev in ["HIGH", "CRITICAL"] else "POTENTIAL"
        elif agent_flag:
            effective_flag = agent_flag

        # Deduplicate effective findings by normalized title
        deduped = []
        seen = set()
        for f in effective_findings:
            t = f["title"].strip().lower()
            if t not in seen:
                seen.add(t)
                deduped.append(f)
        effective_findings = deduped

        # Prevent dummy loopback traffic/tools from polluting findings in named target projects (e.g. lottechem)
        clean_host = (entry.host or "").lower().split(":")[0]
        is_loopback_host = clean_host in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
        if is_loopback_host and proj not in ["default", "local", "lab", "test", "dev"]:
            proj_obj = db.query(Project).filter(Project.name == proj).first()
            proj_scope = proj_obj.to_dict().get("allowed_hosts", ["*"]) if proj_obj else ["*"]
            if proj_scope != ["*"] and not any(h in ["localhost", "127.0.0.1", "0.0.0.0"] for h in proj_scope):
                effective_findings = []
                effective_flag = "CLEAN"

        entry.flag_status = effective_flag

        db.add(entry)
        db.commit()
        db.refresh(entry)
        for f in effective_findings:
            finding = Finding(
                log_id=entry.id,
                title=f["title"],
                severity=f["severity"],
                category=f["category"],
                evidence=f.get("evidence", ""),
                description=f.get("description", ""),
                remediation=f.get("remediation", "")
            )
            db.add(finding)
        db.commit()

        # Auto-Vault: Automatically capture confirmed or high/critical anomaly payload to Payload Vault
        try:
            from backend.payload_vault import auto_vault_payload
            auto_vault_payload(
                db=db,
                project=proj,
                agent_id=entry.agent_id,
                method=entry.method,
                url=entry.url,
                request_body=entry.request_body,
                response_body=entry.response_body,
                status_code=entry.status_code,
                flag_status=effective_flag,
                findings=effective_findings,
                reasoning=entry.reasoning,
                source=entry.source,
                http_log_id=entry.id,
                payload_hint=log_payload.get("payload_hint")
            )
        except Exception:
            pass

        try:
            from backend.target_manager import auto_ingest_url_to_target_graph
            auto_ingest_url_to_target_graph(proj, entry.url, entry.method)
        except Exception:
            pass

        try:
            from backend.js_miner import passive_mine_js_background
            passive_mine_js_background(entry.url, entry.response_body, proj)
        except Exception:
            pass

        return {"id": entry.id, "flag_status": effective_flag, "findings": effective_findings}
    except Exception:
        db.rollback()
        return {"id": None, "flag_status": "CLEAN", "findings": []}
    finally:
        db.close()


async def _persist_and_stream_command(cmd_payload: Dict[str, Any]) -> Optional[int]:
    """Dispatches command log to dashboard or writes directly to SQLite. Returns command_id."""
    try:
        client = await _get_dashboard_client()
        resp = await client.post(f"{get_backend_url()}/api/commands", json=cmd_payload)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and "id" in data:
                return data["id"]
    except Exception:
        pass

    db = SessionLocal()
    try:
        proj = (cmd_payload.get("project") or DEFAULT_PROJECT).strip().lower()
        entry = AgentCommandLog(
            project=proj,
            agent_id=cmd_payload.get("agent_id", "primary_agent") or "primary_agent",
            command=cmd_payload.get("command", ""),
            tool_name=cmd_payload.get("tool_name", "terminal"),
            reasoning=cmd_payload.get("reasoning", ""),
            exit_code=cmd_payload.get("exit_code"),
            stdout=cmd_payload.get("stdout", "")[:5242880],
            stderr=cmd_payload.get("stderr", "")[:5242880],
            duration_ms=cmd_payload.get("duration_ms", 0),
            status=cmd_payload.get("status", "SUCCESS"),
            linked_log_id=cmd_payload.get("linked_log_id"),
            script_content=(cmd_payload.get("script_content") or "")[:5242880]
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)

        # Auto-vault any exploit/pentest payloads extracted from script content or command
        if cmd_payload.get("script_content") or cmd_payload.get("command"):
            try:
                from backend.payload_vault import auto_vault_script_payloads
                auto_vault_script_payloads(
                    db=db,
                    project=proj,
                    agent_id=entry.agent_id,
                    script_content=cmd_payload.get("script_content", ""),
                    command=entry.command,
                    cmd_log_id=entry.id
                )
            except Exception:
                pass

        return entry.id
    except Exception:
        db.rollback()
        return None
    finally:
        db.close()


async def _persist_and_stream_payload(payload_data: Dict[str, Any]) -> Optional[int]:
    """Dispatches captured payload to dashboard or writes directly to SQLite. Returns payload_id."""
    try:
        client = await _get_dashboard_client()
        resp = await client.post(f"{get_backend_url()}/api/payloads", json=payload_data)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and "id" in data:
                return data["id"]
    except Exception:
        pass

    db = SessionLocal()
    try:
        proj = (payload_data.get("project") or DEFAULT_PROJECT).strip().lower()
        entry = CapturedPayload(
            project=proj,
            agent_id=payload_data.get("agent_id", "primary_agent") or "primary_agent",
            vuln_type=(payload_data.get("vuln_type", "CUSTOM") or "CUSTOM").upper(),
            target_param=payload_data.get("target_param", ""),
            raw_payload=payload_data.get("raw_payload", ""),
            mutation_type=payload_data.get("mutation_type", "DIRECT"),
            target_url=payload_data.get("target_url", ""),
            http_method=(payload_data.get("http_method", "GET") or "GET").upper(),
            http_log_id=payload_data.get("http_log_id"),
            outcome=payload_data.get("outcome", "TESTED"),
            http_status=payload_data.get("http_status"),
            response_signature=payload_data.get("response_signature", ""),
            notes=payload_data.get("notes", "")
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry.id
    except Exception:
        db.rollback()
        return None
    finally:
        db.close()


def _extract_domain_cookies(url: str, project: Optional[str] = None) -> Dict[str, str]:
    """Retrieves active session cookies for the target domain and project from SQLite."""
    target_project = _resolve_project(project, allow_all=False)
    cookies = {}
    try:
        parsed = urllib.parse.urlparse(url)
        target_host = (parsed.netloc or "").split(":")[0].strip().lower()
        db = SessionLocal()
        try:
            # First match sessions for this project
            sessions = db.query(ActiveSession).filter(ActiveSession.project == target_project).all()
            if not sessions:
                sessions = db.query(ActiveSession).all()

            for s in sessions:
                stored_dom = (s.domain or "").strip().lower()
                if "://" in stored_dom:
                    stored_dom = urllib.parse.urlparse(stored_dom).netloc
                stored_dom = stored_dom.split(":")[0].strip("/")

                # Robust Bidirectional domain match (exact, subdomain, or root domain)
                is_match = (
                    target_host == stored_dom or
                    target_host.endswith("." + stored_dom) or
                    stored_dom.endswith("." + target_host) or
                    (stored_dom in target_host and len(stored_dom) > 3)
                )

                if is_match:
                    try:
                        state_data = s.get_decrypted_state()
                        for c in state_data.get("cookies", []):
                            c_name = c.get("name")
                            c_val = c.get("value")
                            if c_name and c_val:
                                cookies[c_name] = c_val
                    except Exception:
                        pass
        finally:
            db.close()
    except Exception:
        pass
    return cookies


# ==============================================================================
# MCP Scope Session Tools: set_active_project & get_active_project
# ==============================================================================

@mcp.tool()
async def set_active_project(project: str) -> str:
    """
    Sets the active project workspace scope for the current MCP session.
    When set, all subsequent tool calls without an explicit project parameter
    will default to this project instead of 'default'.
    Passing 'all', '*', 'any', or 'global' enables global visibility stream across all projects.
    """
    global _active_project
    p = (project or "").strip().lower()
    if p in ("all", "*", "any", "global"):
        _active_project = "all"
        return json.dumps({
            "status": "success",
            "active_project": "all",
            "scope_mode": "GLOBAL_ALL_PROJECTS",
            "message": "Global multi-project stream enabled for reading/querying. Mutation operations will safeguard to default workspace."
        }, indent=2)
    _active_project = p if p else DEFAULT_PROJECT
    return json.dumps({
        "status": "success",
        "active_project": _active_project,
        "scope_mode": "PROJECT_ISOLATED",
        "message": f"Active project context set to '{_active_project}' for this session."
    }, indent=2)


@mcp.tool()
async def get_active_project() -> str:
    """
    Returns the currently active project workspace scope and the system default project.
    """
    return json.dumps({
        "active_project": _active_project or DEFAULT_PROJECT,
        "session_active_project": _active_project,
        "default_project": DEFAULT_PROJECT,
        "is_global_stream": (_active_project or "").lower() in ("all", "*", "any", "global")
    }, indent=2)


# ==============================================================================
# MCP Tool 1: send_http_request
# ==============================================================================

@mcp.tool()
async def send_http_request(
    method: str = "GET",
    url: str = "",
    headers: Optional[Dict[str, str]] = None,
    body: str = "",
    project: Optional[str] = None,
    agent_id: str = "primary_agent",
    reasoning: str = "",
    max_body_chars: int = 5000,
    flag_status: str = "",
    finding_title: str = "",
    finding_severity: str = "",
    finding_category: str = "",
    finding_evidence: str = "",
    finding_description: str = "",
    finding_remediation: str = "",
    output_format: str = "json",
    diff_baseline_id: Optional[int] = None,
    distill_response: bool = False
) -> str:
    """
    Executes an HTTP/HTTPS request, routes it through the Proxynth security proxy,
    logs traffic, performs real-time vulnerability triage, AND AUTOMATICALLY INJECTS
    active session cookies configured in Proxynth for the target domain.
    Returns Log ID for chaining and body preview. Use get_log_detail(log_id) for full uncompressed body.
    
    NOTE FOR AI AGENTS (Opencode / Hermes):
    - You DO NOT need to ask the user for session cookies or authenticate manually; Proxynth auto-injects them!
    - DIRECT VULNERABILITY FLAGGING: If this request tests or confirms a known vulnerability, you can directly set
      'finding_title' (e.g. 'SQL Injection — Authentication Bypass'), 'finding_severity' ('CRITICAL', 'HIGH', etc.),
      and 'flag_status' ('CONFIRMED'). Proxynth will immediately catalog the finding in the dashboard.
    - If you don't supply finding parameters, Proxynth's automated security analyzer evaluates the response automatically.
    - You can also call 'report_vulnerability(log_id, title, ...)' at any time after inspecting a response with get_log_detail.
    
    Parameters:
      - method: HTTP Method (GET, POST, PUT, DELETE, etc.)
      - url: Full target URL
      - headers: Optional custom HTTP headers dict
      - body: Request body string (or JSON payload)
      - project: Workspace scope (defaults to session active project or global stream)
      - agent_id: Identifier of the AI agent instance (e.g. 'primary_agent')
      - reasoning: The AI agent's hypothesis or intent (e.g. 'Testing SQL injection login bypass on /rest/user/login')
      - max_body_chars: Preview length (default 5000)
      - flag_status: Optional explicit triage flag ('CONFIRMED', 'POTENTIAL', or 'CLEAN')
      - finding_title: Optional title if this request confirmed a vulnerability (e.g. 'SQL Injection — Authentication Bypass')
      - finding_severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO'
      - finding_category: e.g. 'SQL Injection', 'Authentication Bypass', 'Information Disclosure', etc.
      - finding_evidence: Key proof string (e.g. issued JWT token or admin profile snippet)
    """
    # Defensive normalization for body in case a client or framework passed dict/list or None
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    elif body is None:
        body = ""
    elif not isinstance(body, str):
        body = str(body)

    target_project = _resolve_project(project, allow_all=False)
    target_agent = (agent_id or "primary_agent").strip()
    method = (method or "GET").upper().strip()
    headers = headers or {}
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    # --------------------------------------------------------------------------
    # 1. SCOPE & GUARDRAIL CHECK, THROTTLING, & PROXY LOOKUP
    # --------------------------------------------------------------------------
    db = SessionLocal()
    proj_delay_ms = 0
    proj_proxy = ""
    try:
        is_allowed, block_reason = await async_check_scope(target_project, url, db)
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_delay_ms = proj_obj.delay_ms or 0
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    if not is_allowed:
        # Log blocked attempt for auditing
        blocked_payload = {
            "project": target_project,
            "agent_id": target_agent,
            "source": "HTTP_CLIENT",
            "method": method,
            "url": url,
            "host": host,
            "path": path,
            "status_code": 403,
            "duration_ms": 0,
            "request_headers": headers,
            "request_body": body or "",
            "response_headers": {},
            "response_body": f"<BLOCKED BY PROXSYNTH SCOPE GUARD: {block_reason}>",
            "reasoning": reasoning or ""
        }
        await _persist_and_stream_log(blocked_payload, "BLOCKED", [])
        if (output_format or "").strip().lower() == "json":
            return json.dumps({
                "status": "blocked",
                "error": "SCOPE_GUARD_BLOCKED",
                "reason": block_reason,
                "url": url,
                "project": target_project,
                "message": f"Blocked by Proxynth Scope Guard: {block_reason}. Restrict testing to authorized domains."
            }, indent=2)
        return (
            f"[!] BLOCKED BY PROXSYNTH SCOPE GUARD:\n"
            f"The target '{url}' was blocked because: {block_reason}.\n"
            f"Please restrict testing exclusively to authorized domains defined in project '{target_project}'."
        )

    # Optional Rate Limiting / Delay
    if proj_delay_ms > 0:
        await asyncio.sleep(proj_delay_ms / 1000.0)

    # --------------------------------------------------------------------------
    # 2. INTERACTIVE INTERCEPT PROXY TRAP
    # --------------------------------------------------------------------------
    if is_intercept_enabled():
        req_trap_data = {
            "project": target_project,
            "agent_id": target_agent,
            "method": method,
            "url": url,
            "headers": headers,
            "body": body or "",
            "reasoning": reasoning or ""
        }
        intercept_id, trap_event = create_intercept_trap(req_trap_data)
        
        # Notify running dashboard via HTTP so it pops up in Intercept UI
        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                await client.post(f"{get_backend_url()}/api/logs", json={
                    "project": target_project,
                    "agent_id": target_agent,
                    "source": "HTTP_CLIENT",
                    "method": method,
                    "url": url,
                    "host": host,
                    "path": path,
                    "status_code": None,
                    "duration_ms": 0,
                    "request_headers": headers,
                    "request_body": body or "",
                    "response_headers": {},
                    "response_body": "<WAITING IN INTERCEPT TRAP>",
                    "reasoning": f"[INTERCEPT #{intercept_id}] {reasoning or ''}"
                })
        except Exception:
            pass

        # Wait for human pentester decision (or 180s timeout)
        try:
            await asyncio.wait_for(trap_event.wait(), timeout=180.0)
        except asyncio.TimeoutError:
            pop_intercept_result(intercept_id)
            if (output_format or "").strip().lower() == "json":
                return json.dumps({
                    "status": "intercept_timeout",
                    "intercept_id": intercept_id,
                    "message": "Request paused for 180s without human response. Execution resumed."
                }, indent=2)
            return "[!] INTERCEPT TIMEOUT: Request paused for 180s without human response. Execution resumed."

        result_item = pop_intercept_result(intercept_id)
        if result_item:
            if result_item.get("decision") == "drop":
                if (output_format or "").strip().lower() == "json":
                    return json.dumps({
                        "status": "dropped",
                        "intercept_id": intercept_id,
                        "message": "The request was dropped by the human operator in the Proxynth Intercept Console."
                    }, indent=2)
                return "[!] REQUEST DROPPED: The request was dropped by the human operator in the Proxynth Intercept Console."
            elif result_item.get("modified_data"):
                # Apply modifications made by human operator
                mod = result_item["modified_data"]
                method = mod.get("method", method).upper().strip()
                url = mod.get("url", url)
                headers = mod.get("headers", headers)
                body = mod.get("body", body)
                parsed = urllib.parse.urlparse(url)
                host = parsed.netloc
                path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

    # --------------------------------------------------------------------------
    # 3. OUTBOUND HEADER PREPARATION & SESSION COOKIE INJECTION
    # --------------------------------------------------------------------------
    outbound_headers = dict(headers)
    apply_rotating_user_agent(outbound_headers)
    if "Accept" not in outbound_headers and "accept" not in outbound_headers:
        outbound_headers["Accept"] = "*/*"
    if host and "Host" not in outbound_headers and "host" not in outbound_headers:
        outbound_headers["Host"] = host

    active_cookies = _extract_domain_cookies(url, project=target_project)
    if active_cookies:
        cookie_header = "; ".join([f"{k}={v}" for k, v in active_cookies.items()])
        if "Cookie" in outbound_headers:
            outbound_headers["Cookie"] += f"; {cookie_header}"
        elif "cookie" in outbound_headers:
            outbound_headers["cookie"] += f"; {cookie_header}"
        else:
            outbound_headers["Cookie"] = cookie_header

    # --------------------------------------------------------------------------
    # 4. REQUEST EXECUTION (With Upstream Proxy Chaining)
    # --------------------------------------------------------------------------
    start_time = time.time()
    status_code = None
    res_headers = {}
    res_body = ""
    error_note = None
    final_req_headers = outbound_headers

    proxy_cfg = proj_proxy.strip() if proj_proxy else (os.getenv("PROXSYNTH_UPSTREAM_PROXY") or "").strip()

    try:
        client = await _get_outbound_client(proxy_cfg)
        content_bytes = body.encode("utf-8") if body else None
        response = await client.request(
            method=method,
            url=url,
            headers=outbound_headers,
            content=content_bytes
        )
        status_code = response.status_code
        res_headers = dict(response.headers)

        # Autonomous Session Re-Authentication Check (Zero-Human Session Maintenance)
        if status_code in (401, 403):
            try:
                from backend.auth_macro import maybe_auto_reauth, get_active_credentials
                reauth_success = await maybe_auto_reauth(status_code, target_project)
                if reauth_success:
                    creds = get_active_credentials(target_project)
                    if creds and creds.get("headers"):
                        outbound_headers.update(creds["headers"])
                        response = await client.request(
                            method=method,
                            url=url,
                            headers=outbound_headers,
                            content=content_bytes
                        )
                        status_code = response.status_code
                        res_headers = dict(response.headers)
            except Exception:
                pass

        # Autonomous Adaptive Rate-Limit Backoff (Anti-429 & Anti-Ban)
        if status_code == 429:
            try:
                from backend.adaptive_limiter import handle_rate_limit
                await handle_rate_limit(status_code, res_headers, domain=host)
            except Exception:
                pass

        try:
            if hasattr(response, "request") and hasattr(response.request, "headers"):
                final_req_headers = dict(response.request.headers)
        except Exception:
            pass
        try:
            res_body = response.text
        except Exception:
            res_body = f"<Binary data: {len(response.content)} bytes>"
    except Exception as ex:
        error_note = f"Network/Transport Error: {str(ex)}"
        res_body = error_note

    duration_ms = int((time.time() - start_time) * 1000)

    log_payload = {
        "project": target_project,
        "agent_id": target_agent,
        "source": "HTTP_CLIENT",
        "method": method,
        "url": url,
        "host": host,
        "path": path,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "request_headers": final_req_headers,
        "request_body": body or "",
        "response_headers": res_headers,
        "response_body": res_body,
        "reasoning": reasoning or "",
        "flag_status": flag_status,
        "finding_title": finding_title,
        "finding_severity": finding_severity,
        "finding_category": finding_category,
        "finding_evidence": finding_evidence,
        "finding_description": finding_description,
        "finding_remediation": finding_remediation
    }

    # Single-pass triage: dashboard performs analyzer logic and returns findings + flag_status.
    persist_res = await _persist_and_stream_log(log_payload)
    logged_id = persist_res.get("id")
    flag_status = persist_res.get("flag_status", "CLEAN")
    findings_list = persist_res.get("findings", [])

    max_preview = max(100, min(max_body_chars or 5000, 50000))
    body_snippet = res_body[:max_preview] if res_body else "[Empty response body]"
    log_id_str = f"#{logged_id}" if logged_id else "#untracked"

    # Compute semantic differential against baseline response if diff_baseline_id requested
    diff_result = None
    diff_text = None
    diff_summary = ""
    if diff_baseline_id:
        try:
            from backend.diff_engine import compute_semantic_diff
            db_base = SessionLocal()
            base_entry = db_base.query(HttpLog).filter(HttpLog.id == int(diff_baseline_id)).first()
            if base_entry:
                base_hdrs = {}
                try:
                    base_hdrs = json.loads(base_entry.response_headers) if base_entry.response_headers else {}
                except Exception:
                    pass
                diff_result = compute_semantic_diff(
                    response_a={
                        "status_code": base_entry.status_code,
                        "body": base_entry.response_body or "",
                        "headers": base_hdrs
                    },
                    response_b={
                        "status_code": status_code or 0,
                        "body": res_body or "",
                        "headers": res_headers or {}
                    },
                    max_diff_lines=50
                )
                diff_text = diff_result.get("structural_diff", "")
                changes = []
                sc_change = diff_result.get("status_change", {})
                if sc_change.get("changed"):
                    changes.append(f"Status changed {sc_change.get('from')} -> {sc_change.get('to')}")
                delta = diff_result.get("normalized_length_delta", 0)
                changes.append(f"Norm Delta: {delta:+d}b")
                soft = diff_result.get("soft_errors_b", {})
                if soft.get("is_soft_403"):
                    changes.append("Soft-403 Detected")
                if soft.get("is_soft_404"):
                    changes.append("Soft-404 Detected")
                diff_summary = " | ".join(changes)
            db_base.close()
        except Exception:
            diff_result = None
            diff_text = None
            diff_summary = ""

    fmt_choice = (output_format or "json").strip().lower()

    distilled_data = None
    if distill_response or fmt_choice == "distilled":
        try:
            from backend.body_distiller import distill_response_body
            distilled_data = distill_response_body(
                res_body,
                content_type=res_headers.get("content-type", "text/html"),
                reflected_query=url.split("?")[1] if "?" in url else None
            )
            if fmt_choice == "distilled":
                return distilled_data.get("compact_summary", "")
        except Exception:
            distilled_data = None

    if fmt_choice == "json":
        res_dict = {
            "status": "success" if (status_code and status_code < 500) else "warning",
            "log_id": logged_id,
            "project": target_project,
            "agent_id": target_agent,
            "http_status": status_code,
            "latency_ms": duration_ms,
            "flag_status": flag_status,
            "findings": findings_list,
            "cookies_injected": len(active_cookies),
            "response_headers": res_headers,
            "response_body_preview": body_snippet,
            "body_total_chars": len(res_body),
            "diff_with_baseline": diff_result or diff_text
        }
        if distilled_data:
            res_dict["distilled_response"] = distilled_data

        try:
            from backend.attack_advisor import suggest_attack_actions
            advisor_suggestions = suggest_attack_actions(
                url=url,
                method=method,
                headers=res_headers,
                body=body,
                response_status=status_code,
                response_body=res_body,
                log_id=logged_id
            )
            if advisor_suggestions:
                res_dict["suggested_next_actions"] = advisor_suggestions
        except Exception:
            pass

        return json.dumps(res_dict, indent=2)

    if fmt_choice == "compact":
        return json.dumps({
            "log_id": logged_id,
            "status": status_code,
            "latency": duration_ms,
            "flag": flag_status,
            "findings": [f.get("title") for f in findings_list],
            "body_len": len(res_body),
            "diff": diff_text[:500] if diff_text else None,
            "diff_summary": diff_summary or None
        })

    triage_info = ""
    if flag_status == "CONFIRMED":
        triage_info = f"\n[!] ALERT: CONFIRMED FINDING DETECTED: {[f['title'] for f in findings_list]}"
    elif flag_status == "POTENTIAL":
        triage_info = f"\n[*] NOTICE: POTENTIAL ANOMALY DETECTED: {[f['title'] for f in findings_list]}"

    session_tag = f" | [Proxynth: Auto-injected {len(active_cookies)} cookies]" if active_cookies else ""
    diff_header = f"Semantic Diff against Baseline #{diff_baseline_id}" + (f" ({diff_summary})" if diff_summary else "")
    diff_section = f"\n\n--- {diff_header} ---\n{diff_text}" if diff_text else ""
    return (
        f"Project: [{target_project}] | Log ID: {log_id_str} | Agent: [{target_agent}] | HTTP/{status_code or 'ERR'} | Latency: {duration_ms}ms{session_tag} | Flag: {flag_status}{triage_info}\n"
        f"Headers: {json.dumps(res_headers)}\n\n"
        f"Body Preview (showing {min(len(body_snippet), len(res_body))} of {len(res_body)} chars. Call tool get_log_detail({logged_id or 0}) to read complete uncompressed body):\n{body_snippet}{diff_section}"
    )


# ==============================================================================
# MCP Tool 2: browser_navigate_and_render
# ==============================================================================

@mcp.tool()
async def browser_navigate_and_render(
    url: str,
    click_selector: str = "",
    fill_inputs: Optional[Dict[str, str]] = None,
    project: Optional[str] = None,
    agent_id: str = "primary_agent",
    reasoning: str = "",
    max_dom_chars: int = 10000
) -> str:
    """
    Renders a dynamic webpage headlessly via Playwright, executes automated actions,
    intercepts background asynchronous network requests (AJAX/fetch/scripts), and extracts visible DOM content.
    Returns Log ID, list of intercepted API endpoints/scripts, and DOM content preview.
    """
    target_project = _resolve_project(project, allow_all=False)
    target_agent = (agent_id or "primary_agent").strip()

    # Scope & Settings check
    db = SessionLocal()
    proj_delay_ms = 0
    proj_proxy = ""
    try:
        is_allowed, block_reason = await async_check_scope(target_project, url, db)
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_delay_ms = proj_obj.delay_ms or 0
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    if not is_allowed:
        return f"[!] BLOCKED BY PROXSYNTH SCOPE GUARD: {block_reason}"

    if proj_delay_ms > 0:
        await asyncio.sleep(proj_delay_ms / 1000.0)

    proxy_cfg = proj_proxy.strip() if proj_proxy else (os.getenv("PROXSYNTH_UPSTREAM_PROXY") or "").strip()

    try:
        result = await render_page(
            url=url,
            click_selector=click_selector,
            fill_inputs=fill_inputs,
            upstream_proxy=proxy_cfg if proxy_cfg else None
        )
        
        log_payload = {
            "project": target_project,
            "agent_id": target_agent,
            "source": "BROWSER_RENDER",
            "method": "GET",
            "url": url,
            "host": result.get("domain", ""),
            "path": urllib.parse.urlparse(url).path or "/",
            "status_code": 200,
            "duration_ms": 1500,
            "request_headers": {"User-Agent": get_random_user_agent()},
            "request_body": json.dumps({"click_selector": click_selector, "fill_inputs": fill_inputs}),
            "response_headers": {"Content-Type": "text/html"},
            "response_body": result.get("dom_text", "")[:50000],
            "reasoning": reasoning or ""
        }
        persist_res = await _persist_and_stream_log(log_payload, "CLEAN", [])
        logged_id = persist_res.get("id")

        # Log intercepted background AJAX/fetch sub-requests
        intercepted = result.get("intercepted_requests", [])
        intercepted_summary = []
        for sub_req in intercepted:
            if sub_req.get("resource_type") in ["xhr", "fetch", "script"]:
                sub_parsed = urllib.parse.urlparse(sub_req.get("url", ""))
                real_status = sub_req.get("status_code")
                real_duration = sub_req.get("duration_ms", 0)
                is_synthetic = real_status is None
                sub_payload = {
                    "project": target_project,
                    "agent_id": target_agent,
                    "source": "BROWSER_RENDER",
                    "method": sub_req.get("method", "GET"),
                    "url": sub_req.get("url", ""),
                    "host": sub_parsed.netloc,
                    "path": sub_parsed.path or "/",
                    "status_code": real_status if not is_synthetic else 200,
                    "duration_ms": real_duration if not is_synthetic else 50,
                    "request_headers": sub_req.get("headers", {}),
                    "request_body": "",
                    "response_headers": {},
                    "response_body": f"<Intercepted {sub_req.get('resource_type')} request>",
                    "reasoning": f"[SPA Sub-Request ({sub_req.get('resource_type')})]" if not is_synthetic else f"[Synthetic Asset Marker] Captured {sub_req.get('resource_type')} during headless render"
                }
                await _persist_and_stream_log(sub_payload, "CLEAN", [])

        # Extract top 30 endpoints for agent reconnaissance
        for sub in intercepted[:30]:
            intercepted_summary.append(f"  [{sub.get('method', 'GET')}] {sub.get('url')} ({sub.get('resource_type')})")
        intercepted_str = "\n".join(intercepted_summary) if intercepted_summary else "  [No sub-requests intercepted]"

        max_dom = max(500, min(max_dom_chars or 10000, 100000))
        full_dom = result.get("dom_text", "")
        dom_preview = full_dom[:max_dom]
        log_id_str = f"#{logged_id}" if logged_id else "#untracked"

        return (
            f"Project: [{target_project}] | Log ID: {log_id_str} | Agent: [{target_agent}] | Page: '{result.get('title')}'\n"
            f"Final URL: {result.get('url')}\n"
            f"Intercepted Endpoints ({len(intercepted)} captured):\n{intercepted_str}\n\n"
            f"DOM Text Preview (showing {min(len(dom_preview), len(full_dom))} of {len(full_dom)} chars. Use get_log_detail({logged_id or 0}) to read complete body):\n{dom_preview}"
        )
    except Exception as ex:
        return f"Browser render failure: {str(ex)}"


@mcp.tool()
async def render_webpage(
    url: str,
    click_selector: str = "",
    fill_inputs: Optional[Dict[str, str]] = None,
    project: Optional[str] = None,
    agent_id: str = "primary_agent",
    reasoning: str = "",
    max_dom_chars: int = 10000
) -> str:
    """
    Renders a dynamic webpage headlessly via Playwright, executes automated actions,
    intercepts background asynchronous network requests, and extracts visible DOM content.
    (Alias for browser_navigate_and_render).
    """
    return await browser_navigate_and_render(
        url=url,
        click_selector=click_selector,
        fill_inputs=fill_inputs,
        project=project,
        agent_id=agent_id,
        reasoning=reasoning,
        max_dom_chars=max_dom_chars
    )


# ==============================================================================
# MCP Tool 3: request_manual_login
# ==============================================================================

@mcp.tool()
async def request_manual_login(
    login_url: str,
    domain: str,
    project: Optional[str] = None
) -> str:
    """
    Spawns an interactive headed browser window for Human-in-the-Loop (HITL) authentication.
    Suspends autonomous execution until the human pentester logs in or completes CAPTCHA.
    Extracted cookies and storage tokens are automatically synced to the gateway database.
    """
    target_project = _resolve_project(project, allow_all=False)
    try:
        result = await spawn_interactive_login(login_url, domain, project=target_project)
        cookie_count = result.get("cookie_count", 0)
        return (
            f"Project: [{target_project}] | Authentication successful. Sockets/cookies updated and active for domain '{domain}'. "
            f"Captured {cookie_count} session cookies. Subsequent requests will auto-inject credentials."
        )
    except Exception as ex:
        return f"Interactive login failed: {str(ex)}"


# ==============================================================================
# MCP Tool 4: run_pentest_command
# ==============================================================================

DANGEROUS_COMMAND_PATTERNS = [
    r"rm\s+(-[rfRF]+\s+|--recursive\s+|--force\s+)*\/",
    r"rm\s+(-[rfRF]+\s+|--recursive\s+|--force\s+)*\*",
    r"mkfs",
    r"dd\s+if=",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r"format\s+[a-zA-Z]:",
    r"DROP\s+DATABASE",
    r"DROP\s+TABLE",
    r"shutdown(\.exe)?\s+",
    r"reboot(\.exe)?"
]

@mcp.tool()
async def run_pentest_command(
    command: str,
    reasoning: str = "",
    tool_name: str = "terminal",
    project: Optional[str] = None,
    agent_id: str = "primary_agent",
    timeout: int = 60,
    cwd: str = "",
    output_format: str = "json",
    script_content: Optional[str] = None
) -> str:
    """
    Executes a security testing command in the local shell environment (e.g. nmap, curl, sqlmap, custom scripts),
    streams the command and outputs to Proxynth for full operator observability and audit history,
    automatically captures script source code and extracted attack payloads into the Payload Vault,
    and applies automated safety guardrails to prevent destructive system commands and SSRF metadata exfiltration.
    """
    target_project = _resolve_project(project, allow_all=False)
    target_agent = (agent_id or "primary_agent").strip()
    cmd_clean = command.strip()

    # Query project settings for internal network scope allowance
    db = SessionLocal()
    allow_internal = True
    try:
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            allow_internal = bool(proj_obj.allow_internal_networks)
    finally:
        db.close()

    # Hardened Cross-Platform Safety Guardrail & SSRF Check (Async DNS resolution)
    is_safe_cmd, block_reason = await async_check_command_safe_mode(cmd_clean, allow_internal=allow_internal)
    if not is_safe_cmd:
        blocked_payload = {
            "project": target_project,
            "agent_id": target_agent,
            "command": cmd_clean,
            "tool_name": tool_name or "terminal",
            "reasoning": reasoning or "",
            "exit_code": -1,
            "stdout": "",
            "stderr": block_reason,
            "duration_ms": 0,
            "status": "BLOCKED"
        }
        cmd_id = await _persist_and_stream_command(blocked_payload)
        cmd_id_str = f"#{cmd_id}" if cmd_id else "#untracked"
        return (
            f"[!] BLOCKED BY PROXSYNTH CLI SAFE-MODE / SSRF GUARD (Command ID: {cmd_id_str}):\n"
            f"{block_reason}\n"
            f"Please restrict commands to authorized non-destructive reconnaissance and assessment utilities."
        )

    # Resolve execution working directory
    work_dir = CURRENT_DIR
    if cwd and os.path.isdir(cwd):
        work_dir = os.path.abspath(cwd)

    # Auto-detect executed script source code if not explicitly provided
    effective_script_content = (script_content or "").strip()
    if not effective_script_content:
        m_script = re.search(r'(?:python3?|bash|sh|node)\s+([^\s\'\"]+\.(?:py|sh|js|rb|pl|php))', cmd_clean, re.IGNORECASE)
        if m_script:
            candidate_file = m_script.group(1).strip()
            resolved_path = candidate_file if os.path.isabs(candidate_file) else os.path.join(work_dir, candidate_file)
            if os.path.isfile(resolved_path):
                try:
                    if os.path.getsize(resolved_path) <= 524288:  # 512KB safety cap
                        with open(resolved_path, "r", encoding="utf-8", errors="replace") as sf:
                            effective_script_content = sf.read()
                except Exception:
                    pass

    start_time = time.time()
    stdout_text = ""
    stderr_text = ""
    exit_code = 0
    status = "SUCCESS"

    proxy_port = int(os.getenv("PROXSYNTH_PROXY_PORT", os.getenv("PROXSYNTH_PROXY_PORT", "8088")))

    # 1. Guarantee that Proxynth Forward Proxy is actively running before command execution
    try:
        from backend.forward_proxy import ensure_forward_proxy_running
        await ensure_forward_proxy_running(port=proxy_port)
    except Exception:
        pass

    proxy_url_auth = f"http://{target_project}:{target_agent}@127.0.0.1:{proxy_port}"
    proxy_url_plain = f"http://127.0.0.1:{proxy_port}"

    sub_env = os.environ.copy()
    existing_pythonpath = sub_env.get("PYTHONPATH", "")
    sub_env["PYTHONPATH"] = f"{CURRENT_DIR}{os.pathsep}{existing_pythonpath}".rstrip(os.pathsep)
    sub_env["HTTP_PROXY"] = proxy_url_auth
    sub_env["HTTPS_PROXY"] = proxy_url_auth
    sub_env["http_proxy"] = proxy_url_auth
    sub_env["https_proxy"] = proxy_url_auth
    sub_env["ALL_PROXY"] = proxy_url_auth
    sub_env["all_proxy"] = proxy_url_auth
    sub_env["NO_PROXY"] = ""
    sub_env["no_proxy"] = ""
    sub_env["PROXSYNTH_PROJECT"] = target_project
    sub_env["PROXSYNTH_PROJECT"] = target_project
    sub_env["PROXSYNTH_AGENT_ID"] = target_agent
    sub_env["PROXSYNTH_AGENT_ID"] = target_agent
    sub_env["PROXSYNTH_PROXY_PORT"] = str(proxy_port)
    sub_env["PROXSYNTH_PROXY_PORT"] = str(proxy_port)
    try:
        from backend.forward_proxy import get_ca_cert_path
        ca_cert_path = get_ca_cert_path()
    except Exception:
        ca_cert_path = ""

    sub_env["PYTHONHTTPSVERIFY"] = "0"
    if ca_cert_path and os.path.exists(ca_cert_path):
        sub_env["REQUESTS_CA_BUNDLE"] = ca_cert_path
        sub_env["CURL_CA_BUNDLE"] = ca_cert_path
        sub_env["SSL_CERT_FILE"] = ca_cert_path
        sub_env["NODE_EXTRA_CA_CERTS"] = ca_cert_path
    else:
        sub_env["REQUESTS_CA_BUNDLE"] = ""
    sub_env["CURL_INSECURE"] = "1"
    sub_env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

    try:
        from backend.forward_proxy import ProxyContext
        proxy_ctx = ProxyContext(target_project, target_agent)
    except Exception:
        proxy_ctx = None

    # Auto-immunize curl commands against Windows Schannel SSL rejection
    cmd_exec = cmd_clean
    if "curl" in cmd_clean.lower() and "-k" not in cmd_clean and "--insecure" not in cmd_clean:
        if sys.platform == "win32":
            cmd_exec = re.sub(r"\bcurl(\.exe)?\b", r"curl.exe -k", cmd_clean, flags=re.IGNORECASE, count=1)
        else:
            cmd_exec = re.sub(r"\bcurl\b", r"curl -k", cmd_clean, count=1)

    try:
        if proxy_ctx:
            proxy_ctx.__enter__()
        proc = await asyncio.create_subprocess_shell(
            cmd_exec,
            cwd=work_dir,
            env=sub_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            out_bytes, err_bytes = await asyncio.wait_for(proc.communicate(), timeout=float(timeout or 60))
            stdout_text = out_bytes.decode("utf-8", errors="replace")
            stderr_text = err_bytes.decode("utf-8", errors="replace")
            exit_code = proc.returncode or 0
            if exit_code != 0:
                status = "FAILED"
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            exit_code = -1
            status = "TIMEOUT"
            stderr_text = f"Execution timed out after {timeout} seconds."
        finally:
            if proxy_ctx:
                proxy_ctx.__exit__(None, None, None)
    except Exception as ex:
        exit_code = 1
        status = "FAILED"
        stderr_text = f"Subprocess invocation failure: {str(ex)}"

    duration_ms = int((time.time() - start_time) * 1000)

    cmd_log_payload = {
        "project": target_project,
        "agent_id": target_agent,
        "command": cmd_clean,
        "tool_name": tool_name or "terminal",
        "reasoning": reasoning or "",
        "exit_code": exit_code,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "duration_ms": duration_ms,
        "status": status,
        "script_content": effective_script_content
    }
    cmd_id = await _persist_and_stream_command(cmd_log_payload)
    cmd_id_str = f"#{cmd_id}" if cmd_id else "#untracked"

    # Autonomous CLI Output Miner: Extract structured ports, services, endpoints, or findings
    mined_summary = None
    if stdout_text and len(stdout_text.strip()) > 10:
        try:
            from backend.cli_miner import mine_and_ingest_cli_output
            mined_res = mine_and_ingest_cli_output(
                command=cmd_clean,
                raw_output=stdout_text,
                project=target_project
            )
            if mined_res.get("services_ingested") or mined_res.get("endpoints_ingested") or mined_res.get("findings_recorded"):
                mined_summary = mined_res
        except Exception:
            pass

    stdout_snippet = stdout_text[:5000] if stdout_text else "[No standard output]"
    stderr_snippet = f"\nSTDERR:\n{stderr_text[:2000]}" if stderr_text else ""
    fmt_choice = (output_format or "json").strip().lower()
    if fmt_choice == "json":
        res_obj = {
            "command_id": cmd_id,
            "project": target_project,
            "agent_id": target_agent,
            "command": cmd_clean,
            "cwd": work_dir,
            "status": status,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout": stdout_snippet,
            "stderr": stderr_text[:2000] if stderr_text else "",
            "script_captured": bool(effective_script_content)
        }
        if mined_summary:
            res_obj["mined_knowledge"] = mined_summary
        return json.dumps(res_obj, indent=2)

    return (
        f"Project: [{target_project}] | Command ID: {cmd_id_str} | Agent: [{target_agent}] | Exit Code: {exit_code} | Duration: {duration_ms}ms | CWD: [{work_dir}] | Status: {status}\n"
        f"Command: {cmd_clean}\n\n"
        f"STDOUT:\n{stdout_snippet}{stderr_snippet}"
    )


# ==============================================================================
# MCP Tool 5: record_test_payload
# ==============================================================================

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
async def get_log_detail(
    log_id: int,
    max_body_chars: Optional[int] = 100000,
    distill: bool = False,
    reflected_query: Optional[str] = None
) -> str:
    """
    Retrieves complete headers, full request body, full response body, and triaged findings
    for a specific HTTP transaction by its Log ID.
    When `distill=True`, compresses large HTML/JSON response bodies using Proxynth's Semantic
    Security Distiller into a compact, high-density summary (saving up to 95% LLM tokens)
    while highlighting reflected parameters, hidden form fields, and potential endpoints.
    Queries the central Proxynth Dashboard API first (with local database fallback) to ensure
    consistent access in cross-environment (WSL/Windows) setups.
    Essential for bug bounty research to inspect reflected XSS, deep JSON responses, or sensitive leaks without truncation.
    """
    log_data = None
    source_info = "Dashboard API"

    # 1. Query running Dashboard API first (Primary in distributed/WSL setups)
    try:
        async with httpx.AsyncClient(timeout=2.5) as client:
            resp = await client.get(f"{get_backend_url()}/api/logs/{log_id}")
            if resp.status_code == 200:
                log_data = resp.json()
    except Exception:
        pass

    # 2. Fallback to local SQLite database if Dashboard API is unreachable or returned 404
    if not log_data:
        source_info = "Local Database Fallback"
        db = SessionLocal()
        try:
            entry = db.query(HttpLog).filter(HttpLog.id == log_id).first()
            if entry:
                log_data = entry.to_dict(include_body=True)
        finally:
            db.close()

    if not log_data:
        return f"[!] Log ID #{log_id} was not found in the Proxynth Dashboard ({get_backend_url()}) or local database."

    findings = log_data.get("findings", [])
    findings_str = ""
    if findings:
        findings_str = "\nFindings Detected on this Request:\n" + "\n".join([
            f"- [{f.get('severity', 'INFO')}] {f.get('title', 'Unknown')} ({f.get('category', 'General')})\n  Evidence: {f.get('evidence', '')}\n  Remediation: {f.get('remediation', '')}"
            for f in findings
        ])
    else:
        findings_str = "\nFindings: None (Clean)"

    max_len = max(500, min(max_body_chars or 100000, 1000000))

    # Accurate length calculation (avoids reporting length of placeholder string)
    raw_req_body = log_data.get("request_body") or ""
    req_body_len = len(raw_req_body)
    display_req_body = raw_req_body if raw_req_body else "[Empty Request Body]"

    raw_res_body = log_data.get("response_body") or ""
    res_body_len = len(raw_res_body)
    display_res_body = raw_res_body if raw_res_body else "[Empty Response Body]"

    req_body_prev = display_req_body[:max_len]
    res_body_prev = display_res_body[:max_len]
    distill_label = ""

    req_hdrs = log_data.get("request_headers", {})
    if isinstance(req_hdrs, (dict, list)):
        req_hdrs_str = json.dumps(req_hdrs, indent=2)
    else:
        req_hdrs_str = str(req_hdrs)

    res_hdrs = log_data.get("response_headers", {})
    if isinstance(res_hdrs, (dict, list)):
        res_hdrs_str = json.dumps(res_hdrs, indent=2)
    else:
        res_hdrs_str = str(res_hdrs)

    if distill and raw_res_body:
        try:
            from backend.body_distiller import distill_response_body
            ct = ""
            if isinstance(res_hdrs, dict):
                ct = res_hdrs.get("Content-Type") or res_hdrs.get("content-type") or ""
            dist_res = distill_response_body(
                body=raw_res_body,
                content_type=ct,
                max_length=max_len,
                reflected_query=reflected_query
            )
            dist_summary = dist_res.get("compact_summary", "")
            orig_sz = dist_res.get("original_size", len(raw_res_body))
            dist_sz = dist_res.get("distilled_size", len(dist_summary))
            reduction = dist_res.get("token_reduction_percent", 0.0)
            res_body_prev = f"[DISTILLED SECURITY VIEW: {orig_sz} -> {dist_sz} bytes (-{reduction}% tokens)]\n{dist_summary}"
            distill_label = " [Distilled]"
        except Exception as ex:
            res_body_prev = f"[Distillation fallback: {str(ex)}]\n{display_res_body[:max_len]}"

    return (
        f"=== PROXSYNTH HTTP LOG DETAIL #{log_data.get('id', log_id)} ({source_info}) ===\n"
        f"Project: [{log_data.get('project', 'default')}] | Agent: [{log_data.get('agent_id', 'primary_agent')}] | Source: {log_data.get('source', 'HTTP_CLIENT')}\n"
        f"Target: {log_data.get('method', 'GET')} {log_data.get('url', '')}\n"
        f"Status Code: {log_data.get('status_code', 'ERR')} | Latency: {log_data.get('duration_ms', 0)}ms | Flag: {log_data.get('flag_status', 'CLEAN')}\n"
        f"Timestamp: {log_data.get('timestamp', '')}\n"
        f"Hypothesis / Reasoning: {log_data.get('reasoning') or '[None]'}\n\n"
        f"--- Request Headers ---\n{req_hdrs_str}\n\n"
        f"--- Request Body ({req_body_len} bytes) ---\n{req_body_prev}\n\n"
        f"--- Response Headers ---\n{res_hdrs_str}\n\n"
        f"--- Response Body ({res_body_len} bytes{distill_label}) ---\n{res_body_prev}\n"
        f"{findings_str}"
    )


# ==============================================================================
# MCP Tool 7: get_traffic_history (Traffic Index & Search)
# ==============================================================================

@mcp.tool()
async def get_traffic_history(
    project: Optional[str] = None,
    limit: int = 20
) -> str:
    """
    Lists recent HTTP traffic entries recorded in Proxynth for the selected project.
    Queries the central Dashboard API first (with local database fallback) to guarantee
    consistent visibility across WSL/Windows environments.
    Returns Log IDs, HTTP methods, status codes, URLs, and triage flags so the agent can select IDs for deep inspection.
    """
    target_project = _resolve_project(project, allow_all=True)
    fetch_limit = min(max(limit or 20, 1), 100)
    logs_list = None
    source_info = "Dashboard API"

    # 1. Query running Dashboard API first
    try:
        async with httpx.AsyncClient(timeout=2.5) as client:
            resp = await client.get(f"{get_backend_url()}/api/logs?project={target_project}&limit={fetch_limit}&offset=0")
            if resp.status_code == 200:
                data = resp.json()
                logs_list = data.get("logs", [])
    except Exception:
        pass

    # 2. Fallback to local SQLite database
    if logs_list is None:
        source_info = "Local Database Fallback"
        db = SessionLocal()
        try:
            query = db.query(HttpLog)
            if target_project and target_project.upper() != "ALL":
                query = query.filter(HttpLog.project == target_project)
            db_logs = query.order_by(HttpLog.id.desc()).limit(fetch_limit).all()
            logs_list = [l.to_dict(include_body=False) for l in db_logs]
        finally:
            db.close()

    if not logs_list:
        return f"No traffic logs recorded for project [{target_project}] ({source_info})."

    lines = [f"=== RECENT TRAFFIC HISTORY (Project: {target_project} | {source_info}) ==="]
    for l in logs_list:
        lid = l.get("id", 0)
        method = l.get("method", "GET")
        status = str(l.get("status_code") or "ERR")
        duration = l.get("duration_ms", 0)
        flag = l.get("flag_status", "CLEAN")
        url = l.get("url", "")
        lines.append(f"#{lid:04d} | {method:<5} | {status:<4} | {duration:>4}ms | [{flag:<9}] | {url}")

    lines.append(f"\nTip: Call get_log_detail(log_id) to read complete headers, full body, or vulnerability findings.")
    return "\n".join(lines)


# ==============================================================================
# MCP Tool 8: report_vulnerability (Direct Agent Vulnerability Flagging)
# ==============================================================================

@mcp.tool()
async def report_vulnerability(
    log_id: int,
    title: str,
    severity: str = "HIGH",
    category: str = "General",
    evidence: str = "",
    description: str = "",
    remediation: str = "",
    project: Optional[str] = None
) -> str:
    """
    Explicitly flags an existing HTTP Log entry (by Log ID) as a confirmed vulnerability finding in Proxynth.
    Call this tool whenever you inspect a response (via get_log_detail) and verify a vulnerability,
    such as successful SQL Injection Authentication Bypass, Sensitive Configuration Disclosure, IDOR, or Reflected XSS.
    This immediately elevates the log's flag_status to 'CONFIRMED' and registers the finding in the dashboard.

    Parameters:
      - log_id: The integer Log ID returned by send_http_request or listed in get_traffic_history.
      - title: Clear, concise vulnerability title (e.g. 'SQL Injection — Authentication Bypass', 'Administrative Config Disclosure').
      - severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO' (default: 'HIGH').
      - category: Classification (e.g. 'SQL Injection', 'Authentication Bypass', 'Information Disclosure', 'XSS', 'IDOR').
      - evidence: Key evidence string (e.g. issued JWT token, extracted admin email, sensitive config snippet).
      - description: Brief description of vulnerability mechanics and impact.
      - remediation: Recommended fix for developers.
      - project: Workspace name (defaults to active project).
    """
    target_project = _resolve_project(project, allow_all=False)
    sev_clean = (severity or "HIGH").strip().upper()
    cat_clean = (category or "General").strip()
    finding_id = None
    log_flag = "CONFIRMED" if sev_clean in ["HIGH", "CRITICAL"] else "POTENTIAL"
    source_info = "Dashboard API"

    # 1. Dispatch to running Dashboard API first (Distributed setup)
    try:
        payload = {
            "log_id": log_id,
            "title": title.strip(),
            "severity": sev_clean,
            "category": cat_clean,
            "evidence": evidence or "",
            "description": description or f"Vulnerability confirmed and reported by AI security agent for Log #{log_id}.",
            "remediation": remediation or "Apply strict input validation, parameterized queries, and principle of least privilege.",
            "project": target_project
        }
        async with httpx.AsyncClient(timeout=2.5) as client:
            resp = await client.post(f"{get_backend_url()}/api/findings", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                finding_id = data.get("id")
                log_flag = data.get("flag_status", log_flag)
    except Exception:
        pass

    # 2. Fallback to local SQLite database if dashboard is unreachable
    if finding_id is None:
        source_info = "Local Database Fallback"
        db = SessionLocal()
        try:
            entry = db.query(HttpLog).filter(HttpLog.id == log_id).first()
            if not entry:
                return f"[!] Log ID #{log_id} was not found in the Proxynth Dashboard ({get_backend_url()}) or local database. Cannot attach finding."

            existing_finding = db.query(Finding).filter(
                Finding.log_id == entry.id,
                func.lower(Finding.title) == title.strip().lower()
            ).first()

            if existing_finding:
                existing_finding.severity = sev_clean
                existing_finding.category = cat_clean
                if evidence:
                    existing_finding.evidence = evidence
                if description:
                    existing_finding.description = description
                if remediation:
                    existing_finding.remediation = remediation
                finding = existing_finding
            else:
                finding = Finding(
                    log_id=entry.id,
                    title=title.strip(),
                    severity=sev_clean,
                    category=cat_clean,
                    evidence=evidence or "",
                    description=description or f"Vulnerability confirmed and reported by AI security agent for Log #{log_id}.",
                    remediation=remediation or "Apply strict input validation, parameterized queries, and principle of least privilege."
                )
                db.add(finding)

            if sev_clean in ["HIGH", "CRITICAL"]:
                entry.flag_status = "CONFIRMED"
            elif sev_clean in ["MEDIUM", "LOW", "INFO"] and entry.flag_status != "CONFIRMED":
                entry.flag_status = "POTENTIAL"
            db.commit()
            db.refresh(finding)
            finding_id = finding.id
            log_flag = entry.flag_status
        except Exception as ex:
            db.rollback()
            return f"[!] Failed to attach finding to Log #{log_id}: {str(ex)}"
        finally:
            db.close()

    finding_str = f"#{finding_id}" if finding_id else "#recorded"
    return (
        f"[+] VULNERABILITY CONFIRMED & RECORDED ({source_info}):\n"
        f"Project: [{target_project}] | Finding ID: {finding_str} | Linked to Log: #{log_id}\n"
        f"Title: {title} | Severity: [{sev_clean}] | Category: [{cat_clean}]\n"
        f"Flag Status Updated: [{log_flag}]\n"
        f"Evidence: {evidence or '[None provided]'}\n"
        f"The finding is now actively registered in the Proxynth Dashboard and highlighted for operator review."
    )


# ==============================================================================
# MCP Tool 9: get_attack_surface (Target Knowledge Graph Query)
# ==============================================================================

@mcp.tool()
async def get_attack_surface(
    project: Optional[str] = None,
    host: str = "",
    output_format: str = "json"
) -> str:
    """
    Retrieves the stateful Attack Surface Knowledge Graph for the project.
    Provides inventory of known target assets, open ports, services, endpoints,
    and testing progress (UNTESTED, IN_PROGRESS, TESTED, VULNERABLE).
    Essential for autonomous agents (OpenCode/Hermes) to plan and track reconnaissance and exploitation.
    """
    target_project = _resolve_project(project, allow_all=True)
    graph_data = get_attack_surface_graph(project=target_project, host=host.strip() or None)
    if (output_format or "json").strip().lower() == "text":
        summary = graph_data.get("summary", {})
        assets = graph_data.get("assets", [])
        lines = [
            f"=== TARGET ATTACK SURFACE GRAPH [Project: {target_project}] ===",
            f"Assets: {summary.get('total_assets')} | Services: {summary.get('total_services')} | Endpoints: {summary.get('total_endpoints')}",
            f"Status Breakdown: Untested: {summary.get('untested_endpoints')} | Tested: {summary.get('tested_endpoints')} | Vulnerable: {summary.get('vulnerable_endpoints')}\n"
        ]
        for a in assets[:20]:
            lines.append(f"- Host: {a.get('host')} ({a.get('ip') or 'no IP'}) [OS: {a.get('os_info') or 'Unknown'}]")
            for s in a.get("services", [])[:10]:
                lines.append(f"    Port {s.get('port')}/{s.get('protocol')} ({s.get('service_name')}) - {s.get('state')}")
            for ep in a.get("endpoints", [])[:10]:
                lines.append(f"    [{ep.get('tested_status')}] {ep.get('method')} {ep.get('path')} (Params: {ep.get('parameters')})")
        return "\n".join(lines)
    return json.dumps(graph_data, indent=2)


# ==============================================================================
# MCP Tool 10: record_target_asset (Register Host/IP to Knowledge Graph)
# ==============================================================================

@mcp.tool()
async def record_target_asset(
    host: str,
    ip: str = "",
    port: Optional[int] = None,
    os_info: str = "",
    tags: Any = None,
    notes: str = "",
    project: Optional[str] = None
) -> str:
    """
    Explicitly registers or updates a target host/machine in the Proxynth Attack Surface Graph.
    Parameters:
      - host: Domain or hostname (e.g. 'api.target.com' or 'target.com:8443')
      - ip: Target IP address (e.g. '192.168.1.50')
      - port: Optional target port (e.g. 8443 or 443, also auto-parsed if included in host)
      - os_info: Detected OS banner (e.g. 'Linux Ubuntu 22.04')
      - tags: Comma-separated tags or list of strings (e.g. 'production,dmz,aws' or ['production', 'aws'])
      - notes: Operational notes or architecture context
    """
    target_project = _resolve_project(project, allow_all=False)
    if isinstance(tags, list):
        tag_list = [str(t).strip() for t in tags if str(t).strip()]
    elif isinstance(tags, str) and tags.strip():
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    else:
        tag_list = None

    asset = upsert_target_asset(
        project=target_project,
        host=host,
        ip=ip,
        port=port,
        os_info=os_info,
        tags=tag_list,
        notes=notes
    )
    return json.dumps({
        "status": "success",
        "action": "registered_asset",
        "asset": asset
    }, indent=2)


# ==============================================================================
# MCP Tool 11: record_target_service (Register Port/Service to Knowledge Graph)
# ==============================================================================

@mcp.tool()
async def record_target_service(
    host: str,
    port: int,
    protocol: str = "tcp",
    service_name: str = "unknown",
    banner: str = "",
    state: str = "open",
    project: Optional[str] = None
) -> str:
    """
    Catalogs an open or filtered network port/service discovered during reconnaissance (e.g. from nmap)
    into the Target Knowledge Graph.
    """
    target_project = _resolve_project(project, allow_all=False)
    srv = add_or_update_service(
        project=target_project,
        host=host,
        port=port,
        protocol=protocol,
        service_name=service_name,
        banner=banner,
        state=state
    )
    return json.dumps({
        "status": "success",
        "action": "registered_service",
        "service": srv
    }, indent=2)


# ==============================================================================
# MCP Tool 12: record_target_endpoint (Register Web Endpoint & Test Status)
# ==============================================================================

@mcp.tool()
async def record_target_endpoint(
    host: str,
    url: str,
    method: str = "GET",
    parameters: Any = None,
    auth_required: bool = False,
    tested_status: str = "UNTESTED",
    notes: str = "",
    project: Optional[str] = None
) -> str:
    """
    Catalogs a discovered web route/endpoint into the Target Knowledge Graph and updates its testing status.
    tested_status options: 'UNTESTED', 'IN_PROGRESS', 'TESTED', 'VULNERABLE'.
    """
    target_project = _resolve_project(project, allow_all=False)
    if isinstance(parameters, list):
        param_list = [str(p).strip() for p in parameters if str(p).strip()]
    elif isinstance(parameters, str) and parameters.strip():
        param_list = [p.strip() for p in parameters.split(",") if p.strip()]
    else:
        param_list = None

    ep = add_or_update_endpoint(
        project=target_project,
        host=host,
        url=url,
        method=method,
        parameters=param_list,
        auth_required=auth_required,
        tested_status=tested_status,
        notes=notes
    )
    return json.dumps({
        "status": "success",
        "action": "registered_endpoint",
        "endpoint": ep
    }, indent=2)


# ==============================================================================
# MCP Tool 13: generate_oast_token (Blind Exploit Callback Generation)
# ==============================================================================

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
async def infer_hidden_endpoints(
    host: str,
    project: Optional[str] = None,
    auto_register_to_graph: bool = True
) -> str:
    """
    Analyzes observed REST architectural patterns on the target host and predicts hidden, unmapped attack surface routes
    (CRUD mutations, API documentation, debug actuators, admin consoles, and version probes).
    Optionally auto-registers predictions into the Target Knowledge Graph as 'UNTESTED' endpoints.
    """
    from backend.api_spec_inferrer import infer_endpoints_from_observed
    target_project = _resolve_project(project, allow_all=False)
    res = infer_endpoints_from_observed(
        host=host,
        project=target_project,
        auto_register_to_graph=auto_register_to_graph
    )
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tool 20: get_attack_paths (Exploit Path Chaining & Kill Chain Visualizer)
# ==============================================================================

@mcp.tool()
async def get_attack_paths(
    project: Optional[str] = None
) -> str:
    """
    Constructs an interconnected attack path graph linking:
    [External Entry] -> [Exposed Asset/Service] -> [Target Route] -> [Vulnerability Finding] -> [Crown Jewels / Impact].
    Returns structured kill chains and Mermaid diagram representation.
    """
    from backend.attack_path import build_attack_path_graph
    target_project = _resolve_project(project, allow_all=True)
    res = build_attack_path_graph(project=target_project)
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tool 21: generate_exploit_poc (One-Click Standalone PoC & Dossier Generator)
# ==============================================================================

@mcp.tool()
async def generate_exploit_poc(
    finding_id: int
) -> str:
    """
    Generates a standalone, zero-dependency Python exploit script, cURL command, HTML PoC,
    and complete CVSS/CWE remediation dossier for a verified vulnerability finding.
    """
    from backend.poc_generator import generate_finding_dossier
    dossier = generate_finding_dossier(finding_id=finding_id)
    if not dossier:
        return f"[!] Finding #{finding_id} was not found."
    return json.dumps(dossier, indent=2)


# ==============================================================================
# MCP Tool 22: send_websocket_message (WebSocket Full-Duplex Frame Tester)
# ==============================================================================

@mcp.tool()
async def send_websocket_message(
    url: str,
    message: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    project: Optional[str] = None
) -> str:
    """
    Dispatches a test message frame to a target WebSocket server, captures the server's reply frame,
    and logs the transaction into the database for analysis and replay.
    """
    from backend.ws_manager import send_ws_message
    target_project = _resolve_project(project, allow_all=False)
    res = await send_ws_message(
        url=url,
        message=message,
        headers=headers,
        timeout=timeout,
        project=target_project
    )
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tool 23: fuzz_endpoint (High-Speed Parameter Fuzzer / Mini-Intruder)
# ==============================================================================

@mcp.tool()
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

@mcp.tool()
async def execute_workflow_sequence(
    sequence: Any,
    initial_context: Optional[Dict[str, Any]] = None,
    test_step_skipping: bool = False,
    project: Optional[str] = None,
    agent_id: str = "primary_agent"
) -> str:
    """
    Executes a multi-stage stateful HTTP sequence with dynamic parameter extraction,
    variable chaining ({{var}}), session identity swapping, and automated logic flaw bypass testing.

    Parameters:
      - sequence: List of step dictionaries (or JSON string) defining the workflow stages.
        Each step: {
          "name": "Step Name",
          "url": "http://...",
          "method": "POST",
          "headers": {...},
          "body": "...",
          "extract": {"order_id": "json.data.id", "csrf": "header.x-csrf-token"}
        }
      - initial_context: Optional dictionary of pre-seeded variables.
      - test_step_skipping: If True, tests skipping intermediate steps (e.g. Step 1 -> Step 3)
        to identify business logic execution order enforcement flaws.
      - project: Project workspace name.
      - agent_id: Identifier of the calling AI agent.
    """
    from backend.workflow_engine import execute_workflow

    target_project = _resolve_project(project, allow_all=False)

    if isinstance(sequence, str):
        try:
            sequence = json.loads(sequence)
        except Exception as e:
            return f"[!] Error parsing sequence JSON: {str(e)}"

    if not isinstance(sequence, list):
        return "[!] Error: sequence must be a list of step specifications."

    db = SessionLocal()
    proj_proxy = ""
    try:
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    upstream_proxy = proj_proxy.strip() if proj_proxy else (os.getenv("PROXSYNTH_UPSTREAM_PROXY") or "").strip()

    result = await execute_workflow(
        sequence=sequence,
        initial_context=initial_context or {},
        project=target_project,
        agent_id=agent_id,
        test_step_skipping=test_step_skipping,
        upstream_proxy=upstream_proxy or None
    )
    return json.dumps(result, indent=2)


# ==============================================================================
# MCP Tool 25: test_race_condition (Turbo Race Condition & Burst Testing Engine)
# ==============================================================================

@mcp.tool()
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

@mcp.tool()
async def mine_javascript_assets(
    content_or_url: str,
    base_url: Optional[str] = None,
    auto_register: bool = True,
    project: Optional[str] = None
) -> str:
    """
    Extracts hidden API routes, endpoints, query/body parameter names, source maps (.map),
    and leaked credentials (AWS keys, JWTs, Slack webhooks, hardcoded API keys) from
    client-side JavaScript scripts or URLs. Discovered endpoints are automatically ingested
    into the Target Knowledge Graph.

    Parameters:
      - content_or_url: Raw JavaScript source code OR full URL to remote script (e.g. 'https://target/app.js').
      - base_url: Optional base URL for resolving relative API endpoints when supplying raw code.
      - auto_register: Automatically register endpoints into the Attack Surface Graph and record leaked secrets (default: True).
      - project: Project workspace name.
    """
    from backend.js_miner import mine_javascript

    target_project = _resolve_project(project, allow_all=False)

    db = SessionLocal()
    proj_proxy = ""
    try:
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    upstream_proxy = proj_proxy.strip() if proj_proxy else (os.getenv("PROXSYNTH_UPSTREAM_PROXY") or "").strip()

    result = await mine_javascript(
        content_or_url=content_or_url,
        base_url=base_url,
        auto_register=auto_register,
        project=target_project,
        upstream_proxy=upstream_proxy or None
    )
    return json.dumps(result, indent=2)


# ==============================================================================
# MCP Tool 27: compare_http_responses (Semantic Structural Diffing Engine)
# ==============================================================================

@mcp.tool()
async def compare_http_responses(
    response_a: Any,
    response_b: Any,
    max_diff_lines: int = 50
) -> str:
    """
    Performs semantic structural diffing between two HTTP responses with volatile token stripping
    (timestamps, UUIDs, hex hashes, CSRF nonces) and heuristic Soft-403 / Soft-404 error detection.
    Eliminates AI agent token waste by summarizing exact behavioral deviations.

    Parameters:
      - response_a: Either an HttpLog ID (integer/string) OR a dictionary {"status_code": 200, "body": "...", "headers": {...}}.
      - response_b: Either an HttpLog ID (integer/string) OR a dictionary {"status_code": 200, "body": "...", "headers": {...}}.
      - max_diff_lines: Maximum number of structural diff lines to return (default: 50).
    """
    from backend.diff_engine import compute_semantic_diff

    def _resolve_response(resp_input: Any) -> Dict[str, Any]:
        if isinstance(resp_input, (int, str)) and str(resp_input).isdigit():
            log_id = int(resp_input)
            db = SessionLocal()
            try:
                log_entry = db.query(HttpLog).filter(HttpLog.id == log_id).first()
                if log_entry:
                    hdrs = {}
                    try:
                        hdrs = json.loads(log_entry.response_headers) if log_entry.response_headers else {}
                    except Exception:
                        pass
                    return {
                        "status_code": log_entry.status_code or 0,
                        "body": log_entry.response_body or "",
                        "headers": hdrs
                    }
            finally:
                db.close()
            return {"status_code": 0, "body": f"[Log #{log_id} not found]", "headers": {}}
        elif isinstance(resp_input, str):
            try:
                parsed = json.loads(resp_input)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
            return {"status_code": 200, "body": resp_input, "headers": {}}
        elif isinstance(resp_input, dict):
            return resp_input
        return {"status_code": 0, "body": str(resp_input), "headers": {}}

    res_a = _resolve_response(response_a)
    res_b = _resolve_response(response_b)

    diff_result = compute_semantic_diff(res_a, res_b, max_diff_lines=max_diff_lines)
    return json.dumps(diff_result, indent=2)


# ==============================================================================
# MCP Tool 28: audit_jwt_security (Autonomous JWT & Session Token Security Audit)
# ==============================================================================

@mcp.tool()
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

@mcp.tool()
async def delete_attack_surface_node(
    node_type: str,
    node_id: int,
    project: Optional[str] = None
) -> str:
    """
    Deletes an asset, service (port), or endpoint from the Proxynth attack surface knowledge graph.

    Parameters:
      - node_type: Type of node to remove ('asset', 'endpoint', or 'service').
      - node_id: Integer ID of the record in the attack surface.
      - project: Project workspace name.
    """
    from backend.target_manager import delete_target_asset, delete_target_endpoint, delete_target_service

    target_project = _resolve_project(project, allow_all=False)
    ntype = node_type.strip().lower()

    if ntype in ["asset", "host", "target"]:
        success = delete_target_asset(node_id, project=target_project)
    elif ntype in ["endpoint", "route", "url"]:
        success = delete_target_endpoint(node_id, project=target_project)
    elif ntype in ["service", "port"]:
        success = delete_target_service(node_id, project=target_project)
    else:
        return f"[!] Invalid node_type '{node_type}'. Choose 'asset', 'endpoint', or 'service'."

    if success:
        return json.dumps({
            "status": "deleted",
            "node_type": ntype,
            "node_id": node_id,
            "project": target_project
        }, indent=2)
    else:
        return f"[!] Node #{node_id} of type '{node_type}' not found or could not be deleted in project '{target_project}'."


# ==============================================================================
# MCP Tool 30: clear_attack_surface_graph
# ==============================================================================

@mcp.tool()
async def clear_attack_surface_graph(
    project: Optional[str] = None
) -> str:
    """
    Clears all target assets, services, and endpoints from the attack surface knowledge graph for a project.

    Parameters:
      - project: Project workspace name to clear (or 'all' to clear all projects).
    """
    from backend.target_manager import clear_target_graph

    target_project = _resolve_project(project, allow_all=True)
    cleared_count = clear_target_graph(project=target_project)
    return json.dumps({
        "status": "cleared",
        "deleted_assets": cleared_count,
        "project": target_project
    }, indent=2)


# ==============================================================================
# MCP Tool 32: distill_http_response (P1)
# ==============================================================================

@mcp.tool()
async def distill_http_response(
    body: str,
    content_type: str = "text/html",
    reflected_query: Optional[str] = None,
    max_length: int = 4000
) -> str:
    """
    Distills raw HTML or large JSON API response bodies into compact, high-density security representations.
    Extracts forms, inputs, API routes, sensitive keys, and reflected parameters while stripping
    CSS, SVGs, base64 blobs, and boilerplate scripts. Reduces LLM context token usage by 85-95%.

    Parameters:
      - body: Raw response body string or JSON.
      - content_type: MIME type ('text/html' or 'application/json'). Defaults to 'text/html'.
      - reflected_query: Optional string to check where it reflects in attributes or DOM text.
      - max_length: Maximum character length for compact representation. Defaults to 4000.
    """
    from backend.body_distiller import distill_response_body

    res = distill_response_body(
        body=body,
        content_type=content_type,
        max_length=max_length,
        reflected_query=reflected_query
    )
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tool 33: spray_oast_canaries (P2)
# ==============================================================================

@mcp.tool()
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

@mcp.tool()
async def record_testing_hypothesis(
    target: str,
    vuln_type: str,
    hypothesis: str,
    status: str = "PLANNED",
    evidence_notes: str = "",
    project: Optional[str] = None,
    agent_id: str = "primary_agent"
) -> str:
    """
    Records an attack hypothesis into the agent's persistent working memory ledger.
    Prevents context amnesia during long campaigns and tracks planned vs confirmed testing avenues.

    Parameters:
      - target: Endpoint, URL, or host:port being tested (e.g. '/api/orders/{id}' or '192.168.1.10:80').
      - vuln_type: Vulnerability type (e.g. 'BOLA', 'SQLI', 'SSRF', 'BAC', 'RACE', 'XSS', 'AUTH_BYPASS').
      - hypothesis: Specific reasoning and attack hypothesis (e.g. 'Testing IDOR on user_id param because endpoint returns order object').
      - status: Status ('PLANNED', 'TESTING', 'CONFIRMED', 'DISPROVEN', 'BLOCKED'). Defaults to 'PLANNED'.
      - evidence_notes: Preliminary evidence or reasoning notes.
      - project: Project workspace name. Defaults to active project or 'default'.
      - agent_id: Agent identifier. Defaults to 'primary_agent'.
    """
    from backend.hypothesis_manager import create_hypothesis

    target_project = _resolve_project(project, allow_all=False)
    res = create_hypothesis(
        project=target_project,
        target=target,
        vuln_type=vuln_type,
        hypothesis=hypothesis,
        status=status,
        evidence_notes=evidence_notes,
        agent_id=agent_id
    )

    # Relay event to live dashboard WebSockets if dashboard is running
    try:
        client = await _get_dashboard_client()
        await client.post(
            f"{get_backend_url()}/api/hypotheses/broadcast-event",
            json={"type": "HYPOTHESIS_CREATED", "hypothesis": res, "project": target_project}
        )
    except Exception:
        pass

    return json.dumps({
        "status": "recorded",
        "hypothesis": res
    }, indent=2)


# ==============================================================================
# MCP Tool 35: get_testing_agenda (P3)
# ==============================================================================

@mcp.tool()
async def get_testing_agenda(
    project: Optional[str] = None
):
    """
    Retrieves the agent's active testing agenda and to-do list of unverified attack hypotheses.
    Use this at the beginning of a session or after compaction to know exactly what targets still need testing.

    Parameters:
      - project: Project workspace name ('all' for entire scope, or omit for active project).
    """
    from backend.hypothesis_manager import get_testing_agenda as fetch_agenda

    target_project = _resolve_project(project, allow_all=True)
    agenda = fetch_agenda(project=target_project)
    return json.dumps(agenda, indent=2)


# ==============================================================================
# MCP Tool 36: update_hypothesis_status (P3)
# ==============================================================================

@mcp.tool()
async def update_hypothesis_status(
    hypothesis_id: int,
    status: str,
    evidence_notes: str = "",
    project: Optional[str] = None
):
    """
    Updates the status and findings evidence of a recorded attack hypothesis.

    Parameters:
      - hypothesis_id: ID of the hypothesis to update.
      - status: New status ('PLANNED', 'TESTING', 'CONFIRMED', 'DISPROVEN', 'BLOCKED').
      - evidence_notes: Verified findings, response excerpt, or disproof explanation.
      - project: Project workspace name. Defaults to active project or 'all'.
    """
    from backend.hypothesis_manager import update_hypothesis as edit_hypothesis

    target_project = _resolve_project(project, allow_all=True)
    res = edit_hypothesis(
        hypothesis_id=hypothesis_id,
        status=status,
        evidence_notes=evidence_notes,
        project=target_project
    )
    if not res:
        return f"[!] Hypothesis #{hypothesis_id} not found in project '{target_project}'."

    # Relay event to live dashboard WebSockets if dashboard is running
    try:
        client = await _get_dashboard_client()
        await client.post(
            f"{get_backend_url()}/api/hypotheses/broadcast-event",
            json={"type": "HYPOTHESIS_UPDATED", "hypothesis": res, "project": target_project}
        )
    except Exception:
        pass

    return json.dumps({
        "status": "updated",
        "hypothesis": res
    }, indent=2)


# ==============================================================================
# MCP Tool 37: verify_dom_execution (P4)
# ==============================================================================

@mcp.tool()
async def verify_dom_execution(
    url: str,
    payload: Optional[str] = None,
    param_name: Optional[str] = None,
    trigger_event: str = "load",
    wait_timeout_ms: int = 4000,
    project: Optional[str] = None
) -> str:
    """
    Spawns a sandboxed headless Chromium browser to deterministically verify whether a client-side
    exploit payload (XSS, DOM Injection, CSP bypass) actually executed in the real browser DOM.
    Hooks window.alert/confirm/prompt dialogs and console sinks for 100% false-positive-free verification.

    Parameters:
      - url: Target URL to test.
      - payload: Optional exploit payload (e.g. '<script>alert(1)</script>' or '\"><svg onload=alert(1)>').
      - param_name: Optional query/body parameter name to inject the payload into.
      - trigger_event: Event trigger ('load' or 'click'). Defaults to 'load'.
      - wait_timeout_ms: Timeout in milliseconds for browser navigation and DOM execution. Defaults to 4000.
      - project: Project workspace name for scope guardrail validation.
    """
    from backend.browser_oracle import verify_dom_execution as run_oracle

    target_project = _resolve_project(project, allow_all=False)

    # Scope validation
    db = SessionLocal()
    try:
        is_allowed, block_reason = await async_check_scope(target_project, url, db)
        if not is_allowed:
            return f"[!] Out of Scope: Target '{url}' violates guardrail policy: {block_reason}"
    finally:
        db.close()

    res = await run_oracle(
        url=url,
        payload=payload,
        param_name=param_name,
        trigger_event=trigger_event,
        wait_timeout_ms=wait_timeout_ms
    )
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tools: Public Ingress Tunnel (OAST & Webhooks)
# ==============================================================================

@mcp.tool()
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


@mcp.tool()
async def get_tunnel_status() -> str:
    """
    Returns the operational status, provider, public URL, uptime, and callback base URL
    for the active public ingress tunnel.
    """
    from backend.tunnel_manager import get_tunnel_status as get_status
    return json.dumps(get_status(), indent=2)


@mcp.tool()
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

@mcp.tool()
async def add_interception_rule(
    name: str,
    rule_type: str = "REQUEST",  # REQUEST, RESPONSE, MOCK
    match_url: str = "*",
    match_method: str = "*",
    match_header: str = "",
    match_body: str = "",
    action_type: str = "REPLACE_HEADER",  # REPLACE_HEADER, REMOVE_HEADER, REPLACE_BODY, REWRITE_URL, MOCK_RESPONSE
    action_target: str = "",
    action_value: str = "",
    action_extra: Optional[Dict[str, Any]] = None,
    priority: int = 10,
    project: Optional[str] = None
) -> str:
    """
    Adds a headless interception rule to automatically mutate requests/responses or return synthetic mock responses.
    Allows AI agents to tamper with headers (e.g. X-Forwarded-For, Authorization), replace body contents, or mock 200/403 responses.
    """
    from backend.interception_engine import add_interception_rule as add_rule
    proj = _resolve_project(project, allow_all=False)
    rule = add_rule(
        name=name,
        rule_type=rule_type,
        match_url=match_url,
        match_method=match_method,
        match_header=match_header,
        match_body=match_body,
        action_type=action_type,
        action_target=action_target,
        action_value=action_value,
        action_extra=action_extra,
        project=proj,
        priority=priority,
        enabled=True
    )
    return json.dumps(rule, indent=2)


@mcp.tool()
async def list_interception_rules(project: Optional[str] = None) -> str:
    """
    Lists all active and configured interception and match/replace rules for the target project.
    """
    from backend.interception_engine import list_interception_rules as list_rules
    proj = _resolve_project(project, allow_all=True)
    rules = list_rules(project=proj)
    return json.dumps(rules, indent=2)


@mcp.tool()
async def toggle_interception_rule(rule_id: int, enabled: Optional[bool] = None) -> str:
    """
    Toggles or sets the enabled status of an interception rule by rule ID.
    """
    from backend.interception_engine import toggle_interception_rule as toggle_rule
    res = toggle_rule(rule_id=rule_id, enabled=enabled)
    if not res:
        return json.dumps({"status": "error", "message": f"Rule #{rule_id} not found"}, indent=2)
    return json.dumps(res, indent=2)


@mcp.tool()
async def delete_interception_rule(rule_id: int) -> str:
    """
    Permanently deletes an interception rule by rule ID.
    """
    from backend.interception_engine import delete_interception_rule as del_rule
    ok = del_rule(rule_id=rule_id)
    return json.dumps({"status": "success" if ok else "not_found", "deleted_rule_id": rule_id}, indent=2)


# ==============================================================================
# MCP Tools: Dynamic Anti-CSRF Token Management
# ==============================================================================

@mcp.tool()
async def get_csrf_tokens(domain: Optional[str] = None, project: Optional[str] = None) -> str:
    """
    Retrieves all auto-tracked and manual anti-CSRF tokens extracted from HTTP responses.
    """
    from backend.session_tracker import get_tracked_csrf_tokens
    proj = _resolve_project(project, allow_all=True)
    tokens = get_tracked_csrf_tokens(domain=domain, project=proj)
    return json.dumps(tokens, indent=2)


@mcp.tool()
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


@mcp.tool()
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

@mcp.tool()
async def search_traffic_advanced(
    query: str = "",
    domain: Optional[str] = None,
    method: Optional[str] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    path_pattern: Optional[str] = None,
    has_findings: bool = False,
    min_duration_ms: Optional[int] = None,
    limit: int = 30,
    project: Optional[str] = None
) -> str:
    """
    Performs high-performance multi-dimensional queries across captured HTTP proxy traffic.
    Filter by status ranges (e.g. 500-599), latency thresholds, URL path patterns, and body full-text.
    """
    from backend.traffic_search import search_traffic_advanced as search_adv
    proj = _resolve_project(project, allow_all=True)
    res = search_adv(
        query=query,
        domain=domain,
        method=method,
        status_min=status_min,
        status_max=status_max,
        path_pattern=path_pattern,
        has_findings=has_findings,
        min_duration_ms=min_duration_ms,
        project=proj,
        limit=limit
    )
    return json.dumps(res, indent=2)


@mcp.tool()
async def analyze_traffic_patterns(project: Optional[str] = None) -> str:
    """
    Analyzes all captured traffic in a workspace, returning endpoint route inventories,
    status code distributions, discovered GET/POST/JSON parameter inventories, and latency statistics.
    """
    from backend.traffic_search import analyze_traffic_patterns as analyze_patterns
    proj = _resolve_project(project, allow_all=True)
    res = analyze_patterns(project=proj)
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tools: GraphQL & WebSocket Protocol Security Inspector
# ==============================================================================

@mcp.tool()
async def inspect_graphql_endpoint(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    project: Optional[str] = None
) -> str:
    """
    Performs automated security inspection on a GraphQL endpoint:
    - Tests for schema introspection disclosure and maps queries/mutations
    - Identifies sensitive field names (passwords, tokens, secrets)
    - Tests for Clairvoyance / field suggestion leakage when introspection is disabled
    - Tests for query batching amplification support
    """
    from backend.protocol_inspector import inspect_graphql_endpoint as inspect_gql
    proj = _resolve_project(project, allow_all=False)
    res = await inspect_gql(url=url, headers=headers, project=proj)
    return json.dumps(res, indent=2)


@mcp.tool()
async def audit_websocket_security(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    project: Optional[str] = None
) -> str:
    """
    Performs security audit on a WebSocket handshake:
    - Tests for Cross-Site WebSocket Hijacking (CSWSH) via untrusted Origin validation
    - Checks for unencrypted plaintext ws:// transport
    - Audits sensitive authentication credentials exposed in query parameters
    """
    from backend.protocol_inspector import audit_websocket_security as audit_ws
    proj = _resolve_project(project, allow_all=False)
    res = await audit_ws(url=url, headers=headers, project=proj)
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tools: Automated CI/CD & API Security Auditor
# ==============================================================================

@mcp.tool()
async def run_security_audit_suite(
    project: Optional[str] = None,
    min_severity: str = "LOW"
) -> str:
    """
    Runs automated OWASP API security audit across proxy-captured traffic, computing
    an overall security score (0-100), letter grade (A+ to F), and violation breakdown.
    """
    from backend.ci_auditor import run_security_audit_suite as run_audit
    proj = _resolve_project(project, allow_all=True)
    res = run_audit(project=proj, min_severity=min_severity)
    return json.dumps(res, indent=2)


@mcp.tool()
async def generate_audit_ci_report(
    project: Optional[str] = None,
    output_format: str = "markdown"
) -> str:
    """
    Generates a publication-grade Markdown or JSON security report for CI/CD pipelines (GitHub Actions, GitLab CI).
    """
    from backend.ci_auditor import generate_audit_ci_report as gen_report
    proj = _resolve_project(project, allow_all=True)
    return gen_report(project=proj, output_format=output_format)


# ==============================================================================
# MCP Tool: update_proxsynth_system (Autonomous Self-Update & Codebase Sync)
# ==============================================================================

@mcp.tool()
async def update_proxsynth_system(
    confirm: bool = False,
    force_check: bool = False
) -> str:
    """
    Checks for and applies updates to the Proxsynth platform and FastMCP Server directly from Git.
    When `confirm=False` (default), performs a non-destructive check against the remote repository,
    returning current version, latest version, commits behind, and changelog highlights.
    When `confirm=True`, automatically executes git pull, updates dependencies via pip, and
    synchronizes the Proxsynth runtime without operator manual intervention.
    """
    from backend.update_manager import async_check_for_updates, async_perform_system_update

    if not confirm:
        chk = await async_check_for_updates(force=force_check)
        if chk.get("update_available"):
            cl_text = "\n".join([f"- {c}" for c in chk.get("changelog", [])])
            return (
                f"[⚡ PROXSYNTH UPDATE AVAILABLE]\n"
                f"Current Version: v{chk.get('current_version')} (#{chk.get('current_commit')})\n"
                f"Latest Available: v{chk.get('latest_version')} (#{chk.get('latest_commit')})\n"
                f"Commits Behind: {chk.get('commits_behind')}\n\n"
                f"Changelog:\n{cl_text}\n\n"
                f"To apply this update now, call `update_proxsynth_system(confirm=True)`."
            )
        else:
            return (
                f"[✓ PROXSYNTH IS UP TO DATE]\n"
                f"Version: v{chk.get('current_version')} (#{chk.get('current_commit')}) on branch [{chk.get('branch')}].\n"
                f"Checked at: {chk.get('checked_at')}"
            )

    # Perform automated update
    res = await async_perform_system_update()
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tools: Nuclei Exploit Templates & BOLA Access Matrix & CA Tools
# ==============================================================================

@mcp.tool()
async def generate_nuclei_template(
    finding_id: Optional[int] = None,
    log_id: Optional[int] = None,
    title: Optional[str] = None,
    severity: str = "medium"
) -> str:
    """
    Generates a standard Nuclei v3 YAML exploit/regression template from an existing Finding or HttpLog.
    Enables autonomous DAST regression pipelines and instant reproduction.
    """
    db = SessionLocal()
    try:
        if finding_id:
            from backend.nuclei_generator import generate_nuclei_yaml_from_finding
            f = db.query(Finding).filter(Finding.id == finding_id).first()
            if not f:
                return f"[!] Finding #{finding_id} not found."
            l = db.query(HttpLog).filter(HttpLog.id == f.log_id).first()
            res = generate_nuclei_yaml_from_finding(f, l)
            return res.get("yaml", "")
        elif log_id:
            from backend.nuclei_generator import generate_nuclei_yaml_from_log
            l = db.query(HttpLog).filter(HttpLog.id == log_id).first()
            if not l:
                return f"[!] HttpLog #{log_id} not found."
            res = generate_nuclei_yaml_from_log(l, title=title, severity=severity)
            return res.get("yaml", "")
        else:
            return "[!] Please provide either finding_id or log_id."
    finally:
        db.close()


@mcp.tool()
async def get_bola_access_matrix(project: Optional[str] = None) -> str:
    """
    Retrieves the cross-identity BOLA/IDOR access control matrix for candidate object-level endpoints.
    Lists candidate endpoints, active identity roles, and current vulnerability/protection states.
    """
    from backend.bola_matrix import get_bola_matrix_data
    proj = _resolve_project(project, allow_all=True)
    matrix = get_bola_matrix_data(project=proj)
    return json.dumps(matrix, indent=2)


@mcp.tool()
async def run_bola_matrix_scan(project: Optional[str] = None) -> str:
    """
    Executes automated BOLA shadow replay scans across all observed candidate endpoints in the project.
    Tests each candidate endpoint against all secondary identities and unauthenticated roles.
    """
    from backend.bola_matrix import run_full_bola_matrix_scan
    proj = _resolve_project(project, allow_all=False)
    res = await run_full_bola_matrix_scan(project=proj)
    return json.dumps(res, indent=2)


@mcp.tool()
async def get_ca_certificate_details() -> str:
    """
    Returns Root CA certificate status, SHA-256 fingerprint, and OS-specific trust store installation commands.
    """
    from backend.ca_manager import get_ca_metadata, get_os_trust_scripts
    meta = get_ca_metadata()
    scripts = get_os_trust_scripts("proxsynth-ca.crt")
    return json.dumps({"metadata": meta, "trust_scripts": scripts}, indent=2)


# ==============================================================================
# Advanced Security Audit Tools: BFLA, Mass Assignment, Logic Fuzz, Differential Injection
# ==============================================================================

@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
async def semantic_diff_responses(log_id_a: int, log_id_b: int) -> str:
    """
    Performs noise-filtered semantic differential analysis between two logged HTTP responses.
    Filters volatile dynamic tokens (timestamps, UUIDs, CSRF nonces) and returns only meaningful
    data changes and soft error indicators, saving up to 80% context tokens for the AI agent.
    """
    from backend.diff_engine import compute_semantic_diff
    db = SessionLocal()
    try:
        l_a = db.query(HttpLog).filter(HttpLog.id == log_id_a).first()
        l_b = db.query(HttpLog).filter(HttpLog.id == log_id_b).first()
        if not l_a or not l_b:
            return f"[!] Logs #{log_id_a} and/or #{log_id_b} not found."
        headers_a = json.loads(l_a.response_headers or "{}") if l_a.response_headers else {}
        headers_b = json.loads(l_b.response_headers or "{}") if l_b.response_headers else {}
        resp_a = {"status_code": l_a.status_code, "body": l_a.response_body or "", "headers": headers_a}
        resp_b = {"status_code": l_b.status_code, "body": l_b.response_body or "", "headers": headers_b}
        diff = compute_semantic_diff(resp_a, resp_b)
        return json.dumps(diff, indent=2)
    finally:
        db.close()


# ==============================================================================
# AUTONOMOUS CAMPAIGN & ZERO-HUMAN INTERACTION MCP TOOLS
# ==============================================================================

@mcp.tool()
async def spider_and_crawl_target(
    root_url: str,
    max_depth: int = 2,
    max_pages: int = 25,
    project: Optional[str] = None
) -> str:
    """
    Autonomously crawls and spiders a web target to map out internal links,
    HTML forms, input parameters, and JSON API endpoints.
    Automatically populates the Target Knowledge Graph (assets & endpoints) with zero manual guidance.
    """
    from backend.spider_engine import crawl_and_map_target
    proj = _resolve_project(project, allow_all=False)
    res = await crawl_and_map_target(
        root_url=root_url,
        max_depth=max_depth,
        max_pages=max_pages,
        project=proj
    )
    return json.dumps(res, indent=2)


@mcp.tool()
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


@mcp.tool()
async def execute_reauthentication(project: Optional[str] = None) -> str:
    """
    Manually or proactively triggers the registered re-authentication recipe for a project.
    Refreshes session tokens and cookies in the active credential vault.
    """
    from backend.auth_macro import execute_reauth
    proj = _resolve_project(project, allow_all=False)
    res = await execute_reauth(proj)
    return json.dumps(res, indent=2)


@mcp.tool()
async def verify_vulnerability_candidate(
    finding_id: Optional[int] = None,
    log_id: Optional[int] = None,
    vuln_type: Optional[str] = None,
    project: Optional[str] = None
) -> str:
    """
    Unified Deterministic Verification Gate.
    Verifies suspected vulnerabilities using specialized oracles:
    - Headless Chromium DOM Sandbox for XSS
    - 3-Point Differential Boolean & Z-Score Timing for SQLi/SSTI
    - OAST Interaction Correlator for SSRF/RCE
    - Unauthenticated Shadow Replay for BOLA/BFLA
    Eliminates false positives and marks genuine exploits as VERIFIED_EXPLOITABLE.
    """
    from backend.verification_gate import verify_vulnerability_candidate
    proj = _resolve_project(project, allow_all=False)
    res = await verify_vulnerability_candidate(
        finding_id=finding_id,
        log_id=log_id,
        vuln_type=vuln_type,
        project=proj
    )
    return json.dumps(res, indent=2)


@mcp.tool()
async def scan_network_ports(
    target: str,
    ports_profile: str = "top_100",
    ports_custom: Optional[str] = None,
    concurrency: int = 80,
    project: Optional[str] = None,
    audit_misconfigs: bool = True
) -> str:
    """
    Autonomous Async Port & Network Scanner (Zero-Dependency).
    Scans a target host, IP, or URL for open TCP ports and fingerprint services.
    Automatically grabs service banners, registers assets and services into Target Knowledge Graph,
    and conducts unauthenticated access audits for exposed databases (Redis, Elasticsearch, Docker daemon).
    """
    from backend.network_scanner import scan_target_ports
    proj = _resolve_project(project, allow_all=False)
    res = await scan_target_ports(
        target=target,
        ports_profile=ports_profile,
        ports_custom=ports_custom,
        concurrency=concurrency,
        project=proj,
        audit_misconfigs=audit_misconfigs
    )
    return json.dumps(res, indent=2)


@mcp.tool()
async def import_api_schema(
    spec_source: str,
    target_base_url: Optional[str] = None,
    project: Optional[str] = None
) -> str:
    """
    1-Click OpenAPI & Swagger Specification Importer.
    Imports and maps an OpenAPI 2.0 / 3.0 / 3.1 specification (from URL or raw JSON/YAML string)
    into structured endpoints, methods, parameters, and testable attack body templates in the Target Knowledge Graph.
    """
    from backend.api_importer import import_api_schema as engine_import_api_schema
    proj = _resolve_project(project, allow_all=False)
    res = await engine_import_api_schema(
        spec_source=spec_source,
        target_base_url=target_base_url,
        project=proj
    )
    return json.dumps(res, indent=2)


@mcp.tool()
async def audit_api_gateway_bypass(
    target_url: str,
    project: Optional[str] = None
) -> str:
    """
    API Gateway 401/403 Authorization Bypass Engine.
    Evaluates protected API endpoints returning 401 Unauthorized or 403 Forbidden
    against a matrix of gateway proxy spoofing headers (X-Forwarded-For, X-Custom-IP-Authorization),
    URL override headers (X-Original-URL, X-Rewrite-URL), and path normalization traversal tricks (/..;/, /./, //).
    Automatically logs verified bypass findings to the Findings Ledger.
    """
    from backend.api_importer import audit_api_gateway_bypass as engine_audit_api_gateway_bypass
    proj = _resolve_project(project, allow_all=False)
    res = await engine_audit_api_gateway_bypass(
        target_url=target_url,
        project=proj
    )
    return json.dumps(res, indent=2)


@mcp.tool()
async def mine_cli_output(
    command: str,
    raw_output: str,
    target: str = "",
    project: Optional[str] = None
) -> str:
    """
    Automated CLI Output Miner & Structured Knowledge Extractor.
    Parses raw terminal stdout/stderr from Nmap, Masscan, Nuclei, FFUF, Gobuster, or Dirsearch,
    and automatically extracts open ports, service banners, fuzzing paths, and discovered vulnerabilities,
    inserting them into the Target Knowledge Graph and Findings Ledger.
    """
    from backend.cli_miner import mine_and_ingest_cli_output
    proj = _resolve_project(project, allow_all=False)
    res = mine_and_ingest_cli_output(
        command=command,
        raw_output=raw_output,
        target=target,
        project=proj
    )
    return json.dumps(res, indent=2)


@mcp.tool()
async def run_autonomous_security_campaign(
    target_url: str,
    modes: Optional[List[str]] = None,
    project: Optional[str] = None,
    max_pages: int = 15,
    deep_verify: bool = True,
    ports_profile: str = "top_100",
    enable_spa: bool = True
) -> str:
    """
    Unified Autonomous Campaign Orchestrator ('God Tool').
    Executes a comprehensive, coordinated multi-track security audit in a single call:
    0. Universal Target Classification -> Supports Web URLs, APIs, IPs, CIDRs, or hostnames
    1. Track Infra & Network -> Built-in async port scanner & service exposure auditor (Redis, Elastic, Docker)
    2. Track Web & SPA -> Hybrid crawler with Playwright Chromium DOM engine for React/Vue/Angular
    3. Track API Security -> Route discovery, OpenAPI schema ingestion, & API Gateway 401/403 bypass
    4. Deep Vulnerability Engine -> OAST canary spray (SSRF/RCE), BFLA verb tampering, Mass Assignment, Numeric Logic
    5. Deterministic Verification Gate -> Verifies all findings with specialized oracles and eliminates false positives
    Returns a token-efficient executive dossier with verified findings and standalone PoC instructions.
    """
    from backend.campaign_orchestrator import run_autonomous_security_campaign
    proj = _resolve_project(project, allow_all=False)
    res = await run_autonomous_security_campaign(
        target_url=target_url,
        modes=modes,
        project=proj,
        max_pages=max_pages,
        deep_verify=deep_verify,
        ports_profile=ports_profile,
        enable_spa=enable_spa
    )
    return json.dumps(res, indent=2)


@mcp.tool()
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


if __name__ == "__main__":
    try:
        mcp.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        sys.exit(0)
    except Exception as ex:
        err_msg = str(ex)
        if "CancelledError" not in err_msg and "KeyboardInterrupt" not in err_msg:
            sys.exit(0)


