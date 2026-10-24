"""
Proxsynth MCP - Traffic Tools
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


@proxsynth_tool(name="send_http_request")
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

@proxsynth_tool(name="get_traffic_history")
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

    structured_logs = []
    if logs_list:
        lines = [f"=== RECENT TRAFFIC HISTORY (Project: {target_project} | {source_info}) ==="]
        for l in logs_list:
            lid = l.get("id", 0)
            method = l.get("method", "GET")
            status = str(l.get("status_code") or "ERR")
            duration = l.get("duration_ms", 0)
            flag = l.get("flag_status", "CLEAN")
            url = l.get("url", "")
            lines.append(f"#{lid:04d} | {method:<5} | {status:<4} | {duration:>4}ms | [{flag:<9}] | {url}")
            structured_logs.append({
                "log_id": lid,
                "method": method,
                "url": url,
                "status_code": l.get("status_code"),
                "latency_ms": duration,
                "flag_status": flag,
                "project": l.get("project", target_project),
                "agent_id": l.get("agent_id", "primary_agent")
            })
        lines.append(f"\nTip: Call get_log_detail(log_id) to read complete headers, full body, or vulnerability findings.")
        text_summary = "\n".join(lines)
    else:
        text_summary = f"No traffic logs recorded for project [{target_project}] ({source_info})."

    get_traffic_history._last_structured = {
        "project": target_project,
        "total_count": len(structured_logs),
        "logs": structured_logs
    }
    return text_summary


# ==============================================================================
# MCP Tool 8: report_vulnerability (Direct Agent Vulnerability Flagging)
# ==============================================================================

@proxsynth_tool(name="get_log_detail")
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
        err_msg = f"[!] Log ID #{log_id} was not found in the Proxynth Dashboard ({get_backend_url()}) or local database."
        get_log_detail._last_structured = {"log_id": log_id, "found": False, "error": err_msg}
        return err_msg

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

    full_text = (
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

    structured_data = {
        "log_id": log_id,
        "project": log_data.get("project", "default"),
        "agent_id": log_data.get("agent_id", "primary_agent"),
        "method": log_data.get("method", "GET"),
        "url": log_data.get("url", ""),
        "status_code": log_data.get("status_code"),
        "duration_ms": log_data.get("duration_ms", 0),
        "request_headers": req_hdrs,
        "request_body": req_body_prev,
        "response_headers": res_hdrs,
        "response_body": res_body_prev,
        "flag_status": log_data.get("flag_status", "CLEAN"),
        "reasoning": log_data.get("reasoning", ""),
        "findings": findings
    }

    get_log_detail._last_structured = structured_data
    return full_text


# ==============================================================================
# MCP Tool 7: get_traffic_history (Traffic Index & Search)
# ==============================================================================

@proxsynth_tool(name="distill_http_response")
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

@proxsynth_tool(name="search_traffic_advanced")
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

@proxsynth_tool(name="analyze_traffic_patterns")
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

@proxsynth_tool(name="compare_http_responses")
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

@proxsynth_tool(name="semantic_diff_responses")
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
