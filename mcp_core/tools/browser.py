"""
Proxsynth MCP - Browser Tools
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


@proxsynth_tool(name="browser_navigate_and_render")
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

@proxsynth_tool(name="render_webpage")
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

@proxsynth_tool(name="request_manual_login")
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

@proxsynth_tool(name="verify_dom_execution")
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

@proxsynth_tool(name="spider_and_crawl_target")
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
