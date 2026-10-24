"""
Proxsynth MCP - Intercept Tools
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


@proxsynth_tool(name="add_interception_rule")
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

@proxsynth_tool(name="list_interception_rules")
async def list_interception_rules(project: Optional[str] = None) -> str:
    """
    Lists all active and configured interception and match/replace rules for the target project.
    """
    from backend.interception_engine import list_interception_rules as list_rules
    proj = _resolve_project(project, allow_all=True)
    rules = list_rules(project=proj)
    return json.dumps(rules, indent=2)

@proxsynth_tool(name="toggle_interception_rule")
async def toggle_interception_rule(rule_id: int, enabled: Optional[bool] = None) -> str:
    """
    Toggles or sets the enabled status of an interception rule by rule ID.
    """
    from backend.interception_engine import toggle_interception_rule as toggle_rule
    res = toggle_rule(rule_id=rule_id, enabled=enabled)
    if not res:
        return json.dumps({"status": "error", "message": f"Rule #{rule_id} not found"}, indent=2)
    return json.dumps(res, indent=2)

@proxsynth_tool(name="delete_interception_rule")
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

@proxsynth_tool(name="get_ca_certificate_details")
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
