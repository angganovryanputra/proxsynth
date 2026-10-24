"""
Proxsynth MCP - Agenda Tools
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


@proxsynth_tool(name="record_testing_hypothesis")
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

@proxsynth_tool(name="get_testing_agenda")
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

@proxsynth_tool(name="update_hypothesis_status")
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
