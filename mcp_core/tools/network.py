"""
Proxsynth MCP - Network Tools
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


@proxsynth_tool(name="scan_network_ports")
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

@proxsynth_tool(name="get_target_health")
async def get_target_health(
    url: str,
    timeout: float = 8.0,
    project: Optional[str] = None
) -> str:
    """
    [HARNESS: READ_ONLY]
    Diagnoses target host health and network latency breakdown:
    DNS Resolution -> TCP Connect -> TLS Handshake -> HTTP Time To First Byte (TTFB).
    Detects 5xx server flapping and high latency bottlenecks before launching heavy campaigns.

    Parameters:
      - url: Target URL or hostname to diagnose (e.g. 'http://target.local:3000' or 'https://api.example.com').
      - timeout: Socket and probe timeout in seconds (default: 8.0).
      - project: Optional project workspace to cross-reference recent 5xx error rates.
    """
    from backend.target_health import probe_target_health
    target_project = _resolve_project(project, allow_all=True)
    res = await probe_target_health(url=url, timeout=timeout, project=target_project)
    return json.dumps(res, indent=2)
