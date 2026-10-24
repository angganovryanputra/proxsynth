"""
Proxsynth MCP - Api Tools
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


@proxsynth_tool(name="send_websocket_message")
async def send_websocket_message(
    url: str,
    message: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    project: Optional[str] = None,
    protocol: str = "raw",
    event_name: str = "message"
) -> str:
    """
    [HARNESS: ACTIVE_TRAFFIC]
    Dispatches a test message frame to a target WebSocket or Socket.IO server,
    captures the server's reply frame, and logs the transaction into the database for analysis and replay.

    Parameters:
      - url: Target WebSocket URL (ws:// or wss://, or http:// / https:// which will be converted).
      - message: Raw message string, JSON string, or payload to dispatch.
      - headers: Optional custom HTTP headers to pass during handshake.
      - timeout: Timeout in seconds for connection and frame exchange (default: 5.0).
      - project: Project workspace name.
      - protocol: 'raw' for plain WebSockets, or 'socket.io' for Engine.IO/Socket.IO automatic handshake (default: 'raw').
      - event_name: Socket.IO event identifier (e.g. 'message', 'login', 'query', default: 'message').
    """
    from backend.ws_manager import send_ws_message
    target_project = _resolve_project(project, allow_all=False)
    res = await send_ws_message(
        url=url,
        message=message,
        headers=headers,
        timeout=timeout,
        project=target_project,
        protocol=protocol,
        event_name=event_name
    )
    return json.dumps(res, indent=2)


# ==============================================================================
# MCP Tool 23: fuzz_endpoint (High-Speed Parameter Fuzzer / Mini-Intruder)
# ==============================================================================

@proxsynth_tool(name="audit_websocket_security")
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

@proxsynth_tool(name="inspect_graphql_endpoint")
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

@proxsynth_tool(name="infer_hidden_endpoints")
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

@proxsynth_tool(name="import_api_schema")
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

@proxsynth_tool(name="audit_api_gateway_bypass")
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
