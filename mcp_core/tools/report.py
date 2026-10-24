"""
Proxsynth MCP - Report Tools
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

CURRENT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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


@proxsynth_tool(name="report_vulnerability")
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

    # Auto-sync finding to agent working memory testing hypothesis & agenda
    try:
        from backend.hypothesis_manager import sync_finding_to_hypothesis
        sync_finding_to_hypothesis(
            project=target_project,
            finding_id=finding_id,
            log_id=log_id,
            title=title.strip(),
            severity=sev_clean,
            category=cat_clean,
            evidence=evidence or ""
        )
    except Exception:
        pass

    finding_str = f"#{finding_id}" if finding_id else "#recorded"
    return (
        f"[+] VULNERABILITY CONFIRMED & RECORDED ({source_info}):\n"
        f"Project: [{target_project}] | Finding ID: {finding_str} | Linked to Log: #{log_id}\n"
        f"Title: {title} | Severity: [{sev_clean}] | Category: [{cat_clean}]\n"
        f"Flag Status Updated: [{log_flag}]\n"
        f"Evidence: {evidence or '[None provided]'}\n"
        f"The finding is now actively registered in the Proxynth Dashboard and synchronized into the Testing Agenda."
    )


# ==============================================================================
# MCP Tool 9: get_attack_surface (Target Knowledge Graph Query)
# ==============================================================================

@proxsynth_tool(name="generate_exploit_poc")
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

@proxsynth_tool(name="generate_nuclei_template")
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

@proxsynth_tool(name="verify_vulnerability_candidate")
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

@proxsynth_tool(name="generate_audit_ci_report")
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

@proxsynth_tool(name="get_attack_surface")
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

@proxsynth_tool(name="record_target_asset")
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

@proxsynth_tool(name="record_target_service")
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

@proxsynth_tool(name="record_target_endpoint")
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

@proxsynth_tool(name="get_attack_paths")
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

@proxsynth_tool(name="delete_attack_surface_node")
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

@proxsynth_tool(name="clear_attack_surface_graph")
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

@proxsynth_tool(name="mine_javascript_assets")
async def mine_javascript_assets(
    content_or_url: str,
    base_url: Optional[str] = None,
    auto_register: bool = True,
    project: Optional[str] = None,
    parse_sourcemaps: bool = True,
    follow_bundles: bool = False
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
      - parse_sourcemaps: Automatically download and unpack .map sourcemaps from `sourcesContent` for unminified code discovery (default: True).
      - follow_bundles: Recursively follow and mine referenced vendor/chunk script bundles (default: False).
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
        upstream_proxy=upstream_proxy or None,
        parse_sourcemaps=parse_sourcemaps,
        follow_bundles=follow_bundles
    )
    return json.dumps(result, indent=2)


# ==============================================================================
# MCP Tool 27: compare_http_responses (Semantic Structural Diffing Engine)
# ==============================================================================

@proxsynth_tool(name="mine_cli_output")
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

@proxsynth_tool(name="run_pentest_command")
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

@proxsynth_tool(name="execute_workflow_sequence")
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

@proxsynth_tool(name="run_security_audit_suite")
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

@proxsynth_tool(name="update_proxsynth_system")
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
