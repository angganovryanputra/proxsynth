"""
PROXSYNTH MCP — COGNITIVE PENTEST HEXAGON SUPER-TOOLS
Exposes 6 high-leverage intent-driven super-tools with heuristic auto-decisions:
1. proxsynth_recon
2. proxsynth_traffic
3. proxsynth_audit
4. proxsynth_session
5. proxsynth_verify_and_export
6. proxsynth_autonomous_step
"""

import json
from typing import Optional, Dict, Any, Literal

from mcp_core.server import proxsynth_tool


def _emit(res: Any) -> str:
    """Serialize a super-tool result as compact JSON (no indent padding, keep UTF-8).

    LLMs parse minified JSON identically to pretty-printed JSON, so dropping the
    ``indent=2`` whitespace trims ~15% of output tokens on every hexagon call with
    zero loss of fidelity — the token-efficiency half of the cognitive contract.
    """
    return json.dumps(res, separators=(",", ":"), ensure_ascii=False)
from backend.cognitive_hexagon import (
    recon_intent_router,
    traffic_intent_router,
    audit_intent_router,
    session_intent_router,
    verify_export_intent_router,
    autonomous_step_router,
    _next_action,
)


@proxsynth_tool(name="proxsynth_recon")
async def proxsynth_recon(
    target: str,
    mode: Literal["auto", "spider", "ports", "openapi", "domain", "health"] = "auto",
    project: Optional[str] = None,
    max_pages: int = 15,
    concurrency: int = 40
) -> str:
    """
    [HEXAGON SUPER-TOOL: RECONNAISSANCE & SURFACE MAPPING]
    Consolidates autonomous network scanning, SPA crawler, OpenAPI importer, and domain discovery.
    AUTO-DECISION:
    - IP/CIDR -> Autonomous Port Scanner & Service Fingerprinter
    - Web URL -> Headless Chromium SPA Spider & Endpoint Harvester
    - Spec File/URL -> OpenAPI / Swagger Schema Importer
    - Domain Hostname -> Asset Inventory & Target Health Diagnostic
    """
    try:
        res = await recon_intent_router(
            target=target,
            mode=mode,
            project=project,
            max_pages=max_pages,
            concurrency=concurrency
        )
        return _emit(res)
    except Exception as ex:
        return _emit({
            "status": "error",
            "facet": "recon",
            "target": target,
            "message": str(ex)
        })


@proxsynth_tool(name="proxsynth_traffic")
async def proxsynth_traffic(
    url: Optional[str] = None,
    action: Literal["auto", "send", "diff", "distill", "search"] = "auto",
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    log_id_a: Optional[int] = None,
    log_id_b: Optional[int] = None,
    payload: Optional[str] = None,
    query_search: Optional[str] = None,
    project: Optional[str] = None
) -> str:
    """
    [HEXAGON SUPER-TOOL: TRAFFIC ENGINE & SEMANTIC DIFFING]
    Consolidates HTTP/WS request proxying, WAF auto-heal, response distillation, and differential analysis.
    AUTO-DECISION:
    - Given two Log IDs -> Executes Semantic Differential Analysis & Soft-Error Heuristics
    - Given single Log ID / Body -> Distills large HTML/JSON into compact structural representation
    - Given URL -> Dispatches request via MITM engine with WAF auto-heal and attaches follow-up attack suggestions
    - Given query -> Searches captured traffic history
    """
    try:
        res = await traffic_intent_router(
            url=url,
            action=action,
            method=method,
            headers=headers,
            body=body,
            log_id_a=log_id_a,
            log_id_b=log_id_b,
            payload=payload,
            query_search=query_search,
            project=project
        )
        return _emit(res)
    except Exception as ex:
        return _emit({
            "status": "error",
            "facet": "traffic",
            "message": str(ex)
        })


@proxsynth_tool(name="proxsynth_audit")
async def proxsynth_audit(
    target_url: Optional[str] = None,
    vuln_focus: Literal["auto", "access_control", "logic", "oast", "xss", "graphql", "fuzz"] = "auto",
    log_id: Optional[int] = None,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    body: Optional[str] = None,
    project: Optional[str] = None,
    auto_exploit: bool = False
) -> str:
    """
    [HEXAGON SUPER-TOOL: VULNERABILITY AUDITING & HEURISTIC ENGINE]
    Consolidates Two-Tier Access Control Orchestrator, Numeric Logic Fuzzer, OAST Sprayer, and DOM Oracle.
    AUTO-DECISION:
    - Multi-role credentials or object IDs in path -> Routes to Two-Tier 3-Way Replay (BOLA/BFLA/Unauth)
    - Commercial / numeric parameters -> Routes to Numeric Business Logic & Negative Balance Fuzzer
    - SSRF / callback parameters -> Injects in-house OAST canaries and polls event listener
    - Reflected parameters -> Verifies exploitability in Playwright Headless Chromium DOM Oracle
    - GraphQL routes -> Audits schema introspection and query depth
    """
    try:
        res = await audit_intent_router(
            target_url=target_url,
            vuln_focus=vuln_focus,
            log_id=log_id,
            params=params,
            headers=headers,
            method=method,
            body=body,
            project=project,
            auto_exploit=auto_exploit
        )
        return _emit(res)
    except Exception as ex:
        return _emit({
            "status": "error",
            "facet": "audit",
            "message": str(ex)
        })


@proxsynth_tool(name="proxsynth_session")
async def proxsynth_session(
    domain: Optional[str] = None,
    action: Literal["auto", "set", "get", "list", "refresh", "configure_refresher"] = "auto",
    role: Optional[str] = None,
    token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    login_url: Optional[str] = None,
    project: Optional[str] = None
) -> str:
    """
    [HEXAGON SUPER-TOOL: IDENTITY VAULT & SESSION LIFECYCLE]
    Consolidates multi-role active credentials (User A, User B, Admin), anti-CSRF token cache, and 401 re-auth refresher.
    AUTO-DECISION:
    - Provided token + role -> Upserts persona into project identity vault
    - Provided domain -> Retrieves active identities and cached anti-CSRF tokens
    - Session expired / 401 -> Executes automated re-auth recipe
    """
    try:
        res = await session_intent_router(
            domain=domain,
            action=action,
            role=role,
            token=token,
            headers=headers,
            login_url=login_url,
            project=project
        )
        return _emit(res)
    except Exception as ex:
        return _emit({
            "status": "error",
            "facet": "session",
            "message": str(ex)
        })


@proxsynth_tool(name="proxsynth_verify_and_export")
async def proxsynth_verify_and_export(
    finding_id: Optional[int] = None,
    log_id: Optional[int] = None,
    format: Literal["auto", "nuclei", "report_markdown", "verify"] = "auto",
    project: Optional[str] = None
) -> str:
    """
    [HEXAGON SUPER-TOOL: VERIFICATION GATE & REPORTING SUITE]
    Consolidates deterministic oracle verification, ProjectDiscovery Nuclei v2/v3 YAML PoC generator, and CVSS v4.0 dossiers.
    AUTO-DECISION:
    - Evaluates finding via deterministic gate (eliminating false positives)
    - Synthesizes reproducible Nuclei v2/v3 YAML template with cross-step extractors
    - Compiles publication-ready Markdown dossier with CVSS v4.0 metrics and CWE references
    """
    try:
        res = await verify_export_intent_router(
            finding_id=finding_id,
            log_id=log_id,
            format=format,
            project=project
        )
        return _emit(res)
    except Exception as ex:
        return _emit({
            "status": "error",
            "facet": "verify_and_export",
            "message": str(ex)
        })


@proxsynth_tool(name="proxsynth_execute")
async def proxsynth_execute(
    command: str = "",
    script_content: Optional[str] = None,
    reasoning: str = "",
    tool_name: str = "terminal",
    project: Optional[str] = None,
    timeout: int = 60,
    cwd: str = ""
) -> str:
    """
    [HEXAGON SUPER-TOOL: SCRIPT & CLI EXECUTION -> AI ACTIVITY]
    Runs an external security tool or a custom script LOCALLY, proxied through the MITM
    engine so any HTTP it emits is still captured in Proxy Traffic (auto-linked), and
    records the run in the AI Activity module with full stdout/stderr — re-runnable from
    the Proxsynth web UI.

    DECISION RULE (so you pick the right tool):
    - Use proxsynth_execute when invoking an external tool (nmap, sqlmap, ffuf, nuclei,
      gobuster) OR executing multi-step / custom script logic. Pass the script body as
      `script_content` (it is run as a file) or a shell line as `command`.
    - Use proxsynth_traffic instead for a SINGLE HTTP request/replay/diff (that path
      records into Proxy Traffic, not AI Activity).
    Safe-Mode guardrails + SSRF checks apply; execution is localhost-bound and proxied.
    """
    try:
        from mcp_core.tools.report import run_pentest_command
        raw = await run_pentest_command(
            command=command,
            reasoning=reasoning,
            tool_name=tool_name,
            project=project,
            timeout=timeout,
            cwd=cwd,
            script_content=script_content,
            output_format="json"
        )
        data = json.loads(raw) if isinstance(raw, str) and raw.strip().startswith("{") else {"raw_output": raw}

        # Chain: if the run surfaced structured intel, point at the audit engine; otherwise
        # suggest inspecting the traffic the process generated.
        mined = data.get("mined_summary") or data.get("mined")
        if mined:
            na = _next_action(
                "proxsynth_audit",
                "Script output was mined into the knowledge graph; audit the newly surfaced endpoints.",
                confidence=0.65, project=project
            )
        else:
            na = _next_action(
                "proxsynth_traffic",
                "Inspect the HTTP traffic this script generated (search recent captured logs).",
                confidence=0.55, action="search", query_search=(command or "")[:80], project=project
            )
        if isinstance(data, dict):
            data["facet"] = "execute"
            data["next_action"] = na
        return _emit(data)
    except Exception as ex:
        return _emit({
            "status": "error",
            "facet": "execute",
            "message": str(ex)
        })


@proxsynth_tool(name="proxsynth_autonomous_step")
async def proxsynth_autonomous_step(
    project: Optional[str] = None,
    goal: str = "auto",
    feedback: Optional[str] = None
) -> str:
    """
    [HEXAGON SUPER-TOOL: COGNITIVE OVERSEER & SINGLE-INTENT STEP EXECUTOR]
    Master autonomous agent interface. Inspects Attack Surface Knowledge Graph and recent traffic,
    selects the single next highest-leverage offensive testing action, and executes it immediately.
    """
    try:
        res = await autonomous_step_router(
            project=project,
            goal=goal,
            feedback=feedback
        )
        return _emit(res)
    except Exception as ex:
        return _emit({
            "status": "error",
            "facet": "autonomous_step",
            "message": str(ex)
        })

