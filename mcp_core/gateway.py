"""
Proxsynth MCP - Core Gateway, State Scoping, & Streaming Dispatcher
Handles dashboard API communication, SQLite direct fallbacks, WebSocket event emission,
and project isolation scoping.
"""

import os
import json
import asyncio
import urllib.parse
from typing import Optional, Dict, Any, List

import httpx
from sqlalchemy import func

from backend.database import (
    init_db,
    SessionLocal,
    ActiveSession,
    HttpLog,
    Finding,
    Project,
    AgentCommandLog,
    CapturedPayload,
    TargetAsset
)
from backend.analyzer import analyze_traffic


def get_backend_url() -> str:
    return os.getenv("PROXSYNTH_BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")


BACKEND_URL = get_backend_url()
DEFAULT_PROJECT = os.getenv("PROXSYNTH_PROJECT", "default").strip().lower()

# Session State Scope Management
_active_project: Optional[str] = None
_active_write_project: Optional[str] = None


def _resolve_project(project: Optional[str] = None, allow_all: bool = True, target_host: Optional[str] = None) -> str:
    """
    Resolves project workspace scope for queries and mutations.
    Separates global viewing mode ('all') from write scope:
    - If allow_all is True: returns 'all' if requested or in global view mode.
    - If allow_all is False: writes never mutate global scope. Resolves to _active_write_project,
      or the target host's tagged project from TargetAsset, or explicit project, or DEFAULT_PROJECT.
    """
    p = (project or "").strip().lower()
    if p in ("all", "*", "any", "global"):
        if allow_all:
            return "all"
        return _active_write_project or (_active_project if (_active_project and _active_project not in ("all", "*", "any", "global")) else DEFAULT_PROJECT)
    if p:
        return p

    # If writing with target_host known, resolve from TargetAsset
    if not allow_all and target_host:
        try:
            db = SessionLocal()
            asset = db.query(TargetAsset).filter(TargetAsset.host.ilike(f"%{target_host.strip()}%")).first()
            if asset and asset.project and asset.project.lower() not in ("all", "*", "any", "global"):
                return asset.project.lower()
        except Exception:
            pass
        finally:
            db.close()

    if _active_project:
        if not allow_all and _active_project in ("all", "*", "any", "global"):
            return _active_write_project or DEFAULT_PROJECT
        return _active_project

    return "all" if allow_all else (_active_write_project or DEFAULT_PROJECT)


# Connection Pools
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
        api_key = os.getenv("PROXSYNTH_API_KEY", "").strip()
        if api_key:
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
    verify_ssl = os.getenv("PROXSYNTH_VERIFY_SSL", "false").lower() == "true"
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
    Falls back to direct SQLite database write if dashboard is offline.
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
            proxy_attempts=log_payload.get("proxy_attempts", 1),
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

        # Prevent dummy loopback traffic/tools from polluting findings in named target projects
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
            sessions = db.query(ActiveSession).filter(ActiveSession.project == target_project).all()
            if not sessions:
                sessions = db.query(ActiveSession).all()

            for s in sessions:
                stored_dom = (s.domain or "").strip().lower()
                if "://" in stored_dom:
                    stored_dom = urllib.parse.urlparse(stored_dom).netloc
                stored_dom = stored_dom.split(":")[0].strip("/")

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
