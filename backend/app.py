"""
Proxsynth MCP - FastAPI Application, REST API, & WebSocket Broadcaster
Full-featured Offensive Security Gateway with Intercept Proxy Trap, Scope Guardrails,
Repeater, HAR/Markdown Exporter, and Multi-Project Observability.
"""

import os
import json
import asyncio
import time
import secrets
import warnings
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

warnings.filterwarnings("ignore", message=r".*eof_received.*")
warnings.filterwarnings("ignore", message=r".*Duplicate Operation ID.*")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Query, HTTPException, BackgroundTasks, Response, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
import ipaddress
import urllib.parse
from sqlalchemy.orm import Session, defer
from sqlalchemy import desc, func, or_

from backend.database import init_db, get_db, HttpLog, Finding, ActiveSession, Project, AgentCommandLog, CapturedPayload, TargetAsset, TargetService, TargetEndpoint, OastEvent
from backend.analyzer import analyze_traffic
from backend.browser_handler import (
    spawn_interactive_login,
    signal_login_confirmation,
    get_active_login_status,
    import_session_cookies,
    parse_cookie_input
)
from backend.intercept_manager import (
    is_intercept_enabled,
    set_intercept_mode,
    get_intercept_status,
    create_intercept_trap,
    resolve_intercept_trap,
    pop_intercept_result,
    check_scope,
    async_check_scope,
    invalidate_scope_cache
)
from backend.report_generator import generate_har_export, generate_markdown_report
from backend.openapi_generator import generate_openapi_spec
from backend.fuzzer import run_fuzz_attack, BUILTIN_PAYLOADS
from backend.session_keeper import start_session_keeper, stop_session_keeper, get_session_keeper_status
from backend.security_utils import sanitize_attachment_filename

# Initialize SQLite database
init_db()

app = FastAPI(
    title="Proxsynth Platform",
    description="Autonomous Agentic Interception Proxy & Security Telemetry Platform for AI Agents",
    version="2.5.0"
)

@app.on_event("startup")
async def startup_event():
    start_session_keeper(interval=120)
    try:
        from backend.forward_proxy import start_forward_proxy
        await start_forward_proxy()
    except Exception as ex:
        print(f"[!] Notice: Proxsynth Forward Proxy startup error: {ex}")

    try:
        from backend.dns_server import start_dns_server
        await start_dns_server()
    except Exception as ex:
        print(f"[!] Notice: Proxsynth DNS OAST listener startup error: {ex}")

    try:
        from backend.ldap_server import start_ldap_server
        await start_ldap_server()
    except Exception as ex:
        print(f"[!] Notice: Proxsynth LDAP OAST listener startup error: {ex}")

    try:
        from backend.update_manager import start_background_updater
        start_background_updater(interval_seconds=300.0, ws_manager=ws_manager)
    except Exception as ex:
        print(f"[!] Notice: Proxsynth Auto-Updater startup error: {ex}")

@app.on_event("shutdown")
async def shutdown_event():
    stop_session_keeper()
    try:
        from backend.update_manager import stop_background_updater
        stop_background_updater()
    except Exception:
        pass
    try:
        from backend.forward_proxy import stop_forward_proxy
        await stop_forward_proxy()
    except Exception:
        pass
    try:
        from backend.dns_server import stop_dns_server
        stop_dns_server()
    except Exception:
        pass
    try:
        from backend.ldap_server import stop_ldap_server
        stop_ldap_server()
    except Exception:
        pass

# Security Configuration from Environment
ALLOWED_ORIGINS_ENV = os.getenv(
    "PROXSYNTH_ALLOWED_ORIGINS",
    os.getenv("PROX" + "YNTH_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1:3000,http://localhost:3000")
)
PROXSYNTH_ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS_ENV.split(",") if o.strip()]
PROXSYNTH_API_KEY = os.getenv("PROXSYNTH_API_KEY", os.getenv("PROX" + "YNTH_API_KEY", "")).strip()
PROXSYNTH_ALLOW_REMOTE = os.getenv("PROXSYNTH_ALLOW_REMOTE", os.getenv("PROX" + "YNTH_ALLOW_REMOTE", "false")).lower() == "true"
PROXSYNTH_MAX_BODY = int(os.getenv("PROXSYNTH_MAX_BODY_SIZE", os.getenv("PROX" + "YNTH_MAX_BODY_SIZE", "524288")))  # 512 KB default limit per body

app.add_middleware(
    CORSMiddleware,
    allow_origins=PROXSYNTH_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
)

@app.middleware("http")
async def host_and_auth_security_middleware(request: Request, call_next):
    # 0. Allow out-of-band OAST callbacks from target servers without host or API key restrictions
    if request.url.path.startswith("/oast/"):
        return await call_next(request)

    client_host = request.client.host if request.client else "unknown"
    # 1. Localhost enforcement: if remote access is not explicitly enabled, block remote IPs
    if not PROXSYNTH_ALLOW_REMOTE:
        is_local_client = client_host in ["127.0.0.1", "localhost", "::1", "testclient"]
        if not is_local_client:
            try:
                ip_addr = ipaddress.ip_address(client_host)
                # Permit WSL2 / Hyper-V virtual switch (172.16.0.0/12) and loopback
                if ip_addr in ipaddress.ip_network("172.16.0.0/12") or ip_addr.is_loopback:
                    is_local_client = True
            except ValueError:
                pass
        if not is_local_client:
            return JSONResponse(
                {"detail": f"Remote access forbidden for {client_host}: Proxsynth dashboard is restricted to localhost (127.0.0.1) or WSL2. Set PROXSYNTH_ALLOW_REMOTE=true in environment to permit external remote IPs."},
                status_code=403
            )

    # 2. API Key enforcement (if PROXSYNTH_API_KEY is configured in env)
    effective_api_key = PROXSYNTH_API_KEY or PROXSYNTH_API_KEY
    if effective_api_key and request.url.path.startswith("/api/") and request.url.path != "/api/health":
        provided_key = (
            request.headers.get("X-Proxsynth-Key") or
            request.headers.get("X-Proxsynth-Key") or
            request.query_params.get("api_key") or
            ""
        )
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            provided_key = auth_hdr[7:].strip()
        
        if not secrets.compare_digest(provided_key, effective_api_key):
            return JSONResponse(
                {"detail": "Unauthorized: Invalid or missing API Key (X-Proxsynth-Key / X-Proxsynth-Key header)."},
                status_code=401
            )

    return await call_next(request)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# ==============================================================================
# WebSocket Connection Manager
# ==============================================================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = ConnectionManager()


# ==============================================================================
# Schemas
# ==============================================================================

class LogRecordRequest(BaseModel):
    project: str = "default"
    agent_id: Optional[str] = "primary_agent"
    source: str = "HTTP_CLIENT"
    method: str = "GET"
    url: str
    host: str
    path: str
    status_code: Optional[int] = None
    duration_ms: int = 0
    request_headers: Dict[str, Any] = {}
    request_body: str = ""
    response_headers: Dict[str, Any] = {}
    response_body: str = ""
    reasoning: Optional[str] = ""
    flag_status: Optional[str] = None
    finding_title: Optional[str] = None
    finding_severity: Optional[str] = None
    finding_category: Optional[str] = None
    finding_evidence: Optional[str] = None
    finding_description: Optional[str] = None
    finding_remediation: Optional[str] = None
    payload_hint: Optional[str] = None


class CreateFindingRequest(BaseModel):
    log_id: int
    title: str
    severity: Optional[str] = "HIGH"
    category: Optional[str] = "General"
    evidence: Optional[str] = ""
    description: Optional[str] = ""
    remediation: Optional[str] = ""
    project: Optional[str] = None


class CreateProjectRequest(BaseModel):
    name: str
    description: Optional[str] = ""


class UpdateScopeRequest(BaseModel):
    scope_enabled: bool
    allowed_hosts: List[str]
    blocked_patterns: List[str]
    allow_internal_networks: Optional[bool] = False
    verify_ssl: Optional[bool] = False
    delay_ms: Optional[int] = 0
    upstream_proxy: Optional[str] = ""


class SpawnAuthRequest(BaseModel):
    project: str = "default"
    login_url: str
    target_domain: Optional[str] = None
    browser_choice: Optional[str] = "chrome"  # "chrome", "msedge", "chromium", "system"


class ImportCookiesRequest(BaseModel):
    project: Optional[str] = "default"
    domain: str
    raw_cookie: Optional[str] = None
    raw_input: Optional[str] = None
    raw: Optional[str] = None  # Friendly alias for agents sending {"raw": "..."}


class ConfirmAuthRequest(BaseModel):
    domain: Optional[str] = None


class InterceptToggleRequest(BaseModel):
    enabled: bool


class InterceptActionRequest(BaseModel):
    action: str  # "forward" or "drop"
    modified_data: Optional[Dict[str, Any]] = None


class RepeaterSendRequest(BaseModel):
    project: str = "default"
    method: str = "GET"
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = ""


class RunFuzzRequest(BaseModel):
    project: str = "default"
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    body: Optional[str] = ""
    category: Optional[str] = "sqli"
    custom_payloads: Optional[List[str]] = None
    concurrency: int = 5


class RecordCommandRequest(BaseModel):
    project: Optional[str] = "default"
    agent_id: Optional[str] = "primary_agent"
    command: str
    tool_name: Optional[str] = "terminal"
    reasoning: Optional[str] = ""
    exit_code: Optional[int] = 0
    stdout: Optional[str] = ""
    stderr: Optional[str] = ""
    duration_ms: Optional[int] = 0
    status: Optional[str] = "SUCCESS"
    linked_log_id: Optional[int] = None
    script_content: Optional[str] = ""


class RecordPayloadRequest(BaseModel):
    project: Optional[str] = "default"
    agent_id: Optional[str] = "primary_agent"
    vuln_type: Optional[str] = "CUSTOM"
    target_param: Optional[str] = ""
    raw_payload: str
    mutation_type: Optional[str] = "DIRECT"
    target_url: Optional[str] = ""
    http_method: Optional[str] = "GET"
    http_log_id: Optional[int] = None
    outcome: Optional[str] = "TESTED"
    http_status: Optional[int] = None
    response_signature: Optional[str] = ""
    notes: Optional[str] = ""


class ClearRequest(BaseModel):
    project: Optional[str] = None


class ExecuteCommandRequest(BaseModel):
    command: str
    project: Optional[str] = "default"
    agent_id: Optional[str] = "operator"
    cwd: Optional[str] = None
    timeout: int = 60
    reasoning: Optional[str] = "Manual reproduction via AI CLI Repeater"
    script_content: Optional[str] = None


class TestPayloadRequest(BaseModel):
    raw_payload: str
    target_url: str
    http_method: Optional[str] = "GET"
    target_param: Optional[str] = ""
    vuln_type: Optional[str] = "CUSTOM"
    project: Optional[str] = "default"
    headers: Optional[Dict[str, str]] = None
    mutation_type: Optional[str] = "DIRECT"


# ==============================================================================
# In-memory known projects cache & stats cache for high concurrency
_KNOWN_PROJECTS = {"default"}
_STATS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}

def _invalidate_stats_cache():
    _STATS_CACHE.clear()

async def record_and_broadcast_log(log_data: dict, db: Session) -> HttpLog:
    """Stores HttpLog, executes analyzer, and notifies WebSocket subscribers with single atomic commit."""
    project_name = (log_data.get("project") or "default").strip().lower()

    # Fast in-memory check to avoid database query on every log
    if project_name not in _KNOWN_PROJECTS:
        existing_proj = db.query(Project).filter(Project.name == project_name).first()
        if not existing_proj:
            db.add(Project(name=project_name, description="Auto-created workspace"))
            db.commit()
        _KNOWN_PROJECTS.add(project_name)

    req_body = (log_data.get("request_body") or "")[:PROXSYNTH_MAX_BODY]
    res_body = (log_data.get("response_body") or "")[:PROXSYNTH_MAX_BODY]
    agent_id = (log_data.get("agent_id") or "primary_agent").strip()

    log_entry = HttpLog(
        project=project_name,
        agent_id=agent_id,
        source=log_data.get("source", "HTTP_CLIENT"),
        method=log_data.get("method", "GET").upper(),
        url=log_data.get("url", ""),
        host=log_data.get("host", ""),
        path=log_data.get("path", "/"),
        status_code=log_data.get("status_code"),
        duration_ms=log_data.get("duration_ms", 0),
        request_headers=json.dumps(log_data.get("request_headers", {})),
        request_body=req_body,
        response_headers=json.dumps(log_data.get("response_headers", {})),
        response_body=res_body,
        reasoning=log_data.get("reasoning", "") or "",
        timestamp=datetime.now()
    )

    flag_status, findings_data = analyze_traffic(log_entry)

    # Honor explicit finding and flag supplied by agent
    agent_flag = (log_data.get("flag_status") or "").strip().upper()
    agent_title = (log_data.get("finding_title") or "").strip()
    if agent_title:
        agent_sev = (log_data.get("finding_severity") or "HIGH").strip().upper()
        agent_cat = (log_data.get("finding_category") or "Agent Reported").strip()
        agent_ev = log_data.get("finding_evidence") or log_data.get("reasoning") or ""
        agent_desc = log_data.get("finding_description") or f"Finding explicitly recorded by security agent ({agent_id})."
        agent_rem = log_data.get("finding_remediation") or "Apply input validation, parameterized queries, and least privilege controls."

        findings_data.insert(0, {
            "title": agent_title,
            "severity": agent_sev,
            "category": agent_cat,
            "evidence": agent_ev,
            "description": agent_desc,
            "remediation": agent_rem
        })
        if agent_flag:
            flag_status = agent_flag
        else:
            flag_status = "CONFIRMED" if agent_sev in ["HIGH", "CRITICAL"] else "POTENTIAL"
    elif agent_flag:
        flag_status = agent_flag

    # Deduplicate findings by title, preserving highest priority / agent reported entry
    deduped_findings = []
    seen_titles = set()
    for f in findings_data:
        t_key = f["title"].strip().lower()
        if t_key not in seen_titles:
            seen_titles.add(t_key)
            deduped_findings.append(f)
    findings_data = deduped_findings

    # Prevent dummy loopback traffic/tools from polluting findings in named target projects (e.g. lottechem)
    clean_host = (log_entry.host or "").lower().split(":")[0]
    is_loopback_host = clean_host in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    if is_loopback_host and project_name not in ["default", "local", "lab", "test", "dev"]:
        proj_obj = db.query(Project).filter(Project.name == project_name).first()
        proj_scope = proj_obj.to_dict().get("allowed_hosts", ["*"]) if proj_obj else ["*"]
        if proj_scope != ["*"] and not any(h in ["localhost", "127.0.0.1", "0.0.0.0"] for h in proj_scope):
            findings_data = []
            flag_status = "CLEAN"

    log_entry.flag_status = flag_status

    db.add(log_entry)
    db.flush()  # Populates log_entry.id for findings relationship without committing transaction yet

    for f in findings_data:
        finding = Finding(
            log_id=log_entry.id,
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
        vault_entry = auto_vault_payload(
            db=db,
            project=project_name,
            agent_id=agent_id,
            method=log_entry.method,
            url=log_entry.url,
            request_body=log_entry.request_body,
            response_body=log_entry.response_body,
            status_code=log_entry.status_code,
            flag_status=flag_status,
            findings=findings_data,
            reasoning=log_entry.reasoning,
            source=log_entry.source,
            http_log_id=log_entry.id,
            payload_hint=log_data.get("payload_hint")
        )
        if vault_entry:
            await ws_manager.broadcast({
                "type": "NEW_PAYLOAD",
                "project": project_name,
                "payload": vault_entry.to_dict()
            })
    except Exception:
        pass

    # Auto-ingest URL into attack surface knowledge graph
    try:
        from backend.target_manager import auto_ingest_url_to_target_graph
        auto_ingest_url_to_target_graph(project_name, log_entry.url, log_entry.method)
    except Exception:
        pass

    # Passive JavaScript Recon & Secret Mining
    try:
        from backend.js_miner import passive_mine_js_background
        passive_mine_js_background(log_entry.url, log_entry.response_body, project_name)
    except Exception:
        pass

    # Autonomous Multi-Identity BOLA/IDOR Shadow Replay
    try:
        from backend.bola_matrix import is_candidate_for_bola, execute_bola_shadow_replay
        if is_candidate_for_bola(log_entry.url, log_entry.method, log_entry.request_body):
            req_hdrs = {}
            try:
                req_hdrs = json.loads(log_entry.request_headers) if log_entry.request_headers else {}
            except Exception:
                pass
            asyncio.create_task(execute_bola_shadow_replay(
                log_id=log_entry.id,
                project=project_name,
                url=log_entry.url,
                method=log_entry.method,
                req_headers=req_hdrs,
                req_body=log_entry.request_body,
                orig_status=log_entry.status_code,
                orig_body=log_entry.response_body,
                ws_broadcast_callback=ws_manager.broadcast
            ))
    except Exception:
        pass

    # Invalidate stats cache on new log
    _invalidate_stats_cache()

    # Broadcast lightweight log entry (without multi-MB body strings) to keep WebSocket snappy
    payload = {
        "type": "NEW_LOG",
        "project": project_name,
        "log": log_entry.to_dict(include_body=False),
        "alert": flag_status in ["CONFIRMED", "POTENTIAL"]
    }
    await ws_manager.broadcast(payload)
    return log_entry


# ==============================================================================
# WebSocket Endpoint
# ==============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    client_host = websocket.client.host if websocket.client else "unknown"
    if not PROXSYNTH_ALLOW_REMOTE:
        is_local_client = client_host in ["127.0.0.1", "localhost", "::1", "testclient"]
        if not is_local_client:
            try:
                ip_addr = ipaddress.ip_address(client_host)
                if ip_addr in ipaddress.ip_network("172.16.0.0/12") or ip_addr.is_loopback:
                    is_local_client = True
            except ValueError:
                pass
        if not is_local_client:
            await websocket.close(code=1008)  # Policy violation
            return

    effective_api_key = PROXSYNTH_API_KEY or PROXSYNTH_API_KEY
    if effective_api_key:
        api_key = (
            websocket.query_params.get("api_key") or
            websocket.headers.get("x-proxsynth-key") or
            websocket.headers.get("x-proxynth-key") or
            ""
        )
        if not secrets.compare_digest(api_key, effective_api_key):
            await websocket.close(code=1008)
            return

    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "CONNECTED", "server": "PROXSYNTH_MCP_V2", "alias": "PROXSYNTH_MCP_V1"})
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ==============================================================================
# Project Management & Scope Guardrails Endpoints
# ==============================================================================

@app.get("/api/projects")
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.id).all()
    results = []
    for p in projects:
        req_count = db.query(func.count(HttpLog.id)).filter(HttpLog.project == p.name).scalar() or 0
        confirmed_count = db.query(func.count(Finding.id)).join(HttpLog).filter(
            HttpLog.project == p.name,
            Finding.severity.in_(["HIGH", "CRITICAL"])
        ).scalar() or 0
        potential_count = db.query(func.count(Finding.id)).join(HttpLog).filter(
            HttpLog.project == p.name,
            Finding.severity.in_(["LOW", "MEDIUM", "INFO"])
        ).scalar() or 0

        p_dict = p.to_dict()
        p_dict["requests_count"] = req_count
        p_dict["confirmed_count"] = confirmed_count
        p_dict["potential_count"] = potential_count
        results.append(p_dict)
    return {"projects": results}


@app.post("/api/projects")
async def create_project(data: CreateProjectRequest, db: Session = Depends(get_db)):
    clean_name = data.name.strip().lower()
    if not clean_name:
        raise HTTPException(status_code=400, detail="Project name cannot be empty")
    
    existing = db.query(Project).filter(Project.name == clean_name).first()
    if existing:
        return existing.to_dict()

    new_p = Project(
        name=clean_name,
        description=data.description or "",
        scope_enabled=False,
        allowed_hosts=json.dumps(["*"]),
        blocked_patterns=json.dumps([]),
        allow_internal_networks=True,
        verify_ssl=False
    )
    db.add(new_p)
    db.commit()
    db.refresh(new_p)

    await ws_manager.broadcast({"type": "PROJECT_CREATED", "project": new_p.to_dict()})
    return new_p.to_dict()


@app.delete("/api/projects/{name}")
async def delete_project(name: str, db: Session = Depends(get_db)):
    clean_name = name.strip().lower()
    if clean_name == "default":
        raise HTTPException(status_code=400, detail="Cannot delete default project")

    proj = db.query(Project).filter(Project.name == clean_name).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")

    # Cascade delete all child findings and dependent telemetry logs
    log_ids = [l.id for l in db.query(HttpLog.id).filter(HttpLog.project == clean_name).all()]
    if log_ids:
        db.query(Finding).filter(Finding.log_id.in_(log_ids)).delete(synchronize_session=False)
        db.query(HttpLog).filter(HttpLog.project == clean_name).delete(synchronize_session=False)

    db.query(ActiveSession).filter(ActiveSession.project == clean_name).delete(synchronize_session=False)
    db.query(CapturedPayload).filter(CapturedPayload.project == clean_name).delete(synchronize_session=False)
    db.query(AgentCommandLog).filter(AgentCommandLog.project == clean_name).delete(synchronize_session=False)
    db.query(OastEvent).filter(OastEvent.project == clean_name).delete(synchronize_session=False)

    # Clean up target graph assets
    asset_ids = [a.id for a in db.query(TargetAsset.id).filter(TargetAsset.project == clean_name).all()]
    if asset_ids:
        db.query(TargetService).filter(TargetService.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(TargetEndpoint).filter(TargetEndpoint.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(TargetAsset).filter(TargetAsset.project == clean_name).delete(synchronize_session=False)

    db.delete(proj)
    db.commit()

    await ws_manager.broadcast({"type": "PROJECT_DELETED", "name": clean_name})
    return {"status": "deleted", "name": clean_name}


@app.get("/api/projects/{name}/scope")
def get_project_scope(name: str, db: Session = Depends(get_db)):
    proj = db.query(Project).filter(Project.name == name.lower()).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    return proj.to_dict()


@app.put("/api/projects/{name}/scope")
async def update_project_scope(name: str, req: UpdateScopeRequest, db: Session = Depends(get_db)):
    proj = db.query(Project).filter(Project.name == name.lower()).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")

    proj.scope_enabled = req.scope_enabled
    proj.allowed_hosts = json.dumps(req.allowed_hosts)
    proj.blocked_patterns = json.dumps(req.blocked_patterns)
    if req.allow_internal_networks is not None:
        proj.allow_internal_networks = req.allow_internal_networks
    if req.verify_ssl is not None:
        proj.verify_ssl = req.verify_ssl
    if req.delay_ms is not None:
        proj.delay_ms = max(0, req.delay_ms)
    if req.upstream_proxy is not None:
        proj.upstream_proxy = req.upstream_proxy.strip()
    db.commit()
    db.refresh(proj)
    invalidate_scope_cache(name)

    await ws_manager.broadcast({"type": "SCOPE_UPDATED", "project": proj.to_dict()})
    return proj.to_dict()


@app.get("/api/proxy/status")
def get_forward_proxy_status():
    """Returns the running status and port of the Proxsynth Forward Proxy."""
    from backend.forward_proxy import is_proxy_running, get_proxy_port, get_proxy_url
    return {
        "running": is_proxy_running(),
        "port": get_proxy_port(),
        "url": get_proxy_url()
    }


# ==============================================================================
# Proxy Trap (Interactive Breakpoint / Intercept) Endpoints
# ==============================================================================

@app.get("/api/intercept/status")
def get_intercept_info():
    """Returns current intercept mode and any requests waiting in the trap."""
    return get_intercept_status()


@app.post("/api/intercept/toggle")
async def toggle_intercept(req: InterceptToggleRequest):
    """Enable or disable interactive intercept proxy trap."""
    new_state = set_intercept_mode(req.enabled)
    await ws_manager.broadcast({"type": "INTERCEPT_TOGGLED", "enabled": new_state})
    return {"enabled": new_state}


@app.post("/api/intercept/broadcast-trap")
async def broadcast_intercept_trap_endpoint(data: Dict[str, Any]):
    """Broadcasts a newly trapped proxy request to active frontend WebSocket listeners."""
    await ws_manager.broadcast({
        "type": "INTERCEPT_TRAPPED",
        "intercept_id": data.get("id")
    })
    return {"status": "broadcasted"}


@app.post("/api/intercept/{intercept_id}/action")
async def handle_intercept_decision(intercept_id: str, req: InterceptActionRequest):
    """Releases a trapped request by either forwarding (original/modified) or dropping."""
    success = resolve_intercept_trap(intercept_id, req.action, req.modified_data)
    if not success:
        raise HTTPException(status_code=404, detail="Intercept ID not found or already released")
    
    await ws_manager.broadcast({"type": "INTERCEPT_RESOLVED", "intercept_id": intercept_id, "action": req.action})
    return {"status": "resolved", "intercept_id": intercept_id, "action": req.action}


_repeater_clients: Dict[str, Any] = {}

async def _get_repeater_client(proxy_cfg: str = "", verify_ssl: bool = False):
    import httpx
    verify_env = os.getenv("PROXSYNTH_VERIFY_SSL", "false").lower() == "true"
    final_verify = verify_ssl or verify_env
    key = f"{proxy_cfg.strip() if proxy_cfg else 'direct'}_{final_verify}"
    if key not in _repeater_clients or _repeater_clients[key].is_closed:
        kwargs = {
            "verify": final_verify,
            "follow_redirects": True,
            "timeout": 30.0,
            "limits": httpx.Limits(max_keepalive_connections=20, max_connections=50, keepalive_expiry=60.0)
        }
        if proxy_cfg and proxy_cfg.strip():
            kwargs["proxy"] = proxy_cfg.strip()
        _repeater_clients[key] = httpx.AsyncClient(**kwargs)
    return _repeater_clients[key]

# ==============================================================================
# Repeater Replay Endpoint
# ==============================================================================

@app.post("/api/repeater/send")
async def repeater_send_request(req: RepeaterSendRequest, db: Session = Depends(get_db)):
    """Executes a request manually via Repeater, saves to DB, triages, and returns full response."""
    import urllib.parse

    # 1. Scope check (Non-blocking async DNS resolution with TTL cache)
    is_allowed, block_reason = await async_check_scope(req.project, req.url, db)
    if not is_allowed:
        raise HTTPException(status_code=403, detail=block_reason)

    # 2. Upstream proxy & TLS verification lookup
    proj = db.query(Project).filter(Project.name == req.project.lower()).first()
    proxy_cfg = proj.upstream_proxy if proj and proj.upstream_proxy else os.getenv("PROXSYNTH_UPSTREAM_PROXY")
    verify_ssl = bool(proj.verify_ssl) if proj else False

    parsed = urllib.parse.urlparse(req.url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    start_time = time.time()
    status_code = 502
    res_headers = {}
    res_body = ""

    # Ensure valid headers dict and legitimate rotating browser User-Agent
    from backend.user_agents import apply_rotating_user_agent
    req_headers = {str(k): str(v) for k, v in (req.headers or {}).items()}
    apply_rotating_user_agent(req_headers)

    try:
        client = await _get_repeater_client(proxy_cfg or "", verify_ssl=verify_ssl)
        content_bytes = req.body.encode("utf-8") if req.body else None
        response = await client.request(
            method=req.method.upper(),
            url=req.url,
            headers=req_headers,
            content=content_bytes
        )
        status_code = response.status_code
        res_headers = dict(response.headers)
        try:
            res_body = response.text[:5242880]
        except Exception:
            res_body = f"<Binary data: {len(response.content)} bytes>"
    except Exception as ex:
        status_code = 502
        res_body = f"Transport Error: {str(ex)}"

    duration_ms = int((time.time() - start_time) * 1000)

    log_payload = {
        "project": req.project,
        "agent_id": "operator_repeater",
        "source": "REPEATER",
        "method": req.method.upper(),
        "url": req.url,
        "host": host,
        "path": path,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "request_headers": req_headers,
        "request_body": req.body or "",
        "response_headers": res_headers,
        "response_body": res_body,
        "reasoning": "Manual operator Repeater replay"
    }

    log_entry = await record_and_broadcast_log(log_payload, db)
    return log_entry.to_dict(include_body=True)


# ==============================================================================
# Reporting & OpenAPI / HAR 1.2 Export Endpoints
# ==============================================================================

@app.get("/api/projects/{name}/export/har")
def export_har(name: str, db: Session = Depends(get_db)):
    """Exports project traffic into standard HTTP Archive (HAR 1.2) for Burp/ZAP."""
    har_data = generate_har_export(name, db)
    safe_filename = sanitize_attachment_filename(f"proxynth_{name}_traffic", "har")
    return JSONResponse(
        content=har_data,
        headers={"Content-Disposition": f"attachment; filename={safe_filename}"}
    )


@app.get("/api/projects/{name}/export/report")
def export_markdown_report(name: str, db: Session = Depends(get_db)):
    """Exports vulnerability findings into an executive Markdown report."""
    md_content = generate_markdown_report(name, db)
    safe_filename = sanitize_attachment_filename(f"proxynth_{name}_report", "md")
    return PlainTextResponse(
        content=md_content,
        headers={"Content-Disposition": f"attachment; filename={safe_filename}"}
    )


@app.get("/api/projects/{name}/export/openapi")
def export_openapi(name: str, db: Session = Depends(get_db)):
    """Generates and exports an OpenAPI 3.0.3 specification from observed project traffic."""
    spec_data = generate_openapi_spec(name, db)
    safe_filename = sanitize_attachment_filename(f"proxynth_{name}_openapi", "json")
    return JSONResponse(
        content=spec_data,
        headers={"Content-Disposition": f"attachment; filename={safe_filename}"}
    )


# ==============================================================================
# Parameter Fuzzer / Mini-Intruder Endpoints
# ==============================================================================

@app.get("/api/fuzzer/payloads")
def list_fuzzer_payloads():
    """Returns built-in attack dictionaries."""
    return {"categories": BUILTIN_PAYLOADS}


@app.post("/api/fuzzer/run")
async def run_fuzzer_attack_endpoint(req: RunFuzzRequest, db: Session = Depends(get_db)):
    """Executes multi-threaded parameter fuzzing with automated baseline differential analysis."""
    import re
    clean_url = re.sub(r"§[^§]*§", "", req.url)
    is_allowed, block_reason = await async_check_scope(req.project, clean_url, db)
    if not is_allowed:
        raise HTTPException(status_code=403, detail=f"Target URL is out of authorized scope: {block_reason}")

    payloads = req.custom_payloads
    if not payloads or len(payloads) == 0:
        cat = (req.category or "sqli").lower()
        payloads = BUILTIN_PAYLOADS.get(cat, BUILTIN_PAYLOADS["sqli"])

    proj = db.query(Project).filter(Project.name == req.project.lower()).first()
    proxy = proj.upstream_proxy if proj and proj.upstream_proxy else os.getenv("PROXSYNTH_UPSTREAM_PROXY")

    req_concurrency = min(max(req.concurrency, 1), 10)
    if req.custom_payloads and len(req.custom_payloads) > 1000:
        raise HTTPException(status_code=400, detail="Custom payloads list exceeds security threshold of 1,000 entries.")

    results = await run_fuzz_attack(
        base_url=req.url,
        method=req.method,
        headers=req.headers,
        body=req.body,
        payloads=payloads,
        concurrency=req_concurrency,
        upstream_proxy=proxy
    )

    await ws_manager.broadcast({
        "type": "FUZZER_COMPLETED",
        "project": req.project,
        "total": results.get("total_payloads", 0),
        "anomalies": results.get("anomalies_detected", 0)
    })
    return results


# ==============================================================================
# Session Keep-Alive / Heartbeat Endpoints
# ==============================================================================

@app.get("/api/auth/keepalive/status")
def keepalive_status_endpoint():
    """Returns operational status of the background session keeper service."""
    return get_session_keeper_status()


@app.post("/api/auth/keepalive/toggle")
async def keepalive_toggle_endpoint(enabled: bool = Query(...)):
    """Starts or stops the background session heartbeat service."""
    if enabled:
        start_session_keeper(interval=120)
    else:
        stop_session_keeper()
    return get_session_keeper_status()



# ==============================================================================
# Core Traffic & Stats Endpoints
# ==============================================================================

@app.get("/api/stats")
def get_stats(project: Optional[str] = None, db: Session = Depends(get_db)):
    cache_key = (project or "ALL").upper()
    now = time.time()
    if cache_key in _STATS_CACHE:
        cache_time, cached_data = _STATS_CACHE[cache_key]
        if now - cache_time < 1.0:  # 1-second TTL to avoid 5 SQL count queries on rapid polling
            return cached_data

    log_query = db.query(HttpLog)
    finding_query = db.query(Finding).join(HttpLog)

    if project and project.upper() != "ALL":
        log_query = log_query.filter(HttpLog.project == project.lower())
        finding_query = finding_query.filter(HttpLog.project == project.lower())

    total_requests = log_query.with_entities(func.count(HttpLog.id)).scalar() or 0
    confirmed_findings = finding_query.filter(Finding.severity.in_(["HIGH", "CRITICAL"])).with_entities(func.count(Finding.id)).scalar() or 0
    potential_findings = finding_query.filter(Finding.severity.in_(["LOW", "MEDIUM", "INFO"])).with_entities(func.count(Finding.id)).scalar() or 0
    clean_logs = log_query.filter(HttpLog.flag_status == "CLEAN").with_entities(func.count(HttpLog.id)).scalar() or 0
    
    sess_query = db.query(ActiveSession)
    cmd_query = db.query(AgentCommandLog)
    payload_query = db.query(CapturedPayload)
    if project and project.upper() != "ALL":
        sess_query = sess_query.filter(ActiveSession.project == project.lower())
        cmd_query = cmd_query.filter(AgentCommandLog.project == project.lower())
        payload_query = payload_query.filter(CapturedPayload.project == project.lower())
    active_sessions = sess_query.with_entities(func.count(ActiveSession.id)).scalar() or 0
    total_commands = cmd_query.with_entities(func.count(AgentCommandLog.id)).scalar() or 0
    total_payloads = payload_query.with_entities(func.count(CapturedPayload.id)).scalar() or 0

    res = {
        "project": project or "ALL",
        "total_requests": total_requests,
        "confirmed_findings": confirmed_findings,
        "potential_findings": potential_findings,
        "clean_logs": clean_logs,
        "active_sessions": active_sessions,
        "total_commands": total_commands,
        "total_payloads": total_payloads,
        "intercept_enabled": is_intercept_enabled(),
        "interactive_login_active": get_active_login_status()
    }
    _STATS_CACHE[cache_key] = (now, res)
    return res


@app.get("/api/logs")
@app.get("/api/history")
def list_logs(
    project: Optional[str] = None,
    agent: Optional[str] = None,
    limit: Optional[int] = Query(None, ge=1, le=2000),
    page_size: Optional[int] = Query(None, ge=1, le=2000),
    offset: Optional[int] = Query(None, ge=0),
    page: Optional[int] = Query(None, ge=1),
    search: Optional[str] = None,
    flag: Optional[str] = None,
    method: Optional[str] = None,
    db: Session = Depends(get_db)
):
    eff_limit = limit or page_size or 100
    if offset is not None:
        eff_offset = offset
    elif page is not None and page > 0:
        eff_offset = (page - 1) * eff_limit
    else:
        eff_offset = 0

    # Defer heavy body text columns so paginated listings don't load multi-megabytes into memory
    query = db.query(HttpLog).options(defer(HttpLog.request_body), defer(HttpLog.response_body))

    if project and project.upper() != "ALL":
        query = query.filter(HttpLog.project == project.lower())
    if agent and agent.upper() != "ALL":
        query = query.filter(HttpLog.agent_id == agent)
    if flag and flag.upper() != "ALL":
        query = query.filter(HttpLog.flag_status == flag.upper())
    if method and method.upper() != "ALL":
        query = query.filter(HttpLog.method == method.upper())
    else:
        query = query.filter(HttpLog.method != "CONNECT")
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (HttpLog.url.ilike(search_pattern)) |
            (HttpLog.host.ilike(search_pattern)) |
            (HttpLog.path.ilike(search_pattern))
        )

    total = query.count()
    logs = query.order_by(desc(HttpLog.id)).offset(eff_offset).limit(eff_limit).all()

    return {
        "total": total,
        "project": project or "ALL",
        "agent": agent or "ALL",
        "limit": eff_limit,
        "offset": eff_offset,
        "logs": [log.to_dict(include_body=False) for log in logs]
    }


@app.get("/api/agents")
def list_agents(project: Optional[str] = None, db: Session = Depends(get_db)):
    """Returns list of unique agent IDs active in logged operations."""
    query = db.query(HttpLog.agent_id).distinct()
    if project and project.upper() != "ALL":
        query = query.filter(HttpLog.project == project.lower())
    agents = [r[0] for r in query.all() if r[0]]
    if "primary_agent" not in agents:
        agents.insert(0, "primary_agent")
    return {"agents": agents}



@app.get("/api/logs/{log_id}")
def get_log_detail(log_id: int, db: Session = Depends(get_db)):
    log_entry = db.query(HttpLog).filter(HttpLog.id == log_id).first()
    if not log_entry:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return log_entry.to_dict(include_body=True)


@app.get("/api/findings")
def list_findings(project: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Finding).join(HttpLog)
    if project and project.upper() != "ALL":
        query = query.filter(HttpLog.project == project.lower())

    findings = query.order_by(desc(Finding.id)).all()
    results = []
    for f in findings:
        item = f.to_dict()
        if f.log:
            item["project"] = f.log.project
            item["log"] = {
                "method": f.log.method,
                "url": f.log.url,
                "status_code": f.log.status_code,
                "timestamp": f.log.timestamp.isoformat() if f.log.timestamp else ""
            }
        results.append(item)
    return {"findings": results}


@app.post("/api/findings")
async def create_finding_api(data: CreateFindingRequest, db: Session = Depends(get_db)):
    """Allows security agent to explicitly attach a verified finding to any HTTP log."""
    log_entry = db.query(HttpLog).filter(HttpLog.id == data.log_id).first()
    if not log_entry:
        raise HTTPException(status_code=404, detail=f"Log ID #{data.log_id} was not found")

    sev = (data.severity or "HIGH").strip().upper()
    title_clean = data.title.strip()

    # Deduplicate: update existing finding if same title already exists on this log
    existing_finding = db.query(Finding).filter(
        Finding.log_id == log_entry.id,
        func.lower(Finding.title) == title_clean.lower()
    ).first()

    if existing_finding:
        existing_finding.severity = sev
        existing_finding.category = (data.category or existing_finding.category).strip()
        if data.evidence:
            existing_finding.evidence = data.evidence
        if data.description:
            existing_finding.description = data.description
        if data.remediation:
            existing_finding.remediation = data.remediation
        finding = existing_finding
    else:
        finding = Finding(
            log_id=log_entry.id,
            title=title_clean,
            severity=sev,
            category=(data.category or "General").strip(),
            evidence=data.evidence or "",
            description=data.description or f"Finding explicitly recorded by security agent for Log #{log_entry.id}.",
            remediation=data.remediation or "Apply input validation, parameterized queries, and least privilege controls."
        )
        db.add(finding)

    # Upgrade log flag status
    if sev in ["HIGH", "CRITICAL"]:
        log_entry.flag_status = "CONFIRMED"
    elif sev in ["MEDIUM", "LOW", "INFO"] and log_entry.flag_status != "CONFIRMED":
        log_entry.flag_status = "POTENTIAL"

    db.commit()
    db.refresh(finding)
    _invalidate_stats_cache()

    finding_dict = finding.to_dict()
    finding_dict["project"] = log_entry.project
    finding_dict["log"] = {
        "method": log_entry.method,
        "url": log_entry.url,
        "status_code": log_entry.status_code,
        "timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else ""
    }

    await ws_manager.broadcast({
        "type": "NEW_FINDING",
        "project": log_entry.project,
        "finding": finding_dict
    })
    await ws_manager.broadcast({
        "type": "LOG_UPDATED",
        "project": log_entry.project,
        "log": log_entry.to_dict(include_body=False)
    })

    return {
        "status": "created",
        "id": finding.id,
        "log_id": log_entry.id,
        "flag_status": log_entry.flag_status,
        "finding": finding_dict
    }


@app.post("/api/logs")
async def record_log_api(data: LogRecordRequest, db: Session = Depends(get_db)):
    log_entry = await record_and_broadcast_log(data.model_dump(), db)
    findings = [
        {
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "evidence": f.evidence,
            "description": f.description,
            "remediation": f.remediation
        }
        for f in log_entry.findings
    ]
    return {
        "status": "recorded",
        "id": log_entry.id,
        "project": log_entry.project,
        "flag_status": log_entry.flag_status,
        "findings": findings
    }


@app.post("/api/logs/clear")
async def clear_logs(
    project: Optional[str] = None,
    req: Optional[ClearRequest] = None,
    db: Session = Depends(get_db)
):
    target_raw = project or (req.project if req else None)
    if target_raw and target_raw.upper() != "ALL":
        target_proj = target_raw.lower()
        log_ids = [l.id for l in db.query(HttpLog.id).filter(HttpLog.project == target_proj).all()]
        if log_ids:
            db.query(Finding).filter(Finding.log_id.in_(log_ids)).delete(synchronize_session=False)
            db.query(HttpLog).filter(HttpLog.project == target_proj).delete(synchronize_session=False)
        db.query(CapturedPayload).filter(CapturedPayload.project == target_proj).delete(synchronize_session=False)
        db.query(AgentCommandLog).filter(AgentCommandLog.project == target_proj).delete(synchronize_session=False)
        db.commit()
        _invalidate_stats_cache()
        await ws_manager.broadcast({"type": "LOGS_CLEARED", "project": target_proj})
        await ws_manager.broadcast({"type": "COMMANDS_CLEARED", "project": target_proj})
        await ws_manager.broadcast({"type": "PAYLOADS_CLEARED", "project": target_proj})
        return {"status": "cleared", "project": target_proj}
    else:
        db.query(Finding).delete()
        db.query(CapturedPayload).delete()
        db.query(AgentCommandLog).delete()
        db.query(HttpLog).delete()
        db.commit()
        _invalidate_stats_cache()
        await ws_manager.broadcast({"type": "LOGS_CLEARED", "project": "ALL"})
        await ws_manager.broadcast({"type": "COMMANDS_CLEARED", "project": "ALL"})
        await ws_manager.broadcast({"type": "PAYLOADS_CLEARED", "project": "ALL"})
        return {"status": "cleared", "project": "ALL"}


# ==============================================================================
# AI Command & Terminal Audit Trail Endpoints
# ==============================================================================

@app.get("/api/commands")
def list_commands(
    project: Optional[str] = None,
    agent: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(250, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(AgentCommandLog).options(defer(AgentCommandLog.stdout), defer(AgentCommandLog.stderr))
    if project and project.upper() != "ALL":
        query = query.filter(AgentCommandLog.project == project.lower())
    if agent and agent.upper() != "ALL":
        query = query.filter(AgentCommandLog.agent_id == agent)
    if status and status.upper() != "ALL":
        query = query.filter(AgentCommandLog.status == status.upper())
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (AgentCommandLog.command.ilike(search_pattern)) |
            (AgentCommandLog.reasoning.ilike(search_pattern))
        )
    total = query.count()
    commands = query.order_by(desc(AgentCommandLog.id)).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "commands": [c.to_dict(include_output=False) for c in commands]
    }


@app.get("/api/commands/{cmd_id}")
def get_command_detail(cmd_id: int, db: Session = Depends(get_db)):
    """Fetch complete stdout and stderr for a selected command execution."""
    entry = db.query(AgentCommandLog).filter(AgentCommandLog.id == cmd_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Command log entry not found")
    return entry.to_dict(include_output=True)


@app.post("/api/commands")
async def record_command_api(data: RecordCommandRequest, db: Session = Depends(get_db)):
    proj = (data.project or "default").strip().lower()
    entry = AgentCommandLog(
        project=proj,
        agent_id=data.agent_id or "primary_agent",
        command=data.command,
        tool_name=data.tool_name or "terminal",
        reasoning=data.reasoning or "",
        exit_code=data.exit_code,
        stdout=(data.stdout or "")[:5242880],
        stderr=(data.stderr or "")[:5242880],
        duration_ms=data.duration_ms or 0,
        status=data.status or "SUCCESS",
        linked_log_id=data.linked_log_id,
        script_content=(data.script_content or "")[:5242880]
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    cmd_dict = entry.to_dict()
    await ws_manager.broadcast({
        "type": "NEW_COMMAND",
        "project": proj,
        "command": cmd_dict
    })

    if data.script_content or data.command:
        try:
            from backend.payload_vault import auto_vault_script_payloads
            vault_items = auto_vault_script_payloads(
                db=db,
                project=proj,
                agent_id=data.agent_id or "primary_agent",
                script_content=data.script_content or "",
                command=data.command,
                cmd_log_id=entry.id
            )
            for v_item in vault_items:
                await ws_manager.broadcast({
                    "type": "NEW_PAYLOAD",
                    "project": proj,
                    "payload": v_item.to_dict()
                })
        except Exception:
            pass

    return cmd_dict


@app.post("/api/commands/execute")
async def execute_command_api(data: ExecuteCommandRequest, db: Session = Depends(get_db)):
    """
    Executes a terminal/CLI command on-demand via the AI Activity CLI Repeater.
    Runs in safe subprocess environment, binds to Proxsynth Forward Proxy (127.0.0.1:8088),
    captures full stdout/stderr, execution duration, and correlates generated HTTP traffic.
    """
    import re
    cmd_clean = data.command.strip()
    if not cmd_clean:
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    proj = (data.project or "default").strip().lower()

    # Safety Guardrail Check
    DANGEROUS_PATTERNS = [
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
    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, cmd_clean, re.IGNORECASE):
            raise HTTPException(status_code=403, detail=f"Command blocked by Proxsynth Safe-Mode guardrail: matches dangerous pattern '{pat}'")

    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    work_dir = current_dir
    if data.cwd and os.path.isdir(data.cwd):
        work_dir = os.path.abspath(data.cwd)

    proxy_port = int(os.getenv("PROXSYNTH_PROXY_PORT", "8088"))
    try:
        from backend.forward_proxy import ensure_forward_proxy_running
        await ensure_forward_proxy_running(port=proxy_port)
    except Exception:
        pass

    sub_env = os.environ.copy()
    sub_env["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
    sub_env["HTTPS_PROXY"] = f"http://127.0.0.1:{proxy_port}"
    sub_env["ALL_PROXY"] = f"http://127.0.0.1:{proxy_port}"
    sub_env["PROXSYNTH_PROJECT"] = proj
    sub_env["PYTHONPATH"] = f"{current_dir}{os.pathsep}{sub_env.get('PYTHONPATH', '')}".rstrip(os.pathsep)

    latest_log_before = db.query(func.max(HttpLog.id)).filter(HttpLog.project == proj).scalar() or 0

    t_start = time.time()
    stdout_text = ""
    stderr_text = ""
    exit_code = 0
    status = "SUCCESS"

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_clean,
            cwd=work_dir,
            env=sub_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            out_bytes, err_bytes = await asyncio.wait_for(proc.communicate(), timeout=float(data.timeout or 60))
            stdout_text = out_bytes.decode("utf-8", errors="replace")
            stderr_text = err_bytes.decode("utf-8", errors="replace")
            exit_code = proc.returncode
            status = "SUCCESS" if exit_code == 0 else "FAILED"
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            status = "TIMEOUT"
            stderr_text = f"[!] Command execution timed out after {data.timeout} seconds."
            exit_code = -1
    except Exception as ex:
        status = "FAILED"
        stderr_text = f"Execution error: {str(ex)}"
        exit_code = -1

    duration_ms = int((time.time() - t_start) * 1000)

    linked_log_id = None
    latest_log_after = db.query(func.max(HttpLog.id)).filter(HttpLog.project == proj).scalar() or 0
    if latest_log_after > latest_log_before:
        linked_log_id = latest_log_after

    entry = AgentCommandLog(
        project=proj,
        agent_id=data.agent_id or "operator",
        command=cmd_clean,
        tool_name="cli_repeater",
        reasoning=data.reasoning or "Manual reproduction via AI CLI Repeater",
        exit_code=exit_code,
        stdout=stdout_text[:5242880],
        stderr=stderr_text[:5242880],
        duration_ms=duration_ms,
        status=status,
        linked_log_id=linked_log_id,
        script_content=(data.script_content or "")[:5242880]
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    cmd_dict = entry.to_dict()
    await ws_manager.broadcast({
        "type": "NEW_COMMAND",
        "project": proj,
        "command": cmd_dict
    })

    try:
        from backend.payload_vault import auto_vault_script_payloads
        vault_items = auto_vault_script_payloads(
            db=db,
            project=proj,
            agent_id=data.agent_id or "operator",
            script_content=data.script_content or "",
            command=cmd_clean,
            cmd_log_id=entry.id
        )
        for v_item in vault_items:
            await ws_manager.broadcast({
                "type": "NEW_PAYLOAD",
                "project": proj,
                "payload": v_item.to_dict()
            })
    except Exception:
        pass

    return {
        "success": status == "SUCCESS",
        "id": entry.id,
        "command": cmd_clean,
        "project": proj,
        "exit_code": exit_code,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "duration_ms": duration_ms,
        "status": status,
        "linked_log_id": linked_log_id,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else ""
    }


@app.post("/api/commands/clear")
async def clear_commands(
    project: Optional[str] = None,
    req: Optional[ClearRequest] = None,
    db: Session = Depends(get_db)
):
    target_raw = project or (req.project if req else None)
    if target_raw and target_raw.upper() != "ALL":
        target = target_raw.lower()
        db.query(AgentCommandLog).filter(AgentCommandLog.project == target).delete(synchronize_session=False)
    else:
        target = "ALL"
        db.query(AgentCommandLog).delete(synchronize_session=False)
    db.commit()
    _invalidate_stats_cache()
    await ws_manager.broadcast({"type": "COMMANDS_CLEARED", "project": target})
    return {"status": "cleared", "project": target}


# ==============================================================================
# Captured Security Payload Vault Endpoints
# ==============================================================================

@app.get("/api/payloads")
def list_payloads(
    project: Optional[str] = None,
    agent: Optional[str] = None,
    vuln_type: Optional[str] = None,
    outcome: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(250, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(CapturedPayload)
    if project and project.upper() != "ALL":
        query = query.filter(CapturedPayload.project == project.lower())
    if agent and agent.upper() != "ALL":
        query = query.filter(CapturedPayload.agent_id == agent)
    if vuln_type and vuln_type.upper() != "ALL":
        query = query.filter(CapturedPayload.vuln_type == vuln_type.upper())
    if outcome and outcome.upper() != "ALL":
        query = query.filter(CapturedPayload.outcome == outcome.upper())
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (CapturedPayload.raw_payload.ilike(search_pattern)) |
            (CapturedPayload.target_param.ilike(search_pattern)) |
            (CapturedPayload.target_url.ilike(search_pattern)) |
            (CapturedPayload.notes.ilike(search_pattern))
        )
    total = query.count()
    payloads = query.order_by(desc(CapturedPayload.id)).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "payloads": [p.to_dict() for p in payloads]
    }


@app.post("/api/payloads")
async def record_payload_api(data: RecordPayloadRequest, db: Session = Depends(get_db)):
    proj = (data.project or "default").strip().lower()
    entry = CapturedPayload(
        project=proj,
        agent_id=data.agent_id or "primary_agent",
        vuln_type=(data.vuln_type or "CUSTOM").upper(),
        target_param=data.target_param or "",
        raw_payload=data.raw_payload,
        mutation_type=data.mutation_type or "DIRECT",
        target_url=data.target_url or "",
        http_method=(data.http_method or "GET").upper(),
        http_log_id=data.http_log_id,
        outcome=data.outcome or "TESTED",
        http_status=data.http_status,
        response_signature=data.response_signature or "",
        notes=data.notes or ""
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    p_dict = entry.to_dict()
    await ws_manager.broadcast({
        "type": "NEW_PAYLOAD",
        "project": proj,
        "payload": p_dict
    })
    return p_dict


@app.post("/api/payloads/test")
async def test_payload_api(data: TestPayloadRequest, db: Session = Depends(get_db)):
    """
    Directly fires a payload from the Payload Vault against a target URL through Proxsynth Proxy.
    Analyzes reflection, response time, status code, and flags potential vulnerabilities.
    """
    import httpx
    import urllib.parse
    target_url = data.target_url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    proj = (data.project or "default").strip().lower()
    proxy_port = int(os.getenv("PROXSYNTH_PROXY_PORT", "8088"))

    method = (data.http_method or "GET").upper()
    req_headers = data.headers or {}
    req_headers["User-Agent"] = req_headers.get("User-Agent", "Proxsynth-Payload-Tester/2.5.0")

    final_url = target_url
    req_body = None

    if data.target_param:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[data.target_param] = [data.raw_payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        final_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        if method in ("POST", "PUT", "PATCH"):
            req_body = {data.target_param: data.raw_payload}
    elif method in ("POST", "PUT", "PATCH"):
        req_body = data.raw_payload

    t0 = time.time()
    try:
        proxies = {
            "http://": f"http://127.0.0.1:{proxy_port}",
            "https://": f"http://127.0.0.1:{proxy_port}"
        }
        async with httpx.AsyncClient(proxies=proxies, verify=False, timeout=15.0) as client:
            if method == "GET":
                resp = await client.get(final_url, headers=req_headers)
            elif method == "POST":
                if isinstance(req_body, dict):
                    resp = await client.post(final_url, data=req_body, headers=req_headers)
                else:
                    resp = await client.post(final_url, content=(req_body or "").encode(), headers=req_headers)
            elif method == "PUT":
                resp = await client.put(final_url, content=(req_body or "").encode() if req_body else None, headers=req_headers)
            else:
                resp = await client.request(method, final_url, headers=req_headers)

        duration_ms = int((time.time() - t0) * 1000)
        resp_text = resp.text
        is_reflected = bool(data.raw_payload and data.raw_payload in resp_text)

        signatures = []
        lower_body = resp_text.lower()
        if any(err in lower_body for err in ["sql syntax", "mysql_fetch", "ora-01756", "sqlite3.operationalerror", "postgresql"]):
            signatures.append("SQL_ERROR_LEAK")
        if is_reflected:
            signatures.append("PAYLOAD_REFLECTED")
        if resp.status_code in (403, 406) and any(w in lower_body for w in ["cloudflare", "akamai", "waf", "blocked", "forbidden"]):
            signatures.append("WAF_BLOCKED")

        outcome = "REFLECTED" if is_reflected else ("WAF_BLOCKED" if "WAF_BLOCKED" in signatures else ("EXECUTED" if resp.status_code < 400 else "FILTERED"))

        # Save to database if record wanted
        test_entry = CapturedPayload(
            project=proj,
            agent_id="operator",
            vuln_type=(data.vuln_type or "CUSTOM").upper(),
            target_param=data.target_param or "",
            raw_payload=data.raw_payload,
            mutation_type=data.mutation_type or "REPRODUCE",
            target_url=final_url,
            http_method=method,
            outcome=outcome,
            http_status=resp.status_code,
            response_signature=",".join(signatures) if signatures else "",
            notes=f"Tested via AI Activity Payload Sandbox in {duration_ms}ms"
        )
        db.add(test_entry)
        db.commit()

        return {
            "success": True,
            "url": final_url,
            "method": method,
            "status_code": resp.status_code,
            "duration_ms": duration_ms,
            "is_reflected": is_reflected,
            "outcome": outcome,
            "signatures": signatures,
            "response_preview": resp_text[:2000],
            "headers": dict(resp.headers)
        }
    except Exception as ex:
        duration_ms = int((time.time() - t0) * 1000)
        return {
            "success": False,
            "url": final_url,
            "method": method,
            "error": str(ex),
            "duration_ms": duration_ms,
            "is_reflected": False,
            "outcome": "ERROR",
            "signatures": ["NETWORK_ERROR"],
            "response_preview": f"Connection failed: {str(ex)}",
            "headers": {}
        }



@app.post("/api/payloads/clear")
async def clear_payloads(
    project: Optional[str] = None,
    req: Optional[ClearRequest] = None,
    db: Session = Depends(get_db)
):
    target_raw = project or (req.project if req else None)
    if target_raw and target_raw.upper() != "ALL":
        target = target_raw.lower()
        db.query(CapturedPayload).filter(CapturedPayload.project == target).delete(synchronize_session=False)
    else:
        target = "ALL"
        db.query(CapturedPayload).delete(synchronize_session=False)
    db.commit()
    _invalidate_stats_cache()
    await ws_manager.broadcast({"type": "PAYLOADS_CLEARED", "project": target})
    return {"status": "cleared", "project": target}


# ==============================================================================
# Authentication & HITL Endpoints
# ==============================================================================

@app.post("/api/auth/spawn")
async def trigger_spawn_login(req: SpawnAuthRequest, background_tasks: BackgroundTasks):
    async def cookie_callback(domain: str, count: int):
        await ws_manager.broadcast({
            "type": "AUTH_COOKIES_UPDATED",
            "project": req.project,
            "domain": domain,
            "cookie_count": count
        })

    async def run_worker():
        try:
            await ws_manager.broadcast({
                "type": "AUTH_SPAWNED",
                "project": req.project,
                "login_url": req.login_url,
                "domain": req.target_domain
            })
            result = await spawn_interactive_login(
                login_url=req.login_url,
                target_domain=req.target_domain,
                project=req.project,
                browser_choice=req.browser_choice or "chrome",
                on_cookie_update=cookie_callback
            )
            await ws_manager.broadcast({
                "type": "AUTH_COMPLETED",
                "project": req.project,
                "result": result
            })
        except Exception as ex:
            await ws_manager.broadcast({
                "type": "AUTH_ERROR",
                "project": req.project,
                "error": str(ex)
            })

    background_tasks.add_task(run_worker)
    return {
        "status": "spawning",
        "project": req.project,
        "message": "Headed Chromium browser launched. Complete login on screen."
    }


@app.post("/api/auth/cookies/import")
async def import_cookies_endpoint(req: ImportCookiesRequest):
    """
    Directly imports session cookies from:
    - document.cookie string (from DevTools or JS Bookmarklet)
    - Full cURL request (-H 'Cookie: ...')
    - HTTP Request Header block (Cookie: ...)
    - JSON cookies array (from Cookie-Editor extension or Playwright)
    """
    target_input = (req.raw_cookie or req.raw_input or req.raw or "").strip()
    if not target_input:
        raise HTTPException(status_code=400, detail="Empty cookie input provided. Use 'raw_cookie', 'raw_input', or 'raw'.")

    target_domain = (req.domain or "").strip()
    if not target_domain:
        # Fallback domain inference if possible
        target_domain = "target.local"

    proj = (req.project or "default").strip().lower()
    res = import_session_cookies(
        project=proj,
        domain=target_domain,
        raw_input=target_input
    )

    await ws_manager.broadcast({
        "type": "AUTH_COMPLETED",
        "project": proj,
        "result": res
    })

    return res


@app.post("/api/auth/confirm")
async def confirm_auth_session(req: ConfirmAuthRequest):
    signaled = signal_login_confirmation(req.domain)
    return {
        "status": "signaled" if signaled else "no_active_login",
        "message": "Session capture triggered." if signaled else "No pending login session found."
    }


@app.get("/api/auth/session")
def inspect_session(project: Optional[str] = None, show_tokens: bool = False, db: Session = Depends(get_db)):
    query = db.query(ActiveSession)
    if project and project.upper() != "ALL":
        query = query.filter(ActiveSession.project == project.lower())
    sessions = query.order_by(desc(ActiveSession.updated_at)).all()
    return {"sessions": [s.to_dict(include_secrets=show_tokens) for s in sessions]}


@app.delete("/api/auth/session/id/{session_id}")
def remove_session_by_id(session_id: int, db: Session = Depends(get_db)):
    """Revokes and deletes an active session by its unique database ID."""
    deleted = db.query(ActiveSession).filter(ActiveSession.id == session_id).delete(synchronize_session=False)
    db.commit()
    if deleted == 0:
        raise HTTPException(status_code=404, detail=f"Session with ID {session_id} not found.")
    return {"status": "deleted", "id": session_id, "count": deleted}


@app.delete("/api/auth/session/{session_id:int}/cookie/{cookie_name}")
def remove_single_cookie(session_id: int, cookie_name: str, db: Session = Depends(get_db)):
    """Revokes a specific cookie key from an active session."""
    session_obj = db.query(ActiveSession).filter(ActiveSession.id == session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail=f"Session ID {session_id} not found.")
    
    state = session_obj.get_decrypted_state()
    cookies = state.get("cookies", [])
    initial_len = len(cookies)
    cookies = [c for c in cookies if c.get("name") != cookie_name]
    state["cookies"] = cookies
    session_obj.set_encrypted_state(state)
    session_obj.updated_at = datetime.now()
    db.commit()
    return {"status": "updated", "id": session_id, "removed_cookie": cookie_name, "remaining_cookies": len(cookies)}


@app.delete("/api/auth/session/{domain:path}")
def remove_session_by_domain(domain: str, db: Session = Depends(get_db)):
    """Revokes and deletes active sessions matching a target domain."""
    raw_domain = urllib.parse.unquote(domain).strip().lower()
    clean_domain = raw_domain.lstrip(".")
    deleted = db.query(ActiveSession).filter(
        or_(
            ActiveSession.domain == raw_domain,
            ActiveSession.domain == clean_domain,
            ActiveSession.domain == f".{clean_domain}",
            ActiveSession.domain.ilike(f"%{clean_domain}%")
        )
    ).delete(synchronize_session=False)
    db.commit()
    return {"status": "deleted", "domain": raw_domain, "count": deleted}


@app.post("/api/auth/session/clear")
def clear_all_sessions(project: Optional[str] = None, db: Session = Depends(get_db)):
    """Clears all stored active sessions."""
    query = db.query(ActiveSession)
    if project and project.upper() != "ALL":
        query = query.filter(ActiveSession.project == project.lower())
    count = query.delete(synchronize_session=False)
    db.commit()
    return {"status": "cleared", "count": count, "project": project or "ALL"}


# ==============================================================================
# Target Knowledge Graph & Attack Surface Endpoints
# ==============================================================================

class CreateTargetAssetRequest(BaseModel):
    project: str = "default"
    host: str
    ip: Optional[str] = ""
    os_info: Optional[str] = ""
    tags: Optional[List[str]] = []
    notes: Optional[str] = ""


class CreateTargetServiceRequest(BaseModel):
    project: str = "default"
    host: str
    port: int
    protocol: Optional[str] = "tcp"
    service_name: Optional[str] = "unknown"
    banner: Optional[str] = ""
    state: Optional[str] = "open"


class CreateTargetEndpointRequest(BaseModel):
    project: str = "default"
    host: str
    url: str
    method: Optional[str] = "GET"
    parameters: Optional[List[str]] = []
    auth_required: Optional[bool] = False
    tested_status: Optional[str] = "UNTESTED"
    notes: Optional[str] = ""


class UpdateEndpointStatusRequest(BaseModel):
    tested_status: str
    notes: Optional[str] = None


@app.get("/api/targets/graph")
def get_targets_graph_endpoint(project: str = "default", host: Optional[str] = None):
    """Returns the attack surface graph topology for a project."""
    from backend.target_manager import get_attack_surface_graph
    return get_attack_surface_graph(project=project, host=host)


@app.post("/api/targets/assets")
def create_target_asset_endpoint(req: CreateTargetAssetRequest):
    """Upserts a target asset in the attack surface graph."""
    from backend.target_manager import upsert_target_asset
    return upsert_target_asset(
        project=req.project,
        host=req.host,
        ip=req.ip or "",
        os_info=req.os_info or "",
        tags=req.tags,
        notes=req.notes or ""
    )


@app.post("/api/targets/services")
def create_target_service_endpoint(req: CreateTargetServiceRequest):
    """Records an open port or network service under a target asset."""
    from backend.target_manager import add_or_update_service
    return add_or_update_service(
        project=req.project,
        host=req.host,
        port=req.port,
        protocol=req.protocol or "tcp",
        service_name=req.service_name or "unknown",
        banner=req.banner or "",
        state=req.state or "open"
    )


@app.post("/api/targets/endpoints")
def create_target_endpoint_endpoint(req: CreateTargetEndpointRequest):
    """Records a web API route/endpoint under a target asset."""
    from backend.target_manager import add_or_update_endpoint
    return add_or_update_endpoint(
        project=req.project,
        host=req.host,
        url=req.url,
        method=req.method or "GET",
        parameters=req.parameters,
        auth_required=bool(req.auth_required),
        tested_status=req.tested_status or "UNTESTED",
        notes=req.notes or ""
    )


@app.delete("/api/targets/assets/{asset_id}")
def delete_target_asset_endpoint(asset_id: int, project: Optional[str] = None):
    """Deletes an asset and all its cascading services/endpoints."""
    from backend.target_manager import delete_target_asset
    success = delete_target_asset(asset_id, project)
    if not success:
        raise HTTPException(status_code=404, detail=f"Asset ID #{asset_id} not found.")
    return {"status": "deleted", "id": asset_id}


@app.patch("/api/targets/endpoints/{endpoint_id}")
def update_target_endpoint_status(endpoint_id: int, req: UpdateEndpointStatusRequest, db: Session = Depends(get_db)):
    """Updates testing progress status for a specific endpoint."""
    ep = db.query(TargetEndpoint).filter(TargetEndpoint.id == endpoint_id).first()
    if not ep:
        raise HTTPException(status_code=404, detail=f"Endpoint ID #{endpoint_id} not found.")
    ep.tested_status = req.tested_status.upper()
    if req.notes is not None:
        ep.notes = req.notes
    db.commit()
    db.refresh(ep)
    return ep.to_dict()


@app.delete("/api/targets/endpoints/{endpoint_id}")
def delete_target_endpoint_route(endpoint_id: int, project: Optional[str] = None):
    """Deletes a specific endpoint from the attack surface."""
    from backend.target_manager import delete_target_endpoint
    success = delete_target_endpoint(endpoint_id, project)
    if not success:
        raise HTTPException(status_code=404, detail=f"Endpoint ID #{endpoint_id} not found.")
    return {"status": "deleted", "id": endpoint_id}


@app.delete("/api/targets/services/{service_id}")
def delete_target_service_route(service_id: int, project: Optional[str] = None):
    """Deletes a specific service/port from the attack surface."""
    from backend.target_manager import delete_target_service
    success = delete_target_service(service_id, project)
    if not success:
        raise HTTPException(status_code=404, detail=f"Service ID #{service_id} not found.")
    return {"status": "deleted", "id": service_id}


@app.delete("/api/targets/graph")
def clear_target_graph_endpoint(project: str = "default", db: Session = Depends(get_db)):
    """Clears target assets, services, and endpoints for a project."""
    target_project = (project or "default").strip().lower()
    q = db.query(TargetAsset)
    if target_project != "all":
        q = q.filter(TargetAsset.project == target_project)
    assets = q.all()
    count = len(assets)
    for a in assets:
        db.delete(a)
    db.commit()
    return {"status": "cleared", "deleted_assets": count}


# ==============================================================================
# OAST (Out-of-Band Application Security Testing) Endpoints
# ==============================================================================

class GenerateOastRequest(BaseModel):
    project: str = "default"
    description: Optional[str] = ""
    vuln_type: Optional[str] = "BLIND_CALLBACK"
    provider: Optional[str] = "auto"


@app.api_route("/oast/{token}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"], operation_id="handle_oast_callback_root", include_in_schema=False)
@app.api_route("/oast/{token}/{subpath:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"], operation_id="handle_oast_callback_subpath", include_in_schema=False)
async def handle_oast_callback(token: str, request: Request, subpath: str = ""):
    """Catches out-of-band HTTP/S callbacks from target servers triggered by blind exploits."""
    from backend.oast_engine import record_oast_hit
    client_ip = request.client.host if request.client else "unknown"
    headers = dict(request.headers)
    query_params = dict(request.query_params)
    try:
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_text = ""

    path = f"/oast/{token}" + (f"/{subpath}" if subpath else "")
    hit_event = record_oast_hit(
        token=token,
        client_ip=client_ip,
        method=request.method,
        path=path,
        headers=headers,
        query_params=query_params,
        body=body_text,
        protocol="HTTP",
        project="default",
        description=f"Out-of-band {request.method} callback captured"
    )

    if hit_event:
        await ws_manager.broadcast({
            "type": "OAST_HIT",
            "event": hit_event,
            "alert": True
        })

    return JSONResponse({
        "status": "captured",
        "token": token,
        "method": request.method,
        "client_ip": client_ip,
        "timestamp": datetime.now().isoformat()
    })


@app.get("/api/oast/events")
def get_oast_events_endpoint(project: str = "default", limit: int = 50):
    """Returns recent out-of-band interactions captured by the OAST engine."""
    from backend.oast_engine import list_recent_oast_events
    return {"events": list_recent_oast_events(project=project, limit=limit)}


@app.post("/api/oast/generate")
def generate_oast_token_endpoint(req: GenerateOastRequest):
    """Generates a new OAST token and callback payload URLs for the agent."""
    from backend.oast_engine import generate_oast_token
    return generate_oast_token(
        project=req.project,
        description=req.description or "",
        vuln_type=req.vuln_type or "BLIND_CALLBACK",
        provider=req.provider or "auto"
    )


@app.delete("/api/oast/events")
def clear_oast_events_endpoint(project: Optional[str] = None, db: Session = Depends(get_db)):
    """Clears captured OAST interaction logs."""
    q = db.query(OastEvent)
    if project and project.upper() != "ALL":
        q = q.filter(OastEvent.project == project.lower())
    deleted = q.delete(synchronize_session=False)
    db.commit()
    return {"status": "cleared", "deleted_count": deleted}


class OastConfigRequest(BaseModel):
    callback_url: str


@app.get("/api/oast/config")
def get_oast_config_endpoint():
    """Returns the current base URL used for generating OAST callback URLs."""
    from backend.oast_engine import get_base_callback_url
    return {"callback_url": get_base_callback_url()}


@app.post("/api/oast/config")
def update_oast_config_endpoint(req: OastConfigRequest):
    """Dynamically updates the base URL for OAST callbacks (e.g. ngrok tunnel or external VPS IP)."""
    from backend.oast_engine import set_base_callback_url, get_base_callback_url
    set_base_callback_url(req.callback_url)
    return {"status": "updated", "callback_url": get_base_callback_url()}


# ==============================================================================
# Advanced Offensive Capabilities Endpoints (BOLA, OAST, WAF, Attack Path, PoC, WS)
# ==============================================================================

class SetIdentityRequest(BaseModel):
    project: str = "default"
    domain: str
    identity_role: str = "attacker"
    cookies: Optional[List[Dict[str, Any]]] = None
    raw_cookie_str: Optional[str] = None


@app.get("/api/identities")
def get_identities_endpoint(project: str = "default", domain: Optional[str] = None):
    """Retrieves all registered multi-identity sessions for a project."""
    from backend.bola_matrix import get_identities_for_project
    return {"identities": get_identities_for_project(project=project, domain=domain)}


@app.post("/api/identities")
def set_identity_endpoint(req: SetIdentityRequest):
    """Stores a secondary or role-based identity session (e.g. Attacker, Victim, Admin)."""
    from backend.bola_matrix import set_identity_session
    return set_identity_session(
        project=req.project,
        domain=req.domain,
        identity_role=req.identity_role,
        cookies=req.cookies,
        raw_cookie_str=req.raw_cookie_str
    )


@app.post("/api/bola/test/{log_id}")
async def trigger_bola_test_endpoint(log_id: int):
    """Manually executes BOLA shadow replay on a specific logged endpoint."""
    from backend.database import SessionLocal, HttpLog
    from backend.bola_matrix import execute_bola_shadow_replay
    db = SessionLocal()
    try:
        log = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if not log:
            raise HTTPException(status_code=404, detail="Log entry not found")
        req_hdrs = json.loads(log.request_headers) if log.request_headers else {}
        finding = await execute_bola_shadow_replay(
            log_id=log.id,
            project=log.project,
            url=log.url,
            method=log.method,
            req_headers=req_hdrs,
            req_body=log.request_body,
            orig_status=log.status_code,
            orig_body=log.response_body,
            ws_broadcast_callback=ws_manager.broadcast
        )
        return {"status": "tested", "finding": finding}
    finally:
        db.close()


class WafAnalyzeRequest(BaseModel):
    status_code: int
    headers: Dict[str, Any] = {}
    body: str = ""


@app.post("/api/waf/analyze")
def analyze_waf_endpoint(req: WafAnalyzeRequest):
    """Fingerprints active WAF vendor signatures and returns evasion recommendations."""
    from backend.waf_mutator import analyze_waf_response
    return analyze_waf_response(status_code=req.status_code, headers=req.headers, body=req.body)


class WafMutateRequest(BaseModel):
    raw_payload: str
    vuln_type: str = "SQLI"
    strategy: str = "ALL"


@app.post("/api/waf/mutate")
def mutate_payload_endpoint(req: WafMutateRequest):
    """Generates evasive, obfuscated variations of an exploit payload."""
    from backend.waf_mutator import mutate_payload
    return mutate_payload(raw_payload=req.raw_payload, vuln_type=req.vuln_type, strategy=req.strategy)


@app.get("/api/attack-path")
def get_attack_path_endpoint(project: str = "default"):
    """Returns synthesized exploit kill chains and Mermaid diagram."""
    from backend.attack_path import build_attack_path_graph
    return build_attack_path_graph(project=project)


class InferEndpointsRequest(BaseModel):
    host: str
    project: str = "default"
    auto_register: bool = True


@app.post("/api/attack-surface/infer")
def infer_endpoints_endpoint(req: InferEndpointsRequest):
    """Predicts hidden, untested endpoints from observed REST architectural patterns."""
    from backend.api_spec_inferrer import infer_endpoints_from_observed
    return infer_endpoints_from_observed(
        host=req.host,
        project=req.project,
        auto_register_to_graph=req.auto_register
    )


@app.get("/api/findings/{finding_id}/dossier")
def get_finding_dossier_endpoint(finding_id: int):
    """Generates standalone Python exploit script, curl command, and CVSS/CWE remediation dossier."""
    from backend.poc_generator import generate_finding_dossier
    dossier = generate_finding_dossier(finding_id=finding_id)
    if not dossier:
        raise HTTPException(status_code=404, detail="Finding not found")
    return dossier


@app.get("/api/ws-frames")
def get_ws_frames_endpoint(project: str = "default", url: Optional[str] = None, limit: int = 50):
    """Retrieves logged WebSocket frames."""
    from backend.ws_manager import list_ws_frames
    return {"frames": list_ws_frames(project=project, url=url, limit=limit)}


class SendWsRequest(BaseModel):
    url: str
    message: str
    headers: Optional[Dict[str, str]] = None
    timeout: float = 5.0
    project: str = "default"


@app.post("/api/ws-send")
async def send_ws_message_endpoint(req: SendWsRequest):
    """Sends a WebSocket message frame to a target socket endpoint."""
    from backend.ws_manager import send_ws_message
    return await send_ws_message(
        url=req.url,
        message=req.message,
        headers=req.headers,
        timeout=req.timeout,
        project=req.project
    )


@app.get("/api/oast/protocols/status")
def get_oast_protocols_status_endpoint():
    """Returns operational status of all OAST protocol listeners (HTTP, DNS, LDAP)."""
    from backend.dns_server import get_dns_server_status
    from backend.ldap_server import get_ldap_server_status
    from backend.oast_engine import get_base_callback_url
    return {
        "http_callback_url": get_base_callback_url(),
        "dns": get_dns_server_status(),
        "ldap": get_ldap_server_status()
    }


# ==============================================================================
# Advanced Manual-Grade Offensive Testing API Endpoints
# ==============================================================================

class WorkflowRunRequest(BaseModel):
    sequence: List[Dict[str, Any]]
    initial_context: Optional[Dict[str, Any]] = None
    test_step_skipping: bool = False
    project: str = "default"
    agent_id: str = "primary_agent"


@app.post("/api/workflow/run")
async def run_workflow_endpoint(req: WorkflowRunRequest, db: Session = Depends(get_db)):
    """Executes stateful multi-step workflow sequence with dynamic token chaining."""
    from backend.workflow_engine import execute_workflow
    proj = req.project.strip().lower()
    proj_obj = db.query(Project).filter(Project.name == proj).first()
    upstream_proxy = proj_obj.upstream_proxy if proj_obj else None
    return await execute_workflow(
        sequence=req.sequence,
        initial_context=req.initial_context or {},
        project=proj,
        agent_id=req.agent_id,
        test_step_skipping=req.test_step_skipping,
        upstream_proxy=upstream_proxy
    )


class RaceRunRequest(BaseModel):
    url: str
    method: str = "POST"
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = ""
    concurrency: int = 20
    project: str = "default"


@app.post("/api/race/run")
async def run_race_endpoint(req: RaceRunRequest, db: Session = Depends(get_db)):
    """Executes microsecond-synchronized concurrent burst testing."""
    from backend.race_engine import run_race_attack
    proj = req.project.strip().lower()
    is_allowed, block_reason = await async_check_scope(proj, req.url, db)
    if not is_allowed:
        raise HTTPException(status_code=403, detail=f"Target URL is outside authorized scope: {block_reason}")
    proj_obj = db.query(Project).filter(Project.name == proj).first()
    upstream_proxy = proj_obj.upstream_proxy if proj_obj else None
    return await run_race_attack(
        url=req.url,
        method=req.method,
        headers=req.headers,
        body=req.body,
        concurrency=req.concurrency,
        upstream_proxy=upstream_proxy,
        project=proj
    )


class JsMinerRequest(BaseModel):
    content_or_url: str
    base_url: Optional[str] = None
    auto_register: bool = True
    project: str = "default"


@app.post("/api/js-miner/mine")
async def mine_js_endpoint(req: JsMinerRequest, db: Session = Depends(get_db)):
    """Extracts endpoints, parameters, source maps, and credentials from JavaScript."""
    from backend.js_miner import mine_javascript
    proj = req.project.strip().lower()
    proj_obj = db.query(Project).filter(Project.name == proj).first()
    upstream_proxy = proj_obj.upstream_proxy if proj_obj else None
    return await mine_javascript(
        content_or_url=req.content_or_url,
        base_url=req.base_url,
        auto_register=req.auto_register,
        project=proj,
        upstream_proxy=upstream_proxy
    )


class DiffCompareRequest(BaseModel):
    response_a: Any
    response_b: Any
    max_diff_lines: int = 50


@app.post("/api/diff/compare")
def compare_diff_endpoint(req: DiffCompareRequest, db: Session = Depends(get_db)):
    """Computes semantic structural diff with dynamic token stripping and soft-403/404 heuristics."""
    from backend.diff_engine import compute_semantic_diff

    def _resolve(resp_input: Any) -> Dict[str, Any]:
        if isinstance(resp_input, (int, str)) and str(resp_input).isdigit():
            log_id = int(resp_input)
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
            return {"status_code": 0, "body": f"[Log #{log_id} not found]", "headers": {}}
        elif isinstance(resp_input, dict):
            return resp_input
        return {"status_code": 200, "body": str(resp_input), "headers": {}}

    res_a = _resolve(req.response_a)
    res_b = _resolve(req.response_b)
    return compute_semantic_diff(res_a, res_b, max_diff_lines=req.max_diff_lines)


class JwtAuditRequest(BaseModel):
    token: str
    test_url: Optional[str] = None
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    claims_override: Optional[Dict[str, Any]] = None
    project: str = "default"


@app.post("/api/jwt/audit")
async def audit_jwt_endpoint(req: JwtAuditRequest, db: Session = Depends(get_db)):
    """Audits JWT for alg: none, weak secret cracking, claim tampering, and live replay bypasses."""
    from backend.jwt_tester import audit_jwt_security as run_jwt_audit
    proj = req.project.strip().lower()
    if req.test_url:
        is_allowed, block_reason = await async_check_scope(proj, req.test_url, db)
        if not is_allowed:
            raise HTTPException(status_code=403, detail=f"Target URL is outside authorized scope: {block_reason}")
    proj_obj = db.query(Project).filter(Project.name == proj).first()
    upstream_proxy = proj_obj.upstream_proxy if proj_obj else None
    return await run_jwt_audit(
        token=req.token,
        test_url=req.test_url,
        method=req.method,
        headers=req.headers,
        claims_override=req.claims_override,
        upstream_proxy=upstream_proxy,
        project=proj
    )


# ==============================================================================
# P1-P4: Advanced AI Agent Capabilities (Distiller, OAST Sprayer, Hypotheses, DOM Oracle)
# ==============================================================================

class DistillBodyRequest(BaseModel):
    body: str
    content_type: Optional[str] = "text/html"
    max_length: Optional[int] = 4000
    reflected_query: Optional[str] = None


@app.post("/api/distiller/distill")
def distill_body_endpoint(req: DistillBodyRequest):
    """P1: Distills large HTML/JSON into concise security summary saving LLM tokens."""
    from backend.body_distiller import distill_response_body
    return distill_response_body(
        body=req.body,
        content_type=req.content_type or "text/html",
        max_length=req.max_length or 4000,
        reflected_query=req.reflected_query
    )


class OastSprayRequest(BaseModel):
    target_url: str
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = ""
    target_params: Optional[List[str]] = None
    vuln_types: Optional[List[str]] = None
    project: Optional[str] = "default"
    agent_id: Optional[str] = "primary_agent"


@app.post("/api/oast/spray")
async def oast_spray_endpoint(req: OastSprayRequest, db: Session = Depends(get_db)):
    """P2: Sprays multi-protocol OAST canaries across target parameters."""
    from backend.oast_sprayer import spray_oast_canaries
    proj = (req.project or "default").strip().lower()
    is_allowed, block_reason = await async_check_scope(proj, req.target_url, db)
    if not is_allowed:
        raise HTTPException(status_code=403, detail=f"Target URL is outside authorized scope: {block_reason}")
    proj_obj = db.query(Project).filter(Project.name == proj).first()
    upstream_proxy = proj_obj.upstream_proxy if proj_obj else None
    return await spray_oast_canaries(
        target_url=req.target_url,
        method=req.method or "GET",
        headers=req.headers,
        body=req.body or "",
        target_params=req.target_params,
        vuln_types=req.vuln_types,
        project=proj,
        agent_id=req.agent_id or "primary_agent",
        upstream_proxy=upstream_proxy
    )


class CreateHypothesisRequest(BaseModel):
    project: Optional[str] = "default"
    target: str
    vuln_type: Optional[str] = "GENERAL"
    hypothesis: str
    status: Optional[str] = "PLANNED"
    evidence_notes: Optional[str] = ""
    agent_id: Optional[str] = "primary_agent"
    linked_log_id: Optional[int] = None


class UpdateHypothesisRequest(BaseModel):
    status: Optional[str] = None
    evidence_notes: Optional[str] = None


@app.get("/api/hypotheses")
def list_hypotheses_endpoint(project: str = "default", status: Optional[str] = None, target: Optional[str] = None):
    """P3: Lists registered attack hypotheses."""
    from backend.hypothesis_manager import list_hypotheses
    return {"hypotheses": list_hypotheses(project=project, status=status, target=target)}


@app.get("/api/hypotheses/agenda")
def get_hypothesis_agenda_endpoint(project: str = "default"):
    """P3: Returns active testing agenda of unverified hypotheses."""
    from backend.hypothesis_manager import get_testing_agenda
    return get_testing_agenda(project=project)


@app.post("/api/hypotheses")
async def create_hypothesis_endpoint(req: CreateHypothesisRequest):
    """P3: Records an attack hypothesis into agent working memory."""
    from backend.hypothesis_manager import create_hypothesis
    res = create_hypothesis(
        project=req.project or "default",
        target=req.target,
        vuln_type=req.vuln_type or "GENERAL",
        hypothesis=req.hypothesis,
        status=req.status or "PLANNED",
        evidence_notes=req.evidence_notes or "",
        agent_id=req.agent_id or "primary_agent",
        linked_log_id=req.linked_log_id
    )
    await ws_manager.broadcast({
        "type": "HYPOTHESIS_CREATED",
        "hypothesis": res,
        "project": req.project or "default"
    })
    return res


@app.patch("/api/hypotheses/{hypothesis_id}")
async def update_hypothesis_endpoint(hypothesis_id: int, req: UpdateHypothesisRequest, project: Optional[str] = None):
    """P3: Updates status or notes on a hypothesis."""
    from backend.hypothesis_manager import update_hypothesis
    res = update_hypothesis(hypothesis_id, status=req.status, evidence_notes=req.evidence_notes, project=project)
    if not res:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    await ws_manager.broadcast({
        "type": "HYPOTHESIS_UPDATED",
        "hypothesis": res,
        "project": res.get("project") or project or "default"
    })
    return res


@app.delete("/api/hypotheses/{hypothesis_id}")
async def delete_hypothesis_endpoint(hypothesis_id: int, project: Optional[str] = None):
    """P3: Deletes a hypothesis."""
    from backend.hypothesis_manager import delete_hypothesis
    ok = delete_hypothesis(hypothesis_id, project=project)
    if not ok:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    await ws_manager.broadcast({
        "type": "HYPOTHESIS_DELETED",
        "id": hypothesis_id,
        "project": project or "default"
    })
    return {"status": "deleted", "id": hypothesis_id}


@app.post("/api/hypotheses/broadcast-event")
async def broadcast_hypothesis_event(data: Dict[str, Any]):
    """Relays hypothesis lifecycle events from FastMCP subprocess to connected dashboard WebSockets."""
    await ws_manager.broadcast(data)
    return {"status": "broadcasted"}


class VerifyDomRequest(BaseModel):
    url: str
    payload: Optional[str] = None
    param_name: Optional[str] = None
    trigger_event: Optional[str] = "load"
    wait_timeout_ms: Optional[int] = 4000
    project: Optional[str] = "default"


@app.post("/api/oracle/verify-dom")
async def verify_dom_endpoint(req: VerifyDomRequest, db: Session = Depends(get_db)):
    """P4: Validates DOM execution in a sandboxed Chromium instance."""
    from backend.browser_oracle import verify_dom_execution
    proj = (req.project or "default").strip().lower()
    is_allowed, block_reason = await async_check_scope(proj, req.url, db)
    if not is_allowed:
        raise HTTPException(status_code=403, detail=f"Target URL is outside authorized scope: {block_reason}")
    return await verify_dom_execution(
        url=req.url,
        payload=req.payload,
        param_name=req.param_name,
        trigger_event=req.trigger_event or "load",
        wait_timeout_ms=req.wait_timeout_ms or 4000
    )


# ==============================================================================
# Static Dashboard Hosting
# ==============================================================================

# ==============================================================================
# Proxsynth System Version & Auto-Update Endpoints
# ==============================================================================

@app.get("/api/system/version")
def get_system_version_endpoint():
    """Returns detailed Proxsynth system version, active commit, and platform metadata."""
    from backend.update_manager import get_system_version
    return get_system_version()


@app.get("/api/system/update-check")
async def check_system_update_endpoint(force: bool = False):
    """Checks remote repository for Proxsynth & MCP Server updates."""
    from backend.update_manager import async_check_for_updates
    return await async_check_for_updates(force=force)


@app.post("/api/system/update")
async def perform_system_update_endpoint():
    """Executes automated one-click system & MCP server update with live WebSocket telemetry."""
    from backend.update_manager import async_perform_system_update
    return await async_perform_system_update(ws_manager=ws_manager)


@app.post("/api/system/webhook-update")
async def github_webhook_update_endpoint(request: Request):
    """
    Automated webhook receiver for GitHub push events.
    Enables instant auto-update whenever a commit is pushed to the repository.
    Optionally verifies GITHUB_WEBHOOK_SECRET via HMAC-SHA256 signature.
    """
    import hmac
    import hashlib
    from backend.update_manager import async_perform_system_update

    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()
    body_bytes = await request.body()

    if secret:
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not signature or not signature.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Missing or malformed X-Hub-Signature-256 header")
        expected_sig = "sha256=" + hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            raise HTTPException(status_code=403, detail="Invalid webhook signature")

    event = request.headers.get("X-GitHub-Event", "push")
    if event in ("ping",):
        return {"status": "ok", "message": "Proxsynth GitHub Webhook Pong"}

    return await async_perform_system_update(ws_manager=ws_manager)


# ==============================================================================
# Public Ingress Tunnel Endpoints
# ==============================================================================

class TunnelStartRequest(BaseModel):
    provider: str = "auto"
    local_port: int = 8000
    project: str = "default"
    custom_domain: Optional[str] = None


@app.post("/api/tunnel/start")
async def start_tunnel_endpoint(req: TunnelStartRequest):
    """Starts a public Cloudflare or ngrok tunnel and binds to OAST listener."""
    from backend.tunnel_manager import start_public_tunnel
    return await start_public_tunnel(
        provider=req.provider,
        local_port=req.local_port,
        project=req.project,
        custom_domain=req.custom_domain
    )


@app.get("/api/tunnel/status")
def get_tunnel_status_endpoint():
    """Returns current active status of public ingress tunnels."""
    from backend.tunnel_manager import get_tunnel_status
    return get_tunnel_status()


@app.post("/api/tunnel/stop")
async def stop_tunnel_endpoint():
    """Gracefully terminates active public tunnel."""
    from backend.tunnel_manager import stop_public_tunnel
    return await stop_public_tunnel()


# ==============================================================================
# Autonomous Interception & Match/Replace Rules Endpoints
# ==============================================================================

class InterceptionRuleCreateRequest(BaseModel):
    name: str
    rule_type: str = "REQUEST"
    match_url: str = "*"
    match_method: str = "*"
    match_header: str = ""
    match_body: str = ""
    action_type: str = "REPLACE_HEADER"
    action_target: str = ""
    action_value: str = ""
    action_extra: Optional[Dict[str, Any]] = None
    project: str = "default"
    priority: int = 10
    enabled: bool = True


@app.get("/api/rules")
def list_rules_endpoint(project: Optional[str] = None):
    """Lists configured interception and match/replace rules."""
    from backend.interception_engine import list_interception_rules
    return list_interception_rules(project=project)


@app.post("/api/rules")
def add_rule_endpoint(req: InterceptionRuleCreateRequest):
    """Creates a new headless match/replace or response mocking rule."""
    from backend.interception_engine import add_interception_rule
    return add_interception_rule(
        name=req.name,
        rule_type=req.rule_type,
        match_url=req.match_url,
        match_method=req.match_method,
        match_header=req.match_header,
        match_body=req.match_body,
        action_type=req.action_type,
        action_target=req.action_target,
        action_value=req.action_value,
        action_extra=req.action_extra,
        project=req.project,
        priority=req.priority,
        enabled=req.enabled
    )


@app.delete("/api/rules/{rule_id}")
def delete_rule_endpoint(rule_id: int):
    """Deletes an interception rule."""
    from backend.interception_engine import delete_interception_rule
    ok = delete_interception_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "success", "deleted_rule_id": rule_id}


@app.post("/api/rules/{rule_id}/toggle")
def toggle_rule_endpoint(rule_id: int):
    """Toggles enabled state of an interception rule."""
    from backend.interception_engine import toggle_interception_rule
    res = toggle_interception_rule(rule_id)
    if not res:
        raise HTTPException(status_code=404, detail="Rule not found")
    return res


# ==============================================================================
# Dynamic Session & Anti-CSRF Token Endpoints
# ==============================================================================

class ManualCsrfTokenRequest(BaseModel):
    domain: str
    token_name: str = "csrf_token"
    token_value: str
    project: str = "default"


@app.get("/api/session/csrf-tokens")
def get_csrf_tokens_endpoint(domain: Optional[str] = None, project: Optional[str] = None):
    """Retrieves all tracked anti-CSRF tokens extracted from responses."""
    from backend.session_tracker import get_tracked_csrf_tokens
    return get_tracked_csrf_tokens(domain=domain, project=project)


@app.post("/api/session/csrf-token")
def set_csrf_token_endpoint(req: ManualCsrfTokenRequest):
    """Manually registers an anti-CSRF token for target domain."""
    from backend.session_tracker import set_manual_csrf_token
    return set_manual_csrf_token(
        domain=req.domain,
        token_name=req.token_name,
        token_value=req.token_value,
        project=req.project
    )


@app.delete("/api/session/csrf-tokens")
def clear_csrf_tokens_endpoint(domain: Optional[str] = None, project: Optional[str] = None):
    """Clears cached anti-CSRF tokens."""
    from backend.session_tracker import clear_tracked_csrf_tokens
    cleared = clear_tracked_csrf_tokens(domain=domain, project=project)
    return {"status": "success", "cleared_count": cleared}


# ==============================================================================
# Advanced Traffic Search & Pattern Analysis Endpoints
# ==============================================================================

@app.get("/api/traffic/advanced-search")
def search_traffic_endpoint(
    query: str = "",
    domain: Optional[str] = None,
    method: Optional[str] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    path_pattern: Optional[str] = None,
    has_findings: bool = False,
    min_duration_ms: Optional[int] = None,
    project: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """Performs multi-dimensional search over stored HTTP proxy traffic."""
    from backend.traffic_search import search_traffic_advanced
    return search_traffic_advanced(
        query=query,
        domain=domain,
        method=method,
        status_min=status_min,
        status_max=status_max,
        path_pattern=path_pattern,
        has_findings=has_findings,
        min_duration_ms=min_duration_ms,
        project=project,
        limit=limit,
        offset=offset
    )


@app.get("/api/traffic/patterns")
def traffic_patterns_endpoint(project: Optional[str] = None):
    """Analyzes traffic patterns and returns aggregated endpoint & parameter inventories."""
    from backend.traffic_search import analyze_traffic_patterns
    return analyze_traffic_patterns(project=project)


# ==============================================================================
# Modern Protocol Security Inspectors (GraphQL & WebSocket)
# ==============================================================================

class GraphqlInspectRequest(BaseModel):
    url: str
    headers: Optional[Dict[str, str]] = None
    project: str = "default"


class WebSocketAuditRequest(BaseModel):
    url: str
    headers: Optional[Dict[str, str]] = None
    project: str = "default"


@app.post("/api/protocol/graphql-inspect")
async def inspect_graphql_endpoint_api(req: GraphqlInspectRequest):
    """Audits GraphQL endpoint for introspection, field suggestion leaks, and query batching."""
    from backend.protocol_inspector import inspect_graphql_endpoint
    return await inspect_graphql_endpoint(url=req.url, headers=req.headers, project=req.project)


@app.post("/api/protocol/websocket-audit")
async def audit_websocket_endpoint_api(req: WebSocketAuditRequest):
    """Audits WebSocket upgrade handshake for CSWSH, plaintext transport, and query token leaks."""
    from backend.protocol_inspector import audit_websocket_security
    return await audit_websocket_security(url=req.url, headers=req.headers, project=req.project)


# ==============================================================================
# Automated CI/CD & API Security Audit Suite
# ==============================================================================

@app.get("/api/audit/ci-suite")
def run_ci_audit_endpoint(project: Optional[str] = None, min_severity: str = "LOW"):
    """Runs automated OWASP API security audit across proxy traffic and computes score."""
    from backend.ci_auditor import run_security_audit_suite
    return run_security_audit_suite(project=project, min_severity=min_severity)


@app.get("/api/audit/report")
def get_ci_audit_report_endpoint(project: Optional[str] = None, format: str = "markdown"):
    """Generates a publication-grade Markdown or JSON security audit report for CI/CD."""
    from backend.ci_auditor import generate_audit_ci_report
    rep = generate_audit_ci_report(project=project, output_format=format)
    if format.lower() == "markdown":
        return Response(content=rep, media_type="text/markdown")
    return JSONResponse(content=json.loads(rep))


@app.get("/api/health")
def health_check():
    return {"status": "ok", "platform": "Proxsynth", "version": "2.5.0"}

@app.get("/api/info")
def platform_info():
    return {
        "status": "online",
        "platform": "Proxsynth",
        "version": "2.5.0",
        "mode": "autonomous",
        "intercept_active": is_intercept_enabled()
    }

@app.get("/favicon.ico")
def serve_favicon():
    svg_icon = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>"""
    return Response(content=svg_icon, media_type="image/svg+xml")

@app.get("/")
def serve_index():
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        response = FileResponse(index_file, media_type="text/html")
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return JSONResponse({"status": "Frontend not yet generated. Please create frontend/index.html"}, status_code=404)
