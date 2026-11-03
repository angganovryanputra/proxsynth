"""
PROXSYNTH — COGNITIVE PENTEST HEXAGON CORE ENGINE
Consolidates 98 granular tools into 6 high-leverage, intent-driven super-routers
with deterministic heuristic auto-decision capabilities:

1. recon_intent_router        (Auto: IP -> Ports, URL -> SPA Spider, Spec -> OpenAPI, Domain -> Asset Graph)
2. traffic_intent_router      (Auto: Proxy HTTP/WS, WAF Auto-Heal, Distillation >50KB, Semantic Diffing)
3. audit_intent_router        (Auto: 2 Roles/IDs -> Two-Tier Replay, Numeric -> Logic Fuzz, SSRF -> OAST, XSS -> DOM Oracle)
4. session_intent_router      (Auto: Multi-Role Vault, Anti-CSRF Token Cache, 401 Re-Auth Refresher)
5. verify_export_intent_router(Auto: Deterministic Verification Gate, Nuclei YAML, CVSS v4.0 Dossier)
6. autonomous_step_router     (Auto: Master Cognitive Pentest Overseer & Next-Best-Action Executor)
"""

import os
import re
import json
import time
import asyncio
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union

import httpx
from sqlalchemy import func

from backend.database import (
    SessionLocal,
    HttpLog,
    Finding,
    Project,
    ActiveSession,
    TargetAsset,
    TargetService,
    TargetEndpoint,
    CapturedPayload,
    TestingHypothesis
)
from backend.intercept_manager import async_check_scope
from backend.attack_advisor import (
    _OBJECT_ID_PATH_PATTERN,
    _ADMIN_PATH_PATTERN,
    _NUMERIC_PARAM_PATTERN,
    _SSRF_PARAM_PATTERN,
    _OPEN_REDIRECT_PARAM_PATTERN,
    _JWT_PATTERN,
    _GRAPHQL_PATH_PATTERN,
    _GRAPHQL_BODY_PATTERN,
    suggest_attack_actions,
    get_project_attack_guidance
)
from backend.diff_engine import compute_semantic_diff, detect_soft_errors
from backend.body_distiller import distill_response_body as distill_http_response
from backend.target_manager import (
    upsert_target_asset,
    add_or_update_service,
    add_or_update_endpoint,
    get_attack_surface_graph
)
from backend.target_health import probe_target_health
def _resolve_proj(project: Optional[str] = None, allow_all: bool = False) -> str:
    try:
        from mcp_core.gateway import _resolve_project
        return _resolve_proj(project, allow_all=allow_all)
    except Exception:
        p = (project or "").strip().lower()
        if p in ("all", "*", "any", "global") and allow_all:
            return "all"
        return p or os.getenv("PROXSYNTH_PROJECT", "default").strip().lower() or "default"

_IPV4_CIDR_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-9]|[12][0-9]|3[0-2]))?$"
)

# Standard CVSS v4.0 Baseline Mappings for common vulnerability classes
CVSS_V4_MAPPINGS = {
    "SQL_INJECTION": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "score": 9.3,
        "severity": "CRITICAL",
        "cwe": "CWE-89"
    },
    "BOLA_IDOR": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "score": 8.7,
        "severity": "HIGH",
        "cwe": "CWE-639"
    },
    "BFLA_ADMIN": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "score": 8.8,
        "severity": "HIGH",
        "cwe": "CWE-285"
    },
    "SSRF": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N",
        "score": 9.2,
        "severity": "CRITICAL",
        "cwe": "CWE-918"
    },
    "NUMERIC_LOGIC": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
        "score": 7.1,
        "severity": "HIGH",
        "cwe": "CWE-840"
    },
    "REFLECTED_XSS": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
        "score": 5.1,
        "severity": "MEDIUM",
        "cwe": "CWE-79"
    },
    "STORED_XSS": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N",
        "score": 7.1,
        "severity": "HIGH",
        "cwe": "CWE-79"
    },
    "UNAUTHENTICATED_ACCESS": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "score": 8.7,
        "severity": "HIGH",
        "cwe": "CWE-306"
    },
    "DEFAULT": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "score": 5.3,
        "severity": "MEDIUM",
        "cwe": "CWE-699"
    }
}


def get_cvss_v4_rating(category: str) -> Dict[str, Any]:
    cat = (category or "").upper()
    if "SQL" in cat or "INJECTION" in cat:
        return CVSS_V4_MAPPINGS["SQL_INJECTION"]
    if "BOLA" in cat or "IDOR" in cat:
        return CVSS_V4_MAPPINGS["BOLA_IDOR"]
    if "BFLA" in cat or "FUNCTION LEVEL" in cat or "PRIVILEGE" in cat:
        return CVSS_V4_MAPPINGS["BFLA_ADMIN"]
    if "SSRF" in cat or "OAST" in cat:
        return CVSS_V4_MAPPINGS["SSRF"]
    if "LOGIC" in cat or "NUMERIC" in cat or "PRICE" in cat:
        return CVSS_V4_MAPPINGS["NUMERIC_LOGIC"]
    if "STORED XSS" in cat:
        return CVSS_V4_MAPPINGS["STORED_XSS"]
    if "XSS" in cat:
        return CVSS_V4_MAPPINGS["REFLECTED_XSS"]
    if "UNAUTHENTICATED" in cat or "UNAUTH" in cat:
        return CVSS_V4_MAPPINGS["UNAUTHENTICATED_ACCESS"]
    return CVSS_V4_MAPPINGS["DEFAULT"]


# ==============================================================================
# 1. RECON INTENT ROUTER
# ==============================================================================
async def recon_intent_router(
    target: str,
    mode: str = "auto",
    project: Optional[str] = None,
    max_pages: int = 15,
    concurrency: int = 40
) -> Dict[str, Any]:
    """
    Cognitive Recon Facet:
    Autonomously classifies targets into IP/CIDR, OpenAPI specification, Web URL,
    or Root Domain, and executes the appropriate discovery engine.
    """
    clean_target = (target or "").strip()
    if not clean_target:
        return {"status": "error", "message": "Target string cannot be empty."}

    proj = _resolve_proj(project, allow_all=False)
    clean_mode = (mode or "auto").strip().lower()

    # Heuristic Mode Classification
    if clean_mode == "auto":
        target_lower = clean_target.lower()
        if clean_target.startswith("ip:") or _IPV4_CIDR_PATTERN.match(clean_target):
            clean_mode = "ports"
        elif (
            target_lower.endswith((".json", ".yaml", ".yml"))
            or "swagger" in target_lower
            or "openapi" in target_lower
        ):
            clean_mode = "openapi"
        elif clean_target.startswith(("http://", "https://")):
            clean_mode = "spider"
        else:
            clean_mode = "domain"

    # Execution Router
    if clean_mode == "ports":
        ip_target = clean_target.replace("ip:", "").strip()
        from backend.network_scanner import scan_target_ports
        res = await scan_target_ports(
            target=ip_target,
            ports_profile="top_100",
            concurrency=concurrency,
            project=proj,
            audit_misconfigs=True
        )
        return {
            "status": "success",
            "facet": "recon",
            "routed_engine": "network_port_scanner",
            "target": ip_target,
            "project": proj,
            "results": res,
            "cognitive_advice": "Open ports registered in Attack Knowledge Graph. Run proxsynth_audit on HTTP services."
        }

    elif clean_mode == "openapi":
        from backend.api_importer import import_openapi_spec
        spec_content = clean_target
        if clean_target.startswith(("http://", "https://")):
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(clean_target)
                spec_content = resp.text
        elif os.path.exists(clean_target):
            with open(clean_target, "r", encoding="utf-8", errors="replace") as f:
                spec_content = f.read()

        res = import_openapi_spec(
            spec_data=spec_content,
            base_url="",
            project=proj
        )
        return {
            "status": "success",
            "facet": "recon",
            "routed_engine": "openapi_spec_importer",
            "target": clean_target,
            "project": proj,
            "results": res,
            "cognitive_advice": f"Imported API endpoints into Knowledge Graph. Run proxsynth_audit with vuln_focus='auto'."
        }

    elif clean_mode == "spider":
        url_target = clean_target
        if not url_target.startswith(("http://", "https://")):
            url_target = f"http://{url_target}"

        from backend.spider_engine import crawl_and_map_target
        res = await crawl_and_map_target(
            root_url=url_target,
            max_depth=2,
            max_pages=max_pages,
            project=proj
        )
        return {
            "status": "success",
            "facet": "recon",
            "routed_engine": "playwright_spa_spider",
            "target": url_target,
            "project": proj,
            "results": res,
            "cognitive_advice": f"Mapped {len(res.get('discovered_endpoints', []))} endpoints. Inspect with proxsynth_traffic or proxsynth_audit."
        }

    elif clean_mode in ("domain", "health"):
        domain_name = clean_target.replace("domain:", "").strip()
        parsed = urllib.parse.urlparse(domain_name)
        host = parsed.netloc if parsed.netloc else parsed.path.split("/")[0]

        # Register asset
        upsert_target_asset(
            project=proj,
            host=host,
            ip="",
            tags=["recon_discovered"]
        )

        # Probe health
        test_url = f"https://{host}"
        health_res = await probe_target_health(url=test_url, timeout=8.0, project=proj)
        if health_res.get("status") != "online":
            test_url = f"http://{host}"
            health_res = await probe_target_health(url=test_url, timeout=8.0, project=proj)

        return {
            "status": "success",
            "facet": "recon",
            "routed_engine": "domain_surface_probe",
            "target": host,
            "project": proj,
            "asset_registered": host,
            "health_probe": health_res,
            "cognitive_advice": f"Host '{host}' registered. Proceed with proxsynth_recon(target='{test_url}', mode='spider')."
        }

    return {"status": "error", "message": f"Unrecognized recon mode '{clean_mode}'"}


# ==============================================================================
# 2. TRAFFIC INTENT ROUTER
# ==============================================================================
async def traffic_intent_router(
    url: Optional[str] = None,
    action: str = "auto",
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    log_id_a: Optional[int] = None,
    log_id_b: Optional[int] = None,
    payload: Optional[str] = None,
    query_search: Optional[str] = None,
    project: Optional[str] = None
) -> Dict[str, Any]:
    """
    Cognitive Traffic Facet:
    Proxies HTTP requests with WAF auto-heal and distillation if >50KB,
    performs semantic differential analysis when given two logs, or searches traffic history.
    """
    proj = _resolve_proj(project, allow_all=False)
    clean_action = (action or "auto").strip().lower()

    # Heuristic Action Classification
    if clean_action == "auto":
        if log_id_a is not None and log_id_b is not None:
            clean_action = "diff"
        elif log_id_a is not None and not url:
            clean_action = "distill"
        elif query_search:
            clean_action = "search"
        elif url:
            clean_action = "send"
        elif payload and not url:
            clean_action = "vault"
        else:
            clean_action = "search"

    db = SessionLocal()
    try:
        # Differential Semantic Analysis
        if clean_action in ("diff", "semantic_diff"):
            if not log_id_a or not log_id_b:
                return {"status": "error", "message": "Differential action requires both log_id_a and log_id_b."}

            log_a = db.query(HttpLog).filter(HttpLog.id == log_id_a).first()
            log_b = db.query(HttpLog).filter(HttpLog.id == log_id_b).first()
            if not log_a or not log_b:
                return {"status": "error", "message": "One or both specified HttpLog records not found."}

            resp_dict_a = {
                "status_code": log_a.status_code or 200,
                "body": log_a.response_body or "",
                "headers": {}
            }
            if log_a.response_headers:
                try:
                    resp_dict_a["headers"] = json.loads(log_a.response_headers) if isinstance(log_a.response_headers, str) else log_a.response_headers
                except Exception:
                    pass

            resp_dict_b = {
                "status_code": log_b.status_code or 200,
                "body": log_b.response_body or "",
                "headers": {}
            }
            if log_b.response_headers:
                try:
                    resp_dict_b["headers"] = json.loads(log_b.response_headers) if isinstance(log_b.response_headers, str) else log_b.response_headers
                except Exception:
                    pass

            diff_res = compute_semantic_diff(resp_dict_a, resp_dict_b)
            soft_a = detect_soft_errors(log_a.status_code, log_a.response_body or "")
            soft_b = detect_soft_errors(log_b.status_code, log_b.response_body or "")
            sim_ratio = diff_res.get("normalized_similarity", 1.0)

            return {
                "status": "success",
                "facet": "traffic",
                "action": "semantic_diff",
                "log_a": {"id": log_a.id, "url": log_a.url, "status": log_a.status_code, "soft_error": soft_a},
                "log_b": {"id": log_b.id, "url": log_b.url, "status": log_b.status_code, "soft_error": soft_b},
                "similarity_ratio": sim_ratio,
                "raw_similarity": diff_res.get("raw_similarity", 1.0),
                "is_anomalous_difference": sim_ratio < 0.85,
                "diff_summary": diff_res.get("diff_preview", "Identical")[:3000] if diff_res.get("diff_preview") else "Identical"
            }

        # Response Distillation
        elif clean_action == "distill":
            target_body = body
            ct = "text/html"
            if log_id_a:
                target_log = db.query(HttpLog).filter(HttpLog.id == log_id_a).first()
                if not target_log:
                    return {"status": "error", "message": f"HttpLog #{log_id_a} not found."}
                target_body = target_log.response_body or ""
                if target_log.response_headers:
                    try:
                        rh = json.loads(target_log.response_headers) if isinstance(target_log.response_headers, str) else target_log.response_headers
                        ct = rh.get("content-type") or rh.get("Content-Type") or ct
                    except Exception:
                        pass

            dist = distill_http_response(body=target_body or "", content_type=ct)
            return {
                "status": "success",
                "facet": "traffic",
                "action": "distill",
                "distilled": dist
            }

        # Search Traffic
        elif clean_action == "search":
            q = db.query(HttpLog)
            if proj != "all":
                q = q.filter(HttpLog.project == proj)
            if query_search:
                like_term = f"%{query_search}%"
                q = q.filter(
                    (HttpLog.url.ilike(like_term)) |
                    (HttpLog.request_body.ilike(like_term)) |
                    (HttpLog.response_body.ilike(like_term))
                )
            logs = q.order_by(HttpLog.id.desc()).limit(15).all()
            items = []
            for l in logs:
                items.append({
                    "id": l.id,
                    "method": l.method,
                    "url": l.url,
                    "status_code": l.status_code,
                    "flag_status": l.flag_status,
                    "time": l.timestamp
                })
            return {
                "status": "success",
                "facet": "traffic",
                "action": "search",
                "total_matched": len(items),
                "items": items
            }

        # Send HTTP Request with WAF Auto-Heal & Auto-Distillation
        elif clean_action == "send":
            if not url:
                return {"status": "error", "message": "Action 'send' requires target 'url'."}

            req_headers = dict(headers or {})
            clean_method = (method or "GET").upper()

            # Scope check
            is_allowed, block_reason = await async_check_scope(proj, url, db)
            if not is_allowed:
                return {"status": "error", "message": f"Blocked by Proxynth Scope Guard: {block_reason}"}

            # Inject active session if no auth header
            parsed_url = urllib.parse.urlparse(url)
            host = parsed_url.netloc or "default"
            if not any(k.lower() in ("authorization", "cookie") for k in req_headers.keys()):
                sess = db.query(ActiveSession).filter(
                    ActiveSession.project == proj,
                    ActiveSession.domain.ilike(f"%{host}%")
                ).first()
                if sess:
                    try:
                        st = sess.get_decrypted_state()
                        if st.get("bearer_token"):
                            b_tok = st["bearer_token"]
                            req_headers["Authorization"] = f"Bearer {b_tok}" if not b_tok.lower().startswith("bearer ") else b_tok
                        for k, v in (st.get("auth_headers") or {}).items():
                            req_headers[k] = v
                    except Exception:
                        pass

            # Dispatch Request
            req_body_bytes = body.encode("utf-8") if body else None
            async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
                resp = await client.request(
                    method=clean_method,
                    url=url,
                    headers=req_headers,
                    content=req_body_bytes
                )

            resp_body_text = resp.text
            status = resp.status_code

            # WAF Auto-Heal check
            waf_healed = False
            if status in (403, 406, 429) and body:
                from backend.waf_mutator import mutate_payload_waf
                mutated = mutate_payload_waf(body, technique="all")
                if mutated and mutated != body:
                    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
                        resp_retry = await client.request(
                            method=clean_method,
                            url=url,
                            headers=req_headers,
                            content=mutated.encode("utf-8")
                        )
                    if resp_retry.status_code not in (403, 406):
                        resp = resp_retry
                        resp_body_text = resp.text
                        status = resp.status_code
                        waf_healed = True

            # Persist to HttpLog
            log_entry = HttpLog(
                project=proj,
                method=clean_method,
                url=url,
                host=host,
                path=parsed_url.path or "/",
                request_headers=json.dumps(req_headers),
                request_body=body or "",
                response_headers=json.dumps(dict(resp.headers)),
                response_body=resp_body_text[:500000],
                status_code=status,
                flag_status="UNFLAGGED"
            )
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)

            # Auto-Distillation if body > 50KB or HTML
            ct = resp.headers.get("content-type", "")
            is_large = len(resp_body_text) > 50000
            distilled_summary = None
            if is_large or "text/html" in ct.lower():
                dist = distill_http_response(resp_body_text, content_type=ct)
                distilled_summary = dist.get("compact_summary")

            # Follow-up Cognitive Attack Suggestions
            suggestions = suggest_attack_actions(
                url=url,
                method=clean_method,
                headers=req_headers,
                body=body,
                response_status=status,
                response_body=resp_body_text,
                log_id=log_entry.id,
                response_headers=dict(resp.headers)
            )

            return {
                "status": "success",
                "facet": "traffic",
                "action": "send",
                "log_id": log_entry.id,
                "url": url,
                "status_code": status,
                "waf_auto_healed": waf_healed,
                "response_body_length": len(resp_body_text),
                "distilled_summary": distilled_summary,
                "body_preview": (resp_body_text[:1500] if not distilled_summary else None),
                "recommended_follow_ups": suggestions[:3]
            }

        return {"status": "error", "message": f"Unsupported traffic action '{clean_action}'"}
    finally:
        db.close()


# ==============================================================================
# 3. AUDIT INTENT ROUTER
# ==============================================================================
async def audit_intent_router(
    target_url: Optional[str] = None,
    vuln_focus: str = "auto",
    log_id: Optional[int] = None,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    body: Optional[str] = None,
    project: Optional[str] = None,
    auto_exploit: bool = False
) -> Dict[str, Any]:
    """
    Cognitive Audit Facet:
    Evaluates target parameters and state, heuristically routing to:
    - Two-Tier 3-Way Replay (BOLA/BFLA/Unauth) when multiple roles or object IDs are detected
    - Numeric Business Logic Fuzzer when financial/quantity fields are present
    - In-House OAST Canary Sprayer for SSRF / callback vectors
    - Headless Chromium DOM Oracle for XSS / reflected sinks
    """
    proj = _resolve_proj(project, allow_all=False)
    db = SessionLocal()
    try:
        # Resolve URL/Log if log_id provided
        if log_id and not target_url:
            log_record = db.query(HttpLog).filter(HttpLog.id == log_id).first()
            if log_record:
                target_url = log_record.url
                method = log_record.method or "GET"
                body = log_record.request_body or body
                if not headers and log_record.request_headers:
                    try:
                        headers = json.loads(log_record.request_headers)
                    except Exception:
                        pass

        if not target_url:
            return {"status": "error", "message": "Audit facet requires target_url or valid log_id."}

        clean_focus = (vuln_focus or "auto").strip().lower()
        parsed_url = urllib.parse.urlparse(target_url)
        path = parsed_url.path or "/"
        query_dict = urllib.parse.parse_qs(parsed_url.query)

        # Heuristic Vulnerability Classification
        if clean_focus == "auto":
            host = parsed_url.netloc or ""
            domain_sessions = db.query(ActiveSession).filter(
                ActiveSession.project == proj,
                ActiveSession.domain.ilike(f"%{host}%")
            ).count()

            has_object_id = bool(_OBJECT_ID_PATH_PATTERN.search(path))
            has_admin_path = bool(_ADMIN_PATH_PATTERN.search(path))
            has_numeric_param = any(_NUMERIC_PARAM_PATTERN.match(k) for k in query_dict.keys()) or (params and any(_NUMERIC_PARAM_PATTERN.match(str(k)) for k in params.keys()))
            has_ssrf_param = any(_SSRF_PARAM_PATTERN.match(k) or _OPEN_REDIRECT_PARAM_PATTERN.match(k) for k in query_dict.keys())
            has_graphql = bool(_GRAPHQL_PATH_PATTERN.search(path)) or (body and _GRAPHQL_BODY_PATTERN.search(body))

            # 1. Numeric / Pricing / Commercial Logic Flaws
            if has_numeric_param:
                clean_focus = "logic"
            # 2. SSRF / Out-of-band Callbacks
            elif has_ssrf_param:
                clean_focus = "oast"
            # 3. Broken Access Control (BOLA / BFLA)
            elif has_object_id or has_admin_path or (domain_sessions >= 2):
                clean_focus = "access_control"
            # 4. GraphQL Attack Surface
            elif has_graphql:
                clean_focus = "graphql"
            # 5. Fallback: Param Fuzzing
            else:
                clean_focus = "fuzz"

        # Execution Router
        if clean_focus in ("access_control", "bola", "bfla", "idor"):
            from backend.access_control_orchestrator import AccessControlOrchestrator
            orch = AccessControlOrchestrator(project=proj)
            sess_a = {"token": "", "auth_headers": {}}
            sess_b = {"token": "", "auth_headers": {}}
            sessions = db.query(ActiveSession).filter(ActiveSession.project == proj).all()
            if len(sessions) >= 2:
                st_a = sessions[0].get_decrypted_state()
                st_b = sessions[1].get_decrypted_state()
                sess_a["token"] = st_a.get("bearer_token", "")
                sess_a["auth_headers"] = st_a.get("auth_headers", {})
                sess_b["token"] = st_b.get("bearer_token", "")
                sess_b["auth_headers"] = st_b.get("auth_headers", {})

            parsed = urllib.parse.urlparse(target_url)
            target_base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url
            res = await orch.execute_full_campaign(
                target_base=target_base,
                session_a=sess_a,
                session_b=sess_b,
                endpoints=[{"url": target_url, "method": method, "headers": headers or {}, "body": body or ""}],
                test_unauthenticated=True,
                export_nuclei=auto_exploit
            )
            cvss_info = get_cvss_v4_rating("BOLA_IDOR")
            return {
                "status": "success",
                "facet": "audit",
                "vulnerability_focus": "Broken Access Control (BOLA / BFLA / Unauthenticated)",
                "routed_engine": "two_tier_access_control_orchestrator",
                "target_url": target_url,
                "project": proj,
                "cvss_v4_baseline": cvss_info,
                "findings_summary": res.get("findings_summary", {}),
                "findings": res.get("findings", []),
                "remediation": "Enforce server-side tenancy boundary checks and object-level permission validators."
            }

        elif clean_focus in ("logic", "numeric", "pricing"):
            from backend.logic_fuzzer import audit_numeric_business_logic
            # Ensure log entry exists for logic fuzzer
            target_log_id = log_id
            if not target_log_id:
                # Synthesize baseline entry
                log_synth = HttpLog(
                    project=proj,
                    method=method.upper(),
                    url=target_url,
                    host=parsed_url.netloc or "default",
                    path=path,
                    request_headers=json.dumps(headers or {}),
                    request_body=body or "",
                    status_code=200,
                    flag_status="UNFLAGGED"
                )
                db.add(log_synth)
                db.commit()
                db.refresh(log_synth)
                target_log_id = log_synth.id

            target_param = None
            for k in query_dict.keys():
                if _NUMERIC_PARAM_PATTERN.match(k):
                    target_param = k
                    break

            res = await audit_numeric_business_logic(
                log_id=target_log_id,
                target_param=target_param,
                project=proj
            )
            cvss_info = get_cvss_v4_rating("NUMERIC_LOGIC")
            return {
                "status": "success",
                "facet": "audit",
                "vulnerability_focus": "Business Logic & Numeric Boundary Flaws",
                "routed_engine": "numeric_logic_fuzzer",
                "target_url": target_url,
                "project": proj,
                "cvss_v4_baseline": cvss_info,
                "results": res,
                "remediation": "Validate numeric lower bounds strictly (qty > 0, price >= baseline); use signed decimal types."
            }

        elif clean_focus in ("oast", "ssrf"):
            from backend.oast_sprayer import spray_oast_canaries
            from backend.oast_engine import list_recent_oast_events
            canaries_res = await spray_oast_canaries(
                target_url=target_url,
                vuln_type="ssrf",
                project=proj
            )
            events = list_recent_oast_events(project=proj, limit=5)
            cvss_info = get_cvss_v4_rating("SSRF")
            return {
                "status": "success",
                "facet": "audit",
                "vulnerability_focus": "Out-of-Band SSRF & Callback Injection",
                "routed_engine": "oast_canary_sprayer",
                "target_url": target_url,
                "project": proj,
                "cvss_v4_baseline": cvss_info,
                "sprayed_results": canaries_res,
                "callback_events": events,
                "remediation": "Validate and whitelist destination hostnames, disable URL scheme redirection, and block internal RFC1918 / metadata IPs."
            }

        elif clean_focus in ("xss", "dom"):
            from backend.browser_oracle import verify_dom_execution
            res = await verify_dom_execution(
                url=target_url,
                payload="<script>alert(1)</script>"
            )
            cvss_info = get_cvss_v4_rating("REFLECTED_XSS")
            return {
                "status": "success",
                "facet": "audit",
                "vulnerability_focus": "Cross-Site Scripting (DOM / Reflected)",
                "routed_engine": "playwright_browser_dom_oracle",
                "target_url": target_url,
                "project": proj,
                "cvss_v4_baseline": cvss_info,
                "oracle_result": res,
                "remediation": "Apply contextual output encoding and enforce strict Content Security Policy (CSP)."
            }

        elif clean_focus in ("graphql",):
            from backend.protocol_inspector import inspect_graphql_endpoint
            res = await inspect_graphql_endpoint(url=target_url, headers=headers, project=proj)
            return {
                "status": "success",
                "facet": "audit",
                "vulnerability_focus": "GraphQL Attack Surface",
                "routed_engine": "graphql_protocol_inspector",
                "target_url": target_url,
                "project": proj,
                "results": res
            }

        else:
            # Default Smart Fuzzer
            from backend.fuzzer import run_fuzz_attack
            res = await run_fuzz_attack(
                url=target_url,
                method=method.upper(),
                payloads=["'", "\"", "<script>", "../../../etc/passwd"],
                project=proj
            )
            return {
                "status": "success",
                "facet": "audit",
                "vulnerability_focus": "Parameter Fuzzing & Anomaly Detection",
                "routed_engine": "smart_param_fuzzer",
                "target_url": target_url,
                "project": proj,
                "results": res
            }
    finally:
        db.close()


# ==============================================================================
# 4. SESSION INTENT ROUTER
# ==============================================================================
async def session_intent_router(
    domain: Optional[str] = None,
    action: str = "auto",
    role: Optional[str] = None,
    token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    login_url: Optional[str] = None,
    project: Optional[str] = None
) -> Dict[str, Any]:
    """
    Cognitive Session Facet:
    Manages multi-role identity vaults (User A, User B, Admin), handles anti-CSRF token extraction,
    and conducts automated 401 session refreshing.
    """
    proj = _resolve_proj(project, allow_all=False)
    clean_action = (action or "auto").strip().lower()

    if clean_action == "auto":
        if token or headers:
            clean_action = "set"
        elif login_url:
            clean_action = "configure_refresher"
        elif domain:
            clean_action = "get"
        else:
            clean_action = "list"

    db = SessionLocal()
    try:
        # Register or update role session
        if clean_action in ("set", "upsert"):
            clean_domain = (domain or "default").strip().lower()
            clean_role = (role or "user").strip().lower()
            from backend.bola_matrix import set_identity_session
            sess_res = set_identity_session(
                project=proj,
                domain=clean_domain,
                identity_role=clean_role,
                bearer_token=token,
                auth_headers=headers
            )
            return {
                "status": "success",
                "facet": "session",
                "action": "upsert_identity",
                "project": proj,
                "domain": clean_domain,
                "role": clean_role,
                "identity": sess_res,
                "cognitive_advice": f"Role '{clean_role}' mapped. Access control tests will now leverage this identity."
            }

        # Retrieve active sessions for domain
        elif clean_action == "get":
            clean_domain = (domain or "").strip().lower()
            q = db.query(ActiveSession).filter(ActiveSession.project == proj)
            if clean_domain:
                q = q.filter(ActiveSession.domain.ilike(f"%{clean_domain}%"))
            sessions = q.all()

            identities = []
            for s in sessions:
                st = s.get_decrypted_state()
                identities.append({
                    "id": s.id,
                    "role": s.identity_role,
                    "domain": s.domain,
                    "bearer_token": st.get("bearer_token", ""),
                    "auth_headers": list((st.get("auth_headers") or {}).keys())
                })

            # Retrieve anti-CSRF tokens for domain from recent HttpLogs
            csrf_tokens = []
            csrf_logs = db.query(HttpLog).filter(
                HttpLog.project == proj,
                HttpLog.host.ilike(f"%{clean_domain}%")
            ).order_by(HttpLog.id.desc()).limit(20).all()
            for l in csrf_logs:
                if l.response_body:
                    from backend.diff_engine import CSRF_TOKEN_PATTERN
                    matches = CSRF_TOKEN_PATTERN.findall(l.response_body)
                    for m in matches:
                        if m not in csrf_tokens:
                            csrf_tokens.append(m)

            return {
                "status": "success",
                "facet": "session",
                "action": "get_session_state",
                "project": proj,
                "domain": clean_domain,
                "identities": identities,
                "cached_anti_csrf_tokens": csrf_tokens[:5]
            }

        # List all registered personas in project
        elif clean_action == "list":
            sessions = db.query(ActiveSession).filter(ActiveSession.project == proj).all()
            return {
                "status": "success",
                "facet": "session",
                "action": "list_identities",
                "project": proj,
                "total_sessions": len(sessions),
                "sessions": [
                    {"id": s.id, "role": s.identity_role, "domain": s.domain}
                    for s in sessions
                ]
            }

        # Configure session auto-refresher
        elif clean_action == "configure_refresher":
            if not domain or not login_url:
                return {"status": "error", "message": "Refresher configuration requires 'domain' and 'login_url'."}
            from backend.session_refresher import configure_session_refresher
            cfg = configure_session_refresher(
                domain=domain,
                login_url=login_url,
                login_headers=headers,
                project=proj
            )
            return {
                "status": "success",
                "facet": "session",
                "action": "configured_refresher",
                "config": cfg
            }

        # Execute session refresh
        elif clean_action == "refresh":
            if not domain:
                return {"status": "error", "message": "Session refresh requires target 'domain'."}
            from backend.session_refresher import execute_session_refresh
            res = await execute_session_refresh(domain=domain, project=proj)
            return {
                "status": "success",
                "facet": "session",
                "action": "execute_refresh",
                "result": res
            }

        return {"status": "error", "message": f"Unsupported session action '{clean_action}'"}
    finally:
        db.close()


# ==============================================================================
# 5. VERIFY & EXPORT INTENT ROUTER
# ==============================================================================
async def verify_export_intent_router(
    finding_id: Optional[int] = None,
    log_id: Optional[int] = None,
    format: str = "auto",
    project: Optional[str] = None
) -> Dict[str, Any]:
    """
    Cognitive Verification & Export Facet:
    Executes deterministic gate verification, generates reproducible ProjectDiscovery Nuclei YAML PoCs,
    and compiles publication-grade CVSS v4.0 / CWE vulnerability dossiers.
    """
    proj = _resolve_proj(project, allow_all=False)
    clean_format = (format or "auto").strip().lower()

    db = SessionLocal()
    try:
        finding = None
        log_record = None

        if finding_id:
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if finding and finding.log_id:
                log_record = db.query(HttpLog).filter(HttpLog.id == finding.log_id).first()
        elif log_id:
            log_record = db.query(HttpLog).filter(HttpLog.id == log_id).first()
            if log_record:
                finding = db.query(Finding).filter(Finding.log_id == log_id).first()

        if not finding and not log_record:
            return {"status": "error", "message": "Specify valid finding_id or log_id."}

        # 1. Deterministic Verification Gate
        from backend.verification_gate import verify_vulnerability_candidate
        gate_res = await verify_vulnerability_candidate(
            finding_id=finding.id if finding else None,
            log_id=log_record.id if log_record else None,
            project=proj
        )

        # 2. Nuclei YAML Template Generation
        nuclei_yaml = ""
        try:
            if finding and log_record:
                from backend.nuclei_generator import generate_nuclei_yaml_from_finding
                nuclei_yaml = generate_nuclei_yaml_from_finding(finding, log_record)
            elif log_record:
                from backend.nuclei_generator import generate_nuclei_yaml_from_log
                nuclei_yaml = generate_nuclei_yaml_from_log(
                    log_record,
                    title=finding.title if finding else "Verified Vulnerability",
                    severity=finding.severity if finding else "HIGH"
                )
        except Exception as ex:
            nuclei_yaml = f"# Nuclei generation notice: {str(ex)}"

        # 3. CVSS v4.0 & CWE Dossier
        cat = finding.category if finding else "Web Application Vulnerability"
        cvss_meta = get_cvss_v4_rating(cat)

        markdown_dossier = f"""# 🛡️ VULNERABILITY DOSSIER: {finding.title if finding else 'Security Finding'}
**Severity**: {cvss_meta['severity']} | **CVSS v4.0 Score**: {cvss_meta['score']}
**CVSS v4.0 Vector**: `{cvss_meta['vector']}`
**CWE Classification**: {cvss_meta['cwe']}
**Verification Verdict**: `{gate_res.get('verdict', 'UNCONFIRMED')}` (Confidence: {gate_res.get('confidence', 0.5)})

---
## 🎯 Affected Target
- **URL**: `{log_record.url if log_record else 'N/A'}`
- **HTTP Method**: `{log_record.method if log_record else 'GET'}`
- **Status Code**: `{log_record.status_code if log_record else 'N/A'}`

---
## 🔍 Verification Evidence
{gate_res.get('verification_evidence', 'Deterministic verification concluded.')}

---
## 🧪 Reproducible Nuclei Template
```yaml
{nuclei_yaml}
```
"""

        if clean_format == "nuclei":
            return {"status": "success", "format": "nuclei", "nuclei_yaml": nuclei_yaml}
        elif clean_format == "report_markdown":
            return {"status": "success", "format": "markdown", "report_markdown": markdown_dossier}
        elif clean_format == "verify":
            return {"status": "success", "format": "verification", "verification": gate_res}

        # Auto Format: Return Unified Suite
        return {
            "status": "success",
            "facet": "verify_and_export",
            "finding_id": finding.id if finding else None,
            "log_id": log_record.id if log_record else None,
            "verification_verdict": gate_res.get("verdict"),
            "verification_confidence": gate_res.get("confidence"),
            "cvss_v4": cvss_meta,
            "nuclei_yaml": nuclei_yaml,
            "report_markdown": markdown_dossier
        }
    finally:
        db.close()


# ==============================================================================
# 6. AUTONOMOUS STEP ROUTER (COGNITIVE OVERSEER)
# ==============================================================================
async def autonomous_step_router(
    project: Optional[str] = None,
    goal: str = "auto",
    feedback: Optional[str] = None
) -> Dict[str, Any]:
    """
    Cognitive Autonomous Step Facet:
    Master coordinator that assesses the target attack surface, evaluates the hypothesis ledger,
    and executes the single next-best offensive testing action automatically.
    """
    proj = _resolve_proj(project, allow_all=False)
    graph = get_attack_surface_graph(project=proj)
    summary = graph.get("summary", {})
    total_assets = summary.get("total_assets", 0)
    total_endpoints = summary.get("total_endpoints", 0)
    untested_endpoints = summary.get("untested_endpoints", 0)

    db = SessionLocal()
    try:
        # Step A: If no assets exist, prompt for recon
        if total_assets == 0 and total_endpoints == 0:
            return {
                "status": "success",
                "facet": "autonomous_step",
                "phase": "RECON_REQUIRED",
                "action_taken": "Inspected attack graph; workspace is empty.",
                "next_recommended_call": "proxsynth_recon(target='<TARGET_URL_OR_DOMAIN>', mode='auto')"
            }

        # Step B: Check for unverified high-severity findings
        unverified_finding = db.query(Finding).join(HttpLog).filter(
            HttpLog.project == proj,
            Finding.severity.in_(["CRITICAL", "HIGH"])
        ).order_by(Finding.id.desc()).first()

        if unverified_finding and not getattr(unverified_finding, "is_verified", False):
            verify_res = await verify_export_intent_router(
                finding_id=unverified_finding.id,
                format="auto",
                project=proj
            )
            return {
                "status": "success",
                "facet": "autonomous_step",
                "phase": "VERIFICATION_AND_EXPORT",
                "action_taken": f"Executed deterministic verification gate on Finding #{unverified_finding.id} ({unverified_finding.title}).",
                "result": verify_res,
                "next_recommended_call": "Review verified finding and proceed with autonomous audit on next endpoint."
            }

        # Step C: Pull Cognitive Guidance and Execute Top Audit Action
        guidance = get_project_attack_guidance(project=proj, limit=5)
        actions = guidance.get("recommended_actions", [])
        if actions:
            top_action = actions[0]
            focus = top_action.get("vulnerability_focus", "auto")
            target_p = top_action.get("tool_arguments", {})
            test_target = (
                target_p.get("url")
                or target_p.get("target_url")
                or top_action.get("endpoint_path")
            )
            audit_res = await audit_intent_router(
                target_url=test_target,
                vuln_focus=focus,
                project=proj,
                auto_exploit=True
            )
            return {
                "status": "success",
                "facet": "autonomous_step",
                "phase": "VULNERABILITY_AUDIT",
                "action_taken": f"Executed heuristic audit on {test_target} with focus: {focus}.",
                "audit_result": audit_res,
                "next_recommended_call": "proxsynth_autonomous_step(project='...') to continue testing loop."
            }

        # Step D: Untested Endpoints Fallback -> Spider or Fuzz
        endpoints = db.query(TargetEndpoint).join(TargetAsset).filter(
            TargetAsset.project == proj,
            TargetEndpoint.tested_status == "UNTESTED"
        ).limit(1).all()

        if endpoints:
            ep = endpoints[0]
            host_str = ep.asset.host if (ep.asset and ep.asset.host) else "default"
            ep_url = ep.url or f"http://{host_str}{ep.path}"
            audit_res = await audit_intent_router(
                target_url=ep_url,
                vuln_focus="auto",
                project=proj
            )
            ep.tested_status = "TESTED"
            db.commit()
            return {
                "status": "success",
                "facet": "autonomous_step",
                "phase": "ENDPOINT_AUDIT",
                "action_taken": f"Probed untested endpoint {ep_url}.",
                "audit_result": audit_res,
                "next_recommended_call": "proxsynth_autonomous_step(project='...') to continue testing loop."
            }

        return {
            "status": "success",
            "facet": "autonomous_step",
            "phase": "COVERAGE_COMPLETE",
            "action_taken": "All attack surface endpoints tested and verified.",
            "summary": summary,
            "next_recommended_call": "proxsynth_verify_and_export(format='report_markdown') to produce final pentest report."
        }
    finally:
        db.close()
