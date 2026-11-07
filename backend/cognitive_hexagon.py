"""
PROXSYNTH — COGNITIVE PENTEST HEXAGON CORE ENGINE
Consolidates 98 granular tools into 6 high-leverage, intent-driven super-routers
with deterministic heuristic auto-decision capabilities:

1. recon_intent_router        (Auto: IP -> Ports, URL -> SPA Spider, Spec -> OpenAPI, Domain -> Asset Graph)
2. traffic_intent_router      (Auto: Proxy HTTP/WS, WAF Auto-Heal, Distillation >50KB, Semantic Diffing, Vault)
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

from backend.database import (
    SessionLocal,
    HttpLog,
    Finding,
    ActiveSession,
    TargetAsset,
    TargetEndpoint,
    CapturedPayload
)
from backend.intercept_manager import async_check_scope
from backend.attack_advisor import (
    _OBJECT_ID_PATH_PATTERN,
    _ADMIN_PATH_PATTERN,
    _NUMERIC_PARAM_PATTERN,
    _SSRF_PARAM_PATTERN,
    _OPEN_REDIRECT_PARAM_PATTERN,
    _GRAPHQL_PATH_PATTERN,
    _GRAPHQL_BODY_PATTERN,
    suggest_attack_actions,
    get_project_attack_guidance
)
from backend.diff_engine import compute_semantic_diff, detect_soft_errors
from backend.body_distiller import distill_response_body as distill_http_response
from backend.target_manager import (
    upsert_target_asset,
    get_attack_surface_graph
)
from backend.target_health import probe_target_health


def _resolve_proj(project: Optional[str] = None, allow_all: bool = False) -> str:
    """Non-recursive project workspace resolver with safe fallback."""
    try:
        from mcp_core.gateway import _resolve_project
        return _resolve_project(project, allow_all=allow_all)
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


def _next_action(
    tool: str,
    rationale: str,
    confidence: float = 0.6,
    **arguments: Any
) -> Dict[str, Any]:
    """
    Builds a single machine-actionable directive so an autonomous LLM can chain the
    next step without re-reasoning. Every hexagon router attaches this as `next_action`.

    - tool:            the exact hexagon tool to call next (e.g. "proxsynth_audit")
    - arguments:       ready-to-pass kwargs (None values are dropped)
    - rationale:       why this is the highest-leverage next move
    - confidence:      0.0-1.0 heuristic confidence
    - auto_executable: True when confidence is high enough to run without a human gate
    """
    conf = max(0.0, min(1.0, float(confidence)))
    return {
        "tool": tool,
        "arguments": {k: v for k, v in arguments.items() if v is not None},
        "rationale": rationale,
        "confidence": round(conf, 2),
        "auto_executable": conf >= 0.7,
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
            "cognitive_advice": "Open ports registered in Attack Knowledge Graph. Run proxsynth_audit on HTTP services.",
            "next_action": _next_action(
                "proxsynth_autonomous_step",
                "Ports mapped into the graph; let the overseer pick the highest-leverage HTTP service to audit.",
                confidence=0.72, project=proj
            )
        }

    elif clean_mode == "openapi":
        from backend.api_importer import import_api_schema
        res = await import_api_schema(
            spec_source=clean_target,
            target_base_url="",
            project=proj
        )
        return {
            "status": "success",
            "facet": "recon",
            "routed_engine": "openapi_spec_importer",
            "target": clean_target,
            "project": proj,
            "results": res,
            "cognitive_advice": "Imported API endpoints into Knowledge Graph. Run proxsynth_audit with vuln_focus='auto'.",
            "next_action": _next_action(
                "proxsynth_autonomous_step",
                "Schema endpoints are now in the graph; drive the autonomous audit loop over them.",
                confidence=0.75, project=proj
            )
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
            "cognitive_advice": f"Mapped {len(res.get('discovered_endpoints', []))} endpoints. Inspect with proxsynth_traffic or proxsynth_audit.",
            "next_action": _next_action(
                "proxsynth_autonomous_step",
                f"Crawl mapped {len(res.get('discovered_endpoints', []))} endpoints; hand off to the overseer to audit them in priority order.",
                confidence=0.78, project=proj
            )
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
            "cognitive_advice": f"Host '{host}' registered. Proceed with proxsynth_recon(target='{test_url}', mode='spider').",
            "next_action": _next_action(
                "proxsynth_recon",
                f"Host registered and reachable at {test_url}; crawl it to harvest endpoints into the graph.",
                confidence=0.8, target=test_url, mode="spider", project=proj
            )
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

        # Payload Vault Action
        elif clean_action == "vault":
            records = []
            if payload:
                db_payload = CapturedPayload(
                    project=proj,
                    raw_payload=payload,
                    vuln_type="CUSTOM",
                    notes="Ingested via traffic router vault action"
                )
                db.add(db_payload)
                db.commit()
                db.refresh(db_payload)
                records.append({"id": db_payload.id, "payload": db_payload.raw_payload, "type": db_payload.vuln_type})
            else:
                vault_items = db.query(CapturedPayload).filter(CapturedPayload.project == proj).order_by(CapturedPayload.id.desc()).limit(15).all()
                for v in vault_items:
                    records.append({"id": v.id, "payload": v.raw_payload, "type": v.vuln_type})
            return {
                "status": "success",
                "facet": "traffic",
                "action": "vault",
                "total_records": len(records),
                "items": records,
                "vault_entries": records
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
            parsed_url = urllib.parse.urlparse(url)
            host = parsed_url.netloc or "default"

            # --- DB phase 1: scope check + session read, then release the session
            # BEFORE any network I/O. Holding a sync SQLite session open across a
            # 15s+ httpx round-trip serializes writers and triggers "database is
            # locked" under the Swarm worker pool. Read fast, close, then dispatch.
            is_allowed, block_reason = await async_check_scope(proj, url, db)
            if not is_allowed:
                return {"status": "error", "message": f"Blocked by Proxynth Scope Guard: {block_reason}"}

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

            db.close()  # release the SQLite writer lock for the network phase

            # --- Network phase: no DB session held ---
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

            # WAF Auto-Heal: a retry that still returns any WAF-block code
            # (403/406/429) is NOT healed. 429 must be in the success filter too,
            # or a rate-limited retry gets falsely reported as an evasion success.
            waf_healed = False
            if status in (403, 406, 429):
                from backend.waf_mutator import mutate_payload, generate_evasion_headers
                evasion_hdrs = dict(req_headers)
                evasion_hdrs.update(generate_evasion_headers(target_host=host))

                mutated_body = body
                if body:
                    mut_res = mutate_payload(raw_payload=body, strategy="ALL")
                    mut_list = [m.get("payload") for m in mut_res.get("mutations", []) if m.get("payload")]
                    if mut_list:
                        mutated_body = mut_list[0]

                if mutated_body != body or evasion_hdrs != req_headers:
                    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
                        resp_retry = await client.request(
                            method=clean_method,
                            url=url,
                            headers=evasion_hdrs,
                            content=mutated_body.encode("utf-8") if mutated_body else None
                        )
                    if resp_retry.status_code not in (403, 406, 429):
                        resp = resp_retry
                        resp_body_text = resp.text
                        status = resp.status_code
                        waf_healed = True

            # Auto-Distillation if body > 50KB or HTML (pure CPU, no DB)
            ct = resp.headers.get("content-type", "")
            is_large = len(resp_body_text) > 50000
            distilled_summary = None
            if is_large or "text/html" in ct.lower():
                dist = distill_http_response(resp_body_text, content_type=ct)
                distilled_summary = dist.get("compact_summary")

            # --- DB phase 2: persist on a FRESH short-lived session ---
            wdb = SessionLocal()
            try:
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
                wdb.add(log_entry)
                wdb.commit()
                wdb.refresh(log_entry)
                new_log_id = log_entry.id
            finally:
                wdb.close()

            # Follow-up Cognitive Attack Suggestions (pure CPU, no DB held)
            suggestions = suggest_attack_actions(
                url=url,
                method=clean_method,
                headers=req_headers,
                body=body,
                response_status=status,
                response_body=resp_body_text,
                log_id=new_log_id,
                response_headers=dict(resp.headers)
            )

            # Promote the single highest-leverage follow-up into a machine-actionable
            # next_action so an autonomous LLM can chain straight into an audit.
            top = suggestions[0] if suggestions else {}
            focus = top.get("vulnerability_focus") or top.get("focus") or "auto"
            next_action = _next_action(
                "proxsynth_audit",
                top.get("rationale") or top.get("reason")
                or "Response captured; run the heuristic audit engine on this endpoint.",
                confidence=0.74 if suggestions else 0.55,
                target_url=url, vuln_focus=focus, log_id=new_log_id, project=proj
            )

            return {
                "status": "success",
                "facet": "traffic",
                "action": "send",
                "log_id": new_log_id,
                "url": url,
                "status_code": status,
                "waf_auto_healed": waf_healed,
                "response_body_length": len(resp_body_text),
                "distilled_summary": distilled_summary,
                "body_preview": (resp_body_text[:1500] if not distilled_summary else None),
                "recommended_follow_ups": suggestions[:3],
                "next_action": next_action
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

        # Integrate params into target_url if supplied
        if params and isinstance(params, dict):
            parsed_params_url = urllib.parse.urlparse(target_url)
            existing_qs = urllib.parse.parse_qs(parsed_params_url.query)
            for k, v in params.items():
                existing_qs[str(k)] = [str(v)]
            new_qs = urllib.parse.urlencode({k: v[0] for k, v in existing_qs.items()})
            target_url = urllib.parse.urlunparse((
                parsed_params_url.scheme,
                parsed_params_url.netloc,
                parsed_params_url.path,
                parsed_params_url.params,
                new_qs,
                parsed_params_url.fragment
            ))

        clean_focus = (vuln_focus or "auto").strip().lower()
        parsed_url = urllib.parse.urlparse(target_url)
        path = parsed_url.path or "/"
        query_dict = urllib.parse.parse_qs(parsed_url.query)
        host = parsed_url.netloc or ""

        # Heuristic Vulnerability Classification
        if clean_focus == "auto":
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

            # Prioritize host-specific identities
            sessions = db.query(ActiveSession).filter(
                ActiveSession.project == proj,
                ActiveSession.domain.ilike(f"%{host}%")
            ).all()
            if len(sessions) < 2:
                sessions = db.query(ActiveSession).filter(ActiveSession.project == proj).all()

            if len(sessions) >= 2:
                # BOLA/BFLA depends on WHICH identity is the victim vs the attacker,
                # so pick deterministically by role rather than arbitrary insertion
                # order. Prefer an explicit low-privilege "attacker" (user/user_b/
                # attacker) as A and a distinct "victim/admin/owner" identity as B.
                def _role(s):
                    return (getattr(s, "identity_role", "") or "").strip().lower()

                attacker_roles = ("user_a", "user", "attacker", "low", "guest")
                victim_roles = ("user_b", "victim", "admin", "owner", "tenant_b", "high")

                ident_a = next((s for s in sessions if _role(s) in attacker_roles), None)
                ident_b = next((s for s in sessions if _role(s) in victim_roles and s is not ident_a), None)
                # Fall back to a stable ordering (by role name, then id) so repeated
                # runs pair the same two identities every time.
                ordered = sorted(sessions, key=lambda s: (_role(s), s.id))
                if ident_a is None:
                    ident_a = ordered[0]
                if ident_b is None:
                    ident_b = next((s for s in ordered if s is not ident_a), ordered[-1])

                st_a = ident_a.get_decrypted_state()
                st_b = ident_b.get_decrypted_state()
                sess_a["token"] = st_a.get("bearer_token", "")
                sess_a["auth_headers"] = st_a.get("auth_headers", {})
                sess_b["token"] = st_b.get("bearer_token", "")
                sess_b["auth_headers"] = st_b.get("auth_headers", {})

            target_base = f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url.netloc else target_url
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
                "remediation": "Enforce server-side tenancy boundary checks and object-level permission validators.",
                "next_action": (
                    _next_action(
                        "proxsynth_verify_and_export",
                        "Access-control finding detected; run the deterministic oracle to confirm and export a PoC.",
                        confidence=0.82,
                        finding_id=(res.get("findings") or [{}])[0].get("id"),
                        project=proj
                    ) if res.get("findings")
                    else _next_action(
                        "proxsynth_autonomous_step",
                        "No access-control break here; let the overseer advance to the next endpoint.",
                        confidence=0.7, project=proj
                    )
                )
            }

        elif clean_focus in ("logic", "numeric", "pricing"):
            from backend.logic_fuzzer import audit_numeric_business_logic
            target_log_id = log_id
            if not target_log_id:
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
                "remediation": "Validate numeric lower bounds strictly (qty > 0, price >= baseline); use signed decimal types.",
                "next_action": _next_action(
                    "proxsynth_autonomous_step",
                    "Numeric logic probed; advance the autonomous loop to the next prioritized endpoint.",
                    confidence=0.7, project=proj
                )
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
                "remediation": "Validate and whitelist destination hostnames, disable URL scheme redirection, and block internal RFC1918 / metadata IPs.",
                "next_action": (
                    _next_action(
                        "proxsynth_audit",
                        "OAST canaries fired; re-poll shortly by re-auditing with oast focus to catch delayed callbacks.",
                        confidence=0.6, target_url=target_url, vuln_focus="oast", project=proj
                    ) if not events
                    else _next_action(
                        "proxsynth_verify_and_export",
                        "Out-of-band callback received; confirm and export the SSRF finding.",
                        confidence=0.85, project=proj
                    )
                )
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
                "remediation": "Apply contextual output encoding and enforce strict Content Security Policy (CSP).",
                "next_action": _next_action(
                    "proxsynth_autonomous_step",
                    "DOM oracle executed; continue the loop to the next endpoint or verification.",
                    confidence=0.68, project=proj
                )
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
                "results": res,
                "next_action": _next_action(
                    "proxsynth_autonomous_step",
                    "GraphQL surface inspected; advance the loop to audit mutations/resolvers next.",
                    confidence=0.66, project=proj
                )
            }

        else:
            from backend.fuzzer import run_fuzz_attack
            res = await run_fuzz_attack(
                base_url=target_url,
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
                "results": res,
                "next_action": _next_action(
                    "proxsynth_autonomous_step",
                    "Baseline fuzz complete; let the overseer pick the next-best action from the graph.",
                    confidence=0.64, project=proj
                )
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
            nuclei_out = None
            if finding and log_record:
                from backend.nuclei_generator import generate_nuclei_yaml_from_finding
                nuclei_out = generate_nuclei_yaml_from_finding(finding, log_record)
            elif log_record:
                from backend.nuclei_generator import generate_nuclei_yaml_from_log
                nuclei_out = generate_nuclei_yaml_from_log(
                    log_record,
                    title=finding.title if finding else "Verified Vulnerability",
                    severity=finding.severity if finding else "HIGH"
                )
            if isinstance(nuclei_out, dict):
                nuclei_yaml = nuclei_out.get("yaml", "") or nuclei_out.get("template", "") or json.dumps(nuclei_out, indent=2)
            elif nuclei_out:
                nuclei_yaml = str(nuclei_out)
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

    db = SessionLocal()
    try:
        # Step A: If no assets exist, prompt for recon
        if total_assets == 0 and total_endpoints == 0:
            return {
                "status": "success",
                "facet": "autonomous_step",
                "phase": "RECON_REQUIRED",
                "action_taken": "Inspected attack graph; workspace is empty.",
                "next_recommended_call": "proxsynth_recon(target='<TARGET_URL_OR_DOMAIN>', mode='auto')",
                "next_action": _next_action(
                    "proxsynth_recon",
                    "Workspace is empty — a target must be supplied before the loop can self-drive.",
                    confidence=0.4, target="<TARGET_URL_OR_DOMAIN>", mode="auto", project=proj
                )
            }

        # Step B: Check for unverified high-severity findings
        findings_to_verify = db.query(Finding).join(HttpLog).filter(
            HttpLog.project == proj,
            Finding.severity.in_(["CRITICAL", "HIGH"])
        ).order_by(Finding.id.desc()).all()

        unverified_finding = None
        for f in findings_to_verify:
            ev = f.evidence or ""
            is_verified = "[ORACLE VERDICT:" in ev or (f.log and f.log.flag_status in ("CONFIRMED", "VERIFIED"))
            if not is_verified:
                unverified_finding = f
                break

        if unverified_finding:
            verify_res = await verify_export_intent_router(
                finding_id=unverified_finding.id,
                format="auto",
                project=proj
            )
            # Stamp finding evidence with oracle verdict to prevent re-verification loop
            verdict = verify_res.get("verification_verdict", "UNCONFIRMED")
            unverified_finding.evidence = f"{unverified_finding.evidence or ''}\n[ORACLE VERDICT: {verdict}]"
            if unverified_finding.log:
                unverified_finding.log.flag_status = "CONFIRMED" if "VERIFIED" in str(verdict) else "FLAGGED"
            db.commit()

            return {
                "status": "success",
                "facet": "autonomous_step",
                "phase": "VERIFICATION_AND_EXPORT",
                "action_taken": f"Executed deterministic verification gate on Finding #{unverified_finding.id} ({unverified_finding.title}) -> Verdict: {verdict}.",
                "result": verify_res,
                "next_recommended_call": "Review verified finding and proceed with autonomous audit on next endpoint.",
                "next_action": _next_action(
                    "proxsynth_autonomous_step",
                    "Finding verified and stamped; call again to continue auditing the remaining surface.",
                    confidence=0.9, project=proj
                )
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

            # Mark the audited endpoint TESTED so the next guidance pull does not
            # re-surface the same top action, which would spin the loop in place.
            try:
                if test_target:
                    marked = db.query(TargetEndpoint).join(TargetAsset).filter(
                        TargetAsset.project == proj,
                        (TargetEndpoint.url == test_target) | (TargetEndpoint.path == urllib.parse.urlparse(test_target).path)
                    ).first()
                    if marked and marked.tested_status != "TESTED":
                        marked.tested_status = "TESTED"
                        db.commit()
            except Exception:
                db.rollback()

            return {
                "status": "success",
                "facet": "autonomous_step",
                "phase": "VULNERABILITY_AUDIT",
                "action_taken": f"Executed heuristic audit on {test_target} with focus: {focus}.",
                "audit_result": audit_res,
                "next_recommended_call": "proxsynth_autonomous_step(project='...') to continue testing loop.",
                "next_action": _next_action(
                    "proxsynth_autonomous_step",
                    "Top-priority endpoint audited and marked tested; call again to advance to the next action.",
                    confidence=0.88, project=proj
                )
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
                "next_recommended_call": "proxsynth_autonomous_step(project='...') to continue testing loop.",
                "next_action": _next_action(
                    "proxsynth_autonomous_step",
                    "Untested endpoint probed and marked tested; call again to continue coverage.",
                    confidence=0.85, project=proj
                )
            }

        return {
            "status": "success",
            "facet": "autonomous_step",
            "phase": "COVERAGE_COMPLETE",
            "action_taken": "All attack surface endpoints tested and verified.",
            "summary": summary,
            "next_recommended_call": "proxsynth_verify_and_export(format='report_markdown') to produce final pentest report.",
            "next_action": _next_action(
                "proxsynth_verify_and_export",
                "Surface fully covered — compile the publication-ready report to close the engagement.",
                confidence=0.9, format="report_markdown", project=proj
            )
        }
    finally:
        db.close()


async def run_cognitive_hexagon_campaign(
    target_url: str,
    project: str = "default",
    max_steps: int = 5
) -> Dict[str, Any]:
    """
    Runs an autonomous unified pentest sequence orchestrated entirely by the Cognitive Hexagon.
    Seeds target knowledge, prioritizes hypotheses, audits endpoints, verifies findings, and returns telemetry.
    """
    steps_taken = []
    proj = _resolve_proj(project, allow_all=False)

    # Step 1: Recon & Seed
    if target_url and target_url.strip():
        recon_res = await recon_intent_router(target=target_url.strip(), mode="auto", project=proj)
        steps_taken.append({
            "step": 1,
            "facet": "recon",
            "result": recon_res
        })

    # Steps 2..N: Autonomous Iterations
    for step_num in range(2, max_steps + 1):
        step_res = await autonomous_step_router(project=proj, goal="auto")
        steps_taken.append({
            "step": step_num,
            "facet": "autonomous_step",
            "result": step_res
        })
        phase = step_res.get("phase", "")
        if phase in ("COVERAGE_COMPLETE", "RECON_REQUIRED", "IDLE"):
            break

    # Aggregate telemetry metrics from steps & DB for project
    db = SessionLocal()
    findings_list = []
    endpoints_mapped = 0
    confirmed_count = 0
    try:
        endpoints_mapped = db.query(TargetEndpoint).join(TargetAsset).filter(TargetAsset.project == proj).count()
        findings = db.query(Finding).join(HttpLog).filter(HttpLog.project == proj).order_by(Finding.id.desc()).all()
        confirmed_count = len(findings)
        findings_list = [f.to_dict() for f in findings]
    except Exception:
        pass
    finally:
        db.close()

    # Report real, auditable numbers only. A security report must never inflate
    # coverage, so endpoints_mapped is the true DB count (not max(real, steps*2)),
    # and vanity keys that were always 0 are dropped rather than faked.
    verified_count = sum(
        1 for f in findings_list
        if isinstance(f, dict) and "[ORACLE VERDICT: VERIFIED]" in str(f.get("evidence", ""))
    )
    metrics = {
        "endpoints_mapped": endpoints_mapped,
        "autonomous_steps_executed": len(steps_taken),
        "findings_recorded": confirmed_count,
        "findings_oracle_verified": verified_count,
    }

    return {
        "status": "completed",
        "engine": "cognitive_hexagon",
        "project": proj,
        "target_url": target_url,
        "steps_count": len(steps_taken),
        "steps": steps_taken,
        "metrics": metrics,
        "findings_summary": findings_list
    }
