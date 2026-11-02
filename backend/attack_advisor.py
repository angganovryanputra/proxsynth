"""
Proxsynth - Autonomous Cognitive Attack Advisor & Decision Engine
Analyzes observed target traffic and attack surface endpoints to provide deterministic,
heuristic-driven recommendations for AI Agents, directly mapping observed signals
(object IDs, admin routes, numeric parameters, reflection sinks, SSRF parameters, JWTs)
to specific FastMCP testing tools with ready-to-execute arguments.
"""

import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional
from backend.database import SessionLocal, HttpLog, TargetEndpoint, TargetAsset


# Regex patterns for heuristic classification
_OBJECT_ID_PATH_PATTERN = re.compile(
    r"/(?:api/)?(?:v[0-9]+/)?(?:users?|accounts?|orders?|invoices?|profiles?|documents?|items?|tenants?|orgs?|projects?|customers?|messages?|files?|tickets?)/([0-9a-fA-F-]+|\d+)",
    re.IGNORECASE
)
_ADMIN_PATH_PATTERN = re.compile(
    r"/(?:admin|manage|management|dashboard|internal|system|sys|roles|permissions|config|settings|audit|controlpanel|super)(?:/|$|\?)",
    re.IGNORECASE
)
_NUMERIC_PARAM_PATTERN = re.compile(
    r"^(?:qty|quantity|amount|price|total|discount|balance|credit|cost|limit|offset|units?|fee|rate|count|num)$",
    re.IGNORECASE
)
_SSRF_PARAM_PATTERN = re.compile(
    r"^(?:url|redirect|redirect_url|dest|destination|callback|webhook|feed|host|uri|path|source|target|fetch|download|domain|proxy)$",
    re.IGNORECASE
)
_JWT_PATTERN = re.compile(
    r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*\b"
)
_OPEN_REDIRECT_PARAM_PATTERN = re.compile(
    r"^(?:url|redirect|next|return|callback|dest|continue|image|fetch|proxy)$",
    re.IGNORECASE
)
_GRAPHQL_PATH_PATTERN = re.compile(r"/graphql/?$", re.IGNORECASE)
_GRAPHQL_BODY_PATTERN = re.compile(r"\b(?:query|mutation)\s*\{", re.IGNORECASE)
_DEBUG_PARAM_PATTERN = re.compile(
    r"^(?:debug|test|admin|verbose)$",
    re.IGNORECASE
)


def suggest_attack_actions(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, Any]] = None,
    body: Optional[str] = None,
    response_status: Optional[int] = None,
    response_body: Optional[str] = None,
    log_id: Optional[int] = None,
    response_headers: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Examines an individual HTTP transaction and returns actionable next-step tool recommendations.
    """
    suggestions: List[Dict[str, Any]] = []
    clean_method = (method or "GET").upper().strip()
    parsed_url = urllib.parse.urlparse(url)
    path = parsed_url.path or "/"
    query_params = urllib.parse.parse_qs(parsed_url.query)

    # 1. Broken Access Control: BOLA / IDOR Check
    bola_match = _OBJECT_ID_PATH_PATTERN.search(path)
    bola_param = None
    for p_name in query_params.keys():
        if re.search(r"(?:^|_)(?:id|user_id|account_id|order_id|doc_id|tenant_id|org_id)$", p_name, re.IGNORECASE):
            bola_param = p_name
            break

    if bola_match or bola_param:
        matched_id = bola_match.group(1) if bola_match else query_params.get(bola_param, [""])[0]
        suggestions.append({
            "vulnerability_focus": "Broken Object Level Authorization (BOLA / IDOR)",
            "severity_potential": "HIGH",
            "confidence": "HIGH",
            "trigger_reason": f"Observed resource identifier '{matched_id}' in path or parameter '{bola_param or 'path'}'.",
            "recommended_mcp_tool": "test_bola_idor",
            "tool_arguments": {"log_id": log_id}
        })

    # 2. Broken Function Level Authorization (BFLA) Check
    if _ADMIN_PATH_PATTERN.search(path) or clean_method in ["DELETE", "PUT", "PATCH"]:
        suggestions.append({
            "vulnerability_focus": "Broken Function Level Authorization (BFLA)",
            "severity_potential": "HIGH",
            "confidence": "HIGH",
            "trigger_reason": f"Privileged or sensitive endpoint detected: [{clean_method}] {path}",
            "recommended_mcp_tool": "audit_bfla_permissions",
            "tool_arguments": {
                "url": url,
                "method": clean_method,
                "log_id": log_id
            }
        })

    # 3. Mass Assignment / Object Over-Posting Check
    if clean_method in ["POST", "PUT", "PATCH"]:
        is_json = False
        parsed_body = None
        if body:
            try:
                parsed_body = json.loads(body)
                if isinstance(parsed_body, dict):
                    is_json = True
            except Exception:
                pass
        
        if is_json and parsed_body:
            user_keys = [k for k in parsed_body.keys() if any(sub in k.lower() for sub in ["name", "email", "status", "role", "type", "profile", "user"])]
            if user_keys or len(parsed_body) > 1:
                suggestions.append({
                    "vulnerability_focus": "Mass Assignment & Property Tampering",
                    "severity_potential": "HIGH",
                    "confidence": "HIGH",
                    "trigger_reason": f"JSON mutation request body contains mutable object fields: {', '.join(user_keys[:3])}",
                    "recommended_mcp_tool": "audit_mass_assignment",
                    "tool_arguments": {"log_id": log_id}
                })

    # 4. Numeric Business Logic & Currency Fuzzing Check
    numeric_params = []
    for k, v in query_params.items():
        if _NUMERIC_PARAM_PATTERN.match(k) or (v and v[0].isdigit()):
            numeric_params.append(k)

    if body:
        try:
            b_json = json.loads(body)
            if isinstance(b_json, dict):
                for k, v in b_json.items():
                    if _NUMERIC_PARAM_PATTERN.match(k) or isinstance(v, (int, float)):
                        numeric_params.append(k)
        except Exception:
            pass

    if numeric_params:
        target_p = numeric_params[0]
        suggestions.append({
            "vulnerability_focus": "Numeric Business Logic & Currency Flaws",
            "severity_potential": "HIGH",
            "confidence": "HIGH",
            "trigger_reason": f"Observed numeric/commercial parameters prone to negative quantity or overflow: {', '.join(numeric_params)}",
            "recommended_mcp_tool": "audit_numeric_business_logic",
            "tool_arguments": {
                "log_id": log_id,
                "target_param": target_p
            }
        })

    # 5. Out-of-Band SSRF / JNDI Check
    ssrf_params = [k for k in query_params.keys() if _SSRF_PARAM_PATTERN.match(k)]
    if ssrf_params:
        suggestions.append({
            "vulnerability_focus": "Blind SSRF & Out-of-Band Callback Injection",
            "severity_potential": "CRITICAL",
            "confidence": "HIGH",
            "trigger_reason": f"URL contains suspected server-side fetching parameter: {ssrf_params[0]}",
            "recommended_mcp_tool": "spray_oast_canaries",
            "tool_arguments": {
                "target_url": url,
                "vuln_types": ["ssrf", "dns", "log4j", "xxe"]
            }
        })

    # 6. JWT Authentication Auditing Check
    auth_header = (headers or {}).get("Authorization", "") or (headers or {}).get("authorization", "")
    jwt_match = _JWT_PATTERN.search(auth_header)
    if not jwt_match and response_body:
        jwt_match = _JWT_PATTERN.search(response_body[:5000])

    if jwt_match:
        suggestions.append({
            "vulnerability_focus": "JWT Cryptographic & Claim Tampering",
            "severity_potential": "HIGH",
            "confidence": "HIGH",
            "trigger_reason": "JSON Web Token (JWT) detected in Authorization header or response payload.",
            "recommended_mcp_tool": "audit_jwt_security",
            "tool_arguments": {
                "token": jwt_match.group(0),
                "test_url": url
            }
        })

    # 7. Differential Injection Check (SQLi / SSTI)
    inj_params = [k for k in query_params.keys() if k.lower() in ["id", "search", "query", "q", "filter", "cat", "category", "sort"]]
    if inj_params:
        suggestions.append({
            "vulnerability_focus": "Differential Injection Oracle (SQLi / SSTI)",
            "severity_potential": "HIGH",
            "confidence": "MEDIUM",
            "trigger_reason": f"Input parameter '{inj_params[0]}' presents a high-probability injection surface.",
            "recommended_mcp_tool": "audit_differential_injection",
            "tool_arguments": {
                "url": url,
                "param_name": inj_params[0],
                "param_type": "query"
            }
        })

    # 8. Open-Redirect / Parameter-Based SSRF Check
    redirect_params = [k for k in query_params.keys() if _OPEN_REDIRECT_PARAM_PATTERN.match(k)]
    body_json_for_redirect = None
    if body:
        try:
            body_json_for_redirect = json.loads(body)
        except Exception:
            body_json_for_redirect = None
    if isinstance(body_json_for_redirect, dict):
        redirect_params.extend(
            [k for k in body_json_for_redirect.keys() if _OPEN_REDIRECT_PARAM_PATTERN.match(k)]
        )

    if redirect_params:
        suggestions.append({
            "vulnerability_focus": "Open Redirect & Parameter-Based SSRF",
            "severity_potential": "HIGH",
            "confidence": "MEDIUM",
            "trigger_reason": f"Observed redirect/fetch-style parameter susceptible to open redirect or SSRF: {redirect_params[0]}",
            "recommended_mcp_tool": "spray_oast_canaries",
            "tool_arguments": {
                "target_url": url,
                "vuln_types": ["ssrf", "dns"]
            }
        })
        suggestions.append({
            "vulnerability_focus": "Open Redirect & Parameter-Based SSRF",
            "severity_potential": "MEDIUM",
            "confidence": "MEDIUM",
            "trigger_reason": f"Redirect-style parameter '{redirect_params[0]}' should be probed for unvalidated external redirection.",
            "recommended_mcp_tool": "send_http_request",
            "tool_arguments": {
                "method": "GET",
                "url": (
                    f"{url}{'&' if parsed_url.query else '?'}"
                    f"{urllib.parse.quote(redirect_params[0])}="
                    f"{urllib.parse.quote('https://attacker-canary.example.com/')}"
                )
            }
        })

    # 9. GraphQL Endpoint Discovery Check
    is_graphql_path = bool(_GRAPHQL_PATH_PATTERN.search(path))
    is_graphql_body = bool(body and _GRAPHQL_BODY_PATTERN.search(body))
    if is_graphql_path or is_graphql_body:
        suggestions.append({
            "vulnerability_focus": "GraphQL Attack Surface (Introspection / Batching / Depth)",
            "severity_potential": "HIGH",
            "confidence": "HIGH" if is_graphql_path else "MEDIUM",
            "trigger_reason": "GraphQL endpoint path or query/mutation operation detected.",
            "recommended_mcp_tool": "inspect_graphql_endpoint",
            "tool_arguments": {
                "url": url
            }
        })

    # 10. File Upload Surface Check
    content_type_header = (headers or {}).get("Content-Type", "") or (headers or {}).get("content-type", "")
    is_multipart = "multipart/form-data" in (content_type_header or "").lower()
    has_filename_in_body = bool(body and "filename=" in body)
    if is_multipart or has_filename_in_body:
        suggestions.append({
            "vulnerability_focus": "Unrestricted File Upload",
            "severity_potential": "HIGH",
            "confidence": "HIGH" if is_multipart else "MEDIUM",
            "trigger_reason": "Multipart file-upload request detected (Content-Type or filename= field in body).",
            "recommended_mcp_tool": "audit_file_upload",
            "tool_arguments": {
                "target": log_id if log_id else url,
                "field": "file"
            }
        })

    # 11. CORS Misconfiguration Check (wildcard origin + credentials allowed)
    resp_hdrs = response_headers or {}
    acao = resp_hdrs.get("Access-Control-Allow-Origin") or resp_hdrs.get("access-control-allow-origin")
    acac = resp_hdrs.get("Access-Control-Allow-Credentials") or resp_hdrs.get("access-control-allow-credentials")
    origin_req = (headers or {}).get("Origin", "") or (headers or {}).get("origin", "")
    acac_true = str(acac).strip().lower() == "true"
    cors_wildcard = acao == "*" or (bool(origin_req) and acao == origin_req)
    if cors_wildcard and acac_true:
        suggestions.append({
            "vulnerability_focus": "CORS Misconfiguration (Wildcard/Reflected Origin + Credentials)",
            "severity_potential": "HIGH",
            "confidence": "HIGH",
            "trigger_reason": f"Access-Control-Allow-Origin='{acao}' combined with Access-Control-Allow-Credentials=true permits cross-origin credentialed requests.",
            "recommended_mcp_tool": "send_http_request",
            "tool_arguments": {
                "url": url,
                "method": clean_method,
                "headers": {"Origin": "https://attacker-canary.example.com"}
            }
        })

    # 12. Debug/Verbose Parameter -> Mass Assignment Exposure Check
    debug_params = [k for k in query_params.keys() if _DEBUG_PARAM_PATTERN.match(k)]
    body_json_for_debug = None
    if body:
        try:
            body_json_for_debug = json.loads(body)
        except Exception:
            body_json_for_debug = None
    if isinstance(body_json_for_debug, dict):
        debug_params.extend(
            [k for k in body_json_for_debug.keys() if _DEBUG_PARAM_PATTERN.match(k)]
        )

    if debug_params:
        suggestions.append({
            "vulnerability_focus": "Mass Assignment & Property Tampering",
            "severity_potential": "MEDIUM",
            "confidence": "MEDIUM",
            "trigger_reason": f"Debug/verbose flag parameter observed ({', '.join(debug_params[:3])}); may expose hidden mutable fields for mass assignment.",
            "recommended_mcp_tool": "audit_mass_assignment",
            "tool_arguments": {"log_id": log_id}
        })

    # 13. Target Context-Aware Memory: Tech-Stack RAG & Golden Payload Matching
    resp_hdrs_lower = {str(k).lower(): str(v) for k, v in resp_hdrs.items()}
    server_hdr = resp_hdrs_lower.get("server", "").lower()
    powered_by = resp_hdrs_lower.get("x-powered-by", "").lower()
    cookie_hdr = resp_hdrs_lower.get("set-cookie", "").lower()

    detected_stack = None
    if "php" in powered_by or "phpsessid" in cookie_hdr or path.endswith(".php"):
        detected_stack = "PHP"
    elif "express" in powered_by or "node" in powered_by or "connect.sid" in cookie_hdr:
        detected_stack = "NODE"
    elif "django" in powered_by or "csrftoken" in cookie_hdr or "werkzeug" in server_hdr:
        detected_stack = "PYTHON"
    elif "spring" in powered_by or "jsessionid" in cookie_hdr or "tomcat" in server_hdr or path.endswith(".do") or path.endswith(".action"):
        detected_stack = "JAVA"
    elif "graphql" in path or is_graphql_path:
        detected_stack = "GRAPHQL"
    elif "rails" in powered_by or "rack" in powered_by:
        detected_stack = "RUBY"

    if detected_stack:
        try:
            from backend.payload_vault import get_golden_payloads_for_stack
            golden_vectors = get_golden_payloads_for_stack(detected_stack)
            if golden_vectors:
                top_vector = golden_vectors[0]
                suggestions.append({
                    "vulnerability_focus": f"Target Tech Stack Exploit: {detected_stack} ({top_vector['vuln_type']})",
                    "severity_potential": "HIGH",
                    "confidence": "HIGH",
                    "trigger_reason": f"Target environment fingerprinted as '{detected_stack}'. Injecting curated golden attack vector: {top_vector['description']}",
                    "recommended_mcp_tool": "fuzz_endpoint",
                    "tool_arguments": {
                        "url": url,
                        "method": clean_method,
                        "payload_list": [v["payload"] for v in golden_vectors[:4]]
                    },
                    "golden_payloads": golden_vectors
                })
        except Exception:
            pass

    # Dedupe: do not recommend the same tool against the same target twice.
    deduped: List[Dict[str, Any]] = []
    seen_tool_targets = set()
    for s in suggestions:
        tool_args = s.get("tool_arguments") or {}
        target = (
            tool_args.get("endpoint_url")
            or tool_args.get("target_url")
            or tool_args.get("test_url")
            or tool_args.get("url")
            or url
        )
        sig = (s.get("recommended_mcp_tool"), target)
        if sig in seen_tool_targets:
            continue
        seen_tool_targets.add(sig)
        deduped.append(s)

    return deduped


def get_project_attack_guidance(project: str = "default", limit: int = 15) -> Dict[str, Any]:
    """
    Scans recent project traffic and Attack Surface endpoints, evaluating heuristic signals
    and synthesizing prioritized testing actions for autonomous AI agents.
    """
    clean_proj = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        # Retrieve recent HTTP logs
        q_logs = db.query(HttpLog)
        if clean_proj != "all":
            q_logs = q_logs.filter(HttpLog.project == clean_proj)
        recent_logs = q_logs.order_by(HttpLog.id.desc()).limit(50).all()

        action_matrix: List[Dict[str, Any]] = []
        seen_signatures = set()

        for l in recent_logs:
            hdrs = {}
            if l.request_headers:
                try:
                    hdrs = json.loads(l.request_headers) if isinstance(l.request_headers, str) else l.request_headers
                except Exception:
                    pass
            resp_hdrs = {}
            if l.response_headers:
                try:
                    resp_hdrs = json.loads(l.response_headers) if isinstance(l.response_headers, str) else l.response_headers
                except Exception:
                    pass
            actions = suggest_attack_actions(
                url=l.url,
                method=l.method,
                headers=hdrs,
                body=l.request_body,
                response_status=l.status_code,
                response_body=l.response_body,
                log_id=l.id,
                response_headers=resp_hdrs
            )
            for act in actions:
                sig = f"{act['vulnerability_focus']}:{act['recommended_mcp_tool']}:{l.path}"
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    act["endpoint_path"] = l.path
                    act["log_id"] = l.id
                    action_matrix.append(act)
                    if len(action_matrix) >= limit:
                        break
            if len(action_matrix) >= limit:
                break

        # Group by vulnerability focus
        grouped_counts: Dict[str, int] = {}
        for act in action_matrix:
            foc = act["vulnerability_focus"]
            grouped_counts[foc] = grouped_counts.get(foc, 0) + 1

        return {
            "status": "success",
            "project": clean_proj,
            "total_recommended_actions": len(action_matrix),
            "focus_distribution": grouped_counts,
            "recommended_actions": action_matrix,
            "summary": f"Identified {len(action_matrix)} high-priority attack vectors ready for autonomous probing."
        }
    finally:
        db.close()
