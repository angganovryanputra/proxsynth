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


def suggest_attack_actions(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, Any]] = None,
    body: Optional[str] = None,
    response_status: Optional[int] = None,
    response_body: Optional[str] = None,
    log_id: Optional[int] = None
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
            "tool_arguments": {"log_id": log_id} if log_id else {"endpoint_url": url}
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
                "endpoint_url": url,
                "privileged_role": "admin",
                "unprivileged_role": "user"
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
                    "tool_arguments": {
                        "endpoint_url": url,
                        "base_payload": parsed_body,
                        "method": clean_method
                    }
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
                "endpoint_url": url,
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
                "endpoint_url": url,
                "injection_param": inj_params[0],
                "vuln_type": "SQLI"
            }
        })

    return suggestions


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
            actions = suggest_attack_actions(
                url=l.url,
                method=l.method,
                headers=hdrs,
                body=l.request_body,
                response_status=l.status_code,
                response_body=l.response_body,
                log_id=l.id
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
