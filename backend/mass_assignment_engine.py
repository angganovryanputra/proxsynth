"""
Proxsynth - Autonomous Mass Assignment & Privilege Parameter Injection Engine
Audits mutation endpoints (POST, PUT, PATCH) by injecting administrative attributes
into JSON and Form payloads to detect over-posting and unauthorized privilege escalation.
"""

import json
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from backend.database import SessionLocal, HttpLog, Finding
from backend.diff_engine import detect_soft_errors
from backend.user_agents import apply_rotating_user_agent
from backend.forward_proxy import _get_upstream_proxy

# Privilege and administrative parameters to test for Mass Assignment
ADMIN_ATTRIBUTES = {
    "is_admin": True,
    "isAdmin": True,
    "role": "admin",
    "user_role": "superuser",
    "permissions": ["*"],
    "verified": True,
    "is_verified": True,
    "tier": "enterprise",
    "balance": 999999,
    "discount": 100,
    "org_id": 1,
    "plan": "unlimited"
}


async def audit_mass_assignment(
    log_id: int,
    custom_attributes: Optional[Dict[str, Any]] = None,
    project: str = "default",
    ws_broadcast_callback=None
) -> Dict[str, Any]:
    """
    Scans a captured mutation request for Mass Assignment (Over-Posting) vulnerabilities.
    Injects elevated privilege attributes into the payload and evaluates whether
    the server persists or reflects the elevated properties in its response.
    """
    clean_project = (project or "default").strip().lower()
    db = SessionLocal()
    findings_created = []

    try:
        log = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if not log:
            return {"status": "error", "message": f"HttpLog #{log_id} not found"}

        clean_method = (log.method or "POST").upper()
        if clean_method not in ["POST", "PUT", "PATCH"]:
            return {"status": "skipped", "message": f"Method {clean_method} is not a mutation endpoint"}

        req_body = (log.request_body or "").strip()
        parsed_json: Optional[Dict[str, Any]] = None
        is_json = False

        if req_body.startswith("{") or req_body.startswith("["):
            try:
                parsed_json = json.loads(req_body)
                if isinstance(parsed_json, dict):
                    is_json = True
            except Exception:
                pass

        # Prepare attributes to inject
        test_attributes = dict(ADMIN_ATTRIBUTES)
        if custom_attributes:
            test_attributes.update(custom_attributes)

        upstream_p = _get_upstream_proxy(clean_project)
        proxy_kwargs = {"proxy": upstream_p} if upstream_p else {"proxy": None, "trust_env": False}

        req_headers = {}
        if log.request_headers:
            try:
                req_headers = json.loads(log.request_headers)
            except Exception:
                pass

        injected_probes = []

        if is_json and parsed_json is not None:
            # Inject keys into existing JSON dictionary
            mutated_dict = dict(parsed_json)
            injected_keys = []
            for k, v in test_attributes.items():
                if k not in mutated_dict:
                    mutated_dict[k] = v
                    injected_keys.append(k)

            if injected_keys:
                injected_probes.append((
                    json.dumps(mutated_dict),
                    "application/json",
                    injected_keys,
                    mutated_dict
                ))
        elif "=" in req_body:
            # Form URL-Encoded
            params = urllib.parse.parse_qs(req_body)
            injected_keys = []
            for k, v in test_attributes.items():
                if k not in params:
                    params[k] = [str(v)]
                    injected_keys.append(k)
            if injected_keys:
                flat_params = {k: v[0] for k, v in params.items()}
                injected_probes.append((
                    urllib.parse.urlencode(flat_params),
                    "application/x-www-form-urlencoded",
                    injected_keys,
                    flat_params
                ))

        for mutated_body, content_type, keys_tested, injected_map in injected_probes:
            probe_headers = dict(req_headers)
            probe_headers["Content-Type"] = content_type
            probe_headers, _ = apply_rotating_user_agent(probe_headers)

            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=httpx.Timeout(3.0, connect=0.8), **proxy_kwargs) as client:
                    resp = await client.request(
                        method=clean_method,
                        url=log.url,
                        headers=probe_headers,
                        content=mutated_body.encode("utf-8")
                    )

                    resp_text = resp.text or ""
                    resp_status = resp.status_code
                    soft = detect_soft_errors(resp_status, resp_text)

                    # Evaluation:
                    # 1. Server returned 200/201 (success)
                    # 2. Not a soft error
                    # 3. Response body reflects one or more injected privilege keys with corresponding value
                    accepted_keys = []
                    if resp_status in [200, 201] and not soft["is_soft_403"]:
                        try:
                            resp_json = json.loads(resp_text)
                            if isinstance(resp_json, dict):
                                for k in keys_tested:
                                    if k in resp_json and str(resp_json[k]).lower() == str(injected_map[k]).lower():
                                        accepted_keys.append(f"{k}={resp_json[k]}")
                        except Exception:
                            # Substring check for form/text responses
                            for k in keys_tested:
                                pattern = f'"{k}":'
                                if pattern in resp_text:
                                    accepted_keys.append(k)

                    if accepted_keys:
                        title = f"Mass Assignment / Over-Posting on {log.path} ({', '.join(accepted_keys[:3])})"
                        desc = (
                            f"The mutation endpoint '{log.path}' inadvertently binds administrative properties into "
                            f"its internal model without strict DTO validation. The server accepted and reflected "
                            f"the following injected privilege attributes: {', '.join(accepted_keys)}."
                        )
                        evidence = (
                            f"Injected Payload Keys: {', '.join(keys_tested)}\n"
                            f"Confirmed Bound Properties: {', '.join(accepted_keys)}\n"
                            f"Response Status: {resp_status}\n"
                            f"Response Snippet:\n{resp_text[:350]}"
                        )
                        remediation = (
                            "Implement strict Data Transfer Object (DTO) schema validation. Never bind request "
                            "parameters directly to database or entity models. Use allowlists for accepted fields."
                        )

                        existing = db.query(Finding).filter(Finding.log_id == log.id, Finding.title == title).first()
                        if not existing:
                            finding = Finding(
                                log_id=log.id,
                                title=title,
                                severity="HIGH",
                                category="Mass Assignment / Over-Posting",
                                evidence=evidence,
                                description=desc,
                                remediation=remediation
                            )
                            db.add(finding)
                            db.commit()
                            db.refresh(finding)
                            findings_created.append(finding.to_dict())

                            if ws_broadcast_callback:
                                try:
                                    await ws_broadcast_callback({
                                        "type": "MASS_ASSIGNMENT_HIT",
                                        "finding": finding.to_dict(),
                                        "url": log.url,
                                        "accepted_keys": accepted_keys
                                    })
                                except Exception:
                                    pass
            except Exception:
                continue

        return {
            "status": "completed",
            "log_id": log_id,
            "url": log.url,
            "method": clean_method,
            "findings_count": len(findings_created),
            "findings": findings_created
        }
    finally:
        db.close()
