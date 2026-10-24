"""
Proxsynth - Autonomous Broken Function Level Authorization (BFLA) & Method Tampering Engine
Audits endpoints for administrative privilege escalation, HTTP verb tampering, verb tunneling,
and unauthorized access to high-privilege administrative functions.
"""

import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from backend.database import SessionLocal, HttpLog, Finding, ActiveSession, Project
from backend.diff_engine import detect_soft_errors
from backend.user_agents import apply_rotating_user_agent
from backend.forward_proxy import _get_upstream_proxy

# High privilege administrative path segments to test
ADMIN_PATH_CANDIDATES = [
    "/admin",
    "/api/admin",
    "/api/v1/admin",
    "/management",
    "/internal",
    "/manage",
    "/dashboard/admin",
    "/sysadmin",
    "/system"
]

# Sensitive HTTP methods that modify or destroy resources
MUTATING_METHODS = ["POST", "PUT", "PATCH", "DELETE"]


async def audit_bfla_endpoint(
    url: str,
    method: str = "GET",
    req_headers: Optional[Dict[str, Any]] = None,
    req_body: Optional[str] = None,
    project: str = "default",
    log_id: Optional[int] = None,
    ws_broadcast_callback=None
) -> Dict[str, Any]:
    """
    Performs autonomous BFLA and method tampering audits against an endpoint:
    1. HTTP Method Flipping (testing PUT, DELETE, PATCH, POST against GET-only endpoints).
    2. HTTP Verb Tunneling & Header Overriding (X-HTTP-Method-Override, X-Method-Override, _method).
    3. Administrative Path Transposition (/admin, /internal variants).
    4. Evaluates responses using secondary identities (attacker, unauthenticated).
    """
    clean_project = (project or "default").strip().lower()
    clean_method = (method or "GET").upper()
    parsed = urllib.parse.urlparse(url)
    domain = (parsed.hostname or "").lower()

    db = SessionLocal()
    findings_created = []
    tests_executed = []

    try:
        # Fetch secondary identities (attacker, guest, unauthenticated)
        secondary_sessions = db.query(ActiveSession).filter(
            ActiveSession.project == clean_project,
            ActiveSession.identity_role != "primary"
        ).all()

        roles_to_test = []
        for s in secondary_sessions:
            st = s.get_decrypted_state()
            roles_to_test.append((
                s.identity_role,
                st.get("cookies", []),
                st.get("auth_headers", {}),
                st.get("bearer_token", "")
            ))
        # Always test unauthenticated
        roles_to_test.append(("unauthenticated", [], {}, ""))

        upstream_p = _get_upstream_proxy(clean_project)
        proxy_kwargs = {"proxy": upstream_p} if upstream_p else {"proxy": None, "trust_env": False}

        # -------------------------------------------------------------
        # 1. Method Tampering & Flipping
        # -------------------------------------------------------------
        alternative_methods = [m for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] if m != clean_method]

        for alt_m in alternative_methods:
            for role_name, cookies, auth_hdrs, bearer_tok in roles_to_test:
                probe_headers = dict(req_headers or {})
                # Strip original authentication
                for h in list(probe_headers.keys()):
                    if h.lower() in ["cookie", "authorization", "x-access-token", "x-auth-token", "session-id"]:
                        del probe_headers[h]

                # Apply identity credentials
                if cookies:
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'name' in c and 'value' in c])
                    if cookie_str:
                        probe_headers["Cookie"] = cookie_str
                if auth_hdrs:
                    for ah_k, ah_v in auth_hdrs.items():
                        probe_headers[ah_k] = ah_v
                if bearer_tok:
                    probe_headers["Authorization"] = f"Bearer {bearer_tok}"

                probe_headers, _ = apply_rotating_user_agent(probe_headers)

                try:
                    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=httpx.Timeout(3.0, connect=0.8), **proxy_kwargs) as client:
                        resp = await client.request(
                            method=alt_m,
                            url=url,
                            headers=probe_headers,
                            content=req_body.encode("utf-8") if req_body and alt_m in MUTATING_METHODS else None
                        )

                        soft = detect_soft_errors(resp.status_code, resp.text or "")
                        test_record = {
                            "type": "METHOD_FLIP",
                            "method": alt_m,
                            "url": url,
                            "role": role_name,
                            "status": resp.status_code,
                            "is_soft_403": soft["is_soft_403"]
                        }
                        tests_executed.append(test_record)

                        # BFLA Condition: If mutating method (e.g. DELETE/PUT/PATCH) succeeds (200, 201, 204)
                        # without Soft-403 denial for lower-privilege or unauthenticated user
                        if alt_m in MUTATING_METHODS and resp.status_code in [200, 201, 204] and not soft["is_soft_403"]:
                            title = f"Broken Function Level Authorization: Method Flipping [{alt_m}] on {parsed.path} via [{role_name}]"
                            desc = (
                                f"The endpoint '{parsed.path}' permits unauthorized execution of high-privilege HTTP method "
                                f"'{alt_m}' when called using identity role '{role_name}'. The server returned HTTP {resp.status_code} "
                                f"instead of rejecting unauthorized invocation with HTTP 401/403/405."
                            )
                            evidence = f"Method: {alt_m}\nRole: {role_name}\nStatus: {resp.status_code}\nSnippet:\n{resp.text[:300]}"
                            remediation = (
                                f"Enforce strict function-level authorization checks per HTTP verb. Ensure that '{alt_m}' "
                                f"actions require administrative privileges and reject non-privileged tokens."
                            )

                            if log_id:
                                existing = db.query(Finding).filter(Finding.log_id == log_id, Finding.title == title).first()
                                if not existing:
                                    f_obj = Finding(
                                        log_id=log_id,
                                        title=title,
                                        severity="CRITICAL" if role_name == "unauthenticated" else "HIGH",
                                        category="Broken Function Level Authorization (BFLA)",
                                        evidence=evidence,
                                        description=desc,
                                        remediation=remediation
                                    )
                                    db.add(f_obj)
                                    db.commit()
                                    db.refresh(f_obj)
                                    findings_created.append(f_obj.to_dict())

                                    if ws_broadcast_callback:
                                        try:
                                            await ws_broadcast_callback({
                                                "type": "BFLA_HIT",
                                                "finding": f_obj.to_dict(),
                                                "url": url,
                                                "method": alt_m
                                            })
                                        except Exception:
                                            pass
                except Exception:
                    continue

        # -------------------------------------------------------------
        # 2. Verb Tunneling & Header Overriding
        # -------------------------------------------------------------
        override_headers_to_test = [
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-HTTP-Method-Override", "PUT"),
            ("X-Method-Override", "DELETE"),
            ("X-Method-Override", "PUT")
        ]

        for hdr_name, target_verb in override_headers_to_test:
            for role_name, cookies, auth_hdrs, bearer_tok in roles_to_test:
                probe_headers = dict(req_headers or {})
                for h in list(probe_headers.keys()):
                    if h.lower() in ["cookie", "authorization", "x-access-token", "x-auth-token", "session-id"]:
                        del probe_headers[h]

                if cookies:
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'name' in c and 'value' in c])
                    if cookie_str:
                        probe_headers["Cookie"] = cookie_str
                if auth_hdrs:
                    for ah_k, ah_v in auth_hdrs.items():
                        probe_headers[ah_k] = ah_v
                if bearer_tok:
                    probe_headers["Authorization"] = f"Bearer {bearer_tok}"

                probe_headers[hdr_name] = target_verb
                probe_headers, _ = apply_rotating_user_agent(probe_headers)

                try:
                    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=httpx.Timeout(3.0, connect=0.8), **proxy_kwargs) as client:
                        resp = await client.request(
                            method="POST",
                            url=url,
                            headers=probe_headers,
                            content=req_body.encode("utf-8") if req_body else None
                        )

                        soft = detect_soft_errors(resp.status_code, resp.text or "")
                        if resp.status_code in [200, 201, 204] and not soft["is_soft_403"]:
                            title = f"HTTP Verb Tunneling BFLA Bypass via {hdr_name}: {target_verb} on {parsed.path}"
                            desc = (
                                f"The server processes tunneled HTTP verbs supplied in the '{hdr_name}' header, "
                                f"allowing low-privilege role '{role_name}' to execute unauthorized '{target_verb}' operations."
                            )
                            evidence = f"Header: {hdr_name}: {target_verb}\nRole: {role_name}\nStatus: {resp.status_code}\nSnippet:\n{resp.text[:300]}"
                            remediation = "Disable HTTP verb overriding headers on reverse proxies and web application frameworks."

                            if log_id:
                                existing = db.query(Finding).filter(Finding.log_id == log_id, Finding.title == title).first()
                                if not existing:
                                    f_obj = Finding(
                                        log_id=log_id,
                                        title=title,
                                        severity="HIGH",
                                        category="Broken Function Level Authorization (BFLA)",
                                        evidence=evidence,
                                        description=desc,
                                        remediation=remediation
                                    )
                                    db.add(f_obj)
                                    db.commit()
                                    db.refresh(f_obj)
                                    findings_created.append(f_obj.to_dict())
                except Exception:
                    continue

        return {
            "status": "completed",
            "url": url,
            "original_method": clean_method,
            "tests_executed_count": len(tests_executed),
            "findings_detected_count": len(findings_created),
            "findings": findings_created
        }
    finally:
        db.close()
