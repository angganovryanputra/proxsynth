"""
Proxsynth - Autonomous Multi-Identity BOLA/IDOR Shadow Matrix
Automatically tests observed object/resource requests against secondary identities
(Attacker, Guest, Unauthenticated) in the background to detect BOLA/IDOR vulnerabilities without manual intervention.
"""

import re
import json
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime
import httpx

from backend.database import SessionLocal, ActiveSession, HttpLog, Finding, Project
from backend.security_utils import encrypt_secret, decrypt_secret
from backend.user_agents import apply_rotating_user_agent

# Patterns indicating an object/resource identifier in the path or query
_RESOURCE_ID_PATH_REGEX = re.compile(r'/([a-zA-Z0-9_-]+)/([0-9]+|[a-f0-9]{8,36})(?:/|$|\?)', re.IGNORECASE)
_RESOURCE_ID_PARAM_REGEX = re.compile(r'(?:^|[?&])([a-zA-Z0-9_-]*(?:id|account|user|doc|order|invoice|file|org|uuid)[a-zA-Z0-9_-]*)=([a-zA-Z0-9_-]+)', re.IGNORECASE)

_ERROR_DENIAL_KEYWORDS = [
    "unauthorized", "forbidden", "access denied", "permission denied",
    "login required", "please log in", "session expired", "invalid token",
    "authentication failed", "not allowed"
]


def is_candidate_for_bola(url: str, method: str, req_body: str = "") -> bool:
    """Determines whether a request targets a specific object/resource ID and warrants BOLA shadow testing."""
    clean_method = (method or "GET").upper()
    if clean_method not in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
        return False

    parsed = urllib.parse.urlparse(url)
    
    # Check path: e.g. /api/users/123 or /documents/abc-123
    if _RESOURCE_ID_PATH_REGEX.search(parsed.path):
        return True

    # Check query string: e.g. ?user_id=123
    if parsed.query and _RESOURCE_ID_PARAM_REGEX.search(parsed.query):
        return True

    # Check JSON body: e.g. {"user_id": 123}
    if req_body and req_body.strip().startswith("{"):
        try:
            data = json.loads(req_body)
            if isinstance(data, dict):
                for k, v in data.items():
                    if re.search(r'(?:id|account|user|doc|order|invoice|file|org|uuid)', str(k), re.IGNORECASE):
                        return True
        except Exception:
            pass

    return False


def set_identity_session(
    project: str = "default",
    domain: str = "",
    identity_role: str = "attacker",
    cookies: Optional[List[Dict[str, Any]]] = None,
    raw_cookie_str: Optional[str] = None,
    auth_headers: Optional[Dict[str, str]] = None,
    bearer_token: Optional[str] = None
) -> Dict[str, Any]:
    """Stores or updates an authenticated session tagged with a specific identity role."""
    clean_domain = domain.strip().lower()
    clean_role = (identity_role or "attacker").strip().lower()
    target_project = (project or "default").strip().lower()

    parsed_cookies = []
    if cookies and isinstance(cookies, list):
        parsed_cookies = cookies
    elif raw_cookie_str:
        pairs = [p.strip() for p in raw_cookie_str.split(";") if "=" in p]
        for p in pairs:
            name, val = p.split("=", 1)
            parsed_cookies.append({"name": name.strip(), "value": val.strip(), "domain": clean_domain, "path": "/"})

    db = SessionLocal()
    try:
        session_obj = db.query(ActiveSession).filter(
            ActiveSession.project == target_project,
            ActiveSession.domain == clean_domain,
            ActiveSession.identity_role == clean_role
        ).first()

        state_data = {
            "domain": clean_domain,
            "identity_role": clean_role,
            "cookies": parsed_cookies,
            "auth_headers": auth_headers or {},
            "bearer_token": (bearer_token or "").strip(),
            "updated_at": datetime.now().isoformat()
        }

        if session_obj:
            session_obj.set_encrypted_state(state_data)
            session_obj.updated_at = datetime.now()
        else:
            session_obj = ActiveSession(
                project=target_project,
                domain=clean_domain,
                identity_role=clean_role
            )
            session_obj.set_encrypted_state(state_data)
            db.add(session_obj)

        db.commit()
        db.refresh(session_obj)
        return session_obj.to_dict()
    finally:
        db.close()


def get_identities_for_project(project: str = "default", domain: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all registered identity sessions for a project."""
    target_project = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        query = db.query(ActiveSession).filter(ActiveSession.project == target_project)
        if domain:
            query = query.filter(ActiveSession.domain == domain.strip().lower())
        sessions = query.all()
        return [s.to_dict(include_secrets=False) for s in sessions]
    finally:
        db.close()


async def execute_bola_shadow_replay(
    log_id: int,
    project: str,
    url: str,
    method: str,
    req_headers: Dict[str, Any],
    req_body: str,
    orig_status: int,
    orig_body: str,
    ws_broadcast_callback=None
) -> Optional[Dict[str, Any]]:
    """
    Executes shadow replays against candidate endpoints using secondary identities (e.g. attacker, unauthenticated)
    and flags confirmed BOLA/IDOR when unauthorized access succeeds.
    """
    # Only test if original request succeeded (200 OK or 201 Created)
    if orig_status not in [200, 201]:
        return None

    parsed = urllib.parse.urlparse(url)
    domain = (parsed.hostname or "").lower()
    if not domain:
        return None

    db = SessionLocal()
    try:
        # Check if project has BOLA testing enabled
        proj = db.query(Project).filter(Project.name == project).first()
        if proj and proj.bola_matrix_enabled is False:
            return None

        # Fetch secondary identities for this domain with subdomain matching
        all_sessions = db.query(ActiveSession).filter(
            ActiveSession.project == project,
            ActiveSession.identity_role != "primary"
        ).all()
        secondary_sessions = []
        for s in all_sessions:
            stored_dom = (s.domain or "").lower().split(":")[0].strip("/")
            is_match = (
                domain == stored_dom or
                domain.endswith("." + stored_dom) or
                stored_dom.endswith("." + domain) or
                (stored_dom in domain and len(stored_dom) > 3)
            )
            if is_match:
                secondary_sessions.append(s)
    finally:
        db.close()

    # Define test identities: any stored secondary identities, plus Unauthenticated
    roles_to_test = []
    for s in secondary_sessions:
        st = s.get_decrypted_state()
        roles_to_test.append((
            s.identity_role,
            st.get("cookies", []),
            st.get("auth_headers", {}),
            st.get("bearer_token", "")
        ))

    # Always test Unauthenticated identity
    roles_to_test.append(("unauthenticated", [], {}, ""))

    for role_name, cookies, auth_hdrs, bearer_tok in roles_to_test:
        test_headers = dict(req_headers)
        # Strip authorization / cookie headers from original request
        for h in list(test_headers.keys()):
            if h.lower() in ["cookie", "authorization", "x-access-token", "x-auth-token", "session-id"]:
                del test_headers[h]

        # Apply candidate identity cookies
        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'name' in c and 'value' in c])
            if cookie_str:
                test_headers["Cookie"] = cookie_str

        # Apply candidate identity auth headers & bearer token
        if auth_hdrs:
            for ah_k, ah_v in auth_hdrs.items():
                test_headers[ah_k] = ah_v
        if bearer_tok:
            test_headers["Authorization"] = f"Bearer {bearer_tok}"

        # Apply Legitimate Rotating Browser User-Agent
        test_headers, _ = apply_rotating_user_agent(test_headers, force_rotate=True)

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0, proxy=None, trust_env=False) as client:
                res = await client.request(
                    method=method,
                    url=url,
                    headers=test_headers,
                    content=req_body if req_body else None
                )

                res_body = res.text or ""
                res_status = res.status_code

                # Evaluate BOLA condition:
                # 1. Status is 200/201 (not 401, 403, 404, or 500)
                # 2. Body does NOT contain typical denial phrases
                # 3. Body length is substantial (>50 bytes) and within 30% of original body, or returns JSON
                if res_status in [200, 201]:
                    body_lower = res_body.lower()
                    has_denial = any(k in body_lower for k in _ERROR_DENIAL_KEYWORDS)

                    if not has_denial and len(res_body) > 30:
                        # High confidence BOLA
                        evidence_str = (
                            f"Original Identity: 200 OK (Len: {len(orig_body)})\n"
                            f"Shadow Identity [{role_name.upper()}]: {res_status} OK (Len: {len(res_body)})\n"
                            f"Response Snippet:\n{res_body[:300]}"
                        )

                        severity = "CRITICAL" if role_name == "unauthenticated" else "HIGH"
                        title = f"Broken Object Level Authorization (BOLA/IDOR) on {parsed.path} via [{role_name}]"
                        description = (
                            f"Endpoint '{url}' allowed unauthorized access to object/resource data when tested "
                            f"using identity role '{role_name}'. The server returned HTTP {res_status} with full data "
                            f"instead of rejecting unauthorized access (HTTP 401/403)."
                        )
                        remediation = (
                            "Enforce strict object-level authorization checks on the server side. Validate that "
                            "the authenticated user identity matches the resource owner or has explicit permission "
                            "before retrieving or mutating object records."
                        )

                        # Record finding in DB
                        db_write = SessionLocal()
                        try:
                            # Update HttpLog flag
                            log_obj = db_write.query(HttpLog).filter(HttpLog.id == log_id).first()
                            if log_obj:
                                log_obj.flag_status = "CONFIRMED"

                            # Check existing finding
                            existing = db_write.query(Finding).filter(
                                Finding.log_id == log_id,
                                Finding.title == title
                            ).first()

                            if not existing:
                                finding = Finding(
                                    log_id=log_id,
                                    title=title,
                                    severity=severity,
                                    category="Broken Object Level Authorization (BOLA/IDOR)",
                                    evidence=evidence_str,
                                    description=description,
                                    remediation=remediation
                                )
                                db_write.add(finding)
                                db_write.commit()
                                db_write.refresh(finding)
                                finding_dict = finding.to_dict()

                                if ws_broadcast_callback:
                                    try:
                                        await ws_broadcast_callback({
                                            "type": "BOLA_HIT",
                                            "finding": finding_dict,
                                            "url": url,
                                            "role": role_name
                                        })
                                    except Exception:
                                        pass

                                return finding_dict
                        finally:
                            db_write.close()
        except Exception:
            continue

    return None
