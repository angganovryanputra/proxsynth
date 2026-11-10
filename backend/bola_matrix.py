"""
Proxsynth - Autonomous Multi-Identity BOLA/IDOR Shadow Matrix
Automatically tests observed object/resource requests against secondary identities
(Attacker, Guest, Unauthenticated) in the background to detect BOLA/IDOR vulnerabilities without manual intervention.
"""

import re
import json
import asyncio
import difflib
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime
import httpx

from backend.database import SessionLocal, ActiveSession, HttpLog, Finding, Project
from backend.security_utils import encrypt_secret, decrypt_secret
from backend.user_agents import apply_rotating_user_agent
from backend.diff_engine import detect_soft_errors, clean_dynamic_tokens

# Patterns indicating an object/resource identifier in the path or query
_RESOURCE_ID_PATH_REGEX = re.compile(r'/([a-zA-Z0-9_-]+)/([0-9]+|[a-f0-9-]{8,36})(?:/|$|\?)', re.IGNORECASE)
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


def _bola_access_verdict(orig_body: str, shadow_body: str, res_id: str, res_status: int) -> Dict[str, Any]:
    """
    Decides whether a shadow-identity 2xx response is a *real* BOLA hit rather than a
    public endpoint or the shadow identity's own data. The old heuristic flagged any 200
    without a denial keyword, producing false positives on public resources. This oracle:
      1. rejects soft-denials (200 bodies that actually say unauthorized / not found),
      2. measures how similar the shadow body is to the legitimate owner's body
         (normalized to ignore dynamic tokens like CSRF/UUIDs/timestamps),
      3. checks whether the requested object id is echoed back in the shadow body.
    A hit requires the shadow identity to have received substantially the OWNER'S object
    data — the defining property of BOLA/IDOR.
    """
    shadow_body = shadow_body or ""
    orig_body = orig_body or ""
    body_lower = shadow_body.lower()

    soft = detect_soft_errors(res_status, shadow_body)
    if soft.get("is_soft_403") or soft.get("is_soft_404"):
        return {"is_bola": False, "confidence": 0.0, "similarity": 0.0, "echo": False,
                "reason": "Shadow response is a soft-denial (2xx body signals unauthorized/not-found)."}

    if any(k in body_lower for k in _ERROR_DENIAL_KEYWORDS):
        return {"is_bola": False, "confidence": 0.0, "similarity": 0.0, "echo": False,
                "reason": "Shadow response contains an explicit access-denial phrase."}

    if len(shadow_body.strip()) < 30:
        return {"is_bola": False, "confidence": 0.0, "similarity": 0.0, "echo": False,
                "reason": "Shadow response is too small to contain the owner's object data."}

    na = clean_dynamic_tokens(orig_body[:150000])
    nb = clean_dynamic_tokens(shadow_body[:150000])
    similarity = round(difflib.SequenceMatcher(None, na, nb).ratio(), 3) if (na and nb) else 0.0
    echo = bool(res_id) and (res_id.lower() in body_lower)

    # Same-schema JSON for two different users already scores ~0.7, so a pure-similarity
    # hit needs to be near-identical (>=0.85). The object-id echo is the stronger signal:
    # the owner's id reflected in the shadow body means the owner's record itself leaked.
    if similarity >= 0.85 or (echo and similarity >= 0.3):
        conf = min(0.95, 0.6 + similarity * 0.3 + (0.1 if echo else 0.0))
        reason = (
            f"Shadow identity received data {int(similarity * 100)}% similar to the owner's response"
            + (" and the requested object id is echoed back" if echo else "")
            + " — the owner's object leaked across identities."
        )
        return {"is_bola": True, "confidence": round(conf, 2), "similarity": similarity, "echo": echo, "reason": reason}

    return {"is_bola": False, "confidence": round(0.3 + similarity * 0.3, 2), "similarity": similarity, "echo": echo,
            "reason": (f"Shadow identity got HTTP {res_status} but the body is only {int(similarity * 100)}% "
                       "similar to the owner's — likely its own or empty data, not the owner's object.")}


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

    # Resource id under test (for the echo check in the similarity oracle)
    _rid_match = _RESOURCE_ID_PATH_REGEX.search(parsed.path)
    res_id = _rid_match.group(2) if _rid_match else ""
    if not res_id and parsed.query:
        _rid_q = _RESOURCE_ID_PARAM_REGEX.search(parsed.query)
        res_id = _rid_q.group(2) if _rid_q else ""

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
                    verdict = _bola_access_verdict(orig_body, res_body, res_id, res_status)
                    if verdict["is_bola"]:
                        # Confirmed via the response-similarity oracle (not merely a 200 status)
                        evidence_str = (
                            f"Owner (primary): HTTP {orig_status}, {len(orig_body)} bytes\n"
                            f"Shadow [{role_name.upper()}]: HTTP {res_status}, {len(res_body)} bytes\n"
                            f"Body similarity to owner: {int(verdict['similarity'] * 100)}% | object id echoed: {verdict['echo']} | confidence: {verdict['confidence']}\n"
                            f"Verdict: {verdict['reason']}\n"
                            f"Response snippet:\n{res_body[:300]}"
                        )

                        severity = "CRITICAL" if role_name == "unauthenticated" else "HIGH"
                        title = f"Broken Object Level Authorization (BOLA/IDOR) on {parsed.path} via [{role_name}]"
                        description = (
                            f"Endpoint '{url}' returned the owner's object data (HTTP {res_status}, "
                            f"{int(verdict['similarity'] * 100)}% similar to the legitimate owner response) when "
                            f"replayed with identity role '{role_name}', instead of rejecting with HTTP 401/403. "
                            f"This confirms broken object-level authorization."
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
                                finding_dict["confidence"] = verdict["confidence"]
                                finding_dict["similarity"] = verdict["similarity"]

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


# ============================================================================
# UNIFIED BROKEN ACCESS CONTROL (BAC) AUDIT — BOLA / IDOR / BFLA
# ============================================================================

# Privilege ranking of identity roles (higher = more privileged). Used to pick
# valid lower-privilege actors for vertical (BFLA) escalation tests.
_PRIV_RANK = {
    "unauthenticated": 0, "anonymous": 0, "guest": 1, "public": 1,
    "viewer": 2, "reader": 2, "user": 3, "customer": 3, "member": 3,
    "attacker": 3, "victim": 3, "editor": 4, "author": 4,
    "manager": 5, "staff": 5, "operator": 5, "primary": 5,
    "admin": 9, "administrator": 9, "superadmin": 10, "root": 10,
}


def _priv_rank(role: str) -> int:
    return _PRIV_RANK.get((role or "").strip().lower(), 3)


# Paths that expose privileged / function-level operations (BFLA candidates)
_PRIVILEGED_FUNC_REGEX = re.compile(
    r'/(admin|administrator|manage|management|internal|console|config|settings|'
    r'roles?|permissions?|privileges?|approve|grant|revoke|'
    r'promote|demote|disable|enable|ban|suspend|audit|system|billing|payouts?)'
    r'(?:/|$|\?)', re.IGNORECASE
)


def classify_bac_vectors(url: str, method: str, path: str = "", req_body: str = "") -> List[str]:
    """Decide which Broken Access Control tests a captured flow warrants:
    BOLA (object id present), IDOR (numeric/enumerable id), BFLA (privileged
    function or state-changing mutation)."""
    m = (method or "GET").upper()
    p = path or urllib.parse.urlparse(url).path
    vectors: List[str] = []
    if is_candidate_for_bola(url, m, req_body):
        vectors.append("BOLA")
        rid = _RESOURCE_ID_PATH_REGEX.search(urllib.parse.urlparse(url).path)
        if rid and rid.group(2).isdigit():
            vectors.append("IDOR")
    if _PRIVILEGED_FUNC_REGEX.search(p) or m in ("DELETE", "PUT", "PATCH"):
        vectors.append("BFLA")
    return list(dict.fromkeys(vectors))


def _bfla_access_verdict(actor_role: str, res_status: int, res_body: str, state_changing: bool) -> Dict[str, Any]:
    """Vertical-escalation oracle: a *lower-privileged* identity that performs a
    privileged function (2xx, no denial) is BFLA."""
    if _priv_rank(actor_role) > 3:
        return {"is_vuln": False, "confidence": 0.0, "reason": "Actor is not a lower-privileged identity."}
    if not (200 <= (res_status or 0) < 300):
        return {"is_vuln": False, "confidence": 0.0, "reason": f"Privileged function correctly rejected the actor (HTTP {res_status})."}
    body = res_body or ""
    soft = detect_soft_errors(res_status, body)
    if soft.get("is_soft_403") or soft.get("is_soft_404"):
        return {"is_vuln": False, "confidence": 0.0, "reason": "The 2xx body is actually a soft-denial."}
    if any(k in body.lower() for k in _ERROR_DENIAL_KEYWORDS):
        return {"is_vuln": False, "confidence": 0.0, "reason": "Response contains an explicit denial phrase."}
    conf = 0.9 if actor_role.lower() == "unauthenticated" else 0.82
    if state_changing:
        conf = min(0.95, conf + 0.05)
    return {"is_vuln": True, "confidence": round(conf, 2),
            "reason": f"Lower-privileged identity '{actor_role}' executed the privileged function (HTTP {res_status}, no denial)."}


def _apply_identity_headers(req_headers: Dict[str, Any], cookies, auth_hdrs, bearer_tok) -> Dict[str, Any]:
    """Build request headers for a replay under a different identity: strip the original
    auth, apply the candidate identity's creds, rotate the User-Agent."""
    h = {k: v for k, v in (req_headers or {}).items()
         if k.lower() not in ("cookie", "authorization", "x-access-token", "x-auth-token", "session-id")}
    if cookies:
        cs = "; ".join(f"{c['name']}={c['value']}" for c in cookies if 'name' in c and 'value' in c)
        if cs:
            h["Cookie"] = cs
    for ah_k, ah_v in (auth_hdrs or {}).items():
        h[ah_k] = ah_v
    if bearer_tok:
        h["Authorization"] = f"Bearer {bearer_tok}"
    h, _ = apply_rotating_user_agent(h, force_rotate=True)
    return h


def _bac_identities(project: str, domain: str) -> List[tuple]:
    """Secondary identities registered for the domain, plus an implicit unauthenticated one."""
    out: List[tuple] = []
    db = SessionLocal()
    try:
        rows = db.query(ActiveSession).filter(
            ActiveSession.project == project,
            ActiveSession.identity_role != "primary"
        ).all()
        for s in rows:
            stored = (s.domain or "").lower().split(":")[0].strip("/")
            if not stored:
                continue
            if (domain == stored or domain.endswith("." + stored)
                    or stored.endswith("." + domain) or (stored in domain and len(stored) > 3)):
                st = s.get_decrypted_state()
                out.append((s.identity_role, st.get("cookies", []), st.get("auth_headers", {}), st.get("bearer_token", "")))
    finally:
        db.close()
    out.append(("unauthenticated", [], {}, ""))
    return out


async def _replay_once(method: str, url: str, headers: Dict[str, Any], body: str) -> tuple:
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0, proxy=None, trust_env=False) as client:
        res = await client.request(method=method, url=url, headers=headers, content=body if body else None)
        return res.status_code, (res.text or "")


def _record_bac_finding(log_id, title, severity, category, evidence, description, remediation, confidence) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        log_obj = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if log_obj:
            log_obj.flag_status = "CONFIRMED" if confidence >= 0.7 else "POTENTIAL"
        existing = db.query(Finding).filter(Finding.log_id == log_id, Finding.title == title).first()
        if existing:
            db.commit()
            d = existing.to_dict(); d["confidence"] = confidence
            return d
        f = Finding(log_id=log_id, title=title, severity=severity, category=category,
                    evidence=evidence, description=description, remediation=remediation)
        db.add(f); db.commit(); db.refresh(f)
        d = f.to_dict(); d["confidence"] = confidence
        return d
    finally:
        db.close()


async def audit_bac_flow(log_id: int, project: str = "default", enumerate_idor: bool = True,
                         ws_broadcast_callback=None) -> Dict[str, Any]:
    """
    Specific, on-demand Broken Access Control audit of a single captured flow.
    Classifies which of BOLA / IDOR / BFLA apply, replays the flow under every registered
    secondary identity (and unauthenticated), decides validity per vector with a confidence,
    optionally enumerates adjacent numeric ids (IDOR), and returns a machine-actionable
    decision an LLM can act on directly.
    """
    db = SessionLocal()
    try:
        log = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if not log:
            return {"status": "error", "decision": "NOT_FOUND", "message": f"Log #{log_id} not found."}
        url = log.url
        method = (log.method or "GET").upper()
        path = log.path or urllib.parse.urlparse(url).path
        req_body = log.request_body or ""
        orig_status = log.status_code or 0
        orig_body = log.response_body or ""
        try:
            req_headers = json.loads(log.request_headers) if log.request_headers else {}
        except Exception:
            req_headers = {}
    finally:
        db.close()

    vectors = classify_bac_vectors(url, method, path, req_body)
    domain = (urllib.parse.urlparse(url).hostname or "").lower()

    if not vectors:
        return {"status": "success", "log_id": log_id, "decision": "NOT_APPLICABLE", "vectors_tested": [],
                "reason": "No object id or privileged function in this flow.",
                "recommendation": "Capture a flow that reads an object by id (e.g. /orders/5567) or calls a management/admin function."}
    if not (200 <= orig_status < 300):
        return {"status": "success", "log_id": log_id, "decision": "INCONCLUSIVE", "vectors_candidate": vectors,
                "reason": f"Original request returned HTTP {orig_status}; a successful (2xx) baseline is needed to compare against.",
                "recommendation": "Re-capture the flow with a valid privileged/owner session so the baseline is 2xx."}

    rid = _RESOURCE_ID_PATH_REGEX.search(urllib.parse.urlparse(url).path)
    res_id = rid.group(2) if rid else ""
    state_changing = method in ("POST", "PUT", "PATCH", "DELETE")

    identities = _bac_identities(project, domain)
    findings: List[Dict[str, Any]] = []
    tested: List[str] = []

    for role, cookies, auth_hdrs, bearer in identities:
        headers = _apply_identity_headers(req_headers, cookies, auth_hdrs, bearer)
        try:
            st, body = await _replay_once(method, url, headers, req_body)
        except Exception:
            continue
        tested.append(role)

        if "BOLA" in vectors or "IDOR" in vectors:
            v = _bola_access_verdict(orig_body, body, res_id, st)
            if v["is_bola"]:
                sev = "CRITICAL" if role == "unauthenticated" else "HIGH"
                vec = "IDOR" if ("IDOR" in vectors and res_id.isdigit()) else "BOLA"
                title = f"BOLA/IDOR on {path} via [{role}]"
                fd = _record_bac_finding(
                    log_id, title, sev, "Broken Object Level Authorization (BOLA/IDOR)",
                    f"Owner HTTP {orig_status} ({len(orig_body)}b) vs [{role}] HTTP {st} ({len(body)}b); "
                    f"similarity {int(v['similarity'] * 100)}%, object-id echoed {v['echo']}, confidence {v['confidence']}.\n{body[:300]}",
                    f"Identity '{role}' retrieved the owner's object ({int(v['similarity'] * 100)}% similar) instead of being denied.",
                    "Enforce object-level ownership checks server-side before returning or mutating records.", v["confidence"])
                findings.append({"vector": vec, "role": role, "confidence": v["confidence"], "finding": fd})

        if "BFLA" in vectors:
            v = _bfla_access_verdict(role, st, body, state_changing)
            if v["is_vuln"]:
                sev = "CRITICAL" if role == "unauthenticated" else "HIGH"
                title = f"BFLA (function-level escalation) on {path} via [{role}]"
                fd = _record_bac_finding(
                    log_id, title, sev, "Broken Function Level Authorization (BFLA)",
                    f"[{role}] (priv rank {_priv_rank(role)}) executed {method} {path} -> HTTP {st}. {v['reason']}\n{body[:300]}",
                    f"Lower-privileged identity '{role}' executed a privileged function that should require elevated authorization.",
                    "Enforce role/permission checks on every privileged function server-side, not only in the UI.", v["confidence"])
                findings.append({"vector": "BFLA", "role": role, "confidence": v["confidence"], "finding": fd})

    # IDOR sequential enumeration (numeric id) using the first authenticated secondary identity
    enum_hits: List[Dict[str, Any]] = []
    if enumerate_idor and "IDOR" in vectors and res_id.isdigit():
        try:
            base = int(res_id)
            attacker = next((i for i in identities if i[0] != "unauthenticated"), None)
            if attacker:
                headers = _apply_identity_headers(req_headers, attacker[1], attacker[2], attacker[3])
                for delta in (-1, 1, 2):
                    cand = base + delta
                    if cand < 0:
                        continue
                    cand_url = url.replace(f"/{res_id}", f"/{cand}", 1)
                    try:
                        st, body = await _replay_once(method, cand_url, headers, req_body)
                    except Exception:
                        continue
                    if 200 <= st < 300 and len(body) > 30 and not any(k in body.lower() for k in _ERROR_DENIAL_KEYWORDS):
                        enum_hits.append({"id": cand, "status": st, "bytes": len(body)})
        except Exception:
            pass

    for fd in findings:
        if ws_broadcast_callback and fd.get("finding"):
            try:
                await ws_broadcast_callback({"type": "BOLA_HIT", "finding": fd["finding"], "url": url,
                                             "role": fd["role"], "vector": fd["vector"]})
            except Exception:
                pass

    vulnerable = len(findings) > 0 or len(enum_hits) >= 2
    best_conf = max([f["confidence"] for f in findings], default=(0.75 if len(enum_hits) >= 2 else 0.0))
    decision = "VULNERABLE" if vulnerable else "LIKELY_SECURE"
    recommendation = (
        "Broken access control reproduced — report it and confirm impact (reading/modifying another "
        "tenant's data or executing a privileged action)."
        if vulnerable else
        "No unauthorized access reproduced across the tested identities. Register a true low-privilege "
        "identity for deeper BFLA coverage, or treat this flow as access-controlled."
    )
    first_fid = findings[0]["finding"].get("id") if (findings and findings[0].get("finding")) else None
    result = {
        "status": "success", "log_id": log_id, "decision": decision, "confidence": round(best_conf, 2),
        "vectors_tested": vectors, "identities_tested": tested,
        "findings_count": len(findings), "findings": findings,
        "idor_enumeration": enum_hits, "recommendation": recommendation,
    }
    if vulnerable and first_fid:
        result["next_action"] = {
            "tool": "proxsynth_verify_and_export",
            "arguments": {"finding_id": first_fid, "project": project},
            "rationale": "Confirmed broken-access-control finding — generate the reproducible PoC and dossier.",
            "confidence": round(best_conf, 2),
            "auto_executable": best_conf >= 0.7,
        }
    return result


def get_bola_matrix_data(project: str = "default") -> Dict[str, Any]:
    """
    Aggregates candidate object-level endpoints and cross-tabulates them against all active
    identity roles (e.g. primary, attacker, victim, unauthenticated) to build the access control matrix.
    """
    clean_project = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        q = db.query(HttpLog)
        if clean_project != "all":
            q = q.filter(HttpLog.project == clean_project)
        
        logs = q.order_by(HttpLog.id.desc()).limit(200).all()

        # Query all known roles for project
        sess_query = db.query(ActiveSession)
        if clean_project != "all":
            sess_query = sess_query.filter(ActiveSession.project == clean_project)
        sessions = sess_query.all()
        known_roles = set(["primary", "unauthenticated"])
        for s in sessions:
            if s.identity_role:
                known_roles.add(s.identity_role.lower())
        
        # Ensure standard ordering: primary first, unauthenticated last
        role_list = ["primary"]
        for r in sorted(known_roles):
            if r not in ["primary", "unauthenticated"]:
                role_list.append(r)
        if "unauthenticated" not in role_list:
            role_list.append("unauthenticated")

        # Query existing BOLA findings for project
        findings_query = db.query(Finding).filter(Finding.category.like("%BOLA%") | Finding.category.like("%IDOR%"))
        all_findings = findings_query.all()
        finding_by_log_id = {f.log_id: f for f in all_findings}

        candidates = []
        seen_paths = set()

        for l in logs:
            req_body = l.request_body or ""
            if not is_candidate_for_bola(l.url, l.method, req_body):
                continue

            path_key = f"{l.method}:{l.path}"
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)

            parsed = urllib.parse.urlparse(l.url)
            
            # Extract resource ID
            res_match = _RESOURCE_ID_PATH_REGEX.search(parsed.path)
            res_id = res_match.group(2) if res_match else ""
            if not res_id and parsed.query:
                param_match = _RESOURCE_ID_PARAM_REGEX.search(parsed.query)
                res_id = param_match.group(2) if param_match else ""

            # Check if this log has an existing BOLA finding
            matched_finding = finding_by_log_id.get(l.id)
            vuln_role = "attacker"
            if matched_finding:
                for r in role_list:
                    if f"[{r}]" in (matched_finding.title or "").lower():
                        vuln_role = r
                        break

            # Build access map per role
            access_map = {}
            for r in role_list:
                if r == "primary":
                    access_map[r] = {
                        "status": l.status_code or 200,
                        "state": "ALLOWED",
                        "summary": "Legitimate resource owner access"
                    }
                elif matched_finding and r == vuln_role:
                    access_map[r] = {
                        "status": 200,
                        "state": "VULNERABLE",
                        "summary": f"BOLA Confirmed ({matched_finding.severity})",
                        "finding_id": matched_finding.id
                    }
                else:
                    access_map[r] = {
                        "status": None,
                        "state": "UNTESTED",
                        "summary": "Pending shadow replay audit"
                    }

            candidates.append({
                "log_id": l.id,
                "project": l.project or clean_project,
                "method": l.method,
                "url": l.url,
                "path": l.path or parsed.path,
                "host": l.host or parsed.netloc,
                "resource_id": res_id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else "",
                "status_code": l.status_code,
                "access": access_map
            })

        return {
            "project": clean_project,
            "roles": role_list,
            "total_candidates": len(candidates),
            "vulnerabilities_detected": len([c for c in candidates if any(a.get("state") == "VULNERABLE" for a in c["access"].values())]),
            "candidates": candidates
        }
    finally:
        db.close()


async def run_full_bola_matrix_scan(project: str = "default", ws_broadcast_callback=None) -> Dict[str, Any]:
    """
    Executes automated BOLA shadow replay scans across all observed candidate endpoints in the project.
    """
    clean_project = (project or "default").strip().lower()
    db = SessionLocal()
    candidates_to_test = []
    try:
        q = db.query(HttpLog)
        if clean_project != "all":
            q = q.filter(HttpLog.project == clean_project)
        logs = q.order_by(HttpLog.id.desc()).limit(100).all()
        for l in logs:
            if is_candidate_for_bola(l.url, l.method, l.request_body or ""):
                req_headers = {}
                if l.request_headers:
                    try:
                        req_headers = json.loads(l.request_headers)
                    except Exception:
                        pass
                candidates_to_test.append({
                    "id": l.id,
                    "project": l.project or clean_project,
                    "url": l.url,
                    "method": l.method,
                    "headers": req_headers,
                    "body": l.request_body or "",
                    "orig_status": l.status_code or 200,
                    "orig_body": l.response_body or ""
                })
    finally:
        db.close()

    scanned_count = 0
    vulns_found = 0

    for c in candidates_to_test:
        scanned_count += 1
        finding = await execute_bola_shadow_replay(
            log_id=c["id"],
            project=c["project"],
            url=c["url"],
            method=c["method"],
            req_headers=c["headers"],
            req_body=c["body"],
            orig_status=c["orig_status"],
            orig_body=c["orig_body"],
            ws_broadcast_callback=ws_broadcast_callback
        )
        if finding:
            vulns_found += 1

    updated_matrix = get_bola_matrix_data(project=clean_project)
    return {
        "status": "success",
        "project": clean_project,
        "scanned_endpoints": scanned_count,
        "vulnerabilities_detected": vulns_found,
        "matrix": updated_matrix
    }
