"""
PROXSYNTH - Session State Auto-Refresher
Monitors intercepted traffic for HTTP 401 Unauthorized or expired JWT / session indicators.
When expired, automatically replays recorded login/re-auth workflows, extracts fresh credentials,
updates proxy session state in real-time, and retries the original request transparently.
"""

import re
import json
import asyncio
import logging
from typing import Dict, Any, List, Optional
import httpx

from backend.database import SessionLocal, ActiveSession

logger = logging.getLogger("proxsynth.session_refresher")

# In-memory registry: key = f"{project}:{domain}"
_refresher_registry: Dict[str, Dict[str, Any]] = {}
_refresh_locks: Dict[str, asyncio.Lock] = {}


def _get_lock(key: str) -> asyncio.Lock:
    if key not in _refresh_locks:
        _refresh_locks[key] = asyncio.Lock()
    return _refresh_locks[key]


def configure_session_refresher(
    domain: str,
    login_url: str,
    login_method: str = "POST",
    login_headers: Optional[Dict[str, str]] = None,
    login_payload: Optional[str] = None,
    token_extractor: str = "access_token",
    extractor_type: str = "json",
    target_auth_header: str = "Authorization: Bearer {token}",
    target_cookie_name: Optional[str] = None,
    expiry_indicators: Optional[List[str]] = None,
    project: str = "default"
) -> Dict[str, Any]:
    """
    Registers or updates an automated re-authentication recipe for a specific target domain and project.
    """
    clean_domain = domain.strip().lower()
    clean_proj = (project or "default").strip().lower()
    key = f"{clean_proj}:{clean_domain}"

    indicators = expiry_indicators or [
        "token expired",
        "jwt expired",
        "token is expired",
        "invalid_token",
        "session expired",
        "session timeout",
        "unauthorized"
    ]

    hdrs = dict(login_headers or {})
    if "content-type" not in [k.lower() for k in hdrs.keys()] and login_payload and login_payload.strip().startswith("{"):
        hdrs["Content-Type"] = "application/json"

    cfg = {
        "domain": clean_domain,
        "project": clean_proj,
        "login_url": login_url.strip(),
        "login_method": login_method.strip().upper(),
        "login_headers": hdrs,
        "login_payload": login_payload or "",
        "token_extractor": token_extractor.strip(),
        "extractor_type": extractor_type.strip().lower(),  # "json", "header", or "cookie"
        "target_auth_header": target_auth_header.strip(),
        "target_cookie_name": target_cookie_name.strip() if target_cookie_name else None,
        "expiry_indicators": [i.lower() for i in indicators],
        "enabled": True,
        "last_refreshed_at": None,
        "refresh_count": 0
    }

    _refresher_registry[key] = cfg
    logger.info(f"Configured Session Refresher for {clean_domain} in project [{clean_proj}]")
    return cfg


def get_session_refresher_config(domain: str, project: str = "default") -> Optional[Dict[str, Any]]:
    """Retrieves session refresher recipe for domain and project."""
    clean_domain = domain.strip().lower()
    clean_proj = (project or "default").strip().lower()
    key = f"{clean_proj}:{clean_domain}"
    if key in _refresher_registry:
        return _refresher_registry[key]
    # Check fallback without project
    for k, v in _refresher_registry.items():
        if k.endswith(f":{clean_domain}"):
            return v
    return None


def list_session_refreshers() -> List[Dict[str, Any]]:
    """Lists all configured session refreshers."""
    return list(_refresher_registry.values())


def is_session_expired_response(
    status_code: int,
    response_headers: Dict[str, str],
    response_body: str,
    domain: str,
    project: str = "default"
) -> bool:
    """
    Evaluates whether an HTTP response indicates an expired session or revoked token.
    """
    if status_code == 401:
        return True

    cfg = get_session_refresher_config(domain, project)
    indicators = cfg.get("expiry_indicators", []) if cfg else [
        "token expired",
        "jwt expired",
        "token is expired",
        "invalid_token",
        "session expired"
    ]

    body_lower = (response_body or "").lower()
    if status_code in (403, 419, 498):
        if any(ind in body_lower for ind in indicators):
            return True

    return False


async def execute_session_refresh(
    domain: str,
    project: str = "default",
    proxy_kwargs: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Replays the configured authentication workflow, captures the fresh token/cookie,
    updates ActiveSession in database and proxy caches.
    """
    cfg = get_session_refresher_config(domain, project)
    if not cfg:
        return {"status": "FAILED", "error": f"No session refresher configured for domain '{domain}'."}

    clean_proj = cfg.get("project", project)
    key = f"{clean_proj}:{domain}"
    lock = _get_lock(key)

    async with lock:
        login_url = cfg["login_url"]
        login_method = cfg["login_method"]
        login_headers = cfg["login_headers"]
        login_payload = cfg["login_payload"]
        extractor_key = cfg["token_extractor"]
        extractor_type = cfg["extractor_type"]

        pk = dict(proxy_kwargs or {})
        extracted_token = None
        extracted_cookie_val = None

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0, **pk) as client:
                resp = await client.request(
                    method=login_method,
                    url=login_url,
                    headers=login_headers,
                    content=login_payload.encode("utf-8") if login_payload else None
                )

                if resp.status_code >= 400:
                    return {
                        "status": "FAILED",
                        "error": f"Login endpoint returned HTTP {resp.status_code}: {resp.text[:200]}"
                    }

                # Extract token based on extractor type
                if extractor_type == "json":
                    try:
                        data = resp.json()
                        # Support simple key or dotted path
                        parts = extractor_key.split(".")
                        curr = data
                        for p in parts:
                            if isinstance(curr, dict) and p in curr:
                                curr = curr[p]
                            else:
                                curr = None
                                break
                        if curr:
                            extracted_token = str(curr)
                    except Exception:
                        pass
                elif extractor_type == "header":
                    for hk, hv in resp.headers.items():
                        if hk.lower() == extractor_key.lower():
                            extracted_token = hv
                            break
                elif extractor_type == "cookie":
                    cookie_name = cfg.get("target_cookie_name") or extractor_key
                    if cookie_name in resp.cookies:
                        extracted_cookie_val = resp.cookies[cookie_name]

                # Also grab any set-cookie cookies for the domain
                new_cookies = {}
                for ck, cv in resp.cookies.items():
                    new_cookies[ck] = cv

                # Update database ActiveSession
                db = SessionLocal()
                try:
                    auth_headers = {}
                    if extracted_token:
                        tmpl = cfg.get("target_auth_header", "Authorization: Bearer {token}")
                        if ":" in tmpl:
                            hname, hval = tmpl.split(":", 1)
                            auth_headers[hname.strip()] = hval.replace("{token}", extracted_token).strip()

                    cookie_list = [{"name": ck, "value": cv} for ck, cv in new_cookies.items()]

                    sess = db.query(ActiveSession).filter(
                        ActiveSession.project == clean_proj,
                        ActiveSession.domain == domain
                    ).first()

                    if not sess:
                        sess = ActiveSession(
                            project=clean_proj,
                            domain=domain,
                            identity_role="primary"
                        )
                        state_data = {
                            "cookies": cookie_list,
                            "auth_headers": auth_headers
                        }
                        sess.set_encrypted_state(state_data)
                        db.add(sess)
                    else:
                        state_data = sess.get_decrypted_state() or {}
                        existing_cookies = {c.get("name"): c.get("value") for c in state_data.get("cookies", []) if isinstance(c, dict)}
                        existing_cookies.update(new_cookies)
                        state_data["cookies"] = [{"name": ck, "value": cv} for ck, cv in existing_cookies.items()]

                        existing_auth = state_data.get("auth_headers", {})
                        existing_auth.update(auth_headers)
                        state_data["auth_headers"] = existing_auth

                        sess.set_encrypted_state(state_data)

                    db.commit()
                finally:
                    db.close()

                cfg["refresh_count"] += 1
                from datetime import datetime
                cfg["last_refreshed_at"] = datetime.now().isoformat()

                return {
                    "status": "SUCCESS",
                    "domain": domain,
                    "project": clean_proj,
                    "extracted_token": extracted_token,
                    "extracted_cookies": new_cookies,
                    "refreshed_auth_headers": auth_headers if extracted_token else {}
                }
        except Exception as ex:
            return {"status": "FAILED", "error": f"Exception during session refresh replay: {str(ex)}"}
