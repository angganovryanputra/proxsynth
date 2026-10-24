"""
PROXSYNTH — Autonomous Re-Authentication Macro & Session Keeper
Provides zero-human session maintenance. If an autonomous campaign or agent
encounters a 401 Unauthorized or expired session, this engine automatically executes
the registered auth recipe, refreshes bearer tokens/cookies, and keeps the agent unblocked.
"""

import json
import logging
from typing import Dict, Any, Optional, List
import httpx

logger = logging.getLogger("proxynth.auth_macro")

# In-memory auth recipes keyed by project
_AUTH_RECIPES: Dict[str, Dict[str, Any]] = {}

# Cached active credentials per project: {"token": str, "cookies": dict, "headers": dict}
_ACTIVE_CREDENTIALS: Dict[str, Dict[str, Any]] = {}


def register_auth_recipe(
    project: str,
    login_url: str,
    method: str = "POST",
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    token_json_path: str = "token",
    auth_header_format: str = "Bearer {token}",
    cookie_names: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Registers an automated login recipe for a workspace project.
    Whenever authentication expires, Proxynth will replay this recipe.
    """
    recipe = {
        "project": project,
        "login_url": login_url,
        "method": method.upper(),
        "payload": payload or {},
        "headers": headers or {"Content-Type": "application/json"},
        "token_json_path": token_json_path,
        "auth_header_format": auth_header_format,
        "cookie_names": cookie_names or ["session", "sessionid", "token"],
        "active": True
    }
    _AUTH_RECIPES[project] = recipe
    logger.info(f"Registered auto-reauth recipe for project: {project} -> {login_url}")
    return {"status": "success", "message": f"Auth recipe saved for project '{project}'", "recipe": recipe}


def get_auth_recipe(project: str) -> Optional[Dict[str, Any]]:
    """Retrieve the registered auth recipe for a project."""
    return _AUTH_RECIPES.get(project)


def get_active_credentials(project: str) -> Optional[Dict[str, Any]]:
    """Retrieve the currently cached active tokens and headers for a project."""
    return _ACTIVE_CREDENTIALS.get(project)


def _extract_by_path(data: Any, path: str) -> Optional[str]:
    """Extract nested value from JSON using dot-notation path (e.g. 'data.access_token')."""
    if not path:
        return None
    keys = path.split(".")
    curr = data
    for k in keys:
        if isinstance(curr, dict) and k in curr:
            curr = curr[k]
        else:
            return None
    return str(curr) if curr is not None else None


async def execute_reauth(project: str) -> Dict[str, Any]:
    """
    Executes the registered login macro, extracts refreshed tokens/cookies,
    and updates cached credentials without human intervention.
    """
    recipe = _AUTH_RECIPES.get(project)
    if not recipe or not recipe.get("active"):
        return {"status": "error", "message": f"No active auth recipe registered for project '{project}'"}

    login_url = recipe["login_url"]
    method = recipe["method"]
    headers = dict(recipe.get("headers", {}))
    payload = recipe.get("payload", {})

    try:
        async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(5.0, connect=1.5)) as client:
            if method == "POST":
                # Check if JSON or Form
                ct = headers.get("Content-Type", headers.get("content-type", "application/json"))
                if "application/json" in ct:
                    res = await client.post(login_url, json=payload, headers=headers)
                else:
                    res = await client.post(login_url, data=payload, headers=headers)
            else:
                res = await client.get(login_url, params=payload, headers=headers)

            if res.status_code not in (200, 201, 204):
                return {
                    "status": "error",
                    "status_code": res.status_code,
                    "message": f"Re-auth request failed with status {res.status_code}",
                    "response": res.text[:200]
                }

            # Extract Token
            extracted_token = None
            try:
                json_data = res.json()
                # 1. Try specified path
                extracted_token = _extract_by_path(json_data, recipe["token_json_path"])
                # 2. Try common keys fallback if specified path wasn't found
                if not extracted_token:
                    for common in ["token", "access_token", "jwt", "id_token", "accessToken"]:
                        extracted_token = _extract_by_path(json_data, common)
                        if extracted_token:
                            break
            except Exception:
                pass

            # Extract Cookies
            cookies = dict(res.cookies)
            cookie_header_parts = [f"{k}={v}" for k, v in cookies.items()]
            cookie_header = "; ".join(cookie_header_parts) if cookie_header_parts else ""

            # Build fresh auth headers
            auth_headers = {}
            if extracted_token:
                fmt = recipe.get("auth_header_format", "Bearer {token}")
                auth_headers["Authorization"] = fmt.replace("{token}", extracted_token)
            if cookie_header:
                auth_headers["Cookie"] = cookie_header

            # Store into active credentials cache
            _ACTIVE_CREDENTIALS[project] = {
                "token": extracted_token,
                "cookies": cookies,
                "headers": auth_headers,
                "timestamp": res.headers.get("date", "")
            }

            return {
                "status": "success",
                "message": "Re-authentication succeeded. New session credentials active.",
                "token_extracted": bool(extracted_token),
                "cookies_extracted": list(cookies.keys()),
                "auth_headers": auth_headers
            }

    except Exception as e:
        logger.error(f"Auto-reauth failed for project {project}: {e}")
        return {"status": "error", "message": f"Re-authentication connection error: {str(e)}"}


async def maybe_auto_reauth(status_code: int, project: str) -> bool:
    """
    Checks if a status indicates an expired session (401 or 403),
    and if an auth recipe exists, executes re-auth in the background.
    Returns True if re-authentication was successfully triggered and refreshed.
    """
    if status_code in (401, 403) and project in _AUTH_RECIPES:
        res = await execute_reauth(project)
        return res.get("status") == "success"
    return False
