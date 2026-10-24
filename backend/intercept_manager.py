"""
Proxsynth MCP - Intercept & Scope Guardrail Manager
Manages real-time request traps (breakpoints) and out-of-scope domain boundaries.
"""

import os
import re
import json
import uuid
import asyncio
import fnmatch
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from sqlalchemy.orm import Session
from backend.database import Project
from backend.security_utils import check_ssrf_safety, async_check_ssrf_safety

# ==============================================================================
# Intercept Trap State
# ==============================================================================

_intercept_enabled: bool = False
_pending_intercepts: Dict[str, Dict[str, Any]] = {}


def is_intercept_enabled() -> bool:
    return _intercept_enabled


def set_intercept_mode(enabled: bool) -> bool:
    global _intercept_enabled
    _intercept_enabled = enabled
    return _intercept_enabled


def get_intercept_status() -> Dict[str, Any]:
    pending_list = []
    for i_id, item in list(_pending_intercepts.items()):
        req = item["request_data"]
        pending_list.append({
            "id": i_id,
            "project": req.get("project", "default"),
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "headers": req.get("headers", {}),
            "body": req.get("body", ""),
            "reasoning": req.get("reasoning", ""),
            "timestamp": item.get("created_at", "")
        })
    return {
        "enabled": _intercept_enabled,
        "pending_count": len(pending_list),
        "pending": pending_list
    }


def create_intercept_trap(request_data: Dict[str, Any]) -> Tuple[str, asyncio.Event]:
    """Registers an intercepted request and provides an asyncio.Event to wait on."""
    intercept_id = str(uuid.uuid4())[:8]
    event = asyncio.Event()
    _pending_intercepts[intercept_id] = {
        "event": event,
        "request_data": request_data,
        "decision": "pending",  # "forward", "drop"
        "modified_data": None,
        "created_at": datetime.now().isoformat()
    }
    return intercept_id, event


def resolve_intercept_trap(
    intercept_id: str,
    action: str,
    modified_data: Optional[Dict[str, Any]] = None
) -> bool:
    """Releases a waiting intercept trap with operator decision."""
    if intercept_id not in _pending_intercepts:
        return False

    item = _pending_intercepts[intercept_id]
    item["decision"] = action.lower()
    item["modified_data"] = modified_data
    item["event"].set()
    return True


def pop_intercept_result(intercept_id: str) -> Optional[Dict[str, Any]]:
    return _pending_intercepts.pop(intercept_id, None)


# ==============================================================================
# Scope & Guardrail Engine
# ==============================================================================

# In-memory TTL cache for project scope rules (5-second cache to prevent DB churn during high-volume fuzzing/agent runs)
_SCOPE_CACHE: Dict[str, Tuple[float, Optional[Dict[str, Any]]]] = {}

def invalidate_scope_cache(project_name: Optional[str] = None):
    if project_name:
        _SCOPE_CACHE.pop(project_name.lower(), None)
    else:
        _SCOPE_CACHE.clear()


def _get_project_scope_data(project_name: str, db: Session) -> Optional[Dict[str, Any]]:
    import time
    now = time.time()
    cache_entry = _SCOPE_CACHE.get(project_name.lower())
    if cache_entry and (now - cache_entry[0] < 5.0):
        return cache_entry[1]

    project = db.query(Project).filter(Project.name == project_name.lower()).first()
    if not project:
        scope_data = None
    else:
        try:
            blocked_list = json.loads(project.blocked_patterns) if project.blocked_patterns else []
        except Exception:
            blocked_list = []
        try:
            allowed_list = json.loads(project.allowed_hosts) if project.allowed_hosts else ["*"]
        except Exception:
            allowed_list = ["*"]
        scope_data = {
            "scope_enabled": bool(project.scope_enabled),
            "allow_internal_networks": bool(getattr(project, "allow_internal_networks", False)),
            "blocked_patterns": blocked_list,
            "allowed_hosts": allowed_list
        }
    _SCOPE_CACHE[project_name.lower()] = (now, scope_data)
    return scope_data


def _is_self_loop(url: str) -> Tuple[bool, Optional[str]]:
    """Prevents recursive infinite proxy loops directed at Proxsynth's own service ports."""
    try:
        parsed = urllib.parse.urlparse(url)
        clean_path = (parsed.path or "").rstrip("/")
        if clean_path in ["/api/health", "/health", "/healthz", "/api/healthz", "/api/info"]:
            return False, None
        hostname = (parsed.hostname or "").strip().lower()
        if hostname in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            current_proxy_port = int(os.getenv("PROXSYNTH_PROXY_PORT", "8088"))
            backend_url_env = os.getenv("PROXSYNTH_BACKEND_URL", "")
            current_backend_port = int(os.getenv("PROXSYNTH_PORT", "8000"))
            if backend_url_env:
                try:
                    b_parsed = urllib.parse.urlparse(backend_url_env)
                    if b_parsed.port:
                        current_backend_port = b_parsed.port
                except Exception:
                    pass
            if port in [current_proxy_port, current_backend_port]:
                return True, f"Recursive proxy loop blocked: Target points to Proxsynth's own service port ({port})."
    except Exception:
        pass
    return False, None


def _evaluate_scope_rules(project_name: str, url: str, scope_data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    # If project not found or scope guardrail disabled, permit request immediately
    if not scope_data or not scope_data.get("scope_enabled"):
        return True, None

    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.netloc or "").split(":")[0].lower()
        full_path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    except Exception as ex:
        return False, f"Malformed target URL: {str(ex)}"

    # 1. Check Blocked Regex Patterns (Anti-destructive / Out-of-bounds keywords)
    for pattern in scope_data.get("blocked_patterns", []):
        if not pattern:
            continue
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            if regex.search(full_path) or regex.search(url):
                return False, f"Blocked by guardrail: URL or path matches restricted pattern '{pattern}'"
        except Exception:
            if pattern.lower() in url.lower():
                return False, f"Blocked by guardrail: URL contains restricted keyword '{pattern}'"

    # 2. Check Allowed Hosts (Domain Boundaries)
    raw_allowed = scope_data.get("allowed_hosts", [])
    allowed_list = [h.strip().lower() for h in raw_allowed if h and h.strip()]

    # If allowed_hosts contains "*" or "all", or is empty, all hosts are permitted
    if not allowed_list or "*" in allowed_list or "all" in allowed_list:
        return True, None

    host_allowed = False
    for allowed_pattern in allowed_list:
        if fnmatch.fnmatch(host, allowed_pattern):
            host_allowed = True
            break

    if not host_allowed:
        return False, f"Out of Scope: Host '{host}' is not in allowed target domains {allowed_list} for project '{project_name}'"

    return True, None


def check_scope(project_name: str, url: str, db: Session) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a URL is within authorized scope (Synchronous).
    - If scope_enabled is False (DEFAULT): NO GUARDRAILS (all internal/external targets permitted).
    - Only anti-self-loopback to Proxsynth's own proxy/backend port is prevented to avoid crash loops.
    - When scope_enabled is True: enforces configured allowed hosts, blocked patterns, and SSRF policies.
    """
    is_loop, loop_reason = _is_self_loop(url)
    if is_loop:
        return False, loop_reason

    scope_data = _get_project_scope_data(project_name, db)
    # Default: Guardrails OFF unless manually enabled
    if not scope_data or not scope_data.get("scope_enabled", False):
        return True, None

    # Manually enabled scope guardrails
    allow_internal = scope_data.get("allow_internal_networks", True)
    is_safe_ssrf, ssrf_reason = check_ssrf_safety(url, allow_internal=allow_internal)
    if not is_safe_ssrf:
        return False, ssrf_reason

    return _evaluate_scope_rules(project_name, url, scope_data)


async def async_check_scope(project_name: str, url: str, db: Session) -> Tuple[bool, Optional[str]]:
    """
    Asynchronously validates whether a URL is within authorized scope.
    - If scope_enabled is False (DEFAULT): NO GUARDRAILS (all internal/external targets permitted).
    - Only anti-self-loopback to Proxsynth's own proxy/backend port is prevented to avoid crash loops.
    - When scope_enabled is True: enforces configured allowed hosts, blocked patterns, and SSRF policies.
    """
    is_loop, loop_reason = _is_self_loop(url)
    if is_loop:
        return False, loop_reason

    scope_data = _get_project_scope_data(project_name, db)
    # Default: Guardrails OFF unless manually enabled
    if not scope_data or not scope_data.get("scope_enabled", False):
        return True, None

    # Manually enabled scope guardrails
    allow_internal = scope_data.get("allow_internal_networks", True)
    is_safe_ssrf, ssrf_reason = await async_check_ssrf_safety(url, allow_internal=allow_internal)
    if not is_safe_ssrf:
        return False, ssrf_reason

    return _evaluate_scope_rules(project_name, url, scope_data)

