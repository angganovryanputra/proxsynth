"""
Proxsynth MCP - Dynamic Session & Anti-CSRF Token Tracker
Automatically captures anti-CSRF, authenticity tokens, and nonce secrets from incoming responses
(HTML inputs, meta tags, JSON bodies, response headers, Set-Cookie) and auto-injects fresh tokens
into subsequent state-changing requests (POST, PUT, PATCH, DELETE) made by autonomous AI agents.
"""

import re
import json
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

# In-memory token store: (host, project) -> {"token": str, "name": str, "source": str, "updated_at": str}
_CSRF_REGISTRY: Dict[Tuple[str, str], Dict[str, Any]] = {}

# Patterns for HTML forms and meta tags
_HTML_INPUT_REGEX = re.compile(
    r'<input[^>]+name=["\']?(csrf[-_]?token|_csrf|authenticity[-_]?token|xsrf[-_]?token)["\']?[^>]+value=["\']?([^"\'\s>]+)',
    re.IGNORECASE
)
_HTML_INPUT_REVERSE_REGEX = re.compile(
    r'<input[^>]+value=["\']?([^"\'\s>]+)["\']?[^>]+name=["\']?(csrf[-_]?token|_csrf|authenticity[-_]?token|xsrf[-_]?token)',
    re.IGNORECASE
)
_HTML_META_REGEX = re.compile(
    r'<meta[^>]+name=["\']?(csrf[-_]?token|_csrf|authenticity[-_]?token|xsrf[-_]?token)["\']?[^>]+content=["\']?([^"\'\s>]+)',
    re.IGNORECASE
)


def _normalize_host(url_or_host: str) -> str:
    """Normalizes URL or host string to clean lowercase hostname without port."""
    if not url_or_host:
        return ""
    if "://" in url_or_host:
        try:
            return (urllib.parse.urlparse(url_or_host).netloc or "").split(":")[0].strip().lower()
        except Exception:
            return ""
    return url_or_host.split(":")[0].strip().lower()


def extract_and_update_csrf_tokens(
    url: str,
    res_headers: Dict[str, Any],
    res_body: str,
    project: str = "default"
) -> Optional[Dict[str, Any]]:
    """
    Parses response headers and body to extract anti-CSRF tokens and caches them.
    Returns token record if a new/updated token was found, otherwise None.
    """
    host = _normalize_host(url)
    if not host:
        return None

    proj = (project or "default").strip().lower()
    found_token: Optional[str] = None
    token_name = "csrf_token"
    token_source = "header"

    # 1. Check Response Headers
    for hk, hv in res_headers.items():
        hk_lower = hk.lower()
        if hk_lower in ["x-csrf-token", "x-xsrf-token", "csrf-token"]:
            found_token = str(hv).strip()
            token_name = hk
            token_source = f"header:{hk}"
            break

    # 2. Check Set-Cookie headers
    if not found_token:
        for hk, hv in res_headers.items():
            if hk.lower() == "set-cookie":
                cookie_str = str(hv)
                for part in cookie_str.split(";"):
                    if "=" in part:
                        ck, cv = part.strip().split("=", 1)
                        if ck.lower() in ["xsrf-token", "csrftoken", "_csrf", "csrf"]:
                            found_token = cv.strip()
                            token_name = ck
                            token_source = f"cookie:{ck}"
                            break
            if found_token:
                break

    # 3. Check Response Body (HTML or JSON)
    if not found_token and res_body:
        # Check JSON response
        trimmed_body = res_body.strip()
        if (trimmed_body.startswith("{") and trimmed_body.endswith("}")) or (trimmed_body.startswith("[") and trimmed_body.endswith("]")):
            try:
                data = json.loads(trimmed_body)
                if isinstance(data, dict):
                    for cand_key in ["csrf_token", "csrfToken", "_csrf", "authenticity_token", "xsrf_token", "csrf", "token"]:
                        val = data.get(cand_key)
                        if val and isinstance(val, str) and len(val) >= 8 and len(val) <= 256:
                            found_token = val.strip()
                            token_name = cand_key
                            token_source = f"json:{cand_key}"
                            break
            except Exception:
                pass

        # Check HTML response
        if not found_token and "<" in res_body:
            # Check meta tag
            meta_m = _HTML_META_REGEX.search(res_body)
            if meta_m:
                token_name = meta_m.group(1)
                found_token = meta_m.group(2)
                token_source = f"meta:{token_name}"
            else:
                # Check form input
                inp_m = _HTML_INPUT_REGEX.search(res_body)
                if inp_m:
                    token_name = inp_m.group(1)
                    found_token = inp_m.group(2)
                    token_source = f"form:{token_name}"
                else:
                    inp_rev = _HTML_INPUT_REVERSE_REGEX.search(res_body)
                    if inp_rev:
                        found_token = inp_rev.group(1)
                        token_name = inp_rev.group(2)
                        token_source = f"form:{token_name}"

    if found_token:
        # Clean token (strip potential quotes or trailing punctuation)
        found_token = found_token.strip("\"' \t\r\n")
        record = {
            "token": found_token,
            "name": token_name,
            "source": token_source,
            "host": host,
            "project": proj,
            "updated_at": datetime.now().isoformat()
        }
        _CSRF_REGISTRY[(host, proj)] = record
        # Also store for host under 'default' if not present
        if proj != "default" and (host, "default") not in _CSRF_REGISTRY:
            _CSRF_REGISTRY[(host, "default")] = record
        return record

    return None


def get_token_for_host(host: str, project: str = "default") -> Optional[Dict[str, Any]]:
    """Retrieves current cached CSRF token for host and project."""
    norm_host = _normalize_host(host)
    proj = (project or "default").strip().lower()

    if (norm_host, proj) in _CSRF_REGISTRY:
        return _CSRF_REGISTRY[(norm_host, proj)]
    if (norm_host, "default") in _CSRF_REGISTRY:
        return _CSRF_REGISTRY[(norm_host, "default")]

    # Check root domain fallback (e.g. sub.domain.com -> domain.com)
    for (k_host, k_proj), rec in _CSRF_REGISTRY.items():
        if (k_proj == proj or k_proj == "default") and (norm_host.endswith("." + k_host) or k_host.endswith("." + norm_host)):
            return rec
    return None


def inject_csrf_token_if_needed(
    method: str,
    url: str,
    headers: Dict[str, Any],
    body: str,
    project: str = "default"
) -> Tuple[Dict[str, str], str, bool]:
    """
    Auto-injects active anti-CSRF token into state-changing requests if missing.
    Returns: (modified_headers, modified_body, was_injected)
    """
    clean_method = (method or "GET").upper()
    if clean_method not in ["POST", "PUT", "PATCH", "DELETE"]:
        return {k: str(v) for k, v in headers.items()}, body, False

    host = _normalize_host(url)
    token_rec = get_token_for_host(host, project)
    if not token_rec:
        return {k: str(v) for k, v in headers.items()}, body, False

    token_val = token_rec["token"]
    token_name = token_rec["name"]
    mod_headers = {k: str(v) for k, v in headers.items()}
    mod_body = body or ""
    was_injected = False

    # 1. Header injection: Check if X-CSRF-Token or X-XSRF-Token is present
    has_csrf_hdr = any(k.lower() in ["x-csrf-token", "x-xsrf-token", "csrf-token"] for k in mod_headers.keys())
    if not has_csrf_hdr:
        mod_headers["X-CSRF-Token"] = token_val
        was_injected = True

    # 2. Body injection if form urlencoded or JSON
    ct = mod_headers.get("Content-Type", mod_headers.get("content-type", "")).lower()
    if "application/x-www-form-urlencoded" in ct:
        if token_name.lower() not in mod_body.lower():
            if mod_body:
                mod_body = f"{mod_body}&{urllib.parse.quote(token_name)}={urllib.parse.quote(token_val)}"
            else:
                mod_body = f"{urllib.parse.quote(token_name)}={urllib.parse.quote(token_val)}"
            was_injected = True
    elif "application/json" in ct and mod_body.strip().startswith("{") and mod_body.strip().endswith("}"):
        try:
            data = json.loads(mod_body)
            if isinstance(data, dict):
                has_key = any(k.lower() in [token_name.lower(), "csrf_token", "_csrf", "csrftoken"] for k in data.keys())
                if not has_key:
                    data[token_name] = token_val
                    mod_body = json.dumps(data)
                    was_injected = True
        except Exception:
            pass

    return mod_headers, mod_body, was_injected


def get_tracked_csrf_tokens(domain: Optional[str] = None, project: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns list of currently tracked anti-CSRF tokens."""
    results = []
    filter_host = _normalize_host(domain) if domain else None
    filter_proj = (project or "").strip().lower() if project and project not in ["all", "*", "any", "global"] else None

    for (h, p), rec in _CSRF_REGISTRY.items():
        if filter_host and filter_host != h and not h.endswith("." + filter_host):
            continue
        if filter_proj and filter_proj != p:
            continue
        results.append(rec)
    return results


def set_manual_csrf_token(domain: str, token_name: str, token_value: str, project: str = "default") -> Dict[str, Any]:
    """Manually registers an anti-CSRF token for a target domain."""
    host = _normalize_host(domain)
    proj = (project or "default").strip().lower()
    rec = {
        "token": token_value.strip(),
        "name": (token_name or "csrf_token").strip(),
        "source": "manual",
        "host": host,
        "project": proj,
        "updated_at": datetime.now().isoformat()
    }
    _CSRF_REGISTRY[(host, proj)] = rec
    return rec


def clear_tracked_csrf_tokens(domain: Optional[str] = None, project: Optional[str] = None) -> int:
    """Clears cached CSRF tokens. Returns number of records cleared."""
    global _CSRF_REGISTRY
    if not domain and not project:
        count = len(_CSRF_REGISTRY)
        _CSRF_REGISTRY.clear()
        return count

    filter_host = _normalize_host(domain) if domain else None
    filter_proj = (project or "").strip().lower() if project and project not in ["all", "*", "any", "global"] else None

    keys_to_delete = []
    for (h, p) in _CSRF_REGISTRY.keys():
        match_h = not filter_host or filter_host == h
        match_p = not filter_proj or filter_proj == p
        if match_h and match_p:
            keys_to_delete.append((h, p))

    for k in keys_to_delete:
        del _CSRF_REGISTRY[k]
    return len(keys_to_delete)
