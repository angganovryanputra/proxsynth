"""
Proxsynth - Passive & Active JavaScript Recon, Endpoint & Secret Miner
Extracts hidden API endpoints, routes, query/body parameters, source maps,
and leaked credentials (AWS, JWT, Slack, API keys) from client-side JavaScript assets.
"""

import os
import re
import json
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional, Set

import httpx

from backend.user_agents import apply_rotating_user_agent
from backend.analyzer import SECRET_LEAK_PATTERNS
from backend.database import SessionLocal, Finding, HttpLog
from backend.target_manager import add_or_update_endpoint, upsert_target_asset

# Regex patterns for JavaScript analysis
JS_ENDPOINT_PATTERNS = [
    # fetch / axios / ajax calls
    re.compile(r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch|options))?|\$\.(?:ajax|get|post))\s*\(\s*['"`]([^'"`\r\n\s]+)['"`]""", re.IGNORECASE),
    # Common REST & API paths inside quotes
    re.compile(r"""['"`](\/(?:api|v[0-9]+|graphql|rest|auth|admin|users?|accounts?|login|logout|register|settings|config|dashboard|items?|orders?|products?|search|download|upload|file|assets?|static|media|webhook|gateway|service|internal)[a-zA-Z0-9_\-\.\/\?=&]*)['"`]""", re.IGNORECASE),
    # Explicit endpoint, path, url key-value definitions
    re.compile(r"""(?:endpoint|path|url|route|action)\s*:\s*['"`]([^'"`\r\n\s]+)['"`]""", re.IGNORECASE)
]

JS_PARAM_NAME_PATTERNS = [
    # Query parameters inside URLs
    re.compile(r"""[?&]([a-zA-Z0-9_\-]+)=(?:[^&\s'"`;]*)"""),
    # Sensitive or high-impact parameter names in JS code
    re.compile(r"""\b(id|uid|user_id|account_id|token|access_token|refresh_token|api_key|apiKey|secret|role|admin|is_admin|isAdmin|debug|test|redirect|redirect_uri|callback|url|next|code|state|session|auth|email|password|passwd|file|path|cmd|exec|query|search|filter|page|limit|offset|sort|view|format|lang|config|impersonate|internal|tenant_id|org_id|client_id)\b""", re.IGNORECASE)
]

JS_ADDITIONAL_SECRETS = [
    {
        "name": "Hardcoded JWT Token",
        "pattern": re.compile(r"""\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+\b"""),
        "severity": "HIGH",
        "category": "Credential & Token Exposure",
        "remediation": "Remove hardcoded JWT tokens from client-side bundles. Issue short-lived tokens via secure backend session flows."
    },
    {
        "name": "Slack Webhook URL Exposure",
        "pattern": re.compile(r"""https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}"""),
        "severity": "HIGH",
        "category": "Leaked Webhook Credential",
        "remediation": "Revoke exposed Slack incoming webhooks. Route notifications exclusively via trusted server-side services."
    },
    {
        "name": "Generic Hardcoded Secret Assignment",
        "pattern": re.compile(r"""(?i)(?:api[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|bearer[_-]?token|private[_-]?key)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{12,128})["']"""),
        "severity": "HIGH",
        "category": "Hardcoded Application Secret",
        "remediation": "Extract secret variables from client-side scripts. Store keys securely in server-side environment variables or KMS."
    }
]

SOURCEMAP_PATTERN = re.compile(r"""(?:\/\/|\/\*)[#@]\s*sourceMappingURL=([^\s*]+)""")

# File extensions to ignore when extracting endpoints
IGNORE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".scss", ".less"
)

# Common MIME strings or non-routes to reject
IGNORE_PREFIXES = (
    "text/", "image/", "audio/", "video/", "font/",
    "application/x-", "application/json", "application/javascript"
)


def extract_routes(js_content: str) -> List[str]:
    """Finds all URL paths and API endpoints declared in JavaScript source."""
    routes: Set[str] = set()
    for pattern in JS_ENDPOINT_PATTERNS:
        for match in pattern.findall(js_content):
            path = match.strip()
            # Clean string
            if not path or len(path) < 2:
                continue
            # Ignore MIME types or non-routes
            if any(path.startswith(prefix) for prefix in IGNORE_PREFIXES):
                continue
            # Ignore pure static image/font assets unless containing query/api indicators
            clean_path = path.split("?")[0].lower()
            if any(clean_path.endswith(ext) for ext in IGNORE_EXTENSIONS) and "api" not in clean_path:
                continue
            # Normalize path
            if path.startswith("//"):
                continue  # Protocol-relative or comment artifact
            if path.startswith("/"):
                # Clean redundant slashes
                normalized = "/" + "/".join(filter(None, path.split("/")))
                routes.add(normalized)
                if "?" in normalized:
                    routes.add(normalized.split("?")[0])
            elif path.startswith("http://") or path.startswith("https://"):
                routes.add(path)
                if "?" in path:
                    routes.add(path.split("?")[0])
    return sorted(list(routes))


def extract_parameters(js_content: str) -> List[str]:
    """Extracts URL query parameter keys and high-value API parameter identifiers."""
    params: Set[str] = set()
    for pattern in JS_PARAM_NAME_PATTERNS:
        for match in pattern.findall(js_content):
            name = match.strip()
            if len(name) >= 2 and not name.isdigit():
                params.add(name)
    return sorted(list(params))


def extract_secrets(js_content: str) -> List[Dict[str, Any]]:
    """Identifies sensitive credentials and leaked API keys with line locations."""
    findings: List[Dict[str, Any]] = []
    lines = js_content.splitlines()

    all_patterns = list(SECRET_LEAK_PATTERNS) + JS_ADDITIONAL_SECRETS

    for item in all_patterns:
        name = item.get("name", "Exposed Secret")
        pat = item.get("pattern")
        sev = item.get("severity", "HIGH")
        cat = item.get("category", "Information Disclosure")
        rem = item.get("remediation", "Revoke secret immediately.")

        for idx, line in enumerate(lines, 1):
            matches = pat.findall(line)
            for m in matches:
                matched_str = m if isinstance(m, str) else m[0] if isinstance(m, (list, tuple)) else str(m)
                if not matched_str or len(matched_str) < 6:
                    continue
                # Mask secret value in evidence preview
                masked = matched_str[:4] + "*" * (len(matched_str) - 8) + matched_str[-4:] if len(matched_str) > 8 else "***"
                findings.append({
                    "title": name,
                    "severity": sev,
                    "category": cat,
                    "evidence": f"Line {idx}: {masked}",
                    "raw_match": matched_str,
                    "line": idx,
                    "remediation": rem
                })
    return findings


def extract_sourcemaps(js_content: str, base_url: Optional[str] = None) -> List[str]:
    """Extracts references to source map (.map) files for deeper code recovery."""
    maps = []
    for match in SOURCEMAP_PATTERN.findall(js_content):
        ref = match.strip().rstrip("*/").strip()
        if ref:
            if base_url and not ref.startswith("http"):
                full_map_url = urllib.parse.urljoin(base_url, ref)
                maps.append(full_map_url)
            else:
                maps.append(ref)
    return maps


async def mine_javascript(
    content_or_url: str,
    base_url: Optional[str] = None,
    auto_register: bool = True,
    project: str = "default",
    upstream_proxy: Optional[str] = None
) -> Dict[str, Any]:
    """
    Mines a JavaScript file or raw code snippet for hidden endpoints, query parameters,
    leaked secrets, and source maps. Automatically registers endpoints into the target graph
    and persists critical secret exposure findings if auto_register is True.
    """
    target_project = (project or "default").strip().lower()
    raw_js = ""
    source_url = ""

    # Determine if input is a remote URL or raw content
    if content_or_url.strip().startswith(("http://", "https://")):
        source_url = content_or_url.strip()
        base_url = base_url or source_url

        # Validate against project scope guardrails
        if target_project:
            db_scope = SessionLocal()
            try:
                from backend.intercept_manager import async_check_scope
                is_allowed, block_reason = await async_check_scope(target_project, source_url, db_scope)
                if not is_allowed:
                    return {
                        "error": f"Target URL is out of authorized scope: {block_reason}",
                        "source_url": source_url,
                        "endpoints_found": [],
                        "parameters_found": [],
                        "secrets_leaked": [],
                        "sourcemaps": [],
                        "summary": {"endpoints_count": 0, "params_count": 0, "secrets_count": 0}
                    }
            finally:
                db_scope.close()

        headers = {}
        apply_rotating_user_agent(headers)

        proxy_kwargs = {}
        if upstream_proxy and upstream_proxy.strip():
            proxy_kwargs["proxy"] = upstream_proxy.strip()
        else:
            proxy_kwargs["proxy"] = None
            proxy_kwargs["trust_env"] = False

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0, **proxy_kwargs) as client:
                resp = await client.get(source_url, headers=headers)
                raw_js = resp.text
        except Exception as e:
            return {
                "error": f"Failed to fetch remote JavaScript from {source_url}: {str(e)}",
                "source_url": source_url,
                "endpoints_found": [],
                "parameters_found": [],
                "secrets_leaked": [],
                "sourcemaps": [],
                "summary": {"endpoints_count": 0, "params_count": 0, "secrets_count": 0}
            }
    else:
        raw_js = content_or_url

    if not raw_js:
        return {
            "source_url": source_url or "inline_content",
            "endpoints_found": [],
            "parameters_found": [],
            "secrets_leaked": [],
            "sourcemaps": [],
            "summary": {"endpoints_count": 0, "params_count": 0, "secrets_count": 0}
        }

    # Perform static extraction
    routes = extract_routes(raw_js)
    params = extract_parameters(raw_js)
    secrets = extract_secrets(raw_js)
    sourcemaps = extract_sourcemaps(raw_js, base_url)

    # Optional Auto-Registration into Target Knowledge Graph & Database Findings
    if auto_register:
        db = SessionLocal()
        try:
            # 1. Register endpoints into target graph
            target_host = ""
            if base_url:
                parsed_base = urllib.parse.urlparse(base_url)
                target_host = parsed_base.netloc.split(":")[0].lower()

            for route in routes:
                full_endpoint_url = route
                if base_url and not route.startswith("http"):
                    full_endpoint_url = urllib.parse.urljoin(base_url, route)

                ep_host = target_host
                if not ep_host and full_endpoint_url.startswith("http"):
                    ep_host = urllib.parse.urlparse(full_endpoint_url).netloc.split(":")[0].lower()

                if ep_host:
                    try:
                        add_or_update_endpoint(
                            project=target_project,
                            host=ep_host,
                            url=full_endpoint_url,
                            method="GET",
                            parameters=params[:10] if params else [],
                            tested_status="UNTESTED",
                            notes=f"Discovered via JS Recon Miner ({source_url or 'inline_script'})"
                        )
                    except Exception:
                        pass

            # 2. Record critical secrets as Findings in database
            if secrets:
                for sec in secrets:
                    f = Finding(
                        project=target_project,
                        title=sec["title"],
                        severity=sec["severity"],
                        category=sec["category"],
                        evidence=f"Asset: {source_url or 'inline_script'} | {sec['evidence']}",
                        description=f"Automated JavaScript miner detected leaked secret ({sec['title']}).",
                        remediation=sec["remediation"]
                    )
                    db.add(f)
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    return {
        "source_url": source_url or "inline_content",
        "endpoints_found": routes,
        "parameters_found": params,
        "secrets_leaked": [
            {
                "title": s["title"],
                "severity": s["severity"],
                "category": s["category"],
                "evidence": s["evidence"],
                "line": s["line"],
                "remediation": s["remediation"]
            }
            for s in secrets
        ],
        "sourcemaps": sourcemaps,
        "summary": {
            "endpoints_count": len(routes),
            "params_count": len(params),
            "secrets_count": len(secrets),
            "sourcemaps_count": len(sourcemaps)
        }
    }


def passive_mine_js_background(url: str, body: str, project: str = "default"):
    """Fire-and-forget background passive miner triggered during forward proxy response inspection."""
    if not body or len(body) < 50:
        return

    # Check if URL or content is javascript
    is_js_url = any(url.split("?")[0].lower().endswith(ext) for ext in [".js", ".mjs", ".jsx", ".ts", ".tsx"])
    if not is_js_url and "javascript" not in url.lower() and "function(" not in body and "var " not in body and "const " not in body:
        return

    async def _runner():
        try:
            await mine_javascript(
                content_or_url=body,
                base_url=url,
                auto_register=True,
                project=project
            )
        except Exception:
            pass

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_runner())
    except RuntimeError:
        pass
