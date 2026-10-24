"""
Proxsynth MCP - Advanced Automated Audit Tools (Phase 2.5)
Exposes:
- audit_cache_poisoning
- audit_csrf_indepth
- audit_file_upload
"""

import json
from typing import Optional, Dict, Any, Union

from mcp_core.server import proxsynth_tool
from mcp_core.gateway import (
    _resolve_project,
    _persist_and_stream_log,
    _persist_and_stream_payload
)
from backend.cache_auditor import audit_cache_poisoning_engine
from backend.csrf_auditor import audit_csrf_indepth_engine
from backend.upload_auditor import audit_file_upload_engine


@proxsynth_tool(name="audit_cache_poisoning")
async def audit_cache_poisoning(
    url: str,
    param: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    project: Optional[str] = None
) -> str:
    """
    [CATEGORY: cache]
    Probes target URL for Web Cache Poisoning and Web Cache Deception vulnerabilities.
    Evaluates unkeyed HTTP headers (X-Forwarded-Host, X-Host, X-Original-URL, X-Forwarded-Proto),
    cache-key parameter confusion, cache response headers (X-Cache, Age, CF-Cache-Status),
    and path-based cache deception vectors (/.json, /x.css, /;jsessionid=x).
    Dispatches traffic logs and flags findings to dashboard and persists payloads to Vault.
    """
    target_project = _resolve_project(project, allow_all=False)
    results = await audit_cache_poisoning_engine(
        url=url,
        param=param,
        headers=headers,
        project=target_project,
        persist_fn=_persist_and_stream_log,
        vault_fn=_persist_and_stream_payload
    )
    return json.dumps(results, indent=2)


@proxsynth_tool(name="audit_csrf_indepth")
async def audit_csrf_indepth(
    url: str,
    form_field: Optional[str] = None,
    method: str = "POST",
    test_body: Optional[str] = None,
    project: Optional[str] = None
) -> str:
    """
    [CATEGORY: csrf]
    Performs deterministic in-depth Cross-Site Request Forgery (CSRF) audit on target URL.
    Tests: (1) Anti-CSRF token omission (removing token -> response comparison),
    (2) Cross-session token reuse, (3) Cross-origin / missing Origin/Referer acceptance,
    and (4) Session cookie SameSite attribute compliance (Lax, Strict, None).
    Minimizes side-effects using max 1-2 probe requests per vector.
    Dispatches traffic logs, findings, and vault payloads automatically.
    """
    target_project = _resolve_project(project, allow_all=False)
    results = await audit_csrf_indepth_engine(
        url=url,
        form_field=form_field,
        method=method,
        test_body=test_body,
        project=target_project,
        persist_fn=_persist_and_stream_log,
        vault_fn=_persist_and_stream_payload
    )
    return json.dumps(results, indent=2)


@proxsynth_tool(name="audit_file_upload")
async def audit_file_upload(
    target: Union[int, str],
    field: str = "file",
    project: Optional[str] = None,
    allow_exploit: bool = False,
    confirmation: Optional[str] = None
) -> str:
    """
    [CATEGORY: upload]
    Safely probes multipart file upload endpoints for unrestricted file upload vulnerabilities.
    Audits: (1) Server extension filtering (.php, .phtml, .aspx), (2) MIME-type confusion bypass,
    (3) Magic bytes polyglots (GIF89a / PNG headers), (4) Double extension handling (.php.png),
    (5) SVG-based Cross-Site Scripting (SVG XSS), and (6) Filename path traversal (../../probe.txt).
    GUARDRAIL: Defaults strictly to non-destructive detection and reporting.
    Active exploit execution requires allow_exploit=True AND explicit confirmation='CONFIRM_EXPLOIT'.
    Dispatches traffic logs, findings, and vault payloads automatically.
    """
    target_project = _resolve_project(project, allow_all=False)
    results = await audit_file_upload_engine(
        url_or_log_id=str(target),
        field_name=field,
        project=target_project,
        allow_exploit=allow_exploit,
        confirmation=confirmation,
        persist_fn=_persist_and_stream_log,
        vault_fn=_persist_and_stream_payload
    )
    return json.dumps(results, indent=2)
