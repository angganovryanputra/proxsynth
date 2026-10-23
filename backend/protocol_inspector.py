"""
Proxsynth MCP - GraphQL & WebSocket Protocol Security Inspector
Specialized security auditor for modern web APIs:
- GraphQL: Introspection querying, field suggestion leakage (Clairvoyance), and query batching amplification.
- WebSocket: Cross-Site WebSocket Hijacking (CSWSH) origin validation, plaintext transport, and token leaks.
"""

import os
import json
import urllib.parse
from typing import Dict, Any, Optional, List
import httpx

from backend.user_agents import get_random_user_agent
from backend.security_utils import check_ssrf_safety, async_check_ssrf_safety


async def inspect_graphql_endpoint(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    project: str = "default"
) -> Dict[str, Any]:
    """
    Performs security assessment on a GraphQL endpoint:
    - Tests for schema introspection disclosure
    - Extracts query, mutation, and sensitive object field catalogs
    - Tests for Clairvoyance / field suggestion leakage when introspection is disabled
    - Tests for query batching amplification support
    """
    clean_url = url.strip()
    is_safe, ssrf_err = await async_check_ssrf_safety(clean_url)
    if not is_safe:
        return {
            "status": "error",
            "error": f"SSRF Guardrail blocked target URL: {ssrf_err}"
        }

    hdrs = {
        "User-Agent": get_random_user_agent(),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    if headers:
        for k, v in headers.items():
            hdrs[k] = str(v)

    findings: List[Dict[str, Any]] = []
    introspection_enabled = False
    discovered_queries: List[str] = []
    discovered_mutations: List[str] = []
    discovered_types: List[str] = []
    sensitive_fields: List[str] = []

    # 1. Test Introspection
    introspection_query = {
        "query": """
        query IntrospectSchema {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name
              kind
              fields {
                name
              }
            }
          }
        }
        """
    }

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12.0) as client:
            resp = await client.post(clean_url, json=introspection_query, headers=hdrs)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    schema = data.get("data", {}).get("__schema")
                    if schema:
                        introspection_enabled = True
                        findings.append({
                            "title": "GraphQL Introspection Enabled",
                            "severity": "MEDIUM",
                            "category": "Information Disclosure",
                            "description": "GraphQL schema introspection is enabled in production, allowing attackers to reconstruct the entire schema, queries, mutations, and database model representations.",
                            "remediation": "Disable introspection in production environments (e.g., set introspection: false in Apollo Server / Yoga)."
                        })

                        # Parse types & fields
                        types = schema.get("types", [])
                        for t in types:
                            t_name = t.get("name", "")
                            if t_name.startswith("__"):
                                continue
                            discovered_types.append(t_name)
                            fields = t.get("fields") or []
                            for f in fields:
                                f_name = f.get("name", "")
                                f_lower = f_name.lower()
                                if any(s in f_lower for s in ["password", "secret", "token", "hash", "ssn", "creditcard", "apikey", "private"]):
                                    sensitive_fields.append(f"{t_name}.{f_name}")

                        # Identify Query and Mutation fields
                        q_type_name = (schema.get("queryType") or {}).get("name", "Query")
                        m_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")
                        for t in types:
                            if t.get("name") == q_type_name:
                                discovered_queries = [f.get("name") for f in (t.get("fields") or [])]
                            elif t.get("name") == m_type_name:
                                discovered_mutations = [f.get("name") for f in (t.get("fields") or [])]
                except Exception:
                    pass

            # 2. Test Field Suggestion Leakage if introspection disabled
            field_suggestion_leak = False
            if not introspection_enabled:
                probe_query = {"query": "{ __schema_probe_error_check }"}
                probe_resp = await client.post(clean_url, json=probe_query, headers=hdrs)
                if "Did you mean" in probe_resp.text:
                    field_suggestion_leak = True
                    findings.append({
                        "title": "GraphQL Field Suggestion Leakage (Clairvoyance)",
                        "severity": "LOW",
                        "category": "Information Disclosure",
                        "description": "GraphQL server provides 'Did you mean ...' suggestions in syntax error messages, enabling automated wordlist-based schema reconstruction even with introspection disabled.",
                        "remediation": "Disable detailed field suggestions or sanitize error messages before returning them to clients."
                    })

            # 3. Test Query Batching Amplification
            batch_query = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"}
            ]
            batch_enabled = False
            batch_resp = await client.post(clean_url, json=batch_query, headers=hdrs)
            if batch_resp.status_code == 200 and batch_resp.text.strip().startswith("["):
                try:
                    res_arr = batch_resp.json()
                    if isinstance(res_arr, list) and len(res_arr) == 3:
                        batch_enabled = True
                        findings.append({
                            "title": "GraphQL Query Batching Enabled",
                            "severity": "LOW",
                            "category": "Rate Limiting Bypass",
                            "description": "The GraphQL endpoint accepts arrays of batched queries in a single HTTP request, potentially bypassing traditional per-request rate limiting for brute-force attacks.",
                            "remediation": "Limit or disable batched queries, or enforce query complexity limits across entire batch payloads."
                        })
                except Exception:
                    pass

    except Exception as ex:
        return {
            "status": "error",
            "url": clean_url,
            "error": f"Connection error: {str(ex)}"
        }

    return {
        "status": "success",
        "url": clean_url,
        "introspection_enabled": introspection_enabled,
        "query_count": len(discovered_queries),
        "mutation_count": len(discovered_mutations),
        "type_count": len(discovered_types),
        "queries": discovered_queries[:30],
        "mutations": discovered_mutations[:30],
        "sensitive_fields_detected": sensitive_fields,
        "batching_supported": batch_enabled,
        "field_suggestion_leak": field_suggestion_leak if not introspection_enabled else False,
        "findings": findings
    }


async def audit_websocket_security(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    project: str = "default"
) -> Dict[str, Any]:
    """
    Performs security audit on WebSocket connection initiation and handshake:
    - Tests for Cross-Site WebSocket Hijacking (CSWSH) via Origin header validation
    - Checks for sensitive authentication tokens in query strings
    - Checks for unencrypted ws:// protocol transport
    """
    clean_url = url.strip()
    probe_url = clean_url.replace("ws://", "http://").replace("wss://", "https://")
    is_safe, ssrf_err = await async_check_ssrf_safety(probe_url)
    if not is_safe:
        return {
            "status": "error",
            "error": f"SSRF Guardrail blocked target URL: {ssrf_err}"
        }

    findings: List[Dict[str, Any]] = []

    # 1. Check Unencrypted Transport (ws:// vs wss://)
    is_unencrypted = clean_url.lower().startswith("ws://")
    if is_unencrypted:
        findings.append({
            "title": "Unencrypted WebSocket Transport (ws://)",
            "severity": "HIGH",
            "category": "Transport Layer Security",
            "description": "The WebSocket connects using unencrypted plaintext 'ws://' instead of TLS-encrypted 'wss://', exposing message payloads to eavesdropping and MITM tampering.",
            "remediation": "Enforce wss:// exclusively for all WebSocket endpoints."
        })

    # 2. Check Token Leakage in Query Parameters
    parsed = urllib.parse.urlparse(clean_url)
    qs = urllib.parse.parse_qs(parsed.query)
    leaked_params = []
    for k in qs.keys():
        k_lower = k.lower()
        if any(s in k_lower for s in ["token", "auth", "jwt", "key", "secret", "bearer", "session", "pass"]):
            leaked_params.append(k)

    if leaked_params:
        findings.append({
            "title": "Sensitive Credentials in WebSocket Query String",
            "severity": "MEDIUM",
            "category": "Credential Exposure",
            "description": f"Sensitive authentication parameters ({', '.join(leaked_params)}) are passed in the WebSocket URL query string. These are logged in browser history, proxy access logs, and referrer headers.",
            "remediation": "Authenticate WebSockets via HTTP-only cookies or transmit credentials in an initial authenticated JSON message frame after handshake."
        })

    # 3. Test Cross-Site WebSocket Hijacking (CSWSH) via Untrusted Origin
    cswsh_vulnerable = False
    http_probe_url = clean_url.replace("ws://", "http://").replace("wss://", "https://")
    untrusted_origin = "https://untrusted-attacker-domain.org"

    handshake_headers = {
        "User-Agent": get_random_user_agent(),
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
        "Origin": untrusted_origin
    }
    if headers:
        for hk, hv in headers.items():
            if hk.lower() != "origin":
                handshake_headers[hk] = str(hv)

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0) as client:
            resp = await client.get(http_probe_url, headers=handshake_headers)
            # A 101 Switching Protocols with untrusted origin indicates CSWSH vulnerability!
            if resp.status_code == 101:
                cswsh_vulnerable = True
                findings.append({
                    "title": "Cross-Site WebSocket Hijacking (CSWSH) - Origin Not Validated",
                    "severity": "HIGH",
                    "category": "Broken Access Control",
                    "description": f"The WebSocket handshake accepted an arbitrary untrusted Origin ({untrusted_origin}) with HTTP 101 Switching Protocols. An external malicious website can establish WebSocket connections using the victim's session cookies and exfiltrate bidirectional data.",
                    "remediation": "Validate the Origin header strictly against an explicit whitelist of trusted domains during the WebSocket upgrade handshake. Reject mismatched origins with HTTP 403 Forbidden."
                })
    except Exception:
        pass

    return {
        "status": "success",
        "url": clean_url,
        "protocol": "ws" if is_unencrypted else "wss",
        "cswsh_vulnerable": cswsh_vulnerable,
        "credentials_in_query": leaked_params,
        "findings_count": len(findings),
        "findings": findings
    }
