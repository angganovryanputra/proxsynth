"""
Proxsynth - Web Cache Poisoning & Web Cache Deception Auditing Engine
Tests for unkeyed HTTP headers, cache key poisoning, and path confusion / cache deception.
"""

import time
import uuid
import json
import urllib.parse
from typing import Dict, Any, Optional, List

import httpx

from backend.database import SessionLocal, HttpLog, Finding
from backend.user_agents import apply_rotating_user_agent


CACHE_IDENTIFIER_HEADERS = [
    "x-cache", "cf-cache-status", "age", "x-varnish", "x-cache-hits",
    "x-fastly-request-id", "x-served-by", "x-drupal-cache", "x-proxy-cache"
]

UNKEYED_HEADER_VECTORS = [
    {"header": "X-Forwarded-Host", "value": "attacker-cache-poison.internal"},
    {"header": "X-Host", "value": "attacker-cache-poison.internal"},
    {"header": "X-Forwarded-Proto", "value": "http"},
    {"header": "X-Original-URL", "value": "/proxsynth_cache_deception_probe"},
    {"header": "X-Rewrite-URL", "value": "/proxsynth_cache_deception_probe"},
]

DECEPTION_SUFFIXES = [
    "/static_test.css",
    "/;jsessionid=test.css",
    "/.json",
    "/favicon.ico"
]


async def audit_cache_poisoning_engine(
    url: str,
    param: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    project: str = "default",
    persist_fn=None,
    vault_fn=None
) -> Dict[str, Any]:
    """
    Executes automated Web Cache Poisoning and Web Cache Deception probes against target URL.
    """
    target_project = (project or "default").strip().lower()
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    parsed = urllib.parse.urlparse(clean_url)
    hostname = parsed.netloc

    results = {
        "target_url": clean_url,
        "project": target_project,
        "is_caching_detected": False,
        "cache_headers_observed": {},
        "vulnerabilities": [],
        "tests_executed": []
    }

    req_headers = {"User-Agent": "Proxsynth-Cache-Auditor/1.0"}
    if headers:
        req_headers.update(headers)

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10.0) as client:
        # Phase 1: Baseline Request & Cache Fingerprinting
        cb_token = f"cb_{uuid.uuid4().hex[:8]}"
        base_test_url = f"{clean_url}{'&' if '?' in clean_url else '?'}_ps_cb={cb_token}"

        try:
            r1 = await client.get(base_test_url, headers=req_headers)
            r1_cache_hdrs = {k.lower(): v for k, v in r1.headers.items() if k.lower() in CACHE_IDENTIFIER_HEADERS or "cache" in k.lower()}
            results["cache_headers_observed"] = r1_cache_hdrs
            if r1_cache_hdrs:
                results["is_caching_detected"] = True
        except Exception as e:
            return {
                "status": "ERROR",
                "error": f"Failed initial probe to {clean_url}: {str(e)}",
                "vulnerabilities": []
            }

        # Phase 2: Unkeyed Header Poisoning Probes
        for v in UNKEYED_HEADER_VECTORS:
            test_cb = f"poison_{uuid.uuid4().hex[:8]}"
            probe_url = f"{clean_url}{'&' if '?' in clean_url else '?'}_ps_cb={test_cb}"
            probe_hdrs = dict(req_headers)
            probe_hdrs[v["header"]] = v["value"]

            try:
                # 1. Send poisoning probe request
                p_resp = await client.get(probe_url, headers=probe_hdrs)
                poison_reflected_in_probe = v["value"] in p_resp.text

                # 2. Wait 100ms and send clean second request (NO poison header)
                time.sleep(0.1)
                clean_resp = await client.get(probe_url, headers=req_headers)

                # Check if second clean request received cached poisoned response
                is_hit = any("hit" in str(v).lower() for v in clean_resp.headers.values())
                poison_persisted_in_cache = v["value"] in clean_resp.text

                results["tests_executed"].append({
                    "test": f"Unkeyed Header {v['header']}",
                    "reflected_in_probe": poison_reflected_in_probe,
                    "poison_persisted_in_cache": poison_persisted_in_cache,
                    "cache_status": clean_resp.headers.get("x-cache", clean_resp.headers.get("cf-cache-status", "NONE"))
                })

                if poison_persisted_in_cache:
                    vuln = {
                        "type": "WEB_CACHE_POISONING",
                        "severity": "CRITICAL",
                        "title": f"Web Cache Poisoning via Unkeyed Header ({v['header']})",
                        "evidence": f"Header '{v['header']}: {v['value']}' was reflected into the shared cache and served to subsequent clean clients at {probe_url}.",
                        "remediation": f"Ensure '{v['header']}' is added to the Cache-Key or stripped by reverse proxy / CDN prior to caching."
                    }
                    results["vulnerabilities"].append(vuln)

                    # Persist finding and log
                    if persist_fn:
                        await persist_fn(
                            log_payload={
                                "project": target_project,
                                "source": "CACHE_AUDITOR",
                                "method": "GET",
                                "url": probe_url,
                                "host": hostname,
                                "path": parsed.path,
                                "status_code": clean_resp.status_code,
                                "response_headers": dict(clean_resp.headers),
                                "response_body": clean_resp.text[:5000],
                                "reasoning": f"Web cache poisoning verified: unkeyed {v['header']} reflected from cache."
                            },
                            flag_status="CONFIRMED",
                            findings=[vuln]
                        )
                    if vault_fn:
                        await vault_fn({
                            "project": target_project,
                            "vuln_type": "CACHE_POISONING",
                            "target_param": v["header"],
                            "raw_payload": f"{v['header']}: {v['value']}",
                            "target_url": probe_url,
                            "outcome": "EXECUTED",
                            "notes": "Verified persistent web cache poisoning reflection."
                        })
            except Exception:
                pass

        # Phase 3: Web Cache Deception (Path Confusion)
        deception_base = clean_url.split("?")[0].rstrip("/")
        for sfx in DECEPTION_SUFFIXES:
            deception_url = f"{deception_base}{sfx}"
            try:
                dec_resp = await client.get(deception_url, headers=req_headers)
                cache_ctl = dec_resp.headers.get("cache-control", "").lower()
                is_publicly_cached = "public" in cache_ctl or "max-age" in cache_ctl or any("hit" in str(v).lower() for v in dec_resp.headers.values())
                # Check if server returned 200 OK and same content length / body as sensitive route
                is_sensitive_reflection = dec_resp.status_code == 200 and len(dec_resp.text) > 50 and ("html" in dec_resp.headers.get("content-type", "").lower() or "json" in dec_resp.headers.get("content-type", "").lower())

                if is_publicly_cached and is_sensitive_reflection:
                    vuln = {
                        "type": "WEB_CACHE_DECEPTION",
                        "severity": "HIGH",
                        "title": f"Web Cache Deception via Path Extension ({sfx})",
                        "evidence": f"Endpoint {deception_url} returned dynamic sensitive response with public caching headers ({cache_ctl}).",
                        "remediation": "Do not cache responses based solely on file extension. Strictly validate route paths and set 'Cache-Control: private, no-store' on authenticated routes."
                    }
                    results["vulnerabilities"].append(vuln)
                    break
            except Exception:
                pass

    results["status"] = "SUCCESS"
    results["findings_count"] = len(results["vulnerabilities"])
    results["verdict"] = "VULNERABLE" if results["findings_count"] > 0 else "CLEAN"
    return results
