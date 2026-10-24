"""
Proxsynth - Business Logic & Numeric Boundary Flaw Fuzzer
Audits numeric, currency, quantity, and limit parameters to detect negative balance exploits,
zero-cost checkout bypasses, floating point rounding flaws, and integer overflow conditions.
"""

import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from backend.database import SessionLocal, HttpLog, Finding
from backend.diff_engine import detect_soft_errors
from backend.user_agents import apply_rotating_user_agent
from backend.forward_proxy import _get_upstream_proxy

# Keywords identifying business-critical numeric fields
NUMERIC_FIELD_KEYWORDS = [
    "price", "amount", "qty", "quantity", "count", "total", "balance",
    "discount", "credits", "coins", "points", "subtotal", "cost", "fee"
]

# Boundary test cases for business logic probing
LOGIC_TEST_VECTORS = [
    ("-1", "Negative Value Manipulation (-1)", "HIGH", "Verifies whether negative counts or prices alter accounting totals or generate credit."),
    ("-9999", "Extreme Negative Value (-9999)", "HIGH", "Tests if backend validation ignores large negative values."),
    ("0", "Zero-Cost Bypass (0)", "MEDIUM", "Tests whether zero-value transactions are approved without payment verification."),
    ("0.0000001", "Floating Point Precision Underflow (0.0000001)", "MEDIUM", "Exploits round-down behavior to bypass fractional unit pricing."),
    ("2147483648", "32-bit Integer Overflow (2147483648)", "HIGH", "Tests for arithmetic wrap-around into negative numbers on 32-bit integers."),
    ("9223372036854775808", "64-bit Integer Overflow (9223372036854775808)", "MEDIUM", "Tests for 64-bit integer overflow exceptions or boundary bypass.")
]


async def audit_numeric_business_logic(
    log_id: int,
    target_param: Optional[str] = None,
    project: str = "default",
    ws_broadcast_callback=None
) -> Dict[str, Any]:
    """
    Audits an observed request for Business Logic & Numeric Boundary flaws:
    Tests negative values, zero-cost parameters, and integer overflows.
    """
    clean_project = (project or "default").strip().lower()
    db = SessionLocal()
    findings_created = []
    tests_executed = []

    try:
        log = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if not log:
            return {"status": "error", "message": f"HttpLog #{log_id} not found"}

        url = log.url
        method = (log.method or "GET").upper()
        req_body = log.request_body or ""
        parsed = urllib.parse.urlparse(url)

        req_headers = {}
        if log.request_headers:
            try:
                req_headers = json.loads(log.request_headers)
            except Exception:
                pass

        upstream_p = _get_upstream_proxy(clean_project)
        proxy_kwargs = {"proxy": upstream_p} if upstream_p else {"proxy": None, "trust_env": False}

        # Identify target parameters in Query or JSON body
        candidates = []

        # Check Query String
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query)
            for k in qs.keys():
                if target_param and k.lower() != target_param.lower():
                    continue
                if any(kw in k.lower() for kw in NUMERIC_FIELD_KEYWORDS):
                    candidates.append(("query", k, qs[k][0]))

        # Check JSON Body
        is_json = False
        parsed_json = None
        if req_body.strip().startswith("{"):
            try:
                parsed_json = json.loads(req_body)
                if isinstance(parsed_json, dict):
                    is_json = True
                    for k, v in parsed_json.items():
                        if target_param and k.lower() != target_param.lower():
                            continue
                        if any(kw in k.lower() for kw in NUMERIC_FIELD_KEYWORDS):
                            candidates.append(("json", k, v))
            except Exception:
                pass

        if not candidates and target_param:
            # Force target param into JSON or query
            candidates.append(("json" if is_json else "query", target_param, 1))

        for param_loc, param_name, orig_val in candidates:
            for probe_val, test_name, severity, desc in LOGIC_TEST_VECTORS:
                test_url = url
                test_body = req_body

                if param_loc == "query":
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[param_name] = [probe_val]
                    new_q = urllib.parse.urlencode({k: v[0] for k, v in qs.items()})
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment
                    ))
                elif param_loc == "json" and parsed_json is not None:
                    mutated = dict(parsed_json)
                    try:
                        # Try int or float if probe_val is numeric
                        if "." in probe_val:
                            mutated[param_name] = float(probe_val)
                        else:
                            mutated[param_name] = int(probe_val)
                    except Exception:
                        mutated[param_name] = probe_val
                    test_body = json.dumps(mutated)

                probe_headers = dict(req_headers)
                probe_headers, _ = apply_rotating_user_agent(probe_headers)

                try:
                    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=httpx.Timeout(3.0, connect=0.8), **proxy_kwargs) as client:
                        resp = await client.request(
                            method=method,
                            url=test_url,
                            headers=probe_headers,
                            content=test_body.encode("utf-8") if test_body else None
                        )

                        resp_text = resp.text or ""
                        resp_status = resp.status_code
                        soft = detect_soft_errors(resp_status, resp_text)

                        tests_executed.append({
                            "param": param_name,
                            "probe": probe_val,
                            "status": resp_status,
                            "test": test_name
                        })

                        # Vulnerability Condition:
                        # Server returned 200/201 (success) when negative, zero, or overflow value was passed
                        # without rejecting business transaction (not a soft error or validation failure)
                        has_validation_denial = any(w in resp_text.lower() for w in [
                            "must be positive", "invalid amount", "invalid quantity", "cannot be negative",
                            "below minimum", "validation error", "must be greater than"
                        ])

                        if resp_status in [200, 201] and not soft["is_soft_403"] and not has_validation_denial and len(resp_text) > 30:
                            title = f"Business Logic Flaw: {test_name} accepted on '{param_name}' ({parsed.path})"
                            evidence = (
                                f"Parameter: {param_name}\n"
                                f"Original Value: {orig_val}\n"
                                f"Injected Value: {probe_val}\n"
                                f"Server Response Status: {resp_status}\n"
                                f"Response Snippet:\n{resp_text[:300]}"
                            )
                            remediation = (
                                f"Enforce strict server-side boundary validation on parameter '{param_name}'. "
                                f"Reject non-positive integers, fractional decimals below threshold, and "
                                f"validate arithmetic values against strict minimum/maximum bounds before processing."
                            )

                            existing = db.query(Finding).filter(Finding.log_id == log.id, Finding.title == title).first()
                            if not existing:
                                finding = Finding(
                                    log_id=log.id,
                                    title=title,
                                    severity=severity,
                                    category="Business Logic & Numeric Boundary Flaw",
                                    evidence=evidence,
                                    description=desc,
                                    remediation=remediation
                                )
                                db.add(finding)
                                db.commit()
                                db.refresh(finding)
                                findings_created.append(finding.to_dict())

                                if ws_broadcast_callback:
                                    try:
                                        await ws_broadcast_callback({
                                            "type": "BUSINESS_LOGIC_HIT",
                                            "finding": finding.to_dict(),
                                            "url": url,
                                            "param": param_name
                                        })
                                    except Exception:
                                        pass
                except Exception:
                    continue

        return {
            "status": "completed",
            "log_id": log_id,
            "url": log.url,
            "params_tested": len(candidates),
            "tests_executed": len(tests_executed),
            "findings_detected": len(findings_created),
            "findings": findings_created
        }
    finally:
        db.close()
