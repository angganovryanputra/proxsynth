"""
Proxsynth - Autonomous Mass Assignment & Privilege Parameter Injection Engine
Audits mutation endpoints (POST, PUT, PATCH) by injecting administrative attributes
into JSON, Form, and query-string payloads to detect over-posting and unauthorized
privilege escalation.
"""

import json
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from backend.database import SessionLocal, HttpLog, Finding
from backend.diff_engine import detect_soft_errors
from backend.user_agents import apply_rotating_user_agent
from backend.forward_proxy import _get_upstream_proxy

# Privilege and administrative parameters to test for Mass Assignment
ADMIN_ATTRIBUTES = {
    "is_admin": True,
    "isAdmin": True,
    "role": "admin",
    "user_role": "superuser",
    "permissions": ["*"],
    "verified": True,
    "is_verified": True,
    "email_verified": True,
    "account_type": "admin",
    "tier": "enterprise",
    "balance": 999999,
    "credit": 999999,
    "discount": 100,
    "org_id": 1,
    "tenant_id": 1,
    "owner_id": 1,
    "status": "active",
    "approved": True,
    "active": True,
    "plan": "unlimited"
}

# Minimum absolute byte-length difference considered "meaningful" when no
# baseline-relative percentage threshold is larger. Set high enough that common
# dynamic response noise (CSRF tokens, timestamps, nonces, request ids) does not
# on its own cross the threshold and manufacture a false "response delta" hit.
_MIN_MEANINGFUL_LENGTH_DELTA = 96
_MEANINGFUL_LENGTH_DELTA_RATIO = 0.05


def build_mass_assignment_payloads(
    base_body: str,
    content_type: str,
    attributes: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Pure helper: builds the set of mass-assignment injection attempts for a
    given base request body (or query string) and content type.

    content_type is one of:
      - "application/json"                  -> base_body is a JSON object; produces
                                                 a top-level injection and, if a nested
                                                 object field exists, one nested-level
                                                 injection.
      - "application/x-www-form-urlencoded" -> base_body is a form-encoded string.
      - "query"                              -> base_body is a raw query string (no
                                                 leading '?'); produces a query-string
                                                 injection.

    Returns a list of dicts, each describing one injection attempt:
      {
        "kind": "json_top" | "json_nested" | "form" | "query",
        "body": <mutated body / query string as str>,
        "content_type": <effective content-type label>,
        "injected_fields": [<field names actually injected>],
        "injected_map": {<field>: <injected value>},
        "label": <human-readable description>,
      }
    Only fields not already present in the base body are injected (so this is
    purely additive / over-posting, never overwriting an existing value).
    """
    attrs = dict(attributes) if attributes else dict(ADMIN_ATTRIBUTES)
    payloads: List[Dict[str, Any]] = []
    ct = (content_type or "").strip().lower()

    if ct == "application/json":
        parsed: Optional[Any] = None
        try:
            parsed = json.loads(base_body) if base_body else {}
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            # Top-level injection
            mutated = dict(parsed)
            injected_fields: List[str] = []
            for k, v in attrs.items():
                if k not in mutated:
                    mutated[k] = v
                    injected_fields.append(k)
            if injected_fields:
                payloads.append({
                    "kind": "json_top",
                    "body": json.dumps(mutated),
                    "content_type": "application/json",
                    "injected_fields": injected_fields,
                    "injected_map": {k: attrs[k] for k in injected_fields},
                    "label": "JSON top-level mass-assignment injection",
                })

            # Nested (one level deep) injection: use the first nested object found.
            for nested_key, nested_val in parsed.items():
                if isinstance(nested_val, dict):
                    nested_inner = dict(nested_val)
                    nested_injected_fields: List[str] = []
                    for k, v in attrs.items():
                        if k not in nested_inner:
                            nested_inner[k] = v
                            nested_injected_fields.append(k)
                    if nested_injected_fields:
                        mutated_nested = dict(parsed)
                        mutated_nested[nested_key] = nested_inner
                        payloads.append({
                            "kind": "json_nested",
                            "body": json.dumps(mutated_nested),
                            "content_type": "application/json",
                            "injected_fields": nested_injected_fields,
                            "injected_map": {k: attrs[k] for k in nested_injected_fields},
                            "label": f"JSON nested-level mass-assignment injection (field '{nested_key}')",
                        })
                    break  # only one nested level per spec

    elif ct == "application/x-www-form-urlencoded":
        try:
            params = urllib.parse.parse_qs(base_body or "", keep_blank_values=True)
        except Exception:
            params = {}
        flat = {k: v[0] for k, v in params.items()}
        injected_fields = []
        for k, v in attrs.items():
            if k not in flat:
                flat[k] = str(v)
                injected_fields.append(k)
        if injected_fields:
            payloads.append({
                "kind": "form",
                "body": urllib.parse.urlencode(flat),
                "content_type": "application/x-www-form-urlencoded",
                "injected_fields": injected_fields,
                "injected_map": {k: attrs[k] for k in injected_fields},
                "label": "Form-urlencoded mass-assignment injection",
            })

    elif ct == "query":
        try:
            params = urllib.parse.parse_qs(base_body or "", keep_blank_values=True)
        except Exception:
            params = {}
        flat = {k: v[0] for k, v in params.items()}
        injected_fields = []
        for k, v in attrs.items():
            if k not in flat:
                flat[k] = str(v)
                injected_fields.append(k)
        if injected_fields:
            payloads.append({
                "kind": "query",
                "body": urllib.parse.urlencode(flat),
                "content_type": "query",
                "injected_fields": injected_fields,
                "injected_map": {k: attrs[k] for k in injected_fields},
                "label": "Query-string mass-assignment injection",
            })

    return payloads


def evaluate_mass_assignment(
    injected_field: str,
    injected_value: Any,
    baseline: Optional[Dict[str, Any]],
    injected: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Pure helper: decides whether a single injected privilege field likely took
    effect, given the injected-request response and (optionally) the baseline
    (un-injected) response.

    `injected` and `baseline` (when provided) are dicts shaped like:
      {"status": <int>, "text": <str>}

    Confirmation signal (either qualifies as a hit):
      1. The injected field is reflected back in the response body with a
         matching value (JSON key match, or substring match for non-JSON
         bodies).
      2. The injected response is a 2xx, is not a soft-403/soft-404, AND
         shows a meaningful delta vs. the baseline (became successful where
         baseline was not, a meaningful response-length delta, or a change
         in soft-error classification).

    Returns:
      {
        "hit": bool,
        "reflected": bool,
        "delta_hit": bool,
        "status": int,
        "is_soft_403": bool,
        "is_soft_404": bool,
      }
    """
    status = int(injected.get("status") or 0)
    text = injected.get("text") or ""
    soft = detect_soft_errors(status, text)

    reflected = False
    try:
        resp_json = json.loads(text)
        if isinstance(resp_json, dict) and injected_field in resp_json:
            if str(resp_json[injected_field]).lower() == str(injected_value).lower():
                reflected = True
    except Exception:
        pattern = f'"{injected_field}":'
        if pattern in text:
            reflected = True

    delta_hit = False
    is_nominal_success = 200 <= status < 300
    if not reflected and is_nominal_success and not soft["is_soft_403"] and not soft["is_soft_404"]:
        if baseline is not None:
            baseline_status = int(baseline.get("status") or 0)
            baseline_text = baseline.get("text") or ""
            baseline_soft = detect_soft_errors(baseline_status, baseline_text)

            baseline_was_success = 200 <= baseline_status < 300
            # A clear authorization/validation rejection on the un-injected
            # baseline is the only non-2xx state we trust: if the baseline is
            # explicitly denied but the injected request succeeds, the injected
            # privilege field plausibly bound and unlocked access.
            baseline_rejected = (
                baseline_status in (401, 403, 422)
                or baseline_soft["is_soft_403"]
                or baseline_soft["is_soft_404"]
            )
            length_delta = abs(len(text) - len(baseline_text))
            meaningful_len_delta = length_delta >= max(
                _MIN_MEANINGFUL_LENGTH_DELTA,
                int(_MEANINGFUL_LENGTH_DELTA_RATIO * max(len(baseline_text), 1))
            )
            soft_delta = (
                soft["is_soft_403"] != baseline_soft["is_soft_403"]
                or soft["is_soft_404"] != baseline_soft["is_soft_404"]
            )

            if baseline_rejected:
                delta_hit = True
            elif baseline_was_success and (meaningful_len_delta or soft_delta):
                delta_hit = True
            # A transient / non-rejection baseline failure (429, 5xx, a timeout
            # that still returned a body) is inconclusive and is NOT treated as a
            # hit: otherwise any flaky baseline would flip delta_hit true for
            # every injected field on every probe (false-positive amplification).
        # No baseline available: only the reflection signal applies.

    return {
        "hit": bool(reflected or delta_hit),
        "reflected": reflected,
        "delta_hit": delta_hit,
        "status": status,
        "is_soft_403": soft["is_soft_403"],
        "is_soft_404": soft["is_soft_404"],
    }


async def audit_mass_assignment(
    log_id: int,
    custom_attributes: Optional[Dict[str, Any]] = None,
    project: str = "default",
    ws_broadcast_callback=None
) -> Dict[str, Any]:
    """
    Scans a captured mutation request for Mass Assignment (Over-Posting) vulnerabilities.
    Injects elevated privilege attributes into the payload (JSON top-level and one
    nested level, form-urlencoded body, and query-string) and evaluates whether the
    server persists or reflects the elevated properties in its response.
    """
    clean_project = (project or "default").strip().lower()
    db = SessionLocal()
    findings_created = []

    try:
        log = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if not log:
            return {"status": "error", "message": f"HttpLog #{log_id} not found"}

        clean_method = (log.method or "POST").upper()
        if clean_method not in ["POST", "PUT", "PATCH"]:
            return {"status": "skipped", "message": f"Method {clean_method} is not a mutation endpoint"}

        req_body = (log.request_body or "").strip()
        parsed_json: Optional[Dict[str, Any]] = None
        is_json = False

        if req_body.startswith("{") or req_body.startswith("["):
            try:
                parsed_json = json.loads(req_body)
                if isinstance(parsed_json, dict):
                    is_json = True
            except Exception:
                pass

        # Prepare attributes to inject
        test_attributes = dict(ADMIN_ATTRIBUTES)
        if custom_attributes:
            test_attributes.update(custom_attributes)

        upstream_p = _get_upstream_proxy(clean_project)
        proxy_kwargs = {"proxy": upstream_p} if upstream_p else {"proxy": None, "trust_env": False}

        req_headers = {}
        if log.request_headers:
            try:
                req_headers = json.loads(log.request_headers)
            except Exception:
                pass

        # Build injection attempts via the pure helper, chosen by content type.
        injected_probes: List[Dict[str, Any]] = []

        if is_json and parsed_json is not None:
            injected_probes.extend(
                build_mass_assignment_payloads(req_body, "application/json", test_attributes)
            )
        elif "=" in req_body:
            injected_probes.extend(
                build_mass_assignment_payloads(req_body, "application/x-www-form-urlencoded", test_attributes)
            )

        # Query-string injection is independent of body shape (and applies even
        # when the body itself is JSON/form), chosen by whether the endpoint's
        # URL already carries a query string.
        split_url = urllib.parse.urlsplit(log.url)
        if split_url.query:
            injected_probes.extend(
                build_mass_assignment_payloads(split_url.query, "query", test_attributes)
            )

        baseline: Optional[Dict[str, Any]] = None
        if injected_probes:
            baseline_headers = dict(req_headers)
            baseline_headers, _ = apply_rotating_user_agent(baseline_headers)
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=httpx.Timeout(3.0, connect=0.8), **proxy_kwargs) as client:
                    baseline_resp = await client.request(
                        method=clean_method,
                        url=log.url,
                        headers=baseline_headers,
                        content=(req_body or "").encode("utf-8")
                    )
                    baseline = {"status": baseline_resp.status_code, "text": baseline_resp.text or ""}
            except Exception:
                baseline = None

        for probe in injected_probes:
            kind = probe["kind"]
            keys_tested = probe["injected_fields"]
            injected_map = probe["injected_map"]

            probe_headers = dict(req_headers)
            if kind == "query":
                request_url = urllib.parse.urlunsplit((
                    split_url.scheme, split_url.netloc, split_url.path, probe["body"], split_url.fragment
                ))
                request_body_bytes = (req_body or "").encode("utf-8")
                # Leave Content-Type as the original request's; the mutation is in the URL.
            else:
                request_url = log.url
                request_body_bytes = probe["body"].encode("utf-8")
                probe_headers["Content-Type"] = probe["content_type"]

            probe_headers, _ = apply_rotating_user_agent(probe_headers)

            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=httpx.Timeout(3.0, connect=0.8), **proxy_kwargs) as client:
                    resp = await client.request(
                        method=clean_method,
                        url=request_url,
                        headers=probe_headers,
                        content=request_body_bytes
                    )

                    resp_text = resp.text or ""
                    resp_status = resp.status_code
                    injected_resp = {"status": resp_status, "text": resp_text}

                    reflected_keys = []
                    delta_detected = False
                    for k in keys_tested:
                        evaluation = evaluate_mass_assignment(k, injected_map[k], baseline, injected_resp)
                        if evaluation["reflected"]:
                            reflected_keys.append(f"{k}={injected_map[k]}")
                        elif evaluation["delta_hit"]:
                            delta_detected = True

                    # Reflected fields are individually attributable. A whole-
                    # response delta is a property of the probe as a whole and
                    # cannot be pinned to any single injected field, so it is
                    # reported once per probe (and only when nothing concretely
                    # reflected) rather than duplicated across every field.
                    accepted_keys = list(reflected_keys)
                    if delta_detected and not reflected_keys:
                        accepted_keys.append(
                            f"response delta vs baseline ({probe['kind']} probe, "
                            f"{len(keys_tested)} privilege fields injected)"
                        )

                    if accepted_keys:
                        title = f"Mass Assignment / Over-Posting on {log.path} ({', '.join(accepted_keys[:3])})"
                        desc = (
                            f"The mutation endpoint '{log.path}' appears to bind administrative properties into "
                            f"its internal model without strict DTO validation. The server accepted the following "
                            f"injected privilege signals (reflected values are confirmed bound; a 'response delta' "
                            f"indicates a behavioural change that warrants manual confirmation): {', '.join(accepted_keys)}."
                        )
                        evidence = (
                            f"Injection Vector: {probe['label']}\n"
                            f"Injected Payload Keys: {', '.join(keys_tested)}\n"
                            f"Confirmed Bound Properties: {', '.join(accepted_keys)}\n"
                            f"Response Status: {resp_status}\n"
                            f"Response Snippet:\n{resp_text[:350]}"
                        )
                        remediation = (
                            "Implement strict Data Transfer Object (DTO) schema validation. Never bind request "
                            "parameters directly to database or entity models. Use allowlists for accepted fields."
                        )

                        existing = db.query(Finding).filter(Finding.log_id == log.id, Finding.title == title).first()
                        if not existing:
                            finding = Finding(
                                log_id=log.id,
                                title=title,
                                severity="HIGH",
                                category="Mass Assignment / Over-Posting",
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
                                        "type": "MASS_ASSIGNMENT_HIT",
                                        "finding": finding.to_dict(),
                                        "url": log.url,
                                        "accepted_keys": accepted_keys
                                    })
                                except Exception:
                                    pass
            except Exception:
                continue

        return {
            "status": "completed",
            "log_id": log_id,
            "url": log.url,
            "method": clean_method,
            "findings_count": len(findings_created),
            "findings": findings_created
        }
    finally:
        db.close()
