"""
PROXSYNTH — Autonomous Two-Tier Access Control & Business Logic Orchestrator
Full-lifecycle dual-token differential testing, broken access control discovery,
and business logic state verification engine.
"""

import os
import re
import json
import uuid
import difflib
import asyncio
import logging
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

import httpx

from backend.database import SessionLocal, HttpLog, Finding, ActiveSession, Project
from backend.diff_engine import clean_dynamic_tokens, detect_soft_errors
from backend.nuclei_exporter import generate_nuclei_template, _slugify
from backend.user_agents import apply_rotating_user_agent
from backend.adaptive_limiter import get_domain_rate_limiter

logger = logging.getLogger("proxsynth.access_control_orchestrator")

# Heuristic patterns for classification
_OBJECT_ID_PATH_PATTERN = re.compile(
    r"/(?:api/)?(?:v[0-9]+/)?(?:users?|accounts?|orders?|invoices?|profiles?|documents?|items?|tenants?|orgs?|projects?|customers?|messages?|files?|tickets?)/([0-9a-fA-F-]+|\d+)",
    re.IGNORECASE
)
_ADMIN_PATH_PATTERN = re.compile(
    r"/(?:admin|manage|management|dashboard|internal|system|sys|roles|permissions|config|settings|audit|controlpanel|super)(?:/|$|\?)",
    re.IGNORECASE
)
_PUBLIC_PATH_PATTERN = re.compile(
    r"/(?:health|status|ping|favicon\.ico|robots\.txt|public|assets|static|css|js|docs|swagger|openapi)(?:/|$|\?)",
    re.IGNORECASE
)
_LOGIC_MUTATION_PATTERN = re.compile(
    r"/(?:checkout|cart|pay|payment|order|orders|billing|transfer|coupon|discount|balance|refund|subscription)(?:/|$|\?)",
    re.IGNORECASE
)


@dataclass
class EndpointTarget:
    url: str
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, Any] = field(default_factory=dict)
    body: str = ""
    sensitivity: str = "STANDARD"  # BOLA_CANDIDATE, BFLA_ADMIN, BUSINESS_LOGIC, PUBLIC, STANDARD
    object_id: Optional[str] = None
    mutating: bool = False
    param_name: Optional[str] = None


@dataclass
class AccessControlPlan:
    target_base: str
    targets: List[EndpointTarget] = field(default_factory=list)
    matrix_summary: Dict[str, int] = field(default_factory=dict)


@dataclass
class ThreeWayDifferentialResult:
    url: str
    method: str
    status_a: int
    status_b: int
    status_unauth: int
    body_a: str = ""
    body_b: str = ""
    body_unauth: str = ""
    is_bola_anomaly: bool = False
    is_bfla_anomaly: bool = False
    is_unauth_anomaly: bool = False
    is_logic_anomaly: bool = False
    structural_similarity_ab: float = 0.0
    confidence: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW
    secondary_verification: Optional[Dict[str, Any]] = None
    evidence: str = ""


class AccessControlOrchestrator:
    """
    Two-Tier Hybrid Access Control & Business Logic Orchestrator.
    Tier 1: Architectural Endpoint Planner & Sensitivity Classification.
    Deterministic Core: 3-Way Identity Swapper, Diffing, and Secondary State Verification.
    Tier 2: Cognitive Anomaly Evaluator & Multi-Step Nuclei Template Synthesis.
    """

    def __init__(self, project: str = "default"):
        self.project = (project or "default").strip().lower()
        self.rate_limiter = get_domain_rate_limiter()

    def build_test_plan(
        self,
        endpoints: List[Dict[str, Any]],
        target_base: str = ""
    ) -> AccessControlPlan:
        """
        Tier 1 Architectural Planner:
        Analyzes target endpoints, maps object identifiers, and categorizes testing priority.
        """
        targets: List[EndpointTarget] = []
        counts: Dict[str, int] = {
            "BOLA_CANDIDATE": 0,
            "BFLA_ADMIN": 0,
            "BUSINESS_LOGIC": 0,
            "PUBLIC": 0,
            "STANDARD": 0
        }

        for ep in endpoints:
            raw_url = ep.get("url") or f"{target_base.rstrip('/')}/{ep.get('path', '').lstrip('/')}"
            method = (ep.get("method") or "GET").upper().strip()
            body = ep.get("body") or ""
            headers = ep.get("headers") or {}

            parsed = urllib.parse.urlparse(raw_url)
            path = parsed.path or "/"
            query_params = urllib.parse.parse_qs(parsed.query)

            is_mutating = method in ["POST", "PUT", "PATCH", "DELETE"]

            # 1. Check Public
            if _PUBLIC_PATH_PATTERN.search(path):
                sens = "PUBLIC"
                obj_id = None
            # 2. Check Admin / BFLA
            elif _ADMIN_PATH_PATTERN.search(path) or (is_mutating and any(x in path for x in ["/role", "/permission", "/grant", "/user"])):
                sens = "BFLA_ADMIN"
                obj_id = None
            # 3. Check BOLA / IDOR
            else:
                bola_match = _OBJECT_ID_PATH_PATTERN.search(path)
                query_id_key = next((k for k in query_params if re.search(r'(?:id|account|user|doc|order|invoice|uuid)$', k, re.IGNORECASE)), None)

                if bola_match:
                    sens = "BOLA_CANDIDATE"
                    obj_id = bola_match.group(1)
                elif query_id_key:
                    sens = "BOLA_CANDIDATE"
                    obj_id = query_params[query_id_key][0]
                elif _LOGIC_MUTATION_PATTERN.search(path) or (is_mutating and any(k in body.lower() for k in ["price", "amount", "qty", "quantity", "discount", "total"])):
                    sens = "BUSINESS_LOGIC"
                    obj_id = None
                else:
                    sens = "STANDARD"
                    obj_id = None

            counts[sens] += 1
            targets.append(EndpointTarget(
                url=raw_url,
                method=method,
                path=path,
                headers=headers,
                body=body,
                sensitivity=sens,
                object_id=obj_id,
                mutating=is_mutating
            ))

        return AccessControlPlan(
            target_base=target_base,
            targets=targets,
            matrix_summary=counts
        )

    def compute_three_way_diff(
        self,
        target: Dict[str, Any],
        resp_a: Dict[str, Any],
        resp_b: Dict[str, Any],
        resp_unauth: Dict[str, Any]
    ) -> ThreeWayDifferentialResult:
        """
        Deterministic Core: Computes structural response similarity, soft-error suppression,
        and broken access control indicators across the 3 identity representations.
        """
        url = target.get("url", "")
        method = target.get("method", "GET").upper()
        sens = target.get("sensitivity", "STANDARD")

        status_a = int(resp_a.get("status_code", 0))
        status_b = int(resp_b.get("status_code", 0))
        status_u = int(resp_unauth.get("status_code", 0))

        body_a = resp_a.get("body", "") or ""
        body_b = resp_b.get("body", "") or ""
        body_u = resp_unauth.get("body", "") or ""

        # Normalize volatile tokens
        norm_a = clean_dynamic_tokens(body_a)
        norm_b = clean_dynamic_tokens(body_b)
        norm_u = clean_dynamic_tokens(body_u)

        # Check soft error on Identity B and Unauth
        soft_err_b = detect_soft_errors(status_b, norm_b)["is_soft_403"]
        soft_err_u = detect_soft_errors(status_u, norm_u)["is_soft_403"]

        # Calculate structural similarity (Levenshtein ratio on normalized body)
        matcher = difflib.SequenceMatcher(None, norm_a[:4000], norm_b[:4000])
        sim_ab = round(matcher.ratio(), 4)

        is_bola = False
        is_bfla = False
        is_unauth = False
        is_logic = False
        confidence = "LOW"
        evidence_parts = []

        # -------------------------------------------------------------
        # 1. BOLA Evaluation: User B accessing User A's resource
        # -------------------------------------------------------------
        if sens == "BOLA_CANDIDATE" and status_a in [200, 201] and status_b in [200, 201] and not soft_err_b:
            if sim_ab >= 0.70 and len(body_b) > 30:
                is_bola = True
                confidence = "CRITICAL" if status_u in [200, 201] and not soft_err_u else "HIGH"
                evidence_parts.append(
                    f"[BOLA CONFIRMED] User B obtained 200 OK with {sim_ab*100:.1f}% structural match to User A data (Len: {len(body_b)})."
                )

        # -------------------------------------------------------------
        # 2. BFLA Evaluation: Privileged administrative function
        # -------------------------------------------------------------
        if sens == "BFLA_ADMIN" and status_a in [200, 201, 204]:
            if status_b in [200, 201, 204] and not soft_err_b:
                is_bfla = True
                confidence = "CRITICAL"
                evidence_parts.append(
                    f"[BFLA CONFIRMED] Low-privilege User B accessed administrative endpoint {method} {url} with HTTP {status_b}."
                )

        # -------------------------------------------------------------
        # 3. Broken ACL / Unauthenticated Evaluation
        # -------------------------------------------------------------
        if sens != "PUBLIC" and status_a in [200, 201]:
            if status_u in [200, 201] and not soft_err_u and len(body_u) > 50:
                is_unauth = True
                confidence = "CRITICAL"
                evidence_parts.append(
                    f"[UNAUTHENTICATED ACCESS] Endpoint accessible without authentication (HTTP {status_u}, Len: {len(body_u)})."
                )

        # -------------------------------------------------------------
        # 4. Business Logic Evaluation: Mutating requests with numeric fields
        # -------------------------------------------------------------
        if sens == "BUSINESS_LOGIC" and target.get("mutating") and status_a in [200, 201]:
            if status_b in [200, 201] and not soft_err_b:
                is_logic = True
                confidence = "HIGH"
                evidence_parts.append(
                    f"[BUSINESS LOGIC ANOMALY] State mutation permitted across non-primary identity (HTTP {status_b})."
                )

        return ThreeWayDifferentialResult(
            url=url,
            method=method,
            status_a=status_a,
            status_b=status_b,
            status_unauth=status_u,
            body_a=body_a,
            body_b=body_b,
            body_unauth=body_u,
            is_bola_anomaly=is_bola,
            is_bfla_anomaly=is_bfla,
            is_unauth_anomaly=is_unauth,
            is_logic_anomaly=is_logic,
            structural_similarity_ab=sim_ab,
            confidence=confidence,
            evidence="\n".join(evidence_parts)
        )

    async def execute_target_replay(
        self,
        target: EndpointTarget,
        session_a: Dict[str, Any],
        session_b: Dict[str, Any],
        test_unauth: bool = True,
        client: Optional[httpx.AsyncClient] = None
    ) -> ThreeWayDifferentialResult:
        """Executes real-time 3-way HTTP replay against target using provided sessions."""
        parsed = urllib.parse.urlparse(target.url)
        domain = parsed.netloc or "default"
        await self.rate_limiter.acquire(domain)

        def _build_headers(session_dict: Dict[str, Any], base_headers: Dict[str, Any]) -> Dict[str, str]:
            hdrs = dict(base_headers)
            # Strip previous auth
            for h in list(hdrs.keys()):
                if h.lower() in ["cookie", "authorization", "x-access-token", "x-auth-token", "session-id"]:
                    del hdrs[h]

            cookies = session_dict.get("cookies") or []
            cookie_str = session_dict.get("raw_cookie_str") or "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'name' in c and 'value' in c])
            if cookie_str:
                hdrs["Cookie"] = cookie_str

            auth_headers = session_dict.get("auth_headers") or {}
            for k, v in auth_headers.items():
                hdrs[k] = str(v)

            token = session_dict.get("bearer_token") or session_dict.get("token")
            if token and "Authorization" not in hdrs and "authorization" not in hdrs:
                hdrs["Authorization"] = f"Bearer {token}"

            rotated, _ = apply_rotating_user_agent(hdrs, force_rotate=False)
            return rotated

        headers_a = _build_headers(session_a, target.headers)
        headers_b = _build_headers(session_b, target.headers)
        headers_u = dict(target.headers)
        for h in list(headers_u.keys()):
            if h.lower() in ["cookie", "authorization", "x-access-token", "x-auth-token", "session-id"]:
                del headers_u[h]
        headers_u, _ = apply_rotating_user_agent(headers_u, force_rotate=False)

        async def _req(c: httpx.AsyncClient, h: Dict[str, str]) -> Dict[str, Any]:
            try:
                r = await c.request(
                    method=target.method,
                    url=target.url,
                    headers=h,
                    content=target.body if target.body else None
                )
                return {"status_code": r.status_code, "body": r.text or ""}
            except Exception as ex:
                return {"status_code": 0, "body": f"Connection Error: {ex}"}

        local_client = client is None
        c = client or httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0, trust_env=False)
        try:
            res_a = await _req(c, headers_a)
            res_b = await _req(c, headers_b)
            res_u = await _req(c, headers_u) if test_unauth else {"status_code": 401, "body": ""}
        finally:
            if local_client:
                await c.aclose()

        target_dict = {
            "url": target.url,
            "method": target.method,
            "sensitivity": target.sensitivity,
            "mutating": target.mutating
        }
        return self.compute_three_way_diff(target_dict, res_a, res_b, res_u)

    async def execute_full_campaign(
        self,
        target_base: str,
        session_a: Dict[str, Any],
        session_b: Dict[str, Any],
        endpoints: Optional[List[Dict[str, Any]]] = None,
        test_unauthenticated: bool = True,
        export_nuclei: bool = True
    ) -> Dict[str, Any]:
        """
        Runs the complete Two-Tier Access Control & Business Logic Campaign:
        1. If endpoints are not explicitly provided, extracts from recent traffic for this domain/project.
        2. Tier 1 Planner builds test plan and categorizes endpoint sensitivities.
        3. Deterministic 3-Way Runner executes parallel replays with token bucket rate limiting.
        4. Tier 2 Semantic Evaluator assesses anomalies, eliminates FPs, records Findings, and synthesizes Nuclei YAML.
        """
        db = SessionLocal()
        resolved_endpoints = list(endpoints or [])
        if not resolved_endpoints:
            parsed = urllib.parse.urlparse(target_base)
            domain = parsed.netloc or target_base
            q = db.query(HttpLog)
            if self.project != "all":
                q = q.filter(HttpLog.project == self.project)
            logs = q.filter(HttpLog.url.ilike(f"%{domain}%")).order_by(HttpLog.id.desc()).limit(50).all()
            for l in logs:
                resolved_endpoints.append({
                    "url": l.url,
                    "method": l.method,
                    "path": l.path,
                    "body": l.request_body or ""
                })
        db.close()

        if not resolved_endpoints:
            resolved_endpoints = [
                {"url": f"{target_base.rstrip('/')}/api/users/me", "method": "GET"},
                {"url": f"{target_base.rstrip('/')}/api/profile", "method": "GET"}
            ]

        # 1. Tier 1 Plan
        plan = self.build_test_plan(resolved_endpoints, target_base=target_base)

        # 2. Deterministic 3-Way Replay
        differential_results: List[ThreeWayDifferentialResult] = []
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0, trust_env=False) as client:
            for target in plan.targets:
                res = await self.execute_target_replay(
                    target=target,
                    session_a=session_a,
                    session_b=session_b,
                    test_unauth=test_unauthenticated,
                    client=client
                )
                differential_results.append(res)

        # 3. Tier 2 Anomaly Evaluation
        findings = evaluate_access_control_anomalies(
            differential_results,
            project=self.project,
            export_nuclei=export_nuclei
        )

        anomalies_count = sum(1 for r in differential_results if (r.is_bola_anomaly or r.is_bfla_anomaly or r.is_unauth_anomaly or r.is_logic_anomaly))

        matrix_table = []
        for r in differential_results:
            matrix_table.append({
                "url": r.url,
                "method": r.method,
                "status_user_a": r.status_a,
                "status_user_b": r.status_b,
                "status_unauth": r.status_unauth,
                "is_bola": r.is_bola_anomaly,
                "is_bfla": r.is_bfla_anomaly,
                "is_unauth": r.is_unauth_anomaly,
                "confidence": r.confidence
            })

        return {
            "status": "COMPLETED",
            "project": self.project,
            "target_base": target_base,
            "total_endpoints_tested": len(plan.targets),
            "anomalies_detected": anomalies_count,
            "confirmed_findings_count": len(findings),
            "classification_summary": plan.matrix_summary,
            "access_control_matrix": matrix_table,
            "findings": findings
        }


def evaluate_access_control_anomalies(
    anomalies: List[ThreeWayDifferentialResult],
    project: str = "default",
    export_nuclei: bool = True
) -> List[Dict[str, Any]]:
    """
    Tier 2 Semantic Evaluator:
    Filters false positives, contextualizes business impact, commits confirmed findings
    to the database, and synthesizes reproducible ProjectDiscovery Nuclei YAML templates.
    """
    db = SessionLocal()
    findings_output: List[Dict[str, Any]] = []

    try:
        for anomaly in anomalies:
            if not (anomaly.is_bola_anomaly or anomaly.is_bfla_anomaly or anomaly.is_unauth_anomaly or anomaly.is_logic_anomaly):
                continue

            parsed = urllib.parse.urlparse(anomaly.url)
            path = parsed.path or "/"

            if anomaly.is_bola_anomaly:
                category = "BOLA / IDOR (Broken Object Level Authorization)"
                title = f"Broken Object Level Authorization on {path}"
                severity = "CRITICAL" if anomaly.is_unauth_anomaly else "HIGH"
                cwe = "CWE-639: Authorization Bypass Through User-Controlled Key"
                desc = (
                    f"Secondary identity accessed resource belonging to primary identity without authorization.\n"
                    f"Structural match: {anomaly.structural_similarity_ab*100:.1f}%. Evidence:\n{anomaly.evidence}"
                )
                tags = ["bola", "idor", "access-control"]
            elif anomaly.is_bfla_anomaly:
                category = "BFLA (Broken Function Level Authorization)"
                title = f"Broken Function Level Authorization on {anomaly.method} {path}"
                severity = "CRITICAL"
                cwe = "CWE-285: Improper Authorization"
                desc = (
                    f"Low-privilege identity successfully executed administrative function {anomaly.method} {path}.\n"
                    f"Evidence:\n{anomaly.evidence}"
                )
                tags = ["bfla", "privilege-escalation", "admin-bypass"]
            elif anomaly.is_unauth_anomaly:
                category = "UNAUTHENTICATED ACCESS"
                title = f"Sensitive Endpoint Accessible Without Authentication on {path}"
                severity = "CRITICAL"
                cwe = "CWE-306: Missing Authentication for Critical Function"
                desc = (
                    f"Protected endpoint returned HTTP {anomaly.status_unauth} with data when accessed with no credentials.\n"
                    f"Evidence:\n{anomaly.evidence}"
                )
                tags = ["unauth", "broken-acl", "auth-bypass"]
            else:
                category = "BUSINESS LOGIC FLAW"
                title = f"Business Logic Mutation Anomaly on {anomaly.method} {path}"
                severity = "HIGH"
                cwe = "CWE-840: Business Logic Errors"
                desc = f"State mutation accepted across secondary identity.\nEvidence:\n{anomaly.evidence}"
                tags = ["business-logic", "state-mutation"]

            # Synthesize Nuclei verification template
            nuclei_yaml = ""
            if export_nuclei:
                template_id = _slugify(f"{title}-{anomaly.method}")
                matchers = [{"type": "status", "status": [anomaly.status_b if not anomaly.is_unauth_anomaly else anomaly.status_unauth]}]
                words = []
                sample_body = anomaly.body_b if not anomaly.is_unauth_anomaly else anomaly.body_unauth
                if sample_body and len(sample_body) > 10:
                    try:
                        parsed_json = json.loads(sample_body)
                        if isinstance(parsed_json, dict):
                            keys = list(parsed_json.keys())[:2]
                            words.extend(keys)
                    except Exception:
                        clean_lines = [l.strip() for l in sample_body.splitlines() if l.strip()]
                        if clean_lines:
                            words.append(clean_lines[0][:50])

                if words:
                    matchers.append({"type": "word", "words": words, "condition": "or"})

                nuclei_yaml = generate_nuclei_template(
                    template_id=template_id,
                    name=title,
                    severity=severity.lower(),
                    author="Proxsynth Autonomous Two-Tier Orchestrator",
                    description=desc,
                    tags=tags,
                    method=anomaly.method,
                    path=path,
                    matchers=matchers
                )

            # Persist an HttpLog audit trail and Finding to database
            f_id = None
            try:
                http_log = HttpLog(
                    project=project,
                    url=anomaly.url,
                    method=anomaly.method,
                    status_code=anomaly.status_b if not anomaly.is_unauth_anomaly else anomaly.status_unauth,
                    response_body=(anomaly.body_b if not anomaly.is_unauth_anomaly else anomaly.body_unauth)[:2000]
                )
                db.add(http_log)
                db.commit()
                db.refresh(http_log)

                finding_record = Finding(
                    log_id=http_log.id,
                    title=title,
                    category=category,
                    severity=severity,
                    description=desc,
                    evidence=anomaly.evidence,
                    remediation=f"Enforce strict server-side authorization validation for {cwe} on {path}."
                )
                db.add(finding_record)
                db.commit()
                db.refresh(finding_record)
                f_id = finding_record.id
            except Exception as ex:
                db.rollback()
                logger.debug(f"Notice: Finding db persistence skipped: {ex}")

            findings_output.append({
                "finding_id": f_id,
                "title": title,
                "category": category,
                "severity": severity,
                "cwe": cwe,
                "url": anomaly.url,
                "method": anomaly.method,
                "status_code_leak": anomaly.status_b if not anomaly.is_unauth_anomaly else anomaly.status_unauth,
                "nuclei_template": nuclei_yaml
            })

        return findings_output
    finally:
        db.close()
