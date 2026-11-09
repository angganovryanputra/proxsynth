"""
PROXSYNTH — Workflow-Aware Business Logic Auditor
Given a single captured flow, decides which business-logic abuse tests apply —
workflow/approval-state bypass, mass-assignment (over-posting), numeric-boundary —
runs the right engines, and returns a machine-actionable validity decision an LLM can
act on directly, token-efficiently. Vertical approval authorization (a low-privilege
role performing an approver-only action) is handled as BFLA by `audit_bac_flow`.
"""

import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional

from backend.database import SessionLocal, HttpLog
from backend.mass_assignment_engine import audit_mass_assignment
from backend.logic_fuzzer import audit_numeric_business_logic

# Workflow state-transition / approval action verbs in the path
_APPROVAL_ACTION_RE = re.compile(
    r'/(approve|approval|confirm|authorize|publish|activate|verify|validate|complete|'
    r'finalize|sign|release|accept|settle|fulfil|fulfill|checkout|submit|process)(?:/|$|\?)',
    re.IGNORECASE
)
# Fields whose value encodes a workflow state the client should NOT control
_STATE_FIELD_KEYS = {
    "status", "state", "approved", "is_approved", "approval_status", "active", "is_active",
    "stage", "phase", "workflow_state", "verified", "is_verified", "published", "enabled",
    "paid", "is_paid", "locked", "role", "is_admin",
}
# Elevated workflow values to force via over-posting (merged into the mass-assignment set)
_ELEVATED_STATE_ATTRS = {
    "status": "approved", "state": "approved", "approval_status": "approved",
    "approved": True, "is_approved": True, "active": True, "is_active": True,
    "verified": True, "is_verified": True, "published": True, "enabled": True,
    "paid": True, "is_paid": True, "workflow_state": "completed", "stage": "approved",
}
_NUMERIC_FIELD_RE = re.compile(r'(price|amount|total|qty|quantity|balance|cost|sum|count|discount|fee)', re.IGNORECASE)
_STATE_EVIDENCE_HINTS = ("status", "approv", "active", "verified", "publish", "paid", "state", "workflow", "role", "admin")


def _body_keys(req_body: str) -> set:
    """Lower-cased field names present in a JSON (nested) or form-urlencoded body."""
    keys: set = set()
    b = (req_body or "").strip()
    if b.startswith("{"):
        try:
            parsed = json.loads(b)

            def walk(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        keys.add(str(k).lower())
                        walk(v)
                elif isinstance(o, list):
                    for it in o[:20]:
                        walk(it)

            walk(parsed)
        except Exception:
            pass
    else:
        for pair in b.split("&"):
            if "=" in pair:
                keys.add(pair.split("=", 1)[0].strip().lower())
    return keys


def classify_business_logic_vectors(url: str, method: str, path: str = "", req_body: str = "") -> List[str]:
    """Decide which business-logic abuse tests a flow warrants: APPROVAL_BYPASS
    (workflow action or a client-controlled state field), MASS_ASSIGNMENT (any
    mutation with a body), NUMERIC (price/qty/amount fields)."""
    m = (method or "GET").upper()
    p = path or urllib.parse.urlparse(url).path
    bkeys = _body_keys(req_body)
    vectors: List[str] = []
    if _APPROVAL_ACTION_RE.search(p) or (bkeys & _STATE_FIELD_KEYS):
        vectors.append("APPROVAL_BYPASS")
    if m in ("POST", "PUT", "PATCH") and (req_body or "").strip():
        vectors.append("MASS_ASSIGNMENT")
    query = urllib.parse.urlparse(url).query
    if _NUMERIC_FIELD_RE.search(query) or any(_NUMERIC_FIELD_RE.search(k) for k in bkeys):
        vectors.append("NUMERIC")
    return list(dict.fromkeys(vectors))


def _finding_touches_state(finding: Dict[str, Any]) -> bool:
    blob = (str(finding.get("title", "")) + str(finding.get("evidence", ""))).lower()
    return any(h in blob for h in _STATE_EVIDENCE_HINTS)


async def audit_business_logic_flow(log_id: int, project: str = "default", ws_broadcast_callback=None) -> Dict[str, Any]:
    """
    Workflow-aware business-logic audit of one captured flow. Classifies the applicable
    vectors, forces elevated workflow states / over-posted attributes and numeric
    boundaries through the existing engines, and returns a compact decision —
    VULNERABLE / LIKELY_SECURE / NOT_APPLICABLE — plus a next_action.
    """
    db = SessionLocal()
    try:
        log = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if not log:
            return {"status": "error", "decision": "NOT_FOUND", "message": f"Log #{log_id} not found."}
        url = log.url
        method = (log.method or "GET").upper()
        path = log.path or urllib.parse.urlparse(url).path
        req_body = log.request_body or ""
    finally:
        db.close()

    vectors = classify_business_logic_vectors(url, method, path, req_body)
    if not vectors:
        return {"status": "success", "log_id": log_id, "decision": "NOT_APPLICABLE", "vectors_tested": [],
                "reason": "No workflow-state field, mutation body, or numeric field in this flow.",
                "recommendation": "Capture a mutation/approval flow — e.g. POST /orders/88/approve, or a body carrying a status field."}

    findings: List[Dict[str, Any]] = []
    engines: List[str] = []
    is_mutation = method in ("POST", "PUT", "PATCH")
    approval = "APPROVAL_BYPASS" in vectors

    # 1. Forced workflow-state / mass-assignment over-posting
    if is_mutation and ("MASS_ASSIGNMENT" in vectors or approval):
        extra = _ELEVATED_STATE_ATTRS if approval else None
        ma = await audit_mass_assignment(log_id=log_id, custom_attributes=extra, project=project,
                                         ws_broadcast_callback=ws_broadcast_callback)
        engines.append("mass_assignment")
        for f in (ma.get("findings") or []):
            vec = "APPROVAL_BYPASS" if (approval and _finding_touches_state(f)) else "MASS_ASSIGNMENT"
            findings.append({"vector": vec, "confidence": 0.8, "finding": f})

    # 2. Numeric boundary / zero-cost logic
    if "NUMERIC" in vectors:
        nm = await audit_numeric_business_logic(log_id=log_id, project=project,
                                                ws_broadcast_callback=ws_broadcast_callback)
        engines.append("numeric_logic")
        for f in (nm.get("findings") or []):
            findings.append({"vector": "NUMERIC", "confidence": 0.75, "finding": f})

    vulnerable = len(findings) > 0
    best_conf = max([f["confidence"] for f in findings], default=0.0)
    decision = "VULNERABLE" if vulnerable else "LIKELY_SECURE"
    if vulnerable and approval and any(f["vector"] == "APPROVAL_BYPASS" for f in findings):
        recommendation = ("Workflow/approval bypass reproduced — the server accepted a client-controlled "
                          "state field, so a record can be approved/activated without the real approval step. "
                          "Report it and confirm the business impact.")
    elif vulnerable:
        recommendation = "A business-logic abuse (over-post or numeric boundary) was accepted — report and confirm impact."
    else:
        recommendation = ("No state/over-post/numeric abuse reproduced on this single request. If this is a "
                          "multi-step workflow, also capture the step that enforces the transition (the approver's "
                          "call) and run the access-control audit on it for BFLA (approver-only action).")

    first_fid = next((f["finding"].get("id") for f in findings if f.get("finding")), None)
    result = {
        "status": "success", "log_id": log_id, "decision": decision, "confidence": round(best_conf, 2),
        "vectors_tested": vectors, "engines_run": engines,
        "findings_count": len(findings), "findings": findings, "recommendation": recommendation,
    }
    if vulnerable and first_fid:
        result["next_action"] = {
            "tool": "proxsynth_verify_and_export",
            "arguments": {"finding_id": first_fid, "project": project},
            "rationale": "Confirmed business-logic / approval bypass — generate the reproducible PoC and dossier.",
            "confidence": round(best_conf, 2),
            "auto_executable": best_conf >= 0.7,
        }
    return result
