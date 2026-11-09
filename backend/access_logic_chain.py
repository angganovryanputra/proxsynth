"""
PROXSYNTH — Access-Control + Business-Logic Chain
Given ONE captured flow, chains the full Broken-Access-Control family audit
(BOLA / IDOR / BFLA) and the workflow-aware business-logic audit (approval /
workflow bypass, mass-assignment over-posting, numeric boundary) back-to-back,
merges their findings, and returns ONE high-confidence decision an LLM can act
on directly.

The chain is token-efficient (a single call drives both engines and emits a
single next_action) and is confidence-gated: only findings at or above
CONFIDENCE_GATE are reported as CONFIRMED and allowed to drive the auto-executable
next_action; weaker signals are surfaced separately as review candidates so the
LLM never chases a <80%-confidence lead automatically.
"""

from typing import Dict, Any, List, Optional

# Report only findings we are >80% sure of as confirmed. Weaker engine signals
# (numeric boundary ~0.75, weak-echo BOLA ~0.79) stay as review candidates.
CONFIDENCE_GATE = 0.8


def _tag(findings: Optional[List[Dict[str, Any]]], engine: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in (findings or []):
        g = dict(f)
        g["engine"] = engine
        out.append(g)
    return out


def _conf(f: Dict[str, Any]) -> float:
    try:
        return float(f.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


async def audit_access_and_logic_chain(
    log_id: int,
    project: str = "default",
    enumerate_idor: bool = True,
    ws_broadcast_callback=None,
) -> Dict[str, Any]:
    """
    Chain the access-control and business-logic engines over a single captured flow
    and return a confidence-gated decision:
      - VULNERABLE     : at least one finding at >= CONFIDENCE_GATE (reported, auto-actionable)
      - NEEDS_REVIEW   : only sub-gate findings — a lead worth a manual look, not auto-chased
      - INCONCLUSIVE   : a baseline/setup problem blocked a clean verdict
      - LIKELY_SECURE  : an engine applied and reproduced nothing
      - NOT_APPLICABLE : neither engine had a vector to test on this flow
    """
    from backend.bola_matrix import audit_bac_flow
    from backend.business_logic_auditor import audit_business_logic_flow

    bac = await audit_bac_flow(
        log_id=log_id, project=project, enumerate_idor=enumerate_idor,
        ws_broadcast_callback=ws_broadcast_callback,
    )
    # A missing log is a hard stop shared by both engines — don't double-report it.
    if bac.get("decision") == "NOT_FOUND" or bac.get("status") == "error":
        return bac

    logic = await audit_business_logic_flow(
        log_id=log_id, project=project, ws_broadcast_callback=ws_broadcast_callback,
    )

    merged = _tag(bac.get("findings"), "access_control") + _tag(logic.get("findings"), "business_logic")
    confirmed = [f for f in merged if _conf(f) >= CONFIDENCE_GATE]
    candidates = [f for f in merged if _conf(f) < CONFIDENCE_GATE]

    vectors_tested = list(dict.fromkeys(
        (bac.get("vectors_tested") or []) + (logic.get("vectors_tested") or [])
    ))
    engines_run = ["access_control_bac_flow"] + list(logic.get("engines_run") or [])
    sub_decisions = {"access_control": bac.get("decision"), "business_logic": logic.get("decision")}

    if confirmed:
        decision = "VULNERABLE"
        best_conf = max(_conf(f) for f in confirmed)
    elif candidates:
        decision = "NEEDS_REVIEW"
        best_conf = max(_conf(f) for f in candidates)
    elif "INCONCLUSIVE" in sub_decisions.values():
        decision = "INCONCLUSIVE"
        best_conf = 0.0
    elif "LIKELY_SECURE" in sub_decisions.values():
        decision = "LIKELY_SECURE"
        best_conf = 0.0
    else:
        decision = "NOT_APPLICABLE"
        best_conf = 0.0

    if decision == "VULNERABLE":
        vecs = sorted({str(f.get("vector", "")) for f in confirmed if f.get("vector")})
        recommendation = (
            f"Chain confirmed {len(confirmed)} access-control / business-logic finding(s) at "
            f">={int(CONFIDENCE_GATE * 100)}% confidence ({', '.join(vecs) or 'access abuse'}) — "
            "report and confirm business impact, then export the PoC."
        )
    elif decision == "NEEDS_REVIEW":
        recommendation = (
            "Only sub-80%-confidence leads surfaced (e.g. numeric boundary, weak cross-user echo). "
            "Review manually or register a true low-privilege identity, then re-run the chain — "
            "nothing here is confident enough to auto-chase."
        )
    elif decision == "INCONCLUSIVE":
        recommendation = (
            "A baseline/setup issue blocked a clean verdict (non-2xx baseline or no secondary identity). "
            "Re-capture the flow with a valid session, or register an attacker identity, then re-run the chain."
        )
    elif decision == "LIKELY_SECURE":
        recommendation = (
            "Both engines applied and reproduced no unauthorized access or state abuse. Treat this flow as "
            "access-controlled, or deepen identity coverage for stronger BFLA/BOLA assurance."
        )
    else:
        recommendation = (
            "Neither engine had a vector here (no object id / privileged function, no mutation body, no "
            "numeric field). Capture an object-read, an approval/mutation, or a priced request to test."
        )

    result: Dict[str, Any] = {
        "status": "success",
        "log_id": log_id,
        "decision": decision,
        "confidence": round(best_conf, 2),
        "confidence_gate": CONFIDENCE_GATE,
        "vectors_tested": vectors_tested,
        "engines_run": engines_run,
        "sub_decisions": sub_decisions,
        "confirmed_count": len(confirmed),
        "candidate_count": len(candidates),
        "findings": confirmed,
        "review_candidates": candidates,
        "idor_enumeration": bac.get("idor_enumeration", []),
        "recommendation": recommendation,
    }

    # Auto-executable next_action ONLY for a >=80% confirmed finding — chains straight
    # to verify-and-export so the overseer can close the loop on the captured flow.
    first_confirmed = next((f.get("finding", {}).get("id") for f in confirmed if f.get("finding")), None)
    if decision == "VULNERABLE" and first_confirmed:
        result["next_action"] = {
            "tool": "proxsynth_verify_and_export",
            "arguments": {"finding_id": first_confirmed, "project": project},
            "rationale": "Chain-confirmed access-control / business-logic finding at >=80% confidence — "
                         "generate the reproducible PoC and dossier.",
            "confidence": round(best_conf, 2),
            "auto_executable": best_conf >= CONFIDENCE_GATE,
        }
    return result
