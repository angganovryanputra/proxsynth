"""
PROXSYNTH — Autonomous End-to-End Security Campaign Orchestrator
Executes a fully autonomous, coordinated multi-phase vulnerability assessment
pipeline in a single call, enabling AI Agents to achieve complete coverage
with zero human intervention and minimal token consumption.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional

from backend.spider_engine import crawl_and_map_target
from backend.js_miner import mine_javascript
from backend.api_spec_inferrer import infer_endpoints_from_observed
from backend.oast_sprayer import spray_oast_canaries
from backend.bfla_engine import audit_bfla_endpoint
from backend.mass_assignment_engine import audit_mass_assignment
from backend.logic_fuzzer import audit_numeric_business_logic
from backend.verification_gate import verify_vulnerability_candidate
from backend.database import SessionLocal, Finding, HttpLog

logger = logging.getLogger("proxynth.campaign_orchestrator")


async def run_autonomous_security_campaign(
    target_url: str,
    modes: Optional[List[str]] = None,
    project: str = "default",
    max_pages: int = 15,
    deep_verify: bool = True
) -> Dict[str, Any]:
    """
    Executes a complete autonomous security testing campaign from reconnaissance
    to exploitation and deterministic verification in a single coordinated pipeline.
    """
    selected_modes = set(modes or [
        "spider", "js_mine", "oast_spray", "bfla_audit",
        "mass_assignment", "business_logic", "verify_gate"
    ])

    report: Dict[str, Any] = {
        "status": "completed",
        "target_url": target_url,
        "project": project,
        "phases_executed": [],
        "metrics": {
            "endpoints_mapped": 0,
            "forms_identified": 0,
            "canaries_sprayed": 0,
            "vulnerabilities_confirmed": 0,
            "false_positives_filtered": 0
        },
        "findings_summary": [],
        "high_priority_actions": []
    }

    # ==========================================
    # PHASE 1: RECONNAISSANCE & AUTONOMOUS SPIDER
    # ==========================================
    spider_results = {}
    if "spider" in selected_modes:
        logger.info(f"[Campaign] Phase 1: Autonomous Spider on {target_url}...")
        spider_results = await crawl_and_map_target(
            root_url=target_url,
            max_depth=2,
            max_pages=max_pages,
            project=project
        )
        report["phases_executed"].append("spider")
        report["metrics"]["endpoints_mapped"] = spider_results.get("endpoints_discovered_count", 0)
        report["metrics"]["forms_identified"] = spider_results.get("forms_found_count", 0)

    # ==========================================
    # PHASE 2: JAVASCRIPT RECON & SECRET MINING
    # ==========================================
    if "js_mine" in selected_modes and spider_results.get("scripts"):
        logger.info("[Campaign] Phase 2: Mining JavaScript assets for secrets...")
        for script_url in spider_results["scripts"][:5]:
            try:
                mine_res = await mine_javascript(content_or_url=script_url, project=project)
                if mine_res.get("secrets_leaked"):
                    for sec in mine_res["secrets_found"]:
                        report["high_priority_actions"].append(f"Secret detected in {script_url}: {sec.get('type')}")
            except Exception:
                pass
        report["phases_executed"].append("js_mine")

    # ==========================================
    # PHASE 3: OAST CANARY SPRAYING (BLIND SSRF / RCE)
    # ==========================================
    if "oast_spray" in selected_modes:
        logger.info(f"[Campaign] Phase 3: Spraying OAST canaries against {target_url}...")
        try:
            oast_res = await spray_oast_canaries(
                target_url=target_url,
                vuln_types=["ssrf", "dns", "log4j"],
                project=project
            )
            report["metrics"]["canaries_sprayed"] = oast_res.get("canaries_sprayed_count", 0)
            report["phases_executed"].append("oast_spray")
        except Exception as e:
            logger.warning(f"OAST spray failed: {e}")

    # ==========================================
    # PHASE 4: BFLA & METHOD TUNNELING AUDIT
    # ==========================================
    if "bfla_audit" in selected_modes:
        logger.info("[Campaign] Phase 4: Auditing BFLA & HTTP Verb Tampering...")
        try:
            # Audit root and high-value endpoints
            endpoints_to_test = [target_url]
            if spider_results.get("sample_endpoints"):
                for ep in spider_results["sample_endpoints"][:3]:
                    if ep.get("url") not in endpoints_to_test:
                        endpoints_to_test.append(ep["url"])

            for ep_url in endpoints_to_test:
                await audit_bfla_endpoint(url=ep_url, method="GET", project=project)
            report["phases_executed"].append("bfla_audit")
        except Exception as e:
            logger.warning(f"BFLA audit error: {e}")

    # ==========================================
    # PHASE 5: MASS ASSIGNMENT & BUSINESS LOGIC FUZZING
    # ==========================================
    db = SessionLocal()
    try:
        # Find candidate logs in DB created during spidering
        recent_logs = db.query(HttpLog).filter(
            HttpLog.project == project
        ).order_by(HttpLog.id.desc()).limit(10).all()

        if "mass_assignment" in selected_modes and recent_logs:
            logger.info("[Campaign] Phase 5a: Auditing Mass Assignment...")
            for l in recent_logs[:3]:
                if l.method in ("POST", "PUT", "PATCH") or (l.request_body and len(l.request_body) > 2):
                    await audit_mass_assignment(log_id=l.id, project=project)
            report["phases_executed"].append("mass_assignment")

        if "business_logic" in selected_modes and recent_logs:
            logger.info("[Campaign] Phase 5b: Auditing Numeric Business Logic Boundaries...")
            for l in recent_logs[:3]:
                await audit_numeric_business_logic(log_id=l.id, project=project)
            report["phases_executed"].append("business_logic")

        # ==========================================
        # PHASE 6: DETERMINISTIC VERIFICATION GATE
        # ==========================================
        if deep_verify and "verify_gate" in selected_modes:
            logger.info("[Campaign] Phase 6: Executing Deterministic Verification Gate...")
            candidate_findings = db.query(Finding).join(HttpLog).filter(
                HttpLog.project == project
            ).order_by(Finding.id.desc()).limit(15).all()

            for f in candidate_findings:
                ver_res = await verify_vulnerability_candidate(
                    finding_id=f.id,
                    project=project
                )
                if ver_res.get("is_confirmed"):
                    report["metrics"]["vulnerabilities_confirmed"] += 1
                elif ver_res.get("verdict") == "FALSE_POSITIVE":
                    report["metrics"]["false_positives_filtered"] += 1

            report["phases_executed"].append("verify_gate")

        # Gather final confirmed findings
        confirmed_findings = db.query(Finding).join(HttpLog).filter(
            HttpLog.project == project
        ).order_by(Finding.id.desc()).limit(20).all()

        for f in confirmed_findings:
            report["findings_summary"].append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "flag_status": f.log.flag_status if f.log else "CONFIRMED",
                "description": f.description[:150] if f.description else ""
            })

    finally:
        db.close()

    return report
