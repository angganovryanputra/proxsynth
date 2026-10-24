"""
PROXSYNTH — Autonomous Unified End-to-End Security Campaign Orchestrator
Executes a multi-track, multi-phase autonomous offensive security testing campaign
supporting Web Applications, REST/GraphQL APIs, and Network Infrastructure in a single call.
Enables AI Agents to achieve complete attack-surface coverage with zero human intervention.
"""

import asyncio
import ipaddress
import logging
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Set

from backend.spider_engine import crawl_and_map_target
from backend.js_miner import mine_javascript
from backend.api_spec_inferrer import infer_endpoints_from_observed
from backend.api_importer import import_api_schema, audit_api_gateway_bypass
from backend.network_scanner import scan_target_ports
from backend.oast_sprayer import spray_oast_canaries
from backend.bfla_engine import audit_bfla_endpoint
from backend.mass_assignment_engine import audit_mass_assignment
from backend.logic_fuzzer import audit_numeric_business_logic
from backend.verification_gate import verify_vulnerability_candidate
from backend.database import SessionLocal, Finding, HttpLog

logger = logging.getLogger("proxynth.campaign_orchestrator")


def classify_target_input(target_input: str) -> Dict[str, Any]:
    """
    Intelligently analyzes the user or agent target input and determines
    the target category (NETWORK_INFRA, API, or WEB_SPA) and normalizes endpoints.
    """
    raw = target_input.strip()

    # 1. Check IP address or CIDR notation
    is_ip = False
    is_subnet = False
    clean_ip_or_host = raw

    try:
        if "/" in raw and not "://" in raw:
            ipaddress.ip_network(raw, strict=False)
            is_subnet = True
        else:
            host_candidate = raw.split(":")[0].strip("/")
            ipaddress.ip_address(host_candidate)
            is_ip = True
            clean_ip_or_host = host_candidate
    except ValueError:
        pass

    if is_subnet or (is_ip and not "://" in raw):
        return {
            "category": "NETWORK_INFRA",
            "host": clean_ip_or_host,
            "url": f"http://{clean_ip_or_host}",
            "is_subnet": is_subnet,
            "raw_input": raw
        }

    # 2. Check if explicit HTTP/HTTPS URL
    if raw.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(raw)
        path_lower = (parsed.path or "").lower()
        query_lower = (parsed.query or "").lower()

        is_api = any(k in path_lower for k in [
            "/api", "/v1", "/v2", "/v3", "/graphql", "/swagger", "/openapi", "/api-docs", "/docs"
        ]) or any(k in query_lower for k in ["api", "graphql", "wsdl"])

        return {
            "category": "API" if is_api else "WEB_SPA",
            "host": parsed.netloc.split(":")[0],
            "url": raw,
            "is_subnet": False,
            "raw_input": raw
        }

    # 3. Raw domain or hostname without scheme (e.g. gateway.internal.corp, scanme.nmap.org)
    parts = raw.split(":")
    clean_host = parts[0].strip("/")
    port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None

    # If it's a domain name without URL scheme, default to dual INFRA & WEB track
    return {
        "category": "NETWORK_INFRA",
        "host": clean_host,
        "url": f"http://{clean_host}:{port}" if port else f"http://{clean_host}",
        "is_subnet": False,
        "raw_input": raw
    }


async def run_autonomous_security_campaign(
    target_url: str,
    modes: Optional[List[str]] = None,
    project: str = "default",
    max_pages: int = 15,
    deep_verify: bool = True,
    ports_profile: str = "top_100",
    enable_spa: bool = True
) -> Dict[str, Any]:
    """
    Executes a complete, coordinated autonomous security testing campaign from network/port recon
    and hybrid SPA crawling to API gateway audits, business logic fuzzing, and deterministic verification.
    """
    target_info = classify_target_input(target_url)
    primary_category = target_info["category"]
    resolved_host = target_info["host"]
    primary_web_url = target_info["url"]

    selected_modes = set(modes or [
        "network_scan", "spider", "js_mine", "api_infer", "gateway_audit",
        "oast_spray", "bfla_audit", "mass_assignment", "business_logic", "verify_gate"
    ])

    report: Dict[str, Any] = {
        "status": "completed",
        "target_input": target_url,
        "target_classification": target_info,
        "project": project,
        "tracks_executed": [],
        "phases_executed": [],
        "metrics": {
            "ports_scanned": 0,
            "open_ports": 0,
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
    # TRACK 1: NETWORK & INFRASTRUCTURE RECON
    # ==========================================
    network_results = {}
    discovered_web_targets: List[str] = [primary_web_url]

    if "network_scan" in selected_modes or primary_category == "NETWORK_INFRA":
        logger.info(f"[Campaign] Track 1: Scanning open ports and exposed services on {resolved_host}...")
        try:
            network_results = await scan_target_ports(
                target=resolved_host,
                ports_profile=ports_profile,
                project=project,
                audit_misconfigs=True
            )
            report["tracks_executed"].append("network_infra")
            report["phases_executed"].append("network_scan")
            report["metrics"]["ports_scanned"] = network_results.get("scanned_ports_count", 0)
            report["metrics"]["open_ports"] = network_results.get("open_ports_count", 0)

            # Auto-ingest any discovered web ports to feed into the Web/API tracks
            for wt in network_results.get("web_targets", []):
                if wt not in discovered_web_targets:
                    discovered_web_targets.append(wt)

            # Add network misconfiguration warnings
            for m in network_results.get("misconfigurations", []):
                report["high_priority_actions"].append(f"Network Exposure: {m.get('title')}")
        except Exception as e:
            logger.warning(f"Network scan error: {e}")

    # ==========================================
    # TRACK 2: WEB RECON & HYBRID SPA SPIDER
    # ==========================================
    spider_results = {}
    active_web_url = discovered_web_targets[0] if discovered_web_targets else primary_web_url

    if "spider" in selected_modes and (primary_category in ("WEB_SPA", "API") or network_results.get("open_ports_count", 0) > 0):
        logger.info(f"[Campaign] Track 2: Autonomous Hybrid Spider on {active_web_url} (SPA: {enable_spa})...")
        try:
            spider_results = await crawl_and_map_target(
                root_url=active_web_url,
                max_depth=2,
                max_pages=max_pages,
                project=project,
                enable_spa=enable_spa
            )
            report["tracks_executed"].append("web_spa")
            report["phases_executed"].append("spider")
            report["metrics"]["endpoints_mapped"] = spider_results.get("endpoints_discovered_count", 0)
            report["metrics"]["forms_identified"] = spider_results.get("forms_found_count", 0)
        except Exception as e:
            logger.warning(f"Spider execution error: {e}")

    # ==========================================
    # TRACK 3: JAVASCRIPT RECON & SECRET MINING
    # ==========================================
    if "js_mine" in selected_modes and spider_results.get("scripts"):
        logger.info("[Campaign] Track 3: Mining JavaScript assets for secrets...")
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
    # TRACK 4: API RECON & GATEWAY BYPASS AUDIT
    # ==========================================
    if "api_infer" in selected_modes and (primary_category == "API" or spider_results.get("sample_endpoints")):
        logger.info("[Campaign] Track 4a: Inferring hidden API hierarchy & probes...")
        try:
            inferred = infer_endpoints_from_observed(project=project)
            report["phases_executed"].append("api_infer")
        except Exception as e:
            logger.warning(f"API inference error: {e}")

    if "gateway_audit" in selected_modes:
        logger.info(f"[Campaign] Track 4b: Auditing API Gateway 401/403 bypass matrix on {active_web_url}...")
        try:
            gw_res = await audit_api_gateway_bypass(target_url=active_web_url, project=project)
            if gw_res.get("is_vulnerable"):
                report["high_priority_actions"].append(f"API Gateway Bypass Confirmed on {active_web_url}!")
            report["phases_executed"].append("gateway_audit")
        except Exception as e:
            logger.warning(f"Gateway audit error: {e}")

    # ==========================================
    # TRACK 5: OAST CANARY SPRAYING (BLIND SSRF / RCE)
    # ==========================================
    if "oast_spray" in selected_modes:
        logger.info(f"[Campaign] Track 5: Spraying OAST canaries against {active_web_url}...")
        try:
            oast_res = await spray_oast_canaries(
                target_url=active_web_url,
                vuln_types=["ssrf", "dns", "log4j"],
                project=project
            )
            report["metrics"]["canaries_sprayed"] = oast_res.get("canaries_sprayed_count", 0)
            report["phases_executed"].append("oast_spray")
        except Exception as e:
            logger.warning(f"OAST spray failed: {e}")

    # ==========================================
    # TRACK 6: BFLA & METHOD TUNNELING AUDIT
    # ==========================================
    if "bfla_audit" in selected_modes:
        logger.info("[Campaign] Track 6: Auditing BFLA & HTTP Verb Tampering...")
        try:
            endpoints_to_test = [active_web_url]
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
    # TRACK 7: MASS ASSIGNMENT & BUSINESS LOGIC
    # ==========================================
    db = SessionLocal()
    try:
        recent_logs = db.query(HttpLog).filter(
            HttpLog.project == project
        ).order_by(HttpLog.id.desc()).limit(10).all()

        if "mass_assignment" in selected_modes and recent_logs:
            logger.info("[Campaign] Track 7a: Auditing Mass Assignment...")
            for l in recent_logs[:3]:
                if l.method in ("POST", "PUT", "PATCH") or (l.request_body and len(l.request_body) > 2):
                    await audit_mass_assignment(log_id=l.id, project=project)
            report["phases_executed"].append("mass_assignment")

        if "business_logic" in selected_modes and recent_logs:
            logger.info("[Campaign] Track 7b: Auditing Numeric Business Logic Boundaries...")
            for l in recent_logs[:3]:
                await audit_numeric_business_logic(log_id=l.id, project=project)
            report["phases_executed"].append("business_logic")

        # ==========================================
        # TRACK 8: DETERMINISTIC VERIFICATION GATE
        # ==========================================
        if deep_verify and "verify_gate" in selected_modes:
            logger.info("[Campaign] Track 8: Executing Deterministic Verification Gate...")
            candidate_findings = db.query(Finding).join(HttpLog).filter(
                HttpLog.project == project
            ).order_by(Finding.id.desc()).limit(20).all()

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
        ).order_by(Finding.id.desc()).limit(25).all()

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
