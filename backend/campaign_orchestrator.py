"""
PROXSYNTH — Autonomous Unified End-to-End Security Campaign Orchestrator
Executes a multi-track, multi-phase autonomous offensive security testing campaign
supporting Web Applications, REST/GraphQL APIs, and Network Infrastructure.
Features:
- Non-blocking asynchronous campaign spawning (returns campaign_id instantly to prevent MCP timeouts)
- Granular campaign status polling via get_campaign_status(campaign_id)
- Intelligent 5xx/503 Circuit Breaker (auto-pauses when target server flaps or crashes)
- Deep deterministic verification and attack-surface knowledge graph feeding
"""

import asyncio
import ipaddress
import logging
import time
import uuid
import urllib.parse
from datetime import datetime
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


class CircuitBreaker:
    """
    Monitors target health during automated testing.
    Trips when >= threshold consecutive 502/503/504 responses are observed,
    pausing the campaign to protect target availability.
    """
    def __init__(self, threshold: int = 3):
        self.threshold = max(2, threshold)
        self.consecutive_5xx = 0
        self.is_tripped = False
        self.trip_reason = ""
        self.tripped_at: Optional[str] = None

    def record_response_code(self, code: Optional[int]) -> bool:
        if code in (502, 503, 504):
            self.consecutive_5xx += 1
            if self.consecutive_5xx >= self.threshold:
                self.is_tripped = True
                self.trip_reason = (
                    f"Circuit breaker tripped: {self.consecutive_5xx} consecutive HTTP {code} "
                    f"responses detected. Target service is flapping, overloaded, or down."
                )
                self.tripped_at = datetime.now().isoformat()
                return False
        elif code and 200 <= code < 500:
            self.consecutive_5xx = 0
        return True

    def check_recent_db_logs(self, project: str, limit: int = 5) -> bool:
        """Inspects recent database HTTP logs for the project to detect target flapping."""
        db = SessionLocal()
        try:
            recent_codes = db.query(HttpLog.status_code).filter(
                HttpLog.project == project
            ).order_by(HttpLog.id.desc()).limit(limit).all()

            consec = 0
            for row in recent_codes:
                sc = row[0]
                if sc in (502, 503, 504):
                    consec += 1
                else:
                    break

            if consec >= self.threshold:
                self.consecutive_5xx = consec
                self.is_tripped = True
                self.trip_reason = (
                    f"Circuit breaker tripped: {consec} consecutive 502/503/504 responses "
                    f"observed in recent project traffic."
                )
                self.tripped_at = datetime.now().isoformat()
                return False
            return True
        except Exception:
            return True
        finally:
            db.close()


# In-memory storage for autonomous campaigns
CAMPAIGN_REGISTRY: Dict[str, Dict[str, Any]] = {}


def classify_target_input(target_input: str) -> Dict[str, Any]:
    """
    Intelligently analyzes the target input and determines
    the target category (NETWORK_INFRA, API, or WEB_SPA) and normalizes endpoints.
    """
    raw = target_input.strip()

    # 1. Check IP address or CIDR notation
    is_ip = False
    is_subnet = False
    clean_ip_or_host = raw

    try:
        if "/" in raw and "://" not in raw:
            ipaddress.ip_network(raw, strict=False)
            is_subnet = True
        else:
            host_candidate = raw.split(":")[0].strip("/")
            ipaddress.ip_address(host_candidate)
            is_ip = True
            clean_ip_or_host = host_candidate
    except ValueError:
        pass

    if is_subnet or (is_ip and "://" not in raw):
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

    # 3. Raw domain or hostname without scheme
    parts = raw.split(":")
    clean_host = parts[0].strip("/")
    port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None

    return {
        "category": "NETWORK_INFRA",
        "host": clean_host,
        "url": f"http://{clean_host}:{port}" if port else f"http://{clean_host}",
        "is_subnet": False,
        "raw_input": raw
    }


def get_campaign_status(campaign_id: str) -> Dict[str, Any]:
    """Retrieves current execution state, metrics, and findings for a campaign."""
    campaign = CAMPAIGN_REGISTRY.get(campaign_id)
    if not campaign:
        return {
            "campaign_id": campaign_id,
            "status": "NOT_FOUND",
            "error": f"Campaign '{campaign_id}' was not found in active registry."
        }
    return campaign


def list_campaigns(project: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists all registered security campaigns, optionally filtered by project workspace."""
    results = []
    proj_filter = (project or "").strip().lower()
    for cid, camp in CAMPAIGN_REGISTRY.items():
        if not proj_filter or proj_filter in ("all", "*", "any", "global") or camp.get("project", "").lower() == proj_filter:
            results.append({
                "campaign_id": cid,
                "status": camp.get("status"),
                "current_phase": camp.get("current_phase"),
                "target_input": camp.get("target_input"),
                "project": camp.get("project"),
                "started_at": camp.get("started_at"),
                "completed_at": camp.get("completed_at"),
                "circuit_breaker_tripped": camp.get("circuit_breaker", {}).get("is_tripped", False),
                "metrics": camp.get("metrics", {})
            })
    return sorted(results, key=lambda x: x.get("started_at", ""), reverse=True)


async def _execute_campaign_pipeline(
    campaign_id: str,
    target_url: str,
    modes: Optional[List[str]],
    project: str,
    max_pages: int,
    deep_verify: bool,
    ports_profile: str,
    enable_spa: bool,
    circuit_breaker: CircuitBreaker
) -> Dict[str, Any]:
    """Internal asynchronous worker executing the multi-track testing pipeline."""
    report = CAMPAIGN_REGISTRY[campaign_id]
    target_info = report["target_classification"]
    primary_category = target_info["category"]
    resolved_host = target_info["host"]
    primary_web_url = target_info["url"]

    selected_modes = set(modes or [
        "network_scan", "spider", "js_mine", "api_infer", "gateway_audit",
        "oast_spray", "bfla_audit", "mass_assignment", "business_logic", "verify_gate"
    ])

    discovered_web_targets: List[str] = [primary_web_url]

    try:
        # ==========================================
        # TRACK 1: NETWORK & INFRASTRUCTURE RECON
        # ==========================================
        if "network_scan" in selected_modes or primary_category == "NETWORK_INFRA":
            report["current_phase"] = "TRACK_1_NETWORK_SCAN"
            logger.info(f"[Campaign {campaign_id}] Track 1: Scanning ports & exposed services on {resolved_host}...")
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

                for wt in network_results.get("web_targets", []):
                    if wt not in discovered_web_targets:
                        discovered_web_targets.append(wt)

                for m in network_results.get("misconfigurations", []):
                    report["high_priority_actions"].append(f"Network Exposure: {m.get('title')}")
            except Exception as e:
                logger.warning(f"Network scan error: {e}")

        # Circuit Breaker Check before entering Web Tracks
        circuit_breaker.check_recent_db_logs(project)
        if circuit_breaker.is_tripped:
            report["status"] = "PAUSED_CIRCUIT_BREAKER"
            report["current_phase"] = "CIRCUIT_BREAKER_HALTED"
            report["high_priority_actions"].append(f"CIRCUIT BREAKER: {circuit_breaker.trip_reason}")
            report["circuit_breaker"] = {
                "is_tripped": True,
                "reason": circuit_breaker.trip_reason,
                "tripped_at": circuit_breaker.tripped_at
            }
            return report

        active_web_url = discovered_web_targets[0] if discovered_web_targets else primary_web_url

        # ==========================================
        # TRACK 2: WEB RECON & HYBRID SPA SPIDER
        # ==========================================
        spider_results = {}
        if "spider" in selected_modes and (primary_category in ("WEB_SPA", "API") or report["metrics"].get("open_ports", 0) > 0):
            report["current_phase"] = "TRACK_2_WEB_SPIDER"
            logger.info(f"[Campaign {campaign_id}] Track 2: Hybrid Spider on {active_web_url} (SPA: {enable_spa})...")
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

        # Check circuit breaker post-spider
        circuit_breaker.check_recent_db_logs(project)
        if circuit_breaker.is_tripped:
            report["status"] = "PAUSED_CIRCUIT_BREAKER"
            report["current_phase"] = "CIRCUIT_BREAKER_HALTED"
            report["high_priority_actions"].append(f"CIRCUIT BREAKER: {circuit_breaker.trip_reason}")
            report["circuit_breaker"] = {
                "is_tripped": True,
                "reason": circuit_breaker.trip_reason,
                "tripped_at": circuit_breaker.tripped_at
            }
            return report

        # ==========================================
        # TRACK 3: JAVASCRIPT RECON & SECRET MINING
        # ==========================================
        if "js_mine" in selected_modes and spider_results.get("scripts"):
            report["current_phase"] = "TRACK_3_JS_MINE"
            logger.info(f"[Campaign {campaign_id}] Track 3: Mining JavaScript assets for secrets...")
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
            report["current_phase"] = "TRACK_4_API_INFER"
            try:
                infer_endpoints_from_observed(project=project)
                report["phases_executed"].append("api_infer")
            except Exception as e:
                logger.warning(f"API inference error: {e}")

        if "gateway_audit" in selected_modes:
            report["current_phase"] = "TRACK_4_GATEWAY_AUDIT"
            logger.info(f"[Campaign {campaign_id}] Track 4b: Auditing API Gateway 401/403 bypass on {active_web_url}...")
            try:
                gw_res = await audit_api_gateway_bypass(target_url=active_web_url, project=project)
                if gw_res.get("is_vulnerable"):
                    report["high_priority_actions"].append(f"API Gateway Bypass Confirmed on {active_web_url}!")
                report["phases_executed"].append("gateway_audit")

                # Monitor responses for 5xx circuit trip
                for p in gw_res.get("probes_evaluated", []):
                    circuit_breaker.record_response_code(p.get("status_code"))
            except Exception as e:
                logger.warning(f"Gateway audit error: {e}")

        # Check circuit breaker post-gateway
        if circuit_breaker.is_tripped or not circuit_breaker.check_recent_db_logs(project):
            report["status"] = "PAUSED_CIRCUIT_BREAKER"
            report["current_phase"] = "CIRCUIT_BREAKER_HALTED"
            report["high_priority_actions"].append(f"CIRCUIT BREAKER: {circuit_breaker.trip_reason}")
            report["circuit_breaker"] = {
                "is_tripped": True,
                "reason": circuit_breaker.trip_reason,
                "tripped_at": circuit_breaker.tripped_at
            }
            return report

        # ==========================================
        # TRACK 5: OAST CANARY SPRAYING (BLIND SSRF / RCE)
        # ==========================================
        if "oast_spray" in selected_modes:
            report["current_phase"] = "TRACK_5_OAST_SPRAY"
            logger.info(f"[Campaign {campaign_id}] Track 5: Spraying OAST canaries against {active_web_url}...")
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
            report["current_phase"] = "TRACK_6_BFLA_AUDIT"
            logger.info(f"[Campaign {campaign_id}] Track 6: Auditing BFLA & HTTP Verb Tampering...")
            try:
                endpoints_to_test = [active_web_url]
                if spider_results.get("sample_endpoints"):
                    for ep in spider_results["sample_endpoints"][:3]:
                        if ep.get("url") not in endpoints_to_test:
                            endpoints_to_test.append(ep["url"])

                for ep_url in endpoints_to_test:
                    if circuit_breaker.is_tripped:
                        break
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
                report["current_phase"] = "TRACK_7_MASS_ASSIGNMENT"
                logger.info(f"[Campaign {campaign_id}] Track 7a: Auditing Mass Assignment...")
                for l in recent_logs[:3]:
                    if l.method in ("POST", "PUT", "PATCH") or (l.request_body and len(l.request_body) > 2):
                        await audit_mass_assignment(log_id=l.id, project=project)
                report["phases_executed"].append("mass_assignment")

            if "business_logic" in selected_modes and recent_logs:
                report["current_phase"] = "TRACK_7_BUSINESS_LOGIC"
                logger.info(f"[Campaign {campaign_id}] Track 7b: Auditing Numeric Business Logic Boundaries...")
                for l in recent_logs[:3]:
                    await audit_numeric_business_logic(log_id=l.id, project=project)
                report["phases_executed"].append("business_logic")

            # ==========================================
            # TRACK 8: DETERMINISTIC VERIFICATION GATE
            # ==========================================
            if deep_verify and "verify_gate" in selected_modes:
                report["current_phase"] = "TRACK_8_VERIFICATION_GATE"
                logger.info(f"[Campaign {campaign_id}] Track 8: Executing Deterministic Verification Gate...")
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

            report["findings_summary"] = []
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

        report["status"] = "COMPLETED"
        report["current_phase"] = "COMPLETED"
        report["completed_at"] = datetime.now().isoformat()
        logger.info(f"[Campaign {campaign_id}] Campaign finished successfully.")

    except Exception as ex:
        report["status"] = "FAILED"
        report["current_phase"] = "ERROR"
        report["error"] = str(ex)
        logger.error(f"[Campaign {campaign_id}] Fatal pipeline error: {ex}", exc_info=True)

    return report


async def run_autonomous_security_campaign(
    target_url: str,
    modes: Optional[List[str]] = None,
    project: str = "default",
    max_pages: int = 15,
    deep_verify: bool = True,
    ports_profile: str = "top_100",
    enable_spa: bool = True,
    wait_for_completion: bool = False,
    consecutive_5xx_threshold: int = 3
) -> Dict[str, Any]:
    """
    Spawns a complete autonomous offensive security campaign.
    By default, executes asynchronously and immediately returns a campaign_id with status RUNNING,
    preventing MCP 120s timeout errors. Call get_campaign_status(campaign_id) to poll progress.
    """
    target_info = classify_target_input(target_url)
    campaign_id = f"camp_{uuid.uuid4().hex[:10]}"

    circuit_breaker = CircuitBreaker(threshold=consecutive_5xx_threshold)

    report_entry: Dict[str, Any] = {
        "campaign_id": campaign_id,
        "status": "RUNNING",
        "current_phase": "INITIALIZING",
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "target_input": target_url,
        "target_classification": target_info,
        "project": (project or "default").strip().lower(),
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
        "circuit_breaker": {
            "is_tripped": False,
            "threshold": consecutive_5xx_threshold,
            "reason": ""
        },
        "findings_summary": [],
        "high_priority_actions": []
    }

    CAMPAIGN_REGISTRY[campaign_id] = report_entry

    if wait_for_completion:
        return await _execute_campaign_pipeline(
            campaign_id=campaign_id,
            target_url=target_url,
            modes=modes,
            project=project,
            max_pages=max_pages,
            deep_verify=deep_verify,
            ports_profile=ports_profile,
            enable_spa=enable_spa,
            circuit_breaker=circuit_breaker
        )

    # Spawn background task
    asyncio.create_task(
        _execute_campaign_pipeline(
            campaign_id=campaign_id,
            target_url=target_url,
            modes=modes,
            project=project,
            max_pages=max_pages,
            deep_verify=deep_verify,
            ports_profile=ports_profile,
            enable_spa=enable_spa,
            circuit_breaker=circuit_breaker
        )
    )

    return {
        "campaign_id": campaign_id,
        "status": "RUNNING",
        "current_phase": "INITIALIZING",
        "target_input": target_url,
        "target_classification": target_info,
        "project": project,
        "circuit_breaker_enabled": True,
        "consecutive_5xx_threshold": consecutive_5xx_threshold,
        "message": (
            f"Autonomous security campaign '{campaign_id}' has been launched in the background. "
            f"Call get_campaign_status(campaign_id='{campaign_id}') to poll real-time phase progress, "
            f"metrics, circuit-breaker health, and verified vulnerability findings."
        )
    }
