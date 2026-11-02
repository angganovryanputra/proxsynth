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
import json
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
from backend.database import SessionLocal, Finding, HttpLog, CampaignRecord
from backend.protocol_inspector import inspect_graphql_endpoint, audit_websocket_security
from backend.waf_mutator import analyze_waf_response, generate_evasion_headers
from backend.adaptive_limiter import handle_rate_limit
from backend.bola_matrix import is_candidate_for_bola, execute_bola_shadow_replay
from backend.hypothesis_manager import create_hypothesis, sync_finding_to_hypothesis, update_hypothesis
from backend.target_manager import add_or_update_endpoint, upsert_target_asset

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

def _persist_campaign_to_db(campaign: Dict[str, Any]) -> None:
    """Persists or updates campaign state in SQLite database."""
    cid = campaign.get("campaign_id")
    if not cid:
        return
    db = SessionLocal()
    try:
        record = db.query(CampaignRecord).filter(CampaignRecord.campaign_id == cid).first()
        if not record:
            record = CampaignRecord(
                campaign_id=cid,
                project=campaign.get("project", "default"),
                status=campaign.get("status", "RUNNING"),
                current_phase=campaign.get("current_phase", "INITIALIZING"),
                target_input=campaign.get("target_input", ""),
                started_at=campaign.get("started_at", ""),
                completed_at=campaign.get("completed_at"),
                report_json=json.dumps(campaign, default=str)
            )
            db.add(record)
        else:
            record.status = campaign.get("status", record.status)
            record.current_phase = campaign.get("current_phase", record.current_phase)
            record.completed_at = campaign.get("completed_at", record.completed_at)
            record.report_json = json.dumps(campaign, default=str)
        db.commit()
    except Exception as ex:
        db.rollback()
        logger.warning(f"Failed to persist campaign {cid} to database: {ex}")
    finally:
        db.close()



def classify_target_input(target_input: str) -> Dict[str, Any]:
    """
    Intelligently analyzes the target input, determines the target category
    (NETWORK_INFRA, API, or WEB_SPA), detects protocol specifics (GraphQL, OpenAPI, WebSocket),
    and synthesizes an autonomous attack strategy with prioritized tracks.
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
        ttype = "SUBNET_RANGE" if is_subnet else "NETWORK_HOST"
        return {
            "category": "NETWORK_INFRA",
            "target_type": ttype,
            "host": clean_ip_or_host,
            "url": f"http://{clean_ip_or_host}",
            "is_subnet": is_subnet,
            "is_graphql": False,
            "is_openapi": False,
            "is_websocket": False,
            "raw_input": raw,
            "autonomous_strategy": {
                "priority_tracks": ["network_scan", "spider", "api_infer", "gateway_audit", "verify_gate"],
                "decision_reason": f"Target identified as {ttype}; prioritizing port scanning and service discovery before web probing.",
                "recommended_rate": "aggressive" if is_subnet else "normal",
                "primary_vector": "EXPOSED_SERVICES"
            }
        }

    # 2. Check if explicit HTTP/HTTPS URL
    if raw.startswith(("http://", "https://", "ws://", "wss://")):
        parsed = urllib.parse.urlparse(raw)
        path_lower = (parsed.path or "").lower()
        query_lower = (parsed.query or "").lower()

        is_graphql = any(k in path_lower for k in ["/graphql", "/gql", "/api/graphql"]) or "graphql" in query_lower
        is_openapi = any(k in path_lower for k in [
            "/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json"
        ])
        is_websocket = raw.startswith(("ws://", "wss://")) or any(k in path_lower for k in ["/ws", "/websocket", "/socket.io"])

        is_api = is_graphql or is_openapi or any(k in path_lower for k in [
            "/api", "/v1", "/v2", "/v3", "/swagger", "/openapi", "/api-docs", "/docs"
        ]) or any(k in query_lower for k in ["api", "graphql", "wsdl"])

        if is_graphql:
            ttype = "GRAPHQL_API"
            strat = {
                "priority_tracks": ["graphql_audit", "api_infer", "gateway_audit", "bfla_audit", "verify_gate"],
                "decision_reason": "GraphQL endpoint detected; prioritizing schema introspection, query batching amplification, and field suggestion mining.",
                "recommended_rate": "moderate",
                "primary_vector": "GRAPHQL_INTROSPECTION"
            }
        elif is_openapi:
            ttype = "OPENAPI_SPEC"
            strat = {
                "priority_tracks": ["openapi_import", "gateway_audit", "bfla_audit", "mass_assignment", "business_logic", "verify_gate"],
                "decision_reason": "OpenAPI / Swagger spec URL detected; prioritizing automated schema route ingestion and authorization matrix audit.",
                "recommended_rate": "moderate",
                "primary_vector": "API_SCHEMA_FUZZING"
            }
        elif is_api:
            ttype = "REST_API"
            strat = {
                "priority_tracks": ["api_infer", "gateway_audit", "oast_spray", "bfla_audit", "mass_assignment", "business_logic", "verify_gate"],
                "decision_reason": "REST API service detected; prioritizing BOLA/IDOR, BFLA verb tampering, Mass Assignment, and OAST canary spraying.",
                "recommended_rate": "normal",
                "primary_vector": "BOLA_BFLA_API"
            }
        else:
            ttype = "SINGLE_PAGE_APP"
            strat = {
                "priority_tracks": ["spider", "js_mine", "api_infer", "gateway_audit", "oast_spray", "verify_gate"],
                "decision_reason": "Web application / SPA detected; prioritizing DOM spidering, JavaScript asset secret mining, and endpoint discovery.",
                "recommended_rate": "normal",
                "primary_vector": "CLIENT_SECRETS_XSS"
            }

        return {
            "category": "API" if is_api else "WEB_SPA",
            "target_type": ttype,
            "host": parsed.netloc.split(":")[0],
            "url": raw,
            "is_subnet": False,
            "is_graphql": is_graphql,
            "is_openapi": is_openapi,
            "is_websocket": is_websocket,
            "raw_input": raw,
            "autonomous_strategy": strat
        }

    # 3. Raw domain or hostname without scheme
    parts = raw.split(":")
    clean_host = parts[0].strip("/")
    port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None

    return {
        "category": "NETWORK_INFRA",
        "target_type": "HOST_DOMAIN",
        "host": clean_host,
        "url": f"http://{clean_host}:{port}" if port else f"http://{clean_host}",
        "is_subnet": False,
        "is_graphql": False,
        "is_openapi": False,
        "is_websocket": False,
        "raw_input": raw,
        "autonomous_strategy": {
            "priority_tracks": ["network_scan", "spider", "api_infer", "gateway_audit", "verify_gate"],
            "decision_reason": "Domain hostname without scheme; prioritizing network port scanning and banner discovery.",
            "recommended_rate": "normal",
            "primary_vector": "SERVICE_ENUMERATION"
        }
    }


def get_campaign_status(campaign_id: str) -> Dict[str, Any]:
    """Retrieves current execution state, metrics, and findings for a campaign."""
    campaign = CAMPAIGN_REGISTRY.get(campaign_id)
    if campaign:
        return campaign

    # Fallback to persistent database storage
    db = SessionLocal()
    try:
        record = db.query(CampaignRecord).filter(CampaignRecord.campaign_id == campaign_id).first()
        if record:
            data = record.to_dict()
            CAMPAIGN_REGISTRY[campaign_id] = data
            return data
    except Exception as ex:
        logger.warning(f"Error querying CampaignRecord for {campaign_id}: {ex}")
    finally:
        db.close()

    return {
        "campaign_id": campaign_id,
        "status": "NOT_FOUND",
        "error": f"Campaign '{campaign_id}' was not found in active registry or database history."
    }


def list_campaigns(project: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists all registered security campaigns, optionally filtered by project workspace."""
    results: Dict[str, Dict[str, Any]] = {}
    proj_filter = (project or "").strip().lower()

    # 1. Load from DB first (survives process restart)
    db = SessionLocal()
    try:
        query = db.query(CampaignRecord)
        if proj_filter and proj_filter not in ("all", "*", "any", "global"):
            query = query.filter(CampaignRecord.project == proj_filter)
        records = query.order_by(CampaignRecord.id.desc()).all()
        for rec in records:
            data = rec.to_dict()
            results[rec.campaign_id] = {
                "campaign_id": rec.campaign_id,
                "status": rec.status,
                "current_phase": rec.current_phase,
                "target_input": rec.target_input,
                "project": rec.project,
                "started_at": rec.started_at,
                "completed_at": rec.completed_at,
                "circuit_breaker_tripped": data.get("circuit_breaker", {}).get("is_tripped", False),
                "metrics": data.get("metrics", {})
            }
    except Exception as ex:
        logger.warning(f"Error listing campaigns from DB: {ex}")
    finally:
        db.close()

    # 2. Overlay live in-memory registry (has latest metrics/status during execution)
    for cid, camp in CAMPAIGN_REGISTRY.items():
        c_proj = camp.get("project", "").lower()
        if not proj_filter or proj_filter in ("all", "*", "any", "global") or c_proj == proj_filter:
            results[cid] = {
                "campaign_id": cid,
                "status": camp.get("status"),
                "current_phase": camp.get("current_phase"),
                "target_input": camp.get("target_input"),
                "project": camp.get("project"),
                "started_at": camp.get("started_at"),
                "completed_at": camp.get("completed_at"),
                "circuit_breaker_tripped": camp.get("circuit_breaker", {}).get("is_tripped", False),
                "metrics": camp.get("metrics", {})
            }

    return sorted(results.values(), key=lambda x: x.get("started_at", ""), reverse=True)


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

    if "autonomous_decisions" not in report:
        report["autonomous_decisions"] = []

    strat = target_info.get("autonomous_strategy", {})
    auto_tracks = strat.get("priority_tracks", [
        "network_scan", "spider", "js_mine", "api_infer", "gateway_audit",
        "oast_spray", "bfla_audit", "mass_assignment", "business_logic", "verify_gate"
    ])

    if not modes or "auto" in modes:
        selected_modes = set(auto_tracks)
        report["autonomous_decisions"].append({
            "decision": "AUTOMATIC_TRACK_SELECTION",
            "reason": strat.get("decision_reason", "Selected tailored priority tracks based on target classification."),
            "tracks": list(selected_modes)
        })
    else:
        selected_modes = set(modes)

    # Initialize Autonomous Working Memory Hypothesis Roadmap
    root_hypothesis_id = None
    try:
        h_obj = create_hypothesis(
            project=project,
            target=primary_web_url,
            vuln_type=target_info.get("target_type", primary_category),
            hypothesis=f"Autonomous attack campaign against {target_info.get('target_type', primary_category)}: {strat.get('decision_reason', '')}",
            status="IN_PROGRESS",
            evidence_notes=f"Tracks scheduled: {', '.join(sorted(selected_modes))}",
            agent_id=f"campaign_{campaign_id}"
        )
        if isinstance(h_obj, dict):
            root_hypothesis_id = h_obj.get("id")
    except Exception:
        pass

    discovered_web_targets: List[str] = [primary_web_url]

    try:
        # ==========================================
        # TRACK 1: NETWORK & INFRASTRUCTURE RECON
        # ==========================================
        if "network_scan" in selected_modes or primary_category == "NETWORK_INFRA":
            report["current_phase"] = "TRACK_1_NETWORK_SCAN"
            _persist_campaign_to_db(report)
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
            _persist_campaign_to_db(report)
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
            _persist_campaign_to_db(report)
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
            _persist_campaign_to_db(report)
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
            _persist_campaign_to_db(report)
            logger.info(f"[Campaign {campaign_id}] Track 3: Mining JavaScript assets for secrets...")
            for script_url in spider_results["scripts"][:5]:
                try:
                    mine_res = await mine_javascript(content_or_url=script_url, project=project)
                    if mine_res.get("secrets_leaked"):
                        for sec in mine_res["secrets_found"]:
                            report["high_priority_actions"].append(f"Secret detected in {script_url}: {sec.get('type')}")
                    # Feedback loop: auto-ingest discovered endpoints into Target Knowledge Graph
                    if mine_res.get("endpoints_found"):
                        try:
                            from backend.target_manager import add_or_update_endpoint
                            for ep in mine_res["endpoints_found"]:
                                full_ep = ep if ep.startswith("http") else f"{active_web_url.rstrip('/')}/{ep.lstrip('/')}"
                                add_or_update_endpoint(project=project, host=resolved_host, url=full_ep, method="GET", notes="Discovered via JS Asset Mining")
                                report["metrics"]["endpoints_mapped"] += 1
                        except Exception:
                            pass
                except Exception:
                    pass
            report["phases_executed"].append("js_mine")

        # ==========================================
        # TRACK 4: API RECON & GATEWAY BYPASS AUDIT
        # ==========================================
        if "api_infer" in selected_modes and (primary_category == "API" or spider_results.get("sample_endpoints")):
            report["current_phase"] = "TRACK_4_API_INFER"
            _persist_campaign_to_db(report)
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
            _persist_campaign_to_db(report)
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

            # ==========================================
            # TRACK 9: GRAPHQL PROTOCOL AUDIT
            # ==========================================
            graphql_candidates = []
            if target_info.get("is_graphql"):
                graphql_candidates.append(primary_web_url)
            for wt in discovered_web_targets:
                if "/graphql" in wt.lower() or "/gql" in wt.lower():
                    if wt not in graphql_candidates:
                        graphql_candidates.append(wt)
            if spider_results.get("sample_endpoints"):
                for ep in spider_results["sample_endpoints"]:
                    u = ep.get("url", "")
                    if "/graphql" in u.lower() or "/gql" in u.lower():
                        if u not in graphql_candidates:
                            graphql_candidates.append(u)

            if ("graphql_audit" in selected_modes or graphql_candidates) and graphql_candidates:
                report["current_phase"] = "TRACK_9_GRAPHQL_AUDIT"
                _persist_campaign_to_db(report)
                for g_url in graphql_candidates[:2]:
                    logger.info(f"[Campaign {campaign_id}] Track 9: Assessing GraphQL endpoint {g_url}...")
                    try:
                        g_res = await inspect_graphql_endpoint(url=g_url, project=project)
                        report["phases_executed"].append("graphql_audit")
                        if g_res.get("findings"):
                            for gf in g_res["findings"]:
                                report["high_priority_actions"].append(f"GraphQL: {gf.get('title')} on {g_url}")
                                report["metrics"]["vulnerabilities_confirmed"] += 1
                        report["autonomous_decisions"].append({
                            "decision": "GRAPHQL_ASSESSMENT_EXECUTED",
                            "url": g_url,
                            "introspection_enabled": g_res.get("introspection_enabled", False),
                            "queries_found": len(g_res.get("discovered_queries", [])),
                            "mutations_found": len(g_res.get("discovered_mutations", []))
                        })
                    except Exception as ex:
                        logger.warning(f"GraphQL audit error: {ex}")

            # ==========================================
            # TRACK 10: OPENAPI / SWAGGER INGESTION
            # ==========================================
            openapi_candidates = []
            if target_info.get("is_openapi"):
                openapi_candidates.append(primary_web_url)
            for wt in discovered_web_targets:
                if any(k in wt.lower() for k in ["/openapi.json", "/swagger.json", "/api-docs"]):
                    if wt not in openapi_candidates:
                        openapi_candidates.append(wt)

            if ("openapi_import" in selected_modes or openapi_candidates) and openapi_candidates:
                report["current_phase"] = "TRACK_10_OPENAPI_IMPORT"
                _persist_campaign_to_db(report)
                for oa_url in openapi_candidates[:2]:
                    logger.info(f"[Campaign {campaign_id}] Track 10: Ingesting OpenAPI schema from {oa_url}...")
                    try:
                        oa_res = await import_api_schema(schema_content_or_url=oa_url, project=project, auto_register=True)
                        report["phases_executed"].append("openapi_import")
                        report["metrics"]["endpoints_mapped"] += oa_res.get("endpoints_count", 0)
                        report["autonomous_decisions"].append({
                            "decision": "OPENAPI_SCHEMA_INGESTED",
                            "url": oa_url,
                            "endpoints_ingested": oa_res.get("endpoints_count", 0)
                        })
                    except Exception as ex:
                        logger.warning(f"OpenAPI import error: {ex}")

            # ==========================================
            # TRACK 11: AUTONOMOUS BOLA SHADOW TESTING
            # ==========================================
            if "bola_shadow_matrix" in selected_modes or primary_category in ("API", "WEB_SPA"):
                report["current_phase"] = "TRACK_11_BOLA_SHADOW_MATRIX"
                _persist_campaign_to_db(report)
                logger.info(f"[Campaign {campaign_id}] Track 11: Testing BOLA/IDOR candidates with secondary identities...")
                try:
                    from backend.target_manager import discover_bola_candidates
                    cands = discover_bola_candidates(project=project, limit=5)
                    for cand in cands[:3]:
                        m_id = cand.get("log_id")
                        if m_id:
                            orig_log = db.query(HttpLog).filter(HttpLog.id == m_id).first()
                            if orig_log and is_candidate_for_bola(orig_log.url, orig_log.method, orig_log.request_body):
                                req_hdrs = json.loads(orig_log.request_headers) if orig_log.request_headers else {}
                                b_res = await execute_bola_shadow_replay(
                                    log_id=orig_log.id,
                                    project=project,
                                    url=orig_log.url,
                                    method=orig_log.method,
                                    req_headers=req_hdrs,
                                    req_body=orig_log.request_body,
                                    orig_status=orig_log.status_code,
                                    orig_body=orig_log.response_body
                                )
                                if b_res and b_res.get("vulnerable"):
                                    report["high_priority_actions"].append(f"Confirmed BOLA/IDOR on {orig_log.url}")
                                    report["metrics"]["vulnerabilities_confirmed"] += 1
                                    report["autonomous_decisions"].append({
                                        "decision": "BOLA_VULNERABILITY_CONFIRMED",
                                        "url": orig_log.url,
                                        "role": b_res.get("role")
                                    })
                    report["phases_executed"].append("bola_shadow_matrix")
                except Exception as ex:
                    logger.warning(f"BOLA shadow matrix error: {ex}")

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

            # Automated BOLA / IDOR candidate inference feedback loop
            try:
                from backend.target_manager import discover_bola_candidates
                bola_cands = discover_bola_candidates(project=project, limit=5)
                if bola_cands:
                    for bc in bola_cands[:3]:
                        report["high_priority_actions"].append(
                            f"BOLA Candidate detected: {bc['method']} {bc['resource']} (Observed: {bc['observed_value']}, suggested tamper: {bc['suggested_tamper']})"
                        )
            except Exception:
                pass

        finally:
            db.close()

        if root_hypothesis_id:
            try:
                conf_count = report["metrics"].get("vulnerabilities_confirmed", 0)
                final_status = "CONFIRMED" if conf_count > 0 else "COMPLETED"
                update_hypothesis(
                    hypothesis_id=root_hypothesis_id,
                    status=final_status,
                    evidence_notes=f"Autonomous campaign completed. Confirmed vulnerabilities: {conf_count}. False positives filtered: {report['metrics'].get('false_positives_filtered', 0)}.",
                    project=project
                )
            except Exception:
                pass

        report["status"] = "COMPLETED"
        report["current_phase"] = "COMPLETED"
        report["completed_at"] = datetime.now().isoformat()
        _persist_campaign_to_db(report)
        logger.info(f"[Campaign {campaign_id}] Campaign finished successfully.")

    except Exception as ex:
        report["status"] = "FAILED"
        report["current_phase"] = "ERROR"
        report["error"] = str(ex)
        _persist_campaign_to_db(report)
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
        "high_priority_actions": [],
        "autonomous_decisions": []
    }

    CAMPAIGN_REGISTRY[campaign_id] = report_entry
    _persist_campaign_to_db(report_entry)

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
