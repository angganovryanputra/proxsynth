"""
PROXSYNTH — Autonomous CLI Output Miner & Structured Knowledge Extractor
Parses stdout/stderr of external offensive security CLI tools (Nmap, Masscan, Nuclei, FFUF, Gobuster),
extracts structured ports, services, endpoints, and vulnerabilities, and ingests them directly
into the Target Knowledge Graph and Findings Ledger.
"""

import json
import logging
import re
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from backend.database import SessionLocal, TargetAsset, TargetService, TargetEndpoint, Finding, HttpLog
from backend.target_manager import upsert_target_asset, add_or_update_service, add_or_update_endpoint

logger = logging.getLogger("proxynth.cli_miner")


def detect_tool_type(command: str, raw_output: str) -> str:
    """Detects which CLI tool generated the output based on command line or output signatures."""
    cmd_lower = (command or "").lower()
    out_lower = (raw_output or "").lower()

    if "nmap" in cmd_lower or "nmap scan report" in out_lower or "<nmaprun" in out_lower:
        return "NMAP"
    if "masscan" in cmd_lower or "discovered open port" in out_lower:
        return "MASSCAN"
    if "nuclei" in cmd_lower or "[http]" in out_lower or "[dns]" in out_lower or '"template-id"' in out_lower:
        return "NUCLEI"
    if "ffuf" in cmd_lower or ":: progress:" in out_lower or "| url |" in out_lower:
        return "FFUF"
    if "gobuster" in cmd_lower or "found:" in out_lower:
        return "GOBUSTER"
    if "dirsearch" in cmd_lower or "target:" in out_lower:
        return "DIRSEARCH"
    return "GENERIC"


def parse_nmap_output(raw_output: str, fallback_host: str = "") -> List[Dict[str, Any]]:
    """
    Parses standard Nmap text report into structured port and service mappings.
    Example line:
    22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
    80/tcp   open  http    Apache httpd 2.4.41
    """
    results: List[Dict[str, Any]] = []
    current_host = fallback_host

    # Check for Nmap scan report for <host> (<ip>)
    host_match = re.search(r"Nmap scan report for ([^\s\(]+)(?:\s+\(([^\)]+)\))?", raw_output)
    if host_match:
        current_host = host_match.group(1).strip()

    # Regex for port line: <port>/<proto> <state> <service> [<version...>]
    port_line_re = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([^\s]+)(?:\s+(.*))?$", re.MULTILINE)

    for m in port_line_re.finditer(raw_output):
        port = int(m.group(1))
        protocol = m.group(2).lower()
        state = m.group(3).lower()
        service_name = m.group(4).lower()
        banner = (m.group(5) or "").strip()

        if state == "open":
            results.append({
                "host": current_host or fallback_host or "target.local",
                "port": port,
                "protocol": protocol,
                "service_name": service_name,
                "banner": banner,
                "state": state
            })

    return results


def parse_nuclei_output(raw_output: str, fallback_host: str = "") -> List[Dict[str, Any]]:
    """
    Parses Nuclei text or JSONL output into structured finding candidates.
    Supports both standard text:
    [cve-2021-44228] [http] [critical] https://target.com/login?token=abc [1.1.1.1]
    and JSONL lines:
    {"template-id":"...","info":{"name":"...","severity":"high","description":"..."},"matched-at":"..."}
    """
    findings: List[Dict[str, Any]] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Try JSONL format
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                info = data.get("info", {})
                template_id = data.get("template-id") or data.get("templateID", "nuclei-detection")
                title = info.get("name", template_id)
                severity = (info.get("severity", "MEDIUM") or "MEDIUM").upper()
                matched_at = data.get("matched-at") or data.get("matched", "")
                description = info.get("description", "")
                cve_tags = ", ".join(info.get("tags", [])) if isinstance(info.get("tags"), list) else ""

                findings.append({
                    "title": f"[{template_id}] {title}",
                    "severity": severity,
                    "category": "NUCLEI_DISCOVERY",
                    "url": matched_at,
                    "evidence": line[:1000],
                    "description": f"{description}\nTags: {cve_tags}".strip(),
                    "remediation": info.get("remediation", "Review template references and patch vulnerable software component.")
                })
                continue
            except json.JSONDecodeError:
                pass

        # Text format: [template-id] [protocol] [severity] url [extra...]
        text_match = re.search(r"\[([a-zA-Z0-9_\-\.]+)\]\s+\[([a-zA-Z0-9_\-]+)\]\s+\[(info|low|medium|high|critical)\]\s+([^\s]+)", line, re.IGNORECASE)
        if text_match:
            template_id = text_match.group(1)
            severity = text_match.group(3).upper()
            target_url = text_match.group(4)

            findings.append({
                "title": f"[{template_id}] Discovered by Nuclei Scanner",
                "severity": severity,
                "category": "NUCLEI_DISCOVERY",
                "url": target_url,
                "evidence": line,
                "description": f"Automated Nuclei scan match for template '{template_id}'.",
                "remediation": "Investigate flagged component and update target endpoint permissions or packages."
            })

    return findings


def parse_fuzzing_output(raw_output: str, fallback_host: str = "") -> List[Dict[str, Any]]:
    """
    Parses directory and route fuzzing output from FFUF, Gobuster, and Dirsearch.
    Extracts discovered paths with status 200, 301, 302, 401, 403.
    """
    endpoints: List[Dict[str, Any]] = []

    # FFUF text: <word> [Status: 200, Size: 1234, Words: 56, Lines: 78, Duration: 12ms]
    ffuf_matches = re.finditer(r"^\s*([^\s]+)\s+\[Status:\s*(\d{3}),\s*Size:\s*(\d+)", raw_output, re.MULTILINE)
    for m in ffuf_matches:
        path = m.group(1).strip()
        status = int(m.group(2))
        clean_path = path if path.startswith("/") else f"/{path}"
        endpoints.append({
            "path": clean_path,
            "status": status,
            "method": "GET",
            "notes": f"FFUF discovered (Status: {status})"
        })

    # Gobuster: Found: /admin (Status: 200) [Size: ...]
    gobuster_matches = re.finditer(r"Found:\s+([^\s]+)\s+\(Status:\s*(\d{3})\)", raw_output)
    for m in gobuster_matches:
        path = m.group(1).strip()
        status = int(m.group(2))
        clean_path = path if path.startswith("/") else f"/{path}"
        endpoints.append({
            "path": clean_path,
            "status": status,
            "method": "GET",
            "notes": f"Gobuster discovered (Status: {status})"
        })

    # Dirsearch: [12:00:00] 200 - 1KB - /api/v1/users
    dirsearch_matches = re.finditer(r"\[\d+:\d+:\d+\]\s+(\d{3})\s+-\s+[^\s]+\s+-\s+([^\s]+)", raw_output)
    for m in dirsearch_matches:
        status = int(m.group(1))
        path = m.group(2).strip()
        clean_path = path if path.startswith("/") else f"/{path}"
        endpoints.append({
            "path": clean_path,
            "status": status,
            "method": "GET",
            "notes": f"Dirsearch discovered (Status: {status})"
        })

    return endpoints


def mine_and_ingest_cli_output(
    command: str,
    raw_output: str,
    target: str = "",
    project: str = "default"
) -> Dict[str, Any]:
    """
    Main ingestion coordinator that inspects CLI output, parses discovered assets,
    services, endpoints, or findings, and commits them to the SQLite Knowledge Graph.
    """
    tool_type = detect_tool_type(command, raw_output)
    target_project = (project or "default").strip().lower()

    # Determine default host
    fallback_host = target.strip()
    if "://" in fallback_host:
        fallback_host = urllib.parse.urlparse(fallback_host).netloc.split(":")[0]

    services_ingested = 0
    endpoints_ingested = 0
    findings_recorded = 0

    # 1. Parse & Ingest Ports / Services (Nmap / Masscan)
    if tool_type in ("NMAP", "MASSCAN"):
        parsed_services = parse_nmap_output(raw_output, fallback_host=fallback_host)
        for s in parsed_services:
            try:
                add_or_update_service(
                    project=target_project,
                    host=s["host"],
                    port=s["port"],
                    protocol=s["protocol"],
                    service_name=s["service_name"],
                    banner=s["banner"],
                    state=s["state"]
                )
                services_ingested += 1
            except Exception as e:
                logger.debug(f"Service ingestion error: {e}")

    # 2. Parse & Ingest Vulnerabilities (Nuclei)
    elif tool_type == "NUCLEI":
        parsed_findings = parse_nuclei_output(raw_output, fallback_host=fallback_host)
        if parsed_findings:
            db = SessionLocal()
            try:
                for f in parsed_findings:
                    finding_url = f.get("url") or (f"http://{fallback_host}" if fallback_host else "http://cli.target")
                    parsed_u = urllib.parse.urlparse(finding_url)
                    host_val = parsed_u.netloc.split(":")[0] if parsed_u.netloc else (fallback_host or "target.local")

                    # Register asset and synthetic log
                    upsert_target_asset(project=target_project, host=host_val, notes="Discovered via Nuclei CLI")
                    
                    log_entry = HttpLog(
                        project=target_project,
                        source="NUCLEI_CLI",
                        method="VULN_SCAN",
                        url=finding_url,
                        host=host_val,
                        path=parsed_u.path or "/",
                        status_code=200,
                        flag_status="CONFIRMED" if f["severity"] in ("HIGH", "CRITICAL") else "POTENTIAL",
                        reasoning=f"Nuclei automated signature match: {f['title']}"
                    )
                    db.add(log_entry)
                    db.flush()

                    finding_record = Finding(
                        log_id=log_entry.id,
                        title=f["title"],
                        severity=f["severity"],
                        category=f["category"],
                        evidence=f.get("evidence", ""),
                        description=f.get("description", ""),
                        remediation=f.get("remediation", "")
                    )
                    db.add(finding_record)
                    findings_recorded += 1
                db.commit()
            except Exception as e:
                db.rollback()
                logger.warning(f"Failed to record Nuclei findings: {e}")
            finally:
                db.close()

    # 3. Parse & Ingest Routes / Endpoints (FFUF, Gobuster, Dirsearch)
    elif tool_type in ("FFUF", "GOBUSTER", "DIRSEARCH"):
        parsed_eps = parse_fuzzing_output(raw_output, fallback_host=fallback_host)
        for ep in parsed_eps:
            try:
                full_url = f"http://{fallback_host}{ep['path']}" if fallback_host else ep['path']
                add_or_update_endpoint(
                    project=target_project,
                    host=fallback_host or "target.local",
                    url=full_url,
                    method=ep["method"],
                    tested_status="DISCOVERED",
                    notes=ep["notes"]
                )
                endpoints_ingested += 1
            except Exception as e:
                logger.debug(f"Endpoint ingestion error: {e}")

    return {
        "status": "completed",
        "tool_detected": tool_type,
        "services_ingested": services_ingested,
        "endpoints_ingested": endpoints_ingested,
        "findings_recorded": findings_recorded,
        "summary": f"Ingested {services_ingested} services, {endpoints_ingested} endpoints, {findings_recorded} findings from {tool_type} output."
    }
