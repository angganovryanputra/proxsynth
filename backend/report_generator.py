"""
Proxsynth MCP - Report & HAR 1.2 Export Generator
Exports testing traffic to standard HAR format (for Burp/ZAP) and generates executive pentest reports.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any

from sqlalchemy.orm import Session
from backend.database import HttpLog, Finding, Project, AgentCommandLog, CapturedPayload, TargetAsset, TargetService, TargetEndpoint, OastEvent


def generate_har_export(project_name: str, db: Session) -> Dict[str, Any]:
    """
    Exports all HTTP/HTTPS logs for a project to standard HTTP Archive 1.2 (HAR) format.
    Compatible with Burp Suite, OWASP ZAP, Postman, and Chrome DevTools.
    """
    query = db.query(HttpLog)
    if project_name and project_name.upper() != "ALL":
        query = query.filter(HttpLog.project == project_name.lower())

    logs = query.order_by(HttpLog.id.asc()).all()

    entries = []
    for log in logs:
        try:
            req_headers_dict = json.loads(log.request_headers) if log.request_headers else {}
        except Exception:
            req_headers_dict = {}

        try:
            res_headers_dict = json.loads(log.response_headers) if log.response_headers else {}
        except Exception:
            res_headers_dict = {}

        req_headers_list = [{"name": str(k), "value": str(v)} for k, v in req_headers_dict.items()]
        res_headers_list = [{"name": str(k), "value": str(v)} for k, v in res_headers_dict.items()]

        req_body = log.request_body or ""
        res_body = log.response_body or ""

        entry = {
            "startedDateTime": log.timestamp.isoformat() if log.timestamp else datetime.now().isoformat(),
            "time": log.duration_ms or 0,
            "request": {
                "method": log.method,
                "url": log.url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": req_headers_list,
                "queryString": [],
                "postData": {
                    "mimeType": "application/octet-stream",
                    "text": req_body
                } if req_body else None,
                "headersSize": -1,
                "bodySize": len(req_body.encode("utf-8", errors="ignore"))
            },
            "response": {
                "status": log.status_code or 0,
                "statusText": "OK" if log.status_code == 200 else "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": res_headers_list,
                "content": {
                    "size": len(res_body.encode("utf-8", errors="ignore")),
                    "mimeType": "text/plain",
                    "text": res_body
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(res_body.encode("utf-8", errors="ignore"))
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": log.duration_ms or 0,
                "receive": 0
            },
            "comment": f"Proxsynth Flag: {log.flag_status} | Project: {log.project}"
        }
        entries.append(entry)

    return {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "Proxsynth MCP Gateway",
                "version": "1.1.0"
            },
            "pages": [],
            "entries": entries
        }
    }


def generate_markdown_report(project_name: str, db: Session) -> str:
    """
    Generates a professional Markdown Vulnerability Assessment & Pentest Report.
    """
    proj_query = db.query(Project).filter(Project.name == project_name.lower()).first()
    proj_desc = proj_query.description if proj_query else "Security Testing Scope"

    log_query = db.query(HttpLog)
    finding_query = db.query(Finding).join(HttpLog)

    if project_name and project_name.upper() != "ALL":
        log_query = log_query.filter(HttpLog.project == project_name.lower())
        finding_query = finding_query.filter(HttpLog.project == project_name.lower())

    total_reqs = log_query.count()
    findings = finding_query.order_by(Finding.id.asc()).all()

    # Attack Surface & OAST queries
    asset_query = db.query(TargetAsset)
    oast_query = db.query(OastEvent)
    if project_name and project_name.upper() != "ALL":
        asset_query = asset_query.filter(TargetAsset.project == project_name.lower())
        oast_query = oast_query.filter(OastEvent.project == project_name.lower())

    assets = asset_query.all()
    oast_events = oast_query.all()
    total_assets = len(assets)
    total_services = sum(len(a.services) for a in assets)
    total_endpoints = sum(len(a.endpoints) for a in assets)
    total_oast = len(oast_events)

    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity in ["LOW", "INFO"])

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = f"""# 🛡️ SECURITY AUDIT REPORT: {project_name.upper()}
**Generated by:** Proxsynth MCP — AI Security Testing Gateway & Observability Platform  
**Date of Assessment:** {now_str}  
**Target Scope:** `{project_name}` ({proj_desc})  

---

## 1. Executive Summary

During this security assessment, an autonomous AI Agent (e.g., Opencode / Hermes) orchestrated automated testing payloads intercepted and monitored via the **Proxsynth MCP Gateway**.

- **Total Requests Inspected:** `{total_reqs}`
- **Discovered Target Assets:** `{total_assets}`
- **Open Services & Ports:** `{total_services}`
- **Mapped Endpoints:** `{total_endpoints}`
- **Out-of-Band (OAST) Callbacks:** `{total_oast}`
- **Total Security Findings:** `{len(findings)}`
  - 🔴 **Critical Severity:** `{crit_count}`
  - 🟠 **High Severity:** `{high_count}`
  - 🟡 **Medium Severity:** `{med_count}`
  - 🔵 **Low / Informational:** `{low_count}`

---

## 2. Findings Summary Table

| ID | Severity | Title | Category | Target Endpoint |
| :--- | :--- | :--- | :--- | :--- |
"""

    for f in findings:
        endpoint = f"{f.log.method} {f.log.path}" if f.log else "N/A"
        md += f"| `#{f.id}` | **{f.severity}** | {f.title} | {f.category} | `{endpoint}` |\n"

    if not findings:
        md += "| - | - | *No security vulnerabilities detected during this session.* | - | - |\n"

    md += """
---

## 3. Detailed Vulnerability Breakdown

"""

    for f in findings:
        req_line = f"{f.log.method} {f.log.url}" if f.log else "N/A"
        reasoning = f.log.reasoning if (f.log and f.log.reasoning) else "Automated security heuristic"
        
        md += f"""### [{f.severity}] {f.title}
- **Vulnerability Category:** {f.category}
- **Target URL:** `{req_line}`
- **AI Agent Intent / Reasoning:** *"{reasoning}"*

#### Description:
{f.description}

#### Matched Evidence:
```text
{f.evidence or '[No raw snippet recorded]'}
```

#### Remediation Guidance:
> {f.remediation or 'Apply input validation, output encoding, and principle of least privilege.'}

---
"""

    # 4. Target Attack Surface & Infrastructure Topology
    md += """## 4. Target Attack Surface & Infrastructure Topology

### Discovered Target Hosts & Services
| ID | Host / Domain | IP Address | OS Banner | Open Ports / Services | Tags |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for a in assets:
        ports_str = ", ".join([f"{s.port}/{s.protocol} ({s.service_name})" for s in a.services]) if a.services else "No open ports registered"
        if a.tags:
            try:
                parsed_t = json.loads(a.tags)
                tags_str = ", ".join(parsed_t) if isinstance(parsed_t, list) else str(a.tags)
            except Exception:
                tags_str = str(a.tags)
        else:
            tags_str = "-"
        md += f"| `#{a.id}` | `{a.host}` | `{a.ip or '-'}` | {a.os_info or '-'} | {ports_str} | `{tags_str}` |\n"

    if not assets:
        md += "| - | - | - | *No target assets recorded in knowledge graph.* | - | - |\n"

    md += """
### Target Endpoints Testing Progression Matrix
| ID | Method | Target URL | Tested Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
"""
    all_endpoints = []
    for a in assets:
        for ep in a.endpoints:
            all_endpoints.append(ep)

    for ep in all_endpoints:
        md += f"| `#{ep.id}` | `{ep.method}` | `{ep.url}` | **{ep.tested_status}** | {ep.notes or '-'} |\n"

    if not all_endpoints:
        md += "| - | - | *No endpoints mapped in knowledge graph.* | - | - |\n"

    md += """
---

## 5. Out-of-Band (OAST) Interactions Ledger

| ID | Correlation Token | Protocol | Remote Client IP | Timestamp | Path / Subpath |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for ev in oast_events:
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "-"
        md += f"| `#{ev.id}` | `{ev.token}` | `{ev.protocol}` | `{ev.client_ip or '-'}` | {ts} | `{ev.path}` |\n"

    if not oast_events:
        md += "| - | - | - | *No out-of-band callbacks captured.* | - | - |\n"

    md += """
---

## 6. AI Command Execution Audit Trail

| ID | Status | Tool / Engine | Command | Exit Code | Duration | AI Intent / Reasoning |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
"""
    # 6. AI Command Audit Trail
    cmd_query = db.query(AgentCommandLog)
    if project_name and project_name.upper() != "ALL":
        cmd_query = cmd_query.filter(AgentCommandLog.project == project_name.lower())
    commands = cmd_query.order_by(AgentCommandLog.id.asc()).all()

    for c in commands:
        cmd_snippet = f"`{c.command[:60]}...`" if len(c.command) > 60 else f"`{c.command}`"
        reason = c.reasoning or "Automated pentest execution"
        md += f"| `#{c.id}` | **{c.status}** | `{c.tool_name}` | {cmd_snippet} | `{c.exit_code}` | {c.duration_ms}ms | *{reason}* |\n"

    if not commands:
        md += "| - | - | - | *No CLI/terminal commands recorded.* | - | - | - |\n"

    md += """
---

## 7. Captured Security Test Payloads Vault

| ID | Type | Parameter | Raw Payload | HTTP Method | Outcome | Target Endpoint |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
"""
    payload_query = db.query(CapturedPayload)
    if project_name and project_name.upper() != "ALL":
        payload_query = payload_query.filter(CapturedPayload.project == project_name.lower())
    payloads = payload_query.order_by(CapturedPayload.id.asc()).all()

    for p in payloads:
        pay_snippet = f"`{p.raw_payload[:60]}...`" if len(p.raw_payload) > 60 else f"`{p.raw_payload}`"
        md += f"| `#{p.id}` | **{p.vuln_type}** | `{p.target_param or '-'}` | {pay_snippet} | `{p.http_method}` | **{p.outcome}** | `{p.target_url}` |\n"

    if not payloads:
        md += "| - | - | - | *No security test payloads cataloged.* | - | - | - |\n"

    md += """
---

## 8. Assessment Methodology & Guardrails
All testing traffic, terminal commands, attack surface mapping, and out-of-band interactions were isolated and orchestrated through the Proxsynth Model Context Protocol Gateway. Automated deterministic signatures and heuristic anomaly detection triaged each interaction in real-time, while Proxsynth Safe-Mode guardrails prevented destructive system operations.
"""

    return md
