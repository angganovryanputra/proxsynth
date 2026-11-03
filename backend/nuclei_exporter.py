"""
PROXSYNTH - Automatic Nuclei YAML Template Exporter
Converts verified vulnerabilities, AST-extracted payloads, and intercepted HTTP logs
into standard ProjectDiscovery Nuclei v2/v3 YAML templates for automated CI/CD security regression.
"""

import re
import json
import yaml
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urlparse

from backend.database import SessionLocal, Finding, HttpLog, CapturedPayload


def _slugify(text: str) -> str:
    """Converts a title or string into a sanitized Nuclei template ID slug."""
    s = re.sub(r'[^a-zA-Z0-9_-]+', '-', text.strip().lower())
    s = re.sub(r'-+', '-', s).strip('-')
    return s or "custom-template"


def generate_nuclei_template(
    template_id: str,
    name: str,
    severity: str = "high",
    author: str = "Proxsynth Autonomous Engine",
    description: str = "",
    tags: Optional[Union[List[str], str]] = None,
    method: str = "GET",
    path: Union[str, List[str]] = "/api/test",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    matchers: Optional[List[Dict[str, Any]]] = None,
    extractors: Optional[List[Dict[str, Any]]] = None
) -> str:
    """
    Generates a clean, standard Nuclei v2/v3 YAML template string.
    """
    clean_id = _slugify(template_id)
    clean_severity = severity.strip().lower()
    if clean_severity not in ["critical", "high", "medium", "low", "info"]:
        clean_severity = "high"

    tag_list = tags if isinstance(tags, list) else [t.strip() for t in (tags or "").split(",") if t.strip()]
    if "proxsynth" not in tag_list:
        tag_list.append("proxsynth")

    # Format path items with {{BaseURL}}
    path_list: List[str] = []
    raw_paths = [path] if isinstance(path, str) else path
    for p in raw_paths:
        if not p.startswith("{{BaseURL}}"):
            if not p.startswith("/"):
                p = "/" + p
            p = f"{{{{BaseURL}}}}{p}"
        path_list.append(p)

    http_block: Dict[str, Any] = {
        "method": method.upper(),
        "path": path_list
    }

    if headers:
        http_block["headers"] = headers

    if body and method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
        http_block["body"] = body

    if matchers:
        http_block["matchers-condition"] = "and" if len(matchers) > 1 else "or"
        http_block["matchers"] = matchers
    else:
        http_block["matchers"] = [
            {
                "type": "status",
                "status": [200]
            }
        ]

    if extractors:
        http_block["extractors"] = extractors

    template_dict = {
        "id": clean_id,
        "info": {
            "name": name or f"Proxsynth Exploit Template: {clean_id}",
            "author": author or "Proxsynth Autonomous Engine",
            "severity": clean_severity,
            "description": description or f"Auto-generated Nuclei verification template for {clean_id}",
            "tags": ",".join(tag_list)
        },
        "http": [http_block]
    }

    return yaml.dump(template_dict, sort_keys=False, indent=2)


def export_finding_to_nuclei(
    finding_id: int,
    template_id: Optional[str] = None,
    name: Optional[str] = None,
    severity: Optional[str] = None
) -> str:
    """
    Extracts a confirmed Finding and its associated HttpLog from the database
    and synthesizes a reproducible Nuclei YAML template.
    """
    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding #{finding_id} not found in database.")

        log = db.query(HttpLog).filter(HttpLog.id == finding.log_id).first() if finding.log_id else None

        slug_id = template_id or _slugify(finding.title)
        template_name = name or finding.title
        eff_severity = (severity or finding.severity or "high").lower()

        method = log.method if log else "GET"
        raw_url = log.url if log else "/target"
        parsed = urlparse(raw_url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        headers = {}
        if log and log.request_headers:
            try:
                hdrs = json.loads(log.request_headers) if isinstance(log.request_headers, str) else log.request_headers
                # Filter client-specific headers
                for k, v in hdrs.items():
                    if k.lower() not in ["host", "content-length", "cookie", "user-agent", "accept-encoding"]:
                        headers[k] = v
            except Exception:
                pass

        body = log.request_body if log else None

        # Build dynamic matchers based on finding category, evidence, and response
        matchers = []
        if log and log.status_code:
            matchers.append({"type": "status", "status": [log.status_code]})

        words = []
        if finding.evidence:
            # Extract key strings from evidence
            lines = finding.evidence.strip().split("\n")
            for l in lines[:3]:
                clean_l = l.strip()
                if clean_l and len(clean_l) < 100 and not clean_l.startswith("http"):
                    words.append(clean_l)

        if not words and log and log.response_body and len(log.response_body) < 300:
            words.append(log.response_body.strip())

        if words:
            matchers.append({
                "type": "word",
                "words": words[:3],
                "condition": "or"
            })

        tags = [finding.category.lower().replace(" ", "-"), "proxsynth"]

        return generate_nuclei_template(
            template_id=slug_id,
            name=template_name,
            severity=eff_severity,
            description=finding.description or f"Verified finding: {finding.title}",
            tags=tags,
            method=method,
            path=path,
            headers=headers if headers else None,
            body=body if body else None,
            matchers=matchers
        )
    finally:
        db.close()


def export_payload_to_nuclei(
    payload_id: int,
    target_path: str = "/api/test",
    method: str = "GET"
) -> str:
    """
    Exports a CapturedPayload from database to a Nuclei template.
    """
    db = SessionLocal()
    try:
        p = db.query(CapturedPayload).filter(CapturedPayload.id == payload_id).first()
        if not p:
            raise ValueError(f"CapturedPayload #{payload_id} not found.")

        slug_id = f"payload-{p.vuln_type.lower()}-{p.id}"
        return generate_nuclei_template(
            template_id=slug_id,
            name=f"Proxsynth Payload: {p.vuln_type}",
            severity="high",
            description=p.notes or f"Autonomous payload captured for {p.vuln_type}",
            tags=[p.vuln_type.lower(), "proxsynth"],
            method=method,
            path=target_path,
            body=p.raw_payload if method.upper() in ["POST", "PUT"] else None,
            matchers=[{"type": "status", "status": [200]}]
        )
    finally:
        db.close()

