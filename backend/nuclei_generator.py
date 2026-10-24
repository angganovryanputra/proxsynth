"""
Proxsynth - Nuclei v3 Exploit & Regression Template Generator
Automatically generates standardized Nuclei v3 YAML templates from confirmed security findings
and HTTP proxy logs for regression testing, CI/CD pipelines, and DAST workflows.
"""

import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional
import yaml

from backend.database import Finding, HttpLog


def _sanitize_id(text: str) -> str:
    """Creates a clean, valid Nuclei template ID slug."""
    clean = re.sub(r'[^a-zA-Z0-9_-]', '-', text.strip().lower())
    clean = re.sub(r'-+', '-', clean).strip('-')
    if not clean:
        clean = "proxsynth-exploit"
    if not clean.startswith("proxsynth-"):
        clean = f"proxsynth-{clean}"
    return clean[:64]


def _map_cwe_reference(category: str) -> List[str]:
    """Maps security category to standard CWE / OWASP references."""
    cat = (category or "").lower()
    refs = ["https://github.com/angganovryanputra/proxynth"]
    if "sql" in cat or "injection" in cat:
        refs.extend(["https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/Top10/A03_2021-Injection/"])
    elif "bola" in cat or "idor" in cat or "authorization" in cat:
        refs.extend(["https://cwe.mitre.org/data/definitions/639.html", "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"])
    elif "xss" in cat or "cross-site scripting" in cat:
        refs.extend(["https://cwe.mitre.org/data/definitions/79.html", "https://owasp.org/Top10/A03_2021-Injection/"])
    elif "jwt" in cat or "token" in cat or "auth" in cat:
        refs.extend(["https://cwe.mitre.org/data/definitions/287.html", "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"])
    elif "ssrf" in cat:
        refs.extend(["https://cwe.mitre.org/data/definitions/918.html", "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"])
    elif "cors" in cat or "misconfiguration" in cat:
        refs.extend(["https://cwe.mitre.org/data/definitions/16.html", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"])
    elif "info" in cat or "leak" in cat or "disclosure" in cat:
        refs.extend(["https://cwe.mitre.org/data/definitions/200.html", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"])
    return refs


def _extract_match_keywords(evidence: Optional[str], response_body: Optional[str]) -> List[str]:
    """Pulls high-confidence match words from evidence or response body."""
    keywords = []
    if evidence:
        # Check for quoted words or patterns in evidence
        matches = re.findall(r'["\']([^"\']{4,40})["\']', evidence)
        for m in matches:
            if not any(stop in m.lower() for stop in ["content-type", "application/json", "bearer", "authorization"]):
                keywords.append(m)
                if len(keywords) >= 3:
                    break
    
    if not keywords and response_body:
        # If response is JSON, pick top-level identifying keys
        body_trimmed = response_body.strip()
        if body_trimmed.startswith("{"):
            try:
                data = json.loads(body_trimmed)
                if isinstance(data, dict):
                    for k in ["id", "email", "username", "token", "status", "error", "message"]:
                        if k in data:
                            keywords.append(f'"{k}"')
                            break
            except Exception:
                pass

    return keywords[:3]


def _build_raw_http_request(method: str, url: str, req_headers: Dict[str, Any], req_body: Optional[str] = None) -> str:
    """Builds a formatted raw HTTP request with {{Hostname}} placeholder."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    
    clean_method = (method or "GET").upper()
    lines = [f"{clean_method} {path} HTTP/1.1", "Host: {{Hostname}}"]
    
    # Standard headers with default fallback
    has_accept = False
    has_ua = False
    
    for k, v in req_headers.items():
        k_lower = k.lower()
        if k_lower in ["host", "content-length"]:
            continue
        if k_lower == "accept":
            has_accept = True
        if k_lower == "user-agent":
            has_ua = True
        lines.append(f"{k}: {v}")
        
    if not has_ua:
        lines.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Proxsynth/0.1.0-beta")
    if not has_accept:
        lines.append("Accept: */*")
        
    if req_body and clean_method in ["POST", "PUT", "PATCH"]:
        if not any(k.lower() == "content-type" for k in req_headers.keys()):
            if req_body.strip().startswith("{") or req_body.strip().startswith("["):
                lines.append("Content-Type: application/json")
            else:
                lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append("")
        lines.append(req_body.strip())
    else:
        lines.append("")
        
    return "\n".join(lines)


def generate_nuclei_template_dict(
    template_id: str,
    name: str,
    severity: str,
    description: str,
    category: str,
    raw_request: str,
    status_codes: List[int],
    match_words: List[str] = None,
    tags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Generates the structured dictionary representation of a Nuclei v3 template."""
    clean_sev = (severity or "medium").strip().lower()
    if clean_sev not in ["critical", "high", "medium", "low", "info"]:
        clean_sev = "medium"

    all_tags = ["proxsynth", "dast", clean_sev]
    cat_slug = re.sub(r'[^a-zA-Z0-9]', '', category.lower())
    if cat_slug:
        all_tags.append(cat_slug[:16])
    if tags:
        all_tags.extend([t.strip().lower() for t in tags if t.strip()])
    
    unique_tags = list(dict.fromkeys(all_tags))

    matchers = [
        {
            "type": "status",
            "status": status_codes if status_codes else [200]
        }
    ]

    if match_words:
        matchers.append({
            "type": "word",
            "part": "body",
            "words": match_words
        })

    return {
        "id": template_id,
        "info": {
            "name": name,
            "author": "proxsynth",
            "severity": clean_sev,
            "description": description,
            "reference": _map_cwe_reference(category),
            "metadata": {
                "generated_by": "Proxsynth Autonomous Cyber Platform",
                "framework": "nuclei-v3"
            },
            "tags": ",".join(unique_tags)
        },
        "http": [
            {
                "raw": [
                    raw_request + "\n"
                ],
                "matchers-condition": "and",
                "matchers": matchers
            }
        ]
    }


def generate_nuclei_yaml_from_finding(finding: Finding, log: Optional[HttpLog] = None) -> Dict[str, Any]:
    """
    Synthesizes a full Nuclei v3 template from a Finding and optional HttpLog.
    Returns template YAML string, parsed dictionary, and suggested filename.
    """
    clean_id = _sanitize_id(f"{finding.category}-{finding.id}")
    
    url = log.url if log else "http://{{Hostname}}/"
    method = log.method if log else "GET"
    req_headers = {}
    if log and log.request_headers:
        try:
            req_headers = json.loads(log.request_headers)
        except Exception:
            pass
            
    req_body = log.request_body if log else None
    raw_req = _build_raw_http_request(method, url, req_headers, req_body)
    
    # Infer matching conditions
    expected_status = [log.status_code] if (log and log.status_code and log.status_code < 500) else [200]
    match_words = _extract_match_keywords(finding.evidence, log.response_body if log else None)
    
    tmpl_dict = generate_nuclei_template_dict(
        template_id=clean_id,
        name=finding.title or "Vulnerability Regression Check",
        severity=finding.severity or "medium",
        description=finding.description or f"Auto-generated regression template for finding #{finding.id}",
        category=finding.category or "vulnerability",
        raw_request=raw_req,
        status_codes=expected_status,
        match_words=match_words
    )
    
    yaml_str = yaml.dump(tmpl_dict, sort_keys=False, default_flow_style=False, allow_unicode=True)
    filename = f"{clean_id}.yaml"
    
    return {
        "id": clean_id,
        "filename": filename,
        "name": finding.title,
        "severity": finding.severity.lower() if finding.severity else "medium",
        "yaml": yaml_str,
        "template": tmpl_dict
    }


def generate_nuclei_yaml_from_log(
    log: HttpLog,
    title: Optional[str] = None,
    severity: str = "medium",
    match_words: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Synthesizes a Nuclei v3 template from any observed HttpLog."""
    parsed = urllib.parse.urlparse(log.url)
    clean_id = _sanitize_id(f"endpoint-{log.method.lower()}-{parsed.path}")
    
    req_headers = {}
    if log.request_headers:
        try:
            req_headers = json.loads(log.request_headers)
        except Exception:
            pass
            
    raw_req = _build_raw_http_request(log.method, log.url, req_headers, log.request_body)
    status_codes = [log.status_code] if log.status_code else [200]
    
    words = match_words if match_words else _extract_match_keywords(None, log.response_body)
    
    tmpl_dict = generate_nuclei_template_dict(
        template_id=clean_id,
        name=title or f"Validation for {log.method} {parsed.path}",
        severity=severity,
        description=f"Auto-generated Nuclei validation probe for {log.url} (Captured via Proxsynth)",
        category="Regression",
        raw_request=raw_req,
        status_codes=status_codes,
        match_words=words
    )
    
    yaml_str = yaml.dump(tmpl_dict, sort_keys=False, default_flow_style=False, allow_unicode=True)
    return {
        "id": clean_id,
        "filename": f"{clean_id}.yaml",
        "name": title or f"Validation for {log.method} {parsed.path}",
        "severity": severity.lower(),
        "yaml": yaml_str,
        "template": tmpl_dict
    }
