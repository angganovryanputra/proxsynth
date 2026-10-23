"""
Proxsynth - Automated Payload Vault Capture & Extraction Engine
Captures, parses, classifies, and commits verified exploit payloads and fuzzer anomalies
to the cryptographic CapturedPayload vault with real-time WebSocket broadcast.
"""

import re
import urllib.parse
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.database import CapturedPayload, HttpLog

VULN_PATTERNS = [
    ("SQLI", [r"sql", r"union", r"syntax error", r"ora-", r"mysql", r"sqlite", r"pg_query"]),
    ("XSS", [r"xss", r"<script", r"onload=", r"onerror=", r"alert\(", r"javascript:"]),
    ("SSTI", [r"ssti", r"7\*7", r"template", r"jinja", r"mako", r"freemarker"]),
    ("SSRF", [r"ssrf", r"169\.254\.", r"metadata", r"internal", r"oast", r"callback"]),
    ("CMD_INJECTION", [r"rce", r"command", r"exec", r"whoami", r"/bin/sh", r"cmd"]),
    ("LFI", [r"lfi", r"traversal", r"etc/passwd", r"win\.ini", r"\.\./"]),
    ("AUTH_BYPASS", [r"auth", r"idor", r"bola", r"bac", r"privilege", r"token", r"jwt"]),
]


def classify_vuln_type(findings: List[Dict[str, Any]], reasoning: str = "", source: str = "") -> str:
    """Classifies vulnerability type from finding titles, categories, or reasoning."""
    text_to_check = ""
    if findings:
        for f in findings:
            text_to_check += f" {f.get('title', '')} {f.get('category', '')} {f.get('description', '')}"
    text_to_check += f" {reasoning}".lower()

    for vuln_type, keywords in VULN_PATTERNS:
        for kw in keywords:
            if re.search(kw, text_to_check, re.IGNORECASE):
                return vuln_type

    if source == "FUZZER":
        return "FUZZ_ANOMALY"
    return "CUSTOM"


def extract_payload_and_param(url: str, request_body: str, payload_hint: Optional[str] = None) -> Tuple[str, str]:
    """
    Extracts the targeted parameter name and the specific raw payload from request body or URL query.
    Handles §marker§ format, URL query params, and application/x-www-form-urlencoded or JSON bodies.
    """
    if payload_hint and payload_hint.strip():
        param = ""
        body_or_query = f"{urllib.parse.urlparse(url or '').query}&{request_body or ''}"
        for pair in body_or_query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                if urllib.parse.unquote(v) == payload_hint or v == payload_hint:
                    param = k
                    break
        return payload_hint.strip(), param

    raw_payload = ""
    target_param = ""
    req_body_str = request_body or ""
    parsed_u = urllib.parse.urlparse(url or "")

    # 1. Check for §...§ markers in body
    if req_body_str.strip():
        if "§" in req_body_str:
            m = re.search(r'([a-zA-Z0-9_\-\.]+)=§([^§]+)§', req_body_str)
            if m:
                target_param = m.group(1)
                raw_payload = m.group(2)
            else:
                m2 = re.search(r'§([^§]+)§', req_body_str)
                if m2:
                    raw_payload = m2.group(1)
        elif "=" in req_body_str and "&" in req_body_str:
            pairs = req_body_str.split("&")
            for p in pairs:
                if "=" in p:
                    k, v = p.split("=", 1)
                    v_unq = urllib.parse.unquote(v)
                    if any(c in v_unq for c in ["'", '"', "<", ">", ";", "select", "union", "{{", "${", "sleep(", "../", "..\\"]):
                        target_param = k
                        raw_payload = v_unq
                        break
        elif req_body_str.strip().startswith("{") and req_body_str.strip().endswith("}"):
            import json
            try:
                j_data = json.loads(req_body_str)
                if isinstance(j_data, dict):
                    for jk, jv in j_data.items():
                        if isinstance(jv, str) and any(c in jv for c in ["'", '"', "<", ">", ";", "select", "union", "{{", "${", "sleep(", "../", "..\\"]):
                            target_param = jk
                            raw_payload = jv
                            break
            except Exception:
                pass

    # 2. Check URL query parameters
    if (not raw_payload or not target_param) and parsed_u.query:
        if "§" in parsed_u.query:
            m = re.search(r'([a-zA-Z0-9_\-\.]+)=§([^§]+)§', parsed_u.query)
            if m:
                target_param = m.group(1)
                raw_payload = m.group(2)
            else:
                m2 = re.search(r'§([^§]+)§', parsed_u.query)
                if m2:
                    raw_payload = m2.group(1)
        else:
            q_pairs = parsed_u.query.split("&")
            for qp in q_pairs:
                if "=" in qp:
                    k, v = qp.split("=", 1)
                    v_unq = urllib.parse.unquote(v)
                    if any(c in v_unq for c in ["'", '"', "<", ">", ";", "select", "union", "{{", "${", "sleep(", "../", "..\\"]):
                        target_param = k
                        raw_payload = v_unq
                        break
            if not raw_payload and q_pairs:
                parts = q_pairs[0].split("=", 1)
                target_param = parts[0]
                raw_payload = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

    if not raw_payload:
        raw_payload = (req_body_str[:500] if req_body_str else url)[:500]

    return raw_payload, target_param


def auto_vault_payload(
    db: Session,
    project: str,
    agent_id: str,
    method: str,
    url: str,
    request_body: str,
    response_body: str,
    status_code: Optional[int],
    flag_status: str,
    findings: List[Dict[str, Any]],
    reasoning: str = "",
    source: str = "HTTP_CLIENT",
    http_log_id: Optional[int] = None,
    payload_hint: Optional[str] = None
) -> Optional[CapturedPayload]:
    """
    Evaluates whether a traffic log or fuzzer anomaly qualifies for automatic Payload Vault storage.
    If qualified and not a duplicate, creates and commits a CapturedPayload entry.
    """
    proj = (project or "default").strip().lower()
    is_critical_finding = (flag_status == "CONFIRMED") or any(f.get("severity") in ["HIGH", "CRITICAL"] for f in findings)
    is_fuzz_anomaly = (source == "FUZZER" and flag_status in ["CONFIRMED", "POTENTIAL"])

    if not (is_critical_finding or is_fuzz_anomaly or payload_hint):
        return None

    raw_payload, target_param = extract_payload_and_param(url, request_body, payload_hint=payload_hint)
    if not raw_payload or not raw_payload.strip():
        return None

    vuln_type = classify_vuln_type(findings, reasoning, source)

    # Check for duplicate in this project
    existing = db.query(CapturedPayload).filter(
        CapturedPayload.project == proj,
        CapturedPayload.raw_payload == raw_payload,
        CapturedPayload.target_url == url
    ).first()

    if existing:
        return None

    notes_text = f"Auto-vaulted from {source}: "
    if findings:
        notes_text += ", ".join([f.get("title", "") for f in findings])
    elif reasoning:
        notes_text += reasoning
    else:
        notes_text += f"Flag: {flag_status}"

    vault_entry = CapturedPayload(
        project=proj,
        agent_id=agent_id or "primary_agent",
        vuln_type=vuln_type,
        target_param=target_param[:128],
        raw_payload=raw_payload,
        mutation_type="FUZZER" if source == "FUZZER" else "DIRECT",
        target_url=url,
        http_method=(method or "GET").upper(),
        http_log_id=http_log_id,
        outcome="CONFIRMED" if is_critical_finding else "ANOMALY",
        http_status=status_code,
        response_signature=(response_body or "")[:255],
        notes=notes_text[:500]
    )

    db.add(vault_entry)
    db.commit()
    db.refresh(vault_entry)
    return vault_entry


def auto_vault_script_payloads(
    db: Session,
    project: str,
    agent_id: str,
    script_content: str,
    command: str = "",
    cmd_log_id: Optional[int] = None
) -> List[CapturedPayload]:
    """
    Extracts security testing and exploit payloads from custom script sources or executed CLI commands,
    classifies their vulnerability category, and commits them to the CapturedPayload vault.
    """
    proj = (project or "default").strip().lower()
    combined_text = f"{command or ''}\n{script_content or ''}"
    if not combined_text.strip():
        return []

    # 1. Detect target URL
    target_url = ""
    url_match = re.search(r'https?://[^\s\'"<>]+', combined_text)
    if url_match:
        target_url = url_match.group(0).rstrip(")\"',;")

    # 2. Extract payload candidates
    candidates: List[Tuple[str, str]] = []  # List of (payload, param_hint)

    # a) Explicit variable assignments (Python / JS / Bash)
    # e.g., payload = "..." or exploit = '...'
    for m in re.finditer(r'''(?i)(?:payload|exploit|vector|canary|poc)\s*=\s*(?:'([^'\n\r]{2,})'|"([^"\n\r]{2,})")''', combined_text):
        val = (m.group(1) or m.group(2) or "").strip()
        if val and not val.startswith("http://") and not val.startswith("https://"):
            candidates.append((val, "script_variable"))

    # e.g. payloads = ["...", "..."]
    for m in re.finditer(r'''(?i)(?:payloads|vectors|exploits)\s*=\s*\[([^\]]+)\]''', combined_text):
        list_content = m.group(1)
        for item in re.finditer(r'''(?:'([^'\n\r]{2,})'|"([^"\n\r]{2,})")''', list_content):
            item_val = (item.group(1) or item.group(2) or "").strip()
            if item_val and not item_val.startswith("http://") and not item_val.startswith("https://"):
                candidates.append((item_val, "script_payloads_list"))

    # b) Command line parameters containing exploit markers (curl -d "...", -u "...", --data "...")
    for m in re.finditer(r'''(?i)(?:-d|--data(?:-raw)?|-F|--form)\s+['"]([^'"]+)['"]''', command or ''):
        body_val = m.group(1)
        if "=" in body_val:
            for pair in body_val.split("&"):
                if "=" in pair:
                    pk, pv = pair.split("=", 1)
                    if any(c in pv for c in ["'", '"', "<", ">", ";", "select", "union", "{{", "${", "sleep(", "../", "..\\"]):
                        candidates.append((urllib.parse.unquote(pv), pk))

    # c) High-confidence exploit signatures in text
    sig_patterns = [
        (r"(['\"][^'\"]*(?:OR|AND)\s+['\"]?1['\"]?\s*=\s*['\"]?1[^'\"]*['\"])", "sqli"),
        (r"((?:UNION\s+ALL\s+SELECT|UNION\s+SELECT)[^'\";\n]+)", "sqli"),
        (r"((?:SLEEP\(\d+\)|WAITFOR\s+DELAY\s+['\"][^'\"]+['\"]))", "sqli"),
        (r"(<script[^>]*>.*?</script>)", "xss"),
        (r"(<(?:svg|img|iframe|body|input)[^>]+(?:onload|onerror|onfocus)=[^>]+>)", "xss"),
        (r"(javascript:[^\s'\";\)]+)", "xss"),
        (r"(\{\{[0-9a-zA-Z_\.\+\-\*\/]+\}\})", "ssti"),
        (r"(\$\{[0-9a-zA-Z_\.\+\-\*\/]+\})", "ssti"),
        (r"(\$\{(?:jndi|lower|upper):[^}]+\})", "jndi"),
        (r"((?:\.\./|\.\.\\){2,}[a-zA-Z0-9_\-\.\/\\]+)", "path_traversal"),
        (r"(/etc/passwd|windows/win\.ini)", "lfi"),
        (r"(http://169\.254\.169\.254[^\s'\"]*)", "ssrf"),
        (r"(;\s*(?:id|whoami|cat\s+/etc/passwd|uname\s+-a|dir|ipconfig|type\s+win\.ini))", "cmd_injection"),
        (r"(\$\((?:id|whoami|uname)\)|`(?:\s*id\s*|\s*whoami\s*)`)", "cmd_injection")
    ]

    for pat, cat_name in sig_patterns:
        for m in re.finditer(pat, combined_text, re.IGNORECASE):
            val = m.group(1).strip()
            if len(val) >= 3:
                candidates.append((val, cat_name))

    if not candidates:
        return []

    created_entries: List[CapturedPayload] = []
    seen_payloads = set()

    for raw_p, param_hint in candidates:
        cleaned_p = raw_p.strip()
        if not cleaned_p or len(cleaned_p) < 2 or cleaned_p in seen_payloads:
            continue
        seen_payloads.add(cleaned_p)

        # Check duplicate in SQLite database for this project
        exists = db.query(CapturedPayload).filter(
            CapturedPayload.project == proj,
            CapturedPayload.raw_payload == cleaned_p
        ).first()

        if exists:
            continue

        v_type = classify_vuln_type([], reasoning=f"Script payload extraction: {cleaned_p} ({param_hint})", source="AI_AGENT_SCRIPT")
        notes_str = f"Auto-captured from agent script/command execution (param: {param_hint})"
        if command:
            notes_str += f" | CLI: {command[:80]}"

        entry = CapturedPayload(
            project=proj,
            agent_id=agent_id or "primary_agent",
            vuln_type=v_type,
            target_param=param_hint[:128],
            raw_payload=cleaned_p,
            mutation_type="SCRIPT_EXTRACT",
            target_url=target_url,
            http_method="CLI",
            outcome="TESTED",
            notes=notes_str[:500]
        )
        db.add(entry)
        try:
            db.commit()
            db.refresh(entry)
            created_entries.append(entry)
        except Exception:
            db.rollback()

    return created_entries
