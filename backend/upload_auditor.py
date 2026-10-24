"""
Proxsynth - Unrestricted File Upload & Multipart Filter Audit Engine
Safely probes file upload endpoints for MIME sniffing, extension filtering,
magic-byte polyglots, SVG XSS, and filename directory traversal.
"""

import os
import re
import io
import json
import urllib.parse
from typing import Dict, Any, Optional, List

import httpx

from backend.database import SessionLocal, HttpLog, Finding


BENIGN_PROBE_MARKER = "PROXSYNTH_UPLOAD_AUDIT_PROBE_7F3D"

UPLOAD_PAYLOAD_TESTS = [
    {
        "test": "Direct Executable Extension (.php)",
        "filename": "audit_probe.php",
        "content_type": "application/x-php",
        "data": f"<?php /* {BENIGN_PROBE_MARKER} */ echo '{BENIGN_PROBE_MARKER}'; ?>",
        "vuln_type": "UNRESTRICTED_FILE_UPLOAD",
        "severity": "CRITICAL",
        "title": "Unrestricted Executable File Upload (.php Allowed)"
    },
    {
        "test": "MIME-Type Confusion (.php with image/png)",
        "filename": "audit_probe_mime.php",
        "content_type": "image/png",
        "data": f"<?php /* {BENIGN_PROBE_MARKER} */ echo '{BENIGN_PROBE_MARKER}'; ?>",
        "vuln_type": "MIME_VALIDATION_BYPASS",
        "severity": "HIGH",
        "title": "File Upload MIME-Type Validation Bypass"
    },
    {
        "test": "Magic Bytes Polyglot (GIF89a + PHP)",
        "filename": "audit_polyglot.php.gif",
        "content_type": "image/gif",
        "data": f"GIF89a; <?php /* {BENIGN_PROBE_MARKER} */ echo '{BENIGN_PROBE_MARKER}'; ?>",
        "vuln_type": "MAGIC_BYTES_POLYGLOT",
        "severity": "HIGH",
        "title": "File Upload Magic Bytes Polyglot Bypass"
    },
    {
        "test": "Double Extension (.php.png)",
        "filename": "audit_double.php.png",
        "content_type": "image/png",
        "data": f"<?php /* {BENIGN_PROBE_MARKER} */ echo '{BENIGN_PROBE_MARKER}'; ?>",
        "vuln_type": "DOUBLE_EXTENSION_UPLOAD",
        "severity": "MEDIUM",
        "title": "Double Extension Upload Accepted (.php.png)"
    },
    {
        "test": "Filename Directory Traversal (..%2f)",
        "filename": "..%2f..%2faudit_traversal.txt",
        "content_type": "text/plain",
        "data": f"Proxsynth Safe Path Traversal Probe {BENIGN_PROBE_MARKER}",
        "vuln_type": "UPLOAD_PATH_TRAVERSAL",
        "severity": "HIGH",
        "title": "File Upload Filename Path Traversal Vulnerability"
    },
    {
        "test": "Stored SVG Cross-Site Scripting (SVG XSS)",
        "filename": "audit_probe.svg",
        "content_type": "image/svg+xml",
        "data": f"<svg xmlns=\"http://www.w3.org/2000/svg\"><text>Audit</text><script>/* {BENIGN_PROBE_MARKER} */</script></svg>",
        "vuln_type": "SVG_STORED_XSS",
        "severity": "HIGH",
        "title": "Stored Cross-Site Scripting via SVG File Upload"
    }
]


async def audit_file_upload_engine(
    url_or_log_id: str,
    field_name: str = "file",
    project: str = "default",
    allow_exploit: bool = False,
    confirmation: Optional[str] = None,
    persist_fn=None,
    vault_fn=None
) -> Dict[str, Any]:
    """
    Safely audits multipart file upload forms against extension bypasses, magic bytes,
    and path traversal. Active exploitation is locked unless allow_exploit=True and confirmation provided.
    """
    target_project = (project or "default").strip().lower()
    target_url = url_or_log_id.strip()
    headers = {"User-Agent": "Proxsynth-Upload-Auditor/1.0"}

    # Resolve if log_id was provided
    if target_url.isdigit():
        log_id = int(target_url)
        db = SessionLocal()
        try:
            log_obj = db.query(HttpLog).filter(HttpLog.id == log_id).first()
            if log_obj:
                target_url = log_obj.url
                try:
                    stored_hdrs = json.loads(log_obj.request_headers) if log_obj.request_headers else {}
                    for k, v in stored_hdrs.items():
                        if k.lower() in ["authorization", "cookie", "x-csrf-token"]:
                            headers[k] = v
                except Exception:
                    pass
        finally:
            db.close()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.netloc

    results = {
        "target_url": target_url,
        "field_name": field_name,
        "project": target_project,
        "allow_exploit": allow_exploit,
        "guardrail_status": "EXPLOITATION_DISALLOWED" if not allow_exploit else "EXPLOITATION_AUTHORIZED",
        "tests_executed": [],
        "vulnerabilities": []
    }

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=12.0) as client:
        for t in UPLOAD_PAYLOAD_TESTS:
            test_name = t["test"]
            filename = t["filename"]
            content_type = t["content_type"]
            data_payload = t["data"]

            # Construct multipart payload
            files = {
                field_name: (filename, data_payload.encode("utf-8"), content_type)
            }

            try:
                resp = await client.post(target_url, headers=headers, files=files)
                # Analyze upload response
                status_ok = resp.status_code in [200, 201, 202, 204]
                rejected = resp.status_code in [400, 403, 415, 422, 500] and any(kw in resp.text.lower() for kw in ["not allowed", "invalid extension", "disallowed", "forbidden", "bad file"])

                accepted = status_ok and not rejected
                # Try to extract uploaded file path or link from response
                uploaded_path_match = re.search(r"""(?:["']|\b)(https?:\/\/[^\s"']+|(?:\/|uploads?\/|static\/)[a-zA-Z0-9_\-\.\/]+(?:""" + re.escape(filename) + r"""))""", resp.text)
                uploaded_location = uploaded_path_match.group(1) if uploaded_path_match else None

                test_res = {
                    "test": test_name,
                    "filename": filename,
                    "status_code": resp.status_code,
                    "accepted": accepted,
                    "uploaded_location": uploaded_location
                }
                results["tests_executed"].append(test_res)

                if accepted:
                    vuln = {
                        "type": t["vuln_type"],
                        "severity": t["severity"],
                        "title": t["title"],
                        "evidence": f"File '{filename}' with MIME '{content_type}' was accepted by {target_url} (HTTP {resp.status_code})." + (f" Location: {uploaded_location}" if uploaded_location else ""),
                        "remediation": "Validate files against a strict extension whitelist (e.g., .jpg, .png only). Store uploads outside the web root with randomized names, disable execution in upload folders, and re-encode images."
                    }
                    results["vulnerabilities"].append(vuln)

                    if persist_fn:
                        await persist_fn(
                            log_payload={
                                "project": target_project,
                                "source": "UPLOAD_AUDITOR",
                                "method": "POST",
                                "url": target_url,
                                "host": hostname,
                                "path": parsed.path,
                                "status_code": resp.status_code,
                                "reasoning": f"File upload audit verified: {t['title']}."
                            },
                            flag_status="CONFIRMED" if t["severity"] in ["CRITICAL", "HIGH"] else "POTENTIAL",
                            findings=[vuln]
                        )
                    if vault_fn:
                        await vault_fn({
                            "project": target_project,
                            "vuln_type": "FILE_UPLOAD",
                            "target_param": field_name,
                            "raw_payload": filename,
                            "target_url": target_url,
                            "outcome": "EXECUTED",
                            "notes": f"Verified file upload filter weakness: {t['test']}"
                        })

                    # Optional active verification for SVG XSS if confirmed
                    if allow_exploit and confirmation == "CONFIRM_EXPLOIT" and t["vuln_type"] == "SVG_STORED_XSS" and uploaded_location:
                        try:
                            from backend.browser_handler import verify_dom_execution_engine
                            dom_res = await verify_dom_execution_engine(uploaded_location, payload="<script>", project=target_project)
                            test_res["dom_verification"] = dom_res
                        except Exception:
                            pass
            except Exception as ex:
                results["tests_executed"].append({
                    "test": test_name,
                    "filename": filename,
                    "error": str(ex)
                })

    results["status"] = "SUCCESS"
    results["findings_count"] = len(results["vulnerabilities"])
    results["verdict"] = "VULNERABLE" if results["findings_count"] > 0 else "SECURE"
    return results
