"""
Proxsynth MCP - Automated CI/CD & API Security Auditor
Performs automated compliance audits on proxy-captured web and API traffic against OWASP API Security Top 10.
Generates automated security scorecards, letter grades (A+ to F), and CI-ready Markdown/JSON compliance reports.
"""

import re
import json
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set

from backend.database import SessionLocal, HttpLog, Finding, Project

# Sensitive data leak regexes
_LEAK_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", "CRITICAL"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub Personal Access Token", "CRITICAL"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "Stripe Live Secret Key", "CRITICAL"),
    (re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"), "JWT Token in Response Body", "MEDIUM"),
    (re.compile(r"Traceback \(most recent call last\):|NullPointerException|Fatal error:|syntax error at or near", re.IGNORECASE), "Stack Trace / Database Error Disclosure", "HIGH"),
    (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "Internal RFC1918 IP Address Disclosure", "LOW")
]


def run_security_audit_suite(
    project: Optional[str] = None,
    min_severity: str = "LOW"
) -> Dict[str, Any]:
    """
    Evaluates proxy-captured traffic against OWASP API Security Top 10 hygiene rules.
    Returns calculated security scorecard, letter grade, and list of violations.
    """
    db = SessionLocal()
    try:
        q = db.query(HttpLog)
        if project and project.strip().lower() not in ["all", "*", "any", "global"]:
            proj = project.strip().lower()
            q = q.filter(HttpLog.project == proj)

        logs = q.all()
        if not logs:
            return {
                "project": project or "all",
                "total_audited_requests": 0,
                "score": 100,
                "grade": "A+",
                "violations_count": 0,
                "violations": [],
                "summary": "No traffic captured yet. Security audit clean."
            }

        violations: List[Dict[str, Any]] = []
        seen_violations: Set[str] = set()

        severity_penalties = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3
        }

        total_penalty = 0

        for l in logs:
            url = l.url or ""
            res_body = l.response_body or ""
            status = l.status_code or 0

            # Parse headers
            res_headers: Dict[str, str] = {}
            try:
                if l.response_headers:
                    raw_h = json.loads(l.response_headers)
                    res_headers = {k.lower(): str(v) for k, v in raw_h.items()}
            except Exception:
                pass

            # Only audit successful or application responses
            if status >= 200 and status < 500:
                # 1. Check Missing Security Headers
                sec_headers = {
                    "strict-transport-security": ("Missing HSTS Header", "MEDIUM", "Forces HTTPS encrypted transport."),
                    "x-content-type-options": ("Missing X-Content-Type-Options Header", "LOW", "Prevents MIME sniffing attacks (set nosniff)."),
                    "x-frame-options": ("Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)", "MEDIUM", "Prevents UI redressing / clickjacking.")
                }

                # Only require HSTS on HTTPS
                is_https = url.lower().startswith("https://")
                for sh_k, (sh_title, sh_sev, sh_desc) in sec_headers.items():
                    if sh_k == "strict-transport-security" and not is_https:
                        continue
                    if sh_k not in res_headers:
                        v_key = f"{l.host}:{sh_k}"
                        if v_key not in seen_violations:
                            seen_violations.add(v_key)
                            violations.append({
                                "rule": sh_title,
                                "severity": sh_sev,
                                "category": "Security Misconfiguration",
                                "target": l.host or url,
                                "description": sh_desc,
                                "remediation": f"Configure {sh_k} in web server or reverse proxy headers."
                            })
                            total_penalty += severity_penalties.get(sh_sev, 5)

                # 2. Check CORS Misconfiguration
                acao = res_headers.get("access-control-allow-origin", "")
                acac = res_headers.get("access-control-allow-credentials", "").lower()
                if acao == "*" and acac == "true":
                    v_key = f"{l.host}:cors_wildcard_cred"
                    if v_key not in seen_violations:
                        seen_violations.add(v_key)
                        violations.append({
                            "rule": "CORS Wildcard with Credentials Allowed",
                            "severity": "HIGH",
                            "category": "Broken Access Control",
                            "target": url,
                            "description": "Server responds with Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true, exposing private user data across origins.",
                            "remediation": "Never use wildcard origin when credentials are supported. Whitelist explicit trusted origins."
                        })
                        total_penalty += severity_penalties["HIGH"]

                # 3. Check Cookie Security Flags
                set_cookie = res_headers.get("set-cookie", "")
                if set_cookie:
                    cookies_lower = set_cookie.lower()
                    if "httponly" not in cookies_lower:
                        v_key = f"{l.host}:cookie_no_httponly"
                        if v_key not in seen_violations:
                            seen_violations.add(v_key)
                            violations.append({
                                "rule": "Insecure Cookie: Missing HttpOnly Flag",
                                "severity": "MEDIUM",
                                "category": "Sensitive Data Exposure",
                                "target": l.host or url,
                                "description": "Session or authentication cookies lack the HttpOnly flag, allowing XSS scripts to steal them via document.cookie.",
                                "remediation": "Add HttpOnly to all sensitive Set-Cookie headers."
                            })
                            total_penalty += severity_penalties["MEDIUM"]
                    if is_https and "secure" not in cookies_lower:
                        v_key = f"{l.host}:cookie_no_secure"
                        if v_key not in seen_violations:
                            seen_violations.add(v_key)
                            violations.append({
                                "rule": "Insecure Cookie: Missing Secure Flag",
                                "severity": "MEDIUM",
                                "category": "Sensitive Data Exposure",
                                "target": l.host or url,
                                "description": "Cookies served over HTTPS lack the Secure flag, allowing transmission over plaintext HTTP.",
                                "remediation": "Add Secure attribute to Set-Cookie headers on HTTPS endpoints."
                            })
                            total_penalty += severity_penalties["MEDIUM"]

            # 4. Check Query Parameter Credentials Exposure
            if "?" in url:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    for qk in qs.keys():
                        if any(s in qk.lower() for s in ["password", "token", "apikey", "secret", "bearer", "auth"]):
                            v_key = f"{l.host}:cred_in_query:{qk}"
                            if v_key not in seen_violations:
                                seen_violations.add(v_key)
                                violations.append({
                                    "rule": f"Sensitive Credential in URL Query Parameter ({qk})",
                                    "severity": "HIGH",
                                    "category": "Credential Exposure",
                                    "target": url.split("?")[0],
                                    "description": f"Sensitive parameter '{qk}' is transmitted in URL query strings. It gets logged in web server logs, browser histories, and referrer headers.",
                                    "remediation": "Pass credentials via Authorization headers or POST request bodies."
                                })
                                total_penalty += severity_penalties["HIGH"]
                except Exception:
                    pass

            # 5. Check Sensitive Data Leakage in Response Body
            if res_body and len(res_body) > 20:
                for pat, leak_name, leak_sev in _LEAK_PATTERNS:
                    if pat.search(res_body):
                        v_key = f"{l.host}:leak:{leak_name}"
                        if v_key not in seen_violations:
                            seen_violations.add(v_key)
                            violations.append({
                                "rule": f"Information Leakage: {leak_name}",
                                "severity": leak_sev,
                                "category": "Information Disclosure",
                                "target": url,
                                "description": f"Potential {leak_name} matched in HTTP response body.",
                                "remediation": "Sanitize API responses to prevent leakage of internal secrets, stack traces, and keys."
                            })
                            total_penalty += severity_penalties.get(leak_sev, 10)

        # Calculate final score
        final_score = max(0, min(100, 100 - total_penalty))
        if final_score >= 95: grade = "A+"
        elif final_score >= 85: grade = "A"
        elif final_score >= 75: grade = "B"
        elif final_score >= 65: grade = "C"
        elif final_score >= 50: grade = "D"
        else: grade = "F"

        # Severity breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in violations:
            sev = v.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1

        return {
            "project": project or "all",
            "total_audited_requests": len(logs),
            "score": final_score,
            "grade": grade,
            "severity_counts": counts,
            "total_violations": len(violations),
            "violations": violations
        }
    finally:
        db.close()


def generate_sarif_report(project: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates standard SARIF v2.1.0 static/dynamic analysis output for GitHub Code Scanning,
    GitLab CI, DefectDojo, and enterprise vulnerability management platforms.
    """
    res = run_security_audit_suite(project=project)
    violations = res.get("violations", [])

    rules_dict: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note"
    }

    score_map = {
        "CRITICAL": "9.0",
        "HIGH": "7.5",
        "MEDIUM": "5.0",
        "LOW": "2.5",
        "INFO": "1.0"
    }

    for v in violations:
        rule_name = v.get("rule", "API Security Violation")
        rule_id = re.sub(r'[^a-zA-Z0-9_-]', '-', rule_name.strip().lower())
        rule_id = re.sub(r'-+', '-', rule_id).strip('-')
        if not rule_id:
            rule_id = "proxsynth-api-rule"
        rule_id = f"PROXSYNTH-{rule_id.upper()}"

        sev = v.get("severity", "MEDIUM").upper()
        sarif_level = level_map.get(sev, "warning")

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": v.get("description", rule_name)},
                "help": {
                    "text": f"Remediation: {v.get('remediation', 'Follow OWASP security recommendations.')}",
                    "markdown": f"**Category**: {v.get('category', 'OWASP API Security')}\n\n**Remediation**:\n{v.get('remediation', '')}"
                },
                "properties": {
                    "category": v.get("category", "OWASP API Security"),
                    "security-severity": score_map.get(sev, "5.0")
                }
            }

        target_uri = v.get("target", "") or "https://api.local"
        if not (target_uri.startswith("http://") or target_uri.startswith("https://")):
            target_uri = f"https://{target_uri}"

        sarif_results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": f"[{sev}] {rule_name} on {v.get('target', '')}: {v.get('description', '')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_uri
                        }
                    }
                }
            ],
            "properties": {
                "severity": sev,
                "remediation": v.get("remediation", ""),
                "category": v.get("category", "Security")
            }
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Proxsynth",
                        "version": "0.1.0-beta",
                        "informationUri": "https://github.com/angganovryanputra/proxynth",
                        "rules": list(rules_dict.values())
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                ],
                "results": sarif_results
            }
        ]
    }


def generate_audit_ci_report(
    project: Optional[str] = None,
    output_format: str = "markdown"
) -> str:
    """
    Generates a publication-grade Markdown, JSON, or SARIF v2.1.0 compliance report for CI/CD pipelines.
    """
    fmt = output_format.lower().strip()
    if fmt == "sarif":
        return json.dumps(generate_sarif_report(project=project), indent=2)

    res = run_security_audit_suite(project=project)
    if fmt == "json":
        return json.dumps(res, indent=2)

    # Markdown format
    grade_emoji = "🟢" if res["score"] >= 80 else ("🟡" if res["score"] >= 65 else "🔴")
    lines = [
        f"# 🛡️ Proxsynth Automated Security Audit Report",
        f"**Workspace**: `{res['project']}` | **Audited At**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"",
        f"### {grade_emoji} Overall Security Score: **{res['score']} / 100** (Grade: **{res['grade']}**)",
        f"- **Audited Requests**: {res['total_audited_requests']}",
        f"- **Total Violations**: {res['total_violations']} "
        f"(Critical: {res['severity_counts']['CRITICAL']}, "
        f"High: {res['severity_counts']['HIGH']}, "
        f"Medium: {res['severity_counts']['MEDIUM']}, "
        f"Low: {res['severity_counts']['LOW']})",
        f"",
        f"---",
        f"### 📋 Audit Findings & Violations",
        f""
    ]

    if not res["violations"]:
        lines.append("✓ No OWASP API security policy violations detected. Security hygiene is optimal!")
    else:
        for idx, v in enumerate(res["violations"], 1):
            sev_badge = f"**[{v['severity']}]**"
            lines.append(f"#### {idx}. {sev_badge} {v['rule']}")
            lines.append(f"- **Category**: {v.get('category', 'Security')}")
            lines.append(f"- **Target**: `{v.get('target', '')}`")
            lines.append(f"- **Description**: {v.get('description', '')}")
            lines.append(f"- **Remediation**: {v.get('remediation', '')}")
            lines.append("")

    return "\n".join(lines)
