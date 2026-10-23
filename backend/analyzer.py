"""
Proxsynth MCP - Dual-Track Triage Engine
Analyzes HTTP/HTTPS traffic to classify deterministic vs probabilistic security findings.
"""

import re
import urllib.parse
from typing import Tuple, List, Dict, Any

# ==============================================================================
# Track 1: Deterministic Signatures (CONFIRMED FINDINGS)
# ==============================================================================

DB_ERROR_PATTERNS = [
    {
        "name": "MySQL Syntax / Error Leak",
        "pattern": re.compile(r"(?:SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlException|check the manual that corresponds to your MySQL server version)", re.IGNORECASE),
        "severity": "HIGH",
        "category": "SQL Injection & Database Error Leak",
        "remediation": "Disable verbose database error messages in production. Use parameterized queries/prepared statements."
    },
    {
        "name": "PostgreSQL Syntax / Query Error",
        "pattern": re.compile(r"(?:PostgreSQL.*ERROR|pg_query\(\):.*Query failed|PSQLException|org\.postgresql\.util\.PSQLException)", re.IGNORECASE),
        "severity": "HIGH",
        "category": "SQL Injection & Database Error Leak",
        "remediation": "Ensure generic error handling is configured and database exception traces are never returned to clients."
    },
    {
        "name": "Oracle Database Error",
        "pattern": re.compile(r"(?:ORA-[0-9]{5}|Oracle error|Oracle.*Driver)", re.IGNORECASE),
        "severity": "HIGH",
        "category": "SQL Injection & Database Error Leak",
        "remediation": "Intercept database exceptions at the service layer and use prepared statements."
    },
    {
        "name": "SQLite Driver Exception",
        "pattern": re.compile(r"(?:SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|unrecognized token|near \".*\": syntax error)", re.IGNORECASE),
        "severity": "HIGH",
        "category": "SQL Injection & Database Error Leak",
        "remediation": "Sanitize inputs and ensure SQLite queries utilize parameterized query bindings."
    },
    {
        "name": "Microsoft SQL Server Error",
        "pattern": re.compile(r"(?:Driver.*SQL Server|OLE DB.*SQL Server|Unclosed quotation mark before the character string|SqlException)", re.IGNORECASE),
        "severity": "HIGH",
        "category": "SQL Injection & Database Error Leak",
        "remediation": "Use stored procedures or parameterized commands, and suppress detailed database error messages."
    }
]

SECRET_LEAK_PATTERNS = [
    {
        "name": "AWS Access Key ID Exposure",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": "CRITICAL",
        "category": "Cloud Credential Exposure",
        "remediation": "Immediately revoke and rotate the exposed AWS IAM access key. Store secrets in AWS Secrets Manager or KMS."
    },
    {
        "name": "Private Cryptographic Key Exposure",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "severity": "CRITICAL",
        "category": "Private Key Exposure",
        "remediation": "Revoke the private key immediately. Never expose server private certificates or SSH keys in response bodies."
    },
    {
        "name": "Environment Variable / Secret Leak",
        "pattern": re.compile(r"(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY|DATABASE_URL|API_KEY|APP_SECRET)\s*=\s*['\"]?[^\s'\"]+", re.IGNORECASE),
        "severity": "CRITICAL",
        "category": "Secret & Config Exposure",
        "remediation": "Remove environment variable printouts or configuration dumps from public HTTP response handlers."
    },
    {
        "name": "GitHub Personal Access Token Exposure",
        "pattern": re.compile(r"\b(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
        "severity": "CRITICAL",
        "category": "API Token Exposure",
        "remediation": "Revoke token via GitHub Security settings and implement strict repository secret scanning."
    },
    {
        "name": "Exposed Password / Key Field in JSON",
        "pattern": re.compile(r"\"(?:password|passwd|db_password|jwt_secret|private_key|app_secret)\"\s*:\s*\"(?![\*xX]{3,})([^\"\r\n]{4,})\"", re.IGNORECASE),
        "severity": "HIGH",
        "category": "Credential & Secret Exposure",
        "remediation": "Never return raw authentication credentials or secret keys in client-facing API responses."
    }
]

SERVER_EXPOSURE_PATTERNS = [
    {
        "name": "Django Debug Traceback Exposure",
        "pattern": re.compile(r"(?:You're seeing this error because you have DEBUG = True in your Django settings file|Traceback \(most recent call last\):.*django)", re.IGNORECASE | re.DOTALL),
        "severity": "HIGH",
        "category": "Framework Debug Mode Enabled",
        "remediation": "Set `DEBUG = False` in Django settings.py and specify standard 404/500 handler templates."
    },
    {
        "name": "Spring Boot Whitelabel Error Page",
        "pattern": re.compile(r"(?:Whitelabel Error Page|This application has no explicit mapping for /error)", re.IGNORECASE),
        "severity": "MEDIUM",
        "category": "Framework Error Disclosure",
        "remediation": "Configure custom error controller in Spring Boot and disable default whitelabel stack traces."
    },
    {
        "name": "PHP Fatal Error / Stack Trace",
        "pattern": re.compile(r"(?:Fatal error:.*in\s+.*\.php\s+on\s+line\s+\d+|Stack trace:.*#0)", re.IGNORECASE),
        "severity": "HIGH",
        "category": "Server Script Error Disclosure",
        "remediation": "Set `display_errors = Off` in php.ini and log server errors to secure internal syslog."
    },
    {
        "name": "Werkzeug / Flask Debugger Traceback",
        "pattern": re.compile(r"(?:Traceback \(most recent call last\):|The debugger caught an exception in your WSGI application)", re.IGNORECASE),
        "severity": "HIGH",
        "category": "Interactive Debugger Exposure",
        "remediation": "Disable Werkzeug interactive debugger in production and return sanitized error responses."
    }
]


LFI_PATTERNS = [
    {
        "name": "Local File Inclusion — Linux passwd Disclosure",
        "pattern": re.compile(r"root:[x*]?:0:0:[^:]*:[^:]*:(?:/[a-zA-Z0-9_.-]+)+", re.MULTILINE),
        "severity": "CRITICAL",
        "category": "Path Traversal & Local File Inclusion",
        "remediation": "Do not pass user-controlled input to file path operations. Use path canonicalization and whitelisting."
    },
    {
        "name": "Local File Inclusion — Linux shadow Disclosure",
        "pattern": re.compile(r"root:\$(?:1|2[axy]?|5|6|y)\$[a-zA-Z0-9./]+:[0-9]*:[0-9]*:", re.MULTILINE),
        "severity": "CRITICAL",
        "category": "Path Traversal & Local File Inclusion",
        "remediation": "Ensure system files cannot be accessed via application endpoints. Store data outside the web root."
    },
    {
        "name": "Local File Inclusion — Windows INI / System File Disclosure",
        "pattern": re.compile(r"\[(?:fonts|extensions|mci extensions|files|boot loader)\]", re.IGNORECASE),
        "severity": "CRITICAL",
        "category": "Path Traversal & Local File Inclusion",
        "remediation": "Validate and sanitize file path parameters. Prevent directory traversal characters (../, ..\\)."
    },
    {
        "name": "Directory Listing / Directory Indexing Exposed",
        "pattern": re.compile(r"(?:<title>Index of\s+/|Index of\s+/[a-zA-Z0-9_./-]*\s+<hr>|Directory listing for\s+/)", re.IGNORECASE),
        "severity": "MEDIUM",
        "category": "Information Disclosure",
        "remediation": "Disable directory browsing and auto-indexing in web server configuration."
    }
]


# ==============================================================================
# Dual-Track Analyzer Logic
# ==============================================================================

def analyze_traffic(log_entry) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Analyzes an HttpLog instance and returns:
    (flag_status: "CLEAN" | "POTENTIAL" | "CONFIRMED", findings: list of dicts)
    """
    findings: List[Dict[str, Any]] = []
    response_body = log_entry.response_body or ""
    # Cap regex inspection to first 250,000 characters to prevent regex stalling on multi-MB downloads
    scan_body = response_body if len(response_body) <= 250000 else response_body[:250000]
    status_code = log_entry.status_code or 0
    url = log_entry.url or ""
    request_body = log_entry.request_body or ""

    # --------------------------------------------------------------------------
    # TRACK 1: CONFIRMED FINDINGS (Deterministic Signatures)
    # --------------------------------------------------------------------------

    # 1. Database Error Signatures
    for db_check in DB_ERROR_PATTERNS:
        match = db_check["pattern"].search(scan_body)
        if match:
            snippet = scan_body[max(0, match.start() - 40): min(len(scan_body), match.end() + 80)]
            findings.append({
                "title": db_check["name"],
                "severity": db_check["severity"],
                "category": db_check["category"],
                "evidence": snippet.strip(),
                "description": f"Deterministic database error signature detected in HTTP response body matching pattern: {db_check['pattern'].pattern}",
                "remediation": db_check["remediation"]
            })

    # 2. Secret & Credential Leaks
    for sec_check in SECRET_LEAK_PATTERNS:
        match = sec_check["pattern"].search(scan_body)
        if match:
            # Mask sensitive token in evidence snippet
            matched_text = match.group(0)
            masked = matched_text[:4] + ("*" * (len(matched_text) - 8)) + matched_text[-4:] if len(matched_text) > 8 else "***REDACTED***"
            findings.append({
                "title": sec_check["name"],
                "severity": sec_check["severity"],
                "category": sec_check["category"],
                "evidence": f"Matched token: {masked}",
                "description": f"Deterministic secret/credential pattern detected in response: {sec_check['name']}.",
                "remediation": sec_check["remediation"]
            })

    # 3. Critical Server Framework Exposure
    for srv_check in SERVER_EXPOSURE_PATTERNS:
        match = srv_check["pattern"].search(scan_body)
        if match:
            snippet = scan_body[max(0, match.start() - 20): min(len(scan_body), match.end() + 100)]
            findings.append({
                "title": srv_check["name"],
                "severity": srv_check["severity"],
                "category": srv_check["category"],
                "evidence": snippet.strip(),
                "description": f"Detailed server debug traceback or runtime crash exposed directly to client.",
                "remediation": srv_check["remediation"]
            })

    # 4. SQL Injection Authentication Bypass (Successful Login Bypass with SQLi Payload)
    path_lower = (log_entry.path or "").lower()
    is_auth_endpoint = any(kw in path_lower for kw in [
        "login", "signin", "auth", "token", "session", "oauth", "authenticate", "user/login"
    ])
    if is_auth_endpoint and status_code in [200, 201, 204]:
        req_full = ((log_entry.request_body or "") + " " + (log_entry.url or "")).lower()
        sqli_patterns = [
            r"['\"]\s*(?:or|\|\|)\s*['\"]?[0-9a-z_]+['\"]?\s*=\s*['\"]?[0-9a-z_]+",
            r"['\"]\s*(?:or|\|\|)\s*true\b",
            r"['\"]\s*(?:or|and)\s+[0-9]+\s*=\s*[0-9]+",
            r"['\"]\s*--",
            r"['\"]\s*#",
            r"['\"]\s*\/\*",
            r"admin['\"]?\s*--",
            r"admin['\"]?\s*#",
            r"\bunion\s+(?:all\s+)?select\b"
        ]
        sqli_match_str = None
        for pat in sqli_patterns:
            m = re.search(pat, req_full, re.IGNORECASE)
            if m:
                sqli_match_str = m.group(0)
                break

        if sqli_match_str:
            jwt_match = re.search(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", scan_body)
            has_token_json = any(
                tk in scan_body.lower() for tk in [
                    '"token"', '"accesstoken"', '"jwt"', '"bid"', '"authentication"',
                    '"auth_token"', '"sessionid"', '"session_id"', '"bearer"'
                ]
            )
            has_auth_cookie = False
            if log_entry.response_headers:
                try:
                    import json as _json
                    res_hdrs = _json.loads(log_entry.response_headers) if isinstance(log_entry.response_headers, str) else log_entry.response_headers
                    res_hdrs_lower = {str(k).lower(): str(v).lower() for k, v in res_hdrs.items()}
                    set_cookie = res_hdrs_lower.get("set-cookie", "")
                    has_auth_cookie = any(c in set_cookie for c in ["token", "session", "jwt", "auth", "connect.sid"])
                except Exception:
                    pass

            has_admin_user = any(u in scan_body.lower() for u in ['"email":"admin', '"email": "admin', '"role":"admin', '"role": "admin', '"admin@'])

            if jwt_match or has_token_json or has_auth_cookie or has_admin_user:
                evidence_token = ""
                if jwt_match:
                    evidence_token = f"JWT: {jwt_match.group(0)[:35]}..."
                elif has_token_json:
                    evidence_token = "Auth token issued in JSON response"
                elif has_auth_cookie:
                    evidence_token = "Session cookie issued in Set-Cookie header"
                elif has_admin_user:
                    evidence_token = "Admin user profile returned in response body"

                findings.append({
                    "title": "SQL Injection — Authentication Bypass",
                    "severity": "CRITICAL",
                    "category": "SQL Injection",
                    "evidence": f"Injected SQLi pattern '{sqli_match_str}' into auth endpoint ({log_entry.path}) -> HTTP {status_code} with {evidence_token}",
                    "description": "Authentication endpoint permitted complete login bypass when supplied with boolean-based SQL injection payload (' OR 1=1--), issuing a valid administrative session token without valid credentials.",
                    "remediation": "Enforce strict parameterized queries (prepared statements) or ORM abstraction for all authentication query execution. Never concatenate untrusted user input directly into SQL statements."
                })

    # 5. Local File Inclusion & Traversal Signatures
    for lfi_check in LFI_PATTERNS:
        match = lfi_check["pattern"].search(scan_body)
        if match:
            snippet = scan_body[max(0, match.start() - 30): min(len(scan_body), match.end() + 70)]
            findings.append({
                "title": lfi_check["name"],
                "severity": lfi_check["severity"],
                "category": lfi_check["category"],
                "evidence": snippet.strip(),
                "description": f"Local file inclusion or traversal signature confirmed in HTTP response body matching pattern: {lfi_check['pattern'].pattern}",
                "remediation": lfi_check["remediation"]
            })

    # If any Track 1 signature matched, we have confirmed findings
    if findings:
        return "CONFIRMED", findings

    # --------------------------------------------------------------------------
    # TRACK 2: POTENTIAL FINDINGS (Heuristics & Anomalies)
    # --------------------------------------------------------------------------

    # 1. Input Reflection Check (GET query parameters & POST form fields)
    COMMON_NON_INJECTION_WORDS = {
        "true", "false", "null", "none", "json", "text", "html", "user", "admin", "test",
        "demo", "page", "limit", "offset", "sort", "order", "desc", "asc", "view", "edit"
    }

    potential_inputs = []
    try:
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        for param, vals in query_params.items():
            for v in vals:
                clean_v = v.strip()
                if len(clean_v) >= 4 and clean_v.lower() not in COMMON_NON_INJECTION_WORDS:
                    potential_inputs.append((f"Query param '{param}'", clean_v))
    except Exception:
        pass

    if request_body and len(request_body) < 100000:
        # Check JSON request payload fields
        try:
            import json as _json
            body_json = _json.loads(request_body)
            def _extract_json_strings(obj, prefix=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        _extract_json_strings(v, f"{prefix}.{k}" if prefix else str(k))
                elif isinstance(obj, list):
                    for idx, v in enumerate(obj):
                        _extract_json_strings(v, f"{prefix}[{idx}]")
                elif isinstance(obj, (str, int, float)):
                    clean_v = str(obj).strip()
                    if len(clean_v) >= 4 and clean_v.lower() not in COMMON_NON_INJECTION_WORDS:
                        potential_inputs.append((f"JSON field '{prefix}'", clean_v))
            _extract_json_strings(body_json)
        except Exception:
            pass

        # Check URL-encoded form body fields
        try:
            form_params = urllib.parse.parse_qs(request_body)
            for param, vals in form_params.items():
                for v in vals:
                    clean_v = v.strip()
                    if len(clean_v) >= 4 and clean_v.lower() not in COMMON_NON_INJECTION_WORDS:
                        potential_inputs.append((f"Body field '{param}'", clean_v))
        except Exception:
            pass

    for source_label, input_val in potential_inputs:
        if input_val in response_body:
            is_suspicious_char = any(c in input_val for c in ["<", ">", "'", "\"", "(", ")", ";", "{", "}", "/", "script", "alert"])
            if is_suspicious_char or len(input_val) >= 7:
                severity = "MEDIUM" if is_suspicious_char else "LOW"
                idx = response_body.find(input_val)
                snippet = response_body[max(0, idx - 40): min(len(response_body), idx + len(input_val) + 40)]
                findings.append({
                    "title": f"Raw Input Reflection ({source_label})",
                    "severity": severity,
                    "category": "Input Reflection & Potential XSS",
                    "evidence": snippet.strip(),
                    "description": f"Input value from {source_label} is reflected unencoded or verbatim in the response body.",
                    "remediation": "Apply contextual output encoding (e.g., HTML entity encoding, JSON escaping) before rendering user-supplied values."
                })
                break

    # 2. CORS Misconfiguration Check
    try:
        import json as _json
        res_headers = _json.loads(log_entry.response_headers) if log_entry.response_headers else {}
    except Exception:
        res_headers = {}

    res_headers_lower = {str(k).lower(): str(v) for k, v in res_headers.items()}
    cors_origin = res_headers_lower.get("access-control-allow-origin", "")
    cors_creds = res_headers_lower.get("access-control-allow-credentials", "")

    if cors_origin == "*" and cors_creds.lower() == "true":
        findings.append({
            "title": "Insecure CORS: Wildcard Origin with Credentials",
            "severity": "HIGH",
            "category": "CORS Misconfiguration",
            "evidence": f"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
            "description": "Wildcard origin (*) combined with credentials allowed allows unauthorized cross-origin data extraction.",
            "remediation": "Do not specify wildcard '*' when Access-Control-Allow-Credentials is true. Whitelist explicit trusted origin domains."
        })

    # 3. Server Software & Detailed Version Disclosure
    server_hdr = res_headers_lower.get("server", "")
    powered_by = res_headers_lower.get("x-powered-by", "")

    if re.search(r"(?:Apache/[0-9.]+|nginx/[0-9.]+|Microsoft-IIS/[0-9.]+|PHP/[0-9.]+|OpenSSL/[0-9.]+)", server_hdr, re.I):
        findings.append({
            "title": "Server Software & Version Disclosure (Server Header)",
            "severity": "LOW",
            "category": "Information Disclosure",
            "evidence": f"Server: {server_hdr}",
            "description": f"Target reveals detailed server software version ({server_hdr}), assisting attackers in identifying known CVEs.",
            "remediation": "Suppress detailed version banners in web server configuration (e.g. `ServerTokens Prod` or `server_tokens off`)."
        })
    elif re.search(r"(?:PHP/[0-9.]+|ASP\.NET|Express|Next\.js)", powered_by, re.I):
        findings.append({
            "title": "Framework Version Disclosure (X-Powered-By Header)",
            "severity": "LOW",
            "category": "Information Disclosure",
            "evidence": f"X-Powered-By: {powered_by}",
            "description": f"Target reveals internal technology stack ({powered_by}).",
            "remediation": "Disable `X-Powered-By` header in application configuration (e.g. `expose_php = Off`)."
        })

    # 4. Administrative & Sensitive Configuration Endpoint Disclosure
    path_lower = (log_entry.path or "").lower()
    is_admin_config_path = any(
        re.search(p, path_lower) for p in [
            r"/(?:rest/admin/|api/admin/|admin/|actuator/|\.env|\.git/|api/v[0-9]+/admin|manage/|management/|debug/)",
            r"(?:application-configuration|application-config|app-config|server-status|swagger\.json|openapi\.json|actuator/env|actuator/health)"
        ]
    )
    if is_admin_config_path and status_code in [200, 206] and len(scan_body) > 60:
        config_keywords = ["config", "settings", "secret", "database", "version", "port", "key", "host", "token", "auth", "env", "password"]
        matched_kw = [kw for kw in config_keywords if f'"{kw}"' in scan_body.lower() or f"'{kw}'" in scan_body.lower() or f"{kw}:" in scan_body.lower()]
        if len(matched_kw) >= 2 or "application-configuration" in path_lower:
            snippet = scan_body[:250].strip()
            findings.append({
                "title": "Administrative Endpoint & Configuration Disclosure",
                "severity": "HIGH",
                "category": "Sensitive Configuration Disclosure",
                "evidence": f"HTTP {status_code} on {log_entry.path} returned {len(scan_body)} bytes with keys {matched_kw[:4]}: {snippet}...",
                "description": f"Internal administrative or configuration endpoint ({log_entry.path}) returned accessible configuration data to client requests.",
                "remediation": "Restrict administrative endpoints with strict role-based access control (RBAC) and network boundaries."
            })

    # 5. Verbose Authentication Error (User Enumeration Hint)
    user_enum_pattern = re.compile(
        r"(?:user\s+(?:not\s+found|does\s+not\s+exist)|username\s+not\s+found|invalid\s+password|incorrect\s+password|password\s+(?:is\s+)?incorrect|password\s+does\s+not\s+match|account\s+does\s+not\s+exist|email\s+(?:not\s+registered|is\s+not\s+valid|already\s+exists))",
        re.IGNORECASE
    )
    user_enum_match = user_enum_pattern.search(scan_body)
    if user_enum_match and (status_code in [401, 403, 400, 422, 200]) and any(k in path_lower for k in ["login", "signin", "auth", "user", "password", "register", "signup"]):
        matched_str = user_enum_match.group(0)
        findings.append({
            "title": "Verbose Authentication Error (User Enumeration Hint)",
            "severity": "MEDIUM",
            "category": "User Enumeration",
            "evidence": f"Response contains: '{matched_str}'",
            "description": f"Target returns differential authentication responses ({matched_str}), enabling attackers to enumerate valid usernames or emails.",
            "remediation": "Return generic error responses (e.g. 'Invalid credentials') regardless of whether the account exists."
        })

    # 4. Status Code Anomalies (e.g. 500 Internal Server Error, 503 Service Unavailable)
    if status_code >= 500:
        req_context = (url + " " + request_body + " " + (log_entry.reasoning or "")).lower()
        is_sqli_probe = any(k in req_context for k in ["select", "union", "sleep(", "benchmark(", "or '1'='1", "or 1=1", "where", "from", "--", "/*", "admin'"])
        is_xss_probe = any(k in req_context for k in ["<script", "javascript:", "onerror=", "onload=", "alert("])
        is_cmd_probe = any(k in req_context for k in [";cat ", "|whoami", "|id", "&&whoami", "$(whoami)", "`id`"])

        if is_sqli_probe:
            findings.append({
                "title": f"Potential SQLi Triggered Server Fault (HTTP {status_code})",
                "severity": "HIGH",
                "category": "Potential SQL Injection",
                "evidence": f"HTTP {status_code} triggered during SQLi injection probe on {log_entry.path}",
                "description": f"The target returned an unhandled server error status ({status_code}) in response to SQL injection probes, indicating database syntax breakdown or unhandled query exceptions.",
                "remediation": "Inspect backend database queries and enforce strict prepared statements."
            })
        elif is_xss_probe:
            findings.append({
                "title": f"Potential XSS/Parser Fault (HTTP {status_code})",
                "severity": "MEDIUM",
                "category": "Parser Anomaly",
                "evidence": f"HTTP {status_code} triggered during XSS probe on {log_entry.path}",
                "description": f"The target returned an unhandled server error status ({status_code}) in response to XSS payload probes.",
                "remediation": "Ensure server-side parsers safely handle unexpected HTML/JS markup."
            })
        elif is_cmd_probe:
            findings.append({
                "title": f"Potential Command Injection Server Fault (HTTP {status_code})",
                "severity": "HIGH",
                "category": "Potential Command Injection",
                "evidence": f"HTTP {status_code} triggered during command injection probe on {log_entry.path}",
                "description": f"The target returned an unhandled server error status ({status_code}) during command delimiter probing.",
                "remediation": "Eliminate shell execution wrappers and sanitize user input."
            })
        else:
            findings.append({
                "title": f"Server Anomaly (HTTP {status_code} Internal Error)",
                "severity": "MEDIUM",
                "category": "Status Code Anomaly",
                "evidence": f"HTTP {status_code} returned for {log_entry.method} {log_entry.path}",
                "description": f"The target returned an unhandled server fault status ({status_code}) which may indicate logic failure or unhandled exception on injected inputs.",
                "remediation": "Audit server logs for unhandled exception paths and enforce robust error boundaries."
            })

    # 5. Insecure Session Cookie Flags Check (Missing HttpOnly, Secure, SameSite)
    set_cookie_raw = res_headers_lower.get("set-cookie", "")
    if set_cookie_raw:
        cookie_lower = set_cookie_raw.lower()
        is_session_cookie = any(k in cookie_lower for k in [
            "session", "sess", "token", "auth", "jwt", "sid", "phpsessid", "jsessionid", "aspsessionid", "connect.sid"
        ])
        if is_session_cookie:
            missing_flags = []
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")

            if missing_flags:
                findings.append({
                    "title": f"Insecure Session Cookie: Missing {', '.join(missing_flags)} Flag(s)",
                    "severity": "MEDIUM" if ("HttpOnly" in missing_flags or "Secure" in missing_flags) else "LOW",
                    "category": "Insecure Cookie Configuration",
                    "evidence": f"Set-Cookie: {set_cookie_raw[:150]}",
                    "description": f"Session cookie is missing recommended security flags ({', '.join(missing_flags)}), increasing susceptibility to XSS token theft or MITM interception.",
                    "remediation": "Set `HttpOnly; Secure; SameSite=Lax` (or Strict) on all sensitive authentication and session cookies."
                })

    # 6. Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)
    content_type = res_headers_lower.get("content-type", "").lower()
    is_html_resp = "text/html" in content_type or "<html" in scan_body[:1000].lower() or "<!doctype html" in scan_body[:1000].lower()
    if is_html_resp and status_code == 200:
        has_xfo = "x-frame-options" in res_headers_lower
        csp_header = res_headers_lower.get("content-security-policy", "").lower()
        has_frame_ancestors = "frame-ancestors" in csp_header
        if not has_xfo and not has_frame_ancestors:
            findings.append({
                "title": "Missing Clickjacking Protection (Missing X-Frame-Options / frame-ancestors)",
                "severity": "LOW",
                "category": "Clickjacking / Missing Security Header",
                "evidence": f"Content-Type: {content_type or 'text/html'} without X-Frame-Options or CSP frame-ancestors",
                "description": "HTML response does not specify X-Frame-Options or Content-Security-Policy frame-ancestors, allowing malicious third-party pages to iframe this application and execute UI redress / clickjacking attacks.",
                "remediation": "Configure web server or application framework to emit `X-Frame-Options: DENY` (or `SAMEORIGIN`) and `Content-Security-Policy: frame-ancestors 'self'`."
            })

    if findings:
        has_high_or_critical = any(f.get("severity") in ["HIGH", "CRITICAL"] for f in findings)
        return ("CONFIRMED" if has_high_or_critical else "POTENTIAL"), findings

    return "CLEAN", []
