"""
Offline, deterministic checks for backend/jwt_tester.py (Task 2: JWT security audit).

Covers:
- Round-trip parse_jwt / forge_jwt / b64url_* on crafted tokens.
- crack_weak_secret recovers a token signed with a known weak secret (default
  wordlist); returns None for a strong random secret.
- generate_jwt_attack_variants produces structurally valid variants for:
    alg:none family, alg-confusion RS256->HS256 (with public_key_pem),
    kid injection (SQLi / path-traversal / command-injection), jku/x5u
    injection, claim escalation / subject swap, and expiry/nbf tampering.

No network calls. audit_jwt_security's HTTP replay path is never invoked.
Run: ./venv/Scripts/python.exe scripts/check_jwt.py
Exits non-zero on any failure.
"""

import os
import sys
import json
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.jwt_tester import (  # noqa: E402
    b64url_decode,
    b64url_encode,
    parse_jwt,
    forge_jwt,
    crack_weak_secret,
    generate_jwt_attack_variants,
    COMMON_JWT_SECRETS,
)

failures = []


def check(name, condition, detail=""):
    if condition:
        print(f"PASS: {name}")
    else:
        msg = f"FAIL: {name}" + (f" ({detail})" if detail else "")
        print(msg)
        failures.append(msg)


# ---------------------------------------------------------------------------
# 1. Round-trip parse_jwt / forge_jwt / b64url_*
# ---------------------------------------------------------------------------

header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "user123", "role": "user", "exp": 1999999999}
secret = "my-test-secret"

token = forge_jwt(header, payload, secret=secret)
check("forge_jwt produces a 3-part token", len(token.split(".")) == 3, token)

parsed = parse_jwt(token)
check("parse_jwt recovers header", parsed["header"] == header, parsed["header"])
check("parse_jwt recovers payload", parsed["payload"] == payload, parsed["payload"])
check(
    "parse_jwt signing_input matches header.payload",
    parsed["signing_input"] == ".".join(token.split(".")[:2]),
)

# b64url round-trip, including an input requiring '-'/'_' substitution chars
raw = b"\xfb\xff\x00binary-data-\xf0\xf1\xf2"
encoded = b64url_encode(raw)
check("b64url_encode omits padding", "=" not in encoded)
decoded = b64url_decode(encoded)
check("b64url round-trip preserves bytes", decoded == raw, decoded)

# forge with alg override to none should strip signature
none_token = forge_jwt(header, payload, alg_override="none")
none_parts = none_token.split(".")
check("alg=none forged token has empty signature segment", none_parts[2] == "")
none_parsed = parse_jwt(none_token)
check("alg=none forged token header reflects override", none_parsed["header"]["alg"] == "none")

# ---------------------------------------------------------------------------
# 2. crack_weak_secret
# ---------------------------------------------------------------------------

weak_secret = COMMON_JWT_SECRETS[0]
check("sanity: weak secret present in default wordlist", weak_secret == "secret")

weak_token = forge_jwt(header, payload, secret=weak_secret)
cracked = crack_weak_secret(weak_token)
check(
    "crack_weak_secret recovers known weak secret from default wordlist",
    cracked is not None and cracked[0] == weak_secret and cracked[1] == "HS256",
    cracked,
)

# Expanded wordlist entries from 2b should also be crackable
for extra_secret in ["jwt_secret", "your-256-bit-secret", "changeme", "supersecret"]:
    check(f"wordlist contains expanded entry '{extra_secret}'", extra_secret in COMMON_JWT_SECRETS)
    tok = forge_jwt(header, payload, secret=extra_secret)
    result = crack_weak_secret(tok)
    check(
        f"crack_weak_secret recovers expanded wordlist secret '{extra_secret}'",
        result is not None and result[0] == extra_secret,
        result,
    )

# Strong random secret should NOT be crackable
strong_secret = secrets.token_hex(32)
strong_token = forge_jwt(header, payload, secret=strong_secret)
not_cracked = crack_weak_secret(strong_token)
check(
    "crack_weak_secret returns None for a strong random secret",
    not_cracked is None,
    not_cracked,
)

# Custom wordlist override still works
custom_secret = "totally-custom-value"
custom_token = forge_jwt(header, payload, secret=custom_secret)
custom_cracked = crack_weak_secret(custom_token, wordlist=[custom_secret])
check(
    "crack_weak_secret honors wordlist override param",
    custom_cracked is not None and custom_cracked[0] == custom_secret,
    custom_cracked,
)
not_in_custom = crack_weak_secret(weak_token, wordlist=[custom_secret])
check(
    "crack_weak_secret with override wordlist misses secrets not in it",
    not_in_custom is None,
    not_in_custom,
)

# ---------------------------------------------------------------------------
# 3. generate_jwt_attack_variants
# ---------------------------------------------------------------------------

base_header = {"alg": "HS256", "typ": "JWT", "kid": "key-1"}
base_payload = {"sub": "user123", "role": "user", "isAdmin": False, "exp": 1999999999}
base_token = forge_jwt(base_header, base_payload, secret="irrelevant-for-structural-checks")

FAKE_PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL6z7xP1placeholderNotARealKey==\n"
    "-----END PUBLIC KEY-----\n"
)

variants = generate_jwt_attack_variants(
    token=base_token,
    known_secret=None,
    public_key_pem=FAKE_PUBLIC_KEY_PEM,
)

by_vector = {}
for v in variants:
    by_vector.setdefault(v["vector"], []).append(v)


def decode_variant(v):
    """Decode a variant token's header/payload without verifying signature."""
    return parse_jwt(v["token"])


# --- alg:none family ---
for alg_val in ["none", "None", "NONE"]:
    key = f"alg_none_{alg_val}"
    check(f"variant '{key}' present", key in by_vector)
    if key in by_vector:
        v = by_vector[key][0]
        d = decode_variant(v)
        check(f"variant '{key}' header.alg == '{alg_val}'", d["header"]["alg"] == alg_val, d["header"])
        check(f"variant '{key}' signature segment is empty", v["token"].split(".")[2] == "")

# --- alg confusion RS256 -> HS256 ---
check("variant 'alg_confusion_rs256_to_hs256' present (public_key_pem supplied)",
      "alg_confusion_rs256_to_hs256" in by_vector)
if "alg_confusion_rs256_to_hs256" in by_vector:
    v = by_vector["alg_confusion_rs256_to_hs256"][0]
    d = decode_variant(v)
    check("alg-confusion variant header.alg == 'HS256'", d["header"]["alg"] == "HS256", d["header"])
    # Signature must verify with the public key PEM bytes as the HMAC secret
    import hmac as _hmac
    import hashlib as _hashlib
    signing_input = v["token"].rsplit(".", 1)[0].encode("utf-8")
    expected_sig = _hmac.new(FAKE_PUBLIC_KEY_PEM.encode("utf-8"), signing_input, _hashlib.sha256).digest()
    actual_sig = b64url_decode(v["token"].split(".")[2])
    check(
        "alg-confusion variant signature matches HMAC(public_key_pem_bytes)",
        _hmac.compare_digest(expected_sig, actual_sig),
    )

# When no public key is supplied, the variant should be skipped gracefully (no crash, no entry)
variants_no_key = generate_jwt_attack_variants(token=base_token, known_secret=None)
check(
    "alg-confusion variant absent when public_key_pem is not supplied",
    not any(v["vector"] == "alg_confusion_rs256_to_hs256" for v in variants_no_key),
)

# --- kid injection: SQLi / path-traversal / command-injection ---
kid_checks = {
    "kid_sqli_bypass": "' OR '1'='1",
    "kid_path_traversal_dev_null": "../../dev/null",
    "kid_command_injection": None,  # value is command-ish; checked for shell metacharacters below
}
for vector_name, expected_substring in kid_checks.items():
    check(f"variant '{vector_name}' present", vector_name in by_vector)
    if vector_name in by_vector:
        v = by_vector[vector_name][0]
        d = decode_variant(v)
        kid_val = d["header"].get("kid", "")
        if vector_name == "kid_sqli_bypass":
            check(f"'{vector_name}' kid contains SQLi payload", "OR '1'='1" in kid_val or expected_substring in kid_val, kid_val)
        elif vector_name == "kid_path_traversal_dev_null":
            check(f"'{vector_name}' kid contains path-traversal payload", ".." in kid_val and "dev/null" in kid_val, kid_val)
        else:
            has_meta = any(ch in kid_val for ch in [";", "|", "$", "`", "&"])
            check(f"'{vector_name}' kid contains shell metacharacters", has_meta, kid_val)

# --- jku / x5u injection ---
check("variant 'jku_header_injection' present", "jku_header_injection" in by_vector)
if "jku_header_injection" in by_vector:
    d = decode_variant(by_vector["jku_header_injection"][0])
    check("jku_header_injection has jku header", "jku" in d["header"], d["header"])

check("variant 'jku_canary_injection' present", "jku_canary_injection" in by_vector)
if "jku_canary_injection" in by_vector:
    d = decode_variant(by_vector["jku_canary_injection"][0])
    check(
        "jku_canary_injection jku points to OAST_CANARY placeholder",
        d["header"].get("jku", "").startswith("https://OAST_CANARY/"),
        d["header"],
    )

check("variant 'x5u_canary_injection' present", "x5u_canary_injection" in by_vector)
if "x5u_canary_injection" in by_vector:
    d = decode_variant(by_vector["x5u_canary_injection"][0])
    check(
        "x5u_canary_injection x5u points to OAST_CANARY placeholder",
        d["header"].get("x5u", "").startswith("https://OAST_CANARY/"),
        d["header"],
    )

# --- claim escalation / subject swap ---
check("variant 'claim_sub_swap_admin' present", "claim_sub_swap_admin" in by_vector)
if "claim_sub_swap_admin" in by_vector:
    d = decode_variant(by_vector["claim_sub_swap_admin"][0])
    check("claim_sub_swap_admin payload.sub == 'admin'", d["payload"].get("sub") == "admin", d["payload"])

# Default heuristic escalation (role/isAdmin) still applies to alg_none_escalated_* variants
check("variant 'alg_none_escalated_none' present", "alg_none_escalated_none" in by_vector)
if "alg_none_escalated_none" in by_vector:
    d = decode_variant(by_vector["alg_none_escalated_none"][0])
    check("escalated variant payload.role == 'admin'", d["payload"].get("role") == "admin", d["payload"])
    check("escalated variant payload.isAdmin == True", d["payload"].get("isAdmin") is True, d["payload"])

# --- expiry / nbf tampering ---
check("variant 'temporal_exp_nbf_tampering' present", "temporal_exp_nbf_tampering" in by_vector)
if "temporal_exp_nbf_tampering" in by_vector:
    d = decode_variant(by_vector["temporal_exp_nbf_tampering"][0])
    check("temporal variant exp extended far into the future", d["payload"].get("exp", 0) > base_payload["exp"], d["payload"])
    check("temporal variant nbf backdated to epoch 0", d["payload"].get("nbf") == 0, d["payload"])

# --- all variants are structurally decodable (sanity sweep) ---
all_decodable = True
for v in variants:
    try:
        decode_variant(v)
    except Exception as e:
        all_decodable = False
        print(f"  -> variant '{v['vector']}' failed to decode: {e}")
check("all generated variants are structurally decodable (header/payload parse cleanly)", all_decodable)

# known_secret still produces a forged variant with a valid signature (existing behavior)
variants_with_secret = generate_jwt_attack_variants(token=base_token, known_secret="cracked123")
check(
    "variant 'forged_with_cracked_secret' present when known_secret is supplied",
    any(v["vector"] == "forged_with_cracked_secret" for v in variants_with_secret),
)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print()
if failures:
    print(f"{len(failures)} check(s) FAILED:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
else:
    print(f"All checks passed ({len(variants)} attack variants generated in the full-featured run).")
    sys.exit(0)
