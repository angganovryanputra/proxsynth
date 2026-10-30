"""
Proxsynth MCP - Offline acceptance check for the parameter fuzzer (Task 1).

Verifies, with NO network access:
  - BUILTIN_PAYLOADS has the new categories (nosqli, xxe, ssrf, crlf, open_redirect)
    and existing categories are retained / grew.
  - generate_waf_evasion_variants still produces the expected variant types.
  - detect_anomalies() (the refactored pure helper) correctly flags: reflected
    payload, SQL error body, generalized SSTI arithmetic evaluation (both the
    backward-compatible 49 case and the general case), command-injection
    evidence (/etc/passwd + id output), NoSQL error signatures, status-code
    shift, and large length delta.
  - SQL_ERROR_PATTERNS grew with MSSQL/Oracle/DB2 signatures.
  - run_fuzz_attack keeps its public signature backward compatible (new
    payload_type param is optional / last / defaults to None).

Run: ./venv/Scripts/python.exe scripts/check_fuzzer.py
Exits non-zero if any assertion fails.
"""

import inspect
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import backend.fuzzer as fuzzer  # noqa: E402

FAILURES = []
PASSES = 0


def check(label, condition):
    global PASSES
    if condition:
        PASSES += 1
        print(f"  [PASS] {label}")
    else:
        FAILURES.append(label)
        print(f"  [FAIL] {label}")


def main():
    print("=== check_fuzzer.py: offline parameter fuzzer acceptance check ===\n")

    # ------------------------------------------------------------------
    # 1a. Bug fixes: module-level sanity (no NameError at import time, both
    #     `json` and `diag` paths reachable without crashing the module).
    # ------------------------------------------------------------------
    print("[1] Bug-fix groundwork")
    check("backend.fuzzer imports cleanly (no NameError at import time)", True)
    check("json module is imported in backend.fuzzer", "json" in fuzzer.__dict__ or hasattr(fuzzer, "json"))
    sig = inspect.signature(fuzzer.run_fuzz_attack)
    params = list(sig.parameters.keys())
    check(
        "run_fuzz_attack keeps original params in original order (additive-only)",
        params[:11] == [
            "base_url", "method", "headers", "body", "payloads", "concurrency",
            "delay_ms", "jitter_ms", "upstream_proxy", "project", "agent_id",
        ],
    )
    check("run_fuzz_attack retains auto_evade_waf", "auto_evade_waf" in params)
    check(
        "new payload_type param is additive: present, last, optional, defaults to None",
        params[-1] == "payload_type"
        and sig.parameters["payload_type"].default is None,
    )

    # ------------------------------------------------------------------
    # 1b. Payload dictionary expansion
    # ------------------------------------------------------------------
    print("\n[2] BUILTIN_PAYLOADS expansion")
    payloads = fuzzer.BUILTIN_PAYLOADS
    new_categories = ["nosqli", "xxe", "ssrf", "crlf", "open_redirect"]
    for cat in new_categories:
        check(f"category '{cat}' exists", cat in payloads)
        check(f"category '{cat}' is non-empty", cat in payloads and len(payloads[cat]) > 0)

    check("nosqli contains a $ne operator payload", any("$ne" in p for p in payloads.get("nosqli", [])))
    check("xxe contains a classic external-entity payload", any("ENTITY" in p and "SYSTEM" in p for p in payloads.get("xxe", [])))
    check("xxe contains a parameter-entity SSRF form", any("%xxe" in p for p in payloads.get("xxe", [])))
    check("ssrf contains the cloud metadata endpoint", any("169.254.169.254" in p for p in payloads.get("ssrf", [])))
    check("ssrf contains a file:// scheme payload", any(p.startswith("file://") for p in payloads.get("ssrf", [])))
    check("crlf contains a %0d%0a Set-Cookie injection", any("%0d%0a" in p.lower() and "set-cookie" in p.lower() for p in payloads.get("crlf", [])))
    check("open_redirect contains a protocol-relative bypass", "//evil.example" in payloads.get("open_redirect", []))

    # Existing categories retained and grew (baseline counts from the pre-task file).
    baseline_counts = {
        "sqli": 9, "xss": 7, "traversal": 7, "cmd_injection": 7, "ssti": 6,
        "auth_bypass": 10, "business_logic": 14, "mass_assignment": 10,
    }
    for cat, base_n in baseline_counts.items():
        check(f"existing category '{cat}' retained", cat in payloads)
        check(f"existing category '{cat}' grew (>= {base_n} entries)", len(payloads.get(cat, [])) >= base_n)

    check("ssti still contains the original 7*7 probe (back-compat)", "{{7*7}}" in payloads["ssti"])
    check("ssti gained a 9*9 probe", any("9*9" in p for p in payloads["ssti"]))
    check("ssti gained a 6*6 probe", any("6*6" in p for p in payloads["ssti"]))

    # ------------------------------------------------------------------
    # SQL_ERROR_PATTERNS expansion
    # ------------------------------------------------------------------
    print("\n[3] SQL_ERROR_PATTERNS expansion")
    pats = fuzzer.SQL_ERROR_PATTERNS
    check("original MySQL pattern retained", any("mysql" in p for p in pats))
    check("gained an MSSQL pattern", any("incorrect syntax near" in p for p in pats))
    check("gained an Oracle pattern", any("ora-00933" in p or "ora-00936" in p for p in pats))
    check("gained a DB2 pattern", any("db2" in p.lower() or "sql0104n" in p.lower() for p in pats))

    # ------------------------------------------------------------------
    # 1a. generate_waf_evasion_variants still produces expected types
    # ------------------------------------------------------------------
    print("\n[4] generate_waf_evasion_variants()")
    variants = fuzzer.generate_waf_evasion_variants("' OR 1=1--")
    vtypes = {v["type"] for v in variants}
    for expected in ["DOUBLE_URL_ENCODE", "COMMENT_SPLIT", "NULL_BYTE_PREFIX", "UNICODE_EXPANSION", "GATEWAY_HEADER_BYPASS"]:
        check(f"variant type '{expected}' produced", expected in vtypes)
    gw = next(v for v in variants if v["type"] == "GATEWAY_HEADER_BYPASS")
    check("GATEWAY_HEADER_BYPASS carries spoofed IP headers", "X-Forwarded-For" in gw["headers"])

    case_variants = fuzzer.generate_waf_evasion_variants("UNION SELECT 1")
    case_types = {v["type"] for v in case_variants}
    check("CASE_RANDOMIZATION produced for keyword-bearing payload", "CASE_RANDOMIZATION" in case_types)

    # ------------------------------------------------------------------
    # 1c. detect_anomalies() unit tests (pure helper, synthetic inputs only)
    # ------------------------------------------------------------------
    print("\n[5] detect_anomalies() — synthetic, offline unit tests")
    da = fuzzer.detect_anomalies

    # Reflected payload
    r = da("<script>alert(1)</script>", "echo: <script>alert(1)</script>", "echo: ", 200, 200, 10, 10)
    check("reflected payload -> REFLECTED", "REFLECTED" in r)

    # SQL error body
    r = da("' OR 1=1--", "You have an error in your SQL syntax near ...", "ok", 200, 200, 10, 10)
    check("SQL error body -> SQL_ERROR_LEAK", "SQL_ERROR_LEAK" in r)

    # Backward-compatible SSTI 7*7 -> 49
    r = da("{{7*7}}", "result is 49", "result is ", 200, 200, 10, 10)
    check("{{7*7}} evaluated to 49 -> SSTI_EVALUATED_49 (back-compat)", "SSTI_EVALUATED_49" in r)
    check("49 case does NOT also emit the generic SSTI_EVALUATED tag", "SSTI_EVALUATED" not in r)

    # Generalized SSTI probes (9*9 -> 81, 6*6 -> 36)
    r = da("${9*9}", "val=81", "val=", 200, 200, 10, 10)
    check("${9*9} evaluated to 81 -> general SSTI_EVALUATED", "SSTI_EVALUATED" in r and "SSTI_EVALUATED_49" not in r)
    r = da("#{6*6}", "val=36", "val=", 200, 200, 10, 10)
    check("#{6*6} evaluated to 36 -> general SSTI_EVALUATED", "SSTI_EVALUATED" in r)

    # SSTI probe present but NOT evaluated (product already in baseline) -> no false positive
    r = da("{{7*7}}", "result is 49", "result is 49 (default)", 200, 200, 10, 10)
    check("49 already present in baseline -> no SSTI anomaly (avoids false positive)", "SSTI_EVALUATED_49" not in r and "SSTI_EVALUATED" not in r)

    # NoSQL error signature
    r = da("' || '1'=='1", "MongoError: unterminated string in expression", "", 200, 200, 10, 10)
    check("NoSQL error body -> NOSQL_ERROR_LEAK", "NOSQL_ERROR_LEAK" in r)

    # Command-injection evidence: /etc/passwd content
    r = da("../../../../etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin", "", 200, 200, 10, 10)
    check("/etc/passwd leakage -> CMDI_EVIDENCE", "CMDI_EVIDENCE" in r)

    # Command-injection evidence: `id` output
    r = da("; id", "uid=0(root) gid=0(root) groups=0(root)", "", 200, 200, 10, 10)
    check("`id` output leakage -> CMDI_EVIDENCE", "CMDI_EVIDENCE" in r)

    # Status code shift
    r = da("1' AND 1=2--", "Internal Server Error", "OK", 500, 200, 10, 10)
    check("status shift 200->500 -> STATUS_500", "STATUS_500" in r)

    # Large length delta
    r = da("x", "y" * 2000, "y" * 10, 200, 200, 10, 10)
    check("large length delta (>250 bytes) -> DELTA_LENGTH", "DELTA_LENGTH" in r)

    # Latency anomaly (time-based SQLi)
    r = da("1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--", "OK", "OK", 2500, 300, 2500, 300)
    check("large timing delta -> TIME_DELAY", "TIME_DELAY" in r)

    # Clean / no anomalies baseline case
    r = da("harmless", "all good here", "all good here", 200, 200, 10, 10)
    check("benign payload + matching baseline -> no anomalies", r == [])

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n=== {PASSES} passed, {len(FAILURES)} failed ===")
    if FAILURES:
        print("\nFailed checks:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
