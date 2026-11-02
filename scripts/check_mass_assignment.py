"""
Proxsynth MCP - Offline acceptance check for the mass-assignment engine (Task 3).

Verifies, with NO network access:
  - build_mass_assignment_payloads() produces the privileged-field mutations
    for a JSON body (top-level AND one nested level) and for a form-urlencoded
    body, including the broadened attribute set (role/isAdmin/is_admin/
    permissions/verified/email_verified/account_type/tier/plan/balance/credit/
    discount/org_id/tenant_id/owner_id/status/approved/active).
  - build_mass_assignment_payloads() produces a query-string injection when
    given content_type="query".
  - evaluate_mass_assignment() flags a reflected injected field as a hit,
    flags a 2xx response with a meaningful length/soft-error delta vs.
    baseline as a hit, and does NOT flag a baseline-equal clean response.

Run: ./venv/Scripts/python.exe scripts/check_mass_assignment.py
Exits non-zero if any assertion fails.
"""

import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import backend.mass_assignment_engine as mae  # noqa: E402

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


EXPECTED_PRIVILEGED_FIELDS = [
    "role", "isAdmin", "is_admin", "permissions", "verified",
    "email_verified", "account_type", "tier", "plan", "balance",
    "credit", "discount", "org_id", "tenant_id", "owner_id",
    "status", "approved", "active",
]


def test_admin_attributes_broadened():
    print("\n[1/6] ADMIN_ATTRIBUTES broadened with expected privileged fields...")
    for field in EXPECTED_PRIVILEGED_FIELDS:
        check(f"ADMIN_ATTRIBUTES contains '{field}'", field in mae.ADMIN_ATTRIBUTES)


def test_build_payloads_json_top_and_nested():
    print("\n[2/6] build_mass_assignment_payloads: JSON top-level + one nested level...")
    base_body = json.dumps({"username": "bob", "profile": {"display_name": "Bob"}})
    payloads = mae.build_mass_assignment_payloads(base_body, "application/json")

    kinds = {p["kind"] for p in payloads}
    check("produces a json_top payload", "json_top" in kinds)
    check("produces a json_nested payload", "json_nested" in kinds)

    top = next((p for p in payloads if p["kind"] == "json_top"), None)
    check("json_top payload exists", top is not None)
    if top is not None:
        top_body = json.loads(top["body"])
        for field in EXPECTED_PRIVILEGED_FIELDS:
            check(f"json_top body contains injected field '{field}'", field in top_body)
        check("json_top preserves original field 'username'", top_body.get("username") == "bob")
        check("json_top content_type is application/json", top["content_type"] == "application/json")

    nested = next((p for p in payloads if p["kind"] == "json_nested"), None)
    check("json_nested payload exists", nested is not None)
    if nested is not None:
        nested_body = json.loads(nested["body"])
        nested_profile = nested_body.get("profile", {})
        for field in EXPECTED_PRIVILEGED_FIELDS:
            check(f"json_nested body['profile'] contains injected field '{field}'", field in nested_profile)
        check("json_nested preserves nested original field 'display_name'",
              nested_profile.get("display_name") == "Bob")
        check("json_nested does not inject at top level",
              all(field not in nested_body for field in EXPECTED_PRIVILEGED_FIELDS))

    # A field already present should never be overwritten (purely additive).
    base_with_role = json.dumps({"role": "user"})
    payloads2 = mae.build_mass_assignment_payloads(base_with_role, "application/json")
    top2 = next((p for p in payloads2 if p["kind"] == "json_top"), None)
    check("existing field is not overwritten", "role" not in top2["injected_fields"])
    top2_body = json.loads(top2["body"])
    check("existing field value preserved", top2_body.get("role") == "user")


def test_build_payloads_form():
    print("\n[3/6] build_mass_assignment_payloads: form-urlencoded body...")
    base_body = "username=bob&email=bob%40example.com"
    payloads = mae.build_mass_assignment_payloads(base_body, "application/x-www-form-urlencoded")

    form = next((p for p in payloads if p["kind"] == "form"), None)
    check("produces a form payload", form is not None)
    if form is not None:
        check("form content_type is application/x-www-form-urlencoded",
              form["content_type"] == "application/x-www-form-urlencoded")
        for field in EXPECTED_PRIVILEGED_FIELDS:
            check(f"form body contains injected field '{field}'", f"{field}=" in form["body"])
        check("form body preserves original field 'username'", "username=bob" in form["body"])


def test_build_payloads_query():
    print("\n[4/6] build_mass_assignment_payloads: query-string injection...")
    base_qs = "page=1&limit=10"
    payloads = mae.build_mass_assignment_payloads(base_qs, "query")
    query = next((p for p in payloads if p["kind"] == "query"), None)
    check("produces a query payload", query is not None)
    if query is not None:
        check("query content_type label is 'query'", query["content_type"] == "query")
        for field in EXPECTED_PRIVILEGED_FIELDS:
            check(f"query string contains injected field '{field}'", f"{field}=" in query["body"])
        check("query string preserves original param 'page'", "page=1" in query["body"])

    # Custom attributes override/extend the default set additively.
    custom = {"super_secret_flag": True}
    payloads_custom = mae.build_mass_assignment_payloads(base_qs, "query", attributes=custom)
    query_custom = next((p for p in payloads_custom if p["kind"] == "query"), None)
    check("custom attributes are used when provided", "super_secret_flag=True" in query_custom["body"])
    check("default attributes are not mixed in when custom attributes provided",
          "is_admin" not in query_custom["body"])


def test_evaluate_mass_assignment():
    print("\n[5/6] evaluate_mass_assignment: reflection, delta, and clean-baseline cases...")

    # Case 1: reflected injected field in a JSON response -> hit.
    baseline = {"status": 200, "text": json.dumps({"id": 1, "username": "bob"})}
    injected = {"status": 200, "text": json.dumps({"id": 1, "username": "bob", "is_admin": True})}
    result = mae.evaluate_mass_assignment("is_admin", True, baseline, injected)
    check("reflected field is flagged as a hit", result["hit"] is True)
    check("reflected flag set", result["reflected"] is True)

    # Case 2: reflected field via substring match in a non-JSON response -> hit.
    # Force the non-JSON parse path with a body that isn't valid JSON but contains the key pattern.
    injected_nonjson = {"status": 200, "text": '{"is_admin":true, invalid json'}
    result2 = mae.evaluate_mass_assignment("is_admin", True, baseline, injected_nonjson)
    check("substring-reflected field (non-JSON body) is flagged as a hit", result2["hit"] is True)

    # Case 3: 2xx with meaningful length delta vs baseline (no reflection) -> hit.
    baseline3 = {"status": 403, "text": "Forbidden"}
    injected3 = {"status": 200, "text": "A" * 500 + json.dumps({"id": 1, "username": "bob"})}
    result3 = mae.evaluate_mass_assignment("role", "admin", baseline3, injected3)
    check("2xx + status-became-success delta is flagged as a hit", result3["hit"] is True)
    check("delta_hit flag set for status-success delta", result3["delta_hit"] is True)

    # Case 4: baseline-equal clean response (same status, same body shape) -> NOT a hit.
    clean_baseline = {"status": 200, "text": json.dumps({"id": 1, "username": "bob"})}
    clean_injected = {"status": 200, "text": json.dumps({"id": 1, "username": "bob"})}
    result4 = mae.evaluate_mass_assignment("role", "admin", clean_baseline, clean_injected)
    check("baseline-equal clean response is NOT flagged as a hit", result4["hit"] is False)
    check("clean response has reflected=False", result4["reflected"] is False)
    check("clean response has delta_hit=False", result4["delta_hit"] is False)

    # Case 5: soft-403 response despite 200 status -> NOT a hit (even with some length delta).
    soft_baseline = {"status": 200, "text": json.dumps({"id": 1})}
    soft_injected = {"status": 200, "text": "Access Denied: insufficient permissions " * 5}
    result5 = mae.evaluate_mass_assignment("role", "admin", soft_baseline, soft_injected)
    check("soft-403-flavored 200 response is NOT flagged as a hit", result5["hit"] is False)

    # Case 6: no baseline available -> only reflection signal applies, delta never fires.
    result6 = mae.evaluate_mass_assignment("role", "admin", None, {
        "status": 200, "text": "A" * 5000
    })
    check("without a baseline, a non-reflected response is NOT flagged as a hit", result6["hit"] is False)


def test_evaluate_false_positive_vectors():
    print("\n[6/6] evaluate_mass_assignment: false-positive amplification guards...")

    nominal = json.dumps({"id": 1, "username": "bob"})

    # FP Vector A: a transient / non-rejection baseline failure (503, 429, a
    # 5xx) must NOT, on its own, flip a non-reflected 2xx injected response to a
    # hit. Previously "any non-2xx baseline" was treated as a success delta,
    # which marked every injected field on every probe as a confirmed bind.
    for transient_status in (500, 502, 503, 429):
        baseline = {"status": transient_status, "text": "Service Unavailable"}
        injected = {"status": 200, "text": nominal}
        res = mae.evaluate_mass_assignment("role", "admin", baseline, injected)
        check(f"transient {transient_status} baseline does NOT manufacture a hit", res["hit"] is False)
        check(f"transient {transient_status} baseline -> delta_hit False", res["delta_hit"] is False)

    # A genuine authorization rejection (401/403/422) that flips to 2xx IS still
    # a trusted signal (regression guard for the legitimate case).
    for rejected_status in (401, 403, 422):
        baseline = {"status": rejected_status, "text": "Forbidden"}
        injected = {"status": 200, "text": nominal}
        res = mae.evaluate_mass_assignment("role", "admin", baseline, injected)
        check(f"rejected {rejected_status} baseline -> 2xx IS a delta hit", res["delta_hit"] is True)

    # FP Vector B: both responses succeed (2xx) and differ only by small dynamic
    # noise (a CSRF token / timestamp / nonce) below the meaningful-length floor.
    # This must NOT be a hit.
    base_obj = {"id": 1, "username": "bob", "csrf": "a" * 32}
    inj_obj = {"id": 1, "username": "bob", "csrf": "b" * 40, "ts": "2026-11-02T00:00:00Z"}
    baseline_b = {"status": 200, "text": json.dumps(base_obj)}
    injected_b = {"status": 200, "text": json.dumps(inj_obj)}
    res_b = mae.evaluate_mass_assignment("role", "admin", baseline_b, injected_b)
    check("small dynamic-token delta between two 2xx responses is NOT a hit", res_b["hit"] is False)

    # But a large, genuinely meaningful length delta between two 2xx responses
    # still registers (regression guard — the signal is only tightened, not removed).
    injected_big = {"status": 200, "text": json.dumps(base_obj) + ("X" * 400)}
    res_big = mae.evaluate_mass_assignment("role", "admin", baseline_b, injected_big)
    check("large meaningful length delta between two 2xx responses IS a hit", res_big["delta_hit"] is True)


def main():
    print("=" * 70)
    print("Proxsynth Mass Assignment Engine - Offline Acceptance Check (Task 3)")
    print("=" * 70)

    test_admin_attributes_broadened()
    test_build_payloads_json_top_and_nested()
    test_build_payloads_form()
    test_build_payloads_query()
    test_evaluate_mass_assignment()
    test_evaluate_false_positive_vectors()

    print("\n" + "=" * 70)
    print(f"Result: {PASSES} passed, {len(FAILURES)} failed")
    if FAILURES:
        print("\nFailures:")
        for f in FAILURES:
            print(f"  - {f}")
        print("=" * 70)
        sys.exit(1)
    else:
        print("All checks passed.")
        print("=" * 70)
        sys.exit(0)


if __name__ == "__main__":
    main()
