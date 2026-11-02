"""
Proxsynth MCP - Offline acceptance check for the attack advisor engine (Task 4).

Verifies, with NO network access and NO database dependency, that
suggest_attack_actions() maps newly-added signals to the correct real MCP
tools with plausible arguments, that existing signals still fire, that a
benign static-asset request yields no spurious high-value recommendations,
and that recommendations are deduped by (tool, target).

Run: ./venv/Scripts/python.exe scripts/check_attack_advisor.py
Exits non-zero if any assertion fails.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.attack_advisor import suggest_attack_actions  # noqa: E402

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


def find_tool(suggestions, tool_name):
    return [s for s in suggestions if s.get("recommended_mcp_tool") == tool_name]


def test_open_redirect_ssrf_param():
    print("\n[1/9] Open-redirect / SSRF query param -> spray_oast_canaries + send_http_request...")
    url = "https://target.example/go?next=https://evil.example/phish"
    suggestions = suggest_attack_actions(url=url, method="GET")

    oast = find_tool(suggestions, "spray_oast_canaries")
    check("spray_oast_canaries recommended for 'next' param", len(oast) >= 1)
    if oast:
        check("spray_oast_canaries targets the request url", oast[0]["tool_arguments"].get("target_url") == url)
        check("spray_oast_canaries includes vuln_types list", isinstance(oast[0]["tool_arguments"].get("vuln_types"), list))

    probe = find_tool(suggestions, "send_http_request")
    check("send_http_request CORS/redirect probe recommended for 'next' param", len(probe) >= 1)
    if probe:
        # send_http_request has no 'params' arg: the redirect value must be folded
        # into the url instead, so an agent can call the tool verbatim.
        probe_args = probe[0]["tool_arguments"]
        check("send_http_request probe does NOT emit an invalid 'params' arg",
              "params" not in probe_args)
        check("send_http_request probe folds the redirect param into the url",
              "next=" in probe_args.get("url", ""))


def test_open_redirect_body_param():
    print("\n[2/9] Open-redirect param in JSON body -> spray_oast_canaries...")
    url = "https://target.example/api/share"
    body = '{"return": "https://evil.example/collect", "note": "hi"}'
    suggestions = suggest_attack_actions(url=url, method="POST", body=body)
    oast = find_tool(suggestions, "spray_oast_canaries")
    check("spray_oast_canaries recommended for body 'return' param", len(oast) >= 1)


def test_graphql_path():
    print("\n[3/9] GraphQL path -> inspect_graphql_endpoint...")
    url = "https://target.example/api/graphql"
    suggestions = suggest_attack_actions(url=url, method="POST", body='{"query": "{ __typename }"}')
    gql = find_tool(suggestions, "inspect_graphql_endpoint")
    check("inspect_graphql_endpoint recommended for /graphql path", len(gql) == 1)
    if gql:
        check("inspect_graphql_endpoint targets the endpoint via 'url'", gql[0]["tool_arguments"].get("url") == url)


def test_graphql_body_only():
    print("\n[4/9] GraphQL-shaped body on a non-/graphql path -> inspect_graphql_endpoint...")
    url = "https://target.example/api/query-service"
    body = "mutation { createWidget(name: \"x\") { id } }"
    suggestions = suggest_attack_actions(url=url, method="POST", body=body)
    gql = find_tool(suggestions, "inspect_graphql_endpoint")
    check("inspect_graphql_endpoint recommended for GraphQL mutation body", len(gql) == 1)


def test_file_upload_multipart():
    print("\n[5/9] multipart/form-data request -> audit_file_upload...")
    url = "https://target.example/api/avatar"
    headers = {"Content-Type": "multipart/form-data; boundary=----xyz"}
    body = '------xyz\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["c"]); ?>\r\n------xyz--'
    suggestions = suggest_attack_actions(url=url, method="POST", headers=headers, body=body)
    upload = find_tool(suggestions, "audit_file_upload")
    check("audit_file_upload recommended for multipart upload", len(upload) == 1)
    if upload:
        check("audit_file_upload targets via 'target' (log_id when known, else url)", upload[0]["tool_arguments"].get("target") == url)


def test_file_upload_filename_in_body():
    print("\n[6/9] filename= in body without multipart header -> audit_file_upload...")
    url = "https://target.example/api/import"
    body = 'payload=filename="report.csv"&data=abc'
    suggestions = suggest_attack_actions(url=url, method="POST", body=body)
    upload = find_tool(suggestions, "audit_file_upload")
    check("audit_file_upload recommended for filename= in body", len(upload) == 1)


def test_cors_wildcard_with_credentials():
    print("\n[7/9] CORS wildcard/reflected origin + credentials -> send_http_request CORS probe...")
    url = "https://target.example/api/profile"
    headers = {"Origin": "https://attacker.example"}
    response_headers = {
        "Access-Control-Allow-Origin": "https://attacker.example",
        "Access-Control-Allow-Credentials": "true",
    }
    suggestions = suggest_attack_actions(
        url=url, method="GET", headers=headers, response_headers=response_headers
    )
    cors = [
        s for s in find_tool(suggestions, "send_http_request")
        if "CORS" in s.get("vulnerability_focus", "")
    ]
    check("send_http_request CORS probe recommended for reflected-origin + credentials", len(cors) == 1)
    if cors:
        check("CORS probe includes a cross-origin Origin header", "Origin" in (cors[0]["tool_arguments"].get("headers") or {}))


def test_cors_wildcard_without_credentials_not_flagged():
    print("\n[8/9] CORS wildcard WITHOUT credentials -> no CORS probe recommended...")
    url = "https://target.example/api/public-data"
    response_headers = {"Access-Control-Allow-Origin": "*"}
    suggestions = suggest_attack_actions(url=url, method="GET", response_headers=response_headers)
    cors = [
        s for s in find_tool(suggestions, "send_http_request")
        if "CORS" in s.get("vulnerability_focus", "")
    ]
    check("no CORS probe recommended when Allow-Credentials is absent", len(cors) == 0)


def test_authorization_bearer_jwt():
    print("\n[9/9] Authorization: Bearer <jwt> -> audit_jwt_security...")
    url = "https://target.example/api/me"
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    headers = {"Authorization": f"Bearer {token}"}
    suggestions = suggest_attack_actions(url=url, method="GET", headers=headers)
    jwt = find_tool(suggestions, "audit_jwt_security")
    check("audit_jwt_security recommended for Bearer JWT", len(jwt) == 1)
    if jwt:
        check("audit_jwt_security receives the extracted token", jwt[0]["tool_arguments"].get("token") == token)


def test_numeric_object_id_in_path():
    print("\n[extra] Numeric object id in path -> test_bola_idor...")
    url = "https://target.example/api/orders/8820"
    suggestions = suggest_attack_actions(url=url, method="GET")
    bola = find_tool(suggestions, "test_bola_idor")
    check("test_bola_idor recommended for numeric object id in path", len(bola) == 1)


def test_debug_param_mass_assignment():
    print("\n[extra] Debug/verbose query param -> audit_mass_assignment...")
    url = "https://target.example/api/export?debug=1&format=json"
    suggestions = suggest_attack_actions(url=url, method="GET")
    mass = find_tool(suggestions, "audit_mass_assignment")
    check("audit_mass_assignment recommended for debug=1 param", len(mass) == 1)


def test_json_mutation_mass_assignment_still_present():
    print("\n[extra] Existing JSON mutation mass-assignment signal preserved...")
    url = "https://target.example/api/users/55"
    body = '{"email": "a@b.com", "role": "admin", "name": "A"}'
    suggestions = suggest_attack_actions(url=url, method="PUT", body=body)
    mass = find_tool(suggestions, "audit_mass_assignment")
    check("audit_mass_assignment still recommended for existing JSON mutation signal", len(mass) >= 1)
    bola = find_tool(suggestions, "test_bola_idor")
    check("existing BOLA signal (numeric id in path) still fires alongside it", len(bola) == 1)


def test_benign_static_asset_no_spurious_recommendations():
    print("\n[extra] Benign static GET of a .js asset -> no spurious recommendations...")
    url = "https://target.example/static/app.bundle.js"
    suggestions = suggest_attack_actions(url=url, method="GET", response_status=200, response_body="console.log('ok');")
    check("no recommendations for a benign static asset GET", len(suggestions) == 0)


def test_dedupe_same_tool_and_target():
    print("\n[extra] Dedupe: same tool+target not suggested twice...")
    # The literal param name 'url' matches BOTH the legacy SSRF pattern and the
    # new open-redirect pattern; both map to spray_oast_canaries against the
    # same target_url, so only one should survive.
    url = "https://target.example/fetch?url=https://internal.example/meta"
    suggestions = suggest_attack_actions(url=url, method="GET")
    oast = find_tool(suggestions, "spray_oast_canaries")
    check("spray_oast_canaries appears exactly once despite two matching signals", len(oast) == 1)

    # Global uniqueness check across every recommendation returned.
    seen = set()
    duplicates = []
    for s in suggestions:
        tool_args = s.get("tool_arguments") or {}
        target = (
            tool_args.get("endpoint_url")
            or tool_args.get("target_url")
            or tool_args.get("test_url")
            or tool_args.get("url")
            or url
        )
        sig = (s.get("recommended_mcp_tool"), target)
        if sig in seen:
            duplicates.append(sig)
        seen.add(sig)
    check("no duplicate (tool, target) pairs in any recommendation set", len(duplicates) == 0)


def main():
    print("=" * 70)
    print("Proxsynth Attack Advisor - Offline Acceptance Check (Task 4)")
    print("=" * 70)

    test_open_redirect_ssrf_param()
    test_open_redirect_body_param()
    test_graphql_path()
    test_graphql_body_only()
    test_file_upload_multipart()
    test_file_upload_filename_in_body()
    test_cors_wildcard_with_credentials()
    test_cors_wildcard_without_credentials_not_flagged()
    test_authorization_bearer_jwt()
    test_numeric_object_id_in_path()
    test_debug_param_mass_assignment()
    test_json_mutation_mass_assignment_still_present()
    test_benign_static_asset_no_spurious_recommendations()
    test_dedupe_same_tool_and_target()

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
