# Plan — Proxsynth MCP Feature Enhancement, Batch 1

Deepen four existing Proxsynth security engines so the MCP tools built on them
are materially more powerful, without changing their public contracts. Each
task is one engine file plus a tracked test script; the tasks are independent
(different files) and can be executed and reviewed in any order.

This plan is its own authority (no separate spec file exists).

## Global Constraints (binding on every task)

- **Branch / cwd:** work on branch `feat/mcp-enhance-batch-1` from the repo root
  `D:/0x13 PROJECT/Proxsynth`. Commit each task's work on this branch.
- **Python:** run everything with the project venv: `./venv/Scripts/python.exe`.
- **Backward compatibility (hard):** do NOT rename or remove existing public
  functions, change their existing parameter order/names, or remove/rename any
  key currently present in their returned dicts. Changes are ADDITIVE only —
  new optional parameters with safe defaults, and new dict keys. These engines
  are imported by `mcp_core/tools/*.py` and exercised by `scripts/self_test.py`;
  breaking a signature breaks the MCP server.
- **Offline, deterministic tests (hard):** new tests must NOT make real network
  calls to any external host. Test pure/synchronous helpers directly. For logic
  that lives inside an async HTTP function, refactor the pure decision logic
  (payload generation, response/anomaly evaluation) into a separate module-level
  helper and unit-test that helper. Never contact a real server.
- **Test location & naming (hard):** put each task's tests in
  `scripts/check_<feature>.py`. The repo `.gitignore` ignores `test_*.py` and
  `tests/`, so a file named `test_*.py` would be invisible to review and to git —
  do NOT use that name. Each check script must run as
  `./venv/Scripts/python.exe scripts/check_<feature>.py`, print a clear
  pass/fail summary, and exit non-zero if any assertion fails.
- **Regression gate (hard):** after your change,
  `./venv/Scripts/python.exe scripts/self_test.py` must still exit 0
  (83 tools register, acceptance gate green). Run it and include the result in
  your report.
- **Style:** match the surrounding code. Library modules must not print to
  stdout (the MCP stdio transport reserves stdout for JSON-RPC); if you must log,
  use `mcp_core.diag` or stderr. Do not add new third-party dependencies.
- **Scope discipline:** touch only the task's target engine file and its
  `scripts/check_<feature>.py`. Do not refactor unrelated modules.

## Task 1: Strengthen the parameter fuzzer

Target file: `backend/fuzzer.py`. Test: `scripts/check_fuzzer.py`.

The fuzzer (`run_fuzz_attack`, `BUILTIN_PAYLOADS`, `generate_waf_evasion_variants`,
and the anomaly heuristics) powers the `fuzz_endpoint` MCP tool. Read the whole
file first.

**1a. Fix two latent bugs (confirmed, currently masked by bare `except`):**
- In `run_fuzz_attack`, the CapturedPayload persistence block references
  `payload_type`, which is never defined in the function → `NameError` →
  silently swallowed, so fuzz anomalies are never written to the Payload Vault.
  Fix it so the vault record stores a correct vulnerability category. Derive the
  category by adding a new **optional** parameter `payload_type: Optional[str] = None`
  to `run_fuzz_attack` (additive — keep it last, default `None`); when `None`,
  fall back to `"CUSTOM"`. Thread it through from callers only if trivial and
  backward-compatible; otherwise defaulting to `None`/`"CUSTOM"` is sufficient.
- `run_fuzz_attack` calls `json.dumps(...)` in the clean-session logging path but
  `json` is not imported in this module → `NameError` → swallowed, so the
  "clean fuzzing session" log is never recorded. Add `import json`.
- Both blocks are wrapped in `except Exception: pass`. Replace those two bare
  passes with `mcp_core.diag.exc("fuzzer: ...")` so future failures are visible
  under `PROXSYNTH_DEBUG` (import `from mcp_core import diag`).

**1b. Expand `BUILTIN_PAYLOADS`** with new categories and additional entries:
- Add categories: `nosqli` (e.g. `{"$ne": null}`, `{"$gt": ""}`, `';return true;//`,
  `[$ne]=1`), `xxe` (classic external-entity + parameter-entity SSRF forms),
  `ssrf` (e.g. `http://169.254.169.254/latest/meta-data/`, `http://127.0.0.1:80`,
  `file:///etc/passwd`, `gopher://`), `crlf` (e.g. `%0d%0aSet-Cookie:x=1`),
  `open_redirect` (e.g. `//evil.example`, `https:evil.example`, `/\evil.example`).
- Add several modern entries to existing `sqli`, `xss`, and `ssti` lists
  (e.g. time-based SQLi for Postgres/MSSQL, polyglot XSS, Jinja/Twig/Freemarker
  SSTI). Keep all existing entries.

**1c. Strengthen anomaly detection** in the worker's heuristics:
- Generalize the SSTI arithmetic check beyond the hard-coded `7*7`→`49`: detect
  any payload containing an arithmetic SSTI probe whose evaluated product appears
  in the response but not the baseline (e.g. `{{7*7}}`, `${9*9}`, `#{6*6}` →
  look for `49`/`81`/`36` accordingly). Keep a backward-compatible
  `"SSTI_EVALUATED_49"` anomaly when it is specifically 49, and add a general
  `"SSTI_EVALUATED"` anomaly otherwise.
- Add NoSQL error signatures and command-injection evidence (e.g. `uid=`/`gid=`
  from `id`, `root:.*:0:0:` from `/etc/passwd`) as new anomaly strings.
- Add a few more SQL error patterns to `SQL_ERROR_PATTERNS` (MSSQL, Oracle, DB2).

**1d. Tests (`scripts/check_fuzzer.py`), offline only:**
- Assert the new payload categories exist and existing ones retained/grew.
- Call `generate_waf_evasion_variants` and assert the expected variant types.
- Unit-test the detection logic. If the SSTI/NoSQL/cmdi evaluation is inline in
  the async worker, refactor it into a module-level pure helper
  (e.g. `detect_anomalies(payload, response_text, baseline_text, status, baseline_status, duration_ms, baseline_duration_ms) -> List[str]`)
  and have the worker call it; then unit-test the helper with synthetic inputs
  (reflected payload, SQL error body, `{{7*7}}`→`49`, `/etc/passwd` content,
  status shift, large delta). No network.

**Acceptance:** two bugs fixed; new categories + detection present; the two
previously-dead code paths now reachable; `scripts/check_fuzzer.py` passes;
`scripts/self_test.py` still exits 0.

## Task 2: Deepen the JWT security audit

Target file: `backend/jwt_tester.py`. Test: `scripts/check_jwt.py`.

Powers `audit_jwt_security`. Key existing helpers: `parse_jwt`, `b64url_decode`,
`b64url_encode`, `crack_weak_secret`, `forge_jwt`, `generate_jwt_attack_variants`,
`audit_jwt_security`. Read the whole file first; keep all signatures and returned
keys backward-compatible (additive only).

**2a. Add attack modes to `generate_jwt_attack_variants`** (each as a labeled
variant in the existing structure):
- **alg confusion RS256→HS256**: if a PEM public key is available (add an
  optional `public_key_pem: Optional[str] = None` parameter), forge a token whose
  `alg` is switched to `HS256` and signed with the public key bytes as the HMAC
  secret. If no key is provided, skip this variant gracefully.
- **`alg: none` family**: ensure variants for `none`/`None`/`NONE` with an empty
  signature exist (add if missing).
- **`kid` injection**: variants that set the header `kid` to a SQLi payload
  (`' OR '1'='1`), a path-traversal value (`../../dev/null`), and a command-ish
  value, to probe kid-based key lookups.
- **`jku`/`x5u` header injection**: variants pointing those headers at an
  attacker-controlled placeholder URL (use a clearly-placeholder host, e.g.
  `https://OAST_CANARY/jwks.json`), to flag servers that fetch remote keys.
- **claim tampering**: escalate common claims (`role`→`admin`, `isAdmin`/`admin`→
  `true`, `sub` swap) — extend what exists.
- **expiry/`nbf` tampering**: a variant that extends/removes `exp` and backdates
  `nbf`, to probe for missing temporal validation.

**2b. Expand `crack_weak_secret`** default wordlist with more common JWT secrets
(e.g. `secret`, `password`, `changeme`, `jwt_secret`, `your-256-bit-secret`,
`supersecret`, framework defaults). Keep the `wordlist` override param working.

**2c. Tests (`scripts/check_jwt.py`), offline only** (no live replay):
- Round-trip `parse_jwt`/`forge_jwt`/`b64url_*` on crafted tokens.
- `crack_weak_secret` recovers a token signed with a known weak secret from the
  default list; returns `None` for a strong random secret.
- `generate_jwt_attack_variants` produces variants for alg:none, alg-confusion
  (when a public key is supplied), kid injection, jku/x5u, claim escalation, and
  expiry tampering — assert each variant is structurally valid (decodable header
  with the expected `alg`/`kid`/claims). No HTTP.

**Acceptance:** new attack modes present and structurally verified; wordlist
expanded; `scripts/check_jwt.py` passes; `scripts/self_test.py` still exits 0.

## Task 3: Deepen the mass-assignment engine

Target file: `backend/mass_assignment_engine.py`. Test: `scripts/check_mass_assignment.py`.

Powers `audit_mass_assignment` (single async HTTP function). Read the whole file
first; keep its signature and returned keys backward-compatible.

**3a. Refactor the pure logic out of the network path (for testability):**
- Extract a module-level pure helper that builds the set of injection payloads
  from a base body + content type, e.g.
  `build_mass_assignment_payloads(base_body: str, content_type: str) -> List[Dict[str, Any]]`
  returning, per attempt, the mutated body, the injected field/value, and a
  label. `audit_mass_assignment` must call this helper (behavior-preserving).
- Extract a pure evaluation helper that decides, given baseline vs. injected
  response (status, length, body, and the injected field), whether the injection
  likely took effect, e.g.
  `evaluate_mass_assignment(injected_field, injected_value, baseline, injected) -> Dict[str, Any]`
  (uses the existing `detect_soft_errors`). `audit_mass_assignment` calls it.

**3b. Broaden coverage:**
- Expand the injected privileged attributes (role/isAdmin/is_admin/permissions/
  verified/email_verified/account_type/tier/plan/balance/credit/discount/
  org_id/tenant_id/owner_id/status/approved/active). Keep existing ones.
- Support JSON body injection (top-level and one nested level), form-urlencoded
  body injection, and query-string injection — chosen by content type / method.
- Confirmation signal: reflect the injected field back in the response, or a
  2xx + meaningful length/soft-error delta vs. baseline.

**3c. Tests (`scripts/check_mass_assignment.py`), offline only:**
- `build_mass_assignment_payloads` for a JSON body produces mutations containing
  each privileged attribute; for a form body produces form-encoded mutations;
  nested injection present for nested JSON.
- `evaluate_mass_assignment` flags a reflected injected field / 2xx+delta as a
  hit and a clean baseline-equal response as not a hit. No HTTP.

**Acceptance:** pure helpers exist and are used by `audit_mass_assignment`
(unchanged public contract); coverage broadened; `scripts/check_mass_assignment.py`
passes; `scripts/self_test.py` still exits 0.

## Task 4: Broaden the attack advisor signal coverage

Target file: `backend/attack_advisor.py`. Test: `scripts/check_attack_advisor.py`.

`suggest_attack_actions(url, method, headers, body, response_status, response_body, log_id)`
is a pure function mapping observed signals to recommended MCP tool calls with
ready args; it feeds `send_http_request`'s `suggested_next_actions` and the
`get_autonomous_attack_guidance` tool. Read the whole file first; keep the
signature and the shape of each recommendation entry backward-compatible
(additive only).

**4a. Add detection signals** (each appends a recommendation with the right MCP
tool name and concrete args), without removing existing ones:
- **Open-redirect / SSRF params**: query/body params named `url`, `redirect`,
  `next`, `return`, `callback`, `dest`, `continue`, `image`, `fetch`, `proxy` →
  recommend `spray_oast_canaries` / `send_http_request` probes.
- **GraphQL**: path ending `/graphql` or body containing `query {`/`mutation {`
  → recommend `inspect_graphql_endpoint`.
- **File-upload**: `multipart/form-data` request or `filename=` in body →
  recommend `audit_file_upload`.
- **CORS misconfig**: response header `Access-Control-Allow-Origin: *` (or
  reflects Origin) with credentials → recommend a focused `send_http_request`
  CORS probe.
- **Auth/JWT**: `Authorization: Bearer <jwt>` present → recommend
  `audit_jwt_security`.
- **IDOR/numeric object id** in path (e.g. `/users/4471`, `/orders/8820`) →
  recommend `test_bola_idor` with the id parameterized.
- **Debug/verbose params** (`debug`, `test`, `admin`, `verbose`) and **mass-assignment**
  shaped mutation endpoints (POST/PUT/PATCH with JSON) → recommend
  `audit_mass_assignment`.
- Dedupe recommendations so the same tool+target is not suggested twice.

**4b. Tests (`scripts/check_attack_advisor.py`), offline only:**
- Drive `suggest_attack_actions` with synthetic inputs for each new signal and
  assert the expected tool appears with plausible args; assert a benign request
  (static GET of a JS asset, 200) yields no spurious high-value recommendations;
  assert dedupe. No network, no DB dependency (pass inputs directly).

**Acceptance:** new signals mapped to correct MCP tools with concrete args;
no duplicate recommendations; existing recommendations preserved;
`scripts/check_attack_advisor.py` passes; `scripts/self_test.py` still exits 0.

## Task 5: Repair the DOM-verification gate and deepen the browser oracle

Target files: `backend/verification_gate.py` and `backend/browser_oracle.py`.
Test: `scripts/check_verification_gate.py`.

`verify_vulnerability_candidate` (`backend/verification_gate.py:19`) is the
"zero-false-positive" oracle that confirms or dismisses findings. Its XSS/DOM
branch calls `verify_dom_execution` (`backend/browser_oracle.py:16`) and reads
the result — but reads the WRONG keys, so it is currently broken. Read both
files fully first. Keep every existing returned-dict key on both functions
(additive only).

**5a. Fix the result-contract mismatch (confirmed bug, P0):**
- `verify_dom_execution` returns: `execution_confirmed` (bool), `verdict`
  (`"CONFIRMED_VULNERABLE_DOM_EXECUTION"` | `"EXECUTION_BLOCKED_BY_CSP"` |
  `"NO_DOM_EXECUTION"` | error verdicts), `evidence` (str), `dialog_fired`,
  `dialog_events`, `csp_violations`, `console_logs`, `page_errors`.
- `verification_gate.py` (~lines 69-77) currently tests
  `res.get("status")=="success" and (res.get("dialog_detected") or
  res.get("sink_triggered"))` and reads `res.get("dialog_message")` — NONE of
  those keys exist, so the branch ALWAYS goes to the FALSE_POSITIVE else-arm.
- Rewrite the interpretation so: `execution_confirmed` / `verdict ==
  "CONFIRMED_VULNERABLE_DOM_EXECUTION"` → `VERIFIED_EXPLOITABLE`, confidence
  1.0, evidence from `res["evidence"]`/`res["dialog_events"]`; `verdict ==
  "NO_DOM_EXECUTION"` → `FALSE_POSITIVE`, confidence 0.1; `verdict ==
  "EXECUTION_BLOCKED_BY_CSP"` → a distinct `MITIGATED_BY_CSP` (or
  `INCONCLUSIVE`) verdict, confidence ~0.4 (NOT a clean false positive — the
  payload parsed but CSP blocked it); error verdicts → `UNCONFIRMED`.
- **Refactor for testability:** extract the oracle-result interpretation into a
  pure module-level helper in `verification_gate.py`, e.g.
  `interpret_dom_oracle_result(res: dict) -> dict` returning
  `{verdict, confidence, verification_evidence}`; the XSS branch calls it. This
  lets tests cover the mapping without launching a browser.

**5b. Deepen `verify_dom_execution` (P1) — additive, keep back-compat keys:**
- Add an optional `oast_token: Optional[str] = None` parameter. When provided,
  treat an observed request to a URL containing that token (seen via a
  `page.on("request", ...)` network hook or in `console_logs`) as additional
  confirmation of execution (exfil/beacon XSS that never opens a dialog). Add a
  new `network_beacons` list and a `beacon_fired` bool to the result.
- Add a canary-function hook: inject an init script defining a uniquely named
  global that, if called by a payload, is recorded (new `canary_fired` bool).
- Detect `document.cookie` read attempts via the init script where feasible
  (new `cookie_access` bool). Keep all of this best-effort and guarded.
- Broaden `execution_confirmed` to be true when ANY of: dialog fired, canary
  fired, or an OAST beacon to the provided token was observed. Preserve the
  existing `dialog_fired`/`verdict`/`evidence` keys and their meanings.

**5c. Tests (`scripts/check_verification_gate.py`), offline only (NO browser,
NO network):**
- Unit-test `interpret_dom_oracle_result` with synthetic oracle dicts:
  `execution_confirmed=True`/confirmed verdict → VERIFIED_EXPLOITABLE conf 1.0;
  `NO_DOM_EXECUTION` → FALSE_POSITIVE conf 0.1; `EXECUTION_BLOCKED_BY_CSP` →
  the mitigated/inconclusive verdict (NOT false positive); an error verdict →
  UNCONFIRMED. Assert the old broken keys are no longer relied upon.
- Do NOT launch Chromium in tests. If you want to sanity-check the oracle's new
  parameter is accepted, assert via signature introspection
  (`inspect.signature`) that `oast_token` exists with default `None` — no live
  browser call.

**Acceptance:** confirmed DOM executions now yield VERIFIED_EXPLOITABLE (not
FALSE_POSITIVE); CSP-blocked is distinct; oracle gains additive beacon/canary
detection without breaking existing keys; `scripts/check_verification_gate.py`
passes; `scripts/self_test.py` still exits 0.
