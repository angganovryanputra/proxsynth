"""Offline checks for the DOM verification gate (no browser, no network)."""
import inspect
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from backend.verification_gate import interpret_dom_oracle_result  # noqa: E402
from backend.browser_oracle import verify_dom_execution  # noqa: E402

failures = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


r = interpret_dom_oracle_result({
    "execution_confirmed": True, "verdict": "CONFIRMED_VULNERABLE_DOM_EXECUTION",
    "evidence": "Dialog alert fired", "dialog_events": [{"type": "alert", "message": "1"}]})
check("confirmed -> VERIFIED_EXPLOITABLE", r["verdict"] == "VERIFIED_EXPLOITABLE")
check("confirmed confidence 1.0", r["confidence"] == 1.0)
check("confirmed evidence carried", "Dialog alert fired" in r["verification_evidence"])

r = interpret_dom_oracle_result({"execution_confirmed": True})
check("execution_confirmed alone -> VERIFIED", r["verdict"] == "VERIFIED_EXPLOITABLE")

r = interpret_dom_oracle_result({"execution_confirmed": False, "verdict": "NO_DOM_EXECUTION"})
check("NO_DOM_EXECUTION -> FALSE_POSITIVE 0.1", r["verdict"] == "FALSE_POSITIVE" and r["confidence"] == 0.1)

r = interpret_dom_oracle_result({"execution_confirmed": False, "verdict": "EXECUTION_BLOCKED_BY_CSP", "evidence": "csp x"})
check("CSP -> MITIGATED_BY_CSP, not FP", r["verdict"] == "MITIGATED_BY_CSP" and r["verdict"] != "FALSE_POSITIVE")
check("CSP confidence ~0.4", abs(r["confidence"] - 0.4) < 1e-9)

for v in ("NAVIGATION_ERROR", "SANDBOX_ERROR"):
    r = interpret_dom_oracle_result({"execution_confirmed": False, "verdict": v, "error": "boom"})
    check(f"{v} -> UNCONFIRMED", r["verdict"] == "UNCONFIRMED" and "boom" in r["verification_evidence"])

r = interpret_dom_oracle_result({})
check("empty dict -> UNCONFIRMED", r["verdict"] == "UNCONFIRMED")

# Old broken keys must not produce VERIFIED
r = interpret_dom_oracle_result({"status": "success", "dialog_detected": True, "sink_triggered": True})
check("legacy keys alone do not verify", r["verdict"] != "VERIFIED_EXPLOITABLE")

check("returns required keys", set(interpret_dom_oracle_result({})) == {"verdict", "confidence", "verification_evidence"})

sig = inspect.signature(verify_dom_execution)
check("oast_token param default None",
      "oast_token" in sig.parameters and sig.parameters["oast_token"].default is None)
check("oast_token is last param", list(sig.parameters)[-1] == "oast_token")
for p in ("url", "payload", "param_name", "trigger_event", "wait_timeout_ms"):
    check(f"existing param {p} kept", p in sig.parameters)

if failures:
    print(f"{len(failures)} FAILED")
    sys.exit(1)
print("ALL PASSED")
