"""
Proxsynth - Multi-Step Stateful Business Logic Workflow Engine
Executes multi-stage stateful HTTP/HTTPS sequences with dynamic parameter extraction,
variable chaining ({{var}}), session identity swapping, and automated logic flaw bypass testing.
"""

import re
import json
import time
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import httpx

from backend.user_agents import apply_rotating_user_agent
from backend.database import SessionLocal, HttpLog, Finding, Project
from backend.intercept_manager import async_check_scope

VARIABLE_PATTERN = re.compile(r"\{\{([a-zA-Z0-9_\-\.]+)\}\}")


def substitute_variables(text: Any, context: Dict[str, Any]) -> Any:
    """Recursively replaces {{var_name}} placeholders with extracted values from context."""
    if isinstance(text, str):
        def _repl(match):
            key = match.group(1).strip()
            return str(context.get(key, match.group(0)))
        return VARIABLE_PATTERN.sub(_repl, text)
    elif isinstance(text, dict):
        return {substitute_variables(k, context): substitute_variables(v, context) for k, v in text.items()}
    elif isinstance(text, list):
        return [substitute_variables(item, context) for item in text]
    return text


def extract_value_from_response(
    source_expr: str,
    status_code: int,
    headers: Dict[str, str],
    body_text: str
) -> Optional[Any]:
    """
    Extracts dynamic tokens or identifiers based on expression:
    - 'json.data.order_id' -> walks json keys
    - 'header.authorization' or 'header.set-cookie'
    - 'regex:token=([a-zA-Z0-9_-]+)'
    - 'status'
    """
    expr = source_expr.strip()

    if expr == "status":
        return status_code

    if expr.startswith("json."):
        path = expr[5:].split(".")
        try:
            curr = json.loads(body_text)
            for part in path:
                if isinstance(curr, dict):
                    curr = curr.get(part)
                elif isinstance(curr, list) and part.isdigit():
                    curr = curr[int(part)]
                else:
                    return None
            return curr
        except Exception:
            return None

    if expr.startswith("header."):
        target_hdr = expr[7:].lower().strip()
        for k, v in headers.items():
            if k.lower() == target_hdr:
                return v
        return None

    if expr.startswith("regex:"):
        pattern = expr[6:].strip()
        try:
            m = re.search(pattern, body_text)
            if m:
                return m.group(1) if m.groups() else m.group(0)
        except Exception:
            return None

    return None


async def run_workflow_sequence(
    steps: List[Dict[str, Any]],
    mutations: Optional[Dict[str, Any]] = None,
    project: str = "default",
    agent_id: str = "primary_agent",
    upstream_proxy: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes a multi-step sequence with automatic state propagation.
    mutations can include:
      - skip_steps: ['step_verify_payment']
      - override_vars: {'amount': '-100'}
      - tamper_step_headers: {'step_3': {'X-Role': 'admin'}}
    """
    context: Dict[str, Any] = {}
    mutations = mutations or {}
    skip_steps = set(mutations.get("skip_steps", []))
    override_vars = mutations.get("override_vars", {})
    context.update(override_vars)

    results: List[Dict[str, Any]] = []
    proxy_kwargs = {}
    if upstream_proxy and upstream_proxy.strip():
        proxy_kwargs["proxy"] = upstream_proxy.strip()
    else:
        proxy_kwargs["proxy"] = None
        proxy_kwargs["trust_env"] = False

    anomalies: List[Dict[str, Any]] = []

    limits = httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0)
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=25.0, limits=limits, **proxy_kwargs) as client:
        for idx, step in enumerate(steps):
            step_name = step.get("name", f"step_{idx + 1}")

            # Check if this step is mutated to be skipped
            if step_name in skip_steps:
                results.append({
                    "step": step_name,
                    "status": "SKIPPED_BY_MUTATION",
                    "details": "Step intentionally bypassed to test business logic authorization"
                })
                continue

            raw_url = step.get("url", "")
            raw_method = (step.get("method") or "GET").upper().strip()
            raw_headers = step.get("headers") or {}
            raw_body = step.get("body") or ""

            # Template variable resolution
            step_url = substitute_variables(raw_url, context)
            step_headers = substitute_variables(raw_headers, context)
            step_body = substitute_variables(raw_body, context)

            if isinstance(step_body, (dict, list)):
                step_body = json.dumps(step_body)
            elif not isinstance(step_body, str):
                step_body = str(step_body) if step_body is not None else ""

            # Ensure legitimate browser User-Agent
            apply_rotating_user_agent(step_headers)

            # Validate against project scope guardrails
            db_scope = SessionLocal()
            try:
                is_allowed, block_reason = await async_check_scope(project, step_url, db_scope)
                if not is_allowed:
                    results.append({
                        "step": step_name,
                        "status": "BLOCKED_BY_SCOPE",
                        "details": f"Target URL is out of authorized scope: {block_reason}"
                    })
                    continue
            finally:
                db_scope.close()

            t0 = time.time()
            res_status = None
            res_headers = {}
            res_body = ""
            error = None

            try:
                b_bytes = step_body.encode("utf-8") if step_body else None
                resp = await client.request(
                    method=raw_method,
                    url=step_url,
                    headers=step_headers,
                    content=b_bytes
                )
                res_status = resp.status_code
                res_headers = dict(resp.headers)
                res_body = resp.text
            except Exception as ex:
                error = str(ex)

            dur_ms = int((time.time() - t0) * 1000)

            # Extract variables from response into context
            extracted_vars = {}
            for var_name, source_expr in (step.get("extract") or {}).items():
                val = extract_value_from_response(source_expr, res_status or 0, res_headers, res_body)
                if val is not None:
                    context[var_name] = val
                    extracted_vars[var_name] = val

            step_result = {
                "step": step_name,
                "method": raw_method,
                "url": step_url,
                "duration_ms": dur_ms,
                "status_code": res_status,
                "extracted_variables": extracted_vars,
                "response_body_preview": res_body[:500] if res_body else "",
                "error": error
            }
            results.append(step_result)

            # Record step execution to Proxsynth HttpLog (Proxy History)
            try:
                from backend.forward_proxy import _dispatch_log
                parsed_step = urllib.parse.urlparse(step_url)
                await _dispatch_log({
                    "project": project,
                    "agent_id": agent_id,
                    "source": "WORKFLOW_ENGINE",
                    "method": raw_method,
                    "url": step_url,
                    "host": parsed_step.netloc,
                    "path": parsed_step.path or "/",
                    "status_code": res_status,
                    "duration_ms": dur_ms,
                    "request_headers": step_headers,
                    "request_body": step_body or "",
                    "response_headers": res_headers,
                    "response_body": res_body,
                    "reasoning": f"[Workflow Sequence: {step_name}] Extracted vars: {list(extracted_vars.keys())}"
                })
            except Exception:
                pass

            # Logic flaw analysis
            expected_status = step.get("expected_status")
            if expected_status:
                exp_list = expected_status if isinstance(expected_status, list) else [expected_status]
                if res_status not in exp_list:
                    anomalies.append({
                        "type": "STATUS_MISMATCH",
                        "step": step_name,
                        "expected": exp_list,
                        "received": res_status,
                        "message": f"Step '{step_name}' returned status {res_status} instead of expected {exp_list}"
                    })

    # Check for Business Logic Bypass if critical steps were skipped
    if skip_steps:
        # If final step succeeded with 200/201 despite skipping prerequisite step
        final_executed = [r for r in results if r.get("status_code")]
        if final_executed:
            last_res = final_executed[-1]
            if last_res.get("status_code") in [200, 201, 204]:
                anomalies.append({
                    "type": "BUSINESS_LOGIC_BYPASS_CONFIRMED",
                    "severity": "CRITICAL",
                    "skipped_steps": list(skip_steps),
                    "final_status": last_res.get("status_code"),
                    "final_url": last_res.get("url"),
                    "description": f"Workflow completed successfully ({last_res.get('status_code')}) even after skipping required steps: {list(skip_steps)}"
                })

    return {
        "status": "COMPLETED",
        "total_steps": len(steps),
        "executed_steps": len([r for r in results if r.get("status") != "SKIPPED_BY_MUTATION"]),
        "context_state": context,
        "anomalies": anomalies,
        "results": results
    }


async def execute_workflow(
    sequence: List[Dict[str, Any]],
    initial_context: Optional[Dict[str, Any]] = None,
    project: str = "default",
    agent_id: str = "primary_agent",
    test_step_skipping: bool = False,
    upstream_proxy: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level orchestrator for multi-step stateful business logic testing.
    Executes standard sequence and optionally conducts automated step-skipping
    to detect state machine bypasses.
    """
    initial_context = initial_context or {}
    base_result = await run_workflow_sequence(
        steps=sequence,
        mutations={"override_vars": initial_context},
        project=project,
        agent_id=agent_id,
        upstream_proxy=upstream_proxy
    )

    all_succeeded = (
        len(base_result["results"]) > 0
        and all(r.get("status_code") in [200, 201, 204] for r in base_result["results"])
    )

    skip_tests = []
    if test_step_skipping and len(sequence) >= 2:
        # Test skipping intermediate steps
        for skip_idx in range(len(sequence) - 1):
            target_step = sequence[skip_idx]
            step_name = target_step.get("name", f"step_{skip_idx + 1}")

            # Re-run with step intentionally skipped
            mutated_result = await run_workflow_sequence(
                steps=sequence,
                mutations={"skip_steps": [step_name], "override_vars": dict(base_result["context_state"])},
                project=project,
                upstream_proxy=upstream_proxy
            )

            # Check if an anomaly was detected
            bypass = any(
                a.get("type") == "BUSINESS_LOGIC_BYPASS_CONFIRMED"
                for a in mutated_result.get("anomalies", [])
            )
            skip_tests.append({
                "skipped_step": step_name,
                "potential_logic_bypass": bypass,
                "anomalies": mutated_result.get("anomalies", []),
                "summary": f"Step '{step_name}' skipped. {'CRITICAL: Sequence succeeded without prerequisite!' if bypass else 'Enforcement intact.'}"
            })

    return {
        "status": "COMPLETED",
        "all_steps_succeeded": all_succeeded,
        "step_results": base_result["results"],
        "context_extracted": base_result["context_state"],
        "anomalies": base_result["anomalies"],
        "step_skip_tests": skip_tests
    }

