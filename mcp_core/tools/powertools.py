"""
PROXSYNTH MCP — CONSOLIDATED UNIFIED POWER TOOLS
Provides 7 high-leverage, multi-action domain power tools consolidating fragmented operations:
1. manage_pentest_execution (Run, Record External, Capture Script with AST, Replay with Mutations)
2. manage_attack_surface (Batch Ingestion, Add Node, Delete, Clear, Get Graph)
3. analyze_and_diff_traffic (Semantic Diff, Raw Diff, Distill Noise, Pattern Analysis)
4. manage_interception_rules (List, Add, Toggle, Delete Interception Rules)
5. manage_session_vault (CSRF Tokens & Multi-Role Active Identity Sessions)
6. manage_oast_and_tunnels (Canary Generation, Spraying, Event Polling, Tunnel Control)
7. manage_testing_agenda (Hypotheses Agenda Planning & Execution Trace)
"""

import os
import sys
import json
import time
import asyncio
import re
from typing import Optional, Dict, Any, List, Literal

from mcp_core.server import proxsynth_tool
from mcp_core.gateway import (
    _resolve_project,
    _persist_and_stream_command,
    _persist_and_stream_payload,
    _persist_and_stream_log
)
from backend.database import SessionLocal, HttpLog, AgentCommandLog, CapturedPayload, Project, ActiveSession
from backend.security_utils import async_check_command_safe_mode
CURRENT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.payload_vault import auto_vault_script_payloads
from sqlalchemy import func


# ==============================================================================
# POWER TOOL 1: manage_pentest_execution
# ==============================================================================
@proxsynth_tool(name="manage_pentest_execution")
async def manage_pentest_execution(
    action: Literal["execute", "execute_sandbox_command", "record_external", "capture_script", "replay"] = "execute",
    command: Optional[str] = None,
    script_path: Optional[str] = None,
    script_content: Optional[str] = None,
    script_name: Optional[str] = None,
    reasoning: str = "",
    target_url: Optional[str] = None,
    timeout: int = 60,
    cwd: str = "",
    tool_name: str = "terminal",
    agent_id: str = "primary_agent",
    project: Optional[str] = None,
    stdout: Optional[str] = "",
    stderr: Optional[str] = "",
    exit_code: Optional[int] = 0,
    duration_ms: Optional[int] = 0,
    replay_command_id: Optional[int] = None,
    mutations: Optional[str] = None
) -> str:
    """
    Unified Pentest Command & Exploit Script Intelligence Hub.
    - 'execute': Runs shell command in Proxsynth proxy sandbox, intercepts traffic, links logs, & vaults payloads.
    - 'record_external': Records a command executed outside Proxsynth (IDE terminal / external tool).
    - 'capture_script': Ingests an exploit/PoC/test script, runs Deep AST parsing, & vaults attack vectors.
    - 'replay': Re-executes a previously logged command with optional mutations & computes response diff.
    """
    target_project = _resolve_project(project, allow_all=False)
    target_agent = (agent_id or "primary_agent").strip()

    # --------------------------------------------------------------------------
    # ACTION: capture_script
    # --------------------------------------------------------------------------
    if action == "capture_script":
        code = (script_content or "").strip()
        work_dir = CURRENT_DIR if not cwd or not os.path.isdir(cwd) else os.path.abspath(cwd)
        resolved_name = script_name or "exploit_script.py"

        if script_path:
            p = script_path if os.path.isabs(script_path) else os.path.join(work_dir, script_path)
            if os.path.isfile(p):
                resolved_name = os.path.basename(p)
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        code = f.read()
                except Exception as ex:
                    return json.dumps({"status": "FAILED", "error": f"Failed reading script file: {ex}"})

        if not code:
            return json.dumps({"status": "FAILED", "error": "No script content or valid script_path provided."})

        # Deep AST & Pattern extraction into Payload Vault
        db = SessionLocal()
        created_payload_dicts = []
        try:
            created_payloads = auto_vault_script_payloads(
                db=db,
                project=target_project,
                agent_id=target_agent,
                script_content=code,
                command=f"# Ingested script: {resolved_name}"
            )
            for p_obj in created_payloads:
                created_payload_dicts.append(p_obj.to_dict())
        finally:
            db.close()

        # Log to AgentCommandLog
        cmd_payload = {
            "project": target_project,
            "agent_id": target_agent,
            "command": f"# SCRIPT INGEST: {resolved_name}",
            "tool_name": "script_vault",
            "reasoning": reasoning or f"Registered pentest script {resolved_name}",
            "exit_code": 0,
            "stdout": f"Successfully ingested {len(code.splitlines())} lines of code. Extracted {len(created_payload_dicts)} attack vectors.",
            "stderr": "",
            "duration_ms": 0,
            "status": "CAPTURED",
            "script_content": code
        }
        cmd_id = await _persist_and_stream_command(cmd_payload)

        return json.dumps({
            "status": "SUCCESS",
            "command_id": cmd_id,
            "project": target_project,
            "script_name": resolved_name,
            "lines_of_code": len(code.splitlines()),
            "payloads_vaulted_count": len(created_payload_dicts),
            "vaulted_payloads": created_payload_dicts[:10]
        }, indent=2)

    # --------------------------------------------------------------------------
    # ACTION: record_external
    # --------------------------------------------------------------------------
    elif action == "record_external":
        cmd_str = (command or "").strip()
        if not cmd_str:
            return json.dumps({"status": "FAILED", "error": "Command string cannot be empty for record_external."})

        cmd_payload = {
            "project": target_project,
            "agent_id": target_agent,
            "command": cmd_str,
            "tool_name": tool_name or "external_terminal",
            "reasoning": reasoning or "Recorded external CLI pentest activity",
            "exit_code": exit_code if exit_code is not None else 0,
            "stdout": stdout or "",
            "stderr": stderr or "",
            "duration_ms": duration_ms or 0,
            "status": "SUCCESS" if (exit_code == 0) else "FAILED",
            "script_content": script_content or ""
        }
        cmd_id = await _persist_and_stream_command(cmd_payload)

        # Correlate with recent HTTP logs in target project
        linked_log_id = None
        db = SessionLocal()
        try:
            recent_log = db.query(HttpLog).filter(HttpLog.project == target_project).order_by(HttpLog.id.desc()).first()
            if recent_log:
                linked_log_id = recent_log.id
                recent_log.command_id = cmd_id
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

        return json.dumps({
            "status": "SUCCESS",
            "command_id": cmd_id,
            "project": target_project,
            "linked_log_id": linked_log_id,
            "message": f"External command #{cmd_id} successfully recorded and vaulted in Proxsynth."
        }, indent=2)

    # --------------------------------------------------------------------------
    # ACTION: replay
    # --------------------------------------------------------------------------
    elif action == "replay":
        if not replay_command_id:
            return json.dumps({"status": "FAILED", "error": "replay_command_id is required for replay action."})

        db = SessionLocal()
        original_entry = None
        try:
            original_entry = db.query(AgentCommandLog).filter(AgentCommandLog.id == replay_command_id).first()
        finally:
            db.close()

        if not original_entry:
            return json.dumps({"status": "FAILED", "error": f"Command #{replay_command_id} not found."})

        exec_cmd = original_entry.command
        # Apply mutations if specified
        if mutations:
            try:
                mut_dict = json.loads(mutations) if isinstance(mutations, str) else mutations
                for old_val, new_val in mut_dict.items():
                    exec_cmd = exec_cmd.replace(old_val, str(new_val))
            except Exception:
                pass

        # Execute replayed command via execute path
        return await manage_pentest_execution(
            action="execute",
            command=exec_cmd,
            reasoning=f"Replay of Command #{replay_command_id}. " + (reasoning or ""),
            project=target_project,
            agent_id=target_agent,
            timeout=timeout,
            cwd=cwd
        )

    # --------------------------------------------------------------------------
    # ACTION: execute (Default Execution in Proxy Sandbox)
    # --------------------------------------------------------------------------
    cmd_clean = (command or "").strip()
    if not cmd_clean:
        return json.dumps({"status": "FAILED", "error": "command is required for execute action."})

    # Scope & Safe-mode check
    db = SessionLocal()
    allow_internal = True
    min_log_id = 0
    try:
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            allow_internal = bool(proj_obj.allow_internal_networks)
        min_log_id = db.query(func.max(HttpLog.id)).filter(HttpLog.project == target_project).scalar() or 0
    finally:
        db.close()

    is_safe, block_reason = await async_check_command_safe_mode(cmd_clean, allow_internal=allow_internal)
    if not is_safe:
        return json.dumps({
            "status": "BLOCKED",
            "reason": block_reason,
            "message": "Blocked by Proxsynth Safe-Mode guardrail."
        }, indent=2)

    work_dir = CURRENT_DIR if not cwd or not os.path.isdir(cwd) else os.path.abspath(cwd)

    # Auto-detect script content
    effective_script_content = (script_content or "").strip()
    if not effective_script_content:
        m_script = re.search(r'(?:python3?|bash|sh|node)\s+([^\s\'\"]+\.(?:py|sh|js|rb|pl|php))', cmd_clean, re.IGNORECASE)
        if m_script:
            candidate_file = m_script.group(1).strip()
            resolved_path = candidate_file if os.path.isabs(candidate_file) else os.path.join(work_dir, candidate_file)
            if os.path.isfile(resolved_path) and os.path.getsize(resolved_path) <= 524288:
                try:
                    with open(resolved_path, "r", encoding="utf-8", errors="replace") as sf:
                        effective_script_content = sf.read()
                except Exception:
                    pass

    proxy_port = int(os.getenv("PROXSYNTH_PROXY_PORT", "8088"))
    try:
        from backend.forward_proxy import ensure_forward_proxy_running
        await ensure_forward_proxy_running(port=proxy_port)
    except Exception:
        pass

    proxy_url = f"http://{target_project}:{target_agent}@127.0.0.1:{proxy_port}"
    sub_env = os.environ.copy()
    sub_env["HTTP_PROXY"] = proxy_url
    sub_env["HTTPS_PROXY"] = proxy_url
    sub_env["ALL_PROXY"] = proxy_url
    sub_env["PYTHONHTTPSVERIFY"] = "0"
    sub_env["CURL_INSECURE"] = "1"
    sub_env["PROXSYNTH_PROJECT"] = target_project

    # Windows curl auto-fix
    cmd_exec = cmd_clean
    if "curl" in cmd_clean.lower() and "-k" not in cmd_clean and "--insecure" not in cmd_clean:
        cmd_exec = re.sub(r"\bcurl(\.exe)?\b", r"curl.exe -k", cmd_clean, flags=re.IGNORECASE, count=1)

    t_start = time.time()
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_exec,
            cwd=work_dir,
            env=sub_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=float(timeout or 60))
            out_txt = out_b.decode("utf-8", errors="replace")
            err_txt = err_b.decode("utf-8", errors="replace")
            ret_code = proc.returncode or 0
            status_str = "SUCCESS" if ret_code == 0 else "FAILED"
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            ret_code = -1
            status_str = "TIMEOUT"
            out_txt = ""
            err_txt = f"Execution timed out after {timeout}s."
    except Exception as ex:
        ret_code = 1
        status_str = "FAILED"
        out_txt = ""
        err_txt = f"Subprocess failed: {ex}"

    dur_ms = int((time.time() - t_start) * 1000)

    # Correlate generated HTTP logs with this command execution
    max_log_id = min_log_id
    linked_log_ids = []
    db = SessionLocal()
    try:
        max_log_id = db.query(func.max(HttpLog.id)).filter(HttpLog.project == target_project).scalar() or min_log_id
        if max_log_id > min_log_id:
            linked_log_ids = list(range(min_log_id + 1, max_log_id + 1))
    finally:
        db.close()

    primary_log_id = linked_log_ids[-1] if linked_log_ids else None

    # Persist command log
    cmd_payload = {
        "project": target_project,
        "agent_id": target_agent,
        "command": cmd_clean,
        "tool_name": tool_name or "terminal",
        "reasoning": reasoning or "",
        "exit_code": ret_code,
        "stdout": out_txt,
        "stderr": err_txt,
        "duration_ms": dur_ms,
        "status": status_str,
        "linked_log_id": primary_log_id,
        "script_content": effective_script_content
    }
    cmd_id = await _persist_and_stream_command(cmd_payload)

    # Tag HTTP logs with command_id
    if linked_log_ids and cmd_id:
        db = SessionLocal()
        try:
            db.query(HttpLog).filter(HttpLog.id.in_(linked_log_ids)).update({"command_id": cmd_id}, synchronize_session=False)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    return json.dumps({
        "status": status_str,
        "command_id": cmd_id,
        "project": target_project,
        "exit_code": ret_code,
        "duration_ms": dur_ms,
        "linked_http_logs_count": len(linked_log_ids),
        "linked_log_ids": linked_log_ids,
        "stdout": out_txt[:5000],
        "stderr": err_txt[:2000],
        "script_captured": bool(effective_script_content)
    }, indent=2)


# ==============================================================================
# POWER TOOL 2: manage_attack_surface
# ==============================================================================
@proxsynth_tool(name="manage_attack_surface")
async def manage_attack_surface(
    action: Literal["add_asset", "upsert_asset", "add_service", "upsert_service", "add_endpoint", "upsert_endpoint", "batch_ingest", "delete", "clear", "get_graph", "scope_recon", "recon", "exploit_chains", "synthesize_chains"] = "get_graph",
    project: Optional[str] = None,
    host: Optional[str] = None,
    target: Optional[str] = None,
    ip_address: Optional[str] = None,
    port: Optional[int] = None,
    service_name: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    method: str = "GET",
    batch_items: Optional[str] = None,
    node_id: Optional[int] = None,
    node_type: str = "endpoint",
    notes: str = ""
) -> str:
    """
    Unified Target Knowledge Graph Manager.
    Consolidates asset, service, and endpoint mapping, batch ingestion, graph deletion, and visualization.
    """
    from backend.target_manager import (
        upsert_target_asset,
        add_or_update_service,
        add_or_update_endpoint,
        get_attack_surface_graph,
        delete_target_asset,
        delete_target_service,
        delete_target_endpoint,
        clear_target_graph
    )
    target_project = _resolve_project(project, allow_all=(action == "get_graph"))

    if action == "get_graph":
        res = get_attack_surface_graph(project=target_project)
        return json.dumps(res, indent=2)

    elif action == "clear":
        res = clear_target_graph(project=target_project)
        return json.dumps({"status": "SUCCESS", "message": f"Attack surface graph cleared for {target_project}"}, indent=2)

    elif action == "delete":
        if not node_id:
            return json.dumps({"status": "FAILED", "error": "node_id required for delete."})
        if node_type == "asset":
            res = delete_target_asset(node_id, project=target_project)
        elif node_type == "service":
            res = delete_target_service(node_id, project=target_project)
        else:
            res = delete_target_endpoint(node_id, project=target_project)
        return json.dumps({"status": "SUCCESS", "deleted": res}, indent=2)

    effective_host = (host or target or "").strip()
    effective_endpoint = (endpoint_url or target or "").strip()

    if action in ["add_asset", "upsert_asset"]:
        if not effective_host:
            return json.dumps({"status": "FAILED", "error": "host (or target) is required for add_asset/upsert_asset."})
        res = upsert_target_asset(project=target_project, host=effective_host, ip=ip_address or "", notes=notes)
        return json.dumps({"status": "SUCCESS", "asset": res}, indent=2)

    elif action in ["add_service", "upsert_service"]:
        if not effective_host or not port:
            return json.dumps({"status": "FAILED", "error": "host (or target) and port are required for add_service/upsert_service."})
        res = add_or_update_service(project=target_project, host=effective_host, port=port, service_name=service_name or "http")
        return json.dumps({"status": "SUCCESS", "service": res}, indent=2)

    elif action in ["add_endpoint", "upsert_endpoint"]:
        if not effective_host or not effective_endpoint:
            return json.dumps({"status": "FAILED", "error": "host and endpoint_url (or target) are required for add_endpoint/upsert_endpoint."})
        res = add_or_update_endpoint(project=target_project, host=effective_host, url=effective_endpoint, method=method, notes=notes)
        return json.dumps({"status": "SUCCESS", "endpoint": res}, indent=2)

    elif action == "batch_ingest":
        if not batch_items:
            return json.dumps({"status": "FAILED", "error": "batch_items (JSON array) is required for batch_ingest."})
        try:
            items = json.loads(batch_items) if isinstance(batch_items, str) else batch_items
        except Exception as ex:
            return json.dumps({"status": "FAILED", "error": f"Invalid JSON in batch_items: {ex}"})

        ingested = 0
        for it in items:
            h = it.get("host")
            u = it.get("url")
            p = it.get("port")
            m = it.get("method", "GET")
            n = it.get("notes", "Batch Ingestion")
            if h and u:
                add_or_update_endpoint(project=target_project, host=h, url=u, method=m, notes=n)
                ingested += 1
            elif h and p:
                add_or_update_service(project=target_project, host=h, port=p, service_name=it.get("service_name", "unknown"))
                ingested += 1
            elif h:
                upsert_target_asset(project=target_project, host=h, ip=it.get("ip_address") or it.get("ip") or "", notes=n)
                ingested += 1

        return json.dumps({"status": "SUCCESS", "project": target_project, "ingested_count": ingested}, indent=2)

    elif action in ["scope_recon", "recon"]:
        from backend.scope_recon import auto_ingest_scope_targets
        target_domain = effective_host or target_project
        res = auto_ingest_scope_targets(domain=target_domain, project=target_project)
        return json.dumps(res, indent=2)

    elif action in ["exploit_chains", "synthesize_chains"]:
        from backend.exploit_chainer import synthesize_exploit_chains
        res = synthesize_exploit_chains(project=target_project)
        return json.dumps(res, indent=2)

    return json.dumps({"status": "FAILED", "error": f"Unknown action '{action}'"})


# ==============================================================================
# POWER TOOL 3: analyze_and_diff_traffic
# ==============================================================================
@proxsynth_tool(name="analyze_and_diff_traffic")
async def analyze_and_diff_traffic(
    mode: Literal["semantic_diff", "raw_diff", "distill_noise", "cluster_patterns", "strip_noise"] = "semantic_diff",
    log_id_a: Optional[int] = None,
    log_id_b: Optional[int] = None,
    text_a: Optional[str] = None,
    text_b: Optional[str] = None,
    project: Optional[str] = None,
    limit: int = 50
) -> str:
    """
    Unified HTTP Traffic Comparison, Semantic Diffing & Pattern Distiller.
    Supports semantic noise filtering, line-by-line diffs, DOM-based distillation, and traffic pattern clustering.
    """
    from backend.diff_engine import compute_semantic_diff
    from backend.body_distiller import distill_response_body
    from backend.analyzer import analyze_traffic
    target_project = _resolve_project(project, allow_all=True)

    if mode == "semantic_diff":
        db = SessionLocal()
        b_a, b_b = (text_a or ""), (text_b or "")
        try:
            if log_id_a:
                row_a = db.query(HttpLog).filter(HttpLog.id == log_id_a).first()
                if row_a:
                    b_a = row_a.response_body or ""
            if log_id_b:
                row_b = db.query(HttpLog).filter(HttpLog.id == log_id_b).first()
                if row_b:
                    b_b = row_b.response_body or ""
        finally:
            db.close()

        resp_a = {"status_code": 200, "headers": {}, "body": b_a} if isinstance(b_a, str) else b_a
        resp_b = {"status_code": 200, "headers": {}, "body": b_b} if isinstance(b_b, str) else b_b
        diff_res = compute_semantic_diff(resp_a, resp_b)
        return json.dumps({
            "status": "SUCCESS",
            "mode": "semantic_diff",
            "log_id_a": log_id_a,
            "log_id_b": log_id_b,
            "similarity_ratio": diff_res.get("similarity_ratio", 1.0),
            "meaningful_change_detected": diff_res.get("is_different", False),
            "diff_summary": diff_res.get("diff_summary", "")
        }, indent=2)

    elif mode in ["distill_noise", "strip_noise"]:
        body_to_distill = text_a or ""
        if log_id_a and not body_to_distill:
            db = SessionLocal()
            try:
                row = db.query(HttpLog).filter(HttpLog.id == log_id_a).first()
                if row:
                    body_to_distill = row.response_body or ""
            finally:
                db.close()

        distilled = distill_response_body(body_to_distill)
        from backend.semantic_fuzzer import strip_dynamic_noise
        noise_stripped = strip_dynamic_noise(body_to_distill)
        return json.dumps({
            "status": "SUCCESS",
            "mode": mode,
            "log_id": log_id_a,
            "distilled": distilled,
            "noise_stripped": noise_stripped
        }, indent=2)

    elif mode == "cluster_patterns":
        db = SessionLocal()
        patterns = []
        try:
            q = db.query(HttpLog)
            if target_project and target_project not in ("all", "*", "any", "global"):
                q = q.filter(HttpLog.project == target_project)
            rows = q.order_by(HttpLog.id.desc()).limit(limit).all()
            patterns = [{"id": r.id, "method": r.method, "path": r.path, "status": r.status_code} for r in rows]
        finally:
            db.close()
        return json.dumps({"status": "SUCCESS", "mode": "cluster_patterns", "project": target_project, "patterns": patterns}, indent=2)

    else:
        # raw_diff
        resp_a = {"status_code": 200, "headers": {}, "body": text_a or ""}
        resp_b = {"status_code": 200, "headers": {}, "body": text_b or ""}
        diff_res = compute_semantic_diff(resp_a, resp_b)
        if isinstance(diff_res, dict) and "status" not in diff_res:
            diff_res["status"] = "SUCCESS"
        return json.dumps(diff_res, indent=2)


# ==============================================================================
# POWER TOOL 4: manage_interception_rules
# ==============================================================================
@proxsynth_tool(name="manage_interception_rules")
async def manage_interception_rules(
    action: Literal["list", "list_rules", "add", "add_rule", "toggle", "toggle_rule", "delete", "delete_rule"] = "list",
    rule_id: Optional[int] = None,
    name: Optional[str] = None,
    rule_type: str = "REQUEST",
    match_url: str = "*",
    match_method: str = "*",
    action_type: str = "REPLACE_HEADER",
    action_target: str = "",
    action_value: str = "",
    enabled: Optional[bool] = None,
    project: Optional[str] = None
) -> str:
    """
    Unified Forward Proxy Interception & Mock Rule Manager.
    Lists active rules, creates request/response rewrites, toggles mock state, and deletes interception traps.
    """
    from backend.interception_engine import (
        list_interception_rules,
        add_interception_rule,
        toggle_interception_rule,
        delete_interception_rule
    )
    target_project = _resolve_project(project, allow_all=(action in ["list", "list_rules"]))

    if action in ["list", "list_rules"]:
        rules = list_interception_rules(project=target_project)
        return json.dumps({"status": "SUCCESS", "project": target_project, "rules": rules}, indent=2)

    elif action in ["add", "add_rule"]:
        if not name:
            return json.dumps({"status": "FAILED", "error": "name is required to add rule."})
        res = add_interception_rule(
            name=name,
            project=target_project,
            rule_type=rule_type,
            match_url=match_url,
            match_method=match_method,
            action_type=action_type,
            action_target=action_target,
            action_value=action_value
        )
        return json.dumps({"status": "SUCCESS", "rule": res}, indent=2)

    elif action in ["toggle", "toggle_rule"]:
        if not rule_id:
            return json.dumps({"status": "FAILED", "error": "rule_id is required to toggle."})
        res = toggle_interception_rule(rule_id=rule_id, enabled=enabled)
        return json.dumps({"status": "SUCCESS", "rule": res}, indent=2)

    elif action in ["delete", "delete_rule"]:
        if not rule_id:
            return json.dumps({"status": "FAILED", "error": "rule_id is required to delete."})
        ok = delete_interception_rule(rule_id=rule_id)
        return json.dumps({"status": "SUCCESS" if ok else "NOT_FOUND", "deleted_rule_id": rule_id}, indent=2)

    return json.dumps({"status": "FAILED", "error": f"Unknown action '{action}'"})


# ==============================================================================
# POWER TOOL 5: manage_session_vault
# ==============================================================================
@proxsynth_tool(name="manage_session_vault")
async def manage_session_vault(
    action: Literal["get_csrf", "set_csrf", "clear_csrf", "set_role_session", "list_identities", "get_identities"] = "get_csrf",
    domain: Optional[str] = None,
    role: str = "primary",
    token_name: Optional[str] = None,
    token_value: Optional[str] = None,
    cookies: Optional[str] = None,
    headers: Optional[str] = None,
    project: Optional[str] = None
) -> str:
    """
    Unified Session, Anti-CSRF Token Vault & Multi-Persona Identity Manager.
    Manages active session cookies for victim/attacker/admin personas and resolves anti-CSRF tokens for replaying attacks.
    """
    from backend.session_tracker import (
        get_tracked_csrf_tokens,
        set_manual_csrf_token,
        clear_tracked_csrf_tokens
    )
    target_project = _resolve_project(project, allow_all=(action in ["list_identities", "get_identities"]))

    if action in ["list_identities", "get_identities"]:
        from backend.bola_matrix import get_identities_for_project
        identities = get_identities_for_project(project=target_project, domain=domain)
        return json.dumps({"status": "SUCCESS", "project": target_project, "identities": identities}, indent=2)

    elif action == "get_csrf":
        t_dict = get_tracked_csrf_tokens(domain=domain or "", project=target_project)
        return json.dumps({"status": "SUCCESS", "project": target_project, "domain": domain or "*", "csrf_tokens": t_dict}, indent=2)

    elif action == "set_csrf":
        if not token_name or not token_value or not domain:
            return json.dumps({"status": "FAILED", "error": "domain, token_name, and token_value required."})
        rec = set_manual_csrf_token(domain=domain, token_name=token_name, token_value=token_value, project=target_project)
        return json.dumps({"status": "SUCCESS", "domain": domain, "token": token_name}, indent=2)

    elif action == "clear_csrf":
        clear_tracked_csrf_tokens(domain=domain or "", project=target_project)
        return json.dumps({"status": "SUCCESS", "message": "CSRF tokens cleared."}, indent=2)

    elif action == "set_role_session":
        if not domain:
            return json.dumps({"status": "FAILED", "error": "domain required for set_role_session."})
        db = SessionLocal()
        try:
            sess = db.query(ActiveSession).filter(
                ActiveSession.project == target_project,
                ActiveSession.domain == domain.strip().lower(),
                ActiveSession.identity_role == (role or "primary").lower()
            ).first()

            parsed_cookies = json.loads(cookies) if cookies and isinstance(cookies, str) else (cookies or {})
            parsed_headers = json.loads(headers) if headers and isinstance(headers, str) else (headers or {})

            state = {
                "cookies": [{"name": k, "value": v} for k, v in parsed_cookies.items()],
                "headers": parsed_headers
            }

            if not sess:
                sess = ActiveSession(
                    project=target_project,
                    domain=domain.strip().lower(),
                    identity_role=(role or "primary").lower()
                )
                sess.set_encrypted_state(state)
                db.add(sess)
            else:
                sess.set_encrypted_state(state)
            db.commit()
            return json.dumps({"status": "SUCCESS", "role": role, "domain": domain}, indent=2)
        finally:
            db.close()

    return json.dumps({"status": "FAILED", "error": f"Unknown action '{action}'"})


# ==============================================================================
# POWER TOOL 6: manage_oast_and_tunnels
# ==============================================================================
@proxsynth_tool(name="manage_oast_and_tunnels")
async def manage_oast_and_tunnels(
    action: Literal["generate_token", "spray_canaries", "poll_callbacks", "tunnel_setup", "tunnel_status", "tunnel_close"] = "poll_callbacks",
    vuln_type: str = "SSRF",
    target_url: Optional[str] = None,
    token: Optional[str] = None,
    injection_types: str = "all",
    subdomain: Optional[str] = None,
    provider: str = "localtunnel",
    project: Optional[str] = None
) -> str:
    """
    Unified Out-of-Band (OAST) Canary & Public Tunnel Manager.
    Generates DNS/HTTP canary tokens, sprays callback payloads, polls out-of-band events, and manages public tunnels.
    """
    from backend.oast_engine import generate_oast_token, poll_oast_events
    from backend.oast_sprayer import spray_oast_canaries
    from backend.tunnel_manager import start_public_tunnel, get_tunnel_status, stop_public_tunnel

    target_project = _resolve_project(project, allow_all=(action == "poll_callbacks"))

    if action == "generate_token":
        tok = generate_oast_token(project=target_project, vuln_type=vuln_type)
        return json.dumps(tok, indent=2)

    elif action == "spray_canaries":
        if not target_url:
            return json.dumps({"status": "FAILED", "error": "target_url required for spray_canaries."})
        res = await spray_oast_canaries(target_url=target_url, vuln_type=vuln_type, project=target_project)
        return json.dumps(res, indent=2)

    elif action == "poll_callbacks":
        events = await poll_oast_events(token=token or "", project=target_project)
        return json.dumps({"project": target_project, "events_count": len(events), "events": events}, indent=2)

    elif action == "tunnel_setup":
        tun = await start_public_tunnel(provider=provider, local_port=8000, project=target_project)
        return json.dumps(tun, indent=2)

    elif action == "tunnel_status":
        return json.dumps(get_tunnel_status(), indent=2)

    elif action == "tunnel_close":
        res = await stop_public_tunnel()
        return json.dumps({"status": "SUCCESS" if res else "NOT_RUNNING"}, indent=2)

    return json.dumps({"status": "FAILED", "error": f"Unknown action '{action}'"})


# ==============================================================================
# POWER TOOL 7: manage_testing_agenda
# ==============================================================================
@proxsynth_tool(name="manage_testing_agenda")
async def manage_testing_agenda(
    action: Literal["view_agenda", "create_hypothesis", "update_status"] = "view_agenda",
    hypothesis_id: Optional[int] = None,
    target: Optional[str] = None,
    vuln_type: str = "GENERAL",
    hypothesis: Optional[str] = None,
    status: Optional[str] = None,
    evidence_notes: str = "",
    linked_log_id: Optional[int] = None,
    project: Optional[str] = None
) -> str:
    """
    Unified Security Testing Agenda & Working Memory Hypothesis Tracker.
    Coordinates planned attack vectors, updates verification states, and cross-references confirmed vulnerabilities.
    """
    from backend.database import TestingHypothesis
    target_project = _resolve_project(project, allow_all=(action == "view_agenda"))

    db = SessionLocal()
    try:
        if action == "view_agenda":
            q = db.query(TestingHypothesis)
            if target_project and target_project not in ("all", "*", "any", "global"):
                q = q.filter(TestingHypothesis.project == target_project)
            items = [h.to_dict() for h in q.order_by(TestingHypothesis.id.desc()).all()]
            return json.dumps({"project": target_project, "total_hypotheses": len(items), "hypotheses": items}, indent=2)

        elif action == "create_hypothesis":
            if not target or not hypothesis:
                return json.dumps({"status": "FAILED", "error": "target and hypothesis are required."})
            h_obj = TestingHypothesis(
                project=target_project,
                target=target,
                vuln_type=vuln_type or "GENERAL",
                hypothesis=hypothesis,
                status=status or "PLANNED",
                evidence_notes=evidence_notes or "",
                linked_log_id=linked_log_id
            )
            db.add(h_obj)
            db.commit()
            db.refresh(h_obj)
            return json.dumps({"status": "SUCCESS", "hypothesis": h_obj.to_dict()}, indent=2)

        elif action == "update_status":
            if not hypothesis_id:
                return json.dumps({"status": "FAILED", "error": "hypothesis_id is required."})
            h_obj = db.query(TestingHypothesis).filter(TestingHypothesis.id == hypothesis_id).first()
            if not h_obj:
                return json.dumps({"status": "FAILED", "error": f"Hypothesis #{hypothesis_id} not found."})
            if status:
                h_obj.status = status.upper()
            if evidence_notes:
                h_obj.evidence_notes = (h_obj.evidence_notes + "\n" + evidence_notes).strip()
            if linked_log_id:
                h_obj.linked_log_id = linked_log_id
            db.commit()
            return json.dumps({"status": "SUCCESS", "hypothesis": h_obj.to_dict()}, indent=2)

    finally:
        db.close()

    return json.dumps({"status": "FAILED", "error": f"Unknown action '{action}'"})