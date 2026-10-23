"""
Proxsynth MCP - Autonomous Interception & Match/Replace Engine
Provides headless, programmatically-controlled HTTP traffic modification and response mocking.
Enables AI coding agents (Claude, Cursor, Windsurf, Hermes, Antigravity) to mutate headers,
rewrite payloads, strip security controls, or return synthetic mock responses without manual GUI intervention.
"""

import os
import re
import json
import fnmatch
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session
from backend.database import SessionLocal, InterceptionRule

# In-memory cached rules ordered by priority (ascending: 1 = highest priority)
_CACHED_RULES: List[Dict[str, Any]] = []
_RULES_INITIALIZED = False


def _match_pattern(pattern: str, text: str, is_regex: bool = False) -> bool:
    """Matches text against wildcard or regex pattern."""
    if not pattern or pattern == "*":
        return True
    if not text:
        return False
    if is_regex:
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except Exception:
            return False
    # Check simple wildcard match or case-insensitive substring
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(text.lower(), pattern.lower())
    return pattern.lower() in text.lower()


def reload_interception_rules():
    """Reloads enabled interception rules from SQLite database into memory."""
    global _CACHED_RULES, _RULES_INITIALIZED
    db = SessionLocal()
    try:
        rules = db.query(InterceptionRule).filter(InterceptionRule.enabled == True).order_by(InterceptionRule.priority.asc(), InterceptionRule.id.asc()).all()
        _CACHED_RULES = [r.to_dict() for r in rules]
        _RULES_INITIALIZED = True
    except Exception:
        pass
    finally:
        db.close()


def ensure_rules_loaded():
    if not _RULES_INITIALIZED:
        reload_interception_rules()


def add_interception_rule(
    name: str,
    rule_type: str = "REQUEST",  # REQUEST, RESPONSE, MOCK
    match_url: str = "*",
    match_method: str = "*",
    match_header: str = "",
    match_body: str = "",
    action_type: str = "REPLACE_HEADER",  # REPLACE_HEADER, REMOVE_HEADER, REPLACE_BODY, REWRITE_URL, MOCK_RESPONSE
    action_target: str = "",
    action_value: str = "",
    action_extra: Optional[Dict[str, Any]] = None,
    project: str = "default",
    priority: int = 10,
    enabled: bool = True
) -> Dict[str, Any]:
    """Adds a new interception rule and persists it in SQLite."""
    db = SessionLocal()
    try:
        rule = InterceptionRule(
            name=name.strip(),
            project=(project or "default").strip().lower(),
            enabled=enabled,
            priority=priority,
            rule_type=rule_type.strip().upper(),
            match_url=match_url.strip(),
            match_method=match_method.strip().upper(),
            match_header=match_header.strip(),
            match_body=match_body,
            action_type=action_type.strip().upper(),
            action_target=action_target.strip(),
            action_value=action_value,
            action_extra=json.dumps(action_extra or {})
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        result = rule.to_dict()
        reload_interception_rules()
        return result
    finally:
        db.close()


def list_interception_rules(project: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns all configured interception rules, optionally filtered by project."""
    db = SessionLocal()
    try:
        query = db.query(InterceptionRule).order_by(InterceptionRule.priority.asc(), InterceptionRule.id.asc())
        if project and project.strip().lower() not in ["all", "*", "any", "global"]:
            proj = project.strip().lower()
            query = query.filter((InterceptionRule.project == proj) | (InterceptionRule.project == "all"))
        rules = query.all()
        return [r.to_dict() for r in rules]
    finally:
        db.close()


def delete_interception_rule(rule_id: int) -> bool:
    """Deletes an interception rule by ID."""
    db = SessionLocal()
    try:
        rule = db.query(InterceptionRule).filter(InterceptionRule.id == rule_id).first()
        if not rule:
            return False
        db.delete(rule)
        db.commit()
        reload_interception_rules()
        return True
    finally:
        db.close()


def toggle_interception_rule(rule_id: int, enabled: Optional[bool] = None) -> Optional[Dict[str, Any]]:
    """Toggles or sets the enabled status of a rule."""
    db = SessionLocal()
    try:
        rule = db.query(InterceptionRule).filter(InterceptionRule.id == rule_id).first()
        if not rule:
            return None
        rule.enabled = not rule.enabled if enabled is None else enabled
        rule.updated_at = datetime.now()
        db.commit()
        db.refresh(rule)
        res = rule.to_dict()
        reload_interception_rules()
        return res
    finally:
        db.close()


def apply_request_rules(
    method: str,
    url: str,
    headers: Dict[str, Any],
    body: str,
    project: str = "default"
) -> Tuple[bool, str, str, Dict[str, str], str, Optional[Dict[str, Any]]]:
    """
    Applies active request modification and mock rules in priority sequence.
    Returns: (is_mocked, modified_method, modified_url, modified_headers, modified_body, mock_response_dict)
    """
    ensure_rules_loaded()
    if not _CACHED_RULES:
        return False, method, url, {k: str(v) for k, v in headers.items()}, body, None

    proj = (project or "default").strip().lower()
    mod_method = method.upper()
    mod_url = url
    mod_headers = {k: str(v) for k, v in headers.items()}
    mod_body = body or ""

    for rule in _CACHED_RULES:
        rule_proj = (rule.get("project") or "default").lower()
        if rule_proj != "all" and rule_proj != proj and proj != "all":
            continue

        rule_type = rule.get("rule_type", "REQUEST")
        if rule_type not in ["REQUEST", "MOCK"]:
            continue

        # Match Method
        m_method = rule.get("match_method", "*")
        if m_method and m_method != "*":
            allowed_methods = [m.strip().upper() for m in m_method.split(",")]
            if mod_method not in allowed_methods:
                continue

        # Match URL
        m_url = rule.get("match_url", "*")
        if not _match_pattern(m_url, mod_url):
            continue

        # Match Header
        m_header = rule.get("match_header", "")
        if m_header:
            if ":" in m_header:
                hk, hv = m_header.split(":", 1)
                hk, hv = hk.strip(), hv.strip()
                matched_hdr = False
                for cur_k, cur_v in mod_headers.items():
                    if cur_k.lower() == hk.lower() and _match_pattern(hv, cur_v):
                        matched_hdr = True
                        break
                if not matched_hdr:
                    continue
            else:
                # Just checks header name presence
                if not any(k.lower() == m_header.lower() for k in mod_headers.keys()):
                    continue

        # Match Body
        m_body = rule.get("match_body", "")
        if m_body and not _match_pattern(m_body, mod_body):
            continue

        # Rule Matched! Apply Action
        action_type = rule.get("action_type", "")
        action_target = rule.get("action_target", "")
        action_value = rule.get("action_value", "")
        action_extra = rule.get("action_extra", {})

        if action_type == "MOCK_RESPONSE" or rule_type == "MOCK":
            # Return synthetic mock response immediately
            status_code = 200
            try:
                status_code = int(action_target) if action_target.isdigit() else 200
            except Exception:
                status_code = 200

            mock_headers = {"Content-Type": "application/json", "X-Proxsynth-Mocked": "1"}
            if isinstance(action_extra, dict) and "headers" in action_extra:
                mock_headers.update(action_extra["headers"])

            mock_res = {
                "status_code": status_code,
                "headers": mock_headers,
                "body": action_value or '{"status": "mocked", "message": "Synthetic response by Proxsynth Interception Rule"}'
            }
            return True, mod_method, mod_url, mod_headers, mod_body, mock_res

        elif action_type == "REPLACE_HEADER":
            if action_target:
                # Remove case variants first
                target_lower = action_target.lower()
                keys_to_remove = [k for k in mod_headers if k.lower() == target_lower]
                for k in keys_to_remove:
                    del mod_headers[k]
                mod_headers[action_target] = action_value

        elif action_type == "REMOVE_HEADER":
            if action_target:
                target_lower = action_target.lower()
                keys_to_remove = [k for k in mod_headers if k.lower() == target_lower]
                for k in keys_to_remove:
                    del mod_headers[k]

        elif action_type == "REPLACE_BODY":
            if action_target and mod_body:
                try:
                    mod_body = re.sub(action_target, action_value, mod_body)
                except Exception:
                    mod_body = mod_body.replace(action_target, action_value)

        elif action_type == "REWRITE_URL":
            if action_target:
                try:
                    mod_url = re.sub(action_target, action_value, mod_url)
                except Exception:
                    mod_url = mod_url.replace(action_target, action_value)

    return False, mod_method, mod_url, mod_headers, mod_body, None


def apply_response_rules(
    status_code: int,
    headers: Dict[str, Any],
    body: str,
    url: str,
    project: str = "default"
) -> Tuple[int, Dict[str, str], str]:
    """
    Applies active response modification rules (e.g. stripping CSP, injecting payloads).
    Returns: (modified_status_code, modified_headers, modified_body)
    """
    ensure_rules_loaded()
    if not _CACHED_RULES:
        return status_code, {k: str(v) for k, v in headers.items()}, body

    proj = (project or "default").strip().lower()
    mod_status = status_code
    mod_headers = {k: str(v) for k, v in headers.items()}
    mod_body = body or ""

    for rule in _CACHED_RULES:
        rule_proj = (rule.get("project") or "default").lower()
        if rule_proj != "all" and rule_proj != proj and proj != "all":
            continue

        if rule.get("rule_type", "") != "RESPONSE":
            continue

        # Match URL
        m_url = rule.get("match_url", "*")
        if not _match_pattern(m_url, url):
            continue

        action_type = rule.get("action_type", "")
        action_target = rule.get("action_target", "")
        action_value = rule.get("action_value", "")

        if action_type == "REMOVE_HEADER":
            if action_target:
                t_lower = action_target.lower()
                for k in list(mod_headers.keys()):
                    if k.lower() == t_lower:
                        del mod_headers[k]

        elif action_type == "REPLACE_HEADER":
            if action_target:
                t_lower = action_target.lower()
                for k in list(mod_headers.keys()):
                    if k.lower() == t_lower:
                        del mod_headers[k]
                mod_headers[action_target] = action_value

        elif action_type == "REPLACE_BODY":
            if action_target and mod_body:
                try:
                    mod_body = re.sub(action_target, action_value, mod_body)
                except Exception:
                    mod_body = mod_body.replace(action_target, action_value)

    return mod_status, mod_headers, mod_body
