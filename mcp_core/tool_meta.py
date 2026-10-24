"""
Proxsynth MCP - Tool Metadata & Permissions Specification
Single source of truth for all 83 FastMCP tool permissions, categories,
MCP-standard ToolAnnotations (readOnlyHint, destructiveHint), and outputSchemas.
"""

from typing import Dict, Any
from mcp.types import ToolAnnotations


TOOL_PERMS: Dict[str, Dict[str, Any]] = {
    # 1. Project Context & Workspace (2 tools)
    "set_active_project": {"read_only": False, "destructive": False, "category": "context"},
    "get_active_project": {"read_only": True, "destructive": False, "category": "context"},

    # 2. HTTP Traffic & Inspection (8 tools)
    "send_http_request": {"read_only": False, "destructive": False, "category": "traffic"},
    "get_traffic_history": {"read_only": True, "destructive": False, "category": "traffic"},
    "get_log_detail": {"read_only": True, "destructive": False, "category": "traffic"},
    "distill_http_response": {"read_only": True, "destructive": False, "category": "traffic"},
    "search_traffic_advanced": {"read_only": True, "destructive": False, "category": "traffic"},
    "analyze_traffic_patterns": {"read_only": True, "destructive": False, "category": "traffic"},
    "compare_http_responses": {"read_only": True, "destructive": False, "category": "analysis"},
    "semantic_diff_responses": {"read_only": True, "destructive": False, "category": "analysis"},

    # 3. Browser & Interactive Session (5 tools)
    "browser_navigate_and_render": {"read_only": False, "destructive": False, "category": "browser"},
    "render_webpage": {"read_only": False, "destructive": False, "category": "browser"},
    "spider_and_crawl_target": {"read_only": False, "destructive": False, "category": "spider"},
    "verify_dom_execution": {"read_only": False, "destructive": False, "category": "xss"},
    "request_manual_login": {"read_only": False, "destructive": False, "category": "auth"},

    # 4. Payload Vault & Fuzzing (4 tools)
    "record_test_payload": {"read_only": False, "destructive": False, "category": "vault"},
    "get_captured_payloads": {"read_only": True, "destructive": False, "category": "vault"},
    "mutate_payload": {"read_only": False, "destructive": False, "category": "waf"},
    "analyze_waf_response": {"read_only": False, "destructive": False, "category": "waf"},

    # 5. Injection & Concurrency (3 tools)
    "fuzz_endpoint": {"read_only": False, "destructive": True, "category": "fuzzing"},
    "test_race_condition": {"read_only": False, "destructive": True, "category": "concurrency"},
    "audit_differential_injection": {"read_only": False, "destructive": False, "category": "audit"},

    # 6. Authorization & Logic (7 tools)
    "audit_jwt_security": {"read_only": False, "destructive": False, "category": "audit"},
    "audit_bfla_permissions": {"read_only": False, "destructive": False, "category": "audit"},
    "audit_mass_assignment": {"read_only": False, "destructive": False, "category": "audit"},
    "audit_numeric_business_logic": {"read_only": False, "destructive": False, "category": "audit"},
    "test_bola_idor": {"read_only": False, "destructive": True, "category": "bola"},
    "get_bola_access_matrix": {"read_only": True, "destructive": False, "category": "bola"},
    "run_bola_matrix_scan": {"read_only": False, "destructive": True, "category": "bola"},

    # 7. API, GraphQL & WebSocket (6 tools)
    "inspect_graphql_endpoint": {"read_only": False, "destructive": False, "category": "graphql"},
    "send_websocket_message": {"read_only": False, "destructive": False, "category": "websocket"},
    "audit_websocket_security": {"read_only": False, "destructive": False, "category": "websocket"},
    "import_api_schema": {"read_only": False, "destructive": False, "category": "api_import"},
    "infer_hidden_endpoints": {"read_only": True, "destructive": False, "category": "recon"},
    "audit_api_gateway_bypass": {"read_only": False, "destructive": False, "category": "audit"},

    # 8. Network Recon & Health (2 tools)
    "scan_network_ports": {"read_only": False, "destructive": False, "category": "network"},
    "get_target_health": {"read_only": True, "destructive": False, "category": "recon"},

    # 9. Out-of-Band (OAST) Engine & Tunnels (6 tools)
    "generate_oast_token": {"read_only": False, "destructive": False, "category": "oast"},
    "poll_oast_events": {"read_only": True, "destructive": False, "category": "oast"},
    "spray_oast_canaries": {"read_only": False, "destructive": False, "category": "oast"},
    "setup_public_tunnel": {"read_only": False, "destructive": False, "category": "tunnel"},
    "get_tunnel_status": {"read_only": True, "destructive": False, "category": "tunnel"},
    "close_public_tunnel": {"read_only": False, "destructive": False, "category": "tunnel"},

    # 10. Interception Rules & Certificates (5 tools)
    "add_interception_rule": {"read_only": False, "destructive": False, "category": "intercept"},
    "list_interception_rules": {"read_only": True, "destructive": False, "category": "intercept"},
    "toggle_interception_rule": {"read_only": False, "destructive": False, "category": "intercept"},
    "delete_interception_rule": {"read_only": False, "destructive": True, "category": "intercept"},
    "get_ca_certificate_details": {"read_only": True, "destructive": False, "category": "ca"},

    # 11. Working Memory Agenda & Hypotheses (3 tools)
    "record_testing_hypothesis": {"read_only": False, "destructive": False, "category": "agenda"},
    "get_testing_agenda": {"read_only": True, "destructive": False, "category": "agenda"},
    "update_hypothesis_status": {"read_only": False, "destructive": False, "category": "agenda"},

    # 12. Autonomous Campaign & Cognitive Guidance (5 tools)
    "run_autonomous_security_campaign": {"read_only": False, "destructive": True, "category": "orchestration"},
    "get_campaign_status": {"read_only": True, "destructive": False, "category": "orchestration"},
    "list_campaigns": {"read_only": True, "destructive": False, "category": "orchestration"},
    "get_autonomous_attack_guidance": {"read_only": True, "destructive": False, "category": "advisor"},
    "get_tool_harness_manifest": {"read_only": True, "destructive": False, "category": "meta"},

    # 13. Session, Auth & CSRF Management (6 tools)
    "set_identity_session": {"read_only": False, "destructive": False, "category": "auth"},
    "register_auth_recipe": {"read_only": False, "destructive": False, "category": "auth"},
    "execute_reauthentication": {"read_only": False, "destructive": False, "category": "auth"},
    "get_csrf_tokens": {"read_only": True, "destructive": False, "category": "session"},
    "set_csrf_token": {"read_only": False, "destructive": False, "category": "session"},
    "clear_csrf_tokens": {"read_only": False, "destructive": True, "category": "session"},

    # 14. Reporting, PoC, Attack Graph & System (18 tools)
    "report_vulnerability": {"read_only": False, "destructive": False, "category": "triage"},
    "generate_exploit_poc": {"read_only": True, "destructive": False, "category": "exploit"},
    "generate_nuclei_template": {"read_only": True, "destructive": False, "category": "exploit"},
    "verify_vulnerability_candidate": {"read_only": False, "destructive": False, "category": "verification"},
    "generate_audit_ci_report": {"read_only": True, "destructive": False, "category": "report"},
    "get_attack_surface": {"read_only": True, "destructive": False, "category": "recon"},
    "record_target_asset": {"read_only": False, "destructive": False, "category": "recon"},
    "record_target_service": {"read_only": False, "destructive": False, "category": "recon"},
    "record_target_endpoint": {"read_only": False, "destructive": False, "category": "recon"},
    "get_attack_paths": {"read_only": True, "destructive": False, "category": "killchain"},
    "delete_attack_surface_node": {"read_only": False, "destructive": True, "category": "recon"},
    "clear_attack_surface_graph": {"read_only": False, "destructive": True, "category": "recon"},
    "mine_javascript_assets": {"read_only": False, "destructive": False, "category": "js"},
    "mine_cli_output": {"read_only": True, "destructive": False, "category": "miner"},
    "run_pentest_command": {"read_only": False, "destructive": True, "category": "cli"},
    "execute_workflow_sequence": {"read_only": False, "destructive": True, "category": "workflow"},
    "run_security_audit_suite": {"read_only": False, "destructive": True, "category": "suite"},
    "update_proxsynth_system": {"read_only": False, "destructive": True, "category": "admin"},

    # 15. New Phase 2.5 Audit Tools (3 tools)
    "audit_cache_poisoning": {"read_only": False, "destructive": False, "category": "cache"},
    "audit_csrf_indepth": {"read_only": False, "destructive": False, "category": "csrf"},
    "audit_file_upload": {"read_only": False, "destructive": False, "category": "upload"},
}

# Alias for backward compatibility
TOOL_HARNESS_METADATA = TOOL_PERMS


def meta(name: str) -> ToolAnnotations:
    """
    Builds official MCP ToolAnnotations with readOnlyHint, destructiveHint,
    idempotentHint, and openWorldHint flags.
    """
    m = TOOL_PERMS.get(name, {"read_only": False, "destructive": False, "category": "misc"})
    is_ro = bool(m["read_only"])
    is_dest = bool(m["destructive"])
    hidden = is_dest and not is_ro

    return ToolAnnotations(
        title=name.replace("_", " ").title(),
        read_only_hint=is_ro,
        destructive_hint=hidden,
        idempotent_hint=(is_ro and not hidden),
        open_world_hint=True,
    )


# 8 Structured Read-Only Tools (TASK 2)
STRUCTURED_READ_ONLY_TOOLS = {
    "get_traffic_history",
    "get_log_detail",
    "get_testing_agenda",
    "get_attack_surface",
    "get_captured_payloads",
    "search_traffic_advanced",
    "get_bola_access_matrix",
    "get_csrf_tokens"
}

STRUCTURED_OUTPUT_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "get_traffic_history": {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "total_count": {"type": "integer"},
            "logs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "method": {"type": "string"},
                        "url": {"type": "string"},
                        "status_code": {"type": ["integer", "null"]},
                        "duration_ms": {"type": "integer"},
                        "flag_status": {"type": "string"},
                        "project": {"type": "string"},
                        "agent_id": {"type": "string"}
                    }
                }
            }
        }
    },
    "get_log_detail": {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "project": {"type": "string"},
            "agent_id": {"type": "string"},
            "method": {"type": "string"},
            "url": {"type": "string"},
            "host": {"type": "string"},
            "path": {"type": "string"},
            "status_code": {"type": ["integer", "null"]},
            "duration_ms": {"type": "integer"},
            "request_headers": {"type": "object"},
            "request_body": {"type": "string"},
            "response_headers": {"type": "object"},
            "response_body": {"type": "string"},
            "flag_status": {"type": "string"},
            "reasoning": {"type": "string"},
            "findings": {"type": "array"}
        }
    },
    "get_testing_agenda": {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "planned_hypotheses": {"type": "array"},
            "testing_hypotheses": {"type": "array"},
            "confirmed_count": {"type": "integer"},
            "total_hypotheses": {"type": "integer"}
        }
    },
    "get_attack_surface": {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "total_assets": {"type": "integer"},
            "total_services": {"type": "integer"},
            "total_endpoints": {"type": "integer"},
            "untested_endpoints": {"type": "integer"},
            "tested_endpoints": {"type": "integer"},
            "vulnerable_endpoints": {"type": "integer"},
            "assets": {"type": "array"}
        }
    },
    "get_captured_payloads": {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "total_count": {"type": "integer"},
            "payloads": {"type": "array"}
        }
    },
    "search_traffic_advanced": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "results_count": {"type": "integer"},
            "logs": {"type": "array"}
        }
    },
    "get_bola_access_matrix": {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "total_endpoints_analyzed": {"type": "integer"},
            "matrix": {"type": "array"},
            "violations_found": {"type": "integer"}
        }
    },
    "get_csrf_tokens": {
        "type": "object",
        "properties": {
            "domain": {"type": "string"},
            "tokens": {"type": "object"},
            "token_count": {"type": "integer"}
        }
    }
}
