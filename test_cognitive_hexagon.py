"""
TDD TEST SUITE: PROXSYNTH COGNITIVE PENTEST HEXAGON
Tests all 6 intent-driven super-routers, heuristic auto-decisions,
and FastMCP mode registration tiers.
"""

import os
import sys
import json
import asyncio
from unittest.mock import patch, MagicMock

# Ensure repo root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal, HttpLog, Finding, ActiveSession, TargetAsset, TargetEndpoint, CapturedPayload
from backend.cognitive_hexagon import (
    recon_intent_router,
    traffic_intent_router,
    audit_intent_router,
    session_intent_router,
    verify_export_intent_router,
    autonomous_step_router,
    get_cvss_v4_rating
)
from mcp_core.tools.hexagon import (
    proxsynth_recon,
    proxsynth_traffic,
    proxsynth_audit,
    proxsynth_session,
    proxsynth_verify_and_export,
    proxsynth_autonomous_step
)
import mcp_core.tool_meta as tm

TEST_PROJECT = "test_hexagon_lab"


def cleanup_test_data():
    db = SessionLocal()
    try:
        log_ids = [l.id for l in db.query(HttpLog).filter(HttpLog.project == TEST_PROJECT).all()]
        if log_ids:
            db.query(Finding).filter(Finding.log_id.in_(log_ids)).delete(synchronize_session=False)
        db.query(HttpLog).filter(HttpLog.project == TEST_PROJECT).delete(synchronize_session=False)
        db.query(ActiveSession).filter(ActiveSession.project == TEST_PROJECT).delete(synchronize_session=False)
        db.query(CapturedPayload).filter(CapturedPayload.project == TEST_PROJECT).delete(synchronize_session=False)
        asset_ids = [a.id for a in db.query(TargetAsset).filter(TargetAsset.project == TEST_PROJECT).all()]
        if asset_ids:
            db.query(TargetEndpoint).filter(TargetEndpoint.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(TargetAsset).filter(TargetAsset.project == TEST_PROJECT).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


async def test_01_recon_auto_routing():
    print("[*] [1/7] Testing Recon Intent Router (Auto-Decision Heuristics)...")

    # 1. IP target should route to port scanner
    with patch("backend.network_scanner.scan_target_ports") as mock_scan:
        mock_scan.return_value = {"open_ports": [80, 443], "services": ["http", "https"]}
        res_ip = await recon_intent_router(target="192.168.1.1", mode="auto", project=TEST_PROJECT)
        assert res_ip["status"] == "success"
        assert res_ip["routed_engine"] == "network_port_scanner"

    # 2. Web URL target should route to Playwright spider
    with patch("backend.spider_engine.crawl_and_map_target") as mock_spider:
        mock_spider.return_value = {"discovered_endpoints": ["/api/users", "/login"]}
        res_url = await recon_intent_router(target="http://target.local:3000", mode="auto", project=TEST_PROJECT)
        assert res_url["status"] == "success"
        assert res_url["routed_engine"] == "playwright_spa_spider"

    # 3. Domain target should route to domain surface probe
    with patch("backend.target_health.probe_target_health") as mock_health:
        mock_health.return_value = {"status": "online", "ttfb_ms": 12.5}
        res_dom = await recon_intent_router(target="api.targetcorp.local", mode="auto", project=TEST_PROJECT)
        assert res_dom["status"] == "success"
        assert res_dom["routed_engine"] == "domain_surface_probe"

    # 4. OpenAPI / Swagger target should route to import_api_schema
    with patch("backend.api_importer.import_api_schema") as mock_schema:
        mock_schema.return_value = {"imported_count": 8, "endpoints": ["/api/v1/users", "/api/v1/items"]}
        res_api = await recon_intent_router(target="http://target.local/swagger.json", mode="openapi", project=TEST_PROJECT)
        assert res_api["status"] == "success"
        assert res_api["routed_engine"] == "openapi_spec_importer"
        assert res_api["results"]["imported_count"] == 8

    print("  -> Passed: Recon facet accurately routed IP, URL, Domain, and OpenAPI targets.")


async def test_02_traffic_auto_routing():
    print("[*] [2/7] Testing Traffic Intent Router (Diffing & Response Distillation)...")
    db = SessionLocal()
    try:
        # Seed 2 logs for semantic diffing
        log1 = HttpLog(
            project=TEST_PROJECT,
            method="GET",
            url="http://target.local/api/profile",
            host="target.local",
            path="/api/profile",
            status_code=200,
            response_body='{"user_id": 101, "email": "alice@corp.local", "time": "2026-11-03T00:00:00Z"}'
        )
        log2 = HttpLog(
            project=TEST_PROJECT,
            method="GET",
            url="http://target.local/api/profile",
            host="target.local",
            path="/api/profile",
            status_code=200,
            response_body='{"user_id": 102, "email": "bob@corp.local", "time": "2026-11-03T00:00:05Z"}'
        )
        db.add_all([log1, log2])
        db.commit()
        id1, id2 = log1.id, log2.id
    finally:
        db.close()

    # Action: auto with log_id_a and log_id_b -> should auto-route to semantic diff
    diff_res = await traffic_intent_router(
        action="auto",
        log_id_a=id1,
        log_id_b=id2,
        project=TEST_PROJECT
    )
    assert diff_res["status"] == "success"
    assert diff_res["action"] == "semantic_diff"
    assert "similarity_ratio" in diff_res

    # Action: distill large response
    large_html = "<html><head><title>Admin Portal</title></head><body><form action='/login' method='POST'><input name='user'/><input name='pass'/></form>" + ("<div>Noise</div>" * 500) + "</body></html>"
    distill_res = await traffic_intent_router(
        action="distill",
        body=large_html,
        project=TEST_PROJECT
    )
    assert distill_res["status"] == "success"
    assert distill_res["action"] == "distill"
    assert "Distilled Security View" in distill_res["distilled"]["compact_summary"]

    # Action: vault -> stores payload into CapturedPayload and retrieves
    vault_res = await traffic_intent_router(
        action="vault",
        payload="' OR 1=1--",
        project=TEST_PROJECT
    )
    assert vault_res["status"] == "success"
    assert vault_res["action"] == "vault"
    assert any(p["payload"] == "' OR 1=1--" for p in vault_res["vault_entries"])

    # Action: send with WAF auto-heal
    mock_resp_403 = MagicMock()
    mock_resp_403.status_code = 403
    mock_resp_403.headers = {"server": "cloudflare"}
    mock_resp_403.text = "Forbidden - Cloudflare WAF Blocked"

    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200
    mock_resp_200.headers = {"server": "cloudflare"}
    mock_resp_200.text = '{"success": true}'

    with patch("httpx.AsyncClient.request") as mock_req, \
         patch("backend.waf_mutator.mutate_payload") as mock_mut, \
         patch("backend.waf_mutator.generate_evasion_headers") as mock_hdr:
        mock_req.side_effect = [mock_resp_403, mock_resp_200]
        mock_mut.return_value = {"mutations": [{"payload": "%27%20OR%201%3D1--"}]}
        mock_hdr.return_value = {"X-Originating-IP": "127.0.0.1"}

        waf_res = await traffic_intent_router(
            url="http://target.local/search?q=' OR 1=1--",
            action="send",
            body="' OR 1=1--",
            project=TEST_PROJECT
        )
        assert waf_res["status"] == "success"
        assert waf_res.get("waf_auto_healed") is True

    print("  -> Passed: Traffic facet accurately handled semantic diff, distillation, vault, and WAF auto-heal.")


async def test_03_audit_auto_routing():
    print("[*] [3/7] Testing Audit Intent Router (BOLA vs Numeric Logic vs OAST)...")
    db = SessionLocal()
    try:
        # Multi-role sessions exist -> auto-routes to Two-Tier Access Control Orchestrator
        from backend.bola_matrix import set_identity_session
        set_identity_session(project=TEST_PROJECT, domain="api.corp.local", identity_role="admin", bearer_token="tok_admin_123")
        set_identity_session(project=TEST_PROJECT, domain="api.corp.local", identity_role="user", bearer_token="tok_user_456")
    finally:
        db.close()

    from backend.access_control_orchestrator import AccessControlOrchestrator
    with patch.object(AccessControlOrchestrator, "execute_full_campaign") as mock_orch:
        mock_orch.return_value = {
            "findings_summary": {"total_flagged": 1},
            "findings": [{"id": 101, "category": "BOLA"}]
        }
        res_authz = await audit_intent_router(
            target_url="http://api.corp.local/api/users/101",
            vuln_focus="auto",
            project=TEST_PROJECT
        )
        assert res_authz["status"] == "success"
        assert res_authz["routed_engine"] == "two_tier_access_control_orchestrator"
        assert res_authz["cvss_v4_baseline"]["cwe"] == "CWE-639"

    # Numeric / pricing parameters -> auto-routes to Numeric Business Logic Fuzzer
    with patch("backend.logic_fuzzer.audit_numeric_business_logic") as mock_logic:
        mock_logic.return_value = {"tests_passed": 6, "vulnerabilities_found": 1}
        res_logic = await audit_intent_router(
            target_url="http://store.local/api/checkout?item_id=5&price=100&qty=2",
            vuln_focus="auto",
            project=TEST_PROJECT
        )
        assert res_logic["status"] == "success"
        assert res_logic["routed_engine"] == "numeric_logic_fuzzer"
        assert res_logic["cvss_v4_baseline"]["cwe"] == "CWE-840"

    # SSRF / redirect parameters -> auto-routes to OAST Canary Sprayer
    with patch("backend.oast_sprayer.spray_oast_canaries") as mock_spray, \
         patch("backend.oast_engine.list_recent_oast_events") as mock_poll:
        mock_spray.return_value = {"canaries": ["canary_ssrf_token_123"]}
        mock_poll.return_value = []
        res_oast = await audit_intent_router(
            target_url="http://gateway.local/fetch?url=http://example.com",
            vuln_focus="auto",
            project=TEST_PROJECT
        )
        assert res_oast["status"] == "success"
        assert res_oast["routed_engine"] == "oast_canary_sprayer"
        assert res_oast["cvss_v4_baseline"]["cwe"] == "CWE-918"

    # Generic smart fuzzer fallback
    with patch("backend.fuzzer.run_fuzz_attack") as mock_fuzz:
        mock_fuzz.return_value = {"fuzz_completed": True, "anomalies": []}
        res_fuzz = await audit_intent_router(
            target_url="http://target.local/api/items",
            vuln_focus="fuzz",
            project=TEST_PROJECT
        )
        assert res_fuzz["status"] == "success"
        assert res_fuzz["routed_engine"] == "smart_param_fuzzer"
        assert mock_fuzz.call_args[1]["base_url"] == "http://target.local/api/items"

    print("  -> Passed: Audit facet accurately routed multi-role access control, numeric logic, SSRF, and smart fuzzer.")


async def test_04_session_auto_routing():
    print("[*] [4/7] Testing Session Intent Router (Multi-Role Vault & Anti-CSRF)...")

    # 1. Action: set -> stores identity in ActiveSession
    res_set = await session_intent_router(
        domain="app.target.local",
        action="auto",
        role="victim_user",
        token="jwt_secret_token_999",
        headers={"X-Custom-Tenant": "tenant_42"},
        project=TEST_PROJECT
    )
    assert res_set["status"] == "success"
    assert res_set["action"] == "upsert_identity"
    assert res_set["role"] == "victim_user"

    # 2. Action: get -> retrieves identities for domain
    res_get = await session_intent_router(
        domain="app.target.local",
        action="auto",
        project=TEST_PROJECT
    )
    assert res_get["status"] == "success"
    assert res_get["action"] == "get_session_state"
    assert any(s["role"] == "victim_user" for s in res_get["identities"])

    print("  -> Passed: Session facet accurately managed multi-role vault identities.")


async def test_05_verify_export_auto_routing():
    print("[*] [5/7] Testing Verify & Export Router (Deterministic Gate + Nuclei YAML + CVSS v4.0)...")
    db = SessionLocal()
    try:
        log = HttpLog(
            project=TEST_PROJECT,
            method="POST",
            url="http://target.local/api/admin/delete",
            host="target.local",
            path="/api/admin/delete",
            status_code=200,
            response_body='{"status": "deleted", "admin": true}'
        )
        db.add(log)
        db.commit()

        finding = Finding(
            log_id=log.id,
            title="Broken Function Level Authorization on Admin Delete",
            category="BFLA",
            severity="HIGH",
            evidence="Replayed with unauthenticated token and returned 200 OK"
        )
        db.add(finding)
        db.commit()
        fid = finding.id
    finally:
        db.close()

    # Run verify and export in auto mode
    with patch("backend.verification_gate.verify_vulnerability_candidate") as mock_gate:
        mock_gate.return_value = {
            "verdict": "VERIFIED_EXPLOITABLE",
            "confidence": 0.95,
            "verification_evidence": "Deterministic 3-way replay confirmed BFLA privilege anomaly."
        }
        res_export = await verify_export_intent_router(
            finding_id=fid,
            format="auto",
            project=TEST_PROJECT
        )

    assert res_export["status"] == "success"
    assert "cvss_v4" in res_export
    assert res_export["cvss_v4"]["severity"] == "HIGH"
    assert "CVSS:4.0" in res_export["cvss_v4"]["vector"]
    assert "nuclei_yaml" in res_export
    assert "report_markdown" in res_export
    assert "VULNERABILITY DOSSIER" in res_export["report_markdown"]

    print("  -> Passed: Verify & Export facet synthesized deterministic PoC, Nuclei YAML, and CVSS v4.0 dossier.")


async def test_06_autonomous_step_execution():
    print("[*] [6/7] Testing Autonomous Step Router (Master Cognitive Coordinator)...")

    # Case A: Empty workspace -> prompts for recon
    cleanup_test_data()
    res_empty = await autonomous_step_router(project=TEST_PROJECT)
    assert res_empty["status"] == "success"
    assert res_empty["phase"] == "RECON_REQUIRED"

    # Case B: Endpoints exist -> probes top attack vector
    db = SessionLocal()
    try:
        asset = TargetAsset(project=TEST_PROJECT, host="api.testcorp.local")
        db.add(asset)
        db.commit()

        ep = TargetEndpoint(
            asset_id=asset.id,
            path="/api/accounts/1",
            method="GET",
            url="http://api.testcorp.local/api/accounts/1",
            tested_status="UNTESTED"
        )
        db.add(ep)
        db.commit()
    finally:
        db.close()

    from backend.access_control_orchestrator import AccessControlOrchestrator
    with patch.object(AccessControlOrchestrator, "execute_full_campaign") as mock_orch:
        mock_orch.return_value = {"findings_summary": {"total_flagged": 0}, "findings": []}
        res_step = await autonomous_step_router(project=TEST_PROJECT)
        assert res_step["status"] == "success"
        assert res_step["phase"] in ["ENDPOINT_AUDIT", "VULNERABILITY_AUDIT"]

    # Case C: Verification loop test - unverified finding is verified once, stamped, and not re-verified
    db = SessionLocal()
    try:
        log_f = HttpLog(
            project=TEST_PROJECT,
            method="GET",
            url="http://api.testcorp.local/api/accounts/2",
            host="api.testcorp.local",
            path="/api/accounts/2",
            status_code=200
        )
        db.add(log_f)
        db.commit()

        crit_f = Finding(
            log_id=log_f.id,
            title="Critical IDOR in Accounts API",
            category="IDOR",
            severity="CRITICAL",
            evidence="Initial unverified candidate"
        )
        db.add(crit_f)
        db.commit()
        crit_id = crit_f.id
    finally:
        db.close()

    with patch("backend.verification_gate.verify_vulnerability_candidate") as mock_gate:
        mock_gate.return_value = {"verdict": "VERIFIED_EXPLOITABLE", "confidence": 0.99}
        # First step: should detect unverified finding and verify it
        res_v1 = await autonomous_step_router(project=TEST_PROJECT)
        assert res_v1["status"] == "success"
        assert res_v1["phase"] == "VERIFICATION_AND_EXPORT"
        assert "Verdict:" in res_v1["action_taken"]

        # Check that DB was stamped with verdict
        db_check = SessionLocal()
        try:
            saved_f = db_check.query(Finding).filter(Finding.id == crit_id).first()
            assert "[ORACLE VERDICT:" in (saved_f.evidence or "")
            assert saved_f.log.flag_status == "CONFIRMED"
        finally:
            db_check.close()

        # Second step: with orchestrator mocked, should not verify again, but proceed to next endpoint
        with patch.object(AccessControlOrchestrator, "execute_full_campaign") as mock_orch2:
            mock_orch2.return_value = {"findings_summary": {"total_flagged": 0}, "findings": []}
            res_v2 = await autonomous_step_router(project=TEST_PROJECT)
            assert res_v2["status"] == "success"
            assert res_v2["phase"] != "VERIFICATION_AND_EXPORT"

    print("  -> Passed: Autonomous Step overseer evaluated state machine, resolved unverified findings without loops, and advanced.")


def test_07_fastmcp_mode_registration():
    print("[*] [7/7] Testing FastMCP Tool Mode Registration & Token Reduction Tier...")

    # Full Mode: >= 100 tools
    assert len(tm.TOOL_PERMS) >= 100

    # Power Mode: 18 tools
    assert len(tm.POWER_MODE_TOOLS) == 18

    # Hexagon Mode: Exactly 9 tools (6 super-tools + 3 context tools)
    assert len(tm.HEXAGON_MODE_TOOLS) == 9

    # Ensure all 6 Hexagon super-tools are in HEXAGON_MODE_TOOLS
    expected_super_tools = {
        "proxsynth_recon",
        "proxsynth_traffic",
        "proxsynth_audit",
        "proxsynth_session",
        "proxsynth_verify_and_export",
        "proxsynth_autonomous_step"
    }
    assert expected_super_tools.issubset(tm.HEXAGON_MODE_TOOLS)

    # Calculate Token Overhead Reduction Percentage
    full_count = len(tm.TOOL_PERMS)
    hex_count = len(tm.HEXAGON_MODE_TOOLS)
    reduction_pct = round(((full_count - hex_count) / full_count) * 100, 1)
    print(f"  -> Full Mode Tools: {full_count}")
    print(f"  -> Hexagon Mode Tools: {hex_count}")
    print(f"  -> Prompt Schema Reduction: {reduction_pct}% (Target: >90%)")
    assert reduction_pct >= 90.0
    print("  -> Passed: FastMCP Hexagon Mode cuts tool schema token overhead by >90%.")


async def test_08_fastmcp_tool_exception_handling():
    print("[*] [8/8] Testing FastMCP Super-Tool Exception Handling & JSON Fallback...")

    with patch("mcp_core.tools.hexagon.recon_intent_router") as mock_router:
        mock_router.side_effect = RuntimeError("Simulated network timeout during recon")
        res_raw = await proxsynth_recon(target="invalid_target")
        parsed = json.loads(res_raw)
        assert parsed["status"] == "error"
        assert parsed["facet"] == "recon"
        assert "Simulated network timeout" in parsed["message"]

    with patch("mcp_core.tools.hexagon.audit_intent_router") as mock_router:
        mock_router.side_effect = ValueError("Corrupt request format")
        res_raw = await proxsynth_audit(target_url="http://example.local")
        parsed = json.loads(res_raw)
        assert parsed["status"] == "error"
        assert parsed["facet"] == "audit"
        assert "Corrupt request format" in parsed["message"]

    print("  -> Passed: FastMCP tools safely capture exceptions and return structured JSON errors.")


async def main():
    print("==================================================")
    print("RUNNING TDD SUITE: COGNITIVE PENTEST HEXAGON")
    print("==================================================")
    try:
        cleanup_test_data()
        await test_01_recon_auto_routing()
        await test_02_traffic_auto_routing()
        await test_03_audit_auto_routing()
        await test_04_session_auto_routing()
        await test_05_verify_export_auto_routing()
        await test_06_autonomous_step_execution()
        test_07_fastmcp_mode_registration()
        await test_08_fastmcp_tool_exception_handling()
    finally:
        cleanup_test_data()
    print("==================================================")
    print("ALL COGNITIVE PENTEST HEXAGON TESTS PASSED (100%)")
    print("==================================================")


if __name__ == "__main__":
    asyncio.run(main())
