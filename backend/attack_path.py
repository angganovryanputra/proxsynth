"""
Proxsynth - Exploit Path Chaining Graph Engine
Synthesizes verified findings, assets, credentials, and open attack surfaces
into causal, multi-stage attack paths (Kill Chains) leading to Crown Jewel compromise.
"""

import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from backend.database import (
    SessionLocal,
    TargetAsset,
    TargetService,
    TargetEndpoint,
    Finding,
    HttpLog,
    ActiveSession,
    TestingHypothesis
)


SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 10
}


def _evaluate_asset_exposure(asset: TargetAsset) -> Tuple[str, str, str]:
    """
    Evaluates whether an asset is Public, Internal, or Firewalled based on IP, tags, and service states.
    Returns: (exposure_category, display_str, relationship_type)
    """
    tags_lower = (asset.tags or "").lower()
    host_lower = (asset.host or "").lower()
    ip_str = (asset.ip or "").strip()

    is_internal_ip = False
    if ip_str:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            is_internal_ip = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except Exception:
            pass

    is_internal_host = (
        is_internal_ip or
        host_lower in ["localhost", "127.0.0.1", "0.0.0.0", "::1"] or
        host_lower.endswith(".local") or
        host_lower.endswith(".internal") or
        "internal" in tags_lower
    )

    services = asset.services or []
    has_services = len(services) > 0
    open_services = [s for s in services if (s.state or "open").lower() == "open"]
    all_services_filtered = has_services and len(open_services) == 0

    is_firewalled = (
        all_services_filtered or
        "firewalled" in tags_lower or
        "filtered" in tags_lower or
        "waf" in tags_lower
    )

    if is_firewalled:
        display = ip_str if ip_str else "Firewalled"
        return "Firewalled", display, "FILTERED_BY_FIREWALL"
    elif is_internal_host:
        display = ip_str if ip_str else "Internal"
        return "Internal", display, "INTERNAL_PIVOT_REQUIRED"
    else:
        display = ip_str if ip_str else "Public"
        return "Public", display, "INTERNET_FACING"


def build_attack_path_graph(project: str = "default") -> Dict[str, Any]:
    """
    Constructs an interconnected multi-hop attack path graph linking:
    [External Attacker] -> [Exposed Asset/Service] -> [Initial Finding / Auth Bypass]
                        -> [Harvested Session / Credentials] -> [Protected Route]
                        -> [High-Impact Exploit] -> [Crown Jewels / Impact]
    """
    target_project = (project or "default").strip().lower()

    db = SessionLocal()
    try:
        if target_project in ["all", "*", "any", "global"]:
            assets = db.query(TargetAsset).all()
            findings = db.query(Finding).join(HttpLog).all()
            sessions = db.query(ActiveSession).all()
            hypotheses = db.query(TestingHypothesis).filter(TestingHypothesis.status.in_(["CONFIRMED", "TESTING"])).all()
        else:
            assets = db.query(TargetAsset).filter(TargetAsset.project == target_project).all()
            findings = db.query(Finding).join(HttpLog).filter(HttpLog.project == target_project).all()
            sessions = db.query(ActiveSession).filter(ActiveSession.project == target_project).all()
            hypotheses = db.query(TestingHypothesis).filter(
                TestingHypothesis.project == target_project,
                TestingHypothesis.status.in_(["CONFIRMED", "TESTING"])
            ).all()

        nodes = []
        edges = []
        chains = []
        existing_node_ids = set()

        def _add_node(n_dict):
            if n_dict["id"] not in existing_node_ids:
                existing_node_ids.add(n_dict["id"])
                nodes.append(n_dict)

        def _add_edge(from_id, to_id, rel):
            edges.append({
                "from": from_id,
                "to": to_id,
                "relationship": rel
            })

        # 1. Entry Point Node
        entry_node_id = "node_entry"
        _add_node({
            "id": entry_node_id,
            "label": "External Attacker / Autonomous Agent",
            "type": "ENTRY_POINT",
            "severity": "INFO"
        })

        asset_map = {}
        endpoint_node_map = {}
        protected_endpoints = []

        # 2. Asset & Infrastructure Topology
        for a in assets:
            a_node_id = f"asset_{a.id}"
            asset_map[a.host.lower()] = a_node_id
            exposure_cat, display_ip, relationship = _evaluate_asset_exposure(a)

            badge = f" [{exposure_cat}]" if exposure_cat in ["Firewalled", "Internal"] else ""
            _add_node({
                "id": a_node_id,
                "label": f"Host: {a.host} ({display_ip}){badge}",
                "type": "ASSET",
                "exposure": exposure_cat,
                "details": f"OS: {a.os_info or 'Unknown'} | Exposure: {exposure_cat}",
                "severity": "LOW" if exposure_cat == "Firewalled" else "INFO"
            })
            _add_edge(entry_node_id, a_node_id, relationship)

            # Services
            for svc in (a.services or []):
                svc_node_id = f"svc_{svc.id}"
                _add_node({
                    "id": svc_node_id,
                    "label": f"Port {svc.port}/{svc.protocol} ({svc.service_name})",
                    "type": "SERVICE",
                    "severity": "INFO"
                })
                _add_edge(a_node_id, svc_node_id, "EXPOSES_PORT")

            # Endpoints
            for ep in (a.endpoints or []):
                ep_node_id = f"ep_{ep.id}"
                endpoint_node_map[ep.id] = ep_node_id
                is_protected = bool(ep.auth_required or any(k in (ep.path or "").lower() for k in ["admin", "internal", "user", "order", "setting", "manage", "account", "dashboard"]))
                if is_protected:
                    protected_endpoints.append((ep, ep_node_id, a_node_id))

                if ep.tested_status in ["VULNERABLE", "TESTED", "IN_PROGRESS"] or is_protected:
                    prot_badge = " [AUTH_PROTECTED]" if is_protected else ""
                    _add_node({
                        "id": ep_node_id,
                        "label": f"{ep.method} {ep.path}{prot_badge}",
                        "type": "ENDPOINT",
                        "auth_required": is_protected,
                        "severity": "HIGH" if ep.tested_status == "VULNERABLE" else ("MEDIUM" if is_protected else "LOW")
                    })
                    _add_edge(a_node_id, ep_node_id, "ROUTES_TO")

        # 3. Active Sessions & Stolen Credentials (Multi-hop Pivot Bridge)
        session_nodes = []
        for s in sessions:
            s_node_id = f"session_{s.id}"
            role = (s.identity_role or "primary").upper()
            domain = s.domain or "target"
            _add_node({
                "id": s_node_id,
                "label": f"Stolen Session [{role}] @ {domain}",
                "type": "SESSION_CREDENTIAL",
                "severity": "HIGH",
                "details": f"Role: {role} | Domain: {domain}"
            })
            session_nodes.append((s, s_node_id))

            # Connect session to relevant protected endpoints on this domain/host
            matched_host = None
            for host_name, a_nid in asset_map.items():
                if domain.lower() in host_name or host_name in domain.lower():
                    matched_host = a_nid
                    break

            for ep, ep_nid, ep_anid in protected_endpoints:
                if matched_host is None or ep_anid == matched_host:
                    _add_edge(s_node_id, ep_nid, "AUTHENTICATED_ACCESS")

        # 4. Findings & Exploitation Nodes
        finding_nodes = []
        auth_harvesting_findings = []
        high_impact_findings = []

        for f in findings:
            f_node_id = f"vuln_{f.id}"
            f_sev = (f.severity or "MEDIUM").upper()
            cat_upper = (f.category or "").upper()
            title_upper = (f.title or "").upper()

            _add_node({
                "id": f_node_id,
                "label": f"[{f_sev}] {f.title}",
                "type": "VULNERABILITY",
                "severity": f_sev,
                "category": f.category
            })
            finding_nodes.append((f, f_node_id))

            # Connect Finding to originating Host / Endpoint
            host_node_id = None
            if f.log and f.log.host:
                host_node_id = asset_map.get(f.log.host.lower())
                if host_node_id:
                    _add_edge(host_node_id, f_node_id, "EXPLOITS")
                else:
                    _add_edge(entry_node_id, f_node_id, "EXPLOITS_EXTERNAL")
            else:
                _add_edge(entry_node_id, f_node_id, "EXPLOITS")

            # Check if this finding is an initial foothold / credential harvest
            is_auth_harvest = any(kw in title_upper or kw in cat_upper for kw in [
                "AUTH", "LOGIN", "CREDENTIAL", "TOKEN", "KEY", "SECRET", "SQL",
                "INJECTION", "LEAK", "DISCLOSURE", "BYPASS", "IDOR", "BOLA"
            ])
            if is_auth_harvest:
                auth_harvesting_findings.append((f, f_node_id, host_node_id))

            # Check for Crown Jewel / High Impact
            impact_label = None
            if "RCE" in title_upper or "COMMAND" in cat_upper or "EXECUTION" in title_upper:
                impact_label = "Crown Jewel: Host Takeover / Remote Code Execution"
            elif "SQL" in title_upper or "INJECTION" in cat_upper:
                impact_label = "Crown Jewel: Database Exfiltration & Data Tampering"
            elif "SSRF" in title_upper or "METADATA" in title_upper:
                impact_label = "Crown Jewel: Internal Network Pivot / Cloud Metadata Leak"
            elif "BOLA" in title_upper or "IDOR" in cat_upper:
                impact_label = "Crown Jewel: Horizontal Account Takeover / PII Breach"
            elif "AUTH" in cat_upper or "BYPASS" in title_upper or "PRIVILEGE" in title_upper:
                impact_label = "Crown Jewel: Administrative Privilege Escalation"
            elif f_sev in ["CRITICAL", "HIGH"]:
                impact_label = f"Crown Jewel: Critical Compromise via {f.title[:40]}"

            if impact_label:
                impact_node_id = f"impact_{f.id}"
                _add_node({
                    "id": impact_node_id,
                    "label": impact_label,
                    "type": "CROWN_JEWEL",
                    "severity": "CRITICAL"
                })
                _add_edge(f_node_id, impact_node_id, "ACHIEVES_IMPACT")
                high_impact_findings.append((f, f_node_id, host_node_id, impact_label, impact_node_id))

        # 5. Connect Causal Multi-Hop Chains:
        # Initial Finding -> Stolen Session -> Protected Endpoint -> High-Impact Finding -> Crown Jewel
        created_multi_hop = False
        if session_nodes:
            for s_obj, s_nid in session_nodes:
                # Link auth-harvesting finding to session
                if auth_harvesting_findings:
                    for af, af_nid, af_hnid in auth_harvesting_findings:
                        _add_edge(af_nid, s_nid, "HARVESTS_SESSION")
                else:
                    _add_edge(entry_node_id, s_nid, "COMPROMISED_CREDENTIALS")

                # If we have protected endpoints and high-impact findings, build a multi-hop kill chain
                for ep, ep_nid, ep_anid in protected_endpoints:
                    for hf, hf_nid, hf_hnid, h_label, h_nid in high_impact_findings:
                        _add_edge(ep_nid, hf_nid, "POST_AUTH_EXPLOIT")
                        chain_path = [
                            entry_node_id,
                            auth_harvesting_findings[0][1] if auth_harvesting_findings else entry_node_id,
                            s_nid,
                            ep_nid,
                            hf_nid,
                            h_nid
                        ]
                        chains.append({
                            "chain_id": f"chain_multi_{len(chains)+1}",
                            "type": "MULTI_HOP_KILL_CHAIN",
                            "target_impact": h_label,
                            "severity": "CRITICAL",
                            "hop_count": len(chain_path) - 1,
                            "stages": [
                                "Stage 1: External Access / Initial Reconnaissance",
                                f"Stage 2: Foothold Exploitation via {auth_harvesting_findings[0][0].title if auth_harvesting_findings else 'Harvested Credentials'}",
                                f"Stage 3: Credential Hijacking -> ActiveSession [{s_obj.identity_role}] on {s_obj.domain}",
                                f"Stage 4: Privileged Route Access -> {ep.method} {ep.path}",
                                f"Stage 5: High-Impact Compromise -> {hf.title}",
                                f"Stage 6: Crown Jewel Compromise -> {h_label}"
                            ],
                            "exploit_step": hf.title,
                            "target_host": hf.log.host if hf.log else "Target",
                            "path_nodes": chain_path
                        })
                        created_multi_hop = True
                        break
                    if created_multi_hop:
                        break

        # 6. Direct Exploitation Chains (for high-impact findings)
        for hf, hf_nid, hf_hnid, h_label, h_nid in high_impact_findings:
            direct_path = [entry_node_id, hf_hnid or "target", hf_nid, h_nid]
            chains.append({
                "chain_id": f"chain_direct_{len(chains)+1}",
                "type": "DIRECT_EXPLOITATION",
                "target_impact": h_label,
                "severity": (hf.severity or "HIGH").upper(),
                "hop_count": len(direct_path) - 1,
                "stages": [
                    "Stage 1: External Entry & Reconnaissance",
                    f"Stage 2: Target Host Exposure ({hf.log.host if hf.log else 'Host'})",
                    f"Stage 3: Vulnerability Exploitation ({hf.title})",
                    f"Stage 4: Impact Achievement ({h_label})"
                ],
                "exploit_step": hf.title,
                "target_host": hf.log.host if hf.log else "Unknown",
                "path_nodes": direct_path
            })

        # 7. Testing Hypothesis Integration (In-Flight Kill Chain Verification)
        for h in hypotheses:
            h_node_id = f"hyp_{h.id}"
            _add_node({
                "id": h_node_id,
                "label": f"Hypothesis [{h.status}]: {h.vuln_type} on {h.target}",
                "type": "HYPOTHESIS",
                "severity": "MEDIUM" if h.status == "CONFIRMED" else "INFO"
            })
            _add_edge(entry_node_id, h_node_id, f"TESTING_{h.status}")

        # 8. Generate Mermaid Diagram
        mermaid_lines = ["flowchart LR"]
        for n in nodes:
            safe_label = n["label"].replace('"', "'")
            shape_start, shape_end = ("[", "]")
            if n["type"] == "ENTRY_POINT":
                shape_start, shape_end = ("([", "])")
            elif n["type"] == "VULNERABILITY":
                shape_start, shape_end = ("{{", "}}")
            elif n["type"] == "SESSION_CREDENTIAL":
                shape_start, shape_end = ("[/", "/]")
            elif n["type"] == "CROWN_JEWEL":
                shape_start, shape_end = ("[[", "]]")
            elif n["type"] == "ENDPOINT":
                shape_start, shape_end = ("([", "])")
            elif n["type"] == "HYPOTHESIS":
                shape_start, shape_end = (">", "]")

            mermaid_lines.append(f'    {n["id"]}{shape_start}"{safe_label}"{shape_end}')

        for e in edges:
            mermaid_lines.append(f'    {e["from"]} -->|"{e["relationship"]}"| {e["to"]}')

        mermaid_code = "\n".join(mermaid_lines)

        return {
            "project": target_project,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_chains": len(chains),
            "critical_chains": [c for c in chains if c["severity"] in ["CRITICAL", "HIGH"]],
            "mermaid": mermaid_code,
            "nodes": nodes,
            "edges": edges,
            "chains": chains
        }
    finally:
        db.close()
