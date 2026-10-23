"""
Proxsynth - Semantic API Spec Reconstructor & Endpoint Inference Engine
Analyzes observed HTTP endpoints, reconstructs REST resource hierarchies,
and predicts hidden, unmapped attack surface routes (API docs, admin consoles, debug probes, mutations).
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from backend.database import SessionLocal, TargetAsset, TargetEndpoint
from backend.target_manager import add_or_update_endpoint

COMMON_DOCS_PROBES = [
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/graphql",
    "/api/graphql"
]

COMMON_MANAGEMENT_PROBES = [
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/actuator/heapdump",
    "/debug/pprof",
    "/metrics",
    "/.env",
    "/.git/HEAD",
    "/server-status"
]

COMMON_ADMIN_PROBES = [
    "/admin",
    "/administrator",
    "/api/admin",
    "/api/v1/admin",
    "/dashboard/admin",
    "/internal",
    "/api/internal"
]


def infer_endpoints_from_observed(
    host: str,
    project: str = "default",
    auto_register_to_graph: bool = True
) -> Dict[str, Any]:
    """
    Analyzes observed endpoints for a host and infers likely hidden/untested routes.
    Optionally registers high-confidence predictions into the Target Knowledge Graph.
    """
    clean_host = host.strip().lower()
    target_project = (project or "default").strip().lower()

    db = SessionLocal()
    try:
        asset = db.query(TargetAsset).filter(
            TargetAsset.project == target_project,
            TargetAsset.host == clean_host
        ).first()

        observed_endpoints = []
        observed_paths: Set[str] = set()
        if asset:
            for ep in (asset.endpoints or []):
                # An endpoint is genuinely observed if it was logged/tested, not an unverified prediction
                if not (ep.notes and "[Semantic Inferrer]" in ep.notes):
                    observed_endpoints.append(ep)
                    observed_paths.add(ep.path.lower().rstrip("/"))
    finally:
        db.close()

    inferred_candidates = []
    seen_inferred = set()

    def add_candidate(method: str, path: str, category: str, priority: str, confidence: str):
        clean_path = path.rstrip("/")
        if not clean_path:
            clean_path = "/"
        if clean_path.lower() in observed_paths or clean_path.lower() in seen_inferred:
            return
        seen_inferred.add(clean_path.lower())
        inferred_candidates.append({
            "method": method.upper(),
            "path": clean_path,
            "category": category,
            "priority": priority,
            "confidence": confidence,
            "rationale": f"Inferred {category} route based on architectural conventions"
        })

    # 1. Inspect existing REST paths to predict CRUD and versioning
    for ep in observed_endpoints:
        path = ep.path
        method = (ep.method or "GET").upper()

        # Check resource pattern: /api/v{N}/{resource} or /{resource}/{id}
        parts = [p for p in path.split("/") if p]
        if not parts:
            continue

        # Resource with ID: e.g. /api/users/12 -> test mutations
        id_match = re.search(r'/([a-zA-Z_-]+)/([0-9]+|[a-f0-9]{8,36})(?:/|$)', path)
        if id_match:
            resource = id_match.group(1)
            item_id = id_match.group(2)
            prefix = path[:id_match.start()]

            # Predict collection root
            add_candidate("GET", f"{prefix}/{resource}", "REST_COLLECTION", "HIGH", "HIGH")
            add_candidate("POST", f"{prefix}/{resource}", "REST_CREATION", "HIGH", "HIGH")

            # Predict item mutations
            for m in ["PUT", "PATCH", "DELETE"]:
                add_candidate(m, f"{prefix}/{resource}/{item_id}", "REST_MUTATION", "HIGH", "HIGH")

            # Predict common sub-resources
            for sub in ["export", "download", "settings", "profile", "permissions", "history", "logs"]:
                add_candidate("GET", f"{prefix}/{resource}/{item_id}/{sub}", "SUB_RESOURCE", "MEDIUM", "MEDIUM")

        # API Version Probes: /api/v1/... -> predict /api/v2/..., /api/v3/...
        v_match = re.search(r'/(v[0-9]+)/', path, re.IGNORECASE)
        if v_match:
            curr_v = v_match.group(1)
            # Try v1, v2, v3
            for v_target in ["v1", "v2", "v3", "internal"]:
                if v_target.lower() != curr_v.lower():
                    new_path = path.replace(f"/{curr_v}/", f"/{v_target}/")
                    add_candidate("GET", new_path, "API_VERSION_PROBE", "HIGH", "MEDIUM")

    # 2. Add Standard API Documentation Probes
    for doc in COMMON_DOCS_PROBES:
        add_candidate("GET", doc, "API_DOCUMENTATION", "CRITICAL", "HIGH")

    # 3. Add Sensitive Management & Debug Probes
    for mgmt in COMMON_MANAGEMENT_PROBES:
        add_candidate("GET", mgmt, "MANAGEMENT_EXPOSURE", "HIGH", "MEDIUM")

    # 4. Add Internal / Admin Probes
    for adm in COMMON_ADMIN_PROBES:
        add_candidate("GET", adm, "ADMIN_SURFACE", "HIGH", "MEDIUM")

    # Optionally auto-register into Target Knowledge Graph
    registered_count = 0
    if auto_register_to_graph and inferred_candidates:
        scheme = "https"
        for cand in inferred_candidates:
            target_url = f"{scheme}://{clean_host}{cand['path']}"
            try:
                add_or_update_endpoint(
                    project=target_project,
                    host=clean_host,
                    url=target_url,
                    method=cand["method"],
                    tested_status="UNTESTED",
                    notes=f"[Semantic Inferrer] {cand['category']}: {cand['rationale']}"
                )
                registered_count += 1
            except Exception:
                pass

    return {
        "host": clean_host,
        "project": target_project,
        "observed_endpoint_count": len(observed_endpoints),
        "inferred_endpoint_count": len(inferred_candidates),
        "auto_registered_count": registered_count,
        "predictions": inferred_candidates
    }
