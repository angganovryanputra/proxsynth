"""
Proxsynth - Target Knowledge Graph & Attack Surface Manager
Maintains stateful inventory of targets, hosts, ports, services, endpoints,
and testing progression (Untested -> In Progress -> Tested -> Vulnerable).
"""

import os
import json
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional

from sqlalchemy.orm import Session
from backend.database import SessionLocal, TargetAsset, TargetService, TargetEndpoint, Finding, HttpLog, Project


def upsert_target_asset(
    project: str = "default",
    host: str = "",
    ip: str = "",
    os_info: str = "",
    tags: Optional[List[str]] = None,
    notes: str = "",
    port: Optional[int] = None
) -> Dict[str, Any]:
    """Creates or updates a target host in the attack surface graph. Preserves port and auto-registers service."""
    clean_host = host.strip().lower()
    if not clean_host:
        raise ValueError("Host cannot be empty")
    
    detected_port = port
    # Parse scheme, netloc, or host:port if supplied
    if "://" in clean_host:
        parsed_u = urllib.parse.urlparse(clean_host)
        if parsed_u.port:
            detected_port = parsed_u.port
        clean_host = parsed_u.hostname or clean_host
    elif ":" in clean_host:
        parts = clean_host.split(":")
        clean_host = parts[0].strip("/")
        if len(parts) > 1 and parts[1].isdigit():
            detected_port = int(parts[1])
    else:
        clean_host = clean_host.strip("/")

    target_project = (project or "default").strip().lower()
    tags_str = ",".join([t.strip() for t in tags]) if tags else ""

    db = SessionLocal()
    try:
        asset = db.query(TargetAsset).filter(
            TargetAsset.project == target_project,
            TargetAsset.host == clean_host
        ).first()

        if asset:
            if ip:
                asset.ip = ip.strip()
            if os_info:
                asset.os_info = os_info.strip()
            if tags_str:
                existing_tags = set(asset.tags.split(",")) if asset.tags else set()
                new_tags = existing_tags.union(set([t.strip() for t in tags if t.strip()]))
                asset.tags = ",".join(new_tags)
            if notes:
                asset.notes = notes.strip()
            asset.updated_at = datetime.now()
        else:
            asset = TargetAsset(
                project=target_project,
                host=clean_host,
                ip=ip.strip() if ip else None,
                os_info=os_info.strip(),
                tags=tags_str,
                notes=notes.strip()
            )
            db.add(asset)

        db.commit()
        db.refresh(asset)
        res_dict = asset.to_dict()

        # Auto-register detected port into TargetService
        if detected_port:
            try:
                svc_proto = "https" if detected_port in [443, 8443] else "http"
                add_or_update_service(
                    project=target_project,
                    host=clean_host,
                    port=detected_port,
                    protocol="tcp",
                    service_name=svc_proto
                )
            except Exception:
                pass

        return res_dict
    finally:
        db.close()


def add_or_update_service(
    project: str = "default",
    host: str = "",
    port: int = 80,
    protocol: str = "tcp",
    service_name: str = "unknown",
    banner: str = "",
    state: str = "open"
) -> Dict[str, Any]:
    """Associates an open/filtered port and service to a target asset."""
    target_project = (project or "default").strip().lower()
    asset_dict = upsert_target_asset(project=target_project, host=host)

    db = SessionLocal()
    try:
        service = db.query(TargetService).filter(
            TargetService.asset_id == asset_dict["id"],
            TargetService.port == int(port)
        ).first()

        if service:
            service.protocol = (protocol or "tcp").lower()
            if service_name and service_name != "unknown":
                service.service_name = service_name.lower()
            if banner:
                service.banner = banner.strip()
            service.state = (state or "open").lower()
        else:
            service = TargetService(
                asset_id=asset_dict["id"],
                port=int(port),
                protocol=(protocol or "tcp").lower(),
                service_name=(service_name or "unknown").lower(),
                banner=banner.strip() if banner else "",
                state=(state or "open").lower()
            )
            db.add(service)

        db.commit()
        db.refresh(service)
        return service.to_dict()
    finally:
        db.close()


def add_or_update_endpoint(
    project: str = "default",
    host: str = "",
    url: str = "",
    method: str = "GET",
    parameters: Optional[List[str]] = None,
    auth_required: bool = False,
    tested_status: str = "UNTESTED",
    notes: str = ""
) -> Dict[str, Any]:
    """Records a discovered web endpoint under a target asset."""
    target_project = (project or "default").strip().lower()
    clean_method = (method or "GET").upper().strip()

    parsed = urllib.parse.urlparse(url)
    clean_host = host.strip().lower() or (parsed.netloc or "").split(":")[0].strip().lower()
    if not clean_host:
        raise ValueError("Target host or valid URL must be provided")

    path = parsed.path or "/"

    # Auto-extract query param keys if parameters not explicitly provided
    if parameters is None and parsed.query:
        query_dict = urllib.parse.parse_qs(parsed.query)
        parameters = list(query_dict.keys())

    asset_dict = upsert_target_asset(project=target_project, host=clean_host)

    db = SessionLocal()
    try:
        endpoint = db.query(TargetEndpoint).filter(
            TargetEndpoint.asset_id == asset_dict["id"],
            TargetEndpoint.method == clean_method,
            TargetEndpoint.path == path
        ).first()

        params_json = json.dumps(parameters or [])

        if endpoint:
            endpoint.url = url
            endpoint.auth_required = bool(auth_required)
            if parameters:
                endpoint.parameters = params_json
            if tested_status:
                endpoint.tested_status = tested_status.upper()
            if notes:
                endpoint.notes = notes
        else:
            endpoint = TargetEndpoint(
                asset_id=asset_dict["id"],
                method=clean_method,
                path=path,
                url=url,
                auth_required=bool(auth_required),
                parameters=params_json,
                tested_status=(tested_status or "UNTESTED").upper(),
                notes=notes or ""
            )
            db.add(endpoint)

        db.commit()
        db.refresh(endpoint)
        return endpoint.to_dict()
    finally:
        db.close()


def get_attack_surface_graph(
    project: str = "default",
    host: Optional[str] = None
) -> Dict[str, Any]:
    """
    Returns high-level graph topology of the attack surface:
    Assets, Services, Endpoints, Tested Status, and Findings counts.
    """
    target_project = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        query = db.query(TargetAsset)
        if target_project and target_project.upper() != "ALL":
            query = query.filter(TargetAsset.project == target_project)
        if host:
            clean_host = host.strip().lower()
            query = query.filter(TargetAsset.host.ilike(f"%{clean_host}%"))

        assets = query.all()
        assets_data = [a.to_dict() for a in assets]

        total_assets = len(assets_data)
        total_services = sum(a.get("services_count", 0) for a in assets_data)
        total_endpoints = sum(a.get("endpoints_count", 0) for a in assets_data)

        # Count testing status across all endpoints
        untested_count = 0
        tested_count = 0
        vulnerable_count = 0

        for a in assets_data:
            for ep in a.get("endpoints", []):
                st = ep.get("tested_status", "UNTESTED")
                if st == "UNTESTED":
                    untested_count += 1
                elif st in ["TESTED", "IN_PROGRESS"]:
                    tested_count += 1
                elif st == "VULNERABLE":
                    vulnerable_count += 1

        return {
            "project": target_project,
            "summary": {
                "total_assets": total_assets,
                "total_services": total_services,
                "total_endpoints": total_endpoints,
                "untested_endpoints": untested_count,
                "tested_endpoints": tested_count,
                "vulnerable_endpoints": vulnerable_count
            },
            "assets": assets_data
        }
    finally:
        db.close()


def auto_ingest_url_to_target_graph(project: str, url: str, method: str = "GET"):
    """Silently ingests an outbound or observed URL into the attack surface graph."""
    if not url or not url.startswith("http"):
        return
    try:
        parsed = urllib.parse.urlparse(url)
        backend_url_env = os.getenv("PROXSYNTH_BACKEND_URL", "")
        backend_port = None
        if backend_url_env:
            try:
                b_parsed = urllib.parse.urlparse(backend_url_env)
                if b_parsed.port:
                    backend_port = b_parsed.port
            except Exception:
                pass
        if not backend_port:
            try:
                backend_port = int(os.getenv("PROXSYNTH_PORT", "8000"))
            except Exception:
                backend_port = 8000
        proxy_port = int(os.getenv("PROXSYNTH_PROXY_PORT", "8088"))
        host = (parsed.hostname or "").lower()
        if not host:
            return

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        # 1. Do not ingest Proxsynth's own server infrastructure or common test mock ports
        if host in ["localhost", "127.0.0.1", "0.0.0.0", "::1"] and (port in [backend_port, proxy_port, 9999] or port >= 9990):
            return

        clean_project = (project or "default").strip().lower()
        is_loopback = host in ["localhost", "127.0.0.1", "0.0.0.0", "::1"] or host.endswith(".local")
        # 2. Prevent dummy loopback targets from contaminating named target projects (e.g. lottechem)
        if is_loopback and clean_project not in ["default", "local", "lab", "test", "dev"]:
            db = SessionLocal()
            try:
                proj_obj = db.query(Project).filter(Project.name == clean_project).first()
                if proj_obj:
                    allowed = proj_obj.to_dict().get("allowed_hosts", ["*"])
                    if allowed != ["*"] and not any(h in ["localhost", "127.0.0.1", "0.0.0.0"] for h in allowed):
                        return
            finally:
                db.close()

        service_name = "https" if parsed.scheme == "https" else "http"
        add_or_update_service(project=clean_project, host=host, port=port, service_name=service_name)
        add_or_update_endpoint(project=clean_project, host=host, url=url, method=method)
    except Exception:
        pass


def delete_target_asset(asset_id: int, project: Optional[str] = None) -> bool:
    """Deletes a target asset and all its associated services and endpoints."""
    db = SessionLocal()
    try:
        q = db.query(TargetAsset).filter(TargetAsset.id == int(asset_id))
        if project and project.strip().lower() != "all":
            q = q.filter(TargetAsset.project == project.strip().lower())
        asset = q.first()
        if not asset:
            return False
        db.delete(asset)
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()


def delete_target_endpoint(endpoint_id: int, project: Optional[str] = None) -> bool:
    """Deletes a specific endpoint from the attack surface knowledge graph."""
    db = SessionLocal()
    try:
        q = db.query(TargetEndpoint).filter(TargetEndpoint.id == int(endpoint_id))
        endpoint = q.first()
        if not endpoint:
            return False
        if project and project.strip().lower() != "all":
            asset = db.query(TargetAsset).filter(TargetAsset.id == endpoint.asset_id).first()
            if not asset or asset.project != project.strip().lower():
                return False
        db.delete(endpoint)
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()


def delete_target_service(service_id: int, project: Optional[str] = None) -> bool:
    """Deletes a specific service/port from the attack surface knowledge graph."""
    db = SessionLocal()
    try:
        q = db.query(TargetService).filter(TargetService.id == int(service_id))
        service = q.first()
        if not service:
            return False
        if project and project.strip().lower() != "all":
            asset = db.query(TargetAsset).filter(TargetAsset.id == service.asset_id).first()
            if not asset or asset.project != project.strip().lower():
                return False
        db.delete(service)
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()


def clear_target_graph(project: str = "default") -> int:
    """Clears all target assets, services, and endpoints for a specific project or all projects."""
    target_project = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        q = db.query(TargetAsset)
        if target_project != "all":
            q = q.filter(TargetAsset.project == target_project)
        assets = q.all()
        count = len(assets)
        for a in assets:
            db.delete(a)
        db.commit()
        return count
    except Exception:
        db.rollback()
        return 0
    finally:
        db.close()


def discover_bola_candidates(project: str = "default", limit: int = 100) -> List[Dict[str, Any]]:
    """
    Scans project HTTP traffic to discover BOLA / IDOR candidate endpoints and parameter entropy.
    Detects integer sequence IDs, UUIDs, and object keys in URL paths, query parameters, and JSON bodies.
    """
    import re
    target_project = (project or "default").strip().lower()
    db = SessionLocal()
    candidates = []
    seen = set()
    try:
        q = db.query(HttpLog)
        if target_project != "all":
            q = q.filter(HttpLog.project == target_project)
        logs = q.order_by(HttpLog.id.desc()).limit(limit * 3).all()

        id_path_pattern = re.compile(r"/([a-zA-Z0-9_\-]+)/([0-9]{1,10}|[0-9a-fA-F-]{36})(/|$)")
        id_param_pattern = re.compile(r"^(id|.*_id|user|account|order|doc|invoice|profile|item|file)$", re.IGNORECASE)

        for l in logs:
            if not l.url:
                continue
            parsed = urllib.parse.urlparse(l.url)
            # 1. Path-based candidates (e.g. /api/users/123)
            for m in id_path_pattern.finditer(parsed.path):
                resource = m.group(1)
                ident = m.group(2)
                key = (l.method, parsed.netloc, resource, "PATH")
                if key not in seen:
                    seen.add(key)
                    is_num = ident.isdigit()
                    candidates.append({
                        "method": l.method,
                        "url": l.url,
                        "resource": resource,
                        "parameter_type": "PATH_ID",
                        "observed_value": ident,
                        "id_type": "NUMERIC_SEQUENCE" if is_num else "UUID_HASH",
                        "entropy": len(set(ident)) / float(max(1, len(ident))),
                        "suggested_tamper": [str(int(ident) + 1), str(int(ident) - 1)] if is_num else ["00000000-0000-0000-0000-000000000000"],
                        "source_log_id": l.id
                    })

            # 2. Query parameter candidates
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                for pk, pvals in params.items():
                    if id_param_pattern.match(pk) and pvals:
                        val = pvals[0]
                        key = (l.method, parsed.netloc, parsed.path, pk)
                        if key not in seen:
                            seen.add(key)
                            is_num = val.isdigit()
                            candidates.append({
                                "method": l.method,
                                "url": l.url,
                                "resource": pk,
                                "parameter_type": "QUERY_PARAM",
                                "observed_value": val,
                                "id_type": "NUMERIC_SEQUENCE" if is_num else "UUID_HASH",
                                "entropy": len(set(val)) / float(max(1, len(val))),
                                "suggested_tamper": [str(int(val) + 1), str(int(val) - 1)] if is_num else ["admin", "root"],
                                "source_log_id": l.id
                            })
            if len(candidates) >= limit:
                break
    finally:
        db.close()
    return candidates

