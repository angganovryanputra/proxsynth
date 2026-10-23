"""
Proxsynth MCP - Auto-Reverse OpenAPI 3.0.3 Specification Generator
Extracts real-time observed HTTP proxy traffic and synthesizes a valid, structured OpenAPI 3.0 specification.
"""

import json
import urllib.parse
from typing import Dict, Any, List, Set
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import HttpLog, Project


def _infer_type(val: Any) -> str:
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "integer"
    if isinstance(val, float):
        return "number"
    if isinstance(val, list):
        return "array"
    if isinstance(val, dict):
        return "object"
    return "string"


def _json_to_schema(data: Any) -> Dict[str, Any]:
    """Recursively converts a Python JSON-compatible object into an OpenAPI Schema."""
    t = _infer_type(data)
    if t == "object" and isinstance(data, dict):
        properties = {}
        for k, v in data.items():
            properties[k] = _json_to_schema(v)
        return {"type": "object", "properties": properties}
    elif t == "array" and isinstance(data, list):
        if data:
            return {"type": "array", "items": _json_to_schema(data[0])}
        return {"type": "array", "items": {"type": "string"}}
    else:
        return {"type": t, "example": data}


def generate_openapi_spec(project_name: str, db: Session) -> Dict[str, Any]:
    """
    Constructs an OpenAPI 3.0.3 specification by inspecting logged HTTP traffic for a given project.
    """
    clean_project = (project_name or "default").strip().lower()
    
    # Query project info
    proj = db.query(Project).filter(Project.name == clean_project).first()
    proj_desc = proj.description if proj and proj.description else f"Observed API endpoints captured by Proxsynth MCP for project '{clean_project}'"

    # Query logs
    query = db.query(HttpLog)
    if clean_project != "all":
        query = query.filter(HttpLog.project == clean_project)
    
    logs = query.order_by(HttpLog.id.asc()).all()

    servers_set: Set[str] = set()
    paths: Dict[str, Dict[str, Any]] = {}

    for log in logs:
        parsed = urllib.parse.urlparse(log.url)
        scheme = parsed.scheme or "http"
        host = parsed.netloc or log.host or "127.0.0.1"
        base_server = f"{scheme}://{host}"
        servers_set.add(base_server)

        raw_path = parsed.path or "/"
        method = (log.method or "GET").lower()

        if raw_path not in paths:
            paths[raw_path] = {}

        # If method already defined, enhance it
        if method not in paths[raw_path]:
            # Extract Tag based on path first segment
            segments = [s for s in raw_path.split("/") if s]
            tag = segments[0].capitalize() if segments else "General"

            paths[raw_path][method] = {
                "tags": [tag],
                "summary": f"{method.upper()} {raw_path}",
                "description": f"Observed from Proxsynth MCP proxy traffic (Last reasoning: {log.reasoning or 'Automated AI Pentest'})",
                "parameters": [],
                "responses": {}
            }

        operation = paths[raw_path][method]

        # Extract Query Parameters
        if parsed.query:
            query_dict = urllib.parse.parse_qs(parsed.query)
            existing_param_names = {p["name"] for p in operation.get("parameters", []) if p.get("in") == "query"}
            for q_name, q_vals in query_dict.items():
                if q_name not in existing_param_names:
                    val = q_vals[0] if q_vals else ""
                    # Check if integer
                    val_type = "integer" if val.isdigit() else "string"
                    operation["parameters"].append({
                        "name": q_name,
                        "in": "query",
                        "required": False,
                        "schema": {"type": val_type, "example": val}
                    })

        # Extract Request Body if JSON and method in POST/PUT/PATCH
        if method in ["post", "put", "patch"] and log.request_body and log.request_body.strip():
            try:
                parsed_body = json.loads(log.request_body)
                schema = _json_to_schema(parsed_body)
                if "requestBody" not in operation:
                    operation["requestBody"] = {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": schema,
                                "example": parsed_body
                            }
                        }
                    }
            except Exception:
                pass

        # Extract Responses
        status_str = str(log.status_code) if log.status_code else "200"
        if status_str not in operation["responses"]:
            res_content: Dict[str, Any] = {}
            if log.response_body and log.response_body.strip():
                try:
                    parsed_res = json.loads(log.response_body)
                    res_content["application/json"] = {
                        "schema": _json_to_schema(parsed_res),
                        "example": parsed_res
                    }
                except Exception:
                    # Text / HTML
                    res_content["text/plain"] = {
                        "schema": {"type": "string"},
                        "example": log.response_body[:200]
                    }

            status_desc_map = {
                "200": "OK - Successful operation",
                "201": "Created - Resource generated",
                "204": "No Content",
                "301": "Moved Permanently",
                "302": "Found / Redirect",
                "400": "Bad Request - Potential input anomaly",
                "401": "Unauthorized - Missing credentials",
                "403": "Forbidden - Permission denied",
                "404": "Not Found",
                "500": "Internal Server Error - Server failure"
            }
            desc_text = status_desc_map.get(status_str, f"HTTP {status_str} Response")

            response_spec: Dict[str, Any] = {"description": desc_text}
            if res_content:
                response_spec["content"] = res_content

            operation["responses"][status_str] = response_spec

    # Build OpenAPI Spec
    servers = [{"url": s, "description": "Target Host"} for s in sorted(servers_set)] if servers_set else [{"url": "http://127.0.0.1:8000"}]

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": f"Proxsynth MCP Auto-Reverse API - {clean_project.upper()}",
            "version": "2.5.0",
            "description": proj_desc,
            "contact": {
                "name": "Proxsynth Observability Engine",
                "url": "https://github.com/proxsynth-mcp"
            }
        },
        "servers": servers,
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                },
                "cookieAuth": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "session"
                }
            }
        }
    }

    return spec
