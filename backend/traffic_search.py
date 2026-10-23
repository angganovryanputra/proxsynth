"""
Proxsynth MCP - Multi-Dimensional & Semantic Traffic Search Engine
Provides comprehensive query capabilities and parameter discovery across captured HTTP traffic,
allowing autonomous AI agents to search by latency, status codes, parameter names, full-text bodies,
and vulnerability status without pulling entire database dumps.
"""

import re
import json
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set

from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, and_
from backend.database import SessionLocal, HttpLog, Finding, Project


def search_traffic_advanced(
    query: str = "",
    domain: Optional[str] = None,
    method: Optional[str] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    path_pattern: Optional[str] = None,
    has_findings: bool = False,
    min_duration_ms: Optional[int] = None,
    project: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """
    Executes a multi-dimensional search over stored HTTP proxy traffic.
    Returns matching logs with highlights and summary metrics.
    """
    db = SessionLocal()
    try:
        q = db.query(HttpLog)

        # 1. Project filtering
        if project and project.strip().lower() not in ["all", "*", "any", "global"]:
            proj = project.strip().lower()
            q = q.filter(HttpLog.project == proj)

        # 2. Domain / Host filtering
        if domain and domain.strip():
            clean_dom = domain.strip().lower()
            q = q.filter(or_(HttpLog.host == clean_dom, HttpLog.host.like(f"%.{clean_dom}")))

        # 3. HTTP Method
        if method and method.strip() and method.strip() != "*":
            q = q.filter(HttpLog.method == method.strip().upper())

        # 4. Status code range
        if status_min is not None:
            q = q.filter(HttpLog.status_code >= status_min)
        if status_max is not None:
            q = q.filter(HttpLog.status_code <= status_max)

        # 5. Path pattern
        if path_pattern and path_pattern.strip() and path_pattern.strip() != "*":
            pat = path_pattern.strip()
            if "*" in pat:
                sql_like = pat.replace("*", "%")
                q = q.filter(HttpLog.path.like(sql_like))
            else:
                q = q.filter(HttpLog.path.contains(pat))

        # 6. Minimum latency
        if min_duration_ms is not None and min_duration_ms > 0:
            q = q.filter(HttpLog.duration_ms >= min_duration_ms)

        # 7. Vulnerability findings flag
        if has_findings:
            q = q.filter(HttpLog.flag_status.in_(["VULNERABLE", "CONFIRMED", "POTENTIAL", "FLAGGED"]))

        # 8. Full-text search across URL, request/response body, reasoning
        if query and query.strip():
            term = query.strip()
            like_term = f"%{term}%"
            q = q.filter(or_(
                HttpLog.url.like(like_term),
                HttpLog.request_body.like(like_term),
                HttpLog.response_body.like(like_term),
                HttpLog.reasoning.like(like_term)
            ))

        total_count = q.count()
        logs = q.order_by(HttpLog.id.desc()).offset(offset).limit(limit).all()

        results = []
        for l in logs:
            entry = l.to_dict()
            # Truncate large bodies for compact JSON return
            if len(entry.get("request_body", "")) > 1000:
                entry["request_body"] = entry["request_body"][:1000] + "... [TRUNCATED]"
            if len(entry.get("response_body", "")) > 1000:
                entry["response_body"] = entry["response_body"][:1000] + "... [TRUNCATED]"
            results.append(entry)

        return {
            "total_matches": total_count,
            "returned_count": len(results),
            "limit": limit,
            "offset": offset,
            "filters": {
                "query": query,
                "domain": domain,
                "method": method,
                "status_range": f"{status_min or '*'}-{status_max or '*'}",
                "path_pattern": path_pattern,
                "has_findings": has_findings,
                "min_duration_ms": min_duration_ms,
                "project": project
            },
            "results": results
        }
    finally:
        db.close()


def analyze_traffic_patterns(project: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyzes all captured traffic in a project, aggregating endpoint routes,
    status code distributions, discovered parameter inventory, and performance metrics.
    """
    db = SessionLocal()
    try:
        q = db.query(HttpLog)
        if project and project.strip().lower() not in ["all", "*", "any", "global"]:
            proj = project.strip().lower()
            q = q.filter(HttpLog.project == proj)

        logs = q.all()
        if not logs:
            return {
                "project": project or "all",
                "total_requests": 0,
                "message": "No traffic captured yet for this project."
            }

        status_dist = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
        method_dist: Dict[str, int] = {}
        host_dist: Dict[str, int] = {}
        unique_endpoints: Set[str] = set()
        param_inventory: Dict[str, Set[str]] = {
            "query_params": set(),
            "body_params": set(),
            "headers_seen": set()
        }
        total_duration = 0
        max_duration = 0
        slowest_endpoint = ""
        vulnerable_count = 0

        for l in logs:
            # Status distribution
            code = l.status_code or 0
            if 200 <= code <= 299:
                status_dist["2xx"] += 1
            elif 300 <= code <= 399:
                status_dist["3xx"] += 1
            elif 400 <= code <= 499:
                status_dist["4xx"] += 1
            elif 500 <= code <= 599:
                status_dist["5xx"] += 1
            else:
                status_dist["other"] += 1

            # Method distribution
            m = (l.method or "GET").upper()
            method_dist[m] = method_dist.get(m, 0) + 1

            # Host distribution
            h = (l.host or "unknown").lower()
            host_dist[h] = host_dist.get(h, 0) + 1

            # Unique endpoint
            path = (l.path or "/").split("?")[0]
            unique_endpoints.add(f"{m} {path}")

            # Latency
            dur = l.duration_ms or 0
            total_duration += dur
            if dur > max_duration:
                max_duration = dur
                slowest_endpoint = f"{m} {l.url}"

            # Flags
            if l.flag_status in ["VULNERABLE", "CONFIRMED", "POTENTIAL", "FLAGGED"]:
                vulnerable_count += 1

            # Parameter discovery
            if "?" in (l.url or ""):
                try:
                    parsed = urllib.parse.urlparse(l.url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    for k in qs.keys():
                        param_inventory["query_params"].add(k)
                except Exception:
                    pass

            # Body parameters
            rb = l.request_body or ""
            if rb:
                if rb.strip().startswith("{") and rb.strip().endswith("}"):
                    try:
                        data = json.loads(rb)
                        if isinstance(data, dict):
                            for k in data.keys():
                                param_inventory["body_params"].add(k)
                    except Exception:
                        pass
                elif "=" in rb and "&" in rb:
                    try:
                        parsed_b = urllib.parse.parse_qs(rb)
                        for k in parsed_b.keys():
                            param_inventory["body_params"].add(k)
                    except Exception:
                        pass

            # Headers seen
            try:
                hdrs = json.loads(l.request_headers) if l.request_headers else {}
                if isinstance(hdrs, dict):
                    for k in hdrs.keys():
                        param_inventory["headers_seen"].add(k)
            except Exception:
                pass

        avg_duration = round(total_duration / len(logs), 2) if logs else 0

        return {
            "project": project or "all",
            "total_requests": len(logs),
            "status_distribution": status_dist,
            "method_distribution": method_dist,
            "top_hosts": dict(sorted(host_dist.items(), key=lambda x: x[1], reverse=True)[:10]),
            "unique_endpoint_count": len(unique_endpoints),
            "unique_endpoints": sorted(list(unique_endpoints))[:50],
            "parameter_inventory": {
                "discovered_query_params": sorted(list(param_inventory["query_params"])),
                "discovered_body_params": sorted(list(param_inventory["body_params"])),
                "total_unique_params": len(param_inventory["query_params"] | param_inventory["body_params"])
            },
            "performance_metrics": {
                "average_duration_ms": avg_duration,
                "max_duration_ms": max_duration,
                "slowest_endpoint": slowest_endpoint
            },
            "security_summary": {
                "vulnerable_requests_count": vulnerable_count,
                "clean_requests_count": len(logs) - vulnerable_count
            }
        }
    finally:
        db.close()
