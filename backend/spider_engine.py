"""
PROXSYNTH — Autonomous Web Spider & Form Discovery Engine
Recursively crawls web targets, extracts forms, inputs, endpoints, and scripts,
and automatically ingests them into the Target Knowledge Graph without human intervention.
"""

import re
import urllib.parse
from html.parser import HTMLParser
from typing import Dict, List, Set, Any, Optional
import httpx

from backend.target_manager import upsert_target_asset, add_or_update_endpoint
from backend.user_agents import get_random_user_agent


class WebPageExtractor(HTMLParser):
    """HTML Parser that extracts links, forms, input fields, and script endpoints."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.scripts: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[tuple]):
        attr_dict = dict(attrs)

        # Links
        if tag == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urllib.parse.urljoin(self.base_url, href)
                self.links.add(full_url)

        # Script sources
        elif tag == "script" and "src" in attr_dict:
            src = attr_dict["src"].strip()
            if src:
                self.scripts.add(urllib.parse.urljoin(self.base_url, src))

        # Forms
        elif tag == "form":
            action = attr_dict.get("action", "").strip()
            form_url = urllib.parse.urljoin(self.base_url, action) if action else self.base_url
            method = attr_dict.get("method", "GET").upper()
            enctype = attr_dict.get("enctype", "application/x-www-form-urlencoded")
            self._current_form = {
                "action": form_url,
                "method": method,
                "enctype": enctype,
                "inputs": []
            }

        # Form Inputs
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                input_type = attr_dict.get("type", "text" if tag == "input" else tag).lower()
                value = attr_dict.get("value", "")
                self._current_form["inputs"].append({
                    "name": name,
                    "type": input_type,
                    "value": value
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


async def crawl_and_map_target(
    root_url: str,
    max_depth: int = 3,
    max_pages: int = 30,
    project: str = "default",
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Autonomously crawl a web target to map out endpoints, forms, input sinks,
    and automatically ingest everything into the Target Knowledge Graph.
    """
    parsed_root = urllib.parse.urlparse(root_url)
    root_domain = parsed_root.netloc

    visited_urls: Set[str] = set()
    queue: List[tuple] = [(root_url, 0)]  # (url, depth)
    discovered_endpoints: List[Dict[str, Any]] = []
    discovered_forms: List[Dict[str, Any]] = []
    discovered_scripts: Set[str] = set()
    vulnerable_sinks: List[Dict[str, Any]] = []

    request_headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    if headers:
        request_headers.update(headers)

    # Ingest Root Target Asset into Target Knowledge Graph
    try:
        upsert_target_asset(
            project=project,
            host=root_domain,
            notes=f"Auto-mapped from root: {root_url}"
        )
    except Exception:
        pass

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=httpx.Timeout(4.0, connect=1.0)
    ) as client:
        while queue and len(visited_urls) < max_pages:
            current_url, depth = queue.pop(0)

            # Normalize URL (strip fragment)
            clean_url = urllib.parse.urldefrag(current_url)[0]
            if clean_url in visited_urls:
                continue

            # Scope Check: Stay on same host/domain
            parsed_current = urllib.parse.urlparse(clean_url)
            if parsed_current.netloc != root_domain:
                continue

            visited_urls.add(clean_url)

            try:
                res = await client.get(clean_url, headers=request_headers)
            except Exception:
                continue

            content_type = res.headers.get("content-type", "").lower()
            status_code = res.status_code
            endpoint_path = parsed_current.path or "/"

            # Ingest Endpoint into Knowledge Graph
            try:
                add_or_update_endpoint(
                    project=project,
                    host=root_domain,
                    url=clean_url,
                    method="GET",
                    tested_status="DISCOVERED",
                    notes=f"Spider status: {status_code}"
                )
            except Exception:
                pass

            discovered_endpoints.append({
                "url": clean_url,
                "path": endpoint_path,
                "method": "GET",
                "status_code": status_code,
                "depth": depth
            })

            # If HTML, extract links and forms
            if "text/html" in content_type:
                extractor = WebPageExtractor(clean_url)
                extractor.feed(res.text)

                # Ingest Scripts
                for s in extractor.scripts:
                    discovered_scripts.add(s)

                # Ingest Forms
                for f in extractor.forms:
                    discovered_forms.append(f)
                    input_names = [i["name"] for i in f.get("inputs", [])]
                    is_auth_form = any(k in "".join(input_names).lower() for k in ["pass", "user", "login", "auth"])
                    is_upload_form = any(i.get("type") == "file" for i in f.get("inputs", []))
                    is_numeric_form = any(i.get("type") == "number" or k in "".join(input_names).lower() for k in ["price", "qty", "amount", "total", "balance"])

                    if is_auth_form or is_upload_form or is_numeric_form:
                        vulnerable_sinks.append({
                            "action": f["action"],
                            "method": f["method"],
                            "sink_type": "AUTHENTICATION" if is_auth_form else ("FILE_UPLOAD" if is_upload_form else "NUMERIC_LOGIC"),
                            "inputs": input_names
                        })

                    # Ingest form action into Knowledge Graph
                    try:
                        add_or_update_endpoint(
                            project=project,
                            host=root_domain,
                            url=f["action"],
                            method=f["method"],
                            parameters=input_names,
                            tested_status="DISCOVERED",
                            notes=f"Form inputs: {', '.join(input_names[:5])}"
                        )
                    except Exception:
                        pass

                # Add new links to queue if depth permits
                if depth < max_depth:
                    for l in extractor.links:
                        if l not in visited_urls:
                            queue.append((l, depth + 1))

            # Also search for API endpoints in JavaScript/JSON
            elif "json" in content_type:
                discovered_endpoints.append({
                    "url": clean_url,
                    "path": endpoint_path,
                    "method": "JSON_API",
                    "status_code": status_code
                })

    return {
        "status": "completed",
        "target": root_url,
        "domain": root_domain,
        "pages_visited_count": len(visited_urls),
        "endpoints_discovered_count": len(discovered_endpoints),
        "forms_found_count": len(discovered_forms),
        "scripts_mined_count": len(discovered_scripts),
        "high_value_sinks_count": len(vulnerable_sinks),
        "high_value_sinks": vulnerable_sinks,
        "sample_endpoints": discovered_endpoints[:15],
        "scripts": list(discovered_scripts)[:10]
    }
