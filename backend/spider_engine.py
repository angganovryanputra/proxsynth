"""
PROXSYNTH — Autonomous Hybrid Web Spider & SPA DOM Discovery Engine
Recursively crawls web targets, extracts forms, inputs, endpoints, and scripts,
and utilizes a Playwright headless Chromium DOM engine for modern Single Page Applications (React/Vue/Angular),
automatically ingesting everything into the Target Knowledge Graph without human intervention.
"""

import asyncio
import logging
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Dict, List, Set, Any, Optional

import httpx

from backend.target_manager import upsert_target_asset, add_or_update_endpoint
from backend.user_agents import get_random_user_agent

logger = logging.getLogger("proxynth.spider_engine")


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


def detect_spa_indicators(html_text: str, content_type: str = "") -> bool:
    """
    Detects if a target HTML page is a Single Page Application (SPA)
    such as React, Vue, Angular, Next.js, Nuxt, or Svelte.
    """
    if "text/html" not in content_type and content_type != "":
        return False

    html_lower = html_text.lower()

    # Regex matching container IDs regardless of single/double quotes or whitespace
    if re.search(r'<div\s+id=[\'"](root|app|__next|__nuxt|app-root)[\'"]', html_lower):
        return True

    spa_signatures = [
        '<app-root>', '<ng-view>', 'data-reactroot',
        'react-dom', 'vue.runtime', 'angular.js', 'svelte-'
    ]
    for sig in spa_signatures:
        if sig in html_lower:
            return True

    # Check for short HTML body with JavaScript bundler artifacts
    if len(html_text) < 2500 and ("bundle.js" in html_lower or "chunk." in html_lower or "main." in html_lower or "vite" in html_lower):
        return True

    return False


async def crawl_spa_dom_playwright(
    target_url: str,
    project: str = "default",
    timeout_ms: int = 12000
) -> Dict[str, Any]:
    """
    Spawns a headless Playwright Chromium instance to render the dynamic DOM of an SPA.
    Intercepts client-side AJAX/Fetch API calls, extracts dynamically generated forms,
    input fields, and client-side router navigation links.
    """
    parsed_u = urllib.parse.urlparse(target_url)
    root_domain = parsed_u.netloc

    captured_api_requests: List[Dict[str, Any]] = []
    discovered_dom_forms: List[Dict[str, Any]] = []
    discovered_dom_links: List[str] = []

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning("Playwright not installed, skipping SPA DOM crawler.")
        return {"status": "skipped", "reason": "Playwright not installed"}

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context(
                user_agent=get_random_user_agent(),
                ignore_https_errors=True
            )
            page = await context.new_page()

            # Intercept background network traffic (XHR / Fetch calls generated by SPA scripts)
            def handle_request(req):
                if req.resource_type in ("xhr", "fetch"):
                    req_url = req.url
                    # Record API endpoint if on same domain or relative
                    if root_domain in req_url:
                        captured_api_requests.append({
                            "url": req_url,
                            "method": req.method,
                            "resource_type": req.resource_type,
                            "headers": dict(req.headers)
                        })

            page.on("request", handle_request)

            # Navigate to target page and wait for DOM hydration
            try:
                await page.goto(target_url, timeout=timeout_ms, wait_until="domcontentloaded")
                # Wait briefly for dynamic JavaScript components to render
                await page.wait_for_timeout(2000)
            except Exception as e:
                logger.debug(f"Playwright navigation timeout/error on {target_url}: {e}")

            # Extract live rendered forms & inputs via JavaScript execution
            dom_forms_data = await page.evaluate('''() => {
                const results = [];
                const forms = document.querySelectorAll('form');
                forms.forEach(f => {
                    const inputs = [];
                    f.querySelectorAll('input, textarea, select').forEach(inp => {
                        inputs.push({
                            name: inp.name || inp.id || '',
                            type: inp.type || inp.tagName.toLowerCase(),
                            value: inp.value || ''
                        });
                    });
                    results.push({
                        action: f.action || window.location.href,
                        method: (f.method || 'GET').toUpperCase(),
                        inputs: inputs
                    });
                });
                return results;
            }''')

            # Extract live rendered links
            dom_links_data = await page.evaluate('''() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    const h = a.getAttribute('href');
                    if (h && !h.startsWith('#') && !h.startsWith('javascript:')) {
                        links.push(a.href);
                    }
                });
                return Array.from(new Set(links));
            }''')

            await browser.close()

            # Ingest discovered dynamic forms into Target Knowledge Graph
            for f in dom_forms_data:
                discovered_dom_forms.append(f)
                input_names = [i["name"] for i in f.get("inputs", []) if i.get("name")]
                try:
                    add_or_update_endpoint(
                        project=project,
                        host=root_domain,
                        url=f["action"],
                        method=f["method"],
                        parameters=input_names,
                        tested_status="DISCOVERED",
                        notes=f"SPA DOM Form: {', '.join(input_names[:5])}"
                    )
                except Exception:
                    pass

            # Ingest background API endpoints intercepted during SPA execution
            for api in captured_api_requests:
                try:
                    add_or_update_endpoint(
                        project=project,
                        host=root_domain,
                        url=api["url"],
                        method=api["method"],
                        tested_status="DISCOVERED",
                        notes=f"SPA AJAX/Fetch Intercept ({api['resource_type']})"
                    )
                except Exception:
                    pass

            discovered_dom_links = [l for l in dom_links_data if root_domain in l]

            return {
                "status": "completed",
                "spa_rendered": True,
                "forms_discovered_count": len(discovered_dom_forms),
                "forms": discovered_dom_forms,
                "api_endpoints_intercepted_count": len(captured_api_requests),
                "api_endpoints": captured_api_requests,
                "dom_links_count": len(discovered_dom_links),
                "dom_links": discovered_dom_links[:20]
            }

    except Exception as e:
        logger.warning(f"Playwright SPA crawler execution failed: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


async def crawl_and_map_target(
    root_url: str,
    max_depth: int = 3,
    max_pages: int = 30,
    project: str = "default",
    headers: Optional[Dict[str, str]] = None,
    enable_spa: bool = True
) -> Dict[str, Any]:
    """
    Autonomously crawl a web target to map out endpoints, forms, input sinks,
    and automatically ingest everything into the Target Knowledge Graph.
    Uses hybrid mode: fast HTTP crawler + Playwright SPA engine if dynamic DOM is detected.
    """
    parsed_root = urllib.parse.urlparse(root_url)
    root_domain = parsed_root.netloc

    visited_urls: Set[str] = set()
    queue: List[tuple] = [(root_url, 0)]  # (url, depth)
    discovered_endpoints: List[Dict[str, Any]] = []
    discovered_forms: List[Dict[str, Any]] = []
    discovered_scripts: Set[str] = set()
    vulnerable_sinks: List[Dict[str, Any]] = []
    spa_detected = False

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

            # If HTML, check for SPA and extract links and forms
            if "text/html" in content_type:
                # Check for SPA indicators
                if not spa_detected and detect_spa_indicators(res.text, content_type):
                    spa_detected = True

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

    # ==========================================
    # HYBRID SPA DOM EXPANSION (Playwright)
    # ==========================================
    spa_results = None
    if enable_spa and (spa_detected or len(discovered_forms) == 0):
        logger.info(f"[Spider] SPA indicators detected or zero forms on {root_url}. Triggering Playwright DOM Engine...")
        spa_res = await crawl_spa_dom_playwright(target_url=root_url, project=project)
        if spa_res.get("status") == "completed":
            spa_results = spa_res
            # Merge discovered SPA forms
            for sf in spa_res.get("forms", []):
                discovered_forms.append(sf)
            # Merge API endpoints
            for api in spa_res.get("api_endpoints", []):
                discovered_endpoints.append({
                    "url": api["url"],
                    "path": urllib.parse.urlparse(api["url"]).path,
                    "method": api["method"],
                    "status_code": 200,
                    "depth": 1,
                    "spa_origin": True
                })

    return {
        "status": "completed",
        "target": root_url,
        "domain": root_domain,
        "is_spa_detected": spa_detected,
        "pages_visited_count": len(visited_urls),
        "endpoints_discovered_count": len(discovered_endpoints),
        "forms_found_count": len(discovered_forms),
        "scripts_mined_count": len(discovered_scripts),
        "high_value_sinks_count": len(vulnerable_sinks),
        "high_value_sinks": vulnerable_sinks,
        "sample_endpoints": discovered_endpoints[:15],
        "scripts": list(discovered_scripts)[:10],
        "spa_crawler_details": spa_results
    }
