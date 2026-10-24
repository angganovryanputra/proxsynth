"""
Proxsynth MCP - Browser & HITL (Human-in-the-Loop) Login Handler
Automated Playwright DOM rendering and interactive headed authentication handover.
"""

import asyncio
import json
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from backend.database import SessionLocal, ActiveSession
from backend.security_utils import check_ssrf_safety

logger = logging.getLogger("proxsynth.browser")

# Active interactive login tracking: domain -> asyncio.Event
active_login_events: Dict[str, asyncio.Event] = {}
active_login_status: Dict[str, Dict[str, Any]] = {}


def signal_login_confirmation(domain: Optional[str] = None) -> bool:
    """Signals manual completion from the dashboard API for a given domain or all active domains."""
    signaled = False
    if domain and domain in active_login_events:
        active_login_events[domain].set()
        return True
    
    # If no specific domain or not found, signal all pending
    for d, evt in list(active_login_events.items()):
        evt.set()
        signaled = True
    return signaled


def get_active_login_status() -> Optional[Dict[str, Any]]:
    """Returns information about any currently running interactive login session."""
    for domain, info in active_login_status.items():
        if info.get("active"):
            return info
    return None

class PlaywrightPoolManager:
    """
    Recycled Browser Pool for Headless Playwright Crawling.
    Reuses Chromium instances across requests to eliminate 2-3s cold-start overhead per page,
    drastically reducing CPU/RAM consumption during intensive SPA crawls.
    """
    _playwright = None
    _browser = None
    _lock = asyncio.Lock()

    @classmethod
    async def get_browser(cls, upstream_proxy: Optional[str] = None):
        from playwright.async_api import async_playwright
        async with cls._lock:
            if cls._playwright is None:
                cls._playwright = await async_playwright().start()
            launch_kwargs = {"headless": True}
            if upstream_proxy and upstream_proxy.strip():
                launch_kwargs["proxy"] = {"server": upstream_proxy.strip()}
            if cls._browser is None or not cls._browser.is_connected():
                cls._browser = await cls._playwright.chromium.launch(**launch_kwargs)
            return cls._browser

    @classmethod
    async def cleanup(cls):
        async with cls._lock:
            if cls._browser:
                try:
                    await cls._browser.close()
                except Exception:
                    pass
                cls._browser = None
            if cls._playwright:
                try:
                    await cls._playwright.stop()
                except Exception:
                    pass
                cls._playwright = None


async def render_page(
    url: str,
    click_selector: Optional[str] = None,
    fill_inputs: Optional[Dict[str, str]] = None,
    wait_time_ms: int = 2000,
    upstream_proxy: Optional[str] = None
) -> Dict[str, Any]:
    """
    Renders a URL headlessly using Playwright, intercepts sub-requests, and returns DOM content.
    Supports routing traffic through upstream proxy (e.g. Burp Suite).
    """
    from playwright.async_api import async_playwright
    from backend.user_agents import get_random_user_agent

    # Validate target URL against SSRF policy (cloud metadata is strictly blocked)
    is_safe, ssrf_reason = check_ssrf_safety(url, allow_internal=True)
    if not is_safe:
        return {
            "error": f"Blocked by SSRF Guard: {ssrf_reason}",
            "domain": urllib.parse.urlparse(url).netloc,
            "dom_text": "",
            "intercepted_requests": []
        }

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc

    intercepted_requests: List[Dict[str, Any]] = []

    browser = await PlaywrightPoolManager.get_browser(upstream_proxy)
    context = await browser.new_context(
        user_agent=get_random_user_agent(),
        ignore_https_errors=True
    )

    # Inject existing active session cookies if available
    db = SessionLocal()
    try:
        sess_record = db.query(ActiveSession).filter(ActiveSession.domain == domain).first()
        if sess_record:
            try:
                state_data = sess_record.get_decrypted_state()
                cookies = state_data.get("cookies", [])
                if cookies:
                    await context.add_cookies(cookies)
            except Exception as ex:
                logger.warning("Failed injecting cookies for %s: %s", domain, ex)
    finally:
        db.close()

    page = await context.new_page()

    # Network hooks to capture AJAX / sub-requests with real status codes and latencies
    import time as _time
    request_timings: Dict[str, float] = {}

    def on_req(req):
        request_timings[req.url] = _time.time()
        intercepted_requests.append({
            "url": req.url,
            "method": req.method,
            "resource_type": req.resource_type,
            "headers": dict(req.headers),
            "status_code": None,
            "duration_ms": 0,
            "synthetic": False
        })

    def on_res(res):
        start = request_timings.get(res.url)
        duration = int((_time.time() - start) * 1000) if start else 0
        for item in reversed(intercepted_requests):
            if item["url"] == res.url and item["status_code"] is None:
                item["status_code"] = res.status
                item["duration_ms"] = duration
                break

    page.on("request", on_req)
    page.on("response", on_res)

    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)

        # Optional fill inputs
        if fill_inputs:
            for selector, val in fill_inputs.items():
                try:
                    await page.fill(selector, val, timeout=3000)
                except Exception as ex:
                    logger.debug("Could not fill input %s: %s", selector, ex)

        # Optional click action
        if click_selector:
            try:
                await page.click(click_selector, timeout=5000)
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                await asyncio.sleep(1.0)
        else:
            try:
                await page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                await asyncio.sleep(0.5)

        title = await page.title()
        final_url = page.url
        try:
            body_text = await page.inner_text("body", timeout=5000)
        except Exception:
            body_text = await page.content()

        return {
            "title": title,
            "url": final_url,
            "domain": domain,
            "dom_text": body_text[:10000],  # Trim to prevent overwhelming context
            "intercepted_count": len(intercepted_requests),
            "intercepted_requests": intercepted_requests[:30]
        }
    finally:
        try:
            await context.close()
        except Exception:
            pass


def _save_session_cookies(project: str, domain: str, storage_state: dict):
    """Upserts captured session state into SQLite ActiveSession table with encryption."""
    db = SessionLocal()
    try:
        existing = db.query(ActiveSession).filter(ActiveSession.domain == domain).first()
        if existing:
            existing.project = project
            existing.set_encrypted_state(storage_state)
            existing.updated_at = datetime.now()
        else:
            new_session = ActiveSession(
                project=project,
                domain=domain,
                updated_at=datetime.now()
            )
            new_session.set_encrypted_state(storage_state)
            db.add(new_session)
        db.commit()
    except Exception as ex:
        logger.warning("Error saving active session: %s", ex)
    finally:
        db.close()


def parse_cookie_input(raw_input: str, domain: str = "") -> List[Dict[str, Any]]:
    """
    Intelligently parses cookies from:
    1. Raw document.cookie string (key1=val1; key2=val2)
    2. cURL command with -H 'Cookie: ...'
    3. HTTP request header block (Cookie: ...)
    4. JSON array (from Cookie-Editor extension or Playwright storage_state)
    """
    import re
    cookies = []
    text = (raw_input or "").strip()
    if not text:
        return cookies

    # 1. Try JSON parsing
    if (text.startswith("[") and text.endswith("]")) or (text.startswith("{") and text.endswith("}")):
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "cookies" in data:
                data = data["cookies"]
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "name" in item and "value" in item:
                        cookies.append({
                            "name": str(item["name"]).strip(),
                            "value": str(item["value"]).strip(),
                            "domain": item.get("domain", domain or "target.local"),
                            "path": item.get("path", "/"),
                            "httpOnly": bool(item.get("httpOnly", False)),
                            "secure": bool(item.get("secure", True))
                        })
                if cookies:
                    return cookies
        except Exception:
            pass

    # 2. Try cURL header extraction
    curl_match = re.search(r'(?:-H|--header)\s+[\'"](?:Cookie|cookie):\s*([^\'"]+)[\'"]', text, re.IGNORECASE)
    if curl_match:
        text = curl_match.group(1).strip()

    # 3. Try HTTP request header block extraction
    hdr_match = re.search(r'^Cookie:\s*(.+)$', text, re.IGNORECASE | re.MULTILINE)
    if hdr_match:
        text = hdr_match.group(1).strip()

    # 4. Parse key=value pairs separated by semicolon or newline
    pairs = re.split(r'[;\n]+', text)
    for pair in pairs:
        pair = pair.strip()
        if not pair or '=' not in pair:
            continue
        parts = pair.split('=', 1)
        k = parts[0].strip()
        v = parts[1].strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        if k:
            cookies.append({
                "name": k,
                "value": v,
                "domain": domain or "target.local",
                "path": "/",
                "httpOnly": False,
                "secure": True
            })
    return cookies


def import_session_cookies(project: str, domain: str, raw_input: str) -> Dict[str, Any]:
    """Parses arbitrary cookie / cURL / JSON input and persists it into ActiveSession."""
    clean_domain = (domain or "").strip().lower()
    if "://" in clean_domain:
        clean_domain = urllib.parse.urlparse(clean_domain).netloc
    clean_domain = clean_domain.split(":")[0].strip("/")
    if not clean_domain:
        clean_domain = "target.local"

    cookies = parse_cookie_input(raw_input, domain=clean_domain)
    storage_state = {
        "cookies": cookies,
        "origins": []
    }
    _save_session_cookies(project, clean_domain, storage_state)
    return {
        "status": "success",
        "domain": clean_domain,
        "project": project,
        "cookie_count": len(cookies),
        "cookies": cookies
    }


async def spawn_interactive_login(
    login_url: str,
    target_domain: Optional[str] = None,
    project: str = "default",
    timeout_seconds: int = 300,
    browser_choice: str = "chrome",
    on_cookie_update: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Spawns interactive browser for Human-in-the-Loop (HITL) authentication.
    Supports host-installed browsers:
    - 'chrome': Host Google Chrome (channel='chrome', fallback to msedge / chromium)
    - 'msedge': Host Microsoft Edge (channel='msedge', fallback to chrome / chromium)
    - 'chromium': Bundled Playwright Chromium
    - 'system': Directly opens target in the host's default operating system browser
    """
    import webbrowser
    from playwright.async_api import async_playwright

    clean_url = (login_url or "").strip()
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = "https://" + clean_url

    parsed = urllib.parse.urlparse(clean_url)
    domain = (target_domain or parsed.netloc.split(":")[0]).strip()

    # Validate target login URL against SSRF policy
    is_safe, ssrf_reason = check_ssrf_safety(clean_url, allow_internal=True)
    if not is_safe:
        return {
            "status": "error",
            "message": f"Blocked by SSRF Guard: {ssrf_reason}",
            "domain": domain,
            "project": project,
            "cookies": [],
            "cookie_count": 0
        }

    # If operator selected host's default system browser, open directly via OS
    if browser_choice == "system":
        logger.info("Opening URL directly in host default system browser: %s", clean_url)
        webbrowser.open(clean_url)
        return {
            "cookies": [],
            "cookie_count": 0,
            "domain": domain,
            "project": project,
            "status": "system_browser_opened",
            "message": "Opened in system default browser. Please sync cookies via JS Bookmarklet or Paste Cookies tab."
        }

    completion_event = asyncio.Event()
    active_login_events[domain] = completion_event
    active_login_status[domain] = {
        "active": True,
        "login_url": clean_url,
        "domain": domain,
        "project": project,
        "browser_choice": browser_choice,
        "started_at": datetime.now().isoformat()
    }

    captured_data = {
        "cookies": [],
        "cookie_count": 0,
        "domain": domain,
        "project": project,
        "status": "pending"
    }

    try:
        async with async_playwright() as p:
            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-infobars"
            ]

            # Channel fallback ladder for maximum reliability
            if browser_choice == "msedge":
                channels_to_try = ["msedge", "chrome", None]
            elif browser_choice == "chromium":
                channels_to_try = [None, "chrome", "msedge"]
            else: # default "chrome"
                channels_to_try = ["chrome", "msedge", None]

            browser = None
            last_err = None
            for chan in channels_to_try:
                try:
                    kwargs = {
                        "headless": False,
                        "args": launch_args
                    }
                    if chan:
                        kwargs["channel"] = chan
                    browser = await p.chromium.launch(**kwargs)
                    logger.info("Spawned headed browser successfully (channel: %s)", chan or "bundled_chromium")
                    break
                except Exception as ex:
                    last_err = ex
                    logger.warning("Failed launching browser with channel %s: %s", chan, ex)

            if not browser:
                raise RuntimeError(f"Could not launch browser (tried: {channels_to_try}): {last_err}")

            context = await browser.new_context(
                viewport={"width": 1280, "height": 850},
                user_agent=get_random_user_agent(),
                ignore_https_errors=True
            )
            page = await context.new_page()

            # Active continuous cookie synchronization loop
            async def sync_loop():
                while not completion_event.is_set():
                    try:
                        storage = await context.storage_state()
                        current_cookies = storage.get("cookies", [])
                        if current_cookies:
                            captured_data["cookies"] = current_cookies
                            captured_data["cookie_count"] = len(current_cookies)
                            _save_session_cookies(project, domain, storage)
                            if on_cookie_update:
                                try:
                                    await on_cookie_update(domain, len(current_cookies))
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    await asyncio.sleep(2.0)

            sync_task = asyncio.create_task(sync_loop())

            # Passive Navigation Monitoring:
            # Keep browser open until operator explicitly confirms or closes the window
            async def on_frame_navigated(frame):
                if frame == page.main_frame:
                    curr_url = page.url or ""
                    if curr_url and curr_url != "about:blank":
                        logger.info("HITL browser navigated to: %s", curr_url)

            page.on("framenavigated", lambda frame: asyncio.create_task(on_frame_navigated(frame)))

            # If user closes browser window directly, finalize capture immediately
            context.on("close", lambda: completion_event.set())
            page.on("close", lambda: completion_event.set())

            try:
                await page.goto(clean_url, wait_until="domcontentloaded", timeout=45000)
            except Exception as nav_ex:
                logger.warning("Initial navigation error on %s: %s", clean_url, nav_ex)

            # Wait for either completion event or timeout
            try:
                await asyncio.wait_for(completion_event.wait(), timeout=float(timeout_seconds))
            except asyncio.TimeoutError:
                logger.warning("HITL interactive login timed out after %ds for %s", timeout_seconds, domain)

            sync_task.cancel()

            # Final capture and storage
            try:
                storage_state = await context.storage_state()
            except Exception:
                storage_state = {"cookies": captured_data.get("cookies", [])}

            cookies = storage_state.get("cookies", [])
            captured_data["cookies"] = cookies
            captured_data["cookie_count"] = len(cookies)
            captured_data["status"] = "success" if len(cookies) > 0 else "completed_no_cookies"

            if cookies:
                _save_session_cookies(project, domain, storage_state)

            try:
                await browser.close()
            except Exception:
                pass
    finally:
        active_login_events.pop(domain, None)
        active_login_status.pop(domain, None)

    return captured_data
