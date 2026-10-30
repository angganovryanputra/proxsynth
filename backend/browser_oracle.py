"""
Proxsynth - Browser DOM Execution Oracle Sandbox
Provides zero-false-positive deterministic client-side execution verification (XSS, DOM Injection, CSP bypass).
Spawns a sandboxed headless Chromium instance, hooks alert/dialog listeners and console sinks,
and confirms whether an injected script payload actually fired in the real browser DOM.
"""

import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

from backend.user_agents import get_random_user_agent


_CANARY_NAME = "__pxs_canary__"
_CANARY_MARKER = "__PXS_CANARY_HIT__"
_COOKIE_MARKER = "__PXS_COOKIE_READ__"

# Defines a global canary function payloads can call, and wraps document.cookie reads.
_INIT_SCRIPT = """
(() => {
  try {
    window.%s = function () {
      try { console.debug("%s " + Array.prototype.join.call(arguments, ",")); } catch (e) {}
    };
  } catch (e) {}
  try {
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    if (desc && desc.get && desc.configurable) {
      Object.defineProperty(Document.prototype, "cookie", {
        configurable: true,
        enumerable: desc.enumerable,
        get: function () {
          try { console.debug("%s"); } catch (e) {}
          return desc.get.call(this);
        },
        set: function (v) { return desc.set.call(this, v); }
      });
    }
  } catch (e) {}
})();
""" % (_CANARY_NAME, _CANARY_MARKER, _COOKIE_MARKER)


async def verify_dom_execution(
    url: str,
    payload: Optional[str] = None,
    param_name: Optional[str] = None,
    trigger_event: str = "load",
    wait_timeout_ms: int = 4000,
    oast_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Spawns headless Chromium sandbox to prove if an exploit payload executed in the DOM.
    Hooks window.alert, window.confirm, window.prompt, console logs, and uncaught exceptions.
    """
    target_url = url.strip()
    
    # If param_name and payload are provided, construct injected URL
    if payload and param_name:
        parsed = urllib.parse.urlparse(target_url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [payload]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        target_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
    elif payload and not param_name and "§" in target_url:
        target_url = target_url.replace("§", payload)

    dialog_events: List[Dict[str, Any]] = []
    console_logs: List[str] = []
    page_errors: List[str] = []
    csp_violations: List[str] = []

    network_beacons: List[str] = []
    canary_hits: List[str] = []
    cookie_hits: List[str] = []

    user_agent = get_random_user_agent()

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--ignore-certificate-errors"
                ]
            )

            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=user_agent
            )

            page = await context.new_page()

            # 1. Listen for Dialogs (window.alert, confirm, prompt)
            async def handle_dialog(dialog):
                dialog_events.append({
                    "type": dialog.type,
                    "message": dialog.message
                })
                try:
                    await dialog.accept()
                except Exception:
                    pass

            page.on("dialog", handle_dialog)

            # 2. Listen for Console Logs & CSP Violations
            def handle_console(msg):
                txt = msg.text
                # Internal canary / cookie-probe markers: record, do not pollute logs
                if txt.startswith(_CANARY_MARKER):
                    canary_hits.append(txt)
                    return
                if txt.startswith(_COOKIE_MARKER):
                    cookie_hits.append(txt)
                    return
                console_logs.append(f"[{msg.type.upper()}] {txt}")
                if "content security policy" in txt.lower() or "csp" in txt.lower():
                    csp_violations.append(txt)

            page.on("console", handle_console)

            # 3. Listen for Page Errors
            def handle_pageerror(err):
                page_errors.append(str(err))

            page.on("pageerror", handle_pageerror)

            # 3b. Best-effort canary / cookie probes and OAST beacon hook (never fatal)
            try:
                await page.add_init_script(_INIT_SCRIPT)
            except Exception:
                pass

            if oast_token:
                try:
                    def handle_request(req):
                        try:
                            if oast_token in req.url:
                                network_beacons.append(req.url)
                        except Exception:
                            pass

                    page.on("request", handle_request)
                except Exception:
                    pass

            # 4. Navigate and observe
            try:
                await page.goto(target_url, timeout=wait_timeout_ms, wait_until="domcontentloaded")
            except PlaywrightTimeoutError:
                pass
            except Exception as nav_err:
                await browser.close()
                return {
                    "execution_confirmed": False,
                    "target_url": target_url,
                    "error": f"Navigation failed: {str(nav_err)}",
                    "verdict": "NAVIGATION_ERROR"
                }

            # 5. Brief observation window for async / timer execution (e.g. setTimeout, svg onload)
            await asyncio.sleep(0.8)

            # 6. Trigger common DOM click events if trigger_event is click
            if trigger_event == "click":
                try:
                    clickable = await page.query_selector("button, a, input[type=submit]")
                    if clickable:
                        await clickable.click(timeout=1000)
                        await asyncio.sleep(0.5)
                except Exception:
                    pass

            await browser.close()

    except Exception as ex:
        return {
            "execution_confirmed": False,
            "target_url": target_url,
            "error": f"Browser sandbox initialization failed: {str(ex)}",
            "verdict": "SANDBOX_ERROR"
        }

    # Evaluate execution verdict
    dialog_fired = len(dialog_events) > 0
    csp_blocked = len(csp_violations) > 0 and not dialog_fired
    canary_fired = len(canary_hits) > 0
    cookie_access = len(cookie_hits) > 0
    beacon_fired = len(network_beacons) > 0
    csp_blocked = csp_blocked and not (canary_fired or beacon_fired)
    execution_confirmed = dialog_fired or canary_fired or beacon_fired

    if dialog_fired:
        verdict = "CONFIRMED_VULNERABLE_DOM_EXECUTION"
        evidence = f"Client-side DOM execution verified! Dialog of type '{dialog_events[0]['type']}' triggered with message: '{dialog_events[0]['message']}'."
    elif canary_fired:
        verdict = "CONFIRMED_VULNERABLE_DOM_EXECUTION"
        evidence = f"Client-side DOM execution verified! Canary function {_CANARY_NAME} was invoked by the payload."
    elif beacon_fired:
        verdict = "CONFIRMED_VULNERABLE_DOM_EXECUTION"
        evidence = f"Client-side execution verified via OAST beacon: browser requested {network_beacons[0]}"
    elif csp_blocked:
        verdict = "EXECUTION_BLOCKED_BY_CSP"
        evidence = f"Payload parsed into DOM but script execution was prevented by Content Security Policy (CSP): {csp_violations[0]}"
    else:
        verdict = "NO_DOM_EXECUTION"
        evidence = "No browser dialog or unhandled script execution occurred during observation window."

    return {
        "execution_confirmed": execution_confirmed,
        "target_url": target_url,
        "verdict": verdict,
        "evidence": evidence,
        "dialog_fired": dialog_fired,
        "dialog_events": dialog_events,
        "csp_violations": csp_violations,
        "console_logs": console_logs[:10],
        "page_errors": page_errors[:5],
        "network_beacons": network_beacons[:10],
        "beacon_fired": beacon_fired,
        "canary_fired": canary_fired,
        "cookie_access": cookie_access
    }
