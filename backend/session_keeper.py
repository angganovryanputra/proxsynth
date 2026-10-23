"""
Proxsynth MCP - Session Keep-Alive / Heartbeat Worker
Maintains authenticated sessions and prevents cookie/token expiration during long pentest operations.
"""

import json
import time
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import httpx

from backend.database import SessionLocal, ActiveSession

_keeper_task: Optional[asyncio.Task] = None
_is_running: bool = False
_interval_seconds: int = 120
_last_run_timestamp: Optional[str] = None
_last_summary: Dict[str, Any] = {"pings_sent": 0, "success_count": 0, "fail_count": 0}


async def _ping_session(session_record: ActiveSession) -> bool:
    """Sends a lightweight HEAD probe using active cookies to keep the session alive."""
    domain = session_record.domain
    if not domain:
        return False

    url = f"https://{domain}/" if not domain.startswith("http") else domain
    cookies = {}
    try:
        data = session_record.get_decrypted_state()
        for c in data.get("cookies", []):
            name = c.get("name")
            val = c.get("value")
            if name and val:
                cookies[name] = val
    except Exception:
        pass

    from backend.user_agents import get_random_user_agent

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=4.0) as client:
            cookie_hdr = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            headers = {"User-Agent": get_random_user_agent(), "Cookie": cookie_hdr}
            resp = await client.head(url, headers=headers)
            # If HEAD is 405 Method Not Allowed, fallback to light GET
            if resp.status_code == 405:
                resp = await client.get(url, headers=headers)
            return resp.status_code < 500
    except Exception:
        # Fallback to http:// if https failed
        try:
            url_http = f"http://{domain}/"
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=4.0) as client:
                cookie_hdr = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                headers = {"User-Agent": get_random_user_agent(), "Cookie": cookie_hdr}
                resp = await client.head(url_http, headers=headers)
                return resp.status_code < 500
        except Exception:
            return False


async def _keepalive_loop():
    """Background polling loop executing periodic heartbeats."""
    global _is_running, _last_run_timestamp, _last_summary
    _is_running = True

    while _is_running:
        db = SessionLocal()
        try:
            sessions = db.query(ActiveSession).all()
            if sessions:
                ping_tasks = [_ping_session(s) for s in sessions]
                results = await asyncio.gather(*ping_tasks, return_exceptions=True)
                success = 0
                failed = 0
                for s, res in zip(sessions, results):
                    if res is True:
                        success += 1
                        s.updated_at = datetime.now()
                    else:
                        failed += 1
                if success > 0:
                    db.commit()
            else:
                success = 0
                failed = 0
            _last_run_timestamp = datetime.now().isoformat()
            _last_summary = {
                "pings_sent": len(sessions),
                "success_count": success,
                "fail_count": failed
            }
        except Exception:
            db.rollback()
        finally:
            db.close()

        # Sleep interval with interruptible check
        for _ in range(_interval_seconds):
            if not _is_running:
                break
            await asyncio.sleep(1)


def start_session_keeper(interval: int = 120):
    """Starts the background session keeper worker task."""
    global _keeper_task, _is_running, _interval_seconds
    _interval_seconds = max(30, interval)
    if _keeper_task and not _keeper_task.done():
        return
    _is_running = True
    _keeper_task = asyncio.create_task(_keepalive_loop())


def stop_session_keeper():
    """Stops the background session keeper worker task."""
    global _keeper_task, _is_running
    _is_running = False
    if _keeper_task and not _keeper_task.done():
        _keeper_task.cancel()
    _keeper_task = None


def get_session_keeper_status() -> Dict[str, Any]:
    """Returns the operational status of the session keepalive service."""
    return {
        "running": _is_running and (_keeper_task is not None and not _keeper_task.done()),
        "interval_seconds": _interval_seconds,
        "last_run": _last_run_timestamp,
        "last_summary": _last_summary
    }
