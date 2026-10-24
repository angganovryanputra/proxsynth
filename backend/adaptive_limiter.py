"""
PROXSYNTH — Adaptive Rate-Limit Backoff & Upstream Proxy Rotator
Transparently manages HTTP 429 Too Many Requests and IP blocks during autonomous
campaigns by implementing exponential backoff and rotating through the configured proxy pool.
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional

logger = logging.getLogger("proxynth.adaptive_limiter")

# Track backoff state per domain: {"consecutive_429s": int, "last_429_time": float, "current_delay": float}
_DOMAIN_LIMITS: Dict[str, Dict[str, Any]] = {}


def get_backoff_state(domain: str) -> Dict[str, Any]:
    """Retrieve backoff state for a specific domain."""
    if domain not in _DOMAIN_LIMITS:
        _DOMAIN_LIMITS[domain] = {
            "consecutive_429s": 0,
            "last_429_time": 0.0,
            "current_delay": 0.0
        }
    return _DOMAIN_LIMITS[domain]


async def handle_rate_limit(
    status_code: int,
    headers: Optional[Dict[str, str]] = None,
    domain: str = "default"
) -> Dict[str, Any]:
    """
    Checks if a response represents rate-limiting (429 or 503 with retry-after).
    If triggered, performs asynchronous backoff and optionally signals proxy pool rotation.
    """
    if status_code != 429 and status_code != 503:
        # Reset backoff count on successful requests
        if domain in _DOMAIN_LIMITS and _DOMAIN_LIMITS[domain]["consecutive_429s"] > 0:
            if time.time() - _DOMAIN_LIMITS[domain]["last_429_time"] > 30.0:
                _DOMAIN_LIMITS[domain]["consecutive_429s"] = 0
                _DOMAIN_LIMITS[domain]["current_delay"] = 0.0
        return {"rate_limited": False, "delay_applied": 0.0}

    state = get_backoff_state(domain)
    state["consecutive_429s"] += 1
    state["last_429_time"] = time.time()

    # Determine delay
    delay = 1.0
    if headers:
        retry_after = headers.get("Retry-After", headers.get("retry-after"))
        if retry_after:
            try:
                delay = float(retry_after)
                # Cap maximum delay to 8.0s to avoid blocking agent forever
                delay = min(delay, 8.0)
            except ValueError:
                delay = 2.0
        else:
            # Exponential backoff: 1.0s, 2.0s, 4.0s, 8.0s
            delay = min(1.0 * (2 ** (state["consecutive_429s"] - 1)), 8.0)
    else:
        delay = min(1.0 * (2 ** (state["consecutive_429s"] - 1)), 8.0)

    state["current_delay"] = delay
    logger.warning(f"Rate limit (HTTP {status_code}) hit on {domain}. Applying backoff delay of {delay:.2f}s (consecutive: {state['consecutive_429s']})")

    # Perform async sleep
    await asyncio.sleep(delay)

    # Attempt proxy pool rotation if upstream proxy pool is configured
    rotated = False
    try:
        from backend.forward_proxy import _upstream_proxy_indices
        proj_key = (domain or "default").lower()
        curr_idx = _upstream_proxy_indices.get(proj_key, 0)
        _upstream_proxy_indices[proj_key] = curr_idx + 1
        rotated = True
        logger.info(f"Rotated upstream proxy pool index for '{proj_key}' to #{_upstream_proxy_indices[proj_key]}")
    except Exception:
        pass

    return {
        "rate_limited": True,
        "status_code": status_code,
        "delay_applied": delay,
        "consecutive_count": state["consecutive_429s"],
        "proxy_rotated": rotated
    }
