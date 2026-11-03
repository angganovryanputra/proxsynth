"""
PROXSYNTH — Adaptive Rate-Limit Backoff & Upstream Proxy Rotator
Transparently manages HTTP 429 Too Many Requests and IP blocks during autonomous
campaigns by implementing exponential backoff, per-domain token-bucket throttling,
and rotating through the configured proxy pool.
"""

import asyncio
import logging
import time
import urllib.parse
from typing import Dict, Any, Optional

logger = logging.getLogger("proxynth.adaptive_limiter")


class AdaptiveDomainRateLimiter:
    """
    Thread-safe & async-friendly per-domain token bucket rate limiter with
    coordinated backoff for multi-worker swarm pentest operations.
    """

    def __init__(self, default_rps: float = 10.0, default_burst: int = 5):
        self.default_rps = max(0.1, default_rps)
        self.default_burst = max(1, default_burst)
        self._domain_buckets: Dict[str, Dict[str, Any]] = {}
        self._global_lock = asyncio.Lock()

    def _normalize_domain(self, target_or_domain: str) -> str:
        """Extracts clean hostname without protocol or port."""
        if not target_or_domain:
            return "default"
        clean = target_or_domain.strip().lower()
        if "://" in clean:
            try:
                parsed = urllib.parse.urlparse(clean)
                clean = parsed.hostname or parsed.netloc or parsed.path
            except Exception:
                pass
        elif ":" in clean:
            try:
                if clean.startswith("[") and "]" in clean:
                    clean = clean.split("]")[0].lstrip("[")
                else:
                    clean = clean.split(":")[0]
            except Exception:
                pass
        return clean or "default"

    def _get_bucket(self, domain: str) -> Dict[str, Any]:
        """Gets or initializes the token bucket for a domain."""
        norm_domain = self._normalize_domain(domain)
        if norm_domain not in self._domain_buckets:
            self._domain_buckets[norm_domain] = {
                "tokens": float(self.default_burst),
                "last_refill": time.time(),
                "rps": float(self.default_rps),
                "burst": float(self.default_burst),
                "backoff_until": 0.0,
                "consecutive_429s": 0,
                "lock": asyncio.Lock()
            }
        return self._domain_buckets[norm_domain]

    def is_backing_off(self, domain: str) -> bool:
        """Returns True if the domain is currently within a rate-limit backoff window."""
        bucket = self._get_bucket(domain)
        return time.time() < bucket["backoff_until"]

    async def record_rate_limit(
        self,
        domain: str,
        status_code: int = 429,
        retry_after: Optional[float] = None
    ) -> float:
        """
        Signals that a 429/503 rate-limit was received on the domain.
        Applies exponential backoff and drains current token reserves.
        """
        bucket = self._get_bucket(domain)
        async with bucket["lock"]:
            now = time.time()
            # Decay/reset consecutive count if previous rate limit was over 30s ago
            last_time = bucket.get("last_429_time", 0.0)
            if now - last_time > 30.0:
                bucket["consecutive_429s"] = 1
            else:
                bucket["consecutive_429s"] += 1
            bucket["last_429_time"] = now

            if retry_after is not None and retry_after > 0:
                delay = min(float(retry_after), 8.0)
            else:
                delay = min(1.0 * (2 ** (bucket["consecutive_429s"] - 1)), 8.0)

            bucket["backoff_until"] = now + delay
            bucket["tokens"] = 0.0  # Drain burst capacity
            bucket["last_refill"] = bucket["backoff_until"]

            logger.warning(
                f"[RateLimiter] Domain '{self._normalize_domain(domain)}' backed off for {delay:.2f}s "
                f"(Consecutive 429s: {bucket['consecutive_429s']})"
            )
            return delay

    def record_success(self, domain: str) -> None:
        """Records a successful HTTP response, decaying the consecutive rate-limit counter."""
        bucket = self._get_bucket(domain)
        if bucket.get("consecutive_429s", 0) > 0:
            bucket["consecutive_429s"] = max(0, bucket["consecutive_429s"] - 1)

    async def acquire(self, domain: str) -> None:
        """
        Acquires permission to make a request to the domain.
        Waits if in backoff or if token bucket is temporarily empty.
        """
        bucket = self._get_bucket(domain)
        async with bucket["lock"]:
            now = time.time()

            # 1. Handle active backoff window
            if now < bucket["backoff_until"]:
                wait_time = bucket["backoff_until"] - now
                await asyncio.sleep(wait_time)
                now = time.time()
                bucket["backoff_until"] = 0.0
                bucket["last_refill"] = now
                bucket["tokens"] = 1.0

            # 2. Refill tokens based on elapsed time
            elapsed = now - bucket["last_refill"]
            refill = elapsed * bucket["rps"]
            bucket["tokens"] = min(bucket["burst"], bucket["tokens"] + refill)
            bucket["last_refill"] = now

            # 3. If no token available, sleep until at least 1 token is ready
            if bucket["tokens"] < 1.0:
                deficit = 1.0 - bucket["tokens"]
                delay = deficit / bucket["rps"]
                await asyncio.sleep(delay)
                bucket["tokens"] = 0.0
                bucket["last_refill"] = time.time()
            else:
                bucket["tokens"] -= 1.0


# Global singleton instance
_GLOBAL_RATE_LIMITER: Optional[AdaptiveDomainRateLimiter] = None


def get_domain_rate_limiter() -> AdaptiveDomainRateLimiter:
    """Returns global shared domain rate limiter."""
    global _GLOBAL_RATE_LIMITER
    if _GLOBAL_RATE_LIMITER is None:
        _GLOBAL_RATE_LIMITER = AdaptiveDomainRateLimiter()
    return _GLOBAL_RATE_LIMITER


# Legacy / direct helper functions for backward compatibility
_DOMAIN_LIMITS: Dict[str, Dict[str, Any]] = {}


def get_backoff_state(domain: str) -> Dict[str, Any]:
    """Retrieve backoff state for a specific domain."""
    limiter = get_domain_rate_limiter()
    bucket = limiter._get_bucket(domain)
    return {
        "consecutive_429s": bucket["consecutive_429s"],
        "last_429_time": bucket["backoff_until"],
        "current_delay": max(0.0, bucket["backoff_until"] - time.time())
    }


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
        return {"rate_limited": False, "delay_applied": 0.0}

    retry_val = None
    if headers:
        ra = headers.get("Retry-After", headers.get("retry-after"))
        if ra:
            try:
                retry_val = float(ra)
            except ValueError:
                retry_val = 2.0

    limiter = get_domain_rate_limiter()
    delay = await limiter.record_rate_limit(domain, status_code=status_code, retry_after=retry_val)
    await asyncio.sleep(delay)

    # Attempt proxy pool rotation
    rotated = False
    try:
        from backend.forward_proxy import _upstream_proxy_indices
        proj_key = (domain or "default").lower()
        curr_idx = _upstream_proxy_indices.get(proj_key, 0)
        _upstream_proxy_indices[proj_key] = curr_idx + 1
        rotated = True
    except Exception:
        pass

    return {
        "rate_limited": True,
        "status_code": status_code,
        "delay_applied": delay,
        "consecutive_count": limiter._get_bucket(domain)["consecutive_429s"],
        "proxy_rotated": rotated
    }
