"""
Proxsynth - High-Performance In-Memory LRU Cache & Request Deduplication Engine
Reduces redundant target I/O, prevents duplicate active scan requests,
and conserves bandwidth during autonomous pentesting campaigns.
"""

import hashlib
import json
import logging
import threading
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("proxsynth.cache_manager")


class ResponseCacheEntry:
    def __init__(self, status_code: int, headers: Dict[str, str], body: str, ttl: float = 60.0):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.expires_at = time.time() + ttl

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class InMemoryRequestCache:
    """Thread-safe LRU cache for HTTP response deduplication."""

    def __init__(self, max_entries: int = 500, default_ttl: float = 60.0):
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self._cache: Dict[str, ResponseCacheEntry] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def _generate_key(
        self,
        method: str,
        url: str,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> str:
        """Generates deterministic SHA-256 hash key for request parameters."""
        raw_key = f"{method.upper().strip()}:{url.strip()}"
        if body:
            raw_key += f":body={body}"
        return hashlib.sha256(raw_key.encode("utf-8", errors="replace")).hexdigest()

    def get(
        self,
        method: str,
        url: str,
        body: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Retrieves cached response if valid and not expired."""
        # Only cache safe or idempotent methods by default
        clean_m = method.upper().strip()
        if clean_m not in ("GET", "HEAD", "OPTIONS"):
            return None

        key = self._generate_key(clean_m, url, body)
        with self._lock:
            entry = self._cache.get(key)
            if entry:
                if entry.is_expired():
                    del self._cache[key]
                    self.misses += 1
                    return None
                self.hits += 1
                return {
                    "status_code": entry.status_code,
                    "headers": dict(entry.headers),
                    "body": entry.body,
                    "cached": True
                }
            self.misses += 1
            return None

    def set(
        self,
        method: str,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        req_body: Optional[str] = None,
        ttl: Optional[float] = None
    ) -> None:
        """Stores response in LRU cache."""
        clean_m = method.upper().strip()
        if clean_m not in ("GET", "HEAD", "OPTIONS") or status_code >= 500:
            return

        key = self._generate_key(clean_m, url, req_body)
        with self._lock:
            # Evict oldest entry if over capacity
            if len(self._cache) >= self.max_entries:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]

            self._cache[key] = ResponseCacheEntry(
                status_code=status_code,
                headers=headers,
                body=body,
                ttl=ttl or self.default_ttl
            )

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "entries_count": len(self._cache),
                "max_entries": self.max_entries,
                "hits": self.hits,
                "misses": self.misses,
                "hit_ratio": round(self.hits / max(1, self.hits + self.misses), 3)
            }


# Global singleton instance
http_cache = InMemoryRequestCache()
