"""
Legacy alias for Proxsynth Client SDK.
Redirects to `proxsynth_client` for backward compatibility.
"""

from proxsynth_client import (
    PROXSYNTH_PROXY_PORT,
    PROXSYNTH_PROXY_URL,
    PROXSYNTH_PROJECT,
    PROXSYNTH_BACKEND_URL,
    ProxsynthSession,
    AsyncProxsynthSession,
    ProxynthSession,
    AsyncProxynthSession
)

__all__ = [
    "PROXSYNTH_PROXY_PORT",
    "PROXSYNTH_PROXY_URL",
    "PROXSYNTH_PROJECT",
    "PROXSYNTH_BACKEND_URL",
    "ProxsynthSession",
    "AsyncProxsynthSession",
    "ProxynthSession",
    "AsyncProxynthSession"
]
