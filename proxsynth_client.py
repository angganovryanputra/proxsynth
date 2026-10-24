"""
Proxsynth Client SDK - Micro-helper for AI Agents & Custom Pentest Scripts
Enables custom scripts to route traffic through Proxsynth Proxy with automatic session injection,
and provides programmatic reporting back to the Proxsynth Dashboard.
"""

__version__ = "0.1.0-beta"

import os
import requests
from typing import Optional, Dict, Any

PROXSYNTH_PROXY_PORT = os.getenv("PROXSYNTH_PROXY_PORT", os.getenv("PROXSYNTH_PROXY_PORT", "8088"))
PROXSYNTH_PROXY_URL = os.getenv("HTTP_PROXY", os.getenv("http_proxy", f"http://127.0.0.1:{PROXSYNTH_PROXY_PORT}"))
PROXSYNTH_PROJECT = os.getenv("PROXSYNTH_PROJECT", os.getenv("PROXSYNTH_PROJECT", "default"))
PROXSYNTH_BACKEND_URL = os.getenv("PROXSYNTH_BACKEND_URL", os.getenv("PROXSYNTH_BACKEND_URL", "http://127.0.0.1:8000")).rstrip("/")


class ProxsynthSession(requests.Session):
    """
    Drop-in replacement for requests.Session that automatically routes through Proxsynth Forward Proxy (:8088),
    injects Proxsynth project/agent metadata headers, and disables SSL warning noise during testing.
    """
    def __init__(self, project: Optional[str] = None, agent_id: str = "primary_agent"):
        super().__init__()
        self.project = (project or PROXSYNTH_PROJECT).strip().lower()
        self.agent_id = agent_id
        self.proxies = {
            "http": PROXSYNTH_PROXY_URL,
            "https": PROXSYNTH_PROXY_URL
        }
        self.verify = False
        self.headers.update({
            "X-Proxsynth-Project": self.project,
            "X-Proxsynth-Agent": self.agent_id,
            "X-Proxynth-Project": self.project,
            "X-Proxynth-Agent": self.agent_id
        })

    def report_finding(
        self,
        title: str,
        severity: str = "HIGH",
        category: str = "Custom Script Finding",
        evidence: str = "",
        remediation: str = "",
        description: str = ""
    ) -> bool:
        """Programmatically records a confirmed vulnerability directly into Proxsynth Findings Ledger."""
        try:
            resp = requests.post(
                f"{PROXSYNTH_BACKEND_URL}/api/findings",
                json={
                    "title": title,
                    "severity": severity.upper(),
                    "category": category,
                    "evidence": str(evidence),
                    "remediation": remediation,
                    "description": description or "Reported by custom agent script via Proxsynth SDK",
                    "project": self.project
                },
                timeout=3.0
            )
            return resp.status_code == 200
        except Exception:
            return False


try:
    import httpx
except ImportError:
    httpx = None


class AsyncProxsynthSession:
    """
    Asynchronous drop-in HTTP client for AI agents and custom async pentest scripts.
    Wraps httpx.AsyncClient with automatic routing through Proxsynth Forward Proxy (:8088),
    scoped project/agent correlation headers, disabled SSL verification, and async report_finding().
    Can be used as an async context manager:
        async with AsyncProxsynthSession(project="target") as session:
            resp = await session.get("https://example.com/api")
            await session.report_finding(title="SQL Injection", severity="HIGH", evidence=resp.text)
    """
    def __init__(self, project: Optional[str] = None, agent_id: str = "primary_agent", **kwargs):
        if httpx is None:
            raise ImportError("httpx is required for AsyncProxsynthSession. Please install httpx (`pip install httpx`).")
        self.project = (project or PROXSYNTH_PROJECT).strip().lower()
        self.agent_id = agent_id

        headers = kwargs.pop("headers", None)
        if headers is None:
            headers = {}
        elif isinstance(headers, dict):
            headers = dict(headers)
        headers.setdefault("X-Proxsynth-Project", self.project)
        headers.setdefault("X-Proxsynth-Agent", self.agent_id)
        headers.setdefault("X-Proxynth-Project", self.project)
        headers.setdefault("X-Proxynth-Agent", self.agent_id)

        proxy = kwargs.pop("proxy", None) or kwargs.pop("proxies", None) or PROXSYNTH_PROXY_URL
        verify = kwargs.pop("verify", False)

        self.client = httpx.AsyncClient(
            proxy=proxy,
            verify=verify,
            headers=headers,
            **kwargs
        )

    async def __aenter__(self):
        await self.client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.__aexit__(exc_type, exc_val, exc_tb)

    async def aclose(self):
        await self.client.aclose()

    async def get(self, url: str, **kwargs):
        return await self.client.get(url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.client.post(url, **kwargs)

    async def put(self, url: str, **kwargs):
        return await self.client.put(url, **kwargs)

    async def delete(self, url: str, **kwargs):
        return await self.client.delete(url, **kwargs)

    async def patch(self, url: str, **kwargs):
        return await self.client.patch(url, **kwargs)

    async def request(self, method: str, url: str, **kwargs):
        return await self.client.request(method, url, **kwargs)

    async def report_finding(
        self,
        title: str,
        severity: str = "HIGH",
        category: str = "Custom Async Script Finding",
        evidence: str = "",
        remediation: str = "",
        description: str = ""
    ) -> bool:
        """Programmatically records a confirmed vulnerability directly into Proxsynth Findings Ledger asynchronously."""
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=False) as report_client:
                resp = await report_client.post(
                    f"{PROXSYNTH_BACKEND_URL}/api/findings",
                    json={
                        "title": title,
                        "severity": severity.upper(),
                        "category": category,
                        "evidence": str(evidence),
                        "remediation": remediation,
                        "description": description or "Reported by custom async agent script via Proxsynth SDK",
                        "project": self.project
                    }
                )
                return resp.status_code == 200
        except Exception:
            return False


# Aliases for backward compatibility
ProxynthSession = ProxsynthSession
AsyncProxynthSession = AsyncProxsynthSession
