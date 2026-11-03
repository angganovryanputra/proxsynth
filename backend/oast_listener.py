"""
PROXSYNTH - Out-of-Band (OAST) Listener & Webhook Dispatcher
Provides local listener lifecycle management and automatic webhook forwarding
for Out-of-Band security events (Blind SSRF, Blind XXE, Blind RCE, DNS Callbacks).
"""

import os
import json
import hmac
import hashlib
import asyncio
import logging
from typing import Dict, Any, Optional
import httpx

from backend.database import SessionLocal, OastEvent
from backend.oast_engine import record_oast_hit

logger = logging.getLogger("proxsynth.oast_listener")

_webhook_config: Dict[str, Any] = {
    "webhook_url": os.getenv("PROXSYNTH_OAST_WEBHOOK_URL", ""),
    "secret": os.getenv("PROXSYNTH_OAST_WEBHOOK_SECRET", ""),
    "enabled": bool(os.getenv("PROXSYNTH_OAST_WEBHOOK_URL", "").strip()),
    "forward_all": True
}


def set_oast_webhook_url(url: str, secret: Optional[str] = None, forward_all: bool = True) -> Dict[str, Any]:
    """Dynamically sets or updates the destination webhook URL for real-time OAST event forwarding."""
    global _webhook_config
    clean_url = (url or "").strip()
    _webhook_config["webhook_url"] = clean_url
    _webhook_config["secret"] = (secret or "").strip()
    _webhook_config["enabled"] = bool(clean_url)
    _webhook_config["forward_all"] = forward_all
    logger.info(f"OAST Webhook updated: enabled={_webhook_config['enabled']}, url={clean_url}")
    return dict(_webhook_config)


def get_oast_webhook_config() -> Dict[str, Any]:
    """Returns current OAST webhook forwarding configuration."""
    return dict(_webhook_config)


async def dispatch_oast_webhook(event_data: Dict[str, Any]) -> bool:
    """
    Asynchronously forwards an OAST interaction event to the configured webhook URL.
    Includes HMAC-SHA256 signature header if a secret is configured.
    """
    if not _webhook_config.get("enabled") or not _webhook_config.get("webhook_url"):
        return False

    webhook_url = _webhook_config["webhook_url"]
    secret = _webhook_config.get("secret", "")
    payload_bytes = json.dumps(event_data, default=str).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Proxsynth-OAST-Webhook/2.0",
        "X-Proxsynth-Event": "OAST_HIT"
    }

    if secret:
        signature = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        headers["X-Proxsynth-Signature"] = f"sha256={signature}"

    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            resp = await client.post(webhook_url, content=payload_bytes, headers=headers)
            return resp.status_code < 400
    except Exception as ex:
        logger.debug(f"OAST Webhook dispatch error to {webhook_url}: {ex}")
        return False


def simulate_local_oast_hit(
    token: str,
    client_ip: str = "127.0.0.1",
    method: str = "GET",
    path: str = "",
    headers: Optional[Dict[str, Any]] = None,
    query_params: Optional[Dict[str, Any]] = None,
    body: str = "",
    protocol: str = "HTTP",
    project: str = "default",
    description: str = ""
) -> Optional[Dict[str, Any]]:
    """
    Simulates or directly ingests a local OAST callback into the database,
    triggers event listeners, and attempts webhook dispatch.
    """
    res = record_oast_hit(
        token=token,
        client_ip=client_ip,
        method=method,
        path=path or f"/oast/{token}",
        headers=headers,
        query_params=query_params,
        body=body,
        protocol=protocol,
        project=project,
        description=description or f"Local OAST {protocol} callback hit"
    )

    if res and _webhook_config.get("enabled"):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(dispatch_oast_webhook(res))
            else:
                loop.run_until_complete(dispatch_oast_webhook(res))
        except Exception:
            pass

    return res
