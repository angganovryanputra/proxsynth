"""
Proxsynth MCP - Public OAST & Webhook Tunnel Manager
Automates public ingress tunneling via Cloudflare Quick Tunnels (cloudflared) or ngrok,
enabling external targets and out-of-band payloads (SSRF, XXE, Blind SQLi, RCE)
to reach local Proxsynth listeners across NAT and firewalls.
"""

import os
import sys
import shutil
import asyncio
import re
import time
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from backend.oast_engine import set_base_callback_url, get_base_callback_url

_tunnel_process: Optional[asyncio.subprocess.Process] = None
_tunnel_info: Dict[str, Any] = {
    "active": False,
    "provider": None,
    "public_url": None,
    "local_port": 8000,
    "started_at": None,
    "pid": None,
    "project": "default",
    "error": None
}
_tunnel_lock = asyncio.Lock()


def is_tunnel_active() -> bool:
    return _tunnel_info["active"] and _tunnel_info["public_url"] is not None


def get_tunnel_status() -> Dict[str, Any]:
    uptime_sec = 0
    if _tunnel_info["started_at"]:
        try:
            started = datetime.fromisoformat(_tunnel_info["started_at"])
            uptime_sec = int((datetime.now() - started).total_seconds())
        except Exception:
            pass

    return {
        "active": _tunnel_info["active"],
        "provider": _tunnel_info["provider"],
        "public_url": _tunnel_info["public_url"],
        "local_port": _tunnel_info["local_port"],
        "started_at": _tunnel_info["started_at"],
        "uptime_seconds": uptime_sec,
        "pid": _tunnel_info["pid"],
        "project": _tunnel_info["project"],
        "error": _tunnel_info["error"],
        "oast_base_url": get_base_callback_url()
    }


def find_tunnel_binary(name: str) -> Optional[str]:
    """Finds path to cloudflared or ngrok in system PATH or common locations."""
    # Check PATH first
    found = shutil.which(name)
    if found:
        return found

    # Check Windows common user or appdata paths
    if sys.platform == "win32":
        candidates = [
            os.path.expanduser(f"~\\AppData\\Local\\Programs\\{name}\\{name}.exe"),
            os.path.expanduser(f"~\\bin\\{name}.exe"),
            f"C:\\Program Files\\{name}\\{name}.exe",
            f"C:\\tools\\{name}.exe",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), f"{name}.exe")
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
    return None


async def start_public_tunnel(
    provider: str = "auto",
    local_port: int = 8000,
    project: str = "default",
    custom_domain: Optional[str] = None
) -> Dict[str, Any]:
    """
    Spins up a public tunnel (Cloudflare Quick Tunnel, ngrok, or mock relay)
    and binds the public URL to Proxsynth's OAST callback listener.
    """
    global _tunnel_process, _tunnel_info
    async with _tunnel_lock:
        if _tunnel_info["active"] and _tunnel_info["public_url"]:
            return {
                "status": "already_running",
                "message": f"Tunnel is already active at {_tunnel_info['public_url']}",
                "tunnel": get_tunnel_status()
            }

        target_provider = (provider or "auto").strip().lower()
        cf_bin = find_tunnel_binary("cloudflared")
        ngrok_bin = find_tunnel_binary("ngrok")

        # Resolve provider
        if target_provider == "auto":
            if cf_bin:
                target_provider = "cloudflare"
            elif ngrok_bin:
                target_provider = "ngrok"
            else:
                target_provider = "simulated"
        elif target_provider in ["cf", "cloudflare"]:
            target_provider = "cloudflare"
        elif target_provider == "ngrok":
            target_provider = "ngrok"

        public_url = None
        cmd = []

        if target_provider == "cloudflare":
            bin_path = cf_bin or "cloudflared"
            cmd = [bin_path, "tunnel", "--url", f"http://127.0.0.1:{local_port}", "--no-autoupdate"]
        elif target_provider == "ngrok":
            bin_path = ngrok_bin or "ngrok"
            cmd = [bin_path, "http", str(local_port), "--log=stdout"]
        else:
            # Simulated loopback / custom endpoint for offline/dev environments
            sim_host = custom_domain or f"tunnel-{int(time.time())}.proxsynth.local"
            public_url = f"https://{sim_host}"
            _tunnel_info.update({
                "active": True,
                "provider": "simulated",
                "public_url": public_url,
                "local_port": local_port,
                "started_at": datetime.now().isoformat(),
                "pid": None,
                "project": project,
                "error": None
            })
            set_base_callback_url(public_url)
            return {
                "status": "started",
                "provider": "simulated",
                "public_url": public_url,
                "message": f"Simulated tunnel endpoint active at {public_url}. Install cloudflared for live public routing.",
                "tunnel": get_tunnel_status()
            }

        try:
            _tunnel_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Read stream until URL is found or timeout occurs (up to 15s)
            url_pattern_cf = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
            url_pattern_ngrok = re.compile(r"https://[a-zA-Z0-9-]+\.ngrok[-a-z0-9]*\.app|https://[a-zA-Z0-9-]+\.ngrok\.io")

            start_wait = time.time()
            while time.time() - start_wait < 15.0:
                # Cloudflared prints to stderr, ngrok to stdout
                line = ""
                if _tunnel_process.stderr and not _tunnel_process.stderr.at_eof():
                    try:
                        raw = await asyncio.wait_for(_tunnel_process.stderr.readline(), timeout=0.8)
                        line = raw.decode("utf-8", errors="replace")
                    except asyncio.TimeoutError:
                        pass
                if not line and _tunnel_process.stdout and not _tunnel_process.stdout.at_eof():
                    try:
                        raw = await asyncio.wait_for(_tunnel_process.stdout.readline(), timeout=0.8)
                        line = raw.decode("utf-8", errors="replace")
                    except asyncio.TimeoutError:
                        pass

                if line:
                    match_cf = url_pattern_cf.search(line)
                    match_ng = url_pattern_ngrok.search(line)
                    if match_cf:
                        public_url = match_cf.group(0)
                        break
                    elif match_ng:
                        public_url = match_ng.group(0)
                        break

                if _tunnel_process.returncode is not None:
                    break

            if public_url:
                _tunnel_info.update({
                    "active": True,
                    "provider": target_provider,
                    "public_url": public_url,
                    "local_port": local_port,
                    "started_at": datetime.now().isoformat(),
                    "pid": _tunnel_process.pid,
                    "project": project,
                    "error": None
                })
                # Auto-bind to OAST engine
                set_base_callback_url(public_url)
                return {
                    "status": "started",
                    "provider": target_provider,
                    "public_url": public_url,
                    "message": f"Live public tunnel established via {target_provider} at {public_url}",
                    "tunnel": get_tunnel_status()
                }
            else:
                # Terminate failed process
                try:
                    _tunnel_process.terminate()
                except Exception:
                    pass
                _tunnel_process = None
                # Fallback to simulated mode
                sim_url = f"https://tunnel-fallback.proxsynth.local"
                _tunnel_info.update({
                    "active": True,
                    "provider": "simulated",
                    "public_url": sim_url,
                    "local_port": local_port,
                    "started_at": datetime.now().isoformat(),
                    "pid": None,
                    "project": project,
                    "error": "Failed to parse live public tunnel URL from process output. Using fallback."
                })
                set_base_callback_url(sim_url)
                return {
                    "status": "fallback",
                    "provider": "simulated",
                    "public_url": sim_url,
                    "message": f"Live tunnel timeout. Initialized fallback simulated endpoint at {sim_url}",
                    "tunnel": get_tunnel_status()
                }

        except Exception as ex:
            _tunnel_process = None
            sim_url = f"https://tunnel-fallback.proxsynth.local"
            _tunnel_info.update({
                "active": True,
                "provider": "simulated",
                "public_url": sim_url,
                "local_port": local_port,
                "started_at": datetime.now().isoformat(),
                "pid": None,
                "project": project,
                "error": str(ex)
            })
            set_base_callback_url(sim_url)
            return {
                "status": "fallback",
                "provider": "simulated",
                "public_url": sim_url,
                "message": f"Could not launch binary ({str(ex)}). Using simulated endpoint at {sim_url}",
                "tunnel": get_tunnel_status()
            }


async def stop_public_tunnel() -> Dict[str, Any]:
    """Gracefully terminates active public tunnel and clears OAST callback base URL."""
    global _tunnel_process, _tunnel_info
    async with _tunnel_lock:
        prev_url = _tunnel_info["public_url"]
        if _tunnel_process:
            try:
                _tunnel_process.terminate()
                await asyncio.wait_for(_tunnel_process.wait(), timeout=3.0)
            except Exception:
                try:
                    _tunnel_process.kill()
                except Exception:
                    pass
            _tunnel_process = None

        _tunnel_info.update({
            "active": False,
            "provider": None,
            "public_url": None,
            "started_at": None,
            "pid": None,
            "error": None
        })

        # Reset OAST callback to local backend URL
        backend_url = os.getenv("PROXSYNTH_BACKEND_URL", "http://127.0.0.1:8000")
        set_base_callback_url(backend_url)

        return {
            "status": "stopped",
            "message": f"Public tunnel {prev_url or ''} successfully closed. Callback URL restored to local backend.",
            "tunnel": get_tunnel_status()
        }
