"""
Proxsynth - Multi-Protocol OAST LDAP & JNDI Callback Listener
Catches incoming LDAP bind/search queries (e.g. jndi:ldap://host:port/{token})
for detecting Blind Log4j, Spring4Shell, and JNDI Injection vulnerabilities.
"""

import os
import re
import asyncio
from typing import Optional, Tuple
from datetime import datetime

from backend.oast_engine import record_oast_hit, _token_registry

_HEX_TOKEN_REGEX = re.compile(r'([a-zA-Z0-9]{12,33})', re.IGNORECASE)

_ldap_server: Optional[asyncio.Server] = None
_is_running: bool = False
_active_ldap_port: int = 1389


# Minimal valid ASN.1 BER BindResponse (Success) message
# 30 0c (SEQUENCE 12 bytes)
#   02 01 01 (messageID: 1)
#   61 07 (bindResponse: [APPLICATION 1] 7 bytes)
#     0a 01 00 (resultCode: success 0)
#     04 00 (matchedDN: "")
#     04 00 (diagnosticMessage: "")
LDAP_BIND_SUCCESS = bytes.fromhex("300c02010161070a010004000400")


async def _handle_ldap_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Processes incoming raw LDAP connection with two-stage handshake."""
    client_addr = writer.get_extra_info('peername')
    client_ip = client_addr[0] if client_addr else "unknown"

    try:
        # Read initial packet (BindRequest or direct query)
        data = await asyncio.wait_for(reader.read(4096), timeout=4.0)
        if not data:
            writer.close()
            await writer.wait_closed()
            return

        all_text = data.decode('utf-8', errors='ignore')

        # If data looks like an LDAP BindRequest, acknowledge with BindResponse
        # so Java JNDI clients proceed to send SearchRequest (which contains the token in Base DN)
        if len(data) >= 5 and data[0] == 0x30:
            try:
                writer.write(LDAP_BIND_SUCCESS)
                await writer.drain()
                # Read stage 2: SearchRequest containing target token
                next_data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                if next_data:
                    all_text += " " + next_data.decode('utf-8', errors='ignore')
            except Exception:
                pass

        detected_token = None
        for reg_tok in _token_registry.keys():
            if reg_tok.lower() in all_text.lower():
                detected_token = reg_tok
                break

        if not detected_token:
            match = _HEX_TOKEN_REGEX.search(all_text)
            detected_token = match.group(1).lower() if match else None

        if detected_token:
            record_oast_hit(
                token=detected_token,
                client_ip=client_ip,
                method="LDAP_BIND",
                path=f"ldap://callback/{detected_token}",
                protocol="LDAP",
                description=f"Out-of-band LDAP/JNDI callback from {client_ip} (Raw Len: {len(all_text)})"
            )

        writer.close()
        await writer.wait_closed()
    except Exception:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_ldap_server(port: Optional[int] = None) -> bool:
    """Starts the asyncio TCP LDAP listener."""
    global _ldap_server, _is_running, _active_ldap_port

    if _is_running and _ldap_server:
        return True

    ports_to_try = []
    if port:
        ports_to_try.append(port)
    env_port = os.getenv("PROXSYNTH_LDAP_PORT")
    if env_port:
        try:
            ports_to_try.append(int(env_port))
        except Exception:
            pass
    for p in [1389, 389, 8389]:
        if p not in ports_to_try:
            ports_to_try.append(p)

    for p in ports_to_try:
        try:
            server = await asyncio.start_server(_handle_ldap_client, "0.0.0.0", p)
            _ldap_server = server
            _is_running = True
            _active_ldap_port = p
            return True
        except (PermissionError, OSError):
            continue

    return False


def stop_ldap_server():
    """Stops the LDAP server."""
    global _ldap_server, _is_running
    _is_running = False
    if _ldap_server:
        _ldap_server.close()
        _ldap_server = None


def get_ldap_server_status():
    """Returns LDAP server status."""
    return {
        "running": _is_running,
        "port": _active_ldap_port if _is_running else None
    }
