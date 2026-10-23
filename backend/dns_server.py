"""
Proxsynth - Multi-Protocol OAST DNS Tunneling Listener
Lightweight Asyncio UDP DNS Server that catches DNS queries, extracts correlation tokens,
and records DNS-based Out-of-Band (OAST) interactions for Blind SSRF, Blind SQLi, and RCE.
"""

import os
import re
import socket
import struct
import asyncio
import ipaddress
from typing import Optional, Tuple
from datetime import datetime

from backend.oast_engine import record_oast_hit, _token_registry

_HEX_TOKEN_REGEX = re.compile(r'([a-f0-9]{12})', re.IGNORECASE)

_dns_transport: Optional[asyncio.DatagramTransport] = None
_is_running: bool = False
_active_dns_port: int = 5353


def _parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decodes DNS query name labels from raw packet bytes."""
    labels = []
    curr = offset
    max_len = len(data)
    
    while curr < max_len:
        length = data[curr]
        if length == 0:
            curr += 1
            break
        # Pointer check
        if (length & 0xC0) == 0xC0:
            curr += 2
            break
        curr += 1
        if curr + length > max_len:
            break
        label = data[curr:curr + length].decode('ascii', errors='ignore')
        labels.append(label)
        curr += length

    return ".".join(labels), curr


def _build_dns_response(query_data: bytes, qname: str, qtype: int, resolve_ip: str = "127.0.0.1") -> bytes:
    """Builds a minimal valid DNS A-record response packet."""
    if len(query_data) < 12:
        return b""

    # Extract Transaction ID
    tx_id = query_data[:2]
    # Standard query response flags: QR=1, AA=1, RA=1, RCODE=0
    flags = b"\x81\x80"
    # QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    counts = struct.pack(">HHHH", 1, 1, 0, 0)
    question_section = query_data[12:]

    # Build Answer Section (Pointer to question name at offset 12, Type A, Class IN, TTL 60, Length 4, IP bytes)
    name_pointer = b"\xc0\x0c"  # Offset 12
    ans_type = struct.pack(">H", 1)  # Type A
    ans_class = struct.pack(">H", 1)  # Class IN
    ttl = struct.pack(">I", 60)  # 60s
    data_len = struct.pack(">H", 4)
    try:
        ip_bytes = ipaddress.IPv4Address(resolve_ip.strip()).packed
    except Exception:
        ip_bytes = socket.inet_aton("127.0.0.1")

    answer_section = name_pointer + ans_type + ans_class + ttl + data_len + ip_bytes

    return tx_id + flags + counts + question_section + answer_section


class ProxynthDNSProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if len(data) < 12:
            return

        try:
            client_ip = addr[0]
            qname, q_end = _parse_dns_name(data, 12)
            qtype = 1
            if q_end + 2 <= len(data):
                qtype = struct.unpack(">H", data[q_end:q_end + 2])[0]

            qtype_name = "A" if qtype == 1 else ("TXT" if qtype == 16 else f"TYPE_{qtype}")

            # Search for registered or alphanumeric token inside the queried domain name
            detected_token = None
            for reg_tok in _token_registry.keys():
                if reg_tok.lower() in qname.lower():
                    detected_token = reg_tok
                    break

            if not detected_token:
                match = _HEX_TOKEN_REGEX.search(qname)
                detected_token = match.group(1).lower() if match else None

            if detected_token:
                # Correlate with OAST engine
                record_oast_hit(
                    token=detected_token,
                    client_ip=client_ip,
                    method="DNS_QUERY",
                    path=qname,
                    protocol="DNS",
                    description=f"Out-of-band DNS ({qtype_name}) lookup for '{qname}' from {client_ip}"
                )

            # Send back standard DNS reply so targets don't hang
            resolve_ip = os.getenv("PROXSYNTH_DNS_RESOLVE_IP", "127.0.0.1")
            response_pkt = _build_dns_response(data, qname, qtype, resolve_ip)
            if response_pkt:
                self.transport.sendto(response_pkt, addr)
        except Exception:
            pass


async def start_dns_server(port: Optional[int] = None) -> bool:
    """Starts the asyncio UDP DNS listener on the designated port."""
    global _dns_transport, _is_running, _active_dns_port

    if _is_running and _dns_transport:
        return True

    ports_to_try = []
    if port:
        ports_to_try.append(port)
    env_port = os.getenv("PROXSYNTH_DNS_PORT")
    if env_port:
        try:
            ports_to_try.append(int(env_port))
        except Exception:
            pass
    # Preferred ports: 53 (standard DNS) -> 5353 -> 1053 (unprivileged)
    for p in [53, 5353, 1053]:
        if p not in ports_to_try:
            ports_to_try.append(p)

    loop = asyncio.get_running_loop()

    for p in ports_to_try:
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: ProxynthDNSProtocol(),
                local_addr=("0.0.0.0", p)
            )
            _dns_transport = transport
            _is_running = True
            _active_dns_port = p
            return True
        except (PermissionError, OSError):
            continue

    return False


def stop_dns_server():
    """Stops the DNS listener."""
    global _dns_transport, _is_running
    _is_running = False
    if _dns_transport:
        _dns_transport.close()
        _dns_transport = None


def get_dns_server_status():
    """Returns DNS server operational status."""
    return {
        "running": _is_running,
        "port": _active_dns_port if _is_running else None
    }
