"""
PROXSYNTH — Autonomous Async Network Recon & Service Fingerprinting Engine
Zero-dependency, non-blocking TCP port scanner and service banner analyzer
that automatically updates the Target Knowledge Graph and audits exposed services.
"""

import asyncio
import ipaddress
import logging
import re
import socket
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple

import httpx

from backend.database import SessionLocal, HttpLog, Finding
from backend.target_manager import upsert_target_asset, add_or_update_service

logger = logging.getLogger("proxynth.network_scanner")

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445,
    465, 500, 514, 587, 636, 873, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 2049, 2082, 2083,
    2086, 2087, 2181, 2222, 2375, 2376, 2379, 3000, 3128, 3306, 3389, 3690, 4000, 4369, 5000, 5432,
    5672, 5900, 5985, 5986, 6000, 6379, 6443, 6667, 7001, 7077, 8000, 8008, 8080, 8081, 8088, 8443,
    8500, 8888, 9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 11211, 15672,
    27017, 27018, 28017, 50000, 50070
]

WEB_PORTS = [80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443, 3000, 5000]

DATABASE_PORTS = {
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb"
}

KNOWN_SERVICE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2222: "ssh-alt",
    2375: "docker",
    2379: "etcd",
    3000: "http-alt",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "http-alt",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    6443: "kubernetes",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8500: "consul",
    9000: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb"
}


def parse_port_list(ports_spec: Optional[str] = None, profile: str = "top_100") -> List[int]:
    """Resolves port profiles or string specifications (e.g., '80,443,8000-8010') into a sorted unique list."""
    if ports_spec:
        ports: Set[int] = set()
        for chunk in ports_spec.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                try:
                    start, end = map(int, chunk.split("-", 1))
                    for p in range(max(1, start), min(65535, end) + 1):
                        ports.add(p)
                except ValueError:
                    pass
            elif chunk.isdigit():
                p = int(chunk)
                if 1 <= p <= 65535:
                    ports.add(p)
        if ports:
            return sorted(list(ports))

    prof = (profile or "top_100").lower().strip()
    if prof == "top_20":
        return list(TOP_20_PORTS)
    elif prof == "web":
        return list(WEB_PORTS)
    elif prof == "databases":
        return list(DATABASE_PORTS.keys())
    return list(TOP_100_PORTS)


def clean_target_hostname(target: str) -> Tuple[str, Optional[int]]:
    """Extracts raw host or IP and optional port from URLs or host:port strings."""
    raw = target.strip()
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        return (parsed.hostname or "127.0.0.1", parsed.port)
    if ":" in raw and not raw.startswith("["):
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return (parts[0], int(parts[1]))
    return (raw.strip("/"), None)


async def check_port_open(host: str, port: int, timeout: float = 0.8) -> bool:
    """Checks if a TCP port is open using non-blocking asyncio socket connection."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def grab_service_banner(host: str, port: int, timeout: float = 1.2) -> Tuple[str, str]:
    """
    Attempts banner grabbing and protocol identification on an open port.
    Returns (service_name, banner_string).
    """
    default_name = KNOWN_SERVICE_PORTS.get(port, "unknown")
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
    except Exception:
        return (default_name, "")

    banner = ""
    try:
        # If it's standard HTTP/HTTPS or high web port, send minimal HTTP probe
        if port in WEB_PORTS or default_name.startswith("http"):
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Proxynth/0.1.0\r\n\r\n".encode())
            await writer.drain()
            raw_data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = raw_data.decode("utf-8", errors="ignore").strip()
            # Extract server header if present
            server_match = re.search(r"server:\s*([^\r\n]+)", banner, re.IGNORECASE)
            if server_match:
                return ("http" if port != 443 and port != 8443 else "https", f"Server: {server_match.group(1).strip()}")
            return ("http" if port != 443 and port != 8443 else "https", banner[:120])

        # For Redis
        elif port == 6379:
            writer.write(b"PING\r\n")
            await writer.drain()
            raw_data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner = raw_data.decode("utf-8", errors="ignore").strip()
            if "+PONG" in banner or "PONG" in banner:
                return ("redis", f"Redis Unauthenticated: {banner}")
            return ("redis", banner[:120])

        # Generic banner grab for SSH, FTP, SMTP, etc.
        try:
            raw_data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner = raw_data.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            # Send newline probe
            writer.write(b"\r\n")
            await writer.drain()
            raw_data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner = raw_data.decode("utf-8", errors="ignore").strip()

        if "SSH-" in banner:
            return ("ssh", banner[:100])
        elif "FTP" in banner or banner.startswith("220"):
            return ("ftp", banner[:100])
        elif "ESMTP" in banner or "SMTP" in banner:
            return ("smtp", banner[:100])
        elif "MySQL" in banner or "mariadb" in banner.lower():
            return ("mysql", banner[:100])

        return (default_name, banner[:120])
    except Exception:
        return (default_name, banner[:120])
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def audit_exposed_service_misconfigurations(
    host: str,
    open_ports: List[int],
    project: str = "default"
) -> List[Dict[str, Any]]:
    """
    Automatically tests discovered open ports for critical unauthenticated access
    and misconfigurations (Redis unauth, Elasticsearch cluster dump, Docker daemon RCE).
    """
    findings: List[Dict[str, Any]] = []

    # 1. Check Unauthenticated Redis on Port 6379
    if 6379 in open_ports:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, 6379), timeout=1.5)
            writer.write(b"INFO\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(2048), timeout=1.5)
            resp_str = resp.decode("utf-8", errors="ignore")
            writer.close()
            await writer.wait_closed()

            if "redis_version:" in resp_str and "NOAUTH" not in resp_str:
                ver = re.search(r"redis_version:([^\r\n]+)", resp_str)
                ver_str = ver.group(1) if ver else "unknown"
                findings.append({
                    "title": f"Unauthenticated Redis Instance Exposed on {host}:6379",
                    "severity": "CRITICAL",
                    "category": "NETWORK_MISCONFIGURATION",
                    "port": 6379,
                    "evidence": f"Successfully executed INFO command without authentication. Redis version: {ver_str}",
                    "description": "The Redis cache/in-memory store has no authentication enabled. Remote unauthenticated attackers can execute arbitrary commands, read sensitive cached tokens, or dump database keys.",
                    "remediation": "Enable 'requirepass' in redis.conf, bind Redis strictly to 127.0.0.1, or place it behind a secure VPC security group."
                })
        except Exception as e:
            logger.debug(f"Redis audit check error: {e}")

    # 2. Check Unauthenticated Elasticsearch on Port 9200
    if 9200 in open_ports:
        try:
            async with httpx.AsyncClient(timeout=2.0, verify=False) as client:
                res = await client.get(f"http://{host}:9200/")
                if res.status_code == 200 and "cluster_name" in res.text:
                    findings.append({
                        "title": f"Unauthenticated Elasticsearch Cluster Exposed on {host}:9200",
                        "severity": "HIGH",
                        "category": "NETWORK_MISCONFIGURATION",
                        "port": 9200,
                        "evidence": res.text[:400],
                        "description": "Elasticsearch REST API is accessible without authentication, exposing index clusters, document structures, and stored business data.",
                        "remediation": "Enable Elasticsearch Security (xpack.security.enabled: true), configure HTTPS, and enforce strong role-based passwords."
                    })
        except Exception as e:
            logger.debug(f"Elasticsearch audit check error: {e}")

    # 3. Check Exposed Docker API on Port 2375
    if 2375 in open_ports:
        try:
            async with httpx.AsyncClient(timeout=2.0, verify=False) as client:
                res = await client.get(f"http://{host}:2375/version")
                if res.status_code == 200 and "ApiVersion" in res.text:
                    findings.append({
                        "title": f"Unauthenticated Docker Daemon Socket Exposed on {host}:2375 (Direct Host RCE)",
                        "severity": "CRITICAL",
                        "category": "REMOTE_CODE_EXECUTION",
                        "port": 2375,
                        "evidence": res.text[:300],
                        "description": "The unencrypted Docker daemon REST API is exposed to the network without TLS mutual authentication. Attackers can spawn privileged containers and mount the host filesystem, achieving instant root code execution.",
                        "remediation": "Disable TCP binding on port 2375. Use unix socket (/var/run/docker.sock) or enable TLS client certificate authentication."
                    })
        except Exception as e:
            logger.debug(f"Docker socket audit check error: {e}")

    # Record any discovered misconfigurations directly into Findings Ledger
    if findings:
        db = SessionLocal()
        try:
            for f in findings:
                # Create synthetic audit HttpLog entry for relational integrity
                log_entry = HttpLog(
                    project=project,
                    source="NETWORK_SCANNER",
                    method="PORT_AUDIT",
                    url=f"tcp://{host}:{f['port']}",
                    host=host,
                    path=f"port_{f['port']}",
                    status_code=200,
                    flag_status="CONFIRMED",
                    reasoning=f"Autonomous port scanner discovered open port and verified misconfiguration: {f['title']}"
                )
                db.add(log_entry)
                db.flush()

                finding_record = Finding(
                    log_id=log_entry.id,
                    title=f["title"],
                    severity=f["severity"],
                    category=f["category"],
                    evidence=f.get("evidence", ""),
                    description=f.get("description", ""),
                    remediation=f.get("remediation", "")
                )
                db.add(finding_record)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Failed to record network findings: {e}")
        finally:
            db.close()

    return findings


async def scan_target_ports(
    target: str,
    ports_profile: str = "top_100",
    ports_custom: Optional[str] = None,
    concurrency: int = 80,
    timeout: float = 0.8,
    project: str = "default",
    audit_misconfigs: bool = True
) -> Dict[str, Any]:
    """
    Autonomously scans a target host or IP for open TCP ports and fingerprint services.
    Ingests all assets and services into the Target Knowledge Graph.
    """
    clean_host, specific_port = clean_target_hostname(target)
    ports_to_scan = [specific_port] if specific_port else parse_port_list(ports_custom, ports_profile)

    # Ingest target asset
    try:
        upsert_target_asset(project=project, host=clean_host, notes="Discovered via autonomous network scanner")
    except Exception:
        pass

    sem = asyncio.Semaphore(concurrency)
    open_ports: List[int] = []

    async def _probe(p: int):
        async with sem:
            is_open = await check_port_open(clean_host, p, timeout=timeout)
            if is_open:
                open_ports.append(p)

    tasks = [_probe(p) for p in ports_to_scan]
    await asyncio.gather(*tasks)

    open_ports.sort()

    # Banner Grabbing & Service Registration
    services_found: List[Dict[str, Any]] = []
    web_targets: List[str] = []

    for p in open_ports:
        svc_name, banner = await grab_service_banner(clean_host, p, timeout=1.2)
        try:
            svc_dict = add_or_update_service(
                project=project,
                host=clean_host,
                port=p,
                protocol="tcp",
                service_name=svc_name,
                banner=banner,
                state="open"
            )
            services_found.append(svc_dict)
        except Exception:
            services_found.append({
                "port": p,
                "protocol": "tcp",
                "service_name": svc_name,
                "banner": banner
            })

        # Identify candidate web targets for crawling/API testing
        if p == 80:
            web_targets.append(f"http://{clean_host}")
        elif p == 443:
            web_targets.append(f"https://{clean_host}")
        elif p in WEB_PORTS or svc_name.startswith("http"):
            proto = "https" if p in [8443, 9443] else "http"
            web_targets.append(f"{proto}://{clean_host}:{p}")

    # Misconfiguration / Exposure Audits
    misconfigs: List[Dict[str, Any]] = []
    if audit_misconfigs and open_ports:
        misconfigs = await audit_exposed_service_misconfigurations(
            host=clean_host,
            open_ports=open_ports,
            project=project
        )

    return {
        "status": "completed",
        "target": target,
        "resolved_host": clean_host,
        "scanned_ports_count": len(ports_to_scan),
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "services": services_found,
        "web_targets": list(set(web_targets)),
        "misconfigurations_count": len(misconfigs),
        "misconfigurations": misconfigs
    }
