"""
Proxsynth - Target Health & Latency Observability Engine
Probes target hosts and URLs measuring granular latency breakdowns:
DNS Resolution -> TCP Connect -> TLS Handshake -> HTTP Time To First Byte (TTFB).
Detects latency bottlenecks, 5xx server flapping, and connection failures.
"""

import time
import socket
import ssl
import asyncio
import urllib.parse
from typing import Dict, Any, Optional, List

import httpx
from backend.database import SessionLocal, HttpLog


async def probe_target_health(
    url: str,
    timeout: float = 8.0,
    project: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs a granular network and HTTP health check against a target URL,
    diagnosing DNS latency, TCP socket connection time, TLS handshake time,
    and HTTP Time To First Byte (TTFB).
    """
    raw_url = (url or "").strip()
    if not raw_url:
        return {
            "status": "ERROR",
            "verdict": "DOWN",
            "error": "URL parameter cannot be empty."
        }

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    parsed = urllib.parse.urlparse(raw_url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    if not hostname:
        return {
            "status": "ERROR",
            "verdict": "DOWN",
            "error": f"Could not parse valid hostname from URL: {url}"
        }

    # Latency tracking variables
    dns_latency_ms = 0.0
    tcp_latency_ms = 0.0
    tls_latency_ms: Optional[float] = None
    ttfb_ms = 0.0
    resolved_ips: List[str] = []
    tls_info: Dict[str, Any] = {}
    http_status: Optional[int] = None
    server_header: str = ""
    error_msg: Optional[str] = None

    loop = asyncio.get_running_loop()

    # 1. DNS Resolution
    t_dns_start = time.perf_counter()
    try:
        # Check if already an IP literal
        socket.inet_aton(hostname)
        resolved_ips = [hostname]
        dns_latency_ms = 0.0
    except (socket.error, OSError):
        try:
            # Domain lookup
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
                timeout=timeout
            )
            dns_latency_ms = round((time.perf_counter() - t_dns_start) * 1000, 2)
            resolved_ips = sorted(list(set(item[4][0] for item in addr_info if item[4])))
        except Exception as e:
            return {
                "url": raw_url,
                "hostname": hostname,
                "verdict": "DOWN",
                "phase_failed": "DNS",
                "error": f"DNS resolution failed for {hostname}: {str(e)}",
                "latencies": {"dns_ms": None, "tcp_ms": None, "tls_ms": None, "ttfb_ms": None, "total_ms": None},
                "diagnostics": [f"DNS resolution failed for {hostname}: {str(e)}. Check DNS server or domain validity."]
            }

    primary_ip = resolved_ips[0] if resolved_ips else hostname

    # 2. TCP Socket Connection
    t_tcp_start = time.perf_counter()
    try:
        conn = asyncio.open_connection(primary_ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        tcp_latency_ms = round((time.perf_counter() - t_tcp_start) * 1000, 2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as e:
        return {
            "url": raw_url,
            "hostname": hostname,
            "ip": primary_ip,
            "port": port,
            "verdict": "DOWN",
            "phase_failed": "TCP",
            "error": f"TCP connect to {primary_ip}:{port} failed: {str(e)}",
            "latencies": {"dns_ms": dns_latency_ms, "tcp_ms": None, "tls_ms": None, "ttfb_ms": None, "total_ms": None},
            "diagnostics": [f"TCP connect to {primary_ip}:{port} failed: {str(e)}. Target service may be offline or port is closed."]
        }

    # 3. TLS Handshake (if HTTPS)
    if scheme == "https":
        t_tls_start = time.perf_counter()
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE  # Allow lab / self-signed pentest targets

            conn = asyncio.open_connection(primary_ip, port, ssl=ssl_ctx, server_hostname=hostname)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            tls_latency_ms = round((time.perf_counter() - t_tls_start) * 1000, 2)

            cipher = writer.get_extra_info("cipher")
            if cipher:
                tls_info = {
                    "version": cipher[1] if len(cipher) > 1 else "Unknown",
                    "cipher": cipher[0] if len(cipher) > 0 else "Unknown",
                    "bits": cipher[2] if len(cipher) > 2 else 0
                }
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception as e:
            return {
                "url": raw_url,
                "hostname": hostname,
                "ip": primary_ip,
                "port": port,
                "verdict": "DOWN",
                "phase_failed": "TLS",
                "error": f"TLS handshake to {hostname} ({primary_ip}:{port}) failed: {str(e)}",
                "latencies": {"dns_ms": dns_latency_ms, "tcp_ms": tcp_latency_ms, "tls_ms": None, "ttfb_ms": None, "total_ms": None},
                "diagnostics": [f"TLS handshake to {hostname} failed: {str(e)}. Target certificate or cipher suite mismatch."]
            }

    # 4. HTTP Request & TTFB
    t_http_start = time.perf_counter()
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout) as client:
            # Try HEAD first for lightweight probe
            try:
                resp = await client.head(raw_url)
                if resp.status_code in [405, 501]:
                    resp = await client.get(raw_url, headers={"Range": "bytes=0-1024"})
            except Exception:
                resp = await client.get(raw_url, headers={"Range": "bytes=0-1024"})

            ttfb_ms = round((time.perf_counter() - t_http_start) * 1000, 2)
            http_status = resp.status_code
            server_header = resp.headers.get("server", "")
    except Exception as e:
        error_msg = str(e)
        http_status = None

    total_latency_ms = round(dns_latency_ms + tcp_latency_ms + (tls_latency_ms or 0.0) + ttfb_ms, 2)

    # 5. Check Project HttpLog for recent 5xx / 503 flapping
    flapping_detected = False
    recent_5xx_count = 0
    if project:
        db = SessionLocal()
        try:
            target_proj = project.strip().lower()
            recent_logs = (
                db.query(HttpLog)
                .filter(HttpLog.project == target_proj, HttpLog.host == hostname)
                .order_by(HttpLog.id.desc())
                .limit(10)
                .all()
            )
            consecutive_5xx = 0
            for l in recent_logs:
                if l.status_code and l.status_code >= 500:
                    recent_5xx_count += 1
                    consecutive_5xx += 1
                else:
                    break
            if consecutive_5xx >= 3 or (http_status and http_status in [502, 503, 504]):
                flapping_detected = True
        finally:
            db.close()
    elif http_status and http_status in [502, 503, 504]:
        flapping_detected = True

    # 6. Verdict Determination
    if error_msg or (http_status is None and ttfb_ms == 0.0):
        verdict = "DOWN"
    elif flapping_detected:
        verdict = "UNSTABLE_FLAPPING"
    elif total_latency_ms >= 1500 or ttfb_ms >= 1000:
        verdict = "HIGH_LATENCY"
    else:
        verdict = "HEALTHY"

    # Diagnostics recommendations
    recommendations = []
    if verdict == "HEALTHY":
        recommendations.append(f"Target is responsive (Total RTT {total_latency_ms}ms, HTTP {http_status}). Safe for automated campaigns.")
    elif verdict == "HIGH_LATENCY":
        recommendations.append(f"Target TTFB is high ({ttfb_ms}ms). Consider throttling concurrency (rate limit delay ≥200ms) to avoid target denial-of-service.")
    elif verdict == "UNSTABLE_FLAPPING":
        recommendations.append(f"Target returned 5xx errors or flapping (HTTP {http_status}). Proxsynth Circuit Breaker will pause campaigns to prevent crashing target.")
    elif verdict == "DOWN":
        recommendations.append(f"Target host is unreachable or connection refused ({error_msg or 'No HTTP response'}). Check network interface or container status.")

    if dns_latency_ms > 100:
        recommendations.append(f"DNS lookup took {dns_latency_ms}ms; consider caching DNS or using direct IP.")

    return {
        "url": raw_url,
        "hostname": hostname,
        "resolved_ips": resolved_ips,
        "primary_ip": primary_ip,
        "port": port,
        "scheme": scheme.upper(),
        "verdict": verdict,
        "http_status": http_status,
        "server_banner": server_header or "Unknown",
        "tls": tls_info if scheme == "https" else {"status": "PLAIN_HTTP"},
        "latencies": {
            "dns_ms": dns_latency_ms,
            "tcp_ms": tcp_latency_ms,
            "tls_ms": tls_latency_ms,
            "ttfb_ms": ttfb_ms,
            "total_ms": total_latency_ms
        },
        "flapping_detected": flapping_detected,
        "recent_5xx_count": recent_5xx_count,
        "diagnostics": recommendations
    }
