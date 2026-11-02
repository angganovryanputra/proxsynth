"""
Proxsynth - Wildcard Subdomain & Scope Reconnaissance Engine
Passive Certificate Transparency (crt.sh) Enumerator, DNS Resolver,
Dangling CNAME Takeover Detector, and Attack Surface Knowledge Graph Ingester.
"""

import asyncio
import json
import logging
import re
import socket
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from backend.database import Finding, HttpLog, SessionLocal, TargetAsset, TargetEndpoint, TargetService
from backend.target_manager import upsert_target_asset, add_or_update_service, add_or_update_endpoint

logger = logging.getLogger("proxsynth.scope_recon")

# Cloud provider CNAME signatures for Dangling CNAME Takeover detection
TAKEOVER_SIGNATURES = [
    {
        "provider": "AWS S3 Bucket",
        "cname_pattern": r"\.s3(?:-website)?(?:-[a-z0-9-]+)?\.amazonaws\.com$",
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "HIGH",
        "remediation": "Claim the abandoned S3 bucket or remove the dangling CNAME DNS record immediately.",
    },
    {
        "provider": "GitHub Pages",
        "cname_pattern": r"\.github\.io$",
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
        "severity": "HIGH",
        "remediation": "Re-claim the GitHub Pages repository or remove the dangling CNAME record from DNS.",
    },
    {
        "provider": "Heroku",
        "cname_pattern": r"\.(?:herokudns|herokuapp)\.com$",
        "fingerprints": ["No such app", "Heroku | No such app", "There's nothing here, yet"],
        "severity": "HIGH",
        "remediation": "Re-associate the custom domain in Heroku or remove the dangling CNAME record.",
    },
    {
        "provider": "Microsoft Azure",
        "cname_pattern": r"\.(?:azurewebsites|trafficmanager|cloudapp)\.net$",
        "fingerprints": ["404 Web Site not found", "Web App - Unavailable"],
        "severity": "HIGH",
        "remediation": "Restore the Azure App Service resource or remove the dangling DNS pointer.",
    },
    {
        "provider": "Shopify",
        "cname_pattern": r"\.myshopify\.com$",
        "fingerprints": ["Sorry, this shop is currently unavailable"],
        "severity": "HIGH",
        "remediation": "Rebind the store in Shopify admin or delete the DNS CNAME record.",
    },
    {
        "provider": "Surge.sh",
        "cname_pattern": r"\.surge\.sh$",
        "fingerprints": ["project not found"],
        "severity": "HIGH",
        "remediation": "Deploy a project on Surge under this name or remove the CNAME record.",
    },
    {
        "provider": "Bitbucket",
        "cname_pattern": r"\.bitbucket\.io$",
        "fingerprints": ["Repository not found"],
        "severity": "HIGH",
        "remediation": "Re-create the Bitbucket repository or clean up the DNS CNAME.",
    },
]

COMMON_SUBDOMAIN_SEEDS = [
    "api", "app", "dev", "staging", "admin", "auth", "portal",
    "mail", "vpn", "test", "dashboard", "internal", "cdn",
    "gateway", "beta", "docs", "login", "sso", "status", "web"
]


def clean_domain_input(target: str) -> str:
    """Normalizes wildcard domains like *.example.com or http://example.com to clean example.com."""
    raw = target.strip().lower()
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.netloc
    raw = raw.split(":")[0]
    if raw.startswith("*."):
        raw = raw[2:]
    elif raw.startswith("."):
        raw = raw[1:]
    return raw.strip("/")


def query_crtsh_subdomains(domain: str, timeout: float = 8.0) -> List[str]:
    """
    Queries Certificate Transparency (crt.sh) logs for active subdomains.
    Returns normalized unique subdomains.
    """
    clean_d = clean_domain_input(domain)
    url = f"https://crt.sh/?q=%.{clean_d}&output=json"
    subdomains: Set[str] = set()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProxsynthScopeRecon/2.0",
        "Accept": "application/json"
    }

    try:
        with httpx.Client(timeout=timeout, verify=False) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    for item in data:
                        name_val = item.get("name_value", "")
                        for line in name_val.split("\n"):
                            line = line.strip().lower()
                            if line.startswith("*."):
                                line = line[2:]
                            if line.endswith(clean_d) and line:
                                subdomains.add(line)
                except Exception as ex:
                    logger.warning(f"Error parsing crt.sh JSON for {clean_d}: {ex}")
    except Exception as ex:
        logger.info(f"crt.sh CT lookup timed out or failed for {clean_d} ({ex}); applying seed fallback.")

    # Always ensure base domain and common seed candidates are checked
    subdomains.add(clean_d)
    for seed in COMMON_SUBDOMAIN_SEEDS:
        subdomains.add(f"{seed}.{clean_d}")

    return sorted(list(subdomains))


def resolve_domain_dns(domain: str) -> Dict[str, Any]:
    """
    Resolves IP addresses and canonical names (CNAME) for a domain.
    """
    ips: List[str] = []
    cname: Optional[str] = None
    is_alive = False

    try:
        host_info = socket.gethostbyname_ex(domain)
        primary_host = host_info[0]
        aliases = host_info[1]
        ips = host_info[2]
        is_alive = len(ips) > 0

        if aliases:
            cname = aliases[0]
        elif primary_host and primary_host.lower() != domain.lower():
            cname = primary_host
    except (socket.gaierror, socket.herror, Exception):
        is_alive = False

    return {
        "domain": domain,
        "is_alive": is_alive,
        "ip_addresses": ips,
        "primary_ip": ips[0] if ips else None,
        "cname": cname,
    }


def inspect_cname_takeover(domain: str, cname: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Checks if a resolved CNAME matches a vulnerable cloud service signature
    and checks if the resource is dangling.
    """
    if not cname:
        return None

    cname_clean = cname.lower().strip(".")
    for sig in TAKEOVER_SIGNATURES:
        if re.search(sig["cname_pattern"], cname_clean):
            # Probe HTTP and HTTPS to confirm dangling error signature
            is_dangling = False
            matched_fingerprint = None
            for scheme in ["https", "http"]:
                test_url = f"{scheme}://{domain}"
                try:
                    with httpx.Client(timeout=3.0, verify=False, follow_redirects=True) as client:
                        r = client.get(test_url)
                        for fp in sig["fingerprints"]:
                            if fp.lower() in (r.text or "").lower():
                                is_dangling = True
                                matched_fingerprint = fp
                                break
                    if is_dangling:
                        break
                except Exception:
                    pass

            if is_dangling:
                return {
                    "vulnerable": True,
                    "provider": sig["provider"],
                    "domain": domain,
                    "cname": cname,
                    "fingerprint": matched_fingerprint,
                    "severity": sig["severity"],
                    "remediation": sig["remediation"],
                    "confidence": "HIGH",
                }

    return None


def auto_ingest_scope_targets(
    domain: str,
    project: str = "default",
    auto_probe_takeover: bool = True,
    custom_subdomains: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Performs full scope reconnaissance for a root/wildcard domain:
    1. Passive CT log subdomain harvesting via crt.sh
    2. DNS resolution (A/AAAA/CNAME)
    3. Dangling CNAME takeover evaluation
    4. Auto-ingests active assets into TargetAsset, TargetService, TargetEndpoint
    5. Creates Finding records if takeover vulnerabilities are detected
    """
    clean_d = clean_domain_input(domain)
    clean_proj = (project or "default").strip().lower()

    if custom_subdomains:
        discovered_subs = [clean_domain_input(s) for s in custom_subdomains]
    else:
        discovered_subs = query_crtsh_subdomains(clean_d)

    resolved_records = []
    alive_assets = []
    takeover_alerts = []

    db = SessionLocal()
    try:
        for sub in discovered_subs:
            dns_res = resolve_domain_dns(sub)
            resolved_records.append(dns_res)

            if dns_res["is_alive"]:
                ip_addr = dns_res["primary_ip"]
                # Ingest into TargetAsset
                asset = upsert_target_asset(
                    project=clean_proj,
                    host=sub,
                    ip=ip_addr,
                    tags="recon,subdomain,crtsh"
                )
                alive_assets.append({
                    "host": sub,
                    "ip": ip_addr,
                    "cname": dns_res["cname"],
                    "asset_id": asset.get("id") if isinstance(asset, dict) else getattr(asset, "id", None)
                })

                # Ingest common HTTP / HTTPS services
                for port in [80, 443]:
                    svc_name = "http" if port == 80 else "https"
                    add_or_update_service(
                        project=clean_proj,
                        host=sub,
                        port=port,
                        service_name=svc_name
                    )

                # Ingest common root endpoints
                for path in ["/", "/api", "/login"]:
                    add_or_update_endpoint(
                        project=clean_proj,
                        host=sub,
                        url=f"http://{sub}{path}",
                        method="GET"
                    )

            # Check for Dangling CNAME Subdomain Takeover
            if auto_probe_takeover and dns_res["cname"]:
                takeover_result = inspect_cname_takeover(sub, dns_res["cname"])
                if takeover_result:
                    takeover_alerts.append(takeover_result)

                    # Create High/Critical Finding in DB
                    title = f"Subdomain Takeover Vulnerability on '{sub}' ({takeover_result['provider']})"
                    desc = (
                        f"Dangling CNAME record detected pointing to {dns_res['cname']} "
                        f"({takeover_result['provider']}). The remote service returned indicator: '{takeover_result['fingerprint']}', "
                        f"confirming the underlying cloud resource is unclaimed and can be hijacked by an attacker."
                    )
                    evidence = (
                        f"Subdomain: {sub}\n"
                        f"CNAME Pointer: {dns_res['cname']}\n"
                        f"Matched Fingerprint: {takeover_result['fingerprint']}\n"
                        f"Provider: {takeover_result['provider']}"
                    )

                    existing = db.query(Finding).filter(Finding.title == title).first()
                    if not existing:
                        finding = Finding(
                            title=title,
                            severity=takeover_result["severity"],
                            category="Subdomain Takeover",
                            evidence=evidence,
                            description=desc,
                            remediation=takeover_result["remediation"],
                        )
                        db.add(finding)
                        db.commit()

        return {
            "status": "success",
            "root_domain": clean_d,
            "project": clean_proj,
            "total_subdomains_discovered": len(discovered_subs),
            "alive_assets_count": len(alive_assets),
            "alive_assets": alive_assets,
            "takeover_alerts_count": len(takeover_alerts),
            "takeover_alerts": takeover_alerts,
            "timestamp": datetime.now().isoformat(),
        }
    finally:
        db.close()
