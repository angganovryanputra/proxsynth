"""
Proxsynth MCP - Core Security Utilities
Provides authenticated credential encryption, SSRF protection, shell command safe-mode guardrails,
and header/filename sanitization.
"""

import os
import re
import base64
import hashlib
import ipaddress
import urllib.parse
from typing import Tuple, Optional
from cryptography.fernet import Fernet

# ==============================================================================
# 1. Credential Encryption Engine (Fernet AES-128-CBC + HMAC-SHA256)
# ==============================================================================

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KEY_FILE = os.path.join(_BASE_DIR, ".proxsynth_key")
_OLD_KEY_FILE = os.path.join(_BASE_DIR, ".proxynth_key")
if not os.path.exists(_KEY_FILE) and os.path.exists(_OLD_KEY_FILE):
    try:
        os.rename(_OLD_KEY_FILE, _KEY_FILE)
    except Exception:
        _KEY_FILE = _OLD_KEY_FILE

def _get_or_create_fernet_key() -> bytes:
    """Retrieves encryption key from environment, key file, or generates a persistent one."""
    env_secret = os.getenv("PROXSYNTH_SECRET_KEY") or os.getenv("PROXSYNTH_SECRET_KEY")
    if env_secret and env_secret.strip():
        # Derive 32-byte url-safe base64 key using SHA-256
        derived = hashlib.sha256(env_secret.strip().encode("utf-8")).digest()
        return base64.urlsafe_b64encode(derived)

    # Check local key file
    if os.path.exists(_KEY_FILE):
        try:
            with open(_KEY_FILE, "rb") as f:
                key = f.read().strip()
                if len(key) == 44:  # Standard Fernet key length
                    return key
        except Exception:
            pass

    # Generate and persist a new key
    new_key = Fernet.generate_key()
    try:
        with open(_KEY_FILE, "wb") as f:
            f.write(new_key)
        # Set restrictive file permissions on Unix if available
        if hasattr(os, "chmod"):
            os.chmod(_KEY_FILE, 0o600)
    except Exception:
        pass
    return new_key

_FERNET_INSTANCE: Optional[Fernet] = None

def _get_fernet() -> Fernet:
    global _FERNET_INSTANCE
    if _FERNET_INSTANCE is None:
        _FERNET_INSTANCE = Fernet(_get_or_create_fernet_key())
    return _FERNET_INSTANCE


def get_or_create_encryption_key() -> bytes:
    """Public helper to initialize and return the master Fernet encryption key."""
    return _get_or_create_fernet_key()


def encrypt_secret(plaintext: str) -> str:
    """Encrypts sensitive session data/token string and prefixes with 'ENC:'."""
    if not plaintext:
        return ""
    try:
        f = _get_fernet()
        encrypted_bytes = f.encrypt(plaintext.encode("utf-8"))
        return f"ENC:{encrypted_bytes.decode('utf-8')}"
    except Exception:
        return plaintext


def decrypt_secret(stored_text: str) -> str:
    """Decrypts ciphertext if encrypted with 'ENC:', otherwise returns as-is for backward compatibility."""
    if not stored_text:
        return ""
    if stored_text.startswith("ENC:"):
        token = stored_text[4:].strip()
        try:
            f = _get_fernet()
            decrypted_bytes = f.decrypt(token.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except Exception:
            return ""
    return stored_text


# ==============================================================================
# 2. SSRF & Dangerous Network Target Guardrail
# ==============================================================================

import socket
import time
import asyncio
from typing import Dict, List, Any

# Dangerous IP ranges that must be blocked unless explicitly permitted
_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # AWS/Azure/GCP/OpenStack Instance Metadata Service (IMDS)
]

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

# High-concurrency DNS Cache with TTL (default 60s) to prevent hot-path event loop stalling during fuzzing
_DNS_CACHE: Dict[str, Tuple[float, List[Any]]] = {}
_DNS_CACHE_TTL = 60.0  # seconds


def resolve_hostname_ips(hostname: str) -> List[Any]:
    """Resolves a hostname to IP addresses using an in-memory TTL cache to prevent socket blocking on hot-paths."""
    now = time.time()
    cached = _DNS_CACHE.get(hostname)
    if cached and (now - cached[0] < _DNS_CACHE_TTL):
        return cached[1]

    resolved: List[Any] = []
    if hostname in ["localhost", "ip6-localhost", "ip6-loopback"]:
        resolved.append(ipaddress.ip_address("127.0.0.1"))
    else:
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                try:
                    resolved.append(ipaddress.ip_address(ip_str))
                except ValueError:
                    pass
        except Exception:
            pass

    _DNS_CACHE[hostname] = (now, resolved)
    return resolved


async def async_resolve_hostname_ips(hostname: str) -> List[Any]:
    """Asynchronously resolves a hostname without blocking the event loop, leveraging threadpool executor and TTL cache."""
    now = time.time()
    cached = _DNS_CACHE.get(hostname)
    if cached and (now - cached[0] < _DNS_CACHE_TTL):
        return cached[1]

    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, resolve_hostname_ips, hostname)
    except RuntimeError:
        return resolve_hostname_ips(hostname)


def _evaluate_ip_list(hostname: str, ips: List[Any], allow_internal: bool) -> Tuple[bool, Optional[str]]:
    for ip_check in ips:
        # Check Cloud Metadata (Strictly blocked under all circumstances)
        for meta_net in _METADATA_NETWORKS:
            if ip_check in meta_net:
                return False, f"SSRF Guardrail: Target '{hostname}' ({ip_check}) belongs to cloud instance metadata service (169.254.x.x)."

        # Check Private Networks (Blocked unless allow_internal is enabled)
        if not allow_internal:
            for priv_net in _PRIVATE_NETWORKS:
                if ip_check in priv_net:
                    return False, f"SSRF Guardrail: Target '{hostname}' resolves to private/loopback IP '{ip_check}'. Enable 'Allow Internal Scope' in project settings to permit."
    return True, None


def check_ssrf_safety(url: str, allow_internal: bool = True, proxsynth_backend_port: int = 8000, proxynth_backend_port: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a target URL poses an SSRF threat (Synchronous / Cached).
    - Always blocks Cloud Metadata (169.254.169.254).
    - Always blocks recursive self-loopback requests to Proxsynth's own backend port.
    - Resolves DNS hostnames to verify that domains do not resolve to private/loopback/metadata IPs.
    - Uses in-memory DNS caching with 60s TTL to prevent thread starvation during fuzzing.
    """
    effective_port = proxynth_backend_port if proxynth_backend_port is not None and proxynth_backend_port != 8000 else proxsynth_backend_port
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as ex:
        return False, f"Malformed URL: {str(ex)}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ["http", "https"]:
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, "Target URL is missing a valid hostname."

    port = parsed.port or (443 if scheme == "https" else 80)
    detected_port = None
    backend_url_env = os.getenv("PROXSYNTH_BACKEND_URL") or os.getenv("PROXSYNTH_BACKEND_URL", "")
    if backend_url_env:
        try:
            b_parsed = urllib.parse.urlparse(backend_url_env)
            if b_parsed.port:
                detected_port = b_parsed.port
        except Exception:
            pass
    current_backend_port = (detected_port if effective_port == 8000 and detected_port else effective_port) or int(os.getenv("PROXSYNTH_PORT", os.getenv("PROXSYNTH_PORT", "8000")))
    current_proxy_port = int(os.getenv("PROXSYNTH_PROXY_PORT", os.getenv("PROXSYNTH_PROXY_PORT", "8088")))

    # 1. Anti-Self-Loopback: Prevent recursive infinite loops back to Proxsynth
    if hostname in ["localhost", "127.0.0.1", "0.0.0.0", "::1"] and port in [current_backend_port, current_proxy_port]:
        return False, f"Recursive proxy loop blocked: Target points to Proxsynth's own port ({port})."

    # 2. Check for obvious metadata hostname aliases
    if hostname in ["metadata.google.internal", "instance-data", "metadata"]:
        return False, f"SSRF Guardrail: Target host '{hostname}' matches cloud metadata service."

    # 3. Check IP address (Literal or DNS-Resolved with TTL cache)
    try:
        ip_obj = ipaddress.ip_address(hostname)
        return _evaluate_ip_list(hostname, [ip_obj], allow_internal)
    except ValueError:
        pass

    resolved_ips = resolve_hostname_ips(hostname)
    return _evaluate_ip_list(hostname, resolved_ips, allow_internal)


async def async_check_ssrf_safety(url: str, allow_internal: bool = True, proxsynth_backend_port: int = 8000, proxynth_backend_port: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """
    Asynchronously validates whether a target URL poses an SSRF threat without blocking the event loop.
    """
    effective_port = proxynth_backend_port if proxynth_backend_port is not None and proxynth_backend_port != 8000 else proxsynth_backend_port
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as ex:
        return False, f"Malformed URL: {str(ex)}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ["http", "https"]:
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, "Target URL is missing a valid hostname."

    port = parsed.port or (443 if scheme == "https" else 80)
    detected_port = None
    backend_url_env = os.getenv("PROXSYNTH_BACKEND_URL") or os.getenv("PROXSYNTH_BACKEND_URL", "")
    if backend_url_env:
        try:
            b_parsed = urllib.parse.urlparse(backend_url_env)
            if b_parsed.port:
                detected_port = b_parsed.port
        except Exception:
            pass
    current_backend_port = (detected_port if effective_port == 8000 and detected_port else effective_port) or int(os.getenv("PROXSYNTH_PORT", os.getenv("PROXSYNTH_PORT", "8000")))
    current_proxy_port = int(os.getenv("PROXSYNTH_PROXY_PORT", os.getenv("PROXSYNTH_PROXY_PORT", "8088")))

    if hostname in ["localhost", "127.0.0.1", "0.0.0.0", "::1"] and port in [current_backend_port, current_proxy_port]:
        return False, f"Recursive proxy loop blocked: Target points to Proxsynth's own port ({port})."

    if hostname in ["metadata.google.internal", "instance-data", "metadata"]:
        return False, f"SSRF Guardrail: Target host '{hostname}' matches cloud metadata service."

    try:
        ip_obj = ipaddress.ip_address(hostname)
        return _evaluate_ip_list(hostname, [ip_obj], allow_internal)
    except ValueError:
        pass

    resolved_ips = await async_resolve_hostname_ips(hostname)
    return _evaluate_ip_list(hostname, resolved_ips, allow_internal)


# ==============================================================================
# 3. Hardened CLI Safe-Mode Engine (Windows + Unix)
# ==============================================================================

EXPANDED_DANGEROUS_PATTERNS = [
    # POSIX File system destruction
    r"rm\s+(-[rfRF]+\s+|--recursive\s+|--force\s+)*\/",
    r"rm\s+(-[rfRF]+\s+|--recursive\s+|--force\s+)*\*",
    r"mkfs",
    r"dd\s+if=",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r"\$0\|\$0&",
    r">\s*\/dev\/sd[a-z]",
    r"chmod\s+(-[rR]+\s+)?777\s+\/",
    r"chown\s+(-[rR]+\s+)?.*\/",
    r"find\s+\/\s+-delete",
    
    # Windows File system destruction
    r"format\s+[a-zA-Z]:",
    r"rd\s+(\/s|\/q|\s+)*[a-zA-Z]:\\",
    r"rmdir\s+(\/s|\/q|\s+)*[a-zA-Z]:\\",
    r"del\s+(\/[sfqa]+\s+)*[a-zA-Z]:\\",
    r"Remove-Item\s+(-Recurse|-Force|\s+)*[a-zA-Z]:\\",
    r"Clear-Disk",
    r"Format-Volume",
    
    # Remote pipeline execution
    r"curl\s+[^\n|]+\|\s*(bash|sh|zsh|powershell|cmd)",
    r"wget\s+[^\n|]+\|\s*(bash|sh|zsh|powershell|cmd)",
    r"iwr\s+[^\n|]+\|\s*iex",
    
    # Database destruction
    r"DROP\s+DATABASE",
    r"DROP\s+TABLE",
    r"TRUNCATE\s+TABLE",
    
    # Machine power operations
    r"shutdown(\.exe)?\s+",
    r"reboot(\.exe)?",
    r"init\s+[06]",
    r"Stop-Computer",
    r"Restart-Computer",
]

def check_command_safe_mode(command: str, allow_internal: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Inspects shell commands against:
    1. Dangerous filesystem/system destruction patterns.
    2. Cloud metadata IP/host targeting (SSRF via CLI).
    3. Extracted URL targets violating SSRF policies.
    """
    cmd_clean = command.strip()
    if not cmd_clean:
        return False, "Command cannot be empty"

    # 1. Check dangerous system command patterns
    for pat in EXPANDED_DANGEROUS_PATTERNS:
        if re.search(pat, cmd_clean, re.IGNORECASE):
            return False, f"Command blocked by Proxsynth CLI Safe-Mode (Matched dangerous signature: '{pat}')"

    # 2. Check metadata service targeting in CLI (e.g. curl 169.254.169.254)
    if re.search(r"\b169\.254\.\d+\.\d+\b", cmd_clean) or "metadata.google.internal" in cmd_clean:
        return False, "Command blocked by Proxsynth SSRF Guard: Targeting cloud instance metadata service (169.254.x.x) is strictly forbidden."

    # 3. Extract and validate any HTTP/HTTPS URLs present in the command
    extracted_urls = re.findall(r"https?://[^\s'\"`]+", cmd_clean)
    for u in extracted_urls:
        safe, reason = check_ssrf_safety(u, allow_internal=allow_internal)
        if not safe:
            return False, f"Command blocked by Proxsynth SSRF Guard: Embedded target '{u}' violates SSRF policy ({reason})"

    return True, None


async def async_check_command_safe_mode(command: str, allow_internal: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Asynchronously inspects shell commands against dangerous patterns and SSRF targets
    without blocking the event loop on DNS resolution.
    """
    cmd_clean = command.strip()
    if not cmd_clean:
        return False, "Command cannot be empty"

    # 1. Check dangerous system command patterns
    for pat in EXPANDED_DANGEROUS_PATTERNS:
        if re.search(pat, cmd_clean, re.IGNORECASE):
            return False, f"Command blocked by Proxsynth CLI Safe-Mode (Matched dangerous signature: '{pat}')"

    # 2. Check metadata service targeting in CLI (e.g. curl 169.254.169.254)
    if re.search(r"\b169\.254\.\d+\.\d+\b", cmd_clean) or "metadata.google.internal" in cmd_clean:
        return False, "Command blocked by Proxsynth SSRF Guard: Targeting cloud instance metadata service (169.254.x.x) is strictly forbidden."

    # 3. Extract and asynchronously validate any HTTP/HTTPS URLs present in the command
    extracted_urls = re.findall(r"https?://[^\s'\"`]+", cmd_clean)
    for u in extracted_urls:
        safe, reason = await async_check_ssrf_safety(u, allow_internal=allow_internal)
        if not safe:
            return False, f"Command blocked by Proxsynth SSRF Guard: Embedded target '{u}' violates SSRF policy ({reason})"

    return True, None



# ==============================================================================
# 4. Header & Filename Sanitizer
# ==============================================================================

def sanitize_attachment_filename(name: str, ext: str = "txt") -> str:
    """Sanitizes strings for safe inclusion in HTTP Content-Disposition headers."""
    clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", name).strip("_")
    if not clean:
        clean = "export"
    clean_ext = re.sub(r"[^a-zA-Z0-9]", "", ext).strip()
    return f"{clean}.{clean_ext}" if clean_ext else clean
