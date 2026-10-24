"""
Proxsynth CA Manager & Certificate Authority Orchestrator
Manages Root CA initialization, path resolution, OS trust store hooks, and installation scripts
for seamless TLS MITM proxying across Windows, Linux, macOS, and CLI/API clients.
"""
import os
import hashlib
from typing import Tuple, Any, Dict, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from backend.forward_proxy import get_ca_dir, get_ca_cert_path as _base_get_ca_cert_path, _ensure_ca


def init_ca() -> str:
    """Ensures Root CA key and certificate are generated on disk, returning certificate path."""
    _ensure_ca()
    return _base_get_ca_cert_path()


def get_ca_cert_path() -> str:
    """Returns path to the Root CA certificate, automatically generating it if not present."""
    _ensure_ca()
    return _base_get_ca_cert_path()


def get_ca_pem_bytes() -> bytes:
    """Returns the raw PEM-encoded bytes of the Root CA certificate."""
    cert_path = get_ca_cert_path()
    if os.path.exists(cert_path):
        with open(cert_path, "rb") as f:
            return f.read()
    return b""


def get_ca_metadata() -> Dict[str, Any]:
    """Inspects the active Root CA certificate and returns security metadata and fingerprints."""
    cert_path = get_ca_cert_path()
    pem_bytes = get_ca_pem_bytes()
    if not pem_bytes:
        return {
            "exists": False,
            "path": cert_path,
            "common_name": "Proxsynth Forward Proxy CA",
            "sha256": "",
            "sha1": "",
            "not_before": "",
            "not_after": ""
        }

    sha256_fp = hashlib.sha256(pem_bytes).hexdigest().upper()
    sha1_fp = hashlib.sha1(pem_bytes).hexdigest().upper()
    
    common_name = "Proxsynth Forward Proxy CA"
    not_before = ""
    not_after = ""
    
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
        common_name = cert.subject.rfc4514_string()
        not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat()
        not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat()
    except Exception:
        pass

    return {
        "exists": True,
        "path": cert_path,
        "common_name": common_name,
        "sha256": ":".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2)),
        "sha1": ":".join(sha1_fp[i:i+2] for i in range(0, len(sha1_fp), 2)),
        "not_before": not_before,
        "not_after": not_after
    }


def get_os_trust_scripts(cert_filename: str = "proxsynth-ca.crt") -> Dict[str, str]:
    """Generates one-click OS trust store installation scripts for Windows, Linux, macOS, and CLI tools."""
    cert_path = get_ca_cert_path()
    abs_path_escaped = cert_path.replace("\\", "\\\\")

    return {
        "windows_powershell": f'certutil -addstore -f "Root" "{cert_filename}"',
        "windows_cmd": f'certutil -addstore -f "Root" {cert_filename}',
        "linux_debian": f'sudo cp {cert_filename} /usr/local/share/ca-certificates/{cert_filename} && sudo update-ca-certificates',
        "linux_rhel": f'sudo cp {cert_filename} /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust',
        "macos": f'sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert_filename}',
        "python_env": f'export SSL_CERT_FILE="{cert_path}"\nexport REQUESTS_CA_BUNDLE="{cert_path}"',
        "node_env": f'export NODE_EXTRA_CA_CERTS="{cert_path}"',
        "curl_env": f'export CURL_CA_BUNDLE="{cert_path}"'
    }


__all__ = ["get_ca_dir", "get_ca_cert_path", "init_ca", "get_ca_pem_bytes", "get_ca_metadata", "get_os_trust_scripts"]
