"""
Proxsynth CA Manager & Certificate Authority Orchestrator
Manages Root CA initialization, path resolution, and trust store hooks for TLS MITM proxying.
"""
import os
from typing import Tuple, Any
from backend.forward_proxy import get_ca_dir, get_ca_cert_path as _base_get_ca_cert_path, _ensure_ca

def init_ca() -> str:
    """
    Ensures Root CA key and certificate are generated on disk, returning certificate path.
    """
    _ensure_ca()
    return _base_get_ca_cert_path()

def get_ca_cert_path() -> str:
    """
    Returns path to the Root CA certificate, automatically generating it if not present.
    """
    _ensure_ca()
    return _base_get_ca_cert_path()

__all__ = ["get_ca_dir", "get_ca_cert_path", "init_ca"]
