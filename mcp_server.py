"""
Proxynth MCP - Autonomous Security Testing Gateway & Interception Platform
Version: 0.1.0-beta
Model Context Protocol (MCP) Server Entrypoint (Stdio & SSE Transport)

Modularized architecture delegating to mcp_core package.
Maintains 100% backward compatibility for OpenCode, CLI runners, and test suites.
"""

__version__ = "0.1.0-beta"

import os
import sys
import types
from typing import Optional, Dict, Any, List

# Ensure current directory is on pythonpath
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from mcp_core import build_mcp, build_and_run, mcp
import mcp_core.gateway as gateway
from mcp_core.gateway import (
    DEFAULT_PROJECT,
    BACKEND_URL,
    get_backend_url,
    _resolve_project,
    _persist_and_stream_log,
    _persist_and_stream_command,
    _persist_and_stream_payload,
    _extract_domain_cookies
)
from mcp_core.tool_meta import TOOL_PERMS, TOOL_HARNESS_METADATA

# Re-export all 83 modular tool functions
from mcp_core.tools.context import *
from mcp_core.tools.traffic import *
from mcp_core.tools.browser import *
from mcp_core.tools.vault import *
from mcp_core.tools.injection import *
from mcp_core.tools.authz import *
from mcp_core.tools.api import *
from mcp_core.tools.network import *
from mcp_core.tools.oast import *
from mcp_core.tools.intercept import *
from mcp_core.tools.agenda import *
from mcp_core.tools.autonomous import *
from mcp_core.tools.session import *
from mcp_core.tools.report import *
from mcp_core.tools.audit_new import *


class _ProxynthMcpModule(types.ModuleType):
    """Dynamic proxy preserving mutable module-level state (_active_project, _active_write_project)."""
    @property
    def _active_project(self) -> Optional[str]:
        return gateway._active_project

    @_active_project.setter
    def _active_project(self, value: Optional[str]):
        gateway._active_project = value

    @property
    def _active_write_project(self) -> Optional[str]:
        return gateway._active_write_project

    @_active_write_project.setter
    def _active_write_project(self, value: Optional[str]):
        gateway._active_write_project = value


sys.modules[__name__].__class__ = _ProxynthMcpModule


if __name__ == "__main__":
    build_and_run()
