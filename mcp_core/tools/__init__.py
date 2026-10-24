"""
Proxsynth MCP Tools Package
Aggregates and registers all modular FastMCP security tools.
"""

import mcp_core.tools.context
import mcp_core.tools.traffic
import mcp_core.tools.browser
import mcp_core.tools.vault
import mcp_core.tools.injection
import mcp_core.tools.authz
import mcp_core.tools.api
import mcp_core.tools.network
import mcp_core.tools.oast
import mcp_core.tools.intercept
import mcp_core.tools.agenda
import mcp_core.tools.autonomous
import mcp_core.tools.session
import mcp_core.tools.report
import mcp_core.tools.audit_new

__all__ = [
    "context",
    "traffic",
    "browser",
    "vault",
    "injection",
    "authz",
    "api",
    "network",
    "oast",
    "intercept",
    "agenda",
    "autonomous",
    "session",
    "report",
    "audit_new"
]
