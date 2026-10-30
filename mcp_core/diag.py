"""
Proxsynth MCP - Diagnostics / debug logging.

All output goes to STDERR, never STDOUT: the MCP stdio transport reserves stdout
for the JSON-RPC protocol, so a stray print there corrupts the stream. Logging is
off unless PROXSYNTH_DEBUG is truthy, so production stdio sessions stay silent while
the ~swallowed exceptions across the backend become visible during development.

Usage:
    from mcp_core import diag
    diag.log("dashboard POST failed, using SQLite fallback")
    try: ...
    except Exception: diag.exc("persist_and_stream_log direct write")
"""

import os
import sys
import time
import traceback

_TRUTHY = {"1", "true", "yes", "on", "debug"}


def enabled() -> bool:
    """Read the env each call so it can be toggled without re-importing."""
    return os.getenv("PROXSYNTH_DEBUG", "").strip().lower() in _TRUTHY


def _emit(level: str, msg: str) -> None:
    if not enabled():
        return
    try:
        sys.stderr.write(f"[proxsynth {time.strftime('%H:%M:%S')} {level}] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


def log(msg: str) -> None:
    """Informational trace (e.g. a tool call or a fallback path)."""
    _emit("info", msg)


def warn(msg: str) -> None:
    _emit("warn", msg)


def exc(context: str) -> None:
    """Record the active exception with its traceback under a short context label."""
    if not enabled():
        return
    _emit("exc", f"{context}: {traceback.format_exc().strip()}")
