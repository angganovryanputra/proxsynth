"""
PROXSYNTH — Workspace Script Snooper (Automated Pentest Script Watcher)
Monitors project workspaces for newly created or modified exploit/test scripts (.py, .sh, .js, .http),
extracts attack payloads via Deep AST, commits them to the Payload Vault, and broadcasts real-time telemetry.
"""

import os
import sys
import time
import asyncio
import logging
from typing import Dict, Set, Optional

from backend.database import SessionLocal, AgentCommandLog
from backend.payload_vault import auto_vault_script_payloads
from backend.ws_manager import ws_manager

logger = logging.getLogger("proxynth.script_snooper")

_is_running: bool = False
_snooper_task: Optional[asyncio.Task] = None
_seen_files: Dict[str, float] = {}  # filepath -> mtime
_EXCLUDED_DIRS = {
    ".git", "venv", ".venv", "node_modules", "__pycache__",
    ".gemini", ".claude", ".omc", ".codegraph", "frontend"
}
_WATCH_EXTENSIONS = {".py", ".sh", ".js", ".http", ".php", ".rb"}


def _resolve_watch_dirs() -> Set[str]:
    """Resolves directories to actively monitor for pentest scripts."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    watch_dirs = {base_dir}

    # Include scratch / scripts directories if present
    for cand in ["scratch", "scripts", "exploits", "pocs"]:
        p = os.path.join(base_dir, cand)
        if os.path.isdir(p):
            watch_dirs.add(p)

    env_dir = os.getenv("PROXSYNTH_WATCH_DIR")
    if env_dir and os.path.isdir(env_dir):
        watch_dirs.add(os.path.abspath(env_dir))

    return watch_dirs


async def _scan_and_ingest_scripts():
    """Scans directories and ingests newly authored or modified pentest scripts."""
    watch_dirs = _resolve_watch_dirs()
    for root_dir in watch_dirs:
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
            for fname in files:
                _, ext = os.path.splitext(fname)
                if ext.lower() not in _WATCH_EXTENSIONS:
                    continue

                fpath = os.path.join(root, fname)
                try:
                    stat = os.stat(fpath)
                    mtime = stat.st_mtime
                    size = stat.st_size
                except OSError:
                    continue

                if size <= 0 or size > 524288:  # Skip empty or >512KB
                    continue

                prev_mtime = _seen_files.get(fpath)
                if prev_mtime is not None and prev_mtime >= mtime:
                    continue

                # File is new or modified!
                _seen_files[fpath] = mtime
                if prev_mtime is None and (time.time() - mtime > 600):
                    # Skip old historical files on first startup
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception:
                    continue

                if not content.strip():
                    continue

                # Auto-vault payloads into active project workspace
                from mcp_core.gateway import _resolve_project
                try:
                    active_proj = _resolve_project(None, allow_all=False)
                except Exception:
                    active_proj = os.getenv("PROXSYNTH_PROJECT", "default").strip().lower() or "default"

                db = SessionLocal()
                try:
                    vaulted = auto_vault_script_payloads(
                        db=db,
                        project=active_proj,
                        agent_id="script_snooper",
                        script_content=content,
                        command=f"# SNOOPER CAPTURE: {fname}"
                    )

                    cmd_entry = AgentCommandLog(
                        project=active_proj,
                        agent_id="script_snooper",
                        command=f"# SNOOPED: {fname}",
                        tool_name="script_snooper",
                        reasoning=f"Auto-captured script {fname} from workspace watcher into {active_proj}",
                        exit_code=0,
                        stdout=f"Detected {len(content.splitlines())} lines. Vaulted {len(vaulted)} payloads.",
                        stderr="",
                        duration_ms=0,
                        status="SCRIPT_STAGED",
                        script_content=content
                    )
                    db.add(cmd_entry)
                    db.commit()
                    db.refresh(cmd_entry)

                    # Broadcast real-time WebSocket event
                    await ws_manager.broadcast({
                        "type": "NEW_SCRIPT_CAPTURED",
                        "project": active_proj,
                        "filename": fname,
                        "path": fpath,
                        "command_id": cmd_entry.id,
                        "payloads_vaulted": len(vaulted)
                    })
                except Exception as ex:
                    db.rollback()
                    logger.warning(f"Error auto-ingesting {fname}: {ex}")
                finally:
                    db.close()


async def _snooper_loop():
    """Background loop polling workspace for script modifications."""
    global _is_running
    _is_running = True
    try:
        while _is_running:
            await _scan_and_ingest_scripts()
            for _ in range(5):  # Check every 5 seconds
                if not _is_running:
                    break
                await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass


def start_script_snooper():
    """Starts the background workspace script snooper."""
    global _snooper_task, _is_running
    if _snooper_task and not _snooper_task.done():
        return
    _is_running = True
    try:
        loop = asyncio.get_event_loop()
        _snooper_task = loop.create_task(_snooper_loop())
    except Exception as ex:
        logger.warning(f"Failed to start script snooper: {ex}")


def stop_script_snooper():
    """Stops the workspace script snooper."""
    global _snooper_task, _is_running
    _is_running = False
    if _snooper_task and not _snooper_task.done():
        _snooper_task.cancel()
    _snooper_task = None

