"""
PROXSYNTH — Workspace Script Snooper (Automated Pentest Script Watcher)
Monitors project workspaces for newly created or modified exploit/test scripts (.py, .sh, .js, .http),
extracts attack payloads via Deep AST, commits them to the Payload Vault, and broadcasts real-time telemetry.
Now features native OS Kernel Event monitoring via Watchdog with automatic polling fallback.
"""

import os
import sys
import time
import asyncio
import logging
from typing import Dict, Set, Optional, List, Any

from backend.database import SessionLocal, AgentCommandLog, CapturedPayload
from backend.payload_vault import auto_vault_script_payloads

logger = logging.getLogger("proxynth.script_snooper")

_is_running: bool = False
_snooper_task: Optional[asyncio.Task] = None
_kernel_watcher = None
_seen_files: Dict[str, float] = {}  # filepath -> mtime
_EXCLUDED_DIRS = {
    ".git", "venv", ".venv", "node_modules", "__pycache__",
    ".gemini", ".claude", ".omc", ".codegraph", "frontend"
}
_WATCH_EXTENSIONS = {".py", ".sh", ".js", ".http", ".php", ".rb"}


async def _safe_broadcast(payload: Dict[str, Any]) -> None:
    """Safely broadcasts telemetry event to connected WebSocket clients."""
    try:
        from backend.app import ws_manager
        await ws_manager.broadcast(payload)
    except Exception:
        pass


def _resolve_watch_dirs() -> Set[str]:
    """Resolves directories to actively monitor for pentest scripts."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    watch_dirs = {base_dir}

    for cand in ["scratch", "scripts", "exploits", "pocs"]:
        p = os.path.join(base_dir, cand)
        if os.path.isdir(p):
            watch_dirs.add(p)

    env_dir = os.getenv("PROXSYNTH_WATCH_DIR")
    if env_dir and os.path.isdir(env_dir):
        watch_dirs.add(os.path.abspath(env_dir))

    return watch_dirs


async def ingest_script_file(fpath: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Ingests a single script file, runs AST analysis to extract attack vectors,
    commits them to the Payload Vault, and emits real-time telemetry.
    """
    if not os.path.isfile(fpath):
        return None

    fname = os.path.basename(fpath)
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as ex:
        logger.debug(f"Could not read {fpath}: {ex}")
        return None

    if not content.strip():
        return None

    active_proj = (project or os.getenv("PROXSYNTH_PROJECT", "default")).strip().lower() or "default"

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

        payload_summary = [
            {"id": p.id, "vuln_type": p.vuln_type, "raw_payload": p.raw_payload}
            for p in vaulted
        ]

        # Broadcast real-time WebSocket event
        await _safe_broadcast({
            "type": "NEW_SCRIPT_CAPTURED",
            "project": active_proj,
            "filename": fname,
            "path": fpath,
            "command_id": cmd_entry.id,
            "payloads_vaulted": len(vaulted)
        })

        return {
            "status": "SUCCESS",
            "filename": fname,
            "path": fpath,
            "project": active_proj,
            "command_id": cmd_entry.id,
            "payloads_vaulted": len(vaulted),
            "vaulted_items": payload_summary
        }
    except Exception as ex:
        db.rollback()
        logger.warning(f"Error auto-ingesting {fname}: {ex}")
        return {"status": "ERROR", "error": str(ex)}
    finally:
        db.close()


def get_recent_vaulted_payloads(project: str = "default", limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent payloads vaulted from agent exploit scripts for an active project.
    Allows AI Agents to quickly retrieve and use freshly extracted payloads in fuzzing/testing tools.
    """
    clean_proj = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        q = db.query(CapturedPayload)
        if clean_proj != "all":
            q = q.filter(CapturedPayload.project == clean_proj)
        records = q.order_by(CapturedPayload.id.desc()).limit(min(limit, 50)).all()
        return [r.to_dict() for r in records]
    finally:
        db.close()


class WorkspaceKernelWatcher:
    """
    OS-level Kernel Event Watcher using watchdog to intercept
    script creation & modification events in real-time.
    """

    def __init__(self, watch_dirs: Optional[List[str]] = None, on_change_callback=None):
        self.watch_dirs = watch_dirs or list(_resolve_watch_dirs())
        self.on_change_callback = on_change_callback
        self.is_watchdog_available = False
        self.observer = None
        self._init_watchdog()

    def _init_watchdog(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            class _ScriptEventHandler(FileSystemEventHandler):
                def __init__(self, callback):
                    super().__init__()
                    self.callback = callback

                def on_created(self, event):
                    if not event.is_directory:
                        self._handle(event.src_path)

                def on_modified(self, event):
                    if not event.is_directory:
                        self._handle(event.src_path)

                def _handle(self, path):
                    norm_path = path.replace("\\", "/")
                    path_parts = set(norm_path.split("/"))
                    if any(ex in path_parts for ex in _EXCLUDED_DIRS):
                        return
                    _, ext = os.path.splitext(path)
                    if ext.lower() in _WATCH_EXTENSIONS:
                        if self.callback:
                            self.callback(path)

            self.observer = Observer()
            handler = _ScriptEventHandler(self.on_change_callback)
            for d in self.watch_dirs:
                if os.path.isdir(d):
                    self.observer.schedule(handler, d, recursive=True)
            self.observer.daemon = True
            self.observer.start()
            self.is_watchdog_available = True
            logger.info("WorkspaceKernelWatcher initialized with native watchdog engine.")
        except Exception as ex:
            self.is_watchdog_available = False
            logger.debug(f"Watchdog unavailable or error ({ex}); falling back to timer scanning.")

    def stop(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=1.0)
            except Exception:
                pass


async def _scan_and_ingest_scripts():
    """Fallback scanner for directories."""
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

                _seen_files[fpath] = mtime
                if prev_mtime is None and (time.time() - mtime > 600):
                    continue

                await ingest_script_file(fpath)


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
    global _snooper_task, _is_running, _kernel_watcher
    if _snooper_task and not _snooper_task.done():
        return
    _is_running = True

    try:
        main_loop = asyncio.get_running_loop()
    except RuntimeError:
        try:
            main_loop = asyncio.get_event_loop()
        except Exception:
            main_loop = None

    # Try starting native kernel event observer
    if _kernel_watcher is None:
        def _on_kernel_event(path):
            try:
                target_loop = main_loop
                if target_loop and target_loop.is_running():
                    asyncio.run_coroutine_threadsafe(ingest_script_file(path), target_loop)
            except Exception as e:
                logger.debug(f"Watchdog event dispatch error: {e}")
        _kernel_watcher = WorkspaceKernelWatcher(on_change_callback=_on_kernel_event)

    try:
        loop = main_loop or asyncio.get_event_loop()
        _snooper_task = loop.create_task(_snooper_loop())
    except Exception as ex:
        logger.warning(f"Failed to start script snooper: {ex}")


def stop_script_snooper():
    """Stops the workspace script snooper."""
    global _snooper_task, _is_running, _kernel_watcher
    _is_running = False
    if _kernel_watcher:
        _kernel_watcher.stop()
        _kernel_watcher = None
    if _snooper_task and not _snooper_task.done():
        _snooper_task.cancel()
    _snooper_task = None
