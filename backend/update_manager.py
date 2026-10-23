"""
Proxsynth - Autonomous System & MCP Server Auto-Update Manager
Handles semantic versioning, remote git/release update detection,
one-click zero-downtime codebase updating, and WebSocket live progress broadcasting.
"""

import os
import sys
import time
import asyncio
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

PROXSYNTH_VERSION = "2.5.0"
CURRENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_last_update_check: Optional[Dict[str, Any]] = None
_last_check_timestamp: float = 0.0
_CHECK_CACHE_TTL = 300.0  # 5 minutes


def _run_cmd(args: List[str], cwd: str = CURRENT_DIR, timeout: float = 10.0) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as ex:
        return -1, "", str(ex)


def get_current_commit() -> str:
    """Returns the current short git commit hash, or 'standalone' if git is unavailable."""
    code, out, _ = _run_cmd(["git", "rev-parse", "--short", "HEAD"], timeout=3.0)
    if code == 0 and out:
        return out
    return "standalone"


def get_current_branch() -> str:
    """Returns the active git branch name."""
    code, out, _ = _run_cmd(["git", "branch", "--show-current"], timeout=3.0)
    if code == 0 and out:
        return out
    return "main"


def get_system_version() -> Dict[str, Any]:
    """Returns full system metadata, release version, and active commit details."""
    commit = get_current_commit()
    branch = get_current_branch()
    
    code, last_commit_msg, _ = _run_cmd(["git", "log", "-1", "--format=%s"], timeout=3.0)
    code2, last_commit_date, _ = _run_cmd(["git", "log", "-1", "--format=%cd", "--date=relative"], timeout=3.0)

    return {
        "product": "Proxsynth",
        "name": "Proxsynth",
        "tagline": "Autonomous Security Testing Gateway & Interception Platform",
        "version": PROXSYNTH_VERSION,
        "commit": commit,
        "commit_sha": commit,
        "commit_message": last_commit_msg if code == 0 else "Proxsynth Release Build",
        "commit_date": last_commit_date if code2 == 0 else "recently",
        "branch": branch,
        "mcp_server": "proxsynth-fastmcp-v2",
        "python_version": sys.version.split()[0],
        "platform": sys.platform
    }


async def async_check_for_updates(force: bool = False) -> Dict[str, Any]:
    """
    Checks remote Git repository (or simulation mode) to determine if updates exist.
    Caches check results for 5 minutes unless force=True.
    """
    global _last_update_check, _last_check_timestamp
    now = time.time()

    if not force and _last_update_check is not None and (now - _last_check_timestamp) < _CHECK_CACHE_TTL:
        return _last_update_check

    current_commit = get_current_commit()
    branch = get_current_branch()
    sys_info = get_system_version()

    # Simulation check hook for operator UI demonstration
    simulated = os.getenv("PROXSYNTH_SIMULATE_UPDATE", "").strip().lower() in ("1", "true", "yes")
    if simulated:
        res = {
            "update_available": True,
            "current_version": PROXSYNTH_VERSION,
            "latest_version": "2.5.1",
            "current_commit": current_commit,
            "latest_commit": "a1b2c3d",
            "branch": branch,
            "commits_behind": 1,
            "changelog": [
                "feat(mcp): auto-capture script payloads and persistent distillation",
                "perf: high-speed async client session with auto-proxying",
                "sec: automated scope isolation guardrails"
            ],
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "simulated": True
        }
        _last_update_check = res
        _last_check_timestamp = now
        return res

    # Check Git remote tracking branch
    update_available = False
    commits_behind = 0
    changelog: List[str] = []
    latest_commit = current_commit

    try:
        # Run git fetch asynchronously with short timeout
        fetch_proc = await asyncio.create_subprocess_exec(
            "git", "fetch", "origin", branch, "--quiet",
            cwd=CURRENT_DIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            await asyncio.wait_for(fetch_proc.communicate(), timeout=6.0)
        except asyncio.TimeoutError:
            try:
                fetch_proc.kill()
            except Exception:
                pass

        # Check commit discrepancy
        rev_proc = await asyncio.create_subprocess_exec(
            "git", "rev-list", f"HEAD..origin/{branch}", "--count",
            cwd=CURRENT_DIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        out, _ = await asyncio.wait_for(rev_proc.communicate(), timeout=3.0)
        count_str = out.decode("utf-8", errors="replace").strip()
        if count_str.isdigit():
            commits_behind = int(count_str)
            update_available = commits_behind > 0

        if update_available:
            # Fetch latest commit hash
            hash_proc = await asyncio.create_subprocess_exec(
                "git", "rev-parse", "--short", f"origin/{branch}",
                cwd=CURRENT_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            hout, _ = await asyncio.wait_for(hash_proc.communicate(), timeout=3.0)
            latest_commit = hout.decode("utf-8", errors="replace").strip() or latest_commit

            # Get changelog summary
            log_proc = await asyncio.create_subprocess_exec(
                "git", "log", f"HEAD..origin/{branch}", "--oneline", "-n", "10",
                cwd=CURRENT_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            lout, _ = await asyncio.wait_for(log_proc.communicate(), timeout=3.0)
            log_lines = lout.decode("utf-8", errors="replace").strip().splitlines()
            changelog = [line.strip() for line in log_lines if line.strip()]

    except Exception as ex:
        # If git is not installed or network is offline, report clean up-to-date status
        pass

    res = {
        "product": "Proxsynth",
        "update_available": update_available,
        "current_version": PROXSYNTH_VERSION,
        "latest_version": f"{PROXSYNTH_VERSION}-patch" if update_available else PROXSYNTH_VERSION,
        "remote_version": f"{PROXSYNTH_VERSION}-patch" if update_available else PROXSYNTH_VERSION,
        "current_commit": current_commit,
        "current_commit_sha": current_commit,
        "latest_commit": latest_commit,
        "latest_remote_sha": latest_commit,
        "branch": branch,
        "commits_behind": commits_behind,
        "behind_by": commits_behind,
        "changelog": changelog,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "simulated": False
    }

    _last_update_check = res
    _last_check_timestamp = now
    return res


async def async_perform_system_update(ws_manager=None) -> Dict[str, Any]:
    """
    Executes automated Git pull, dependency synchronization, and system reload.
    Broadcasts real-time progress events over WebSocket if ws_manager is provided.
    """
    logs: List[str] = []

    async def _emit(step: str, message: str, status: str = "IN_PROGRESS"):
        logs.append(f"[{step}] {message}")
        if ws_manager:
            try:
                await ws_manager.broadcast({
                    "type": "SYSTEM_UPDATE_PROGRESS",
                    "step": step,
                    "status": status,
                    "message": message,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            except Exception:
                pass

    await _emit("INIT", "Starting Proxsynth system & MCP server auto-update...")

    branch = get_current_branch()

    # 1. Pull latest code from remote Git repository
    await _emit("GIT_PULL", f"Pulling latest commits from origin/{branch}...")
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "pull", "--ff-only", "origin", branch,
            cwd=CURRENT_DIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=25.0)
        out_text = out.decode("utf-8", errors="replace").strip()
        err_text = err.decode("utf-8", errors="replace").strip()
        
        if proc.returncode != 0:
            # Fallback to general git pull if ff-only is not possible
            proc2 = await asyncio.create_subprocess_exec(
                "git", "pull", "origin", branch,
                cwd=CURRENT_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            out2, err2 = await asyncio.wait_for(proc2.communicate(), timeout=25.0)
            if proc2.returncode != 0:
                err_msg = err2.decode("utf-8", errors="replace").strip() or err_text
                await _emit("GIT_PULL", f"Git pull failed: {err_msg}", status="FAILED")
                return {
                    "success": False,
                    "message": f"Git pull failed: {err_msg}",
                    "logs": logs
                }
            out_text = out2.decode("utf-8", errors="replace").strip()

        await _emit("GIT_PULL", f"Git pull completed successfully: {out_text[:120]}", status="SUCCESS")
    except Exception as ex:
        await _emit("GIT_PULL", f"Subprocess exception during git pull: {str(ex)}", status="FAILED")
        return {
            "success": False,
            "message": f"Git pull exception: {str(ex)}",
            "logs": logs
        }

    # 2. Check and sync python dependencies if requirements.txt exists
    req_file = os.path.join(CURRENT_DIR, "requirements.txt")
    if os.path.isfile(req_file):
        await _emit("DEPENDENCIES", "Verifying and synchronizing Python dependencies...")
        try:
            python_bin = sys.executable
            pip_proc = await asyncio.create_subprocess_exec(
                python_bin, "-m", "pip", "install", "-r", "requirements.txt", "--quiet",
                cwd=CURRENT_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            p_out, p_err = await asyncio.wait_for(pip_proc.communicate(), timeout=60.0)
            if pip_proc.returncode == 0:
                await _emit("DEPENDENCIES", "Dependencies verified and updated successfully.", status="SUCCESS")
            else:
                await _emit("DEPENDENCIES", f"Dependency sync warning: {p_err.decode()[:100]}", status="WARNING")
        except Exception as ex:
            await _emit("DEPENDENCIES", f"Skipping pip sync: {str(ex)}", status="WARNING")

    # 3. Reload version cache and finalize
    new_commit = get_current_commit()
    global _last_update_check, _last_check_timestamp
    _last_update_check = None
    _last_check_timestamp = 0.0

    final_msg = f"Proxsynth & MCP Server successfully updated to commit #{new_commit}!"
    await _emit("COMPLETE", final_msg, status="SUCCESS")

    if ws_manager:
        try:
            await ws_manager.broadcast({
                "type": "SYSTEM_UPDATE_COMPLETE",
                "status": "SUCCESS",
                "new_commit": new_commit,
                "version": PROXSYNTH_VERSION,
                "message": final_msg
            })
        except Exception:
            pass

    return {
        "success": True,
        "message": final_msg,
        "new_commit": new_commit,
        "version": PROXSYNTH_VERSION,
        "logs": logs
    }


_updater_task: Optional[asyncio.Task] = None


async def _auto_update_loop(interval_seconds: float = 300.0, ws_manager=None):
    """
    Background worker that runs if PROXSYNTH_AUTO_UPDATE is enabled.
    Checks remote git repository and automatically pulls new commits without operator interaction.
    """
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            chk = await async_check_for_updates(force=True)
            if chk.get("update_available"):
                await async_perform_system_update(ws_manager=ws_manager)
        except asyncio.CancelledError:
            break
        except Exception:
            pass


def start_background_updater(interval_seconds: float = 300.0, ws_manager=None):
    """Initializes automated background polling if PROXSYNTH_AUTO_UPDATE=true."""
    global _updater_task
    auto_enabled = os.getenv("PROXSYNTH_AUTO_UPDATE", "").strip().lower() in ("1", "true", "yes")
    if auto_enabled and (_updater_task is None or _updater_task.done()):
        try:
            loop = asyncio.get_event_loop()
            _updater_task = loop.create_task(_auto_update_loop(interval_seconds, ws_manager))
        except Exception:
            pass


def stop_background_updater():
    """Cancels running background update worker."""
    global _updater_task
    if _updater_task and not _updater_task.done():
        _updater_task.cancel()
        _updater_task = None

