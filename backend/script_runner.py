"""
PROXSYNTH — Script Materializer
Turns a stored `script_content` blob into an executable command by writing it to a
temp file and choosing the interpreter from the file extension. Shared by the
`/api/commands/execute` + `/api/commands/{id}/rerun` endpoints and the MCP
`run_pentest_command` / `proxsynth_execute` tools so re-running a captured script
behaves identically everywhere.
"""

import os
import re
import sys
import tempfile
from typing import Optional, Tuple

# Extension -> argv prefix that runs a file of that type. Python uses the running
# interpreter (the venv) so captured exploit deps resolve.
_INTERPRETERS = {
    ".py": [sys.executable or "python"],
    ".sh": ["bash"],
    ".js": ["node"],
    ".rb": ["ruby"],
    ".php": ["php"],
    ".pl": ["perl"],
    ".ps1": ["powershell", "-ExecutionPolicy", "Bypass", "-File"],
}

_FILE_IN_CMD = re.compile(r"([^\s'\"]+\.(?:py|sh|js|rb|php|pl|ps1))", re.IGNORECASE)


def _quote(path: str) -> str:
    return f'"{path}"' if (" " in path and not path.startswith('"')) else path


def infer_extension(script_content: str, original_command: str = "") -> str:
    """Pick a file extension for a script: prefer a filename in the original command,
    then a shebang, then light content sniffing, else default to .py."""
    m = _FILE_IN_CMD.search(original_command or "")
    if m:
        return os.path.splitext(m.group(1))[1].lower()

    head = (script_content or "").lstrip()[:200].lower()
    if head.startswith("#!"):
        if "python" in head:
            return ".py"
        if "bash" in head or "/sh" in head:
            return ".sh"
        if "node" in head:
            return ".js"
        if "ruby" in head:
            return ".rb"
        if "php" in head:
            return ".php"
        if "perl" in head:
            return ".pl"
    if "<?php" in head:
        return ".php"
    if "function " in head and ("console.log" in head or "require(" in head):
        return ".js"
    return ".py"


def is_marker_command(command: str) -> bool:
    """True when `command` is empty or a snooper/placeholder marker rather than a real
    shell command — i.e. the script_content is what should actually be executed."""
    c = (command or "").strip()
    return (not c) or c.startswith("#")


def materialize_script(
    script_content: str,
    original_command: str = "",
    work_dir: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """Write `script_content` to a temp file in `work_dir` and return
    (command_string_to_run, temp_path_to_cleanup). Caller removes the temp file after
    the subprocess finishes. Returns ("", None) if there is nothing to materialize."""
    content = (script_content or "")
    if not content.strip():
        return "", None

    ext = infer_extension(content, original_command)
    argv_prefix = _INTERPRETERS.get(ext, _INTERPRETERS[".py"])

    target_dir = work_dir if (work_dir and os.path.isdir(work_dir)) else tempfile.gettempdir()
    fd, path = tempfile.mkstemp(prefix="proxsynth_rerun_", suffix=ext, dir=target_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        return "", None

    command = " ".join(_quote(a) for a in argv_prefix) + " " + _quote(path)
    return command, path


def resolve_execution_command(
    command: str,
    script_content: Optional[str],
    work_dir: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """Decide what to actually run. If script_content is present and `command` is a
    marker/empty, materialize the script and run it; otherwise run `command` as given.
    Returns (effective_command, temp_path_or_None)."""
    if script_content and script_content.strip() and is_marker_command(command):
        cmd, tmp = materialize_script(script_content, command, work_dir)
        if cmd:
            return cmd, tmp
    return (command or "").strip(), None


def cleanup_temp(path: Optional[str]) -> None:
    if path:
        try:
            os.remove(path)
        except Exception:
            pass
