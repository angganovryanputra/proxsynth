"""
PROXSYNTH MCP - Automated Agent Configuration & Installer Helper
Generates dynamic, cross-platform MCP client configurations for:
- OpenCode (opencode.json / ~/.opencode/mcp.json)
- Claude Code & Claude Desktop (claude_desktop_config.json / ~/.claude/mcp.json)
- Cursor (.cursor/mcp.json)
- Windsurf (~/.codeium/windsurf/mcp_config.json)
- Antigravity (~/.gemini/antigravity/mcp_config.json)
- Generic FastMCP clients (mcp_config.json)
"""

import os
import sys
import json
import argparse
from typing import Dict, Any, Optional

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_venv_python() -> str:
    """Resolves absolute path to virtual environment Python executable."""
    if os.name == "nt":
        venv_py = os.path.join(REPO_DIR, "venv", "Scripts", "python.exe")
    else:
        venv_py = os.path.join(REPO_DIR, "venv", "bin", "python3")
        if not os.path.isfile(venv_py):
            venv_py = os.path.join(REPO_DIR, "venv", "bin", "python")

    if os.path.isfile(venv_py):
        return os.path.abspath(venv_py)
    return sys.executable


def get_mcp_server_script() -> str:
    """Resolves absolute path to mcp_server.py."""
    return os.path.abspath(os.path.join(REPO_DIR, "mcp_server.py"))


def build_mcp_config(tool_mode: str = "full", project: str = "default") -> Dict[str, Any]:
    """Generates standard MCP client config dictionary with forward slashes for cross-platform compatibility."""
    py_exec = get_venv_python().replace("\\", "/")
    server_script = get_mcp_server_script().replace("\\", "/")

    env_vars = {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": project,
        "PYTHONIOENCODING": "utf-8"
    }

    if tool_mode.lower() == "power":
        env_vars["PROXSYNTH_TOOL_MODE"] = "power"

    return {
        "mcpServers": {
            "proxsynth": {
                "command": py_exec,
                "args": [server_script],
                "env": env_vars
            }
        }
    }


def build_opencode_config(tool_mode: str = "full", project: str = "default") -> Dict[str, Any]:
    """Generates OpenCode specific configuration dictionary."""
    cfg = build_mcp_config(tool_mode=tool_mode, project=project)
    server_entry = cfg["mcpServers"]["proxsynth"]
    return {
        "mcp": {
            "servers": {
                "proxsynth": server_entry
            }
        },
        # Also include standard mcpServers key for universal compatibility
        "mcpServers": {
            "proxsynth": server_entry
        }
    }


def get_agent_config_paths() -> Dict[str, str]:
    """Resolves standard configuration file paths for common AI agents."""
    home = os.path.expanduser("~")
    appdata = os.getenv("APPDATA", os.path.join(home, "AppData", "Roaming"))

    paths = {
        "repo_mcp": os.path.join(REPO_DIR, "mcp_config.json"),
        "repo_opencode": os.path.join(REPO_DIR, "opencode.json"),
        "opencode_user": os.path.join(home, ".opencode", "mcp.json"),
        "claude_code": os.path.join(home, ".claude", "mcp.json"),
        "cursor_user": os.path.join(home, ".cursor", "mcp.json"),
        "windsurf_user": os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
        "antigravity_user": os.path.join(home, ".gemini", "antigravity", "mcp_config.json"),
    }

    if os.name == "nt":
        paths["claude_desktop"] = os.path.join(appdata, "Claude", "claude_desktop_config.json")
    elif sys.platform == "darwin":
        paths["claude_desktop"] = os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    else:
        paths["claude_desktop"] = os.path.join(home, ".config", "Claude", "claude_desktop_config.json")

    return paths


def merge_mcp_config(target_file: str, new_config: Dict[str, Any]) -> bool:
    """Safely merges Proxsynth configuration into an existing JSON file without overwriting other servers."""
    existing_data: Dict[str, Any] = {}
    if os.path.isfile(target_file):
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except Exception:
            existing_data = {}

    # Handle standard "mcpServers"
    if "mcpServers" in new_config:
        if "mcpServers" not in existing_data or not isinstance(existing_data["mcpServers"], dict):
            existing_data["mcpServers"] = {}
        existing_data["mcpServers"]["proxsynth"] = new_config["mcpServers"]["proxsynth"]

    # Handle OpenCode "mcp.servers"
    if "mcp" in new_config and isinstance(new_config["mcp"], dict):
        if "mcp" not in existing_data or not isinstance(existing_data["mcp"], dict):
            existing_data["mcp"] = {}
        if "servers" not in existing_data["mcp"] or not isinstance(existing_data["mcp"]["servers"], dict):
            existing_data["mcp"]["servers"] = {}
        existing_data["mcp"]["servers"]["proxsynth"] = new_config["mcp"]["servers"]["proxsynth"]

    os.makedirs(os.path.dirname(os.path.abspath(target_file)), exist_ok=True)
    with open(target_file, "w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=2)
    return True


def main():
    parser = argparse.ArgumentParser(description="Proxsynth Automated Agent MCP Configurator")
    parser.add_argument("--tool-mode", choices=["full", "power"], default="full", help="FastMCP registry mode (full=97 tools, power=11 tools)")
    parser.add_argument("--project", default="default", help="Default target project workspace")
    parser.add_argument("--install", choices=["all", "repo", "opencode", "claude", "cursor", "windsurf", "antigravity"], default="repo", help="Target agent config to install/update")
    parser.add_argument("--print", choices=["claude", "opencode"], help="Prints configuration JSON to stdout")

    args = parser.parse_args()

    mcp_cfg = build_mcp_config(tool_mode=args.tool_mode, project=args.project)
    opencode_cfg = build_opencode_config(tool_mode=args.tool_mode, project=args.project)

    if args.print == "opencode":
        print(json.dumps(opencode_cfg, indent=2))
        return
    elif args.print == "claude":
        print(json.dumps(mcp_cfg, indent=2))
        return

    # Always generate dynamic local repository files
    repo_mcp_file = os.path.join(REPO_DIR, "mcp_config.json")
    repo_opencode_file = os.path.join(REPO_DIR, "opencode.json")

    with open(repo_mcp_file, "w", encoding="utf-8") as f:
        json.dump(mcp_cfg, f, indent=2)
    print(f"[+] Generated repository MCP config: {repo_mcp_file}")

    with open(repo_opencode_file, "w", encoding="utf-8") as f:
        json.dump(opencode_cfg, f, indent=2)
    print(f"[+] Generated OpenCode config: {repo_opencode_file}")

    paths = get_agent_config_paths()

    if args.install in ("all", "opencode"):
        target = paths["opencode_user"]
        try:
            merge_mcp_config(target, opencode_cfg)
            print(f"[+] Installed Proxsynth into OpenCode user config: {target}")
        except Exception as ex:
            print(f"[-] Notice: Could not update OpenCode user config ({ex})")

    if args.install in ("all", "claude"):
        for k in ["claude_desktop", "claude_code"]:
            target = paths[k]
            try:
                merge_mcp_config(target, mcp_cfg)
                print(f"[+] Installed Proxsynth into Claude config: {target}")
            except Exception as ex:
                print(f"[-] Notice: Could not update {k} config ({ex})")

    if args.install in ("all", "cursor"):
        target = paths["cursor_user"]
        try:
            merge_mcp_config(target, mcp_cfg)
            print(f"[+] Installed Proxsynth into Cursor user config: {target}")
        except Exception as ex:
            print(f"[-] Notice: Could not update Cursor config ({ex})")

    if args.install in ("all", "windsurf"):
        target = paths["windsurf_user"]
        try:
            merge_mcp_config(target, mcp_cfg)
            print(f"[+] Installed Proxsynth into Windsurf user config: {target}")
        except Exception as ex:
            print(f"[-] Notice: Could not update Windsurf config ({ex})")

    if args.install in ("all", "antigravity"):
        target = paths["antigravity_user"]
        try:
            merge_mcp_config(target, mcp_cfg)
            print(f"[+] Installed Proxsynth into Antigravity user config: {target}")
        except Exception as ex:
            print(f"[-] Notice: Could not update Antigravity config ({ex})")

    print("\n[SUCCESS] Configuration completed. Proxsynth is ready for AI Agents.")


if __name__ == "__main__":
    main()
