"""
PROXSYNTH MCP - Automated Agent Configuration & Installer Helper
Generates dynamic, cross-platform MCP client configurations for:
- OpenCode (opencode.json / ~/.opencode/mcp.json)
- Claude Code CLI (~/.claude.json) & Claude Desktop (claude_desktop_config.json)
- Cursor (.cursor/mcp.json & ~/.cursor/mcp.json)
- Windsurf (~/.codeium/windsurf/mcp_config.json)
- Antigravity (~/.gemini/antigravity/mcp_config.json)
- Generic FastMCP clients (mcp_config.json)
"""

import os
import sys
import json
import shutil
import argparse
from typing import Dict, Any, List

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
    """Generates OpenCode specific configuration dictionary supporting dual schemas."""
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


def get_agent_config_paths() -> Dict[str, Any]:
    """Resolves standard configuration file paths for common AI agents."""
    home = os.path.expanduser("~")
    appdata = os.getenv("APPDATA", os.path.join(home, "AppData", "Roaming"))
    config_home = os.getenv("XDG_CONFIG_HOME", os.path.join(home, ".config"))

    paths: Dict[str, Any] = {
        "repo_mcp": os.path.join(REPO_DIR, "mcp_config.json"),
        "repo_opencode": os.path.join(REPO_DIR, "opencode.json"),
        "repo_cursor": os.path.join(REPO_DIR, ".cursor", "mcp.json"),
        "opencode_user": [
            os.path.join(home, ".opencode", "mcp.json"),
            os.path.join(config_home, "opencode", "opencode.json"),
            os.path.join(appdata, "opencode", "opencode.json"),
        ],
        "claude_code": [
            os.path.join(home, ".claude.json"),
            os.path.join(home, ".claude", "mcp.json"),
        ],
        "cursor_user": os.path.join(home, ".cursor", "mcp.json"),
        "windsurf_user": os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
        "antigravity_user": os.path.join(home, ".gemini", "antigravity", "mcp_config.json"),
    }

    if os.name == "nt":
        paths["claude_desktop"] = os.path.join(appdata, "Claude", "claude_desktop_config.json")
    elif sys.platform == "darwin":
        paths["claude_desktop"] = os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    else:
        paths["claude_desktop"] = os.path.join(config_home, "Claude", "claude_desktop_config.json")

    return paths


def merge_mcp_config(target_file: str, new_config: Dict[str, Any]) -> bool:
    """Safely merges Proxsynth configuration into an existing JSON file without overwriting other servers."""
    existing_data: Dict[str, Any] = {}
    if os.path.isfile(target_file):
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    existing_data = loaded
                else:
                    print(f"[-] Warning: {target_file} root is not a dictionary; resetting to blank.")
                    existing_data = {}
        except Exception as e:
            bak_file = target_file + ".bak"
            try:
                shutil.copyfile(target_file, bak_file)
                print(f"[!] Warning: Could not parse {target_file} ({e}). Backed up original to {bak_file}")
            except Exception:
                pass
            existing_data = {}

    if not isinstance(existing_data, dict):
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


def apply_config_to_targets(targets: Any, config: Dict[str, Any], agent_name: str) -> None:
    """Helper to apply configuration to a target path or list of candidate paths."""
    if isinstance(targets, str):
        target_list = [targets]
    elif isinstance(targets, list):
        target_list = targets
    else:
        return

    # If any existing target file is found, update it. Otherwise update the primary target.
    found_existing = False
    for target in target_list:
        if os.path.isfile(target):
            try:
                merge_mcp_config(target, config)
                print(f"[+] Installed Proxsynth into {agent_name} config: {target}")
                found_existing = True
            except Exception as ex:
                print(f"[-] Notice: Could not update {agent_name} ({target}): {ex}")

    if not found_existing and target_list:
        primary_target = target_list[0]
        try:
            merge_mcp_config(primary_target, config)
            print(f"[+] Installed Proxsynth into {agent_name} config: {primary_target}")
        except Exception as ex:
            print(f"[-] Notice: Could not create {agent_name} ({primary_target}): {ex}")


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

    # 1. Always generate dynamic local repository files (mcp_config.json, opencode.json, .cursor/mcp.json)
    repo_mcp_file = os.path.join(REPO_DIR, "mcp_config.json")
    repo_opencode_file = os.path.join(REPO_DIR, "opencode.json")
    repo_cursor_file = os.path.join(REPO_DIR, ".cursor", "mcp.json")

    with open(repo_mcp_file, "w", encoding="utf-8") as f:
        json.dump(mcp_cfg, f, indent=2)
    print(f"[+] Generated repository MCP config: {repo_mcp_file}")

    with open(repo_opencode_file, "w", encoding="utf-8") as f:
        json.dump(opencode_cfg, f, indent=2)
    print(f"[+] Generated OpenCode config: {repo_opencode_file}")

    os.makedirs(os.path.dirname(repo_cursor_file), exist_ok=True)
    with open(repo_cursor_file, "w", encoding="utf-8") as f:
        json.dump(mcp_cfg, f, indent=2)
    print(f"[+] Generated Workspace Cursor config: {repo_cursor_file}")

    paths = get_agent_config_paths()

    if args.install in ("all", "opencode"):
        apply_config_to_targets(paths["opencode_user"], opencode_cfg, "OpenCode")

    if args.install in ("all", "claude"):
        if "claude_desktop" in paths:
            apply_config_to_targets(paths["claude_desktop"], mcp_cfg, "Claude Desktop")
        apply_config_to_targets(paths["claude_code"], mcp_cfg, "Claude Code")

    if args.install in ("all", "cursor"):
        apply_config_to_targets(paths["cursor_user"], mcp_cfg, "Cursor")

    if args.install in ("all", "windsurf"):
        apply_config_to_targets(paths["windsurf_user"], mcp_cfg, "Windsurf")

    if args.install in ("all", "antigravity"):
        apply_config_to_targets(paths["antigravity_user"], mcp_cfg, "Antigravity")

    print("\n[SUCCESS] Configuration completed. Proxsynth is ready for AI Agents.")


if __name__ == "__main__":
    main()
