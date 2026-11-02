# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Proxsynth (`v0.1.0-beta`) is an interception proxy and security-testing gateway purpose-built for **autonomous AI pentesting agents** that talk to it over the **Model Context Protocol (FastMCP)**. It exposes ~83 MCP tools (traffic inspection, TLS-MITM forward proxy, multi-protocol OAST, DOM/XSS verification, authz/injection/logic audit engines, an autonomous campaign orchestrator, and an agent "hypothesis ledger" working memory) backed by a FastAPI dashboard and a shared SQLite store. It is an authorized-testing tool; treat all target traffic it handles as scoped engagement data.

## Architecture (the big picture)

Two cooperating processes share one SQLite database (`proxsynth.db`, WAL mode):

1. **FastAPI backend** — `backend/app.py`, served by uvicorn on `:8000`. Provides the REST API, the WebSocket live-telemetry broadcaster, and the SOC web console (`frontend/`). On startup it also launches: the **TLS-MITM forward proxy** (`:8088`, `backend/forward_proxy.py` + `backend/ca_manager.py`), the **OAST listeners** (DNS `backend/dns_server.py`, LDAP `backend/ldap_server.py`, HTTP), the **session keeper** (`backend/session_keeper.py`), and the **background auto-updater** (`backend/update_manager.py`). See the `@app.on_event("startup")` block in `backend/app.py`.

2. **MCP server** — `mcp_server.py` (stdio JSON-RPC entrypoint), implemented in the **`mcp_core/`** package. AI agents connect here. The MCP layer does **not** own data: `mcp_core/gateway.py` dispatches each tool call to the FastAPI backend over HTTP and streams results onto the dashboard's WebSocket, with a **direct SQLite fallback** when the backend is down. So most tools work with or without the dashboard running, but the live UI only updates when `:8000` is up.

**`mcp_core/` layout:**
- `server.py` — builds the single `FastMCP("proxsynth")` instance; importing `mcp_core.tools` triggers the registration decorators.
- `envelope.py` — `register_tool` decorator (wraps each tool, attaches annotations/output schema).
- `tool_meta.py` — **single source of truth** for all tool permissions, categories, and MCP `ToolAnnotations` (`readOnlyHint`/`destructiveHint`). Add a tool's entry here when you add a tool.
- `gateway.py` — backend dispatch, project-scope resolution, WebSocket streaming, SQLite fallbacks.
- `tools/` — tool definitions grouped by domain (`traffic`, `browser`, `injection`, `authz`, `api`, `network`, `oast`, `intercept`, `agenda`, `autonomous`, `session`, `report`, `audit_new`, `vault`, `context`). Register a new tool with the `@proxsynth_tool(name=...)` decorator in the right module.

**`mcp_server.py` is a backward-compat shim:** it `from mcp_core.tools.* import *` and re-exports everything (plus `_active_project` state via a module-proxy class) so existing test suites and CLI runners that import from `mcp_server` keep working. When adding/renaming tools, change `mcp_core/`, not this file.

**Data model** — `backend/database.py` (SQLAlchemy). Key tables: `Project` (workspace isolation), `HttpLog`, `Finding`, `ActiveSession`, `CapturedPayload`, `TargetAsset`/`TargetService`/`TargetEndpoint` (attack surface), `OastEvent`, `TestingHypothesis` (agent working memory), `InterceptionRule`, `WebSocketFrameLog`, `AgentCommandLog`.

**Project scoping** — Every query/mutation resolves a workspace via `_resolve_project()` in `gateway.py`. Reads may use the global `"all"` view; **writes never target `"all"`** — they resolve to `_active_write_project`, the target host's tagged project (`TargetAsset`), an explicit `project=`, or `DEFAULT_PROJECT`. Preserve this read/write asymmetry when touching scoping logic.

### Naming gotcha — `proxsynth` vs `proxynth`
Legacy artifacts use the older spelling **`proxynth`** (`proxynth.db`, `.proxynth_ca/`, `proxynth_client.py`, `.proxynth_key`) alongside the current **`proxsynth`** spelling. Both certificate dirs and DBs may exist; `sitecustomize.py` deliberately probes both CA directory names. Don't "fix" one spelling to the other without checking what reads it — the current DB is `proxsynth.db`.

### Transparent proxy enforcement — `sitecustomize.py`
Python auto-runs `sitecustomize.py` on interpreter startup. This hook force-routes all agent subprocess HTTP(S) traffic (`requests`, `httpx`, `urllib`, `aiohttp`, curl, etc.) through the forward proxy on `:8088` and trusts the generated root CA — so agent-spawned scripts can't bypass scope. It is a no-op when `PROXSYNTH_DISABLE_AUTO_PROXY=1` or `PROXSYNTH_IS_PROXY=1` (the latter guards the proxy's own process against self-looping). Keep that guard intact in anything that runs inside the proxy process.

## Commands

Entry wrappers auto-create/populate `venv/` via the installer on first run. The venv Python is `venv/Scripts/python.exe` (Windows) or `venv/bin/python` (Linux/WSL).

```bash
# Install deps + venv + Playwright + CA  (pick one)
./install.sh            # Linux/WSL
install.ps1 / install.bat   # Windows
./run.sh install        # via runner

# Run the dashboard (FastAPI + proxy + OAST listeners) on :8000
./run.sh dashboard                      # Linux/WSL
.\run.ps1 dashboard                     # Windows (also: run.bat)
# equivalently: uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload

# Run the MCP server (stdio) — agents connect here
./run.sh mcp            # -> python mcp_server.py

# Run both (dashboard backgrounded, MCP in foreground)
./run.sh all
```

**MCP stdio rule:** in `mcp` mode nothing may be written to **stdout** — it carries the JSON-RPC protocol. Log to stderr only. The runners are already silent in this mode; preserve that.

### Tests
Tests are standalone scripts (not pytest) that assert via `FastAPI TestClient` and the MCP registry, each with a `__main__` block. They are **gitignored** (`test_*.py`, local-only). Run one directly:

```bash
venv/Scripts/python.exe test_suite_all.py          # full dashboard/API/WebSocket suite
venv/Scripts/python.exe scripts/self_test.py       # acceptance gate: ~83 tools, annotations, output schemas, scoping
bash scripts/self_test.sh                           # same gate, resolves the venv python for you
```

When adding a tool, `scripts/self_test.py` enforces the tool count and that every tool carries correct annotations (and read-only tools carry an `outputSchema`) — run it before claiming an MCP change is done.

## Configuration
Runtime config is environment-driven (see `.env`, loaded by the runners). Common vars: `PROXSYNTH_BACKEND_URL`, `PROXSYNTH_PROJECT` (default workspace), `PROXSYNTH_API_KEY`, `PROXSYNTH_ALLOWED_ORIGINS`, `PROXSYNTH_ALLOW_REMOTE`, `PROXSYNTH_MAX_BODY_SIZE`, `PROXSYNTH_PROXY_PORT`, `PROXSYNTH_DISABLE_AUTO_PROXY`. Several vars are read with both `PROXSYNTH_` and legacy `PROXYNTH_` prefixes. `mcp_config.json` is the sample MCP-client registration (points a client's `command`/`args` at this repo's venv python + `mcp_server.py`).

`AGENT_INSTRUCTIONS.md` and `README.md` are the authoritative functional specs (tool reference, the "4 pillars", campaign orchestration) — consult them for tool-level behavior.
