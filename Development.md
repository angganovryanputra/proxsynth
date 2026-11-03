# 🛠️ PROXSYNTH DEVELOPMENT & ARCHITECTURE GUIDE

This document serves as the technical developer guide, architecture reference, and contribution protocol for **Proxsynth** (`v0.3.0-beta`).

---

## 1. System Architecture Overview

Proxsynth operates as two cooperating processes communicating over a shared SQLite database in WAL mode (`proxsynth.db`):

```text
 ┌─────────────────────────────────────────────────────────────┐
 │                FastAPI Backend (Port :8000)                 │
 │  - REST API & Endpoints (Swagger /docs, OpenAPI)            │
 │  - WebSocket Broadcaster (/ws, /ws/terminal)                │
 │  - Modern Cyberpunk SOC Dashboard (frontend/index.html)     │
 │  - Integrated Background Daemons:                           │
 │    * Forward MITM Proxy (:8088, backend/forward_proxy.py)   │
 │    * OAST DNS Server (:5353 UDP, backend/dns_server.py)     │
 │    * OAST LDAP Server (:1390 TCP, backend/ldap_server.py)   │
 │    * Workspace Watchdog & Snooper (backend/script_snooper.py)│
 └──────────────────────────────┬──────────────────────────────┘
                                │
                         SQLite (WAL Mode)
                                │
 ┌──────────────────────────────┴──────────────────────────────┐
 │                FastMCP Server (mcp_server.py)               │
 │  - JSON-RPC over Stdio (Claude Code, Cursor, Windsurf, AGY) │
 │  - Core package: mcp_core/                                  │
 │  - Tri-Tier Tool Mode (PROXSYNTH_TOOL_MODE):                │
 │    * hexagon: 6 Intent-Driven Super-Tools (~95% token cut)  │
 │    * power  : 18 Consolidated Meta-Tools (~82.7% token cut) │
 │    * full   : 104 Granular Modular Pentest Tools            │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Directory Layout

```text
proxsynth/
├── backend/                  # FastAPI web server, audit engines, proxy pipeline
│   ├── app.py                # Main FastAPI application, REST routes & WebSocket
│   ├── database.py           # SQLAlchemy database schema, models, and connection pools
│   ├── forward_proxy.py      # Async HTTP/HTTPS TLS-MITM forward proxy (:8088)
│   ├── cognitive_hexagon.py  # Autonomous Cognitive Pentest Hexagon engine
│   ├── access_control_orchestrator.py # Two-Tier Access Control (BOLA/BFLA/IDOR)
│   ├── fuzzer.py             # Multi-threaded parameter fuzzer with abort controller
│   ├── intercept_manager.py  # Request intercept trap & scope guardrail evaluation
│   ├── target_manager.py     # Target Knowledge Graph, passive tech fingerprinting
│   ├── oast_engine.py        # Out-of-Band event correlation & HMAC webhook dispatch
│   └── ...
├── frontend/                 # Single-page modern responsive SOC interface
│   ├── index.html            # Main dashboard (Tailwind CSS + Alpine.js + Lucide)
│   ├── static/               # CSS, JS modules (attack_surface.js, oast.js, etc.)
│   └── ...
├── mcp_core/                 # Modular FastMCP 2.0+ tool framework
│   ├── server.py             # FastMCP application instance
│   ├── gateway.py            # Backend dispatcher, WebSocket sync, SQLite fallback
│   ├── tool_meta.py          # Master single-source-of-truth permissions matrix
│   └── tools/                # Categorized tool implementations
├── mcp_server.py             # Stdio entrypoint for MCP agents (Backward-compat shim)
├── sitecustomize.py          # Transparent subprocess proxy hook (:8088 auto-chain)
├── requirements.txt          # Python runtime dependencies
└── ...
```

---

## 3. Development Setup

### Prerequisites
- Python 3.10+ (Recommended: Python 3.11 / 3.12)
- Git
- OpenSSL (for local MITM CA generation)

### Installation
```powershell
# 1. Clone repository
git clone https://github.com/your-org/proxsynth.git
cd proxsynth

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate   # On Windows
source venv/bin/activate  # On Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt
playwright install chromium
```

### Running the Services
```powershell
# Launch FastAPI Backend + Forward Proxy + OAST Listeners:
python -m backend.app

# In a separate terminal, test the FastMCP Server:
python mcp_server.py
```

---

## 4. Architectural Conventions & Standards

### A. API Error Handling (RFC 7807)
All REST API endpoints in [`backend/app.py`](file:///d:/0x13%20PROJECT/Proxsynth/backend/app.py) return standardized error envelopes:
```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Target endpoint /api/v1/user was not found",
    "details": null
  },
  "detail": "Target endpoint /api/v1/user was not found"
}
```
*Note: The root-level `.detail` key is maintained for 100% backward compatibility with standard FastAPI/Starlette client libraries.*

### B. Idempotency-Key Guard
Mutation endpoints (e.g. `POST /api/campaign/run`, `POST /api/fuzzer/run`) MUST support the `Idempotency-Key` header:
- Validates payload hash against active runs.
- Returns `409 Conflict` if the same key is currently being executed.
- Returns `422 Unprocessable` if the same key is reused with mismatched payloads.
- Caches and returns successful results on subsequent identical calls.

### C. Resource Cleanup (Memory Leaks)
All long-running or background tasks (such as active fuzzer runs or asynchronous crawls) that register keys in memory registries MUST be wrapped in `try ... finally` blocks to ensure unconditional deregistration:
```python
job_key = f"{project}_{int(time.time() * 1000)}"
abort_event = register_fuzzer_job(job_key)
try:
    await worker(...)
finally:
    unregister_fuzzer_job(job_key)
```

---

## 5. Testing Framework & Protocols

Proxsynth utilizes standalone test suites designed for zero external test runner friction:

| Test Suite | Purpose |
| :--- | :--- |
| `test_suite_all.py` | Full end-to-end integration test across Static Serving, Target Graph, OAST, WebSocket, and REST endpoints. |
| `test_cognitive_hexagon.py` | TDD suite for all 6 Cognitive Hexagon facets, token reduction, and auto-decision routing. |
| `test_review_fixes.py` | Verifies dangerous route guardrails, idempotency lifecycle, and fuzzer job registry cleanup. |
| `scripts/self_test.py` | Validates MCP tool counts (104 tools), ToolAnnotations, schema completeness, and project isolation. |

To run the full suite:
```powershell
.\venv\Scripts\python.exe test_suite_all.py
.\venv\Scripts\python.exe -m unittest test_review_fixes.py
```

---

## 6. Git & Branching Strategy

- `main`: Production-ready, fully tested codebase.
- `feat/*`: Feature branches for enhancements, architectural refactorings, and MCP expansions.
- Commits follow Conventional Commits standard (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`).
