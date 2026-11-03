# ⚡ PROXSYNTH: Autonomous AI Security Interception Proxy & Cognitive Bug Bounty Gateway

> **An Agent-First HTTP/HTTPS Interception Proxy, FastMCP Security Testing Gateway, and Autonomous Bug Bounty Engine.**  
> Engineered specifically for Autonomous AI Pentesting Agents (*Claude Code*, *Cursor*, *Windsurf*, *OpenCode*, *Hermes*, and *Antigravity*) communicating via the **Model Context Protocol (FastMCP 2.0+)**.

[![Release](https://img.shields.io/badge/Release-v0.3.0--beta-orange.svg)](#-overview)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Cognitive Hexagon](https://img.shields.io/badge/Cognitive%20Hexagon-6%20Super--Tools%20(95%25%20Token%20Cut)-ec4899.svg)](#12-the-cognitive-pentest-hexagon-mode-hexagon)
[![FastMCP Tools](https://img.shields.io/badge/FastMCP%20Tools-104%20Registered%20(Full%20Mode)-8b5cf6.svg)](#-complete-fastmcp-tools-reference-98-tools)
[![Power Mode](https://img.shields.io/badge/Power--Mode-18%20Meta--Tools%20(82.7%25%20Token%20Cut)-10b981.svg)](#option-b-power-mode-18-consolidated-meta-tools)
[![Two-Tier Orchestrator](https://img.shields.io/badge/Access%20Control-Two--Tier%20Orchestrator%20(3--Way%20Swap)-ec4899.svg)](#11-two-tier-hybrid-access-control--business-logic-orchestrator)
[![Interactive Workbenches](https://img.shields.io/badge/UI%20Workbenches-Dual--Pane%20%2B%20Splitters-0ea5e9.svg)](#13-interactive-human-in-the-loop-pentest-workbenches--dual-pane-ui)
[![API Guardrails](https://img.shields.io/badge/API%20Guardrails-Idempotency%20%2B%20RFC%207807-6366f1.svg)](#14-enterprise-api-contract-standardization--guardrails)
[![FastAPI](https://img.shields.io/badge/FastAPI-High%20Performance-009688.svg)](https://fastapi.tiangolo.com)
[![Auto-Pilot](https://img.shields.io/badge/Auto--Pilot-7--Phase%20Closed%20Loop-e11d48.svg)](#1-autonomous-closed-loop-auto-pilot-state-machine)
[![Worker Swarm](https://img.shields.io/badge/Worker%20Swarm-Distributed%20%2B%20Adaptive%20Rate%20Limit-f59e0b.svg)](#2-distributed-multi-agent-swarm-worker-pool)
[![In-House OAST](https://img.shields.io/badge/In--House%20OAST-HTTP%20%7C%20DNS%20%3A5353%20%7C%20LDAP%20%3A1390-38bdf8.svg)](#3-in-house-out-of-band-oast-listener--webhook-dispatcher)
[![WAF Auto-Heal](https://img.shields.io/badge/Proxy%20Auto--Heal-X--Proxsynth--AutoHealed-a855f7.svg)](#6-dynamic-waf-evasion--rate-limit-backoff-in-forward-proxy-8088)
[![CLI Wrappers](https://img.shields.io/badge/CLI%20Wrappers-proxsynth--exec-0ea5e9.svg)](#-agentic-cli-execution-wrappers-proxsynth-exec)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#-license)

---

## 📌 Why Proxsynth? (Traditional Proxies vs. Proxsynth)

Traditional penetration testing proxies (*Burp Suite*, *Caido*, *mitmproxy*, *OWASP ZAP*) were built for manual human point-and-click workflows. When deployed with autonomous AI agents, operators face critical operational bottlenecks:

| Operational Bottleneck | Burp Suite / Caido / ZAP | PROXSYNTH Autonomous Solution |
| :--- | :--- | :--- |
| **Token Exhaustion** | Dumps 100KB–1MB raw HTML/CSS/JS into LLM prompts. | **90% Token Reduction:** LLM Semantic Body Distiller & Dynamic Noise Stripper. |
| **Prompt Bloat (Schema)** | Massive tool registries bloat prompt context by ~36,000 tokens. | **Tri-Tier Registry:** Hexagon Mode exposes 6 intent-driven super-tools cutting prompt schema tokens by **~91.3% - 95%** with heuristic auto-decisions. |
| **Agent Amnesia & Loops** | Stateless; agent repeats tests, gets stuck in loops, and forgets state. | **Hypothesis Working Memory Ledger:** Tracks `PLANNED` ➔ `TESTING` ➔ `CONFIRMED` / `REFUTED` state transitions. |
| **Subprocess Proxy Bypass** | CLI tools (`curl`, `nmap`, `nuclei`, `sqlmap`) bypass local proxy. | **Transparent Interception:** `sitecustomize.py` + `proxsynth-exec` CLI wrappers enforce proxying (:8088) and CA trust. |
| **False-Positive Hallucinations** | Agent guesses XSS or SQLi from reflected strings. | **Deterministic Verification Gate:** Sandboxed Headless Chromium DOM Oracle with **Screenshot Proof** (`evidence/xss_proof_{hash}.png`) & Welch's t-test. |
| **Blind Vulnerabilities** | Out-of-band SSRF/RCE requires complex manual setup. | **In-House Multi-Protocol OAST:** Native HTTP, DNS (:5353), and LDAP (:1390) listeners with **HMAC-SHA256 Webhook Dispatch**. |
| **Multi-Hop Kill Chains** | Manual correlation of disconnected findings. | **Autonomous Exploit Chainer:** Automatically synthesizes multi-hop pivots (SSRF ➔ Cloud IMDS, BOLA ➔ Privilege Escalation) and exports **Nuclei v2/v3 YAML**. |
| **Session Invalidation** | Expired tokens cause cascading 401 Unauthorized failures. | **Session State Auto-Refresher:** Monitors proxy stream, auto-detects 401s, replays auth recipes, and retries with `X-Proxsynth-Session-Refreshed: TRUE`. |
| **WAF Bans & Rate Limits** | Immediate 429/403 block stops agent execution. | **Forward Proxy Auto-Healing:** Exponential backoff on 429/503 and auto-spoofed evasion headers on 403/406 with `X-Proxsynth-AutoHealed: TRUE`. |

---

## 🏗️ System Architecture

```text
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │                        AUTONOMOUS AI PENTESTING AGENTS                        │
 │           (Claude Code / Cursor / Windsurf / OpenCode / Antigravity)          │
 └───────────────────────┬───────────────────────────────┬───────────────────────┘
                         │                               │
       FastMCP JSON-RPC  │                               │ CLI Script Execution (proxsynth-exec)
       (Power / Full)    │                               │ Transparent sitecustomize.py (:8088)
                         ▼                               ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │                           PROXSYNTH GATEWAY ENGINE                            │
 │  ┌──────────────────────────────────────────┐┌─────────────────────────────┐  │
 │  │      FastMCP Dual-Mode Tool Registry     ││      Forward MITM Proxy     │  │
 │  │ - Power Mode: 11 Consolidated Meta-Tools ││ - Port 8088 (TLS MITM)      │  │
 │  │ - Full Mode: 98 Modular Granular Tools   ││ - Dynamic WAF Evasion       │  │
 │  │ - FastMCP 2.0+ Standard ToolAnnotations  ││ - Session Auto-Refresher    │  │
 │  └────────────────────┬─────────────────────┘└──────────────┬──────────────┘  │
 │                       │                                     │                 │
 │                       └──────────────────┬──────────────────┘                 │
 │                                          ▼                                    │
 │  ┌─────────────────────────────────────────────────────────────────────────┐  │
 │  │                     COGNITIVE TESTING & AUDIT CORE                      │  │
 │  │ 1. Autonomous Closed-Loop Auto-Pilot Engine (7-Phase Self-Driving Loop) │  │
 │  │ 2. Distributed Multi-Agent Swarm Worker Pool (Concurrent Queue Runner)  │  │
 │  │ 3. In-House OAST Multi-Protocol Listener (HTTP / DNS :5353 / LDAP :1390)│  │
 │  │ 4. Deterministic Playwright DOM Oracle with Visual Screenshot Proof     │  │
 │  │ 5. Session State Auto-Refresher (Replays Login, 401 Auto-Healing)       │  │
 │  │ 6. Target Context-Aware Memory & Golden Payload RAG (PHP, Node, Java..) │  │
 │  │ 7. Deep AST Pentest Script Snooper (Files & Inline `python -c` / `node`)│  │
 │  │ 8. Multi-Step Exploit Chainer & Automatic Nuclei v2/v3 YAML Exporter    │  │
 │  └───────────────────────────────────────┬─────────────────────────────────┘  │
 │                                          ▼                                    │
 │  ┌─────────────────────────────────────────────────────────────────────────┐  │
 │  │                  SQLite WAL Persistence & State Engine                  │  │
 │  │ - HttpLogs (Raw & Semantic Distilled)    - Target Knowledge Graph       │  │
 │  │ - TestingHypothesis Memory Ledger        - ActiveSession & CSRF Vault   │  │
 │  │ - CapturedPayload Vault & AST Hashes     - In-House OAST Event History  │  │
 │  └─────────────────────────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────┬────────────────────────────────────┘
                                            ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │               Cyberpunk SOC Web Dashboard & Live Cytoscape Map                │
 │   - Interactive Attack Graph (D3 / Cytoscape)   - Real-Time Web Terminal / WS │
 │   - Hypothesis Kanban Board                     - OWASP CI/CD Scorecard & HAR │
 └───────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (30 Seconds)

### 1. Installation
```bash
git clone https://github.com/your-org/proxsynth.git
cd proxsynth
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt
playwright install chromium
```

### 2. Launch Proxsynth
```bash
# Starts FastAPI SOC Dashboard (:8000), Forward Proxy (:8088),
# OAST DNS (:5353), OAST LDAP (:1390), and AST Script Snooper
python -m backend.app
```
* **Cyberpunk SOC Web Console:** `http://127.0.0.1:8000`
* **Forward Interception Proxy:** `http://127.0.0.1:8088`
* **Interactive Attack Topology:** `http://127.0.0.1:8000/api/attack-graph/interactive`
* **OAST DNS Listener:** `127.0.0.1:5353 (UDP)`
* **OAST LDAP Listener:** `127.0.0.1:1390 (TCP)`

### 3. Connect Your AI Agent (FastMCP Configuration)

Proxsynth operates natively with any MCP client (*Claude Desktop*, *Cursor*, *Windsurf*, *OpenCode*, *Hermes*, *Antigravity*).

#### Option A: The Cognitive Pentest Hexagon (Recommended for AI Agents — Cuts Tokens by ~95%)
In Hexagon Mode, Proxsynth registers **6 intent-driven super-tools** (9 total with project context), delivering maximum autonomy, zero hallucinated arguments, and an extreme **~95% prompt token reduction**:

```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/proxsynth",
      "env": {
        "PROXSYNTH_TOOL_MODE": "hexagon"
      }
    }
  }
}
```

#### Option B: Power Mode (18 Consolidated Meta-Tools)
Consolidates domain operations into 18 meta-tools for agents needing structured sub-actions:

```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/proxsynth",
      "env": {
        "PROXSYNTH_TOOL_MODE": "power"
      }
    }
  }
}
```

#### Option C: Full Granular Mode (All 104 Tools)
Registers the complete granular suite of 104 modular security testing tools:

```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/proxsynth",
      "env": {
        "PROXSYNTH_TOOL_MODE": "full"
      }
    }
  }
}
```

---

## ⚡ Dual-Mode FastMCP Registry (Power Mode vs. Full Mode)

Standard MCP servers register dozens of granular tools. In agentic testing loops, dumping 90+ tool JSON schemas into the prompt consumes **~36,000+ tokens per inference turn**, leading to context truncation, high latency, and increased costs.

Proxsynth solves this with its **Dual-Mode Registry Pattern**:

| Feature / Metric | Power Mode (`PROXSYNTH_TOOL_MODE=power`) | Full Mode (`PROXSYNTH_TOOL_MODE=full`) |
| :--- | :--- | :--- |
| **Registered FastMCP Tools** | **11 Consolidated Power Tools** | **97 Granular Tools** |
| **Prompt Token Overhead** | **~4,500 Tokens (~87.5% reduction)** | ~36,000 Tokens |
| **Recommended Environment** | Autonomous LLM Agents (Claude, Cursor, Antigravity) | Human Security Engineers / Automated CI Scripts |
| **Action Routing** | Single tool dispatches multi-action parameters | Direct 1:1 functional tool invocation |
| **Underlying Engine Access** | 100% full access to all backend capabilities | 100% full access to all backend capabilities |

### The 11 High-Leverage Power Mode Tools:

| # | Power Tool | Supported Sub-Actions / Operations | Core Purpose |
| :---: | :--- | :--- | :--- |
| **1** | `manage_pentest_execution` | `execute`, `execute_sandbox_command`, `record_external`, `capture_script`, `replay` | Unified sandbox shell runner, external tool recorder, AST exploit ingester (`python -c`, `node -e`), and replay diffing. |
| **2** | `manage_attack_surface` | `get_graph`, `upsert_asset`, `upsert_service`, `upsert_endpoint`, `batch_ingest`, `scope_recon`, `exploit_chains` | Target Knowledge Graph manager: asset/service/endpoint mapping, passive scope recon, and multi-hop exploit chainer. |
| **3** | `analyze_and_diff_traffic` | `semantic_diff`, `raw_diff`, `distill_noise`, `strip_noise`, `cluster_patterns` | High-precision traffic analysis: semantic diffing, DOM distillation, dynamic noise stripping, and pattern clustering. |
| **4** | `manage_interception_rules` | `list`, `add_rule`, `toggle_rule`, `delete_rule` | Traffic interception rules manager: list, add, toggle, and delete automated traffic modification and mock rules. |
| **5** | `manage_session_vault` | `list_identities`, `store_identity`, `get_identity`, `clear_identities` | Multi-role identity vault: manages primary, attacker, victim, and admin credentials for automated authorization audits. |
| **6** | `manage_oast_and_tunnels` | `spray_canaries`, `poll_events`, `generate_token`, `setup_tunnel`, `get_tunnel_status` | Unified Out-of-Band operations: sprays canaries, polls HTTP/DNS/LDAP events, manages webhooks and reverse tunnels. |
| **7** | `manage_testing_agenda` | `record_hypothesis`, `get_agenda`, `update_status` | Agent working memory hub: manages testing hypotheses, tracks verification states, and synthesizes pending agendas. |
| **8** | `run_autonomous_autopilot` | Single execution entrypoint (`target`, `goal`, `max_depth`, `auto_exploit`) | Closed-loop 7-phase self-driving pentest loop with automatic reconnaissance, auditing, and multi-hop exploitation. |
| **9** | `set_active_project` | Project context switcher (`project`) | Sets active workspace project for complete traffic, finding, and attack graph isolation. |
| **10** | `get_active_project` | Status query | Returns active project context, view mode, write project, and isolation state. |
| **11** | `get_tool_harness_manifest` | Taxonomy manifest | Returns complete tool metadata, annotations, and schemas for agent harness auto-approval. |

*(Note: `run_autopilot_swarm` is also registered in Power Mode for concurrent multi-target swarm auditing).*

---

## 🎯 Key Strategic Capabilities & Feature Deep-Dives

### 1. Autonomous Closed-Loop Auto-Pilot State Machine
* **MCP Tool:** `run_autonomous_autopilot`
* **REST API:** `POST /api/autopilot/start`
* **Module:** [`backend/autopilot_engine.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/autopilot_engine.py)

Proxsynth features an end-to-end, goal-driven cognitive state machine that executes a **7-phase self-driving pentest loop** without requiring human intervention:

```text
 ┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
 │         PHASE 1         │ ──> │         PHASE 2         │ ──> │         PHASE 3         │
 │  Target Classification  │     │   Scope Recon (crt.sh)  │     │ Active Route Spidering  │
 │   & Strategy Synthesis  │     │   & Subdomain Takeover  │     │   & Route Inference     │
 └─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
                                                                              │
 ┌─────────────────────────┐     ┌─────────────────────────┐                  ▼
 │         PHASE 6         │ <── │         PHASE 5         │     ┌─────────────────────────┐
 │   Deterministic Gate    │     │ Targeted Audits/Fuzzing │ <── │         PHASE 4         │
 │   & DOM Proof Capture   │     │ (BOLA, BFLA, Logic..)   │     │ Cognitive Attack Advisor│
 └─────────────────────────┘     └─────────────────────────┘     │    Decision Matrix      │
              │                                                  └─────────────────────────┘
              ▼
 ┌─────────────────────────┐     ┌─────────────────────────┐
 │         PHASE 7         │ ──> │        COMPLETED        │
 │  Multi-Hop Kill Chains  │     │ Standalone PoC & Nuclei │
 │  & Exploit Synthesis    │     │      Dossier Staged     │
 └─────────────────────────┘     └─────────────────────────┘
```

* **Phase 1: Target Classification & Strategy Synthesis:** Analyzes input URL/IP (e.g., GraphQL API, SPA, microservice, legacy monolith) using `classify_target_input` and synthesizes specialized testing vectors.
* **Phase 2: Scope Expansion & Passive Recon:** Queries `crt.sh` Certificate Transparency logs, resolves DNS A/AAAA/CNAME records, and audits for dangling cloud takeovers (AWS S3, GitHub Pages, Heroku, Azure).
* **Phase 3: Active Crawling & Route Inference:** Discovers live endpoints via asynchronous headless crawler (`crawl_and_map_target`) and predicts speculative shadow routes (`infer_endpoints_from_observed`).
* **Phase 4: Cognitive Attack Decisions:** Evaluates recorded traffic patterns against `attack_advisor.py`, ranking prioritized attack candidates based on tech-stack context.
* **Phase 5: Targeted Autonomous Auditing & Fuzzing:** Concurrently audits BOLA/IDOR (`bola_matrix.py`), BFLA (`bfla_engine.py`), Mass Assignment (`mass_assignment_engine.py`), and Business Logic (`logic_fuzzer.py`).
* **Phase 6: Deterministic Verification Gate:** Proves exploitability through differential oracles and headless browser DOM execution.
* **Phase 7: Multi-Hop Exploit Chaining & Reporting:** Chains confirmed vulnerabilities (e.g. SSRF ➔ AWS IMDS, Token Leak ➔ Admin route) and stages verified findings.

---

### 2. Distributed Multi-Agent Swarm Worker Pool
* **MCP Tool:** `run_autopilot_swarm`
* **REST API:** `POST /api/autopilot/swarm`
* **Module:** [`backend/worker_swarm.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/worker_swarm.py)

For large attack surfaces with multiple root domains or dozens of subdomains, Proxsynth orchestrates a **Distributed Multi-Agent Swarm Worker Pool**:
* **Concurrent Worker Architecture:** Manages an asynchronous queue (`asyncio.Queue`) distributing targets across N parallel workers (configurable concurrency from 1 to 10).
* **Shared State Deduplication:** Centralized locking prevents duplicate crawling or redundant fuzzing across overlapping assets.
* **Real-Time Telemetry:** Streams per-worker progress, targets, and discovery metrics over WebSocket (`/ws/terminal`) to the SOC Console.
* **Adaptive Domain Token-Bucket Rate Limiter:** Built-in `AdaptiveDomainRateLimiter` (`backend/adaptive_limiter.py`) dynamically governs worker concurrency per target domain. Automatically backs off on HTTP 429 / 503 responses with exponential jitter, preventing WAF IP bans during heavy swarm audits.

---

### 3. In-House Out-of-Band (OAST) Listener & Webhook Dispatcher
* **MCP Tools:** `configure_oast_webhook`, `simulate_oast_callback`, `generate_oast_token`, `poll_oast_events`, `spray_oast_canaries`
* **REST API:** `POST /api/oast/webhook/config`, `GET /api/oast/webhook/status`, `POST /api/oast/simulate`
* **Modules:** [`backend/oast_listener.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/oast_listener.py) & [`backend/oast_engine.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/oast_engine.py)

Eliminates reliance on third-party Burp Collaborator or public interactsh servers:
* **Multi-Protocol Local Listeners:**
  - **HTTP/HTTPS:** Ingests callback requests at `/oast/{token}`.
  - **DNS Listener:** Dedicated UDP DNS server listening on **Port 5353** capturing sub-domain DNS canary queries (`{token}.oast.proxsynth.local`).
  - **LDAP Listener:** Dedicated TCP LDAP server listening on **Port 1390** capturing JNDI lookup interactions (`${jndi:ldap://...}`).
* **HMAC-SHA256 Webhook Dispatcher:** Forwards intercepted Out-of-Band interactions in real-time to your webhook (Slack, Discord, custom C2) with an `X-Proxsynth-Signature: sha256={digest}` header.
* **Deterministic Correlation:** Matches incoming IP, user-agent, and canary token against the active testing hypothesis, confirming Blind SSRF, Blind XXE, or Log4j/RCE with zero false positives.

---

### 4. Automatic Nuclei YAML Template Exporter
* **MCP Tool:** `export_nuclei_template`
* **REST API:** `POST /api/nuclei/export`, `GET /api/nuclei/templates/{id}`
* **Module:** [`backend/nuclei_exporter.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/nuclei_exporter.py)

Bridges the gap between autonomous bug discovery and continuous regression testing:
* **1-Click Nuclei Serialization:** Instantly converts any confirmed `Finding` or intercepted `HttpLog` into valid **ProjectDiscovery Nuclei v2/v3 YAML**.
* **Intelligent Matcher Generation:** Automatically constructs response status matchers, body word matchers, and regex extractors matching the verified vulnerability proof.
* **CI/CD Ready:** Generates standardized YAML templates tagged with CVSS severity, CWE identifiers, and remediation descriptions ready for automated pipeline regression.

---

### 5. Session State Auto-Refresher (Transparent 401 Auto-Healing)
* **MCP Tools:** `configure_session_refresher`, `test_session_refresh`
* **REST API:** `POST /api/session/refresher/config`, `GET /api/session/refresher/status`, `POST /api/session/refresher/test`
* **Modules:** [`backend/session_refresher.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/session_refresher.py) & [`backend/forward_proxy.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/forward_proxy.py)

AI agents frequently fail during prolonged pentesting when authentication sessions expire or JWT tokens lapse:
* **Automatic Expiration Detection:** Monitors proxy traffic for HTTP `401 Unauthorized` or token revocation signatures (`token expired`, `jwt expired`, `invalid_token`).
* **Zero-Human Replay Workflow:** When expiration is detected, Proxsynth locks outgoing target requests, replays the recorded authentication recipe (`login_url`, credentials payload), extracts the fresh token or cookie, updates the database and cache, and transparently retries the original request.
* **Verification Marker:** Auto-healed requests return with header `X-Proxsynth-Session-Refreshed: TRUE`, preventing agent confusion or session-loss crashes.

---

### 6. Dynamic WAF Evasion & Rate-Limit Backoff in Forward Proxy (:8088)
* **Proxy Port:** `127.0.0.1:8088`
* **Modules:** [`backend/forward_proxy.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/forward_proxy.py), [`backend/adaptive_limiter.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/adaptive_limiter.py), [`backend/waf_mutator.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/waf_mutator.py)

Autonomous testing often triggers WAF blocks and API rate limits. Proxsynth's forward MITM proxy transparently resolves these blocks:
* **Exponential Rate-Limit Backoff:** On HTTP `429 Too Many Requests` or `503 Service Unavailable`, Proxsynth pauses traffic using adaptive jittered backoff, respecting target `Retry-After` headers.
* **Dynamic Header Auto-Spoofing:** On HTTP `403 Forbidden` or `406 Not Acceptable` WAF blocks (Cloudflare, AWS WAF, Akamai), Proxsynth injects evasive client headers (`X-Forwarded-For`, `X-Originating-IP`, `X-Custom-IP-Authorization`, `X-Real-IP`) and retries transparently.
* **Telemetry Header:** Retried requests returning 2xx/3xx include `X-Proxsynth-AutoHealed: TRUE`.

---

### 7. Headless Browser DOM Execution Oracle with Screenshot Evidence
* **MCP Tool:** `verify_dom_execution`
* **REST API:** `POST /api/oracle/verify-dom`
* **Module:** [`backend/browser_oracle.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/browser_oracle.py)

Eliminates XSS false positives (e.g. reflections trapped inside inert HTML text or escaped attributes):
* **Deterministic Execution Oracle:** Spawns a sandboxed headless Playwright Chromium instance, hooks `window.alert`, `window.confirm`, `window.prompt`, and console sinks.
* **Full-Page Screenshot Evidence:** When client-side script execution triggers, Proxsynth takes a full-page browser screenshot and saves it as immutable proof to:
  ```text
  evidence/xss_proof_{md5_hash}.png
  ```
* **CSP & Sandbox Audit:** Accurately diagnoses whether Content Security Policy (CSP) blocked the payload or if DOM execution successfully breached browser boundaries.

---

### 8. Target Context-Aware Memory & Golden Payload RAG
* **Module:** [`backend/payload_vault.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/payload_vault.py)
* **Function:** `get_golden_payloads_for_stack(tech_stack, vuln_category)`

Rather than spraying generic fuzz lists, Proxsynth utilizes **Target Context-Aware Memory** to dynamically retrieve high-probability golden exploit vectors tailored to the target's fingerprint:

| Tech Stack | Curated Golden Exploit Vectors | Focus Vulnerabilities |
| :--- | :--- | :--- |
| **PHP** | `php://filter/convert.base64-encode/resource=index.php`, `0e215962017`, `../../../../etc/passwd%00`, `;system('id');` | LFI Base64 disclosure, Type Juggling magic hash bypass, Null-byte poison, Command Injection. |
| **Node.js** | `{"__proto__":{"admin":true}}`, `{"constructor":{"prototype":{"isAdmin":true}}}`, `{{root.process.mainModule.require('child_process').execSync('id').toString()}}` | Prototype Pollution privilege escalation, Pug/EJS SSTI sandbox breakout RCE, Loopback SSRF. |
| **Python** | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`, `{{''.__class__.__mro__[1].__subclasses__()}}`, `' OR 1=1 -- -` | Jinja2 MRO sandbox breakout RCE, Python class hierarchy enumeration, SQLi tautology bypass. |
| **Java** | `${T(java.lang.Runtime).getRuntime().exec('id')}`, `/actuator/env`, `/actuator/heapdump`, `${jndi:ldap://127.0.0.1:1390/a}` | Spring SpEL expression injection RCE, Spring Boot Actuator leaks, Log4j JNDI remote class lookup. |
| **GraphQL** | `{"query":"{__schema{types{name,fields{name}}}}"}`, `{"query":"query { a: __typename b: __typename }"}` | Full schema introspection extraction, Alias batching / amplification Denial of Service. |
| **Ruby** | `<%= File.read('/etc/passwd') %>`, `\| id` | Ruby ERB template injection, Open3 / IO pipe command injection. |

---

### 9. Deep AST Inline Script Ingestion & Kernel-Event Workspace Watchdog
* **Modules:** [`backend/payload_vault.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/payload_vault.py) & [`backend/script_snooper.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/script_snooper.py)

Autonomous agents frequently write custom Python, Bash, or Node scripts to test endpoints. Proxsynth captures these payloads automatically without requiring manual registration:
* **Real-Time Kernel Watchdog (`watchdog`):** `WorkspaceKernelWatcher` leverages OS-level file system notifications (`FileSystemEventHandler`) to detect and parse newly created/modified test scripts (`.py`, `.js`, `.sh`, `.ps1`) in the workspace the instant the LLM writes them.
* **Inline Shell Command Parsing:** Intercepts inline executions such as:
  ```bash
  python -c "import requests; requests.post('http://target/api', data={'user': 'admin\'--'})"
  node -e "require('http').get('http://target/login?user=admin')"
  ```
* **Deep Python AST Traversal:** Traverses Python Abstract Syntax Trees (`ast.walk`), extracts HTTP URLs from `requests.get` / `urllib`, captures string literals assigned to variables (`payload = "..."`), and automatically commits them to the `CapturedPayload` vault.

---

### 10. Autonomous Multi-Step Exploit Chainer & Multi-Step Nuclei Exporter
* **Modules:** [`backend/exploit_chainer.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/exploit_chainer.py), [`backend/nuclei_exporter.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/nuclei_exporter.py), & [`backend/scope_recon.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/scope_recon.py)

* **SSRF ➔ Cloud Metadata Pivot:** Automatically constructs probes targeting AWS IMDSv1 (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`), GCP Metadata (`metadata.google.internal`), Azure IMDS, and internal microservices.
* **Multi-Step Nuclei Template Exporter:** Generates complex, multi-request ProjectDiscovery Nuclei v2/v3 templates (`generate_multistep_nuclei_template()`) that extract dynamic session tokens, CSRF tokens, or object IDs from Step 1 (`internal: true`) and interpolate them into subsequent exploit steps using `{{token}}` variables.
* **Wildcard Recon & CNAME Takeover:** Queries `crt.sh` and tests DNS CNAME entries for dangling cloud resources (AWS S3 `NoSuchBucket`, Heroku `No such app`, Azure `404 Web Site not found`, Shopify).

---

### 11. Two-Tier Hybrid Access Control & Business Logic Orchestrator
* **Module:** [`backend/access_control_orchestrator.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/access_control_orchestrator.py)
* **FastMCP Tools:** `run_two_tier_access_control_orchestrator` / `manage_session_vault(action="audit_access_matrix")`

Solves the critical problem of broken access control (BOLA, BFLA, Broken ACL, and Unauthenticated endpoints) and business logic flaws without requiring manual script orchestration:

```text
  ┌────────────────────────────────────────────────────────────────────────┐
  │                   TIER 1: HEURISTIC AUDIT PLANNER                      │
  │  - Discovers candidate routes from HttpLog & OpenAPI schema             │
  │  - Classifies endpoints: BOLA_CANDIDATE, BFLA_ADMIN, BUSINESS_LOGIC     │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │               DETERMINISTIC 3-WAY REPLAY & STATE DIFF                  │
  │  1. Baseline Replay (User A credentials)                               │
  │  2. Swapped Identity Replay (User B credentials)                       │
  │  3. Unauthenticated Replay (Stripped Auth headers / cookies)           │
  │  - Calculates Structural Similarity & Soft-Error / Generic 200 Deltas   │
  │  - Secondary State Re-Verification (Confirms state persistence)        │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                 TIER 2: COGNITIVE ANOMALY EVALUATOR                    │
  │  - Evaluates anomalies, eliminates false positives, assigns CWE & CVSS │
  │  - Auto-commits verified findings to database                          │
  │  - Synthesizes 1-click multi-step Nuclei exploit templates             │
  └────────────────────────────────────────────────────────────────────────┘
```

* **Automated 3-Way Identity Swapping:** Automatically compares the response of User A (victim), User B (attacker/swapped), and Anonymous (unauthenticated) to pinpoint unauthorized data disclosures and privileged actions.
* **Soft Error & SPA 200 OK Detection:** Avoids naive HTTP 200 false positives by evaluating response body content length, structural JSON key similarity, and soft error markers (`access denied`, `unauthorized`, `login required`).
* **Multi-Step PoC Template Synthesis:** Every confirmed finding automatically synthesizes a reproducible Nuclei YAML template for instant regression verification.

---

### 12. The Cognitive Pentest Hexagon (Mode: `hexagon`)
* **Module:** [`backend/cognitive_hexagon.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/cognitive_hexagon.py)
* **Registered Super-Tools:** 6 Core Super-Tools (9 Total with Project Context)
* **Prompt Schema Token Reduction:** **~91.3% - 95% Savings** (~1,800 tokens vs ~36,000 tokens)

Standard MCP servers expose 90+ granular functions, forcing the LLM to spend precious tokens memorizing fragile argument combinations. The Cognitive Pentest Hexagon reorganizes Proxsynth into **6 Intent-Driven Facets**:

```text
                       ┌─────────────────────────┐
                       │     PROXSYNTH_RECON     │
                       │ (Subdomains, Ports,     │
                       │  JS, OpenAPI, Health)   │
                       └────────────┬────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       │                            │                            │
       ▼                            ▼                            ▼
┌──────────────┐             ┌──────────────┐             ┌──────────────┐
│  PROXSYNTH_  │             │  PROXSYNTH_  │             │  PROXSYNTH_  │
│   TRAFFIC    │ ◄────────── │  AUTONOMOUS_ │ ──────────► │    AUDIT     │
│ (Inspect,    │             │     STEP     │             │(BOLA, BFLA,  │
│  Diff, Send) │             │ (Auto-Loop)  │             │ SQLi, Race)  │
└──────────────┘             └──────────────┘             └──────────────┘
       ▲                            ▲                            ▲
       │                            │                            │
       └────────────────────────────┼────────────────────────────┘
                                    │
       ┌────────────────────────────┴────────────────────────────┐
       ▼                                                         ▼
┌─────────────────────────┐                   ┌─────────────────────────┐
│    PROXSYNTH_SESSION    │                   │ PROXSYNTH_VERIFY_EXPORT │
│ (Identities, HITL 2FA,  │                   │ (DOM Screenshot Oracle, │
│  Token Auto-Refresh)    │                   │  Nuclei YAML, PoC Rpt)  │
└─────────────────────────┘                   └─────────────────────────┘
```

1. **`proxsynth_recon`**: Surface mapping, passive scope expansion (`crt.sh`), port scanning, JS bundle scraping, and OpenAPI ingestion via a single `mode="auto" | "passive" | "active"` intent router.
2. **`proxsynth_traffic`**: Unified traffic workbench supporting raw/semantic diffing, request replay, and parameter distillation.
3. **`proxsynth_audit`**: Multi-vector vulnerability audit orchestrating BOLA/IDOR, BFLA, SQLi, SSRF, JWT, and Race Conditions based on architectural heuristic profiling.
4. **`proxsynth_session`**: Cross-identity authentication manager supporting primary/attacker/victim identity swapping, CSRF vaulting, and HITL browser sessions.
5. **`proxsynth_verify_and_export`**: Deterministic verification gate uniting the Playwright Headless Chromium DOM oracle (with screenshot evidence), PoC generator, and ProjectDiscovery Nuclei v2/v3 YAML exporter.
6. **`proxsynth_autonomous_step`**: Autonomous cognitive stepping engine evaluating the current state, resolving highest-priority hypotheses, executing targeted probes, and returning structured telemetry (`metrics` and `findings_summary`).

---

### 13. Interactive Human-in-the-Loop Pentest Workbenches & Dual-Pane UI
* **Dashboard URL:** `http://127.0.0.1:8000`
* **Template UI:** [`frontend/index.html`](file:///D:/0x13%20PROJECT/Proxsynth/frontend/index.html)

Proxsynth v0.3.0 introduces a state-of-the-art interactive pentesting frontend engineered for high-speed analysis and zero-lag workflows:
* **Synchronized Dual-Pane Split Inspector:** Dual-pane request and response inspection with draggable resize splitter (`repeaterSplitRatio`), synchronized scrolling, raw/beautified code toggles, and token-saving distillation.
* **Intercept Console with Raw Header Editor:** Live request trap supporting raw HTTP header textarea modification, inline body manipulation, and forward payload enrichment before dispatching to target servers.
* **Parameter Fuzzer with Live Abort Controller:** Multi-threaded fuzzing engine with cancellation event registry and live Abort button (`POST /api/fuzzer/abort`) for instant attack interruption without leaving dangling background threads.
* **Scope Guardrails Sandbox Evaluator:** Interactive sandbox card (`POST /api/scope/test`) for real-time validation of target URLs against scope boundaries and anti-destructive route blacklists (`/logout`, `/delete-account`, `/reset-db`, `/purge`).
* **Repeater Multi-Tab Studio:** Burp Suite-style tab management with draggable split layout, automatic diffing against baseline responses, and `follow_redirects` toggle.
* **OpenAPI / Swagger Sandbox Explorer:** Live endpoint explorer with 1-click OpenAPI/Swagger import modal (`POST /api/openapi/import`) from raw JSON/YAML or remote spec URLs, supporting immediate dispatch to Repeater and Fuzzer.
* **Traffic Proxy Filter Presets & Response Search:** Quick filter buttons (`All`, `In-Scope`, `APIs / JSON`, `Errors (4xx/5xx)`, `Hide Static`), in-page Response Body Search with `<mark>` visual match highlighting, and passive technology fingerprinting (`Nginx`, `Express`, `Django`, `Next.js`, `Cloudflare`).
* **Standardized 60 FPS Table Pagination:** Paginated navigation with per-page density controls (`25`, `50`, `100`, `250`, `All`) standardized across all 14 menu views (Proxy History, Findings, Attack Surface, OAST Events, Fuzzer, Intercept, etc.) preventing DOM lagging during high-throughput fuzzing.

---

### 14. Enterprise API Contract Standardization & Guardrails
* **Modules:** [`backend/app.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/app.py) & [`backend/intercept_manager.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/intercept_manager.py)

Proxsynth strictly adheres to enterprise-grade API design and security testing guardrails:
* **RFC 7807 Unified Error Envelopes:** All REST endpoints return standardized structured JSON errors (`{"error": {"code": "...", "message": "...", "details": ...}}`) with backward-compatible `.detail` fields for legacy clients.
* **Idempotency-Key Concurrency Guard:** Mutation endpoints (`POST /api/campaign/run`, `POST /api/fuzzer/run`) inspect the `Idempotency-Key` header, guarding against duplicate concurrent invocations (`409 Conflict`), payload mismatch tamperings (`422 Unprocessable`), and returning cached execution results on retries.
* **CVSS v4.0 & MITRE ATT&CK Mapping:** Verified findings automatically compute official **CVSS v4.0** base scores and map techniques against the latest **MITRE ATT&CK Enterprise & Mobile Matrix**.

---

---

## ⌨️ Agentic CLI Execution Wrappers (`proxsynth-exec`)

When deploying AI agents that run external terminal tools (`nmap`, `nuclei`, `curl`, `ffuf`, `sqlmap`, or custom scripts), tools often bypass environment proxy variables.

Proxsynth includes native execution wrappers located at the repository root:
* **Windows (PowerShell):** [`proxsynth-exec.ps1`](file:///D:/0x13%20PROJECT/Proxsynth/proxsynth-exec.ps1)
* **Linux / macOS (Bash):** [`proxsynth-exec.sh`](file:///D:/0x13%20PROJECT/Proxsynth/proxsynth-exec.sh)

```powershell
# Windows PowerShell Example
.\proxsynth-exec.ps1 -Target "https://target.com" -Tool "nuclei" -Command "nuclei -u https://target.com -tags cve"
.\proxsynth-exec.ps1 -Target "10.0.0.1" -Tool "nmap" -Command "nmap -sV -p 80,443,8080 10.0.0.1"
```

```bash
# Linux / macOS Bash Example
./proxsynth-exec.sh -t "https://target.com" -c "nuclei -u https://target.com -tags cve"
./proxsynth-exec.sh -t "https://target.com" -c "python3 exploit.py"
```

### Core Execution Wrapper Features:
1. **Auto-Proxy Chaining:** Enforces traffic routing through `127.0.0.1:8088` and auto-trusts the Proxsynth CA certificate.
2. **Real-Time Telemetry:** Streams terminal output lines directly to the SOC Web Console via `POST /api/telemetry/cli-event` and WebSocket.
3. **Workspace Script Snooper:** Watches for generated exploit scripts, parses their AST, and vaults payloads automatically.
4. **Automated Output Mining:** Automatically parses Nmap, Nuclei, and FFUF stdout into structured assets and findings in the knowledge graph.

---

## 🧰 Complete FastMCP Tools Reference (97 Tools)

Proxsynth registers **97 FastMCP tools** equipped with standardized `ToolAnnotations` (`readOnlyHint`, `destructiveHint`, and `outputSchema`).

<details open>
<summary><b>🔍 Expand Master FastMCP Tool Permissions & Safety Matrix (All 97 Tools)</b></summary>

| # | Tool Name | Category | Read-Only | Destructive | Description |
| :---: | :--- | :---: | :---: | :---: | :--- |
| 1 | `set_active_project` | `context` | No | No | Sets the active project workspace scope for multi-target traffic and data isolation. |
| 2 | `get_active_project` | `context` | Yes | No | Returns active project context, view mode, write project, and isolation configuration. |
| 3 | `send_http_request` | `traffic` | No | No | Sends HTTP/HTTPS requests with proxy routing (:8088), automatic cookie injection, and response distillation. |
| 4 | `get_traffic_history` | `traffic` | Yes | No | Lists recent HTTP transactions recorded in Proxsynth for the selected project. |
| 5 | `get_log_detail` | `traffic` | Yes | No | Retrieves full un-truncated HTTP transaction details, raw headers, body, and correlated findings. |
| 6 | `distill_http_response` | `traffic` | Yes | No | Strips DOM/HTML noise to reduce response size by 90% for LLM context windows. |
| 7 | `search_traffic_advanced` | `traffic` | Yes | No | Executes multi-dimensional filtered queries across captured HTTP proxy traffic. |
| 8 | `analyze_traffic_patterns` | `traffic` | Yes | No | Analyzes captured traffic to identify recurring API routes, auth models, and parameter schemes. |
| 9 | `compare_http_responses` | `analysis` | Yes | No | Computes side-by-side response diff with volatile anti-CSRF token and timestamp stripping. |
| 10 | `semantic_diff_responses` | `analysis` | Yes | No | Computes noise-filtered structural semantic diff between two recorded HTTP responses. |
| 11 | `browser_navigate_and_render` | `browser` | No | No | Headless browser navigation with network traffic capture and rendered DOM snapshots. |
| 12 | `render_webpage` | `browser` | No | No | Renders dynamic web pages headlessly via Playwright with automated click/fill actions. |
| 13 | `spider_and_crawl_target` | `spider` | No | No | Autonomous web crawler and spider mapping client-side routes and Single Page Apps (SPA). |
| 14 | `verify_dom_execution` | `xss` | No | No | Deterministic Playwright DOM XSS execution oracle capturing visual screenshot proof (`evidence/xss_proof_{hash}.png`). |
| 15 | `request_manual_login` | `auth` | No | No | Spawns headed browser for Human-in-the-Loop (HITL) 2FA/CAPTCHA authentication. |
| 16 | `record_test_payload` | `vault` | No | No | Explicitly catalogs specialized pentest payloads (SQLi, XSS, SSRF, SSTI, RCE, IDOR) in Payload Vault. |
| 17 | `get_captured_payloads` | `vault` | Yes | No | Retrieves vaulted security testing payloads, AST-extracted vectors, and exploit history. |
| 18 | `mutate_payload` | `waf` | No | No | Generates evasive WAF bypass mutations (case alternation, encoding, whitespace, boundary manipulation). |
| 19 | `analyze_waf_response` | `waf` | No | No | Fingerprints active WAF vendor signatures (Cloudflare, AWS WAF, Akamai, Imperva) from response status and body patterns. |
| 20 | `export_nuclei_template` | `export` | Yes | No | Serializes verified findings or captured payloads into standard ProjectDiscovery Nuclei v2/v3 YAML templates. |
| 21 | `fuzz_endpoint` | `fuzzing` | No | Yes | High-speed parameter fuzzing against targets using position markers (`§...§`). |
| 22 | `test_race_condition` | `concurrency` | No | Yes | Microsecond-synchronized concurrent burst testing for TOCTOU and business logic race conditions. |
| 23 | `audit_differential_injection` | `audit` | No | No | 3-point boolean differential comparison oracle for Blind SQLi, NoSQLi, and SSTI. |
| 24 | `audit_jwt_security` | `audit` | No | No | Audits JWT tokens for algorithm confusion (none/HS256), weak secret brute-force, and expiration bypass. |
| 25 | `audit_bfla_permissions` | `audit` | No | No | Audits endpoints for Broken Function Level Authorization (BFLA) and HTTP method tampering. |
| 26 | `audit_mass_assignment` | `audit` | No | No | Audits mutation endpoints (POST/PUT/PATCH) for object mass assignment and privilege escalation. |
| 27 | `audit_numeric_business_logic` | `audit` | No | No | Audits numeric, currency, and quantity parameters for negative values and integer boundary flaws. |
| 28 | `test_bola_idor` | `bola` | No | Yes | Executes on-demand BOLA/IDOR shadow replay test on a specific logged endpoint across object IDs. |
| 29 | `get_bola_access_matrix` | `bola` | Yes | No | Retrieves cross-identity BOLA/IDOR authorization matrix across roles and candidate endpoints. |
| 30 | `run_bola_matrix_scan` | `bola` | No | Yes | Executes automated project-wide BOLA shadow replay scan across observed candidate endpoints. |
| 31 | `inspect_graphql_endpoint` | `graphql` | No | No | GraphQL schema introspection, field mining, batch query attacks, and query depth analysis. |
| 32 | `send_websocket_message` | `websocket` | No | No | Interacts with live WebSocket connections and injects custom message frames. |
| 33 | `audit_websocket_security` | `websocket` | No | No | Audits WebSocket handshakes for Cross-Site WebSocket Hijacking (CSWSH) and unauthorized access. |
| 34 | `import_api_schema` | `api_import` | No | No | 1-Click OpenAPI and Swagger specification importer for automated attack surface mapping. |
| 35 | `infer_hidden_endpoints` | `recon` | Yes | No | Predicts hidden REST routes and speculative endpoints from observed architectural patterns. |
| 36 | `audit_api_gateway_bypass` | `audit` | No | No | Audits 401/403 gateway authorization bypasses via header injection and path tampering. |
| 37 | `scan_network_ports` | `network` | No | No | Asynchronous TCP port scanner and service banner discovery engine. |
| 38 | `get_target_health` | `recon` | Yes | No | Diagnoses DNS resolution, TCP connectivity, TLS handshake, and TTFB target latency. |
| 39 | `generate_oast_token` | `oast` | No | No | Generates unique multi-protocol Out-of-Band canary token for blind injection detection. |
| 40 | `poll_oast_events` | `oast` | Yes | No | Polls callback events across HTTP, DNS (:5353), and LDAP (:1390). |
| 41 | `spray_oast_canaries` | `oast` | No | No | Automatically injects multi-protocol OAST canaries across URL and body parameters. |
| 42 | `setup_public_tunnel` | `tunnel` | No | No | Launches public reverse tunnel (Cloudflare / Ngrok) for external callbacks. |
| 43 | `get_tunnel_status` | `tunnel` | Yes | No | Returns status, PID, and public URL of active reverse tunnel. |
| 44 | `close_public_tunnel` | `tunnel` | No | No | Terminates active public reverse tunnel. |
| 45 | `configure_oast_webhook` | `oast` | No | No | Configures external webhook endpoint for real-time HMAC-SHA256 signed OAST callback notifications. |
| 46 | `simulate_oast_callback` | `oast` | No | No | Ingests or simulates local OAST callback hit in database and triggers real-time webhook dispatch. |
| 47 | `add_interception_rule` | `intercept` | No | No | Adds automated traffic interception and response modification rule. |
| 48 | `list_interception_rules` | `intercept` | Yes | No | Lists all configured proxy interception and mock rules. |
| 49 | `toggle_interception_rule` | `intercept` | No | No | Enables or disables an interception rule by ID. |
| 50 | `delete_interception_rule` | `intercept` | No | Yes | Permanently removes an interception rule. |
| 51 | `get_ca_certificate_details` | `ca` | Yes | No | Retrieves root CA certificate fingerprint and trust installation instructions. |
| 52 | `record_testing_hypothesis` | `agenda` | No | No | Records attack hypothesis in stateful working memory ledger. |
| 53 | `get_testing_agenda` | `agenda` | Yes | No | Synthesizes pending testing agenda and next actions to eliminate agent loops. |
| 54 | `update_hypothesis_status` | `agenda` | No | No | Updates hypothesis state (`PLANNED` ➔ `TESTING` ➔ `CONFIRMED` / `REFUTED`). |
| 55 | `run_autonomous_security_campaign` | `orchestration` | No | Yes | Unified 12-track autonomous pentest campaign orchestrator. |
| 56 | `run_autonomous_autopilot` | `orchestration` | No | Yes | Executes closed-loop 7-phase self-driving pentest loop with auto-exploitation. |
| 57 | `run_autopilot_swarm` | `orchestration` | No | Yes | Executes distributed multi-agent swarm worker pool for concurrent crawling and auditing. |
| 58 | `get_campaign_status` | `orchestration` | Yes | No | Polls campaign metrics, phase progression, and confirmed findings. |
| 59 | `list_campaigns` | `orchestration` | Yes | No | Lists registered autonomous campaigns and autopilot executions. |
| 60 | `get_autonomous_attack_guidance` | `advisor` | Yes | No | Cognitive Attack Advisor recommending prioritized tools, endpoints, and exact arguments. |
| 61 | `get_tool_harness_manifest` | `meta` | Yes | No | Returns complete tool taxonomy and annotations for agent harness auto-approval. |
| 62 | `set_identity_session` | `auth` | No | No | Registers authenticated session tagged with identity role (attacker, victim, admin). |
| 63 | `register_auth_recipe` | `auth` | No | No | Registers automated login recipe for zero-human session maintenance. |
| 64 | `execute_reauthentication` | `auth` | No | No | Executes registered auth recipe to refresh expired tokens and sessions. |
| 65 | `configure_session_refresher` | `auth` | No | No | Configures automated re-auth recipe for target domain with token extraction rules. |
| 66 | `test_session_refresh` | `auth` | No | No | Executes test re-auth workflow to verify login credentials and token extraction. |
| 67 | `get_csrf_tokens` | `session` | Yes | No | Retrieves cached anti-CSRF tokens extracted from HTTP proxy traffic. |
| 68 | `set_csrf_token` | `session` | No | No | Sets anti-CSRF token for target domain for automated injection. |
| 69 | `clear_csrf_tokens` | `session` | No | Yes | Clears cached anti-CSRF tokens for a domain or project. |
| 70 | `report_vulnerability` | `triage` | No | No | Flags an existing HTTP log entry as a verified vulnerability finding in database. |
| 71 | `generate_exploit_poc` | `exploit` | Yes | No | Generates standalone Python PoC, cURL, or Bug Bounty Markdown report. |
| 72 | `generate_nuclei_template` | `exploit` | Yes | No | Generates standard Nuclei v3 YAML exploit/regression template from finding. |
| 73 | `verify_vulnerability_candidate` | `verification` | No | No | Unified deterministic verification gate validating candidate vulnerabilities. |
| 74 | `generate_audit_ci_report` | `report` | Yes | No | Generates OWASP Top 10 executive scorecard and SARIF report for CI/CD pipelines. |
| 75 | `get_attack_surface` | `recon` | Yes | No | Retrieves stateful Attack Surface Knowledge Graph for project. |
| 76 | `record_target_asset` | `recon` | No | No | Registers or updates target host/IP in Attack Surface Graph. |
| 77 | `record_target_service` | `recon` | No | No | Registers network port and service discovered during reconnaissance. |
| 78 | `record_target_endpoint` | `recon` | No | No | Catalogs discovered web route/endpoint into knowledge graph. |
| 79 | `get_attack_paths` | `killchain` | Yes | No | Synthesizes interconnected multi-hop attack paths and Mermaid diagram. |
| 80 | `delete_attack_surface_node` | `recon` | No | Yes | Deletes asset, service, or endpoint node from attack surface graph. |
| 81 | `clear_attack_surface_graph` | `recon` | No | Yes | Clears attack surface knowledge graph for a project. |
| 82 | `mine_javascript_assets` | `js` | No | No | Mines JS bundles for hidden routes, API parameters, source maps, and hardcoded secrets. |
| 83 | `mine_cli_output` | `miner` | Yes | No | Parses Nmap, Nuclei, and FFUF terminal output into structured graph entities. |
| 84 | `run_pentest_command` | `cli` | No | Yes | Executes shell command with proxy routing (:8088) and CA trust. |
| 85 | `execute_workflow_sequence` | `workflow` | No | Yes | Executes multi-stage stateful HTTP sequence with dynamic parameter extraction. |
| 86 | `run_security_audit_suite` | `suite` | No | Yes | Executes OWASP API security audit suite and computes risk score. |
| 87 | `update_proxsynth_system` | `admin` | No | Yes | Checks and applies Git self-updates for Proxsynth Web Console and FastMCP server. |
| 88 | `audit_cache_poisoning` | `cache` | No | No | Audits unkeyed header web cache poisoning and cache parameter cloaking. |
| 89 | `audit_csrf_indepth` | `csrf` | No | No | Audits anti-CSRF token entropy, SameSite cookie attributes, and CORS misconfigurations. |
| 90 | `audit_file_upload` | `upload` | No | No | Audits multipart file upload filters for extension bypass and polyglot execution. |
| 91 | `manage_pentest_execution` | `execution` | No | Yes | Unified execution hub: sandbox runner, external tool recorder, AST exploit ingester & replay diff. |
| 92 | `manage_attack_surface` | `recon` | No | No | Unified Knowledge Graph: asset/service/endpoint mapping, scope recon & exploit chains. |
| 93 | `analyze_and_diff_traffic` | `analysis` | Yes | No | Unified traffic analysis: semantic diffing, DOM distillation, noise stripping & pattern clustering. |
| 94 | `manage_interception_rules` | `intercept` | No | No | Unified interception rule manager: list, add, toggle, and delete automated traffic rules. |
| 95 | `manage_session_vault` | `session` | No | No | Unified session vault: manages multi-role identities (Attacker, Victim, Admin) and CSRF tokens. |
| 96 | `manage_oast_and_tunnels` | `oast` | No | No | Unified Out-of-Band operations: sprays canaries, polls HTTP/DNS/LDAP events & manages tunnels. |
| 97 | `manage_testing_agenda` | `agenda` | No | No | Unified working memory hub: hypothesis tracking, status transitions & agenda synthesis. |
| 98 | `run_two_tier_access_control_orchestrator` | `authz` | No | No | Two-Tier Orchestrator: automated candidate discovery, 3-way identity replay (User A vs User B vs Unauth), secondary state verification, and Nuclei PoC export. |

</details>

---

## 🖥️ REST API & Telemetry Endpoints Cheat Sheet

The Proxsynth Gateway exposes an enterprise FastAPI REST and WebSocket engine:

| Endpoint | Method | Category | Description |
| :--- | :---: | :---: | :--- |
| `/api/autopilot/start` | `POST` | Autopilot | Launches the 7-phase closed-loop self-driving pentest loop against a target. |
| `/api/autopilot/swarm` | `POST` | Swarm | Launches distributed multi-agent swarm worker pool for concurrent multi-target auditing. |
| `/api/nuclei/export` | `POST` | Nuclei | Serializes verified findings into standardized Nuclei v2/v3 YAML templates. |
| `/api/nuclei/templates/{id}` | `GET` | Nuclei | Downloads or previews auto-generated Nuclei YAML template by finding ID. |
| `/api/session/refresher/config` | `POST` | Session | Configures automated re-authentication recipe for a target domain. |
| `/api/session/refresher/status` | `GET` | Session | Returns status and metrics for all registered session auto-refreshers. |
| `/api/session/refresher/test` | `POST` | Session | Executes a test re-authentication workflow to verify login and token extraction. |
| `/api/oast/webhook/config` | `POST` | OAST | Sets external webhook URL and secret for real-time HMAC-SHA256 OAST dispatch. |
| `/api/oast/webhook/status` | `GET` | OAST | Returns current OAST webhook forwarding status and configuration. |
| `/api/oast/simulate` | `POST` | OAST | Ingests or simulates a local OAST callback and triggers event dispatcher. |
| `/api/oast/events` | `GET` | OAST | Polls captured HTTP, DNS (:5353), and LDAP (:1390) Out-of-Band interactions. |
| `/api/attack-graph/interactive` | `GET` | Attack Map | Cytoscape.js & D3.js interactive attack graph with risk scores and clusters. |
| `/api/exploit-chains/synthesize` | `POST` | Exploits | Synthesizes multi-step exploit kill chains from confirmed findings. |
| `/api/exploit-chains/execute` | `POST` | Exploits | Simulates or executes multi-hop exploit chain and outputs Python PoC. |
| `/api/recon/scope` | `POST` | Recon | Passive Certificate Transparency & DNS scope reconnaissance with takeover checks. |
| `/api/fuzzer/semantic` | `POST` | Fuzzing | Semantic fuzzing with dynamic noise stripping and Welch's t-test timing oracle. |
| `/api/oracle/verify-dom` | `POST` | Oracle | Sandboxed Playwright DOM execution verification with screenshot capture. |
| `/api/telemetry/cli-event` | `POST` | Telemetry | Real-time CLI log ingestion from `proxsynth-exec` execution wrappers. |
| `/api/findings/{id}/report` | `GET` | Triage | Generates complete HackerOne / Bug Bounty Markdown vulnerability report. |
| `/api/campaign/run` | `POST` | Campaign | Launches autonomous pentest campaign (Classic Pipeline or Cognitive Hexagon). |
| `/api/fuzzer/abort` | `POST` | Fuzzer | Signals and aborts running parameter fuzzing attacks in real time. |
| `/api/scope/test` | `POST` | Guardrails | Interactive scope sandbox evaluating URL boundaries and dangerous route patterns. |
| `/api/openapi/import` | `POST` | OpenAPI | 1-Click OpenAPI/Swagger specification importer from raw JSON/YAML or URL. |
| `/api/rules` | `GET` / `POST` | Proxy | Lists, adds, or updates forward proxy interception and mock rules. |
| `/ws/terminal` | `WS` | Real-Time | Bidirectional live terminal telemetry and attack graph event streaming. |
| `/ws` | `WS` | Real-Time | Live HTTP traffic interception, breakpoints, and log streaming. |

---

## 🔒 Target Safety & Destructive Tool Annotations

All 97 tools adhere to the official **Model Context Protocol (FastMCP 2.0+) ToolAnnotations Specification**:
* `readOnlyHint`: Indicates tools that only query or observe target state without performing mutations or injections.
* `destructiveHint`: Flags tools that perform active exploitation, rate-limit testing, parameter fuzzing, or entity deletions. Agent harnesses can automatically prompt for human confirmation or enforce sandboxed guardrails before invoking destructive tools.

---

## ⚖️ Legal & Ethical Disclaimer

PROXSYNTH is intended strictly for authorized security assessments, academic research, and defensive auditing under explicit written consent. Users must comply with all applicable local, national, and international cybersecurity laws. The authors assume no liability for misuse.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.
