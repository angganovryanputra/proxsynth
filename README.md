# ⚡ PROXSYNTH: Autonomous AI Interception Proxy & Security Testing Gateway
### The Open-Source Burp Suite & Caido Alternative Built for LLM Pentesting Agents (Claude Code, Cursor, Windsurf, OpenCode, Hermes, Antigravity) via Model Context Protocol (FastMCP)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-FastMCP%202.0%2B-purple.svg)](https://modelcontextprotocol.io)
[![FastMCP Tools](https://img.shields.io/badge/FastMCP%20Tools-57%20Registered-8b5cf6.svg)](#-complete-fastmcp-tools-reference-specification-57-tools)
[![FastAPI](https://img.shields.io/badge/FastAPI-High%20Performance-009688.svg)](https://fastapi.tiangolo.com)
[![Playwright](https://img.shields.io/badge/Playwright-Chromium%20DOM%20Oracle-45ba4b.svg)](https://playwright.dev)
[![Database](https://img.shields.io/badge/SQLite-WAL%20Engine-003B57.svg)](https://sqlite.org)
[![Forward Proxy](https://img.shields.io/badge/Forward%20Proxy-Port%208088-0ea5e9.svg)](#-transparent-runtime-auto-enforcement-sitecustomizepy)
[![TLS MITM](https://img.shields.io/badge/TLS%20MITM-Decryption%20Engine-ef4444.svg)](#-transparent-runtime-auto-enforcement-sitecustomizepy)
[![Auto-Enforcement](https://img.shields.io/badge/Auto--Enforcement-sitecustomize.py-8b5cf6.svg)](#-transparent-runtime-auto-enforcement-sitecustomizepy)
[![Auto-Updater](https://img.shields.io/badge/Auto--Updater-Web%20%26%20MCP-06b6d4.svg)](#-automated-1-click-system--mcp-update-engine)
[![OAST Engine](https://img.shields.io/badge/OAST%20Engine-HTTP%20%7C%20DNS%20%7C%20LDAP-f97316.svg)](#pillar-2-p2-autonomous-multi-protocol-oast-canary-sprayer)
[![Hypothesis Ledger](https://img.shields.io/badge/Working%20Memory-Hypothesis%20Ledger-ec4899.svg)](#pillar-3-p3-agent-working-memory--attack-hypothesis-ledger)
[![DOM Oracle](https://img.shields.io/badge/DOM%20Oracle-Headless%20Sandbox-10b981.svg)](#pillar-4-p4-browser-dom-execution-oracle-sandbox)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#-license)

---

```
  ██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗██╗   ██╗███╗   ██╗████████╗██╗  ██╗
  ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝██╔════╝╚██╗ ██╔╝████╗  ██║╚══██╔══╝██║  ██║
  ██████╔╝██████╔╝██║   ██║ ╚███╔╝ ███████╗ ╚████╔╝ ██╔██╗ ██║   ██║   ███████║
  ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗ ╚════██║  ╚██╔╝  ██║╚██╗██║   ██║   ██╔══██║
  ██║     ██║  ██║╚██████╔╝██╔╝ ██╗███████║   ██║   ██║ ╚████║   ██║   ██║  ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
     ── THE AUTONOMOUS INTERCEPTION PROXY & AGENTIC SECURITY GATEWAY ──
```

---

## 📑 Table of Contents

- [📌 Executive Overview](#-executive-overview)
- [🥊 Head-to-Head Comparison: Proxsynth vs Burp Suite vs Caido vs mitmproxy](#-head-to-head-comparison-why-ai-agents-need-proxsynth)
- [🏗️ System Architecture Design](#️-system-architecture-design)
- [⚡ The 4 Advanced Agentic Pillars (P1 – P4)](#-the-4-advanced-agentic-pillars-p1--p4)
  - [P1: LLM Semantic Response Body Distiller](#pillar-1-p1-llm-semantic-response-body-distiller)
  - [P2: Autonomous Multi-Protocol OAST Canary Sprayer](#pillar-2-p2-autonomous-multi-protocol-oast-canary-sprayer)
  - [P3: Agent Working Memory & Attack Hypothesis Ledger](#pillar-3-p3-agent-working-memory--attack-hypothesis-ledger)
  - [P4: Browser DOM Execution Oracle Sandbox](#pillar-4-p4-browser-dom-execution-oracle-sandbox)
- [🔄 Automated 1-Click System & MCP Update Engine](#-automated-1-click-system--mcp-update-engine)
- [🧰 Complete FastMCP Tools Reference Specification (57 Tools)](#-complete-fastmcp-tools-reference-specification-57-tools)
- [🐍 Transparent Runtime Auto-Enforcement (`sitecustomize.py`)](#-transparent-runtime-auto-enforcement-sitecustomizepy)
- [🎯 Project Scoping, Auto-Vault & Attack Surface Memory](#-project-scoping-auto-vault--attack-surface-memory)
- [🚀 Installation & Quick Start](#-installation--quick-start)
- [🤖 AI Agent Integration Guide](#-ai-agent-integration-guide)
  - [Claude Code & Claude Desktop](#1-claude-desktop--claude-code)
  - [Cursor IDE](#2-cursor-ide)
  - [Windsurf IDE](#3-windsurf-ide)
  - [OpenCode & Hermes Agent](#4-opencode--hermes-agent)
  - [Antigravity IDE & AGY CLI](#5-antigravity-ide--agy-cli)
- [🖥️ Cyberpunk SOC Operator Console Tour](#️-cyberpunk-soc-operator-console-tour)
- [⚙️ Configuration & Environment Variables](#️-configuration--environment-variables)
- [⚖️ Legal & Ethical Disclaimer](#️-legal--ethical-disclaimer)
- [📄 License](#-license)

---

## 📌 Executive Overview

**PROXSYNTH** is a specialized security testing gateway, transparent interception proxy, and real-time observability platform engineered specifically for **Autonomous AI Pentesting Agents** (such as **Claude Code**, **Cursor**, **Windsurf**, **OpenCode**, **Hermes Agent**, or custom LLM security workflows communicating via the **Model Context Protocol (FastMCP)**).

When deploying autonomous AI agents against web applications, cloud APIs, and internal networks, security operators encounter critical operational hurdles that make traditional interception proxies (*Burp Suite*, *Caido*, *mitmproxy*, *OWASP ZAP*) unworkable:

1. **The "Subprocess Scripting Gap & Proxy Evading":** When agents generate standalone exploit scripts (Python `requests`/`httpx`/`aiohttp`, `curl`, `sqlmap`, `ffuf`, `nuclei`) or execute scripts directly in host terminal/bash, outbound HTTP/HTTPS traffic bypasses proxy listeners, TLS CONNECT tunnels produce blind uninspected noise, and scope boundaries are evaded.
2. **Agent Amnesia & Context Drift:** Autonomous LLM loops suffer from context loss between execution steps. Without persistent structured working memory, agents repeat redundant tests, lose track of verified attack paths, and hallucinate testing conclusions.
3. **Context Window Token Exhaustion:** Feeding raw HTTP response bodies (often 100KB–1MB with HTML layout, inline CSS, SVG paths, and base64 assets) into LLM context windows causes immediate token limit blowouts, sluggish inference, and massive API costs.
4. **Blind Vulnerability Invisibility:** Exploiting Blind SSRF, Blind SQL Injection, Out-of-Band XXE, or Log4j/JNDI callbacks is impossible without an integrated multi-protocol listener that correlates callback hits directly to the originating test request.
5. **False Positive Hallucinated XSS:** LLMs frequently guess whether `<script>alert(1)</script>` fired based purely on reflection in raw HTML, producing hallucinated findings on sanitized or non-executing sinks.
6. **Credential Amnesia & Hallucinated Logins:** Agents lose session cookies across loops, hallucinate expired credentials, or repeatedly interrupt human operators with authentication requests.
7. **Lack of Human-in-the-Loop (HITL) Interception:** Operators cannot pause, inspect, modify, or drop high-risk agent requests before they hit production servers.
8. **Siloed Tooling & Reporting:** Agent interactions remain locked in chat transcripts instead of generating industry-standard security deliverables (**HAR 1.2**, **Burp Suite** archives, **Executive Pentest Reports**, **OpenAPI 3.0 Specs**).

**PROXSYNTH solves every single one of these challenges.** Operating as an intelligent, bidirectional gateway between your AI Agent and the target application, PROXSYNTH provides **transparent forward proxy auto-injection**, **runtime Python auto-enforcement (`sitecustomize.py`)**, **TLS MITM decryption engine with dynamic CA generation**, **stateful attack surface mapping**, **autonomous multi-protocol out-of-band callback listening**, **agent working memory hypothesis ledger**, **LLM semantic body distillation**, **deterministic headless DOM execution verification**, **automated 1-click update synchronization**, and a **high-density cyberpunk SOC dashboard**.

---

## 🥊 Head-to-Head Comparison: Why AI Agents Need Proxsynth

Traditional interception proxies were built for human eyes and manual clicks. When autonomous AI agents use them, critical architectural failures emerge:

| Feature / Capability | PROXSYNTH | Burp Suite Professional | Caido | mitmproxy | OWASP ZAP |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Native Model Context Protocol (FastMCP)** | ✅ **Yes (41 Tools)** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Python Script Auto-Interception (`sitecustomize.py`)** | ✅ **Automatic** | ❌ Manual config | ❌ Manual config | ❌ Manual config | ❌ Manual config |
| **Agent Working Memory (Hypothesis Ledger P3)** | ✅ **Built-in** | ❌ No | ❌ No | ❌ No | ❌ No |
| **LLM Semantic Response Distiller (P1: 90% Savings)** | ✅ **Built-in** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Autonomous Multi-Protocol OAST Sprayer (P2)** | ✅ **HTTP/DNS/LDAP** | ⚠️ Burp Collaborator | ❌ No | ❌ No | ⚠️ OAST Addon |
| **Headless DOM Execution Oracle Sandbox (P4)** | ✅ **Playwright Hook** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Automated System & MCP Self-Update Engine** | ✅ **1-Click Web & MCP** | ⚠️ Desktop updater | ⚠️ Desktop updater | ❌ Manual pip | ❌ Manual package |
| **Zero Guardrails by Default (Local & Labs Work)** | ✅ **Yes** | ✅ Yes | ✅ Yes | ✅ Yes | ⚠️ Complex rules |
| **Dual-Track Vulnerability Triage (Confirmed vs Pot)** | ✅ **Automated** | ⚠️ Scanner Tab | ❌ No | ❌ No | ⚠️ Alert Tree |
| **Human-in-the-Loop Intercept Trap via WebSockets** | ✅ **Yes** | ✅ Yes (GUI) | ✅ Yes (GUI) | ✅ Yes (CLI/Web) | ✅ Yes (GUI) |
| **CLI Pentest Tool Correlation (`sqlmap`, `nuclei`)** | ✅ **Auto-Tagged** | ⚠️ If proxied | ⚠️ If proxied | ⚠️ If proxied | ⚠️ If proxied |
| **One-Click Standalone Python PoC Generator** | ✅ **Built-in** | ❌ Extension | ❌ No | ❌ No | ❌ No |
| **Lightweight Headless Deployment (<50MB RAM idle)** | ✅ **FastAPI+Async** | ❌ Heavy Java JVM | ✅ Rust core | ✅ Python | ❌ Java JVM |

---

## 🏗️ System Architecture Design

PROXSYNTH isolates agent reasoning and LLM API traffic from target security testing traffic while aggregating telemetry into a unified operator console.

### 1. High-Level Architectural Diagram

```
                                  ┌────────────────────────────────────────────────────────┐
                                  │            AUTONOMOUS AI PENTESTING AGENTS             │
                                  │      (Claude Code / Cursor / Windsurf / OpenCode)      │
                                  └───────────────┬────────────────────────┬───────────────┘
                                                  │                        │
                   Direct FastMCP Tools (JSON-RPC)│                        │ Subprocess / Host Script Execution
             (send_http_request, render_webpage)  │                        │ (run_pentest_command OR host terminal)
                                                  │                        │
                                                  │                        ▼
                                                  │         ┌──────────────────────────────────────────────┐
                                                  │         │    Transparent Runtime Hook & Environment    │
                                                  │         │  - sitecustomize.py (Auto-loaded by Python)  │
                                                  │         │  - Workspace .env & Shell Envs Injected      │
                                                  │         │  - Auto-routes requests/httpx/aiohttp :8088  │
                                                  │         │  - Auto-trusts .proxsynth_ca certs           │
                                                  │         └──────────────────────┬───────────────────────┘
                                                  │                                │
                                                  ▼                                ▼
       ┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
       │                                  PROXSYNTH GATEWAY ENGINE                                         │
       │                                                                                                   │
       │   ┌───────────────────────────────────┐               ┌───────────────────────────────────────┐   │
       │   │     FastAPI Core & Dashboard      │               │   Built-in Forward Interception Proxy │   │
       │   │        (Port 8000 / HTTP / WS)    │               │         (Port 8088 / HTTP & TLS MITM) │   │
       │   └─────────────────┬─────────────────┘               └───────────────────┬───────────────────┘   │
       │                     │                                                     │                       │
       │                     └───────────────────────┬─────────────────────────────┘                       │
       │                                             │                                                     │
       │                                             ▼                                                     │
       │                        ┌────────────────────────────────────────┐                                 │
       │                        │   Traffic Interception & Evaluation    │                                 │
       │                        │ - Human-in-the-Loop Trap (WebSockets)  │                                 │
       │                        │ - Zero-Prompt Cookie Auto-Injection    │                                 │
       │                        │ - Project Scope Guardrails             │                                 │
       │                        │ - Anti-Self-Loopback Armor             │                                 │
       │                        └────────────────────┬───────────────────┘                                 │
       │                                             │                                                     │
       │         ┌───────────────────────────────────┼───────────────────────────────────┐                 │
       │         │                                   │                                   │                 │
       │         ▼                                   ▼                                   ▼                 │
       │   ┌───────────────┐                  ┌───────────────┐                   ┌───────────────┐        │
       │   │  P1: Semantic │                  │  P3: Working  │                   │  P4: Headless │        │
       │   │ Body Distiller│                  │ Memory Ledger │                   │  DOM Oracle   │        │
       │   └───────┬───────┘                  └───────┬───────┘                   └───────┬───────┘        │
       │           │                                  │                                   │                │
       │           ▼                                  ▼                                   ▼                │
       │   ┌──────────────────────────────────────────────────────────────────────────────────────┐        │
       │   │                   Persistent SQLite WAL Storage (proxsynth.db)                       │        │
       │   │   - HttpLog (Full Raw & Distilled)         - CapturedPayload (Auto-Vault)            │        │
       │   │   - AttackSurface Assets & Endpoints       - TestingHypothesis (Working Memory)      │        │
       │   │   - OastEvent Callbacks                    - Finding (Confirmed & Potential)         │        │
       │   └──────────────────────────────────────────┬───────────────────────────────────────────┘        │
       └──────────────────────────────────────────────┼────────────────────────────────────────────────────┘
                                                      │
                       ┌──────────────────────────────┼──────────────────────────────┐
                       │                              │                              │
                       ▼                              ▼                              ▼
        ┌─────────────────────────────┐┌─────────────────────────────┐┌─────────────────────────────┐
        │   Multi-Protocol OAST Engine││ Cyberpunk SOC Web Dashboard ││  Automated Update Engine    │
        │ - HTTP Callback (:8000/oast)││ - Virtualized Traffic Table ││ - Git Upstream Sync         │
        │ - UDP DNS Listener (:5354)  ││ - Live Intercept Modal      ││ - Dependency Auto-Update    │
        │ - TCP LDAP Listener (:1390) ││ - Attack Surface Topology   ││ - FastMCP update tool       │
        │ - Canary Sprayer (P2)       ││ - Working Memory Kanban     ││ - Real-time WS Progress Bar │
        └─────────────────────────────┘└─────────────────────────────┘└─────────────────────────────┘
```

---

## ⚡ The 4 Advanced Agentic Pillars (P1 – P4)

PROXSYNTH introduces four cutting-edge subsystems specifically designed to elevate AI agents from blind brute-force scripts into disciplined, cognitive offensive security operators.

---

### Pillar 1 (P1): LLM Semantic Response Body Distiller
* **The Problem:** LLM context windows are easily choked by 200KB–1MB raw HTML responses packed with inline SVG icons, Tailwind CSS classes, base64 data URIs, and third-party tracking scripts.
* **The Solution:** Built-in semantic parser ([`backend/body_distiller.py`](file:///d:/PROJECT/01/backend/body_distiller.py)) that strips layout noise while extracting essential attack-surface intelligence:
  - Form actions, input parameter names, types, and hidden CSRF tokens.
  - Interactive clickable links, endpoints, script sources, and API routes.
  - Heading outline, semantic tables, and page metadata.
  - JWT tokens, inline API secrets, and sensitive comments.
  - Truncation of repetitive arrays and dummy lorem ipsum data in JSON responses.
* **Impact:** **85% to 95% reduction in token consumption**, eliminating context window blowouts and accelerating agent reasoning.
* **MCP Integration:** `send_http_request(..., distill_response=True)` and standalone tool `distill_http_response(raw_body="...", content_type="text/html")`.

---

### Pillar 2 (P2): Autonomous Multi-Protocol OAST Canary Sprayer
* **The Problem:** Traditional scanners cannot trigger out-of-band callbacks across non-HTTP channels (DNS, LDAP, XXE).
* **The Solution:** Unified Out-of-Band (OAST) engine ([`backend/oast_engine.py`](file:///d:/PROJECT/01/backend/oast_engine.py) & [`backend/oast_sprayer.py`](file:///d:/PROJECT/01/backend/oast_sprayer.py)):
  - Built-in UDP DNS Tunneling Server (Port `5354`).
  - Built-in TCP LDAP/JNDI Callback Server (Port `1390`).
  - Local HTTP Callback Router (Port `8000/oast/{token}`).
  - Cloud Interactsh integration (`oast.fun`, `interact.sh`).
* **Canary Sprayer:** Ingests any target URL and automatically sprays context-aware canaries across all discovered query parameters, body parameters, and HTTP headers.
* **MCP Integration:** Tool 36 `spray_oast_canaries(target_url="https://target/api", vuln_type="ALL")`.

---

### Pillar 3 (P3): Agent Working Memory & Attack Hypothesis Ledger
* **The Problem:** AI agents operate statelessly between user prompts. They forget what was tested, repeat redundant exploits, and fail to track the progression of a multi-stage attack.
* **The Solution:** Stateful Hypothesis Ledger ([`backend/hypothesis_manager.py`](file:///d:/PROJECT/01/backend/hypothesis_manager.py) + SQLite model `TestingHypothesis`) tracking testing lifecycle states:
  - `PLANNED` ➔ `TESTING` ➔ `CONFIRMED` | `DISPROVEN` | `BLOCKED`
* **Autonomous Agenda Calculation:** `get_testing_agenda` synthesizes pending attack avenues and prevents looping.
* **Real-Time Synchronized UI:** Dedicated "Hypothesis Ledger" dashboard tab featuring metric cards, status filters, and live WebSocket broadcasts (`HYPOTHESIS_CREATED`, `HYPOTHESIS_UPDATED`, `HYPOTHESIS_DELETED`).
* **MCP Integration:** Tools 37–39 (`record_testing_hypothesis`, `get_testing_agenda`, `update_hypothesis_status`).

---

### Pillar 4 (P4): Browser DOM Execution Oracle Sandbox
* **The Problem:** LLMs guess whether an XSS payload executed by searching for the reflected string in the response body. This produces rampant false positives in attribute contexts, encoded blocks, or sanitization sinks.
* **The Solution:** Sandboxed headless Playwright Chromium oracle ([`backend/browser_oracle.py`](file:///d:/PROJECT/01/backend/browser_oracle.py)) that renders the target URL with the payload and hooks:
  - `window.alert`, `window.confirm`, `window.prompt` dialogs.
  - Page console logs and unhandled error events.
  - Dynamic DOM script elements and sink mutations.
* **Deterministic Verdict:** Returns `CONFIRMED_DOM_EXECUTION` with exact dialog message and URL context, or `NO_DOM_EXECUTION`.
* **MCP Integration:** Tool 40 `verify_dom_execution(url="https://target/search", payload="<script>alert(1)</script>")`.

---

## 🔄 Automated 1-Click System & MCP Update Engine

PROXSYNTH includes a fully automated update subsystem designed for seamless long-running continuous deployments.

### 1. Smart Sidebar Notification Banner
- **Only Appears When an Update Is Available:** The update badge in the web sidebar is conditionally rendered (`x-show="updateInfo && updateInfo.update_available"`). If your system is up to date, the sidebar remains completely distraction-free.
- **1-Click Modal Action:** Clicking the update pill launches an interactive modal presenting the incoming commit changelog, current vs upstream version comparison, and an "Update Now" button.

### 2. Simultaneous Web & MCP Server Synchronization
When triggered (either via Web Dashboard or FastMCP):
1. **Git Fetch & Diff:** Evaluates upstream commits without altering unstaged local user notes.
2. **Git Pull Fast-Forward:** Pulls latest frontend assets, backend modules, database migrations, and tool definitions.
3. **Dependency Sync:** Automatically runs `pip install -r requirements.txt` in the virtual environment.
4. **Live WebSocket Telemetry:** Broadcasts `SYSTEM_UPDATE_PROGRESS` events to the browser with percentage and console step logs.
5. **FastMCP Tool Integration:** AI agents can update their own host toolchain autonomously by executing:
   ```python
   # Check if update is available
   update_proxsynth_system(confirm=False)

   # Apply update automatically
   update_proxsynth_system(confirm=True)
   ```

---

## 🧰 Complete FastMCP Tools Reference Specification (57 Tools)

PROXSYNTH's FastMCP server ([`mcp_server.py`](file:///d:/PROJECT/01/mcp_server.py)) exposes **57 enterprise-grade offensive and defensive security tools**:

| # | Tool Name | Subsystem / Pillar | Primary Operational Capability |
| :---: | :--- | :--- | :--- |
| **1** | `set_active_project` | Workspace Scope | Dynamically sets the active project scope for the agent session. |
| **2** | `get_active_project` | Workspace Scope | Retrieves the currently active project name and isolation directory. |
| **3** | `send_http_request` | Core Network | High-performance HTTP/HTTPS dispatcher with auto-auth injection, scope checks, intercept trap, and response body distillation (`distill_response=True`). |
| **4** | `browser_navigate_and_render` | Browser Automation | Headless Playwright engine capturing dynamic DOM and network Fetch/XHR calls. |
| **5** | `render_webpage` | Browser Automation | Visual capture and DOM snapshot utility for single-page apps. |
| **6** | `request_manual_login` | Authentication | Spawns visible browser for human operator to solve CAPTCHA/2FA; auto-imports session cookies. |
| **7** | `run_pentest_command` | Subprocess Execution | Executes terminal commands (`curl`, `sqlmap`, `nuclei`) with auto-proxy routing to `:8088` and audit logging. |
| **8** | `record_test_payload` | Payload Vault | Stores exploit strings into the Payload Vault with categorization and tags. |
| **9** | `get_captured_payloads` | Payload Vault | Queries stored payloads with filtering by vulnerability type, outcome, and keyword. |
| **10** | `get_log_detail` | Telemetry & History | Retrieves full un-truncated HTTP request/response headers and bodies by Log ID. |
| **11** | `get_traffic_history` | Telemetry & History | Lists recent HTTP transactions with status codes, latency, and triage tags. |
| **12** | `report_vulnerability` | Findings & Audit | Flags an HTTP log entry as a confirmed vulnerability finding in the operator ledger. |
| **13** | `get_attack_surface` | Attack Surface | Returns hierarchical topology graph of assets, open ports, and endpoints. |
| **14** | `record_target_asset` | Reconnaissance | Explicitly catalogs a host/machine, IP address, OS, and status in the knowledge graph. |
| **15** | `record_target_service` | Reconnaissance | Records open ports, protocols (TCP/UDP), and service banners for a target asset. |
| **16** | `record_target_endpoint` | Reconnaissance | Catalogs target URL routes, parameters, auth requirements, and testing status (`UNTESTED`, `TESTED_VULNERABLE`). |
| **17** | `generate_oast_token` | OAST Engine | Generates unique correlation token and callback URLs for Out-of-Band testing. |
| **18** | `poll_oast_events` | OAST Engine | Queries captured callbacks (HTTP, DNS, LDAP) for a specific OAST token. |
| **19** | `set_identity_session` | BOLA / IDOR Matrix | Registers secondary user identity cookies (e.g., attacker/victim) for shadow replay testing. |
| **20** | `test_bola_idor` | BOLA / IDOR Matrix | Executes dual-track BOLA replay against an endpoint using registered identity roles. |
| **21** | `mutate_payload` | WAF Evasion | Generates obfuscated payload variations (URL, hex, comment injection, Unicode bypass). |
| **22** | `analyze_waf_response` | WAF Evasion | Fingerprints target WAF vendor (Cloudflare, AWS WAF, Akamai) and recommends bypass tactics. |
| **23** | `infer_hidden_endpoints` | API Reconstructor | Predicts unmapped REST endpoints (admin, actuator, docs, CRUD variants) from observed paths. |
| **24** | `get_attack_paths` | Attack Chains | Synthesizes Kill Chain attack paths from initial recon to Crown Jewels (RCE, DB dump). |
| **25** | `generate_exploit_poc` | PoC Generator | Generates standalone Python PoC scripts, cURL commands, and CVSS/CWE dossiers for findings. |
| **26** | `send_websocket_message` | WebSocket Audit | Transmits and logs WebSocket frames to target socket endpoints for real-time protocol testing. |
| **27** | `fuzz_endpoint` | Parameter Fuzzer | High-speed dictionary fuzzing against marker positions (`§...§`) with status and length delta analysis. |
| **28** | `execute_workflow_sequence` | Business Logic | Executes multi-step stateful workflows with dynamic variable extraction and step-skipping bypass checks. |
| **29** | `test_race_condition` | Concurrency Burst | Executes microsecond-synchronized request bursts using `asyncio.Barrier` to detect double-spending. |
| **30** | `mine_javascript_assets` | JS Recon | Scrapes frontend `.js` bundles for hidden API routes, query params, source maps, and leaked API secrets. |
| **31** | `compare_http_responses` | Diff Engine | Normalizes dynamic noise (timestamps, UUIDs, CSRF nonces) to detect Soft-403/404 anomalies. |
| **32** | `audit_jwt_security` | JWT Security | Audits JWT tokens for Algorithm None bypass, weak HMAC offline brute-forcing, and claim tampering. |
| **33** | `delete_attack_surface_node` | Attack Surface | Prunes stale or false-positive assets, services, or endpoints from the knowledge graph. |
| **34** | `clear_attack_surface_graph` | Attack Surface | Wipes all attack surface records for a project workspace to reset reconnaissance. |
| **35** | `distill_http_response` | **P1: Distiller** | Compresses HTML/JSON bodies into semantic security structures, achieving 85–95% token savings. |
| **36** | `spray_oast_canaries` | **P2: OAST Sprayer** | Discovers input parameters and sprays multi-protocol canaries (HTTP, DNS, LDAP/JNDI, XXE) across a target URL. |
| **37** | `record_testing_hypothesis` | **P3: Memory** | Logs an attack hypothesis into the stateful ledger (`target`, `vuln_type`, `hypothesis`, `parameters`). |
| **38** | `get_testing_agenda` | **P3: Memory** | Synthesizes an actionable testing agenda of unverified hypotheses to eliminate agent loops. |
| **39** | `update_hypothesis_status` | **P3: Memory** | Transitions hypothesis lifecycle state (`PLANNED` ➔ `TESTING` ➔ `CONFIRMED` / `DISPROVEN` / `BLOCKED`). |
| **40** | `verify_dom_execution` | **P4: DOM Oracle** | Executes payload in sandboxed Playwright Chromium to deterministically verify XSS/DOM sinks. |
| **41** | `setup_public_tunnel` | **Tunnel Manager** | Spins up Cloudflare Quick Tunnel / ngrok and binds public URL to OAST listener. |
| **42** | `get_tunnel_status` | **Tunnel Manager** | Returns operational status, public URL, provider, and uptime of active ingress tunnel. |
| **43** | `close_public_tunnel` | **Tunnel Manager** | Terminates active public tunnel and restores local callback base URL. |
| **44** | `add_interception_rule` | **Interception Rules** | Adds headless rule to tamper with headers, rewrite bodies, or return synthetic mock responses. |
| **45** | `list_interception_rules` | **Interception Rules** | Lists all configured match & replace and response mocking rules. |
| **46** | `toggle_interception_rule` | **Interception Rules** | Toggles or updates the enabled state of an interception rule. |
| **47** | `delete_interception_rule` | **Interception Rules** | Deletes an interception rule by ID. |
| **48** | `get_csrf_tokens` | **Anti-CSRF Tracker** | Retrieves all auto-tracked and manual anti-CSRF tokens extracted from HTTP responses. |
| **49** | `set_csrf_token` | **Anti-CSRF Tracker** | Manually sets an anti-CSRF token for target domain to be auto-injected in state-changing calls. |
| **50** | `clear_csrf_tokens` | **Anti-CSRF Tracker** | Clears cached anti-CSRF tokens. |
| **51** | `search_traffic_advanced` | **Traffic Search** | Multi-dimensional traffic search filtering by status range, latency, and full-text bodies. |
| **52** | `analyze_traffic_patterns` | **Traffic Patterns** | Analyzes captured traffic, aggregating unique routes and discovered parameter inventory. |
| **53** | `inspect_graphql_endpoint` | **Protocol Inspector** | Audits GraphQL for introspection disclosure, field suggestion leaks, and query batching. |
| **54** | `audit_websocket_security` | **Protocol Inspector** | Audits WebSocket handshake for CSWSH, plaintext transport, and token leaks in queries. |
| **55** | `run_security_audit_suite` | **CI/CD Auditor** | Runs automated OWASP API security audit across traffic, returning 0–100 score and letter grade. |
| **56** | `generate_audit_ci_report` | **CI/CD Auditor** | Generates publication-grade Markdown or JSON security report for CI/CD pipelines. |
| **57** | `update_proxsynth_system` | **Auto-Updater** | Performs autonomous remote Git update checks and synchronized system upgrades for Web & MCP. |

---

## 🐍 Transparent Runtime Auto-Enforcement (`sitecustomize.py`)

A major architectural innovation of PROXSYNTH is zero-configuration forwarding for Python subprocesses.

When Python boots, it automatically searches `sys.path` and executes [`sitecustomize.py`](file:///d:/PROJECT/01/sitecustomize.py) if present in the workspace or site-packages. PROXSYNTH uses this hook to achieve transparent interception:

1. **Proxy Environment Injection:** Sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` to `http://127.0.0.1:8088`.
2. **CA Root Auto-Trust:** Injects `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, and `CURL_CA_BUNDLE` pointing to `.proxsynth_ca/proxsynth_ca.crt`.
3. **Runtime In-Memory Monkeypatching:**
   - Monkeypatches `requests.Session.__init__` to default `proxies={"http": proxy_url, "https": proxy_url}` and `verify=False`.
   - Monkeypatches `httpx.Client` and `httpx.AsyncClient` to route via the forward proxy.
   - Monkeypatches `urllib.request.build_opener` and `install_opener`.
   - Monkeypatches `aiohttp.ClientSession` to enable `trust_env=True`.
4. **Legitimate Browser Fingerprint Rotation:** If a script uses default library headers (e.g. `python-requests/2.31.0` or `httpx/0.27.0`), `sitecustomize.py` injects realistic desktop browser User-Agents and Client Hints (`Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`) from [`backend/user_agents.py`](file:///d:/PROJECT/01/backend/user_agents.py) to prevent trivial WAF blocks.

---

## 🎯 Project Scoping, Auto-Vault & Attack Surface Memory

### 1. Dual-Track Project Hierarchy & Correlation Headers
All telemetry in PROXSYNTH is multi-tenant and strictly scoped by project:
- Direct FastMCP tool calls pass `project="my_project"`.
- Python scripts import `proxsynth_client.ProxsynthSession(project="my_project")` or `AsyncProxsynthSession`.
- HTTP transactions carry correlation headers:
  ```http
  X-Proxsynth-Project: client-alpha
  X-Proxsynth-Agent: claude-code-01
  ```
- Backwards compatibility: Legacy `X-Proxynth-...` headers and environment variables remain fully supported.

### 2. Automated Script Payload Vault
Whenever a script is executed via `run_pentest_command` or standalone tools, PROXSYNTH's regex scanner ([`backend/payload_vault.py`](file:///d:/PROJECT/01/backend/payload_vault.py)) extracts high-impact payloads (SQLi, XSS, SSRF, Command Injection, Directory Traversal, Template Injection) and automatically registers them into `CapturedPayload` without requiring manual recording calls.

---

## 🚀 Installation & Quick Start

### 1. Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- Git.
- Windows, Linux, or macOS.

### 2. Automatic 1-Click Setup

#### Windows (Command Prompt / PowerShell):
```cmd
git clone https://github.com/proxsynth/proxsynth.git
cd proxsynth
run.bat
```

#### Linux / macOS:
```bash
git clone https://github.com/proxsynth/proxsynth.git
cd proxsynth
chmod +x run.sh install.sh
./run.sh
```

The script automatically sets up the Python virtual environment, installs dependencies from `requirements.txt`, installs Playwright browser engines, generates CA certificates, and launches the Proxsynth platform:
- **FastAPI Web Dashboard & Telemetry API:** `http://127.0.0.1:8000`
- **Forward Interception Proxy:** `http://127.0.0.1:8088`
- **OAST Multi-Protocol Listeners:** DNS UDP `5354` & LDAP TCP `1390`

---

## 🤖 AI Agent Integration Guide

PROXSYNTH seamlessly connects to all leading autonomous AI agent platforms via JSON-RPC Model Context Protocol (FastMCP).

### 1. Claude Desktop & Claude Code
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "d:\\PROJECT\\01\\venv\\Scripts\\python.exe",
      "args": [
        "d:\\PROJECT\\01\\mcp_server.py"
      ],
      "env": {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": "default",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

### 2. Cursor IDE
Add to `.cursor/mcp.json` or Cursor Settings > MCP:
```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "d:/PROJECT/01/venv/Scripts/python.exe",
      "args": ["d:/PROJECT/01/mcp_server.py"],
      "env": {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": "default"
      }
    }
  }
}
```

### 3. Windsurf IDE
Add to `~/.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "d:/PROJECT/01/venv/Scripts/python.exe",
      "args": ["d:/PROJECT/01/mcp_server.py"],
      "env": {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": "default"
      }
    }
  }
}
```

### 4. OpenCode & Hermes Agent
Add to `opencode.json` or `mcp_config.json`:
```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "d:/PROJECT/01/venv/Scripts/python.exe",
      "args": ["d:/PROJECT/01/mcp_server.py"],
      "env": {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": "client-alpha",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

### 5. Antigravity IDE & AGY CLI
Add to your Antigravity configuration `mcp_config.json`:
```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "d:\\PROJECT\\01\\venv\\Scripts\\python.exe",
      "args": ["d:\\PROJECT\\01\\mcp_server.py"],
      "env": {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": "default"
      }
    }
  }
}
```

---

## 🖥️ Cyberpunk SOC Operator Console Tour

PROXSYNTH's web console (`http://127.0.0.1:8000`) is a high-density, cyberpunk-styled security operations dashboard featuring dedicated operator modules:

1. **Proxy Traffic Ledger:** Live table supporting virtual scrolling for 100,000+ records, resizable columns, per-column text/regex filters, and split-pane request/response inspector. Includes "Distill (P1)" semantic view toggle.
2. **Interactive Intercept Trap:** Pause high-risk agent requests before they reach the target. Inspect headers, modify SQLi payloads on the fly, and choose to **Forward** or **Drop**.
3. **Target Attack Surface Knowledge Graph:** Relational asset inventory (`Host -> Port -> Route`) with live testing state tags (`UNTESTED`, `IN_PROGRESS`, `TESTED_CLEAN`, `TESTED_VULNERABLE`).
4. **OAST Interaction Console:** Real-time event log capturing out-of-band HTTP callbacks, DNS resolutions, and JNDI queries. Includes interactive "Spray Canaries (P2)" modal.
5. **Attack Hypothesis Ledger (P3):** Interactive kanban and list view tracking agent working memory. Real-time metric cards (`PLANNED`, `TESTING`, `CONFIRMED`, `DISPROVEN`, `BLOCKED`) with live WebSocket synchronization.
6. **Vulnerability Findings Ledger:** Automated classification of confirmed and potential findings with evidence snippets, CVSS scores, and 1-Click standalone Python PoC generation.
7. **AI Command Audit & Payload Vault:** Complete execution history displaying sanitized commands, exit codes, and auto-captured exploit payloads.
8. **Repeater & Parameter Fuzzer:** Manual replay workbench with baseline diff analyzer, "Distill Response (P1)" toggle, and "Verify DOM (P4)" execution oracle.
9. **Settings & Scope Guardrails:** Scope enforcement, authorized host wildcards, sensitive regex filters, and upstream proxy chaining (e.g. chaining to Burp Suite at `http://127.0.0.1:8080`).

---

## ⚙️ Configuration & Environment Variables

PROXSYNTH is fully customizable via `.env` or system environment variables:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PROXSYNTH_PORT` | `8000` | Port for the FastAPI dashboard and WebSocket server |
| `PROXSYNTH_BACKEND_URL` | `http://127.0.0.1:8000` | Base URL used by FastMCP tools and client SDKs |
| `PROXSYNTH_PROXY_PORT` | `8088` | Port for the Built-in Forward Interception Proxy |
| `PROXSYNTH_PROXY_HOST` | `127.0.0.1` | Host interface bound by the Forward Proxy |
| `PROXSYNTH_DNS_PORT` | `5354` | Port for the built-in UDP DNS OAST callback listener |
| `PROXSYNTH_LDAP_PORT` | `1390` | Port for the built-in TCP LDAP/JNDI OAST callback listener |
| `PROXSYNTH_PROJECT` | `default` | Default workspace project identifier |
| `PROXSYNTH_UPSTREAM_PROXY` | `""` *(empty)* | Optional upstream proxy for chaining (e.g., `http://127.0.0.1:8080`) |
| `PROXSYNTH_DB_PATH` | `./proxsynth.db` | Path to the SQLite WAL database file |
| `PROXSYNTH_API_KEY` | `""` *(empty)* | Optional security token requiring `X-Proxsynth-Key` header |
| `PROXSYNTH_ALLOW_REMOTE` | `false` | When false, restricts dashboard access strictly to loopback (`127.0.0.1`) |
| `PROXSYNTH_MAX_BODY_SIZE` | `524288` (512 KB) | Maximum byte threshold stored per request/response body in SQLite |

---

## ⚖️ Legal & Ethical Disclaimer

> [!CAUTION]
> **PROXSYNTH is engineered strictly for authorized penetration testing, security auditing, red teaming, and academic vulnerability research.**
> Executing security assessments against target systems without explicit, prior written authorization from the system owner is illegal and violates computer fraud regulations. The authors assume no liability for misuse, unauthorized testing, or damage caused by this software. Always test responsibly within authorized scopes.

---

## 📄 License

PROXSYNTH is distributed under the **MIT License**. See [`LICENSE`](file:///d:/PROJECT/01/LICENSE) for details.
