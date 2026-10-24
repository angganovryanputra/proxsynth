# ⚡ PROXSYNTH: Autonomous AI Security Interception Proxy & Testing Gateway
### An open-source interception proxy, security testing gateway, and real-time observability platform engineered for Autonomous AI Pentesting Agents via Model Context Protocol (FastMCP)

[![Release](https://img.shields.io/badge/Release-v0.1.0--beta-orange.svg)](#-overview)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-FastMCP%202.0%2B-purple.svg)](https://modelcontextprotocol.io)
[![FastMCP Tools](https://img.shields.io/badge/FastMCP%20Tools-71%20Registered-8b5cf6.svg)](#-complete-fastmcp-tools-reference-specification-71-tools)
[![FastAPI](https://img.shields.io/badge/FastAPI-High%20Performance-009688.svg)](https://fastapi.tiangolo.com)
[![Playwright](https://img.shields.io/badge/Playwright-Chromium%20DOM%20Oracle-45ba4b.svg)](https://playwright.dev)
[![Database](https://img.shields.io/badge/SQLite-WAL%20Engine-003B57.svg)](https://sqlite.org)
[![Forward Proxy](https://img.shields.io/badge/Forward%20Proxy-Port%208088-0ea5e9.svg)](#-transparent-runtime-auto-enforcement-sitecustomizepy)
[![TLS MITM](https://img.shields.io/badge/TLS%20MITM-Decryption%20Engine-ef4444.svg)](#-transparent-runtime-auto-enforcement-sitecustomizepy)
[![Auto-Enforcement](https://img.shields.io/badge/Auto--Enforcement-sitecustomize.py-8b5cf6.svg)](#-transparent-runtime-auto-enforcement-sitecustomizepy)
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

- [📌 Overview](#-overview)
- [🥊 Comparison with Traditional Proxies](#-comparison-with-traditional-proxies)
- [🏗️ System Architecture](#️-system-architecture)
- [⚡ The 4 Agentic Pillars (P1 – P4)](#-the-4-agentic-pillars-p1--p4)
  - [P1: LLM Semantic Response Body Distiller](#pillar-1-p1-llm-semantic-response-body-distiller)
  - [P2: Autonomous Multi-Protocol OAST Canary Sprayer](#pillar-2-p2-autonomous-multi-protocol-oast-canary-sprayer)
  - [P3: Agent Working Memory & Attack Hypothesis Ledger](#pillar-3-p3-agent-working-memory--attack-hypothesis-ledger)
  - [P4: Browser DOM Execution Oracle Sandbox](#pillar-4-p4-browser-dom-execution-oracle-sandbox)
- [🚀 Autonomous Campaign Orchestration & Zero-Human Testing](#-autonomous-campaign-orchestration--zero-human-testing)
  - [Autonomous Campaign Orchestrator ('God Tool')](#1-autonomous-campaign-orchestrator-god-tool)
  - [Autonomous Web Spider & Form Discovery Engine](#2-autonomous-web-spider--form-discovery-engine)
  - [Autonomous Re-Authentication Macro & Session Keeper](#3-autonomous-re-authentication-macro--session-keeper)
  - [Unified Deterministic Verification Gate](#4-unified-deterministic-verification-gate)
  - [Adaptive Rate-Limiting & Backoff Engine](#5-adaptive-rate-limiting--backoff-engine)
- [🔬 Advanced Vulnerability Audit Engines](#-advanced-vulnerability-audit-engines)
  - [Broken Function Level Authorization (BFLA) Matrix](#1-broken-function-level-authorization-bfla-matrix)
  - [Mass Assignment & Object Injection Engine](#2-mass-assignment--object-injection-engine)
  - [Numeric Business Logic & Currency Fuzzer](#3-numeric-business-logic--currency-fuzzer)
  - [Differential Injection Oracle & Noise Normalization](#4-differential-injection-oracle--noise-normalization)
  - [Nuclei v3 YAML Exploit Template Generator](#5-nuclei-v3-yaml-exploit-template-generator)
- [🛡️ Key Security & Operational Modules](#️-key-security--operational-modules)
  - [OWASP API Security & CI/CD Auditor](#1-owasp-api-security--cicd-auditor)
  - [AI Activity Command & Payload Studio](#2-ai-activity-command--payload-studio)
  - [Active Project Context Synchronization](#3-active-project-context-synchronization)
  - [Zero-Prompt Session & Cookie Credentials Manager](#4-zero-prompt-session--cookie-credentials-manager)
  - [Automated 1-Click System & MCP Self-Updater](#5-automated-1-click-system--mcp-self-updater)
- [🧰 Complete FastMCP Tools Reference Specification (71 Tools)](#-complete-fastmcp-tools-reference-specification-71-tools)
- [🐍 Transparent Runtime Auto-Enforcement (`sitecustomize.py`)](#-transparent-runtime-auto-enforcement-sitecustomizepy)
- [🚀 Quick Start & Installation](#-quick-start--installation)
- [🤖 AI Agent Integration Guide](#-ai-agent-integration-guide)
- [🖥️ SOC Web Operator Console](#️-soc-web-operator-console)
- [⚙️ Configuration Reference](#️-configuration-reference)
- [⚖️ Legal & Ethical Disclaimer](#️-legal--ethical-disclaimer)
- [📄 License](#-license)

---

## 📌 Overview

**PROXSYNTH** (`v0.1.0-beta`) is an open-source interception proxy, security testing gateway, and real-time observability platform engineered specifically for **Autonomous AI Pentesting Agents** (including Claude Code, Cursor, Windsurf, OpenCode, Hermes, and Antigravity) communicating via the **Model Context Protocol (FastMCP 2.0+)**.

When deploying autonomous AI agents against complex web applications, single-page apps (SPAs), microservices, and APIs, traditional penetration testing proxies (*Burp Suite*, *Caido*, *mitmproxy*, *OWASP ZAP*) fall short because they were designed for manual human point-and-click workflows. Operators face critical operational bottlenecks:

1. **Subprocess Scripting & Proxy Bypass:** Scripts generated by agents (`requests`, `httpx`, `aiohttp`, `curl`, `sqlmap`, `nuclei`) bypass local proxy listeners and escape testing scope boundaries.
2. **Context Window Token Exhaustion:** Raw HTTP responses (100KB–1MB of HTML, CSS, SVG, base64) flood LLM context windows, causing prompt degradation and severe API token costs.
3. **Agent Amnesia & Context Drift:** LLMs lose state across iterative prompts, repeating already completed tests or losing track of confirmed exploit chains.
4. **Blind Vulnerability Invisibility:** Exploiting Blind SSRF, Out-of-Band SQLi, or JNDI/LDAP injections requires an integrated multi-protocol listener correlated directly with request tokens.
5. **Hallucinated XSS Findings:** LLMs often mistake harmless reflected strings for valid XSS without verifying browser DOM script execution.
6. **Session Expiry Blockers:** Long-running security campaigns fail silently when auth cookies expire, requiring repeated human intervention to log back in.
7. **Rate Limit Bans (HTTP 429):** Aggressive fuzzing triggers WAF blocks and IP bans unless rate limiting is dynamically adapted.

**PROXSYNTH resolves these challenges out of the box.** It provides transparent runtime process interception, TLS MITM decryption with on-the-fly CA generation, semantic token compression, multi-protocol out-of-band canary listening, an agent working memory ledger, deterministic Playwright DOM verification, an automated OWASP API security auditor, a fire-and-forget autonomous campaign orchestrator, and an interactive cyberpunk SOC dashboard.

---

## 🥊 Comparison with Traditional Proxies

| Feature / Capability | PROXSYNTH (v0.1.0-beta) | Burp Suite Pro | Caido | mitmproxy | OWASP ZAP |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Native Model Context Protocol (FastMCP)** | ✅ **Yes (71 Tools)** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Autonomous Campaign Orchestrator (1-Command)**| ✅ **Built-in** | ❌ Manual | ❌ Manual | ❌ No | ⚠️ Quick Scan |
| **Transparent Python Script Interception (`sitecustomize.py`)** | ✅ **Automatic** | ❌ Manual config | ❌ Manual config | ❌ Manual config | ❌ Manual config |
| **Agent Working Memory (Hypothesis Ledger P3)** | ✅ **Built-in** | ❌ No | ❌ No | ❌ No | ❌ No |
| **LLM Semantic Response Distiller (P1: 90% Token Savings)** | ✅ **Built-in** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Autonomous Multi-Protocol OAST Sprayer (P2)** | ✅ **HTTP/DNS/LDAP** | ⚠️ Collaborator | ❌ No | ❌ No | ⚠️ Addon |
| **Headless DOM Execution Oracle Sandbox (P4)** | ✅ **Playwright Hook** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Autonomous Re-Authentication Macro & Session Keeper** | ✅ **Built-in** | ⚠️ Session Rules | ❌ No | ❌ No | ⚠️ ZAP Scripts |
| **Broken Function Level Auth (BFLA) Matrix Engine** | ✅ **Built-in** | ⚠️ AuthMatrix ext | ❌ No | ❌ No | ❌ No |
| **Deterministic Verification Gate (Zero False Positive)** | ✅ **Built-in** | ❌ Manual | ❌ No | ❌ No | ❌ No |
| **Adaptive Rate-Limit Backoff & SOCKS5 Pool Rotation** | ✅ **Built-in** | ⚠️ Match/Replace | ❌ No | ❌ No | ❌ No |
| **Nuclei v3 YAML Exploit Template Generator** | ✅ **Built-in** | ⚠️ Extension | ❌ No | ❌ No | ❌ No |
| **OWASP API Security Top 10 CI/CD Auditor** | ✅ **Built-in** | ⚠️ Scanner Tab | ❌ No | ❌ No | ⚠️ Alert Tree |
| **AI Activity CLI Repeater & Payload Studio** | ✅ **Built-in** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Human-in-the-Loop Intercept Trap via WebSockets** | ✅ **Yes** | ✅ Yes (GUI) | ✅ Yes (GUI) | ✅ Yes (CLI/Web) | ✅ Yes (GUI) |
| **Automated System & MCP Self-Update Engine** | ✅ **1-Click Synced** | ⚠️ Desktop updater | ⚠️ Desktop updater | ❌ Manual pip | ❌ Manual pkg |
| **Lightweight Footprint (<60MB RAM idle)** | ✅ **FastAPI + Async** | ❌ Java JVM | ✅ Rust core | ✅ Python | ❌ Java JVM |

---

## 🏗️ System Architecture

```
                                  ┌────────────────────────────────────────────────────────┐
                                  │            AUTONOMOUS AI PENTESTING AGENTS             │
                                  │      (Claude Code / Cursor / Windsurf / Antigravity)   │
                                  └───────────────┬────────────────────────┬───────────────┘
                                                  │                        │
                    Direct FastMCP Tools (JSON-RPC)│                        │ Subprocess / CLI Script Execution
               (send_http_request, render_webpage) │                        │ (run_pentest_command OR host terminal)
                                                  │                        │
                                                  │                        ▼
                                                  │         ┌──────────────────────────────────────────────┐
                                                  │         │    Transparent Runtime Hook & Environment    │
                                                  │         │  - sitecustomize.py (Auto-loaded by Python)  │
                                                  │         │  - Auto-routes requests/httpx/aiohttp :8088  │
                                                  │         │  - Auto-trusts .proxsynth_ca root cert       │
                                                  │         │  - Scopes to Active Project context          │
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
        │                                             ▼                                                     │
        │                        ┌────────────────────────────────────────┐                                 │
        │                        │   Traffic Interception & Evaluation    │                                 │
        │                        │ - Interactive Breakpoint Trap (WS)     │                                 │
        │                        │ - Zero-Prompt Cookie Auto-Injection    │                                 │
        │                        │ - Dynamic Project Scope Guardrails     │                                 │
        │                        │ - Rotating Legitimate Browser Headers  │                                 │
        │                        │ - Adaptive Rate-Limiter Backoff (:429) │                                 │
        │                        └────────────────────┬───────────────────┘                                 │
        │                                             │                                                     │
        │   ┌─────────────────────────────────────────┴─────────────────────────────────────────┐           │
        │   ▼                                         ▼                                         ▼           │
        │ ┌─────────────────────────────┐ ┌─────────────────────────────┐ ┌─────────────────────────────┐   │
        │ │   AUTONOMOUS WORKBENCH      │ │     AUDIT & FUZZING ENGINES │ │     CORE AGENTIC PILLARS    │   │
        │ │ - Campaign Orchestrator     │ │ - BFLA & BOLA Matrix        │ │ - P1: Semantic Distiller    │   │
        │ │ - Web Spider & Form Finder  │ │ - Mass Assignment Engine    │ │ - P2: Multi-Protocol OAST   │   │
        │ │ - Re-Auth Macro Keeper      │ │ - Numeric Logic Fuzzer      │ │ - P3: Hypothesis Memory     │   │
        │ │ - Verification Gate         │ │ - Differential Injection    │ │ - P4: Browser DOM Oracle    │   │
        │ └──────────────┬──────────────┘ └──────────────┬──────────────┘ └──────────────┬──────────────┘   │
        │                │                               │                               │                  │
        │                └───────────────────────┬───────┴───────────────────────────────┘                  │
        │                                        ▼                                                          │
        │   ┌──────────────────────────────────────────────────────────────────────────────────────┐        │
        │   │                   Persistent SQLite WAL Storage (proxsynth.db)                       │        │
        │   │   - HttpLog (Raw & Distilled)              - CapturedPayload (Vault)                 │        │
        │   │   - Target Assets & Endpoints Graph        - TestingHypothesis (Working Memory)      │        │
        │   │   - OastEvent Callbacks                    - Finding (Confirmed & Potential)         │        │
        │   │   - AgentCommandLog (CLI Audits)           - ActiveSession (Auth Cookies & Macros)   │        │
        │   └──────────────────────────────────────────┬───────────────────────────────────────────┘        │
        └──────────────────────────────────────────────┼────────────────────────────────────────────────────┘
                                                       │
                        ┌──────────────────────────────┼──────────────────────────────┐
                        │                              │                              │
                        ▼                              ▼                              ▼
         ┌─────────────────────────────┐┌─────────────────────────────┐┌─────────────────────────────┐
         │   Multi-Protocol OAST Engine││ Cyberpunk SOC Web Dashboard ││  CI/CD Security Auditor     │
         │ - HTTP Callback (:8000/oast)││ - Autonomous Campaign Studio││ - OWASP API Security Top 10 │
         │ - UDP DNS Listener (:5354)  ││ - Live Traffic Intercept    ││ - Automated Scorecard (A-F) │
         │ - TCP LDAP Listener (:1390) ││ - Attack Surface Topology   ││ - SARIF 2.1.0 & Markdown    │
         │ - Canary Sprayer (P2)       ││ - Working Memory Kanban     ││ - Nuclei v3 YAML Generator  │
         └─────────────────────────────┘└─────────────────────────────┘└─────────────────────────────┘
```

---

## ⚡ The 4 Agentic Pillars (P1 – P4)

PROXSYNTH introduces four architectural pillars specifically engineered to elevate AI agents from blind scripts into disciplined offensive security operators.

---

### Pillar 1 (P1): LLM Semantic Response Body Distiller
* **The Problem:** LLM context windows are easily overwhelmed by 100KB–1MB raw HTML responses packed with CSS classes, SVG assets, scripts, and layout markup.
* **The Solution:** Built-in semantic parser ([`backend/body_distiller.py`](file:///d:/PROJECT/01/backend/body_distiller.py)) that strips presentation noise while extracting essential attack-surface intelligence:
  - Form actions, input parameter names, input types, and anti-CSRF tokens.
  - Interactive endpoints, anchor links, script sources, and API routes.
  - Page headings, semantic data tables, and metadata.
  - JWT tokens, exposed API keys, and sensitive comments.
  - Structural compaction of large repetitive JSON arrays.
* **Impact:** **85% to 95% reduction in token consumption**, eliminating context window blowouts and accelerating agent reasoning.
* **MCP Integration:** `send_http_request(..., distill_response=True)` and standalone tool `distill_http_response(raw_body="...", content_type="text/html")`.

---

### Pillar 2 (P2): Autonomous Multi-Protocol OAST Canary Sprayer
* **The Problem:** Out-of-band vulnerabilities (Blind SSRF, Blind SQLi, Out-of-Band XXE, Log4Shell/JNDI) cannot be detected without external callback listeners.
* **The Solution:** Unified Out-of-Band (OAST) engine ([`backend/oast_engine.py`](file:///d:/PROJECT/01/backend/oast_engine.py) & [`backend/oast_sprayer.py`](file:///d:/PROJECT/01/backend/oast_sprayer.py)):
  - Built-in UDP DNS Tunneling Server (Port `5354`).
  - Built-in TCP LDAP/JNDI Callback Server (Port `1390`).
  - Local HTTP Callback Router (Port `8000/oast/{token}`).
  - Cloud Interactsh integration (`oast.fun`, `interact.sh`).
* **Canary Sprayer:** Ingests any target URL and automatically sprays context-aware canaries across all discovered query parameters, body parameters, and HTTP headers.
* **MCP Integration:** Tool `spray_oast_canaries(target_url="https://target/api", vuln_types=["ssrf", "dns", "log4j", "xxe"])`.

---

### Pillar 3 (P3): Agent Working Memory & Attack Hypothesis Ledger
* **The Problem:** AI agents operate statelessly between user prompts. They forget what was tested, repeat redundant exploits, and fail to track the progression of a multi-stage attack.
* **The Solution:** Stateful Hypothesis Ledger ([`backend/hypothesis_manager.py`](file:///d:/PROJECT/01/backend/hypothesis_manager.py) + SQLite model `TestingHypothesis`) tracking testing lifecycle states:
  - `PLANNED` ➔ `TESTING` ➔ `CONFIRMED` | `DISPROVEN` | `BLOCKED`
* **Autonomous Agenda Calculation:** `get_testing_agenda` synthesizes pending attack avenues and prevents looping.
* **Real-Time Synchronized UI:** Dedicated "Hypothesis Ledger" dashboard tab featuring metric cards, status filters, and live WebSocket broadcasts (`HYPOTHESIS_CREATED`, `HYPOTHESIS_UPDATED`, `HYPOTHESIS_DELETED`).
* **MCP Integration:** Tools `record_testing_hypothesis`, `get_testing_agenda`, `update_hypothesis_status`.

---

### Pillar 4 (P4): Browser DOM Execution Oracle Sandbox
* **The Problem:** LLMs guess whether an XSS payload executed by searching for the reflected string in the response body. This produces rampant false positives in attribute contexts, encoded blocks, or sanitization sinks.
* **The Solution:** Sandboxed headless Playwright Chromium oracle ([`backend/browser_oracle.py`](file:///d:/PROJECT/01/backend/browser_oracle.py)) that renders the target URL with the payload and hooks:
  - `window.alert`, `window.confirm`, `window.prompt` dialogs.
  - Page console logs and unhandled error events.
  - Dynamic DOM script elements and sink mutations.
* **Deterministic Verdict:** Returns `CONFIRMED_DOM_EXECUTION` with exact dialog message and URL context, or `NO_DOM_EXECUTION`.
* **MCP Integration:** Tool `verify_dom_execution(url="https://target/search", payload="<script>alert(1)</script>")`.

---

## 🚀 Autonomous Campaign Orchestration & Zero-Human Testing

PROXSYNTH enables end-to-end autonomous penetration testing designed to run without micro-management or step-by-step instructions.

---

### 1. Autonomous Campaign Orchestrator ('God Tool')
Located in [`backend/campaign_orchestrator.py`](file:///d:/PROJECT/01/backend/campaign_orchestrator.py) and exposed via FastMCP `run_autonomous_security_campaign` and `POST /api/campaign/run`:
- **Single-Command Execution:** Takes a target URL and project name, then coordinates every subsystem asynchronously in the background.
- **Full Pentest Lifecycle:**
  1. *Discovery & Spidering:* Crawls internal routes and extracts HTML form schemas.
  2. *JavaScript Recon:* Mines scripts for leaked tokens and hidden endpoints.
  3. *OAST Spraying:* Sprays multi-protocol canaries across observed parameters.
  4. *Access Matrix Audit:* Tests Broken Function Level Authorization (BFLA) and BOLA/IDOR.
  5. *Business Logic & Injection:* Fuzzes numeric logic, mass assignment, and differential SQLi/SSTI.
  6. *Deterministic Verification:* Passes candidates through verification gates to discard false positives.
- **Executive Summary:** Returns a token-efficient executive breakdown of attack surface, testing statistics, and verified critical findings.

---

### 2. Autonomous Web Spider & Form Discovery Engine
Located in [`backend/spider_engine.py`](file:///d:/PROJECT/01/backend/spider_engine.py):
- Recursively traverses same-origin links up to configurable depth (`max_depth=2`, `max_pages=25`).
- Parses HTML documents to identify `<form action="..." method="...">` tags, form field names, parameter types, default values, and buttons.
- Automatically stores newly discovered endpoints in the **Target Knowledge Graph** and schedules them for vulnerability auditing.

---

### 3. Autonomous Re-Authentication Macro & Session Keeper
Located in [`backend/auth_macro.py`](file:///d:/PROJECT/01/backend/auth_macro.py):
- Solves "login amnesia" during long multi-hour test campaigns.
- Operators or agents register an authentication recipe: login URL, HTTP method, JSON payload, and JSONPath to extract bearer tokens or cookies.
- When an ongoing test receives an `HTTP 401 Unauthorized` or `HTTP 403 Forbidden` response, Proxynth's session keeper transparently executes the re-authentication recipe in the background, updates the credential vault, and retries the request seamlessly.

---

### 4. Unified Deterministic Verification Gate
Located in [`backend/verification_gate.py`](file:///d:/PROJECT/01/backend/verification_gate.py):
- Discards unprovable exploit attempts before they clutter reports or mislead the operator.
- Routes candidate findings through modality-specific verification oracles:
  - **Reflected & DOM XSS:** Headless Playwright Chromium executes the payload and checks for real DOM dialog triggers.
  - **Time-Based Injection:** Compares baseline response times with delayed payloads using statistical Z-score analysis.
  - **Out-of-Band SSRF/RCE:** Checks for actual HTTP/DNS/LDAP callback events recorded in the SQLite database.

---

### 5. Adaptive Rate-Limiting & Backoff Engine
Located in [`backend/adaptive_limiter.py`](file:///d:/PROJECT/01/backend/adaptive_limiter.py):
- Automatically intercepts `HTTP 429 Too Many Requests` responses across the forward proxy and `send_http_request`.
- Honors target `Retry-After` headers and calculates exponential backoff with jitter.
- Coordinates transparent upstream proxy pool rotation (e.g., rotating SOCKS5 proxies) to preserve operational stealth and avoid IP bans.

---

## 🔬 Advanced Vulnerability Audit Engines

---

### 1. Broken Function Level Authorization (BFLA) Matrix
Located in [`backend/bfla_engine.py`](file:///d:/PROJECT/01/backend/bfla_engine.py):
- Audits OWASP API5:2023 vulnerabilities where administrative or sensitive functionality is improperly exposed.
- Tests endpoints against high-privilege (`admin`), unprivileged (`user`), and unauthenticated (`anonymous`) roles.
- Employs HTTP method tampering (`GET` vs `POST` vs `DELETE` vs `PATCH`) to discover hidden administrative actions.

---

### 2. Mass Assignment & Object Injection Engine
Located in [`backend/mass_assignment_engine.py`](file:///d:/PROJECT/01/backend/mass_assignment_engine.py):
- Audits OWASP API3:2023 by testing whether target endpoints inadvertently bind client-provided parameters to internal data models.
- Injects sensitive properties (`is_admin`, `role`, `verified`, `balance`, `credits`, `permissions`) into JSON request bodies.
- Compares response mutations and persistent account state changes to flag exploitable parameter binding.

---

### 3. Numeric Business Logic & Currency Fuzzer
Located in [`backend/logic_fuzzer.py`](file:///d:/PROJECT/01/backend/logic_fuzzer.py):
- Audits financial, quantity, and workflow business logic flaws.
- Tests negative quantities (`-1`, `-9999`), integer overflow boundaries (`2147483648`, `9223372036854775808`), zero-price tampering (`0.00`, `0.0001`), and floating-point precision flaws.
- Injects currency switching mismatches (`USD` vs `IDR` vs `JPY`) between checkout steps to detect unit-conversion arbitrage.

---

### 4. Differential Injection Oracle & Noise Normalization
Located in [`backend/differential_oracle.py`](file:///d:/PROJECT/01/backend/differential_oracle.py):
- Validates SQL injection, Server-Side Template Injection (SSTI), and Command Injection through automated differential analysis.
- Strips dynamic nonces, session IDs, timestamps, and anti-CSRF tokens to eliminate false variances.
- Compares Boolean true/false pair responses and calculates statistical response size/status deltas.

---

### 5. Nuclei v3 YAML Exploit Template Generator
Located in [`backend/nuclei_generator.py`](file:///d:/PROJECT/01/backend/nuclei_generator.py):
- Automatically converts confirmed vulnerability findings from Proxynth into standardized **Nuclei v3 YAML templates**.
- Generates reproducible HTTP requests, path variables, and deterministic matchers (status codes, regex words, DSL expressions) ready for CI/CD regression testing.

---

## 🛡️ Key Security & Operational Modules

### 1. OWASP API Security & CI/CD Auditor
Located in [`backend/ci_auditor.py`](file:///d:/PROJECT/01/backend/ci_auditor.py) and accessible via the **Security Audit** tab:
* **Passive Automated Assessment:** Continuously analyzes proxy-captured HTTP/HTTPS traffic against OWASP API Security Top 10 rules without intrusive scans.
* **5 Key Check Categories:**
  1. *Missing Security Headers:* Detects absent HSTS (`Strict-Transport-Security`), `X-Content-Type-Options: nosniff`, and `X-Frame-Options` / CSP clickjacking defenses.
  2. *CORS Misconfiguration:* Flags dangerous `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true`.
  3. *Insecure Cookie Flags:* Identifies session and authentication cookies lacking `HttpOnly` (XSS theft risk) or `Secure` flags.
  4. *Query Parameter Credential Exposure:* Alerts on sensitive tokens (`password`, `apikey`, `secret`, `bearer`) exposed in URL query parameters.
  5. *Information & Secret Disclosure:* Regex scanner for exposed AWS keys, GitHub tokens, Stripe secrets, JWTs, stack traces, and internal RFC1918 IP addresses in response bodies.
* **Scorecards & Grades:** Calculates an objective security score (0–100) with letter grades (**A+** to **F**) and remediation guidance.
* **Publication-Grade Reports:** Generates Markdown, JSON, and SARIF 2.1.0 reports ready for pentest deliverables or CI/CD pipelines.

---

### 2. AI Activity Command & Payload Studio
Accessible via the **AI Activity** tab:
* **CLI Repeater:** Reproduce and debug agent terminal commands in an interactive workbench. Inspect command requests side-by-side with raw server responses, stdout, stderr, and exit codes.
* **Payload Sandbox & Vault:** Re-test security payloads against target endpoints with automatic reflection verification, WAF evasion analysis, and auto-registration in the persistent payload vault.
* **Token Economical:** Re-running commands and replaying payloads in the workbench preserves LLM tokens by allowing fine-grained manual and semi-automated adjustments.

---

### 3. Active Project Context Synchronization
* **Workspace Isolation:** Keep engagements, targets, and clients cleanly segregated.
* **Persistent Forward Proxy Tagging:** Selecting a project in the UI automatically synchronizes with the proxy engine (`/api/projects/active`). Any browser traffic passing through port `8088` is automatically categorized into the active project without requiring custom headers.
* **Real-time Live Scope Filtering:** Telemetry tables, Repeater tabs, Fuzzers, and WebSocket feeds display strictly what belongs to the active project scope.

---

### 4. Zero-Prompt Session & Cookie Credentials Manager
* **Direct Credentials Paste:** Paste session cookies (`session=...; auth=...`) or custom headers directly via the UI modal or FastMCP tools.
* **Target-Host Auto-Injection:** Automatically injects valid session cookies and authorization tokens into matching outgoing target requests.
* **Eliminate Login Amnesia:** Agents maintain persistent authentication states across test sequences without repeatedly asking the operator to re-authenticate.

---

### 5. Automated 1-Click System & MCP Self-Updater
* **Notification Pill:** Appears in the sidebar only when upstream Git commits are detected.
* **Synchronized Web & MCP Upgrades:** Pulls updates, applies database schema changes, and synchronizes Python dependencies without wiping local project files or active configurations.
* **FastMCP Tool:** Agents can self-update their host toolchain via `update_proxsynth_system(confirm=True)`.

---

## 🧰 Complete FastMCP Tools Reference Specification (71 Tools)

PROXSYNTH's FastMCP server ([`mcp_server.py`](file:///d:/PROJECT/01/mcp_server.py)) exposes **71 enterprise-grade security tools** categorized across core offensive operations:

### Category A: Autonomous Campaign & Discovery (Tools 1 – 6)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **1** | `run_autonomous_security_campaign` | `target_url`, `project`, `max_depth`, `deep_verify` | Executes the complete autonomous end-to-end security campaign in a single command. |
| **2** | `spider_and_crawl_target` | `root_url`, `project`, `max_depth`, `max_pages` | Recursively crawls target web application, extracts HTML forms, and logs endpoints. |
| **3** | `register_auth_recipe` | `domain`, `login_url`, `payload`, `token_json_path` | Registers automated login recipe for transparent re-authentication when sessions expire. |
| **4** | `execute_reauthentication` | `domain` | Manually triggers execution of the registered authentication recipe to refresh tokens. |
| **5** | `verify_vulnerability_candidate` | `finding_id`, `log_id`, `verification_type` | Validates vulnerability candidates through deterministic DOM, timing, or OAST oracles. |
| **6** | `mine_javascript_assets` | `content_or_url`, `project` | Mines JS bundles for hidden endpoints, query parameters, source maps, and leaked secrets. |

### Category B: Core Network, Browser & Proxy Trap (Tools 7 – 13)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **7** | `send_http_request` | `url`, `method`, `headers`, `body`, `distill_response` | HTTP/HTTPS dispatcher with auto-auth injection, scope checks, intercept trap, and distillation. |
| **8** | `browser_navigate_and_render` | `url`, `wait_for_selector`, `timeout_ms` | Headless Playwright engine capturing dynamic DOM and network Fetch/XHR calls. |
| **9** | `render_webpage` | `url`, `render_type` | Visual screenshot capture and DOM snapshot utility for single-page applications. |
| **10** | `request_manual_login` | `target_url`, `instruction` | Spawns visible browser for human operator to solve CAPTCHA/2FA; auto-imports cookies. |
| **11** | `run_pentest_command` | `command`, `cwd`, `timeout_seconds` | Executes terminal commands (`curl`, `sqlmap`, `nuclei`) with auto-proxy routing to `:8088`. |
| **12** | `get_log_detail` | `log_id` | Retrieves full un-truncated HTTP request/response headers and bodies by Log ID. |
| **13** | `get_traffic_history` | `project`, `limit`, `filter_status` | Lists recent HTTP transactions with status codes, latency, and triage tags. |

### Category C: Agent Working Memory & Hypotheses (Tools 14 – 16)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **14** | `record_testing_hypothesis` | `target`, `vuln_type`, `hypothesis`, `parameters` | Logs an attack hypothesis into the stateful ledger tracking agent testing state. |
| **15** | `get_testing_agenda` | `project` | Synthesizes an actionable testing agenda of unverified hypotheses to eliminate agent loops. |
| **16** | `update_hypothesis_status` | `hypothesis_id`, `status`, `evidence_notes` | Transitions hypothesis lifecycle state (`PLANNED` -> `TESTING` -> `CONFIRMED` / `DISPROVEN` / `BLOCKED`). |

### Category D: Advanced Vulnerability Audit Engines (Tools 17 – 23)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **17** | `audit_bfla_permissions` | `endpoint_url`, `privileged_role`, `unprivileged_role` | Audits Broken Function Level Authorization against high vs low privilege accounts. |
| **18** | `audit_mass_assignment` | `endpoint_url`, `base_payload`, `method` | Injects sensitive attributes (`is_admin`, `role`) into bodies to detect mass assignment. |
| **19** | `audit_numeric_business_logic` | `endpoint_url`, `target_param`, `base_payload` | Fuzzes numeric parameters with negative numbers, overflow boundaries, and zero prices. |
| **20** | `audit_differential_injection` | `endpoint_url`, `injection_param`, `vuln_type` | Validates injection vulnerabilities via noise normalization and statistical delta analysis. |
| **21** | `audit_jwt_security` | `token`, `test_url` | Audits JWT tokens for Algorithm None bypass, weak HMAC brute-forcing, and tampering. |
| **22** | `audit_websocket_security` | `url` | Audits WebSocket handshake for CSWSH, plaintext transport, and token leaks. |
| **23** | `inspect_graphql_endpoint` | `url` | Audits GraphQL for introspection disclosure, field suggestion leaks, and batching attacks. |

### Category E: Multi-Protocol OAST & Canary Sprayer (Tools 24 – 26)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **24** | `generate_oast_token` | `vuln_type`, `description` | Generates unique correlation token and callback URLs for Out-of-Band testing. |
| **25** | `poll_oast_events` | `token` | Queries captured callbacks (HTTP, DNS UDP 5354, LDAP TCP 1390) for an OAST token. |
| **26** | `spray_oast_canaries` | `target_url`, `vuln_types` | Ingests target URL and sprays context-aware canaries across all discovered inputs. |

### Category F: Access Control & BOLA / IDOR Testing (Tools 27 – 30)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **27** | `set_identity_session` | `domain`, `identity_role`, `raw_cookies` | Registers secondary user identity cookies (attacker vs victim) for shadow replay. |
| **28** | `test_bola_idor` | `log_id`, `role_a`, `role_b` | Executes dual-track BOLA replay against an endpoint using registered identity roles. |
| **29** | `run_bola_matrix_scan` | `project` | Executes comprehensive automated BOLA matrix replay across all logged endpoints. |
| **30** | `get_bola_access_matrix` | `project` | Retrieves compiled cross-role authorization matrix results for active project endpoints. |

### Category G: Response Distillation, Diffing & DOM Oracle (Tools 31 – 34)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **31** | `distill_http_response` | `raw_body`, `content_type` | Compresses HTML/JSON bodies into semantic security structures (85–95% token savings). |
| **32** | `compare_http_responses` | `response_a`, `response_b` | Normalizes dynamic noise (timestamps, nonces) to detect subtle response anomalies. |
| **33** | `semantic_diff_responses` | `log_id_a`, `log_id_b` | Generates structured semantic difference between two historical proxy transactions. |
| **34** | `verify_dom_execution` | `url`, `payload` | Executes payload in sandboxed Playwright Chromium to deterministically verify DOM sinks. |

### Category H: Parameter Fuzzing & Workflow Testing (Tools 35 – 38)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **35** | `fuzz_endpoint` | `url`, `payload_type`, `custom_payloads` | High-speed dictionary fuzzing against marker positions (`§...§`) with delta analysis. |
| **36** | `execute_workflow_sequence` | `sequence`, `test_step_skipping` | Executes stateful multi-step workflows with dynamic variable extraction and step-skipping. |
| **37** | `test_race_condition` | `url`, `concurrency`, `method` | Executes microsecond-synchronized request bursts using `asyncio.Barrier` for race testing. |
| **38** | `send_websocket_message` | `url`, `message` | Transmits and logs WebSocket frames to target socket endpoints for real-time protocol testing. |

### Category I: Reconnaissance & Target Knowledge Graph (Tools 39 – 45)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **39** | `get_attack_surface` | `project` | Returns hierarchical topology graph of assets, open ports, and endpoints. |
| **40** | `record_target_asset` | `host`, `ip_address`, `os` | Catalogs a host/machine, IP address, OS, and status in the knowledge graph. |
| **41** | `record_target_service` | `asset_id`, `port`, `service_name` | Records open ports, protocols (TCP/UDP), and service banners for a target asset. |
| **42** | `record_target_endpoint` | `asset_id`, `url_path`, `http_method` | Catalogs target URL routes, parameters, auth requirements, and testing status. |
| **43** | `delete_attack_surface_node` | `node_type`, `node_id`, `project` | Prunes stale or false-positive assets, services, or endpoints from the knowledge graph. |
| **44** | `clear_attack_surface_graph` | `project` | Wipes all attack surface records for a project workspace to reset reconnaissance. |
| **45** | `infer_hidden_endpoints` | `host`, `project` | Predicts unmapped REST endpoints (admin, actuator, docs, CRUD variants) from observed paths. |

### Category J: Payload Vault & WAF Evasion (Tools 46 – 49)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **46** | `record_test_payload` | `payload`, `vuln_type`, `outcome` | Stores exploit strings into the Payload Vault with categorization and tags. |
| **47** | `get_captured_payloads` | `vuln_type`, `outcome`, `keyword` | Queries stored payloads with filtering by vulnerability type, outcome, and keyword. |
| **48** | `mutate_payload` | `raw_payload`, `vuln_type` | Generates obfuscated payload variations (URL, hex, comment injection, Unicode bypass). |
| **49** | `analyze_waf_response` | `status_code`, `headers`, `body` | Fingerprints target WAF vendor (Cloudflare, AWS WAF, Akamai) and recommends bypass tactics. |

### Category K: Reporting, PoC & Findings (Tools 50 – 54)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **50** | `report_vulnerability` | `log_id`, `title`, `severity` | Flags an HTTP log entry as a confirmed vulnerability finding in the operator ledger. |
| **51** | `generate_exploit_poc` | `finding_id` | Generates standalone Python PoC scripts, cURL commands, and CVSS/CWE dossiers. |
| **52** | `generate_nuclei_template` | `finding_id` | Generates standardized Nuclei v3 YAML exploit templates for regression scanning. |
| **53** | `run_security_audit_suite` | `project`, `min_severity` | Runs automated OWASP API security audit across traffic, returning 0–100 score and grade. |
| **54** | `generate_audit_ci_report` | `project`, `format` | Generates publication-grade Markdown, JSON, or SARIF 2.1.0 security compliance reports. |

### Category L: Interception Rules, CSRF & Scope (Tools 55 – 63)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **55** | `add_interception_rule` | `rule_type`, `match_pattern`, `actions` | Adds rule to tamper with headers, rewrite bodies, or return synthetic mock responses. |
| **56** | `list_interception_rules` | *(none)* | Lists all configured match & replace and response mocking rules. |
| **57** | `toggle_interception_rule` | `rule_id`, `enabled` | Toggles or updates the enabled state of an interception rule. |
| **58** | `delete_interception_rule` | `rule_id` | Deletes an interception rule by ID. |
| **59** | `get_csrf_tokens` | `domain` | Retrieves all auto-tracked and manual anti-CSRF tokens extracted from HTTP responses. |
| **60** | `set_csrf_token` | `domain`, `token_value` | Sets an anti-CSRF token for target domain to be auto-injected in state-changing calls. |
| **61** | `clear_csrf_tokens` | *(none)* | Clears cached anti-CSRF tokens. |
| **62** | `set_active_project` | `project_name` | Dynamically sets the active project scope for the agent session. |
| **63** | `get_active_project` | *(none)* | Retrieves the currently active project name and isolation directory. |

### Category M: Tunnels, Traffic Analysis & System Upgrades (Tools 64 – 71)
| # | Tool Name | Key Arguments | Description |
| :---: | :--- | :--- | :--- |
| **64** | `setup_public_tunnel` | `provider` | Spins up Cloudflare Quick Tunnel / ngrok and binds public URL to OAST listener. |
| **65** | `get_tunnel_status` | *(none)* | Returns operational status, public URL, provider, and uptime of active ingress tunnel. |
| **66** | `close_public_tunnel` | *(none)* | Terminates active public tunnel and restores local callback base URL. |
| **67** | `search_traffic_advanced` | `query`, `min_status`, `max_status` | Multi-dimensional traffic search filtering by status range, latency, and full-text bodies. |
| **68** | `analyze_traffic_patterns` | `project` | Analyzes captured traffic, aggregating unique routes and discovered parameter inventory. |
| **69** | `get_attack_paths` | `project` | Synthesizes Kill Chain attack paths from initial recon to Crown Jewels (RCE, DB dump). |
| **70** | `get_ca_certificate_details` | *(none)* | Returns root CA certificate paths, thumbprint, and installation status for TLS MITM. |
| **71** | `update_proxsynth_system` | `confirm`, `force_check` | Performs autonomous remote Git update checks and synchronized system upgrades for Web & MCP. |

---

## 🐍 Transparent Runtime Auto-Enforcement (`sitecustomize.py`)

When Python boots, it automatically searches `sys.path` and executes [`sitecustomize.py`](file:///d:/PROJECT/01/sitecustomize.py) if present. PROXSYNTH uses this hook to achieve zero-config process interception:

1. **Proxy Environment Injection:** Sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` to `http://127.0.0.1:8088`.
2. **CA Root Auto-Trust:** Injects `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, and `CURL_CA_BUNDLE` pointing to `.proxsynth_ca/proxsynth_ca.crt`.
3. **Runtime In-Memory Monkeypatching:**
   - Patches `requests.Session.__init__` to default `proxies={"http": proxy_url, "https": proxy_url}` and `verify=False`.
   - Patches `httpx.Client` and `httpx.AsyncClient` to route via the forward proxy.
   - Patches `urllib.request.build_opener` and `install_opener`.
   - Patches `aiohttp.ClientSession` to enable `trust_env=True`.
4. **Legitimate Browser Fingerprint Rotation:** Injects realistic desktop browser User-Agents and Client Hints (`Sec-Ch-Ua`, `Sec-Ch-Ua-Platform`) from [`backend/user_agents.py`](file:///d:/PROJECT/01/backend/user_agents.py) to avoid trivial WAF blocks.

---

## 🚀 Quick Start & Installation

### 1. Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- Git.
- Windows, Linux, or macOS.

### 2. Automatic Setup

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

The script automatically sets up the virtual environment, installs dependencies, initializes Playwright browsers, generates CA certificates, and launches the platform:
- **FastAPI Web Dashboard & API:** `http://127.0.0.1:8000`
- **Forward Interception Proxy:** `http://127.0.0.1:8088`
- **OAST Multi-Protocol Listeners:** DNS UDP `5354` & LDAP TCP `1390`

---

## 🤖 AI Agent Integration Guide

Connect your AI coding assistant or autonomous agent to PROXSYNTH via FastMCP:

### 1. Claude Desktop & Claude Code
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "python",
      "args": ["/path/to/proxsynth/mcp_server.py"],
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
      "command": "python",
      "args": ["/path/to/proxsynth/mcp_server.py"],
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
      "command": "python",
      "args": ["/path/to/proxsynth/mcp_server.py"],
      "env": {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": "default"
      }
    }
  }
}
```

### 4. Antigravity IDE & AGY CLI
Add to your Antigravity configuration `mcp_config.json`:
```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "python",
      "args": ["/path/to/proxsynth/mcp_server.py"],
      "env": {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": "default"
      }
    }
  }
}
```

---

## 🖥️ SOC Web Operator Console

The web console (`http://127.0.0.1:8000`) provides a high-density, cyberpunk-styled security operations center:

1. **Autonomous Campaign Studio:** Launch 1-click fire-and-forget pentest campaigns with live stage telemetry, discovered form inventories, and real-time execution logs.
2. **Proxy Traffic Ledger:** Live table with virtual scrolling for 100,000+ records, resizable columns, text/regex filters, and split-pane request/response inspector with "Distill (P1)" toggle.
3. **Interactive Intercept Trap:** Pause high-risk agent requests before they reach the target. Inspect and modify headers or body payloads, and choose to **Forward** or **Drop**.
4. **Target Attack Surface Knowledge Graph:** Relational asset inventory (`Host -> Port -> Route`) with live state tags (`UNTESTED`, `IN_PROGRESS`, `TESTED_CLEAN`, `TESTED_VULNERABLE`).
5. **OAST Interaction Console:** Real-time event log capturing out-of-band HTTP callbacks, DNS resolutions, and JNDI queries with the "Spray Canaries (P2)" modal.
6. **Attack Hypothesis Ledger (P3):** Kanban and list view tracking agent working memory with live WebSocket state transitions (`PLANNED`, `TESTING`, `CONFIRMED`, `DISPROVEN`, `BLOCKED`).
7. **OWASP API Security Auditor:** Automated compliance scanner with 0–100 scorecards, letter grades (A+ to F), and 1-click Markdown/JSON/SARIF exports.
8. **AI Activity Command & Payload Studio:** CLI Repeater workbench for command reproduction alongside a Payload Sandbox for reflection and WAF evasion checks.
9. **Repeater & Parameter Fuzzer:** Manual replay workbench with baseline diff analyzer, "Distill Response (P1)" toggle, and "Verify DOM (P4)" execution oracle.
10. **BFLA & BOLA Matrix Inspector:** Cross-role authorization matrix evaluating endpoint access boundaries between privileged and unprivileged identities.
11. **Settings & Scope Guardrails:** Scope enforcement, authorized host wildcards, sensitive regex filters, and upstream proxy chaining (e.g., chaining to Burp Suite at `:8080`).

---

## ⚙️ Configuration Reference

PROXSYNTH is configurable via `.env` or system environment variables:

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
> **PROXSYNTH is engineered strictly for authorized penetration testing, security auditing, red teaming, and vulnerability research.**
> Executing security assessments against target systems without explicit, prior written authorization from the system owner is illegal and violates computer crime laws. The authors assume no liability for misuse, unauthorized testing, or damage caused by this software. Always test responsibly within authorized scopes.

---

## 📄 License

PROXSYNTH is distributed under the **MIT License**. See [`LICENSE`](file:///d:/PROJECT/01/LICENSE) for details.
