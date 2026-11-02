# ⚡ PROXSYNTH: Autonomous AI Security Interception Proxy & Testing Gateway

> **An Agent-First HTTP/HTTPS Interception Proxy, FastMCP Security Testing Gateway, and Autonomous Bug Bounty Engine.**  
> Engineered specifically for Autonomous AI Pentesting Agents (Claude Code, Cursor, Windsurf, OpenCode, Hermes, and Antigravity) communicating via the **Model Context Protocol (FastMCP 2.0+)**.

[![Release](https://img.shields.io/badge/Release-v0.1.0--beta-orange.svg)](#-overview)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastMCP Tools](https://img.shields.io/badge/FastMCP%20Tools-90%20Registered-8b5cf6.svg)](#-fastmcp-tools-reference-90-tools)
[![FastAPI](https://img.shields.io/badge/FastAPI-High%20Performance-009688.svg)](https://fastapi.tiangolo.com)
[![Exploit Chainer](https://img.shields.io/badge/Exploit%20Chainer-Multi--Hop%20Pivots-e11d48.svg)](#-pilar-1-autonomous-multi-step-exploit-chainer)
[![Wildcard Recon](https://img.shields.io/badge/Scope%20Recon-crt.sh%20%7C%20Takeover%20Detector-38bdf8.svg)](#-pilar-2-wildcard-subdomain--scope-reconnaissance-engine)
[![Semantic Fuzzer](https://img.shields.io/badge/Semantic%20Fuzzer-Welch's%20t--Test%20Oracle-10b981.svg)](#-pilar-3-intelligent-semantic-fuzzing--anomaly-detector)
[![Attack Map](https://img.shields.io/badge/Attack%20Map-Cytoscape%20%26%20D3%20Live-a855f7.svg)](#-pilar-4-interactive-live-attack-map--web-terminal-integration)
[![CLI Wrappers](https://img.shields.io/badge/CLI%20Wrappers-proxsynth--exec-0ea5e9.svg)](#-agentic-cli-execution-wrappers-proxsynth-exec)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#-license)

---

## 📌 Why Proxsynth? (Traditional Proxies vs. Proxsynth)

Traditional penetration testing proxies (*Burp Suite*, *Caido*, *mitmproxy*, *OWASP ZAP*) were designed for manual human point-and-click workflows. When deployed with autonomous AI agents, operators face critical bottlenecks:

| Operational Bottleneck | Burp Suite / Caido / ZAP | PROXSYNTH Solution |
| :--- | :--- | :--- |
| **Token Exhaustion** | Dumps 100KB–1MB raw HTML/CSS into LLM prompts. | **90% Token Reduction:** LLM Semantic Body Distiller & Dynamic Noise Stripper. |
| **Agent Amnesia** | Stateless; agent repeats tests and forgets state. | **Hypothesis Working Memory Ledger:** Tracks `PLANNED` ➔ `TESTING` ➔ `CONFIRMED`. |
| **Subprocess Proxy Bypass** | CLI tools (`curl`, `nmap`, `nuclei`) bypass local proxy. | **Transparent Runtime Interception:** `sitecustomize.py` + `proxsynth-exec` wrappers. |
| **False-Positive Hallucinations** | Agent guesses XSS from raw reflected strings. | **Deterministic Verification Gate:** Headless Playwright DOM Oracle & Welch's t-test. |
| **Blind Vulnerabilities** | Out-of-band SSRF/RCE requires complex manual setup. | **Built-in Multi-Protocol OAST Sprayer:** Correlated HTTP, DNS (:5354), and LDAP (:1390). |
| **Multi-Hop Kill Chains** | Manual correlation of findings. | **Autonomous Exploit Chainer:** SSRF ➔ Cloud IMDS, BOLA ➔ Privilege Escalation. |

---

## 🏗️ System Architecture

```text
 ┌────────────────────────────────────────────────────────┐
 │            AUTONOMOUS AI PENTESTING AGENTS             │
 │      (Claude Code / Cursor / Windsurf / Antigravity)   │
 └───────────────┬────────────────────────┬───────────────┘
                 │                        │
  Direct FastMCP │                        │ CLI Script Execution (proxsynth-exec)
  (90 Tools / RPC)│                        │ Transparent sitecustomize.py (:8088)
                 ▼                        ▼
 ┌────────────────────────────────────────────────────────┐
 │                PROXSYNTH GATEWAY ENGINE                │
 │  ┌──────────────────────────┐┌──────────────────────┐  │
 │  │ FastAPI Core & REST API  ││ Forward TLS MITM     │  │
 │  │ (Port 8000 / HTTP / WS)  ││ Interception (:8088) │  │
 │  └────────────┬─────────────┘└──────────┬───────────┘  │
 │               └──────────────┬──────────┘              │
 │                              ▼                         │
 │  ┌──────────────────────────────────────────────────┐  │
 │  │             THE 4 STRATEGIC PILLARS              │  │
 │  │ 1. Multi-Step Exploit Chainer (SSRF ➔ Cloud IMDS)│  │
 │  │ 2. Wildcard Scope Recon & Takeover Detector      │  │
 │  │ 3. Semantic Fuzzing & Welch's t-Test Timing      │  │
 │  │ 4. Interactive Live Attack Map & Web Terminal    │  │
 │  └───────────────────────────┬──────────────────────┘  │
 │                              ▼                         │
 │  ┌──────────────────────────────────────────────────┐  │
 │  │        SQLite WAL Persistence & State Engine     │  │
 │  │ - HttpLogs (Raw & Distilled)  - Target Graph     │  │
 │  │ - TestingHypothesis Ledger    - ActiveSession    │  │
 │  │ - CapturedPayload Vault       - OAST Callbacks   │  │
 │  └──────────────────────────────────────────────────┘  │
 └──────────────────────────────┬─────────────────────────┘
                                ▼
 ┌────────────────────────────────────────────────────────┐
 │   Cyberpunk SOC Web Dashboard & Live Cytoscape Map     │
 │   - Interactive Attack Graph    - Real-Time Terminal   │
 │   - Hypothesis Kanban Board     - OWASP CI/CD Scorecard│
 └────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (30 Seconds)

### 1. Installation
```bash
git clone https://github.com/your-org/proxsynth.git
cd proxsynth
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
playwright install chromium
```

### 2. Launch Proxsynth
```bash
# Start Gateway, Forward Proxy (:8088), OAST Listeners, and Web SOC Dashboard (:8000)
python -m backend.app
```
* **SOC Web Console:** `http://127.0.0.1:8000`
* **Forward Interception Proxy:** `http://127.0.0.1:8088`
* **Interactive Attack Map:** `http://127.0.0.1:8000/api/attack-graph/interactive`

### 3. Connect Your AI Agent (MCP Config)
Add Proxsynth to your agent's MCP configuration (e.g. `claude_desktop_config.json`, Cursor, or Antigravity):

```json
{
  "mcpServers": {
    "proxsynth": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/proxsynth"
    }
  }
}
```

---

## 🏛️ The 4 Strategic Pillars (Advanced Agentic Architecture)

### 🎯 Pilar 1: Autonomous Multi-Step Exploit Chainer
* **Module:** [`backend/exploit_chainer.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/exploit_chainer.py)
* **Description:** Connects confirmed vulnerabilities into multi-hop exploit kill chains leading to Crown Jewel compromise.
  - **SSRF ➔ Cloud Metadata Pivot:** Probes AWS IMDSv1 (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`), GCP Metadata (`metadata.google.internal`), Azure IMDS, or loopback metrics.
  - **BOLA/IDOR ➔ Privilege Escalation:** Tests administrative ID swap (`0`, `1`, `admin`) and role manipulation (`{"role": "admin"}`).
  - **Token Leak ➔ Authenticated Pivot:** Extracts leaked JWTs/API keys and validates access to protected routes (`/admin`).
* **PoC Generation:** Automatically outputs production-ready standalone Python exploit scripts and synchronizes with `TestingHypothesis`.

### 🌐 Pilar 2: Wildcard Subdomain & Scope Reconnaissance Engine
* **Module:** [`backend/scope_recon.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/scope_recon.py)
* **Description:** Zero-noise reconnaissance for root and wildcard scopes (`*.target.com`).
  - **Passive CT Enumeration:** Queries `crt.sh` logs with automated wildcard cleaning and seed fallback.
  - **DNS & Service Fingerprinting:** Resolves A/AAAA/CNAME records and discovers HTTP :80 and HTTPS :443 services.
  - **Dangling CNAME Takeover Detector:** Identifies orphaned cloud resources across AWS S3 (`NoSuchBucket`), GitHub Pages, Heroku (`No such app`), Azure (`404 Web Site not found`), Shopify, and Surge.sh.
  - **Auto-Ingestion:** Directly populates `TargetAsset`, `TargetService`, and `TargetEndpoint` knowledge graphs.

### 🔬 Pilar 3: Intelligent Semantic Fuzzing & Anomaly Detector
* **Module:** [`backend/semantic_fuzzer.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/semantic_fuzzer.py) & [`backend/differential_oracle.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/differential_oracle.py)
* **Description:** Mathematical, zero-false-positive fuzzing and differential injection detection.
  - **Dynamic Noise Stripper (`strip_dynamic_noise`):** Strips volatile anti-CSRF tokens, dynamic nonces, ISO-8601/epoch timestamps, UUIDs, trace IDs, and ETags before structural diffing.
  - **Welch's t-Test Timing Oracle:** Two-sample statistical testing with IQR network jitter filtering to mathematically confirm time-based injections.
  - **Semantic Boundary Mutations:** Type confusion (array wrapping, NoSQL injection), Unicode dotless i casing bypass, null-byte terminators, and header overrides (`X-Original-URL`, `X-Forwarded-For`).

### 🗺️ Pilar 4: Interactive Live Attack Map & Web Terminal Integration
* **Module:** [`backend/app.py`](file:///D:/0x13%20PROJECT/Proxsynth/backend/app.py)
* **Description:** Real-time visual observability and telemetry streaming for autonomous operations.
  - **Interactive Attack Graph (`GET /api/attack-graph/interactive`):** Cytoscape.js & D3.js compatible topology with hierarchical coordinates, asset clusters, animated exploit edges, and composite risk scores ($0.0 - 100.0$).
  - **Live Web Terminal (`/ws/terminal`):** Bidirectional WebSocket channel streaming live CLI output and attack graph events.
  - **CLI Telemetry Ingestion (`POST /api/telemetry/cli-event`):** Ingests streaming terminal logs from external CLI tools.

---

## ⚡ The 7 Unified FastMCP Power Tools (Token-Optimized)

To save up to **80% of prompt tokens** on tool definitions, Proxsynth provides 7 unified meta-tools that consolidate all pentesting capabilities into high-leverage operations:

| # | Power Tool | Actions / Modes | Description |
| :---: | :--- | :--- | :--- |
| **1** | `manage_pentest_execution` | `execute`, `execute_sandbox_command`, `record_external`, `capture_script`, `replay` | Unified sandbox shell runner, external tool recorder, AST exploit script ingester, and replay with response diffing. |
| **2** | `manage_attack_surface` | `get_graph`, `upsert_asset`, `upsert_service`, `upsert_endpoint`, `batch_ingest`, `scope_recon`, `exploit_chains` | Target Knowledge Graph manager: asset/service/endpoint mapping, passive scope recon, and multi-hop exploit chainer. |
| **3** | `analyze_and_diff_traffic` | `semantic_diff`, `raw_diff`, `distill_noise`, `strip_noise`, `cluster_patterns` | High-precision traffic analysis: semantic diffing, DOM distillation, dynamic noise stripping, and pattern clustering. |
| **4** | `manage_interception_rules` | `list`, `add_rule`, `toggle_rule`, `delete_rule` | Traffic interception rules manager: list, add, toggle, and delete automated traffic modification rules. |
| **5** | `manage_session_vault` | `list_identities`, `store_identity`, `get_identity`, `clear_identities` | Multi-role identity vault: manages primary, attacker, victim, and admin credentials for automated authorization matrix audits. |
| **6** | `manage_oast_and_tunnels` | `spray_canaries`, `poll_events`, `generate_token`, `setup_tunnel`, `get_tunnel_status` | Unified Out-of-Band operations: sprays canaries, polls HTTP/DNS/LDAP events, and manages public tunnels. |
| **7** | `manage_testing_agenda` | `record_hypothesis`, `get_agenda`, `update_status` | Agent working memory hub: manages testing hypotheses, tracks verification states, and synthesizes pending testing agendas. |

---

## ⌨️ Agentic CLI Execution Wrappers (`proxsynth-exec`)

When deploying AI agents that run external terminal tools (`nmap`, `nuclei`, `curl`, `ffuf`, `sqlmap`, or custom Python scripts), tools frequently bypass environment proxy variables.

Proxsynth provides zero-dependency wrapper scripts located at the repository root:
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

**Key Features:**
1. **Auto-Proxy Chaining:** Forces traffic through `127.0.0.1:8088` and auto-trusts the Proxsynth CA.
2. **Real-Time Telemetry:** Streams terminal logs directly to the Cyberpunk SOC Console and Interactive Attack Map.
3. **Workspace Script Snooper:** Watches for generated exploit scripts, parses their AST, and vaults payloads automatically.
4. **Automated Output Mining:** Automatically parses Nmap, Nuclei, and FFUF stdout into structured assets and findings.

---

## 🧰 FastMCP Tools Reference (90 Tools)

Proxsynth registers **90 tools** (83 modular core tools + 7 unified Power Tools) equipped with standardized `ToolAnnotations` (`readOnlyHint`, `destructiveHint`, and `outputSchema`).

<details>
<summary><b>🔍 Expand Master FastMCP Tool Permissions & Safety Matrix (90 Tools)</b></summary>

| # | Tool Name | Category | Read-Only | Destructive | Description |
| :---: | :--- | :---: | :---: | :---: | :--- |
| 1 | `set_active_project` | `context` | No | No | Sets active workspace project for traffic isolation. |
| 2 | `get_active_project` | `context` | Yes | No | Returns the active project context. |
| 3 | `send_http_request` | `traffic` | No | No | Sends HTTP request with auto-cookie injection, proxy routing, and distillation. |
| 4 | `get_traffic_history` | `traffic` | Yes | No | Retrieves recent HTTP transactions. |
| 5 | `get_log_detail` | `traffic` | Yes | No | Retrieves full un-truncated HTTP transaction details. |
| 6 | `distill_http_response` | `traffic` | Yes | No | Strips HTML/DOM noise to save 90% LLM tokens. |
| 7 | `search_traffic_advanced` | `traffic` | Yes | No | Searches captured traffic with filters. |
| 8 | `analyze_traffic_patterns` | `traffic` | Yes | No | Identifies recurring API patterns and auth models. |
| 9 | `compare_http_responses` | `analysis` | Yes | No | Computes side-by-side response diff. |
| 10 | `semantic_diff_responses` | `analysis` | Yes | No | Computes structural semantic difference. |
| 11 | `browser_navigate_and_render` | `browser` | No | No | Headless browser navigation with network capture. |
| 12 | `render_webpage` | `browser` | No | No | Captures screenshots and DOM snapshots. |
| 13 | `spider_and_crawl_target` | `spider` | No | No | Hybrid web crawler for Single Page Apps (SPA). |
| 14 | `verify_dom_execution` | `xss` | No | No | Deterministic Playwright DOM XSS execution oracle. |
| 15 | `request_manual_login` | `auth` | No | No | Spawns visible browser for human 2FA/CAPTCHA solve. |
| 16 | `record_test_payload` | `vault` | No | No | Vaults offensive payloads and exploit vectors. |
| 17 | `get_captured_payloads` | `vault` | Yes | No | Lists vaulted test payloads. |
| 18 | `mutate_payload` | `waf` | No | No | Generates evasive WAF bypass mutations. |
| 19 | `analyze_waf_response` | `waf` | No | No | Analyzes block pages to fingerprint WAF vendors. |
| 20 | `fuzz_endpoint` | `fuzzing` | No | Yes | High-speed parameter fuzzer. |
| 21 | `test_race_condition` | `concurrency` | No | Yes | Turbo-intruder style concurrent race condition tester. |
| 22 | `audit_differential_injection` | `audit` | No | No | 3-point boolean differential SQLi/SSTI oracle. |
| 23 | `audit_jwt_security` | `audit` | No | No | Audits JWT tokens for algorithm confusion and weak secrets. |
| 24 | `audit_bfla_permissions` | `audit` | No | No | Audits Broken Function Level Authorization. |
| 25 | `audit_mass_assignment` | `audit` | No | No | Audits mass assignment on JSON request models. |
| 26 | `audit_numeric_business_logic` | `audit` | No | No | Audits negative numbers and integer boundary flaws. |
| 27 | `test_bola_idor` | `bola` | No | Yes | Audits Broken Object Level Authorization across IDs. |
| 28 | `get_bola_access_matrix` | `bola` | Yes | No | Computes multi-tenant BOLA authorization matrix. |
| 29 | `run_bola_matrix_scan` | `bola` | No | Yes | Autonomous shadow replay BOLA matrix scanner. |
| 30 | `inspect_graphql_endpoint` | `graphql` | No | No | GraphQL introspection, field mining, and query batching. |
| 31 | `send_websocket_message` | `websocket` | No | No | Interacts with live WebSocket connections. |
| 32 | `audit_websocket_security` | `websocket` | No | No | Audits WebSockets for CSWSH and unauthenticated access. |
| 33 | `import_api_schema` | `api_import` | No | No | 1-Click OpenAPI/Swagger schema route importer. |
| 34 | `infer_hidden_endpoints` | `recon` | Yes | No | Predicts hidden REST routes from observed patterns. |
| 35 | `audit_api_gateway_bypass` | `audit` | No | No | Audits 401/403 gateway bypasses via header and path tampering. |
| 36 | `scan_network_ports` | `network` | No | No | Zero-dependency async TCP port scanner. |
| 37 | `get_target_health` | `recon` | Yes | No | Diagnoses DNS, TCP, TLS, and TTFB target latency. |
| 38 | `generate_oast_token` | `oast` | No | No | Generates unique multi-protocol OAST canary token. |
| 39 | `poll_oast_events` | `oast` | Yes | No | Polls callback events (HTTP, DNS, LDAP). |
| 40 | `spray_oast_canaries` | `oast` | No | No | Automatically sprays OAST canaries across parameters. |
| 41 | `setup_public_tunnel` | `tunnel` | No | No | Launches public reverse tunnel (Cloudflare/Ngrok). |
| 42 | `get_tunnel_status` | `tunnel` | Yes | No | Returns active reverse tunnel status. |
| 43 | `close_public_tunnel` | `tunnel` | No | No | Closes active public tunnel. |
| 44 | `add_interception_rule` | `intercept` | No | No | Adds automated traffic interception rule. |
| 45 | `list_interception_rules` | `intercept` | Yes | No | Lists active interception rules. |
| 46 | `toggle_interception_rule` | `intercept` | No | No | Enables or disables interception rule. |
| 47 | `delete_interception_rule` | `intercept` | No | Yes | Deletes interception rule. |
| 48 | `get_ca_certificate_details` | `ca` | Yes | No | Retrieves root CA details for MITM inspection. |
| 49 | `record_testing_hypothesis` | `agenda` | No | No | Records attack hypothesis in stateful ledger. |
| 50 | `get_testing_agenda` | `agenda` | Yes | No | Synthesizes pending attack agenda to eliminate loops. |
| 51 | `update_hypothesis_status` | `agenda` | No | No | Transitions hypothesis state (`PLANNED` ➔ `CONFIRMED`). |
| 52 | `run_autonomous_security_campaign` | `orchestration` | No | Yes | Unified 12-track autonomous pentest campaign orchestrator. |
| 53 | `get_campaign_status` | `orchestration` | Yes | No | Polls campaign metrics, phase progress, and findings. |
| 54 | `list_campaigns` | `orchestration` | Yes | No | Lists registered autonomous campaigns. |
| 55 | `get_autonomous_attack_guidance` | `advisor` | Yes | No | Recommends prioritized tools and exact arguments. |
| 56 | `get_tool_harness_manifest` | `meta` | Yes | No | Returns full tool taxonomy for harness auto-approval. |
| 57 | `set_identity_session` | `auth` | No | No | Registers secondary role identities in Session Vault. |
| 58 | `register_auth_recipe` | `auth` | No | No | Registers automated login recipe for session persistence. |
| 59 | `execute_reauthentication` | `auth` | No | No | Executes registered auth recipe to refresh expired tokens. |
| 60 | `get_csrf_tokens` | `session` | Yes | No | Retrieves stored anti-CSRF tokens for targets. |
| 61 | `set_csrf_token` | `session` | No | No | Stores anti-CSRF token for target domain. |
| 62 | `clear_csrf_tokens` | `session` | No | Yes | Clears stored CSRF tokens. |
| 63 | `report_vulnerability` | `triage` | No | No | Records verified finding into triage database. |
| 64 | `generate_exploit_poc` | `exploit` | Yes | No | Generates standalone Python PoC, curl, or HackerOne report. |
| 65 | `generate_nuclei_template` | `exploit` | Yes | No | Exports finding as standardized Nuclei v3 YAML template. |
| 66 | `verify_vulnerability_candidate` | `verification` | No | No | Deterministic verification gate for candidate findings. |
| 67 | `generate_audit_ci_report` | `report` | Yes | No | Generates OWASP Top 10 executive scorecard & SARIF report. |
| 68 | `get_attack_surface` | `recon` | Yes | No | Returns target assets, services, and endpoints graph. |
| 69 | `record_target_asset` | `recon` | No | No | Records host asset in attack surface graph. |
| 70 | `record_target_service` | `recon` | No | No | Records port/service on asset. |
| 71 | `record_target_endpoint` | `recon` | No | No | Records HTTP endpoint on asset. |
| 72 | `get_attack_paths` | `killchain` | Yes | No | Synthesizes multi-hop attack paths and Mermaid diagram. |
| 73 | `delete_attack_surface_node` | `recon` | No | Yes | Deletes node from attack surface graph. |
| 74 | `clear_attack_surface_graph` | `recon` | No | Yes | Clears attack surface topology. |
| 75 | `mine_javascript_assets` | `js` | No | No | Mines JS bundles for endpoints and leaked secrets. |
| 76 | `mine_cli_output` | `miner` | Yes | No | Mines Nmap, Nuclei, and FFUF output into graph. |
| 77 | `run_pentest_command` | `cli` | No | Yes | Executes terminal command with proxy routing (:8088). |
| 78 | `execute_workflow_sequence` | `workflow` | No | Yes | Executes multi-step testing sequences. |
| 79 | `run_security_audit_suite` | `suite` | No | Yes | Runs automated security audit suite against target. |
| 80 | `update_proxsynth_system` | `admin` | No | Yes | 1-Click synchronized Git self-update for Web & MCP. |
| 81 | `audit_cache_poisoning` | `cache` | No | No | Audits unkeyed header web cache poisoning. |
| 82 | `audit_csrf_indepth` | `csrf` | No | No | Audits anti-CSRF defenses and SameSite cookies. |
| 83 | `audit_file_upload` | `upload` | No | No | Audits multipart file upload validation filters. |
| 84 | `manage_pentest_execution` | `powertools` | No | Yes | Unified sandbox execution, external script capture & replay diff. |
| 85 | `manage_attack_surface` | `powertools` | No | Yes | Unified knowledge graph mapping, scope recon & exploit chains. |
| 86 | `analyze_and_diff_traffic` | `powertools` | Yes | No | High-precision traffic analysis, noise stripping & clustering. |
| 87 | `manage_interception_rules` | `powertools` | No | Yes | Interception rules intelligence hub (list, add, toggle, delete). |
| 88 | `manage_session_vault` | `powertools` | No | Yes | Multi-role identity vault (Attacker, Victim, Admin). |
| 89 | `manage_oast_and_tunnels` | `powertools` | No | Yes | Unified Out-of-Band operations and reverse tunnel manager. |
| 90 | `manage_testing_agenda` | `powertools` | No | No | Agent working memory hub and testing agenda manager. |

</details>

---

## 🖥️ REST API & Telemetry Endpoints Cheat Sheet

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/api/attack-graph/interactive` | `GET` | Cytoscape.js & D3.js interactive attack graph with risk scores & clusters. |
| `/api/exploit-chains/synthesize` | `POST` | Synthesizes multi-step exploit chains from confirmed findings. |
| `/api/exploit-chains/execute` | `POST` | Simulates or executes multi-hop exploit chain and outputs Python PoC. |
| `/api/recon/scope` | `POST` | Passive Certificate Transparency & DNS scope reconnaissance with takeover checks. |
| `/api/fuzzer/semantic` | `POST` | Semantic fuzzing with dynamic noise stripping and Welch's t-test timing oracle. |
| `/api/telemetry/cli-event` | `POST` | Real-time CLI log ingestion from `proxsynth-exec` wrappers. |
| `/api/findings/{id}/report` | `GET` | Generates complete HackerOne / Bug Bounty Markdown vulnerability report. |
| `/api/campaign/run` | `POST` | Launches 12-track autonomous pentest campaign in background. |
| `/ws/terminal` | `WS` | Bidirectional live terminal telemetry and attack graph event streaming. |
| `/ws` | `WS` | Live HTTP traffic interception, breakpoints, and log streaming. |

---

## ⚖️ Legal & Ethical Disclaimer

PROXSYNTH is intended strictly for authorized security assessments, academic research, and defensive auditing under explicit written consent. Users must comply with all applicable local, national, and international cybersecurity laws. The authors assume no liability for misuse.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.
