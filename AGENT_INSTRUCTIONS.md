# PROXSYNTH MCP — AGENT INTEGRATION GUIDE (Claude Code / OpenCode / Hermes / Cursor / Windsurf)

Panduan konfigurasi dan integrasi untuk agen otonom seperti **Claude Code**, **OpenCode**, **Hermes Agent**, **Cursor**, atau **Windsurf** agar seluruh lalu lintas pengujian penetrasi (pentest) diarahkan dan ditangkap melalui gateway Proxynth MCP.

---

## 1. Konfigurasi MCP Client

Tambahkan konfigurasi server Proxynth MCP ke konfigurasi agent Anda:

### Untuk Claude Code / Cursor / OpenCode (`mcp_config.json` atau runtime config)
```json
{
  "mcpServers": {
    "proxynth": {
      "command": "python",
      "args": ["d:/PROJECT/01/mcp_server.py"],
      "env": {
        "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
        "PROXSYNTH_PROJECT": "client-alpha"
      }
    }
  }
}
```

---

## 2. System Prompt / Instruksi untuk Agen (Opencode / Hermes)

Tambahkan arahan berikut pada system prompt agen agar agen:
1. Selalu menggunakan MCP Tool `send_http_request`.
2. Menyertakan hipotesis/alasan pengujian pada parameter `reasoning`.
3. Mematuhi boundary pengujian yang ditentukan operator.

```text
[SECURITY TESTING DIRECTIVE]
Anda terhubung dengan Proxynth Security Testing Gateway melalui MCP Tools:
1. Setiap kali berinteraksi dengan target pentest (HTTP/HTTPS), Anda WAJIB menggunakan tool `send_http_request`. JANGAN menggunakan bash `curl` langsung di terminal host.
2. Selalu sertakan parameter `reasoning` saat memanggil tool untuk menjelaskan hipotesis keamanan Anda (contoh: "Testing SQL injection pada query param id karena aplikasi merespon error SQL").
3. Jika target berada di luar scope atau memicu proteksi guardrail, hormati pesan blokir dan batasi pengujian pada endpoint yang diizinkan.
4. Jika target membutuhkan rendering halaman JavaScript dinamis, gunakan tool `browser_navigate_and_render`.
5. Jika menemui login wall, CAPTCHA, atau Two-Factor Authentication (2FA), gunakan tool `request_manual_login` agar operator manusia dapat melakukan login via browser interaktif.
6. Jika perlu menjalankan perintah terminal / CLI (seperti nmap, curl, sqlmap, custom scripts), gunakan tool `run_pentest_command` agar perintah, stdout, dan stderr terekam di Proxynth Command Audit Trail. Anda dapat menentukan parameter `cwd` untuk direktori kerja eksekusi.
7. Jika membuat atau menguji payload eksploitasi khusus (SQLi, XSS, SSRF, SSTI, RCE, IDOR), gunakan tool `record_test_payload` untuk mencatat payload ke dalam Proxynth Payload Vault (mengembalikan Payload ID).
8. Jika response body terpotong pada `send_http_request` atau Anda membutuhkan response body/headers utuh untuk analisis mendalam (misal: reflected XSS, token extraction, dump JSON besar), gunakan tool `get_log_detail(log_id=<ID>)` dengan `Log ID` yang didapat dari `send_http_request`.
9. Jika perlu meninjau riwayat request yang pernah dikirim sebelumnya untuk chaining atau replay, gunakan tool `get_traffic_history(project="default", limit=20)`.
10. **Pelaporan & Flagging Kerentanan (Sangat Penting):**
    - Saat mengirim request exploit yang Anda ketahui atau duga sebagai kerentanan, Anda dapat langsung menambahkan parameter di `send_http_request`: `finding_title="SQL Injection — Authentication Bypass"`, `finding_severity="CRITICAL"`, `flag_status="CONFIRMED"`, `finding_category="SQL Injection"`, `finding_evidence="Admin JWT token returned"`.
    - ATAU setelah menganalisis respons dengan `get_log_detail(log_id)`, panggil tool `report_vulnerability(log_id=<ID>, title="...", severity="CRITICAL"|"HIGH"|"MEDIUM", category="...", evidence="...")` untuk mencatat temuan terkonfirmasi ke dalam Proxynth Dashboard Findings Ledger.

11. **Standardisasi Output JSON & Token-Saving (Hemat Konteks LLM):**
    - Gunakan `output_format="json"` pada `send_http_request` atau `run_pentest_command` untuk mendapatkan output terstruktur yang mudah diparsing.
    - Gunakan parameter `diff_baseline_id=<ID>` pada `send_http_request` saat mengirim payload variasi/mutasi untuk membandingkan respons dengan baseline awal. Proxynth akan menghitung diff unified secara otomatis sehingga menghemat token LLM hingga 90%.
12. **Target Knowledge Graph (Stateful Recon & Surface Mapping):**
    - Gunakan `get_attack_surface(project="...")` untuk melihat topologi aset target, port/layanan terbuka, dan status endpoint yang sudah maupun belum diuji.
    - Catat host/IP baru dengan `record_target_asset(...)`.
    - Catat port terbuka hasil nmap/portscan dengan `record_target_service(...)`.
    - Catat rute/endpoint baru dan update status progresnya (`UNTESTED`, `IN_PROGRESS`, `TESTED_CLEAN`, `TESTED_VULNERABLE`) dengan `record_target_endpoint(...)`.
13. **OAST Engine (Deteksi Blind Vulnerabilities Out-of-Band):**
    - Untuk mendeteksi Blind SSRF, Blind SQLi, Blind RCE, XXE, atau Log4j/JNDI, gunakan `generate_oast_token(vuln_type="SSRF", description="...")`.
    - Masukkan `callback_url` yang diberikan ke dalam payload eksploitasi Anda.
14. **Custom Pentest Scripts & Transparent Proxy Interception (OpenCode / Hermes):**
    - Saat Anda membuat dan mengeksekusi script pentest mandiri (misal: Python `requests`/`httpx`/`urllib`, `curl`, `sqlmap`, `ffuf`, `nuclei`):
      - **Enforcement Otomatis**: Melalui runtime hook `sitecustomize.py` dan environment proxy (`HTTP_PROXY`, `HTTPS_PROXY`), bahkan jika Anda menjalankan script Python via terminal biasa (`python script.py`), lalu lintasnya **pasti otomatis melewati Proxynth Forward Proxy (:8088)** dengan TLS MITM decryption tanpa perlu konfigurasi proxy manual di script Anda.
      - **Zero Guardrails by Default**: Secara default tidak ada guardrail yang memblokir target internal/lab (`127.0.0.1`, RFC1918) maupun external domain, sehingga seluruh pengujian berjalan lancar tanpa terhalang SSRF filter bawaan kecuali operator sengaja mengaktifkan Scope Guardrail di Dashboard.
      - Seluruh target hit dari script Anda akan **otomatis tertangkap di Proxynth Forward Interception Proxy (:8088)**, disuntikkan session cookies aktif, dianalisis kerentanannya oleh Dual-Track Triage, dan otomatis di-ingest ke Target Knowledge Graph!
    - Untuk script Python tingkat lanjut, Anda juga dapat mengimpor micro-SDK bawaan: `from proxynth_client import ProxynthSession, report_finding`.
15. **Multi-Identity BOLA / IDOR Testing:**
    - Daftarkan sesi akun sekunder (misal penyerang/korban) dengan `set_identity_session(domain="...", identity_role="attacker", raw_cookies="...")`.
    - Setiap endpoint ber-identifier objek yang Anda tes akan otomatis di-shadow replay oleh Proxynth. Anda juga dapat memicu uji manual via `test_bola_idor(log_id=<ID>)`.
16. **Adaptive WAF Evasion & Payload Mutator:**
    - Jika target dilindungi WAF (Cloudflare, AWS WAF, Akamai, ModSecurity), gunakan `analyze_waf_response(status_code, headers, body)` untuk mengetahui vendor dan teknik bypass.
    - Gunakan `mutate_payload(raw_payload="...", vuln_type="SQLI"|"XSS"|"TRAVERSAL")` untuk menghasilkan payload variasi yang lolos filter WAF.
17. **Semantic API Spec Reconstructor (Hidden Routes Inferrer):**
    - Gunakan `infer_hidden_endpoints(host="...", project="...")` untuk merekonstruksi dan memprediksi rute tersembunyi (CRUD mutasi, docs swagger, actuator, admin panel) yang belum pernah diuji.
18. **Exploit Path Chaining Graph (Path to Crown Jewels):**
    - Gunakan `get_attack_paths(project="...")` untuk melihat jalur rantai eksploitasi (Kill Chain) dari akses luar menuju dampak kritis (RCE, DB dump, PII breach).
19. **One-Click Standalone Exploit PoC & Dossier:**
    - Gunakan `generate_exploit_poc(finding_id=<ID>)` untuk menghasilkan script exploit Python mandiri, cURL command, dan dossier CVSS/CWE siap lapor.
20. **WebSocket Frame Testing:**
    - Gunakan `send_websocket_message(url="wss://...", message="...")` untuk menguji komunikasi socket real-time.
21. **High-Speed Parameter Fuzzing (Burp-style Marker §...§):**
    - Gunakan `fuzz_endpoint(url="http://target/api?id=§1§", payload_type="sqli"|"xss"|"traversal")` untuk mini-intruder fuzzing otomatis dengan analisis delta status & panjang response.
22. **Multi-Step Stateful Workflow Testing:**
    - Gunakan `execute_workflow_sequence(sequence=[...], test_step_skipping=True)` untuk menguji urutan logika bisnis berantai dengan ekstraksi variabel dinamis (`{{var}}`) dan pendeteksian bypass otorisasi/pembayaran (`BUSINESS_LOGIC_BYPASS_CONFIRMED`).
23. **Turbo Race Condition & Concurrency Burst Testing:**
    - Gunakan `test_race_condition(url="http://target/api/coupon/claim", concurrency=20)` untuk burst mikrodetik terkoordinasi berbasis `asyncio.Barrier` guna mendeteksi double-spending dan limit bypass.
24. **JavaScript Recon & Secret Mining:**
    - Gunakan `mine_javascript_assets(content_or_url="https://target/app.js")` untuk menambang rute API tersembunyi, query parameter rahasia, source map (`.map`), serta kebocoran kredensial hardcoded (AWS, JWT, Slack, API keys).
25. **Semantic Structural Diffing & Noise Reduction:**
    - Gunakan `compare_http_responses(response_a=<LogID_or_Dict>, response_b=<LogID_or_Dict>)` untuk membersihkan dynamic noise (timestamp, UUID, hex hash, CSRF nonce) dan mendeteksi Soft-403/Soft-404.
26. **Autonomous JWT Security Auditing:**
    - Gunakan `audit_jwt_security(token="...", test_url="https://target/api/protected")` untuk menguji Algorithm None bypass, brute-force weak HMAC secret offline, privilege escalation claim tampering, dan kid path traversal.
27. **Penghapusan & Pembersihan Attack Surface:**
    - Gunakan `delete_attack_surface_node(node_type="asset"|"endpoint"|"service", node_id=<ID>, project="...")` untuk menghapus host, rute, atau service yang sudah usang/salah deteksi dari Attack Surface Knowledge Graph.
    - Gunakan `clear_attack_surface_graph(project="...")` untuk mengosongkan seluruh aset dan endpoint target pada workspace proyek tertentu.
28. **LLM Semantic Response Distillation (Hemat Token 90%):**
    - Gunakan parameter `distill_response=True` pada `send_http_request` atau panggil tool `distill_http_response(body="...")` untuk mereduksi respons HTML/JSON raksasa menjadi representasi padat keamanan (forms, inputs, API routes, reflections, dan sensitive keys) guna menghemat context window.
29. **Autonomous OAST Canary Spraying (Blind Exploit Sprayer):**
    - Gunakan `spray_oast_canaries(target_url="https://target/api", vuln_types=["ssrf", "dns", "log4j", "xxe"])` untuk secara otomatis menemukan seluruh parameter input dan menyemprotkan token canary multi-protokol guna mendeteksi Blind SSRF, Blind RCE, dan Log4j secara instan.
30. **Agent Working Memory & Attack Hypothesis Ledger:**
    - Catat rencana pengujian Anda dengan `record_testing_hypothesis(target="...", vuln_type="IDOR", hypothesis="Testing param id for horizontal privilege escalation")`.
    - Tinjau to-do list pengujian kapan saja dengan `get_testing_agenda(project="...")`.
    - Perbarui hasil pembuktian Anda dengan `update_hypothesis_status(hypothesis_id=<ID>, status="CONFIRMED"|"DISPROVEN", evidence_notes="...")`.
31. **Browser DOM Execution Oracle (Verifikasi XSS 100% Deterministic):**
    - Gunakan `verify_dom_execution(url="https://target/search", payload="<script>alert(1)</script>")` untuk membuka headless Chromium sandbox yang memvalidasi apakah dialog alert/confirm atau DOM script sink benar-benar tereksekusi tanpa false positive.
32. **Autonomous End-to-End Campaign Orchestrator ('God Tool'):**
    - Untuk menjalankan pengujian keamanan lengkap dari hulu ke hilir HANYA DALAM 1 PERINTAH tanpa instruksi langkah-demi-langkah, panggil `run_autonomous_security_campaign(target_url="https://target.com", project="...")`.
    - Engine akan secara otomatis menjalankan: Spider & Form Discovery -> JS Secret Mining -> OAST Spraying -> BFLA/BOLA Matrix -> Mass Assignment -> Numeric Logic -> Deterministic Verification Gate, dan mengembalikan laporan ringkasan eksekutif padat token.
33. **Autonomous Web Spider & Form Discovery Engine:**
    - Gunakan `spider_and_crawl_target(root_url="https://target.com", max_depth=2, max_pages=25)` untuk memetakan seluruh rute internal, formulir HTML, dan endpoint API secara otomatis ke dalam Target Knowledge Graph.
34. **Autonomous Re-Authentication Macro & Session Keeper (Zero-Human Auth):**
    - Daftarkan kredensial atau endpoint login dengan `register_auth_recipe(login_url="http://target/api/login", payload={"username":"admin","password":"password123"}, token_json_path="token")`.
    - Jika sesi kedaluwarsa (HTTP 401/403) di tengah pengujian, Proxynth akan otomatis login ulang di background dan memperbarui token tanpa memerlukan intervensi manusia.
35. **Unified Deterministic Verification Gate:**
    - Gunakan `verify_vulnerability_candidate(finding_id=<ID> atau log_id=<ID>)` untuk memvalidasi temuan melalui orakel deterministik (Chromium DOM Sandbox, Differential Z-score Timing, OAST) guna mengeliminasi false positive.
36. **Adaptive Rate-Limiting & Transparent SOCKS5 Rotation:**
    - Jika target merespon dengan `HTTP 429 Too Many Requests`, Proxynth secara otomatis menerapkan exponential backoff dan merotasi proxy pool upstream secara transparan.
```

---

## 3. Fitur Utama yang Aktif

- **Autonomous Multi-Identity BOLA/IDOR Matrix:** Pengujian otorisasi horizontal otomatis antar role akun secara background shadow replay.
- **Multi-Protocol OAST Engine (HTTP, DNS UDP :5353, LDAP/JNDI TCP :1389):** Deteksi Blind SSRF dan JNDI injection tanpa bergantung pada layanan luar.
- **Adaptive WAF Evasion & Mutation:** Rekomendasi taktik bypass WAF dan generator mutasi payload otomatis.
- **Semantic API Spec Reconstructor:** Prediksi rute tersembunyi berdasarkan pola arsitektur REST.
- **Exploit Path Chaining Graph:** Visualisasi kill chain Mermaid dari akses publik menuju Crown Jewels.
- **One-Click Standalone PoC Generator:** Pembuatan script Python mandiri, cURL command, dan laporan CVSS/CWE otomatis.
- **Transparent Auto-Enforcement (`sitecustomize.py` & `.env`):** Menjamin bahwa setiap script Python yang dieksekusi agen otomatis diarahkan ke Forward Interception Proxy Proxynth (:8088), bahkan saat agen memanggil terminal host langsung.
- **Zero Default Guardrails:** Secara default guardrail berada dalam status nonaktif (`scope_enabled = False`, `allow_internal_networks = True`, `blocked_patterns = []`). Pengguna memiliki kontrol penuh dan hanya perlu mengatur guardrail manual jika pengujian membutuhkan pembatasan scope ketat.
- **TLS MITM Decryption Engine (Dynamic Cert Generator):** Mendekripsi lalu lintas HTTPS dari script agen secara transparan sehingga payload riil, status code, response body, dan findings langsung tercatat (bukan sekadar tunneling CONNECT blind).
- **Target Knowledge Graph:** State reconnaissance dan mapping target terpusat (Asset -> Service/Port -> Endpoint) dengan tracking status pengujian & auto-ingestion dari script traffic.
- **Token-Saving JSON & Differential Analysis:** Output JSON terstruktur dan diffing baseline terotomatisasi untuk efisiensi context window agen.
- **Interactive Intercept (Proxy Trap):** Operator dapat menahan (pause), memodifikasi, atau membatalkan request agen sebelum dikirim ke target.
- **Export HAR 1.2 & Markdown:** Ekspor seluruh lalu lintas pengujian untuk dianalisis di Burp Suite atau dibuat laporan pentest eksekutif.
