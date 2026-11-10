# Design — Script Repeater + LLM HTTP-vs-AI-Activity Decision Contract (Sub-project A)

Date: 2026-11-09 · Branch: feat/engine-next-action-and-ui-redesign · Status: approved to execute ("Laksanakan")

## Intent & why
The operator wants the LLM to reason powerfully during pentests on this MCP, and specifically to
**know when to record an HTTP request (→ Proxy Traffic) vs. when to run a script/CLI tool (→ AI
Activity)**. When the LLM writes a script it should land in AI Activity automatically and be
**re-runnable from the Proxsynth web UI, showing the script's response (stdout/stderr + any HTTP it
generated)**.

## Current state (what already exists — confirmed in code)
- `AgentCommandLog` table stores commands/scripts (command, tool_name, reasoning, exit_code,
  stdout, stderr, status, `script_content`, `linked_log_id`).
- `run_pentest_command` (full mode) executes a shell command proxied through :8088, logs to
  AgentCommandLog, vaults payloads. It CAPTURES `script_content` but executes the `command` string
  only — it does not run stored script_content as a file.
- Backend `POST /api/commands/execute` = "AI Activity CLI Repeater": runs a command in a subprocess
  via the forward proxy, captures stdout/stderr + duration, links generated HTTP (`linked_log_id`),
  broadcasts `NEW_COMMAND`, auto-vaults. Same limitation: runs `command`, not `script_content`.
- `backend/script_snooper.py` watches the workspace and auto-ingests written .py/.sh/.js/... scripts
  into AgentCommandLog (status `SCRIPT_STAGED`).
- Frontend AI Activity view already has a CLI Repeater (command + script textarea, Execute button,
  result panel showing status/exit/duration/stdout/stderr).

## Gaps this sub-project closes
1. **Execute stored script_content as a file.** When script_content is present (e.g. a snooped
   script whose `command` is just `# SNOOPED: x.py`), materialize it to a temp file, pick the
   interpreter from the extension, and run that — so captured scripts actually re-run.
2. **Re-run an existing AgentCommandLog entry by id** from the web UI (new endpoint
   `POST /api/commands/{id}/rerun`) and a per-row "Re-run" button in AI Activity that shows the
   response in the existing result panel.
3. **Hexagon-mode decision affordance.** Add a 7th super-tool `proxsynth_execute` (script/CLI → AI
   Activity) so that in the recommended Hexagon mode the agent has an explicit, differently-named
   tool from `proxsynth_traffic` (HTTP → Proxy). The naming IS the decision contract; tool
   descriptions state the rule plainly, and the result carries a `next_action`.

## Approaches considered
- **(chosen) Distinct `proxsynth_execute` super-tool** + shared script-materialization helper reused
  by run_pentest_command and the /execute endpoint. Clear decision boundary; ~1k extra schema
  tokens (still ~90% below full mode). 
- Overload `proxsynth_traffic` with an `action="script"`: rejected — muddies the exact HTTP-vs-script
  boundary we are trying to teach, and bloats a tuned schema.
- Add `run_pentest_command` to the hexagon set verbatim: rejected — its 1.3k-char schema is heavy and
  its name doesn't signal "AI Activity".

## Decision rule baked into tool descriptions + AGENT_INSTRUCTIONS
- One HTTP probe / replay / fuzz of a request → `proxsynth_traffic` (Proxy Traffic).
- Running an external tool (nmap/sqlmap/ffuf/custom script) or multi-step local logic → `proxsynth_execute`
  (AI Activity); it proxies the process so any HTTP it emits still lands in Proxy Traffic, linked.

## Build order
A1 backend materialization helper + rerun endpoint · A2 `proxsynth_execute` hexagon tool + guidance ·
A3 frontend per-row Re-run · A4 docs/decision contract. Verify with test_cognitive_hexagon.py +
scripts/self_test.py after each engine change.

## Non-goals / safety
Not a general remote code runner: existing Safe-Mode guardrails + SSRF checks stay; execution is
localhost-bound, proxied, size-capped. Re-run executes only content already captured in this project.
