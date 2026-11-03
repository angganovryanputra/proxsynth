#!/usr/bin/env bash
# ==============================================================================
# Proxsynth Transparent CLI & Pentest Command Wrapper (Bash/Linux/macOS)
# Routes all outbound traffic through Proxsynth Forward Proxy (127.0.0.1:8088),
# binds Root CA, captures execution time, and streams logs to Dashboard API.
# ==============================================================================

if [ -z "$1" ]; then
    echo "[!] Usage: ./proxsynth-exec.sh <command> [args...]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_PORT="${PROXSYNTH_PROXY_PORT:-8088}"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

export HTTP_PROXY="${PROXY_URL}"
export HTTPS_PROXY="${PROXY_URL}"
export ALL_PROXY="${PROXY_URL}"
export http_proxy="${PROXY_URL}"
export https_proxy="${PROXY_URL}"
export all_proxy="${PROXY_URL}"

CA_CERT="${SCRIPT_DIR}/.proxsynth_ca/proxsynth_ca.crt"
[ ! -f "${CA_CERT}" ] && CA_CERT="${SCRIPT_DIR}/.proxynth_ca/proxynth_ca.crt"
if [ -f "${CA_CERT}" ]; then
    export REQUESTS_CA_BUNDLE="${CA_CERT}"
    export CURL_CA_BUNDLE="${CA_CERT}"
    export SSL_CERT_FILE="${CA_CERT}"
    export NODE_EXTRA_CA_CERTS="${CA_CERT}"
fi

export PYTHONHTTPSVERIFY="0"
export CURL_INSECURE="1"
export NODE_TLS_REJECT_UNAUTHORIZED="0"

FULL_CMD="$*"
echo "[*] Proxsynth Executing: ${FULL_CMD} (Proxy: ${PROXY_URL})"

START_TIME=$(date +%s%3N 2>/dev/null || date +%s000)
TMP_OUT=$(mktemp)

# Execute command
"$@" 2>&1 | tee "${TMP_OUT}"
EXIT_CODE="${PIPESTATUS[0]}"

END_TIME=$(date +%s%3N 2>/dev/null || date +%s000)
DURATION_MS=$((END_TIME - START_TIME))

STDOUT_TEXT=$(head -c 500000 "${TMP_OUT}")
rm -f "${TMP_OUT}"

# Asynchronous Telemetry to Proxsynth Dashboard API
PY_BIN="python3"
[ -f "${SCRIPT_DIR}/venv/bin/python3" ] && PY_BIN="${SCRIPT_DIR}/venv/bin/python3"

JSON_PAYLOAD=$(cat <<EOF
{
  "command": $(printf '%s' "${FULL_CMD}" | ${PY_BIN} -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo "\"${FULL_CMD}\""),
  "tool_name": "proxsynth-cli-wrapper",
  "reasoning": "Executed via proxsynth-exec wrapper",
  "stdout": $(printf '%s' "${STDOUT_TEXT}" | ${PY_BIN} -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo "\"\""),
  "stderr": "",
  "exit_code": ${EXIT_CODE:-0},
  "duration_ms": ${DURATION_MS:-0},
  "status": "$([ ${EXIT_CODE:-0} -eq 0 ] && echo "SUCCESS" || echo "FAILED")"
}
EOF
)

curl -s -X POST "http://127.0.0.1:8000/api/commands" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}" \
    --max-time 2 >/dev/null 2>&1 || true

exit ${EXIT_CODE}
