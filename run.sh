#!/usr/bin/env bash
# ==============================================================================
# Proxsynth MCP - Unified Application & MCP Server Runner (Linux / WSL2)
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment exists; if not, trigger automated installer
if [ ! -f "venv/bin/activate" ]; then
    echo "[*] Proxsynth virtual environment not detected. Running automated installer..."
    bash install.sh
fi

source venv/bin/activate

MODE="${1:-dashboard}"

case "$MODE" in
    dashboard)
        echo "========================================================================"
        echo "  Starting Proxsynth Web Dashboard"
        echo "  URL: http://127.0.0.1:8000 (Localhost / WSL2)"
        echo "========================================================================"
        exec uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
        ;;
    mcp)
        # In MCP mode, DO NOT print anything to stdout to preserve JSON-RPC protocol
        exec python3 mcp_server.py
        ;;
    all)
        echo "[*] Starting Proxsynth Dashboard in background..." >&2
        uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload &
        FASTAPI_PID=$!
        
        # Cleanly kill background uvicorn and all child workers on script exit / interrupt
        trap 'kill "$FASTAPI_PID" 2>/dev/null || true; pkill -P "$FASTAPI_PID" 2>/dev/null || true' EXIT INT TERM
        
        echo "[*] Proxsynth Dashboard running (PID: $FASTAPI_PID) on http://127.0.0.1:8000" >&2
        echo "[*] Starting Proxsynth MCP Server in foreground..." >&2
        python3 mcp_server.py
        ;;
    install)
        bash install.sh
        ;;
    *)
        echo "[!] Unknown mode: $MODE"
        echo "Usage:"
        echo "  ./run.sh [dashboard | mcp | all | install]"
        exit 1
        ;;
esac
