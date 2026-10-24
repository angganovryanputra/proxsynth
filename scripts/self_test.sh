#!/usr/bin/env bash
# ==============================================================================
# Proxynth Automated Self-Test Acceptance Gate (Task 7)
# Validates FastMCP handshake, 83 tools, standard annotations, structured output,
# and workspace scoping.
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

# Resolve Python binary
if [ -f "venv/bin/python" ]; then
    PYTHON="venv/bin/python"
elif [ -f "venv/Scripts/python.exe" ]; then
    PYTHON="venv/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    PYTHON="python"
fi

echo "================================================================="
echo "PROXSYNTH AUTOMATED SELF-TEST ACCEPTANCE GATE"
echo "Directory: $DIR"
echo "Python:    $PYTHON"
echo "================================================================="

# 1. Verify side-effect free imports
echo "[1/4] Verifying side-effect free imports (backend.app, mcp_core.server, mcp_server)..."
$PYTHON -c "import backend.app, mcp_core.server, mcp_server"
echo "  -> Passed: Clean module imports."

# 2. Verify compilation
echo "[2/4] Verifying syntax & compilation across mcp_core and entrypoint..."
$PYTHON -m py_compile mcp_server.py mcp_core/*.py mcp_core/tools/*.py
echo "  -> Passed: 0 syntax or compilation errors."

# 3. Run full automated self-test suite (Registry, Annotations, Schemas, Scoping)
echo "[3/4] Running automated self-test verification suite..."
$PYTHON scripts/self_test.py

# 4. Run unified autonomous engine verification
echo "[4/4] Running unified autonomous engine verification suite..."
$PYTHON test_unified_autonomous_engine.py

echo "================================================================="
echo "ALL SELF-TEST ACCEPTANCE CRITERIA PASSED (EXIT CODE 0)"
echo "================================================================="
exit 0
