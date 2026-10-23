#!/usr/bin/env bash
# ==============================================================================
# Proxynth MCP - Automated Linux / WSL2 Environment Installer
# ==============================================================================

set -eo pipefail

# ANSI Color Codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}========================================================================${NC}"
echo -e "${CYAN}  PROXSYNTH MCP - Security Testing Gateway & Observability Platform      ${NC}"
echo -e "${CYAN}  Automated Environment Installer for Linux / WSL2                      ${NC}"
echo -e "${CYAN}========================================================================${NC}"
echo ""

# 1. Check Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] ERROR: python3 is not installed or not in PATH.${NC}"
    echo -e "${YELLOW}[*] Please install Python 3.10+ using your package manager:${NC}"
    echo "    Debian/Ubuntu/WSL2 : sudo apt update && sudo apt install -y python3 python3-pip python3-venv"
    echo "    Fedora/RHEL        : sudo dnf install -y python3 python3-pip"
    echo "    Arch Linux         : sudo pacman -S python python-pip"
    exit 1
fi

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}[+] Detected Python version: ${PYTHON_VER}${NC}"

# Check Python version >= 3.10
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" || {
    echo -e "${YELLOW}[!] WARNING: Proxsynth recommends Python 3.10 or higher. Current: ${PYTHON_VER}${NC}"
}

# 2. Check python3-venv support (common issue on Debian/Ubuntu/WSL)
if ! python3 -c "import venv, ensurepip" &>/dev/null; then
    echo -e "${RED}[!] ERROR: python3-venv / ensurepip is not available.${NC}"
    echo -e "${YELLOW}[*] On Debian/Ubuntu/WSL2, install it using:${NC}"
    echo -e "    ${CYAN}sudo apt update && sudo apt install -y python3-venv python3-pip${NC}"
    exit 1
fi

# 3. Setup Virtual Environment
if [ ! -d "venv" ]; then
    echo -e "${CYAN}[*] Creating Python virtual environment in ./venv ...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment successfully created.${NC}"
else
    echo -e "${GREEN}[+] Existing virtual environment detected in ./venv.${NC}"
fi

# 4. Activate Virtual Environment
source venv/bin/activate

# 5. Upgrade pip and Install Dependencies
echo -e "${CYAN}[*] Upgrading pip...${NC}"
pip install --upgrade pip --quiet

echo -e "${CYAN}[*] Installing dependencies from requirements.txt...${NC}"
pip install -r requirements.txt
echo -e "${GREEN}[+] Python dependencies installed successfully.${NC}"

# 6. Install Playwright Chromium Browser & Dependencies
echo -e "${CYAN}[*] Setting up Playwright Chromium browser...${NC}"
playwright install chromium

# Check if running in Linux environment needing OS browser dependencies
if [ "$(uname)" = "Linux" ]; then
    echo -e "${CYAN}[*] Checking for Playwright system dependencies...${NC}"
    if [ "$EUID" -eq 0 ]; then
        playwright install-deps chromium || true
    elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
        sudo playwright install-deps chromium || true
    else
        echo -e "${YELLOW}[*] Note: If headless browser fails to launch, run:${NC}"
        echo -e "    ${CYAN}sudo ./venv/bin/playwright install-deps chromium${NC}"
    fi
fi

# 7. Initialize Database and Master Encryption Key
echo -e "${CYAN}[*] Initializing SQLite database schema & cryptographic vault...${NC}"
python3 -c "from backend.database import init_db; init_db(); from backend.security_utils import get_or_create_encryption_key; get_or_create_encryption_key(); print('[+] Database initialized and Fernet master encryption key active.')"

# 8. Install AI Agent Proxy Enforcer Hook
echo -e "${CYAN}[*] Installing AI Agent Proxy Enforcer into venv...${NC}"
cp sitecustomize.py $(python3 -c "import site; print(site.getsitepackages()[-1])")/sitecustomize.py 2>/dev/null || true
echo -e "${GREEN}[+] AI Agent transparent proxy hook installed in venv.${NC}"

# 9. Initialize CA Certificate & Trust Store
echo -e "${CYAN}[*] Initializing Proxsynth Root CA certificate...${NC}"
python3 -c "from backend.ca_manager import get_ca_cert_path; print('[+] Proxsynth Root CA Certificate ready at:', get_ca_cert_path())"
CA_FILE=".proxsynth_ca/proxsynth_ca.crt"
[ ! -f "$CA_FILE" ] && CA_FILE=".proxynth_ca/proxynth_ca.crt"
if [ -f "$CA_FILE" ]; then
    if [ -d "/usr/local/share/ca-certificates" ] && command -v update-ca-certificates &>/dev/null; then
        if [ "$EUID" -eq 0 ]; then
            cp "$CA_FILE" /usr/local/share/ca-certificates/proxsynth_ca.crt
            update-ca-certificates &>/dev/null || true
            echo -e "${GREEN}[+] Proxsynth Root CA installed into Linux system CA trust store.${NC}"
        elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
            sudo cp "$CA_FILE" /usr/local/share/ca-certificates/proxsynth_ca.crt
            sudo update-ca-certificates &>/dev/null || true
            echo -e "${GREEN}[+] Proxsynth Root CA installed into Linux system CA trust store.${NC}"
        else
            echo -e "${YELLOW}[*] To trust CA system-wide: sudo cp $CA_FILE /usr/local/share/ca-certificates/ && sudo update-ca-certificates${NC}"
        fi
    fi
fi

# 10. Set Executable Permissions
chmod +x run.sh install.sh 2>/dev/null || true

echo ""
echo -e "${GREEN}========================================================================${NC}"
echo -e "${GREEN}  [SUCCESS] Proxsynth Installation Complete!                             ${NC}"
echo -e "${GREEN}========================================================================${NC}"
echo ""
echo -e "  To launch the Web Dashboard:"
echo -e "    ${CYAN}./run.sh${NC} (or ${CYAN}./run.sh dashboard${NC})"
echo ""
echo -e "  To run as an MCP Server for AI Agents (Claude Code, Cursor, OpenCode):"
echo -e "    ${CYAN}./run.sh mcp${NC}"
echo ""
echo -e "  To start both Dashboard (background) and MCP Server (foreground):"
echo -e "    ${CYAN}./run.sh all${NC}"
echo -e "${GREEN}========================================================================${NC}"
echo ""
