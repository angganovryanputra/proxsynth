# ==============================================================================
# Proxsynth MCP - Automated PowerShell Installer for Windows
# ==============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  PROXSYNTH MCP - Security Testing Gateway and Observability Platform    " -ForegroundColor Cyan
Write-Host "  Automated Environment Installer for Windows (PowerShell)               " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Detect Python Command
$PythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonCmd = "py"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $PythonCmd = "python3"
}

if (-not $PythonCmd) {
    Write-Host "[!] ERROR: Python 3 was not found in your system PATH." -ForegroundColor Red
    Write-Host "[*] Please install Python 3.10+ from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "[*] Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    exit 1
}

$PyVer = & $PythonCmd --version
Write-Host "[+] Detected Python: $PyVer" -ForegroundColor Green

# 2. Check Python Version (>= 3.10)
& $PythonCmd -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] WARNING: Proxsynth recommends Python 3.10 or higher." -ForegroundColor Yellow
}

# 3. Setup Virtual Environment
$VenvDir = Join-Path $PSScriptRoot "venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[*] Creating virtual environment at .\venv ..." -ForegroundColor Cyan
    & $PythonCmd -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] ERROR: Failed to create virtual environment." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Virtual environment created successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Existing virtual environment detected." -ForegroundColor Green
}

# 4. Upgrade pip and Install Dependencies
Write-Host "[*] Upgrading pip..." -ForegroundColor Cyan
& $VenvPython -m pip install --upgrade pip --quiet

Write-Host "[*] Installing Proxsynth dependencies from requirements.txt..." -ForegroundColor Cyan
& $VenvPython -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] ERROR: Failed to install Python dependencies." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Dependencies installed successfully." -ForegroundColor Green

# 5. Playwright Chromium Setup
Write-Host "[*] Setting up Playwright Chromium browser..." -ForegroundColor Cyan
& $VenvPython -m playwright install chromium
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Warning: Playwright browser download encountered an issue." -ForegroundColor Yellow
}

# 6. Initialize Database and Master Encryption Key
Write-Host "[*] Initializing SQLite database schema and cryptographic vault..." -ForegroundColor Cyan
& $VenvPython -c "from backend.database import init_db; init_db(); from backend.security_utils import get_or_create_encryption_key; get_or_create_encryption_key(); print('[+] Database initialized and Fernet master encryption key active.')"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Warning: Database pre-initialization check failed." -ForegroundColor Yellow
}

# 7. Install AI Agent Proxy Enforcer Hook
Write-Host "[*] Installing AI Agent Transparent Proxy Enforcer..." -ForegroundColor Cyan
$SitePackages = Join-Path $VenvDir "Lib\site-packages\sitecustomize.py"
Copy-Item (Join-Path $PSScriptRoot "sitecustomize.py") $SitePackages -Force
Write-Host "[+] AI Agent transparent proxy hook installed in venv." -ForegroundColor Green

# 8. Initialize CA Certificate and Trust Store
Write-Host "[*] Initializing Proxsynth Root CA certificate..." -ForegroundColor Cyan
& $VenvPython -c "from backend.ca_manager import get_ca_cert_path; print('[+] Proxsynth Root CA Certificate ready at:', get_ca_cert_path())"
$CaCert = Join-Path $PSScriptRoot ".proxsynth_ca\proxsynth_ca.crt"
if (-not (Test-Path $CaCert)) {
    $CaCert = Join-Path $PSScriptRoot ".proxynth_ca\proxynth_ca.crt"
}
if (Test-Path $CaCert) {
    try {
        certutil -addstore -f "Root" $CaCert | Out-Null
        Write-Host "[+] Proxsynth Root CA successfully trusted in Windows System Store." -ForegroundColor Green
    } catch {
        Write-Host "[!] Note: Run PowerShell as Administrator to install CA certificate system-wide." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] Proxsynth Installation Complete!                             " -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  To launch the Web Dashboard:"
Write-Host "    .\run.ps1" -ForegroundColor Cyan
Write-Host "    (or .\run.ps1 -Mode dashboard)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  To run as an MCP Server for AI Agents:"
Write-Host "    .\run.ps1 -Mode mcp" -ForegroundColor Cyan
Write-Host ""
Write-Host "  To start both Dashboard and MCP Server:"
Write-Host "    .\run.ps1 -Mode all" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Green
Write-Host ""
