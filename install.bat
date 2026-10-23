@echo off
setlocal

echo ========================================================================
echo   PROXSYNTH MCP - Autonomous Security Testing Gateway
echo   Automated Environment Installer for Windows
echo ========================================================================
echo.

:: 1. Detect Python Executable
set "PYTHON_CMD="
where python >nul 2>nul && set "PYTHON_CMD=python"
if "%PYTHON_CMD%"=="" where py >nul 2>nul && set "PYTHON_CMD=py -3"
if "%PYTHON_CMD%"=="" where python3 >nul 2>nul && set "PYTHON_CMD=python3"

if "%PYTHON_CMD%"=="" (
    echo [!] ERROR: Python 3 was not found in your system PATH.
    echo [*] Please install Python 3.10 or newer from:
    echo     https://www.python.org/downloads/
    echo [*] IMPORTANT: Make sure to check "Add Python to PATH" during setup.
    exit /b 1
)

echo [*] Detected Python command: %PYTHON_CMD%
%PYTHON_CMD% --version

:: 2. Verify Python Version (>= 3.10)
%PYTHON_CMD% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
    echo [!] WARNING: Proxsynth recommends Python 3.10 or higher.
    echo     Current version may encounter dependency compatibility issues.
)

:: 3. Setup Virtual Environment
if not exist "venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment at venv ...
    %PYTHON_CMD% -m venv venv
    if errorlevel 1 (
        echo [!] ERROR: Failed to create virtual environment.
        exit /b 1
    )
    echo [+] Virtual environment created successfully.
) else (
    echo [+] Existing virtual environment detected.
)

:: 4. Upgrade pip and Install Dependencies
echo [*] Upgrading pip...
venv\Scripts\python.exe -m pip install --upgrade pip --quiet

echo [*] Installing Proxsynth dependencies from requirements.txt...
venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo [!] ERROR: Failed to install Python dependencies.
    exit /b 1
)
echo [+] Dependencies installed successfully.

:: 5. Install Playwright Chromium Browser
echo [*] Setting up Playwright Chromium browser for headless rendering and HITL...
venv\Scripts\python.exe -m playwright install chromium
if errorlevel 1 (
    echo [!] Warning: Playwright browser download encountered an issue.
    echo     You can retry later via: venv\Scripts\playwright.exe install chromium
)

:: 6. Initialize Database and Master Encryption Key
echo [*] Initializing SQLite database schema and cryptographic vault...
venv\Scripts\python.exe -c "from backend.database import init_db; init_db(); from backend.security_utils import get_or_create_encryption_key; get_or_create_encryption_key(); print('[+] Database initialized and Fernet encryption key active.')"
if errorlevel 1 (
    echo [!] Warning: Database pre-initialization check failed.
)

:: 7. Install AI Agent Proxy Enforcer Hook
echo [*] Installing AI Agent Proxy Enforcer into venv...
copy /Y sitecustomize.py venv\Lib\site-packages\sitecustomize.py >nul
echo [+] AI Agent transparent proxy hook installed in venv.

:: 8. Initialize CA Certificate and Trust Store
echo [*] Initializing Proxsynth Root CA certificate...
venv\Scripts\python.exe -c "from backend.ca_manager import get_ca_cert_path; print('[+] Proxsynth Root CA ready at:', get_ca_cert_path())"
if exist ".proxsynth_ca\proxsynth_ca.crt" (
    echo [*] Registering Proxsynth Root CA in Windows Certificate Store...
    certutil -addstore -f "Root" .proxsynth_ca\proxsynth_ca.crt >nul 2>nul
    if errorlevel 0 (
        echo [+] Proxsynth Root CA successfully trusted in Windows System Store.
    ) else (
        echo [!] Note: To trust CA system-wide, import .proxsynth_ca\proxsynth_ca.crt into Trusted Root Certification Authorities.
    )
) else if exist ".proxynth_ca\proxynth_ca.crt" (
    echo [*] Registering Proxsynth Root CA in Windows Certificate Store...
    certutil -addstore -f "Root" .proxynth_ca\proxynth_ca.crt >nul 2>nul
)

echo.
echo ========================================================================
echo   [SUCCESS] Proxsynth Installation Complete!
echo ========================================================================
echo.
echo   To launch the Web Dashboard:
echo     run.bat
echo     (or run.bat dashboard)
echo.
echo   To run as an MCP Server for AI Agents:
echo     run.bat mcp
echo.
echo   To start both Dashboard and MCP Server:
echo     run.bat all
echo ========================================================================
echo.
exit /b 0
