@echo off
setlocal enabledelayedexpansion

:: Check if virtual environment exists; if not, trigger installer
if not exist "venv\Scripts\python.exe" (
    echo [*] Proxsynth environment not detected. Running automated installer...
    call install.bat
    if %errorlevel% neq 0 (
        echo [!] Installation failed. Aborting.
        exit /b 1
    )
)

:: Handle command line arguments
set "MODE=%~1"

if "%MODE%"=="" set "MODE=dashboard"
if /i "%MODE%"=="dashboard" (
    echo ========================================================================
    echo   Starting Proxsynth Web Dashboard
    echo   URL: http://127.0.0.1:8000
    echo ========================================================================
    venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
    exit /b %errorlevel%
)

if /i "%MODE%"=="mcp" (
    :: In MCP mode, DO NOT print banner/echo to stdout (preserves JSON-RPC protocol)
    venv\Scripts\python.exe mcp_server.py
    exit /b %errorlevel%
)

if /i "%MODE%"=="all" (
    echo [*] Starting Proxsynth Dashboard in background window...
    start "Proxsynth Dashboard Port 8000" venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
    echo [*] Starting Proxsynth MCP Server in foreground...
    venv\Scripts\python.exe mcp_server.py
    exit /b %errorlevel%
)

if /i "%MODE%"=="install" (
    call install.bat
    exit /b %errorlevel%
)

echo [!] Unknown option: %MODE%
echo Usage:
echo   run.bat [dashboard ^| mcp ^| all ^| install]
exit /b 1
