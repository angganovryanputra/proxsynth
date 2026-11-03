<#
.SYNOPSIS
    Proxsynth Transparent CLI & Pentest Command Wrapper (PowerShell)
    Routes all outbound HTTP/HTTPS traffic through Proxsynth Proxy (127.0.0.1:8088),
    binds Root CA, captures execution time, and streams command logs to Dashboard API.

.EXAMPLE
    .\proxsynth-exec.ps1 curl https://example.com
    .\proxsynth-exec.ps1 sqlmap -u "https://target.com/item?id=1" --batch
    .\proxsynth-exec.ps1 python exploits/test_idor.py
#>

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CommandArgs
)

if (-not $CommandArgs) {
    Write-Host "[!] Usage: .\proxsynth-exec.ps1 <command> [args...]" -ForegroundColor Yellow
    exit 1
}

$FullCommand = $CommandArgs -join " "
$ProxyPort = if ($env:PROXSYNTH_PROXY_PORT) { $env:PROXSYNTH_PROXY_PORT } else { "8088" }
$ProxyUrl = "http://127.0.0.1:$ProxyPort"

# Set Proxy Environment Variables
$env:HTTP_PROXY = $ProxyUrl
$env:HTTPS_PROXY = $ProxyUrl
$env:ALL_PROXY = $ProxyUrl
$env:http_proxy = $ProxyUrl
$env:https_proxy = $ProxyUrl
$env:all_proxy = $ProxyUrl

# CA Certificate trust (probe both .proxsynth_ca and legacy .proxynth_ca)
$CaCert = Join-Path $PSScriptRoot ".proxsynth_ca\proxsynth_ca.crt"
if (-not (Test-Path $CaCert)) {
    $CaCert = Join-Path $PSScriptRoot ".proxynth_ca\proxynth_ca.crt"
}
if (Test-Path $CaCert) {
    $env:REQUESTS_CA_BUNDLE = $CaCert
    $env:CURL_CA_BUNDLE = $CaCert
    $env:SSL_CERT_FILE = $CaCert
    $env:NODE_EXTRA_CA_CERTS = $CaCert
}
$env:PYTHONHTTPSVERIFY = "0"
$env:CURL_INSECURE = "1"
$env:NODE_TLS_REJECT_UNAUTHORIZED = "0"

$StartTime = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

Write-Host "[*] Proxsynth Executing: $FullCommand (Proxy: $ProxyUrl)" -ForegroundColor Cyan

# Execute command reliably preserving arguments and quotes
$ExitCode = 0
$StdoutText = ""
$StderrText = ""

try {
    if ($CommandArgs.Length -eq 1 -and ($CommandArgs[0] -match '\s')) {
        $Output = Invoke-Expression $CommandArgs[0] 2>&1
    } else {
        $cmd = $CommandArgs[0]
        $argsList = if ($CommandArgs.Length -gt 1) { $CommandArgs[1..($CommandArgs.Length - 1)] } else { @() }
        $Output = & $cmd $argsList 2>&1
    }
    $ExitCode = $LASTEXITCODE
    if ($null -eq $ExitCode) { $ExitCode = 0 }
    $StdoutText = ($Output | Out-String)
    Write-Output $Output
}
catch {
    $ExitCode = 1
    $StderrText = $_.Exception.Message
    Write-Error $_
}

$EndTime = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$DurationMs = [int]($EndTime - $StartTime)

# Telemetry broadcast to Proxsynth API (non-blocking)
try {
    $Payload = @{
        command = $FullCommand
        tool_name = "proxsynth-cli-wrapper"
        reasoning = "Executed via proxsynth-exec wrapper"
        stdout = if ($StdoutText.Length -gt 500000) { $StdoutText.Substring(0, 500000) } else { $StdoutText }
        stderr = if ($StderrText.Length -gt 50000) { $StderrText.Substring(0, 50000) } else { $StderrText }
        exit_code = [int]$ExitCode
        duration_ms = $DurationMs
        status = if ($ExitCode -eq 0) { "SUCCESS" } else { "FAILED" }
    } | ConvertTo-Json -Compress

    $ApiUrl = "http://127.0.0.1:8000/api/commands"
    Invoke-RestMethod -Uri $ApiUrl -Method Post -Body $Payload -ContentType "application/json" -TimeoutSec 2 | Out-Null
}
catch {
    # Dashboard API offline - safe to ignore
}

exit $ExitCode
