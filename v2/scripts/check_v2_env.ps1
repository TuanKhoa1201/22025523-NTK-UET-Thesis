param(
    [switch]$StartOllamaIfStopped
)
$ErrorActionPreference = "Continue"

$OllamaBin = "F:\ACTIVE-WORKSPACES\Tools\Ollama\v0.40.7\bin\ollama.exe"
$OllamaModels = "F:\ACTIVE-WORKSPACES\Models\Ollama_Staging_20261023-124046-0d639a03"
$OllamaHostUrl = "http://127.0.0.1:11434"
$OpenGrepBridge = "C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.cmd"
$EvidenceDir = "C:\Users\Admin\ntk-thesis-v2\evidence\m0_m2_env_prep"

Write-Host "=== 1. GIT WORKSPACE CHECK ===" -ForegroundColor Cyan
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
git -C $repoRoot status --short --branch
git -C $repoRoot log -n 1 --oneline

Write-Host "`n=== 2. GPU & SYSTEM MEMORY ===" -ForegroundColor Cyan
nvidia-smi --query-gpu=name,driver_version,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu --format=csv
$os = Get-CimInstance Win32_OperatingSystem
Write-Host ("RAM Total: {0:N2} GB | Free: {1:N2} GB" -f ($os.TotalVisibleMemorySize / 1MB), ($os.FreePhysicalMemory / 1MB))

Write-Host "`n=== 3. OLLAMA SERVER & API CHECK ===" -ForegroundColor Cyan
$apiAlive = $false
try {
    $ver = Invoke-RestMethod -Uri "$OllamaHostUrl/api/version" -TimeoutSec 3
    Write-Host "Ollama HTTP API active: version $($ver.version)" -ForegroundColor Green
    $apiAlive = $true
} catch {
    Write-Host "Ollama HTTP API not responding on $OllamaHostUrl" -ForegroundColor Yellow
}

if (-not $apiAlive -and $StartOllamaIfStopped) {
    Write-Host "Starting Ollama server with OLLAMA_NOPRUNE=true..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    $env:OLLAMA_HOST = "127.0.0.1:11434"
    $env:OLLAMA_MODELS = $OllamaModels
    $env:OLLAMA_NOPRUNE = "true"
    $env:OLLAMA_MAX_TRANSFER_STREAMS = "32"
    Start-Process -FilePath $OllamaBin -ArgumentList "serve" -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $EvidenceDir "ollama_serve_stdout.log") `
        -RedirectStandardError (Join-Path $EvidenceDir "ollama_serve_stderr.log")
    Start-Sleep -Seconds 4
    $ver = Invoke-RestMethod -Uri "$OllamaHostUrl/api/version" -TimeoutSec 5
    Write-Host "Ollama HTTP API started: version $($ver.version)" -ForegroundColor Green
}

& $OllamaBin list

Write-Host "`n=== 4. OPENGREP CHECK (WSL2 + WINDOWS BRIDGE) ===" -ForegroundColor Cyan
$wslOgVer = wsl.exe -d Ubuntu-IRIS -- /usr/local/bin/opengrep --version 2>&1
Write-Host "WSL2 Ubuntu-IRIS OpenGrep version: $wslOgVer"
if (Test-Path $OpenGrepBridge) {
    $bridgeVer = & $OpenGrepBridge --version 2>&1
    Write-Host "Windows OpenGrep Bridge version:   $bridgeVer"
} else {
    Write-Host "Windows OpenGrep Bridge not found at $OpenGrepBridge" -ForegroundColor Yellow
}
