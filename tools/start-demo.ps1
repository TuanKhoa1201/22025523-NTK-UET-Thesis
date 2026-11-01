param(
    [string]$Distribution = 'Ubuntu-22.04',
    [string]$PythonBin = '/home/tuankhoa/.venvs/ntk-production-20261028/bin/python',
    [switch]$CheckOnly
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$appRoot = Join-Path $repoRoot 'apps\22025523-thesis'
$runtimeRoot = Join-Path $repoRoot 'work\acceptance\runtime'
$linuxRootResult = & wsl.exe -d $Distribution --exec wslpath -u $repoRoot
if ($LASTEXITCODE -ne 0) { throw 'Cannot access the existing WSL distribution.' }
$linuxRoot = $linuxRootResult.Trim()
$backendArgs = @('-d',$Distribution,'--exec',$PythonBin,'-B',"$linuxRoot/tools/start_demo_backend.py")
if ($CheckOnly) { $backendArgs += '--check-only' }
& wsl.exe @backendArgs
if ($LASTEXITCODE -ne 0) { throw 'Backend startup/check failed; no service was replaced.' }

$listeners = @(Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue)
if ($listeners.Count -gt 0) {
    foreach ($ownerPid in ($listeners.OwningProcess | Select-Object -Unique)) {
        $owner = Get-CimInstance Win32_Process -Filter "ProcessId = $ownerPid"
        if (-not $owner.CommandLine -or $owner.CommandLine -notmatch [regex]::Escape($appRoot)) {
            throw "Port 5173 belongs to another process ($ownerPid); refusing replacement."
        }
    }
    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:5173' -UseBasicParsing -TimeoutSec 10
    if ($response.StatusCode -ne 200) { throw 'Existing frontend is unhealthy; no automatic restart.' }
    Write-Output 'DEMO_FRONTEND_STATUS=EXISTING'
} else {
    if ($CheckOnly) { throw 'Frontend is not running; check-only does not start services.' }
    $vite = Join-Path $appRoot 'node_modules\vite\bin\vite.js'
    if (-not (Test-Path -LiteralPath $vite)) { throw 'Installed Vite is missing; no dependency installation is performed.' }
    $nodeExe = (Get-Command node.exe -ErrorAction Stop).Source
    $frontendProcess = Start-Process -FilePath $nodeExe -WorkingDirectory $appRoot `
        -ArgumentList @("`"$vite`"",'--host','127.0.0.1','--port','5173','--strictPort') `
        -RedirectStandardOutput (Join-Path $runtimeRoot 'frontend-demo.log') `
        -RedirectStandardError (Join-Path $runtimeRoot 'frontend-demo-error.log') `
        -WindowStyle Hidden -PassThru
    $frontendProcess.Id | Set-Content -LiteralPath (Join-Path $runtimeRoot 'frontend.pid')
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri 'http://127.0.0.1:5173' -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch { Start-Sleep -Milliseconds 250 }
    }
    if (-not $ready) { throw 'Frontend startup timed out; inspect frontend-demo logs. No process was killed.' }
    Write-Output 'DEMO_FRONTEND_STATUS=STARTED'
}
Write-Output 'DEMO_URL=http://127.0.0.1:5173/#/results?scan_id=SCAN-20261101164045-3AA266'
