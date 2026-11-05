param([ValidateRange(1, 65535)][int]$Port = 8765, [switch]$Force)
$ErrorActionPreference = "Stop"
$api = "http://127.0.0.1:$Port"
try {
    $health = Invoke-RestMethod "$api/api/health" -TimeoutSec 5
} catch {
    Write-Host "Backend khong phan hoi qua API. Se kiem tra PID do script quan ly."
    $health = $null
}
if ($health -and -not $Force) {
    try {
        $jobs = Invoke-RestMethod "$api/api/scan-jobs?limit=100" -TimeoutSec 10
    } catch {
        throw "Khong doc duoc trang thai quet. Khong tu y tat backend. Chi dung -Force khi da xac nhan."
    }
    $active = @($jobs.jobs | Where-Object { $_.state -in @("QUEUED", "RUNNING") })
    if ($active.Count -gt 0) {
        throw "Dang co $($active.Count) phien quet hoat dong. Dung lai de tranh mat ket qua."
    }
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$linuxRepo = ((& wsl.exe --exec wslpath -a -u $repo) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxRepo) { throw "Khong chuyen duoc duong dan sang WSL." }
& wsl.exe --exec bash "$linuxRepo/scripts/linux/stop-backend.sh" "$Port"
if ($LASTEXITCODE -ne 0) { throw "Khong tat duoc backend. Kiem tra PID va log." }
