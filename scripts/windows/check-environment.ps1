$ErrorActionPreference = "Stop"
Write-Host "KIEM TRA MOI TRUONG HE THONG DO AN" -ForegroundColor Cyan
foreach ($tool in @("git", "node", "npm", "wsl.exe")) {
    $cmd = Get-Command $tool -ErrorAction SilentlyContinue
    if (-not $cmd) { throw "Thieu chuong trinh tren Windows: $tool" }
    Write-Host "Windows ${tool}: OK"
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$linuxRepo = ((& wsl.exe --exec wslpath -a -u $repo) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxRepo) { throw "Khong tim thay WSL hoac duong dan repository." }
& wsl.exe --exec bash "$linuxRepo/scripts/linux/check-environment.sh"
if ($LASTEXITCODE -ne 0) { throw "Moi truong WSL chua du yeu cau. Xem thong bao phia tren." }
Write-Host "Da kiem tra cac cong cu. Model va dataset duoc xac minh khi khoi dong backend."
