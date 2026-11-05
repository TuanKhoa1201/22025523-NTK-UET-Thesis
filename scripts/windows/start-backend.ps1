param([ValidateRange(1, 65535)][int]$Port = 8765)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$cfg = Join-Path $repo "backend\ntk-production-v2\config\ntk_backend.env"
if (-not (Test-Path -LiteralPath $cfg)) {
    throw "Chua co cau hinh. Hay chay scripts/windows/configure-backend.ps1 truoc."
}
$linuxRepo = ((& wsl.exe --exec wslpath -a -u $repo) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxRepo) { throw "Khong chuyen duoc duong dan repository sang WSL." }
$entry = "$linuxRepo/scripts/linux/start-backend.sh"
& wsl.exe --exec bash $entry
if ($LASTEXITCODE -ne 0) { throw "Backend WSL khong khoi dong duoc. Xem log trong NTK_STORAGE_DIR." }
& (Join-Path $PSScriptRoot "check-backend.ps1") -Port $Port
if ($LASTEXITCODE -ne 0) { throw "Backend chua san sang sau khi khoi dong." }
