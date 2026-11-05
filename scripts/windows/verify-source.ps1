$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$linuxRepo = ((& wsl.exe --exec wslpath -a -u $repo) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxRepo) { throw "Khong the truy cap repository tu WSL." }
& wsl.exe --exec bash "$linuxRepo/scripts/linux/test-backend-stdlib.sh"
if ($LASTEXITCODE -ne 0) { throw "Backend tests khong dat." }
Push-Location (Join-Path $repo "apps\22025523-thesis")
try {
    if (-not (Test-Path "node_modules")) {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci loi." }
    }
    & node --test
    if ($LASTEXITCODE -ne 0) { throw "Frontend tests khong dat." }
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw "Frontend build khong dat." }
} finally { Pop-Location }
Write-Host "Kiem tra ma nguon frontend va backend: PASS" -ForegroundColor Green
