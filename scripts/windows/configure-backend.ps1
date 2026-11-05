param(
    [Parameter(Mandatory = $true)][string]$BaseModelPath,
    [Parameter(Mandatory = $true)][string]$AdapterPath,
    [string]$DatasetPath = "",
    [ValidateSet("auto", "cpu", "cuda")][string]$Device = "auto",
    [ValidateRange(1, 65535)][int]$Port = 8765,
    [switch]$Overwrite
)
$ErrorActionPreference = "Stop"
function Assert-LinuxPath([string]$Value, [string]$Label) {
    if (-not $Value.StartsWith("/")) { throw "$Label phai la duong dan tuyet doi trong WSL." }
    if ($Value -match '[\r\n\x27\x22\x60\$\\]') { throw "$Label chua ky tu khong an toan trong tep cau hinh." }
}
Assert-LinuxPath $BaseModelPath "BaseModelPath"
Assert-LinuxPath $AdapterPath "AdapterPath"
if ($DatasetPath) { Assert-LinuxPath $DatasetPath "DatasetPath" }

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$cfgDir = Join-Path $repo "backend\ntk-production-v2\config"
$cfg = Join-Path $cfgDir "ntk_backend.env"
if (-not (Test-Path -LiteralPath $cfgDir -PathType Container)) {
    throw "Khong tim thay backend trong repository."
}
if ((Test-Path -LiteralPath $cfg) -and -not $Overwrite) {
    throw "Tep cau hinh da ton tai. Dung -Overwrite neu muon thay the."
}
if (Test-Path -LiteralPath $cfg) {
    $backup = "$cfg.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $cfg -Destination $backup
    Write-Host "Da sao luu cau hinh cu: $backup"
}
$lines = @(
    '# Cau hinh cuc bo, khong dua len GitHub.',
    "NTK_BASE_MODEL_PATH='$BaseModelPath'",
    "NTK_BEST_ADAPTER_PATH='$AdapterPath'",
    "NTK_INFERENCE_DEVICE=$Device",
    "NTK_BACKEND_PORT=$Port",
    'NTK_BACKEND_HOST=127.0.0.1',
    'NTK_STORAGE_DIR=$HOME/.local/share/he-thong-do-an/scans',
    'NTK_EXT4_CACHE_DIR=$HOME/.cache/he-thong-do-an',
    'NTK_SUBPROCESS_TIMEOUT_SEC=300',
    'PYTHON_BIN=$HOME/.venvs/he-thong-do-an/bin/python'
)
if ($DatasetPath) { $lines += "NTK_DATASET_DIR='$DatasetPath'" }
$text = ($lines -join "`n") + "`n"
[System.IO.File]::WriteAllText($cfg, $text, [System.Text.UTF8Encoding]::new($false))
Write-Host "Da tao cau hinh cuc bo: $cfg" -ForegroundColor Green
if (-not $DatasetPath) {
    Write-Warning "Chua co duong dan dataset. Muc Du lieu nghien cu can 4 tep JSONL goc."
}
Write-Host "Khong commit tep config/ntk_backend.env len GitHub."
