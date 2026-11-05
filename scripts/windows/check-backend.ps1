param([ValidateRange(1, 65535)][int]$Port = 8765, [switch]$CheckDatasets)
$ErrorActionPreference = "Stop"
$base = "http://127.0.0.1:$Port"
try {
    $h = Invoke-RestMethod "$base/api/health" -TimeoutSec 8
    if ($h.status -ne "OK" -or $h.service -ne "ntk-iris-local-sast-backend") {
        throw "Phan hoi khong khop dich vu backend cua he thong do an."
    }
    Write-Host "BACKEND DANG HOAT DONG" -ForegroundColor Green
    $h | Select-Object status, service, active_port, base_model_available, best_adapter_available, model_load_state | Format-List
    if ($CheckDatasets) {
        $manifest = Invoke-RestMethod "$base/api/datasets/manifest" -TimeoutSec 30
        if ($manifest.status -ne "OK") { throw "Dataset manifest chua san sang." }
        $manifest.datasets | Select-Object dataset_id, row_count, sha256_verified, row_count_verified | Format-Table -AutoSize
    }
} catch {
    Write-Host "BACKEND CHUA SAN SANG: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
