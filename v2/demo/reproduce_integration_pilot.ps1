<#
.SYNOPSIS
    Reproducible end-to-end verification script for NTK Thesis V2 Integration Pilot (Progress Report #1).
.DESCRIPTION
    Executes from the integration workspace root into a fresh timestamped output directory ($EvidenceRoot):
    1. Upstream patch verification (verify_patch.py) and all 105 unit tests across M1 (24), M2/M3 (59), and Evaluation (22).
    2. Real OpenGrep 1.25.0 JSON and SARIF scan on v2/evaluation/smoke_evidence/SmokeVulnSample.java.
    3. End-to-end human review queue & SHA-256 freshness tamper demos (demo_queue.py, demo_freshness.py, verify_handoff.py).
    4. Paired Pilot Table (.csv / .json) and score_pilot.py evaluation from verified Qwen3.5:9b-q4_K_M evidence (or optional live Ollama run when -RunLiveLlm is set).
#>
param(
    [string]$Model = "qwen3.5:9b-q4_K_M",
    [string]$EvidenceRoot = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_run_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$RunLiveLlm = $false
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
$env:PATH = "C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0;$env:PATH"

Write-Host "=== [1/4] Verifying Upstream Patch and Running All 105 Unit Tests (M1, M2/M3, Evaluation) ==="
python v2/baseline/verify_patch.py
python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests -v

Write-Host "=== [2/4] Running Real OpenGrep 1.25.0 Scan (JSON + SARIF) into Fresh Evidence Directory ==="
$WslEvDir = "/mnt/c" + ($EvidenceRoot.Substring(2) -replace '\\', '/')
wsl.exe -d Ubuntu-IRIS -- /usr/local/bin/opengrep scan `
    --config v2/baseline/rules/java.yml `
    --json --dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60 `
    --output "$WslEvDir/smoke_m1_raw.opengrep.json" `
    v2/evaluation/smoke_evidence/SmokeVulnSample.java
wsl.exe -d Ubuntu-IRIS -- /usr/local/bin/opengrep scan `
    --config v2/baseline/rules/java.yml `
    --sarif --dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60 `
    --output "$WslEvDir/smoke_m1_raw.opengrep.sarif" `
    v2/evaluation/smoke_evidence/SmokeVulnSample.java

Write-Host "=== [3/4] Running End-to-End Review Queue & SHA-256 Freshness Tamper Verification ==="
python -m v2.triage.demo_queue --output-dir (Join-Path $EvidenceRoot "queue_demo")
python -m v2.triage.demo_freshness --output-dir (Join-Path $EvidenceRoot "freshness_demo")
python v2/baseline/verify_handoff.py `
    --engine (Join-Path $EvidenceRoot "freshness_demo\run\engine") `
    --triage (Join-Path $EvidenceRoot "freshness_demo\run")

Write-Host "=== [4/4] Building Paired Pilot Table (.csv/.json) and Scoring Qwen3.5-9B Evidence ==="
$TriageJsonl = Join-Path $RepoRoot "v2\demo\triage_qwen35_9b_smoke_m1_assessments.jsonl"
if ($RunLiveLlm) {
    $LiveOut = Join-Path $EvidenceRoot "triage_live_qwen35"
    python -m v2.triage run `
        --source-root $RepoRoot `
        --path-base $RepoRoot `
        --json "v2/demo/smoke_m1_rules_raw.opengrep.json" `
        --engine-exit 0 `
        --output-dir $LiveOut `
        --model $Model `
        --timeout 180
    $TriageJsonl = Join-Path $LiveOut "assessments.jsonl"
}

python v2/evaluation/build_paired_pilot_table.py `
    --opengrep "v2/demo/smoke_m1_rules_raw.opengrep.json" `
    --labels "v2/evaluation/smoke_m1_verified_labels.json" `
    --qwen35-triage $TriageJsonl `
    --qwen3-8b-reference "v2/demo/triage_qwen3_8b_summary.json" `
    --source-root $RepoRoot `
    --output-csv (Join-Path $EvidenceRoot "ADVISOR_PAIRED_PILOT_20261111.csv") `
    --output-json (Join-Path $EvidenceRoot "paired_pilot_summary.json")

$env:PYTHONPATH = "v2/evaluation"
python -m v2.evaluation.score_pilot `
    --opengrep "v2/demo/smoke_m1_rules_raw.opengrep.json" `
    --labels "v2/evaluation/smoke_m1_verified_labels.json" `
    --triage $TriageJsonl `
    --source-root $RepoRoot `
    --output-json (Join-Path $EvidenceRoot "score_pilot_verified.json") `
    --output-md (Join-Path $EvidenceRoot "score_pilot_verified.md")
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

Write-Host "=== COMPLETE: All verification artifacts written to $EvidenceRoot ==="
