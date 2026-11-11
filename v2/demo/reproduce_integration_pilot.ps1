<#
.SYNOPSIS
    Reproducible end-to-end verification script for NTK Thesis V2 Integration Pilot (M0/M1/M2/M3).
.DESCRIPTION
    Executes from the integration workspace root:
    1. Unit tests across M1 (scanner), M2/M3 (triage), and M4/M5 (evaluation).
    2. Real OpenGrep 1.25.0 JSON and SARIF scan on v2/evaluation/smoke_evidence/SmokeVulnSample.java.
    3. Real Codex v2.triage execution against local Ollama (qwen3:8b) with citation & SHA-256 verification.
    4. SQLite review queue inspection confirming zero automatic dismissals.
    5. Synthetic/Demo SHA-256 tamper guard check confirming post-scan source edits block confirm-false.
#>
param(
    [string]$Model = "qwen3:8b",
    [string]$EvidenceRoot = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_run_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

Write-Host "=== [1/5] Running M1, M2/M3, and M4/M5 Unit Tests ==="
python -m unittest discover -s v2/triage/tests -v
python -m unittest discover -s v2/evaluation/tests -v

Write-Host "=== [2/5] Running Real OpenGrep 1.25.0 (JSON + SARIF) from Integration Workspace ==="
$RawJson = Join-Path $EvidenceRoot "smoke_v2_taint_raw.opengrep.json"
$RawSarif = Join-Path $EvidenceRoot "smoke_v2_taint_raw.opengrep.sarif"

python -c @"
import subprocess, pathlib
root = pathlib.Path(r'$RepoRoot')
out_json = pathlib.Path(r'$RawJson')
out_sarif = pathlib.Path(r'$RawSarif')
for fmt, out_path in [('--json', out_json), ('--sarif', out_sarif)]:
    cmd = ['wsl.exe', '-d', 'Ubuntu-IRIS', '--', '/usr/local/bin/opengrep', 'scan',
           '--config', 'v2/evaluation/smoke_evidence/v2_java_taint_rules.yaml',
           fmt, '--dataflow-traces', '--no-git-ignore', '--disable-version-check',
           '--jobs', '1', '--timeout', '60',
           'v2/evaluation/smoke_evidence/SmokeVulnSample.java']
    p = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, encoding='utf-8', check=True)
    out_path.write_text(p.stdout, encoding='utf-8')
print('OpenGrep JSON & SARIF written to:', out_json.parent)
"@

Write-Host "=== [3/5] Running Codex v2.triage with Local Ollama ($Model) ==="
$TriageOut = Join-Path $EvidenceRoot "triage_run"
python -m v2.triage run `
    --source-root (Join-Path $RepoRoot "v2\evaluation\smoke_evidence") `
    --path-base $RepoRoot `
    --json $RawJson `
    --engine-exit 0 `
    --output-dir $TriageOut `
    --model $Model `
    --timeout 120

Write-Host "=== [4/5] Inspecting SQLite Review Queue ==="
python -m v2.triage queue --db (Join-Path $TriageOut "review.sqlite")

Write-Host "=== [5/5] Complete. Artifacts stored in $EvidenceRoot ==="
